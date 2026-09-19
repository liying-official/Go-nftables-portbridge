package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const maxNFTDiskBytes = 16 << 20

// The filesystem protects authenticity. The digest detects accidental damage;
// it is NOT a signature against someone who controls the service identity.
type nftDiskContext struct {
	ConfigSHA256 string `json:"config_sha256"`
	BootID       string `json:"boot_id"`
	NetDevice    uint64 `json:"net_device"`
	NetInode     uint64 `json:"net_inode"`
	NetCookie    uint64 `json:"net_cookie"`
	UID          uint32 `json:"uid"`
	Owner        string `json:"owner"`
	ZonePolicy   string `json:"zone_policy"`
}
type nftDiskPath struct {
	Identity string      `json:"identity"`
	Spec     nftRuleSpec `json:"tuple"`
}
type nftDiskSnapshot struct {
	Active    []nftDiskPath `json:"active"`
	Pending   []nftDiskPath `json:"pending"`
	Suspended []nftDiskPath `json:"suspended"`
}
type nftDiskRecord struct {
	Schema     int             `json:"schema"`
	Context    nftDiskContext  `json:"context"`
	Instance   string          `json:"instance"`
	Generation uint64          `json:"generation"`
	Phase      string          `json:"phase"`
	Confirmed  nftDiskSnapshot `json:"confirmed"`
	Intent     nftDiskSnapshot `json:"intent"`
}
type nftDiskEnvelope struct {
	Payload json.RawMessage `json:"payload"`
	SHA256  string          `json:"sha256"`
}
type nftStateStore struct {
	configPath  string
	verifyEmpty func() error
	// A typed fault seam, never supplied by config, the environment or an API.
	fault func(string) error
}
type nftDiskSession struct {
	store        *nftStateStore
	dir          *os.File
	lock         *os.File
	name         string
	context      nftDiskContext
	record       *nftDiskRecord
	threadLocked bool
	rolledBoot   bool
}

func newNFTStateStore(configPath string) *nftStateStore {
	return &nftStateStore{configPath: configPath, verifyEmpty: verifyEmptyNetfilter}
}
func (s *nftStateStore) inject(stage string) error {
	if s.fault != nil {
		return s.fault(stage)
	}
	return nil
}

// Open every directory component relative to an already checked directory FD.
// Root-owned sticky ancestors (/tmp) are permitted, but the final directory
// must be private to root/the service. No symlink, writable-group ancestor or
// untrusted owner is followed. A rename cannot redirect our open directory FD.
func openNFTStateDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("state directory must be an absolute clean path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		if part == "" {
			continue
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var st unix.Stat_t
		if e := unix.Fstat(fd, &st); e != nil {
			unix.Close(fd)
			return nil, e
		}
		trusted := st.Uid == 0 || st.Uid == uint32(os.Geteuid())
		stickyAncestor := i < len(parts)-1 && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
		if !trusted || (st.Mode&0022 != 0 && !stickyAncestor) {
			unix.Close(fd)
			return nil, errors.New("untrusted owner or permissions on nft state directory")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
func checkNFTStateFile(f *os.File) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || st.Mode&0077 != 0 {
		return errors.New("nft recovery file must be a single-link service-owned private regular file")
	}
	return nil
}
func nftCurrentDiskContext(configPath, owner string) (nftDiskContext, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var c nftDiskContext
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return c, err
	}
	sum := sha256.Sum256([]byte(filepath.Clean(absolute)))
	c.ConfigSHA256 = hex.EncodeToString(sum[:])
	c.Owner, c.UID, c.ZonePolicy = owner, uint32(os.Geteuid()), "common-only"
	// ProcSubset=pid hides /proc/sys. The unit provides ONLY this kernel file
	// through a read-only bind; a regular userspace replacement is rejected.
	for _, path := range []string{"/proc/sys/kernel/random/boot_id", "/run/portbridge-boot-id"} {
		f, e := os.Open(path)
		if e != nil {
			continue
		}
		var fs unix.Statfs_t
		e = unix.Fstatfs(int(f.Fd()), &fs)
		data, readErr := io.ReadAll(io.LimitReader(f, 65))
		f.Close()
		id := strings.TrimSpace(string(data))
		if e == nil && readErr == nil && uint64(fs.Type) == uint64(unix.PROC_SUPER_MAGIC) && len(id) == 36 && validNFTBootID(id) {
			c.BootID = id
			break
		}
	}
	if c.BootID == "" {
		return c, errors.New("kernel boot identity is unavailable (check the narrow systemd read-only bind)")
	}
	f, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return c, err
	}
	defer f.Close()
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return c, err
	}
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil || uint64(fs.Type) != uint64(unix.NSFS_MAGIC) {
		return c, errors.New("network namespace is not a kernel namespace object")
	}
	c.NetDevice, c.NetInode = uint64(st.Dev), st.Ino
	threadNS, e := os.Readlink("/proc/thread-self/ns/net")
	leaderNS, e2 := os.Readlink("/proc/self/ns/net")
	if e != nil || e2 != nil || threadNS != leaderNS {
		return c, errors.New("recovery namespace differs from process namespace")
	}
	socket, e := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return c, e
	}
	defer unix.Close(socket)
	c.NetCookie, e = unix.GetsockoptUint64(socket, unix.SOL_SOCKET, unix.SO_NETNS_COOKIE)
	if e != nil || c.NetCookie == 0 {
		return c, errors.New("stable kernel network namespace cookie unavailable")
	}
	return c, nil
}
func validNFTBootID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	return err == nil
}
func (s *nftStateStore) paths() (string, string, error) {
	path, err := filepath.Abs(s.configPath)
	if err != nil {
		return "", "", err
	}
	return filepath.Dir(path), filepath.Base(path) + ".nft-state.json", nil
}
func (s *nftStateStore) begin(owner string, bootProof ...func(nftDiskContext) error) (*nftDiskSession, error) {
	directory, name, err := s.paths()
	if err != nil {
		return nil, err
	}
	dir, err := openNFTStateDirectory(directory)
	if err != nil {
		return nil, fmt.Errorf("open nft recovery directory: %w", err)
	}
	// Keep subprocess reads, the lifecycle proof and the commit on this thread's
	// namespace. close is called on this same goroutine on every success/failure.
	runtime.LockOSThread()
	session := &nftDiskSession{store: s, dir: dir, name: name, threadLocked: true}
	fail := func(err error) (*nftDiskSession, error) { session.close(); return nil, err }
	if err := s.inject("lock"); err != nil {
		return fail(err)
	}
	fd, err := unix.Openat(int(dir.Fd()), name+".lock", unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if err != nil {
		return fail(err)
	}
	session.lock = os.NewFile(uintptr(fd), name+".lock")
	if err := checkNFTStateFile(session.lock); err != nil {
		return fail(err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(fmt.Errorf("nft recovery writer is busy: %w", err))
	}
	session.context, err = nftCurrentDiskContext(s.configPath, owner)
	if err != nil {
		return fail(err)
	}
	session.record, err = session.read()
	archiveSource := name
	if err == nil && session.record == nil {
		// A rename may have completed before directory sync / the new prepare.
		// Absence of the main file is NOT a first-use marker when this exists.
		previous, readErr := session.readNamed(name + ".previous-boot")
		if readErr != nil {
			return fail(readErr)
		}
		if previous != nil {
			err = &nftDiskIdentityError{old: previous.Context}
			archiveSource = "" // already archived; do not overwrite it with emptiness
		}
	}
	if err != nil {
		var mismatch *nftDiskIdentityError
		if !errors.As(err, &mismatch) || !mismatch.newBootOnly(session.context) {
			return fail(err)
		}
		// NFT startup uses a separate, read-only current-instance risk proof.
		// CLI-free Go / standalone stores retain the strictly GLOBAL empty proof.
		// Never treat an unavailable scoped reader as successful emptiness.
		var proofErr error
		if len(bootProof) == 1 && bootProof[0] != nil {
			proofErr = bootProof[0](session.context)
		} else if len(bootProof) == 0 && s.verifyEmpty != nil {
			proofErr = s.verifyEmpty()
		} else {
			proofErr = errors.New("independent boot rollover proof is unavailable")
		}
		if proofErr != nil {
			return fail(errors.Join(err, proofErr))
		}
		current, contextErr := nftCurrentDiskContext(s.configPath, owner)
		if contextErr != nil || current != session.context {
			return fail(errors.New("lifecycle changed during boot rollover verification"))
		}
		if archiveSource != "" {
			// At most one protected historical record. Refuse to overwrite an
			// untrusted archive or one from the current lifecycle.
			previous, e := session.readNamed(name + ".previous-boot")
			if e != nil {
				return fail(e)
			}
			if previous != nil && !(&nftDiskIdentityError{old: previous.Context}).newBootOnly(session.context) {
				return fail(errors.New("previous-boot archive has a conflicting lifecycle or service identity"))
			}
			if e := s.inject("boot-archive"); e != nil {
				return fail(e)
			}
			if e := unix.Renameat(int(dir.Fd()), name, int(dir.Fd()), name+".previous-boot"); e != nil {
				return fail(e)
			}
		}
		if e := s.inject("boot-directory-sync"); e != nil {
			return fail(e)
		}
		if e := dir.Sync(); e != nil {
			return fail(e)
		}
		// Neither old Confirmed nor old Intent may authorize current deletion.
		session.record = nil
		session.rolledBoot = true
	}
	return session, nil
}
func (s *nftDiskSession) close() {
	if s.lock != nil {
		s.lock.Close()
		s.lock = nil
	}
	if s.dir != nil {
		s.dir.Close()
		s.dir = nil
	}
	if s.threadLocked {
		s.threadLocked = false
		runtime.UnlockOSThread()
	}
}
func (s *nftDiskSession) read() (*nftDiskRecord, error) {
	record, err := s.readNamed(s.name)
	if err == nil && record != nil && record.Context != s.context {
		return nil, &nftDiskIdentityError{old: record.Context}
	}
	return record, err
}

// Parse and authenticate the protected file before deciding whether its
// lifecycle can be inherited. Only read() returns current-lifecycle history.
func (s *nftDiskSession) readNamed(name string) (*nftDiskRecord, error) {
	fd, err := unix.Openat(int(s.dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err == unix.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	if err := checkNFTStateFile(file); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxNFTDiskBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxNFTDiskBytes {
		return nil, errors.New("nft recovery file exceeds size limit")
	}
	var envelope nftDiskEnvelope
	if err := strictNFTDiskJSON(data, &envelope); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(envelope.Payload)
	if envelope.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, errors.New("nft recovery checksum mismatch (not an authentication signature)")
	}
	var record nftDiskRecord
	if err := strictNFTDiskJSON(envelope.Payload, &record); err != nil {
		return nil, err
	}
	if record.Schema != 1 || (record.Phase != "prepare" && record.Phase != "checkpoint") || record.Generation == 0 || len(record.Instance) != 32 {
		return nil, errors.New("unsupported or incomplete nft recovery record")
	}
	if _, err := hex.DecodeString(record.Instance); err != nil {
		return nil, errors.New("invalid nft recovery instance")
	}
	for _, snap := range []nftDiskSnapshot{record.Confirmed, record.Intent} {
		if err := validateNFTDiskSnapshot(snap, s.context.Owner); err != nil {
			return nil, err
		}
	}
	return &record, nil
}

type nftDiskIdentityError struct{ old nftDiskContext }

func (e *nftDiskIdentityError) Error() string {
	return "nft recovery boot/namespace/config/mark/service identity mismatch; retain the record for verified recovery"
}
func (e *nftDiskIdentityError) newBootOnly(current nftDiskContext) bool {
	old := e.old
	return old.NetDevice != 0 && old.NetInode != 0 && old.NetCookie != 0 && old.BootID != current.BootID && validNFTBootID(old.BootID) && old.ConfigSHA256 == current.ConfigSHA256 && old.UID == current.UID && old.Owner == current.Owner && old.ZonePolicy == current.ZonePolicy
}
func strictNFTDiskJSON(data []byte, value any) error {
	// Duplicate object keys are ambiguous even when a JSON decoder accepts them.
	tokenDecoder := json.NewDecoder(bytes.NewReader(data))
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 64 {
			return errors.New("nft recovery JSON nesting exceeds bound")
		}
		tok, err := tokenDecoder.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		if delim == '{' {
			seen := map[string]bool{}
			for tokenDecoder.More() {
				key, err := tokenDecoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate nft recovery JSON field")
				}
				seen[name] = true
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
		} else if delim == '[' {
			for tokenDecoder.More() {
				if err := scan(depth + 1); err != nil {
					return err
				}
			}
		} else {
			return errors.New("invalid nft recovery JSON container")
		}
		_, err = tokenDecoder.Token()
		return err
	}
	if err := scan(0); err != nil {
		return errors.New("invalid or truncated nft recovery JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return errors.New("invalid or unknown nft recovery JSON fields")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing nft recovery JSON")
	}
	return nil
}
func diskNFTPaths(specs []nftRuleSpec) []nftDiskPath {
	result := make([]nftDiskPath, 0, len(specs))
	for _, spec := range uniqueNFTSpecs(specs) {
		identity := nftRuleIdentity(spec)
		spec.RuleID = ""
		spec.ruleIdentity = ""
		result = append(result, nftDiskPath{Identity: identity, Spec: spec})
	}
	return result
}
func (s nftDiskSnapshot) specs() (active, pending, suspended []nftRuleSpec) {
	decode := func(paths []nftDiskPath) []nftRuleSpec {
		result := make([]nftRuleSpec, 0, len(paths))
		for _, p := range paths {
			spec := p.Spec
			spec.ruleIdentity = p.Identity
			spec.RuleID = "kernel-" + p.Identity
			result = append(result, spec)
		}
		return result
	}
	return decode(s.Active), decode(s.Pending), decode(s.Suspended)
}
func diskNFTSnapshot(active, pending, suspended []nftRuleSpec) nftDiskSnapshot {
	return nftDiskSnapshot{Active: diskNFTPaths(active), Pending: diskNFTPaths(pending), Suspended: diskNFTPaths(suspended)}
}
func validateNFTDiskSnapshot(s nftDiskSnapshot, owner string) error {
	if len(s.Active)+len(s.Pending)+len(s.Suspended) > maxNFTRetiredSpecs {
		return errors.New("nft recovery path count exceeds limit")
	}
	for _, group := range [][]nftDiskPath{s.Active, s.Pending, s.Suspended} {
		seen := map[string]bool{}
		for _, p := range group {
			if !validNFTIdentity(p.Identity) || p.Spec.RuleID != "" || nftOwnerMarker(p.Spec.ConntrackMark) != owner {
				return errors.New("invalid nft recovery ownership")
			}
			if err := validateRetirementSpec(p.Spec); err != nil {
				return err
			}
			spec := p.Spec
			spec.ruleIdentity = p.Identity
			key := nftRetirementKey(spec)
			if seen[key] {
				return errors.New("duplicate nft recovery path")
			}
			seen[key] = true
		}
	}
	return nil
}
func (s *nftDiskSession) binding(kernelBinding string) (string, error) {
	prefix := "pb-disk:v1:" + s.context.ConfigSHA256 + ":"
	if kernelBinding != "" {
		if !strings.HasPrefix(kernelBinding, prefix) || len(kernelBinding) != len(prefix)+32 {
			return "", errors.New("owned table is bound to another recovery configuration")
		}
		if _, err := hex.DecodeString(strings.TrimPrefix(kernelBinding, prefix)); err != nil {
			return "", errors.New("invalid kernel recovery instance")
		}
	}
	if s.record == nil {
		var instance string
		if kernelBinding != "" {
			instance = strings.TrimPrefix(kernelBinding, prefix)
		} else {
			var random [16]byte
			if _, err := rand.Read(random[:]); err != nil {
				return "", err
			}
			instance = hex.EncodeToString(random[:])
		}
		s.record = &nftDiskRecord{Schema: 1, Context: s.context, Instance: instance}
	}
	want := prefix + s.record.Instance
	if kernelBinding != "" && kernelBinding != want {
		return "", errors.New("kernel and disk recovery instances disagree")
	}
	return want, nil
}
func (s *nftDiskSession) prepare(confirmed, intent nftDiskSnapshot) error {
	if s.record == nil {
		return errors.New("recovery identity was not established")
	}
	if s.record.Generation == ^uint64(0) {
		return errors.New("recovery generation exhausted")
	}
	next := *s.record
	next.Generation++
	next.Phase = "prepare"
	next.Confirmed = confirmed
	next.Intent = intent
	return s.save(&next)
}
func (s *nftDiskSession) checkpoint(confirmed nftDiskSnapshot) error {
	if s.record == nil || s.record.Generation == 0 {
		return errors.New("recovery prepare is missing")
	}
	next := *s.record
	next.Phase = "checkpoint"
	next.Confirmed = confirmed
	next.Intent = nftDiskSnapshot{}
	return s.save(&next)
}
func (s *nftDiskSession) save(record *nftDiskRecord) error {
	if err := validateNFTDiskSnapshot(record.Confirmed, s.context.Owner); err != nil {
		return err
	}
	if err := validateNFTDiskSnapshot(record.Intent, s.context.Owner); err != nil {
		return err
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	data, err := json.Marshal(nftDiskEnvelope{Payload: payload, SHA256: hex.EncodeToString(sum[:])})
	if err != nil {
		return err
	}
	if len(data) > maxNFTDiskBytes {
		return errors.New("nft recovery serialization exceeds size limit")
	}
	if err := s.store.inject("create"); err != nil {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temp := ".pb-nft-" + hex.EncodeToString(random[:]) + ".tmp"
	fd, err := unix.Openat(int(s.dir.Fd()), temp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), temp)
	defer func() { file.Close(); _ = unix.Unlinkat(int(s.dir.Fd()), temp, 0) }()
	if err := s.store.inject("write"); err != nil {
		return err
	}
	written, err := file.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := s.store.inject("file-sync"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := s.store.inject("rename"); err != nil {
		return err
	}
	if err := unix.Renameat(int(s.dir.Fd()), temp, int(s.dir.Fd()), s.name); err != nil {
		return err
	}
	if err := s.store.inject("directory-sync"); err != nil {
		return err
	}
	if err := s.dir.Sync(); err != nil {
		return err
	}
	s.record = record
	return nil
}

// A CLI-free Go path does not create a recovery file. If one already exists it
// must still be readable, correctly bound and intact. Missing files are NOT
// proof of cleanliness; verifyEmptyNetfilter supplies the independent proof.
func (s *nftStateStore) checkExisting(owner string) error {
	directory, name, err := s.paths()
	if err != nil {
		return err
	}
	dir, err := openNFTStateDirectory(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	var st unix.Stat_t
	err = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if err == unix.ENOENT {
		err = unix.Fstatat(int(dir.Fd()), name+".previous-boot", &st, unix.AT_SYMLINK_NOFOLLOW)
		if err == unix.ENOENT {
			return nil
		}
	}
	if err != nil {
		return err
	}
	// Existing state needs the same bounded writer lock as normal recovery.
	session, err := s.begin(owner)
	if err != nil {
		return err
	}
	defer session.close()
	return nil
}

func sameNFTDiskSnapshot(a, b nftDiskSnapshot) bool {
	x, err := json.Marshal(a)
	if err != nil {
		return false
	}
	y, err := json.Marshal(b)
	return err == nil && bytes.Equal(x, y)
}
