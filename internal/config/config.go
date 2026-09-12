package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const CurrentVersion = 2

const MaxWhitelistEntries = 1024

const MaxPortRangeSize = 4096

const MaxRules = 1024

const DefaultNFTConntrackMark uint32 = 0x50420001

const (
	ProtocolTCP  = "tcp"
	ProtocolUDP  = "udp"
	ProtocolBoth = "both"

	RuleDataPlaneNFT = "nftables"
	RuleDataPlaneGo  = "go"

	TLSMinVersion12 = "1.2"
	TLSMinVersion13 = "1.3"
)

type WebConfig struct {
	Port              int      `json:"port"`
	ListenIPv4        string   `json:"listen_ipv4"`
	ListenIPv6        string   `json:"listen_ipv6"`
	AutoLANACL        bool     `json:"auto_lan_acl"`
	StrictIPAllowlist bool     `json:"strict_ip_allowlist,omitempty"`
	AllowInsecureHTTP bool     `json:"allow_insecure_http,omitempty"`
	RequireHTTPS      bool     `json:"require_https,omitempty"`
	AllowUnsafeAllACL bool     `json:"allow_unsafe_all_address_acl,omitempty"`
	Whitelist         []string `json:"whitelist"`
	TLSCertFile       string   `json:"tls_cert_file,omitempty"`
	TLSKeyFile        string   `json:"tls_key_file,omitempty"`
	TLSMinVersion     string   `json:"tls_min_version,omitempty"`
	DNSServers        []string `json:"dns_servers"`
	AdminTokenSHA     string   `json:"admin_token_sha256"`
}

type ResourceLimits struct {
	MaxTCPConnections int   `json:"max_tcp_connections"`
	MaxUDPSessions    int   `json:"max_udp_sessions"`
	MaxUDPMemoryBytes int64 `json:"max_udp_memory_bytes"`
}

type NFTConfig struct {
	ConntrackMark   uint32 `json:"conntrack_mark"`
	EnableFlowtable bool   `json:"enable_flowtable"`
}

type Rule struct {
	ID                     string   `json:"id"`
	Name                   string   `json:"name"`
	Protocol               string   `json:"protocol"`
	DataPlane              string   `json:"data_plane,omitempty"`
	ListenHost             string   `json:"listen_host"`
	ListenPort             int      `json:"listen_port"`
	ListenPortEnd          int      `json:"listen_port_end,omitempty"`
	TargetHost             string   `json:"target_host"`
	TargetPort             int      `json:"target_port"`
	TargetPortEnd          int      `json:"target_port_end,omitempty"`
	Enabled                bool     `json:"enabled"`
	ConnectTimeoutSeconds  int      `json:"connect_timeout_seconds"`
	TCPIdleTimeoutSeconds  int      `json:"tcp_idle_timeout_seconds"`
	MaxTCPConnections      int      `json:"max_tcp_connections"`
	MaxTCPConnectionsPerIP int      `json:"max_tcp_connections_per_source"`
	UDPIdleTimeoutSeconds  int      `json:"udp_idle_timeout_seconds"`
	MaxUDPSessions         int      `json:"max_udp_sessions"`
	MaxUDPSessionsPerIP    int      `json:"max_udp_sessions_per_source"`
	UDPNewSessionsPerSec   int      `json:"udp_new_sessions_per_second_per_source"`
	UDPPacketsPerSec       int      `json:"udp_packets_per_second_per_source"`
	UDPWorkers             int      `json:"udp_workers,omitempty"`
	UDPBatchSize           int      `json:"udp_batch_size,omitempty"`
	UDPPacketBufferSize    int      `json:"udp_packet_buffer_size,omitempty"`
	UDPListenerBufferBytes int      `json:"udp_listener_buffer_bytes,omitempty"`
	UDPSessionBufferBytes  int      `json:"udp_session_buffer_bytes,omitempty"`
	AllowPrivateTarget     bool     `json:"allow_private_target,omitempty"`
	TargetCIDRAllowlist    []string `json:"target_cidr_allowlist,omitempty"`
}

type Config struct {
	Version int            `json:"version"`
	Web     WebConfig      `json:"web"`
	Limits  ResourceLimits `json:"resource_limits"`
	NFT     NFTConfig      `json:"nftables"`
	Rules   []Rule         `json:"rules"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

func Default() Config {
	return Config{
		Version: CurrentVersion,
		Web: WebConfig{
			Port:       9080,
			ListenIPv4: "127.0.0.1",
			ListenIPv6: "::1",
			AutoLANACL: false,
			Whitelist:  []string{},
			DNSServers: []string{},
		},
		Limits: ResourceLimits{
			MaxTCPConnections: 8192,
			MaxUDPSessions:    16384,
			MaxUDPMemoryBytes: 1024 * 1024 * 1024,
		},
		NFT:   NFTConfig{ConntrackMark: DefaultNFTConntrackMark, EnableFlowtable: true},
		Rules: []Rule{},
	}
}

func LoadOrCreate(path, tokenFile string) (*Store, string, error) {
	if path == "" {
		return nil, "", errors.New("config path is empty")
	}
	cfg := Default()
	existed := false
	data, err := os.ReadFile(path) // #nosec G304 -- the local administrator explicitly selects the configuration path on process startup.
	if err == nil {
		existed = true
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, "", fmt.Errorf("decode config: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("read config: %w", err)
	}
	if !existed {
		mark, err := generateNFTConntrackMark()
		if err != nil {
			return nil, "", err
		}
		cfg.NFT.ConntrackMark = mark
	}

	if existed && (cfg.Version == 0 || cfg.Version == 1) {
		migrateV1(&cfg)
	} else if cfg.Version == 0 {
		cfg.Version = CurrentVersion
	}
	if cfg.Web.Port == 0 {
		cfg.Web.Port = 9080
	}
	if cfg.Web.ListenIPv4 == "" && cfg.Web.ListenIPv6 == "" {
		cfg.Web.ListenIPv4 = "127.0.0.1"
		cfg.Web.ListenIPv6 = "::1"
	}
	cfg.Web.TLSCertFile = strings.TrimSpace(cfg.Web.TLSCertFile)
	cfg.Web.TLSKeyFile = strings.TrimSpace(cfg.Web.TLSKeyFile)
	cfg.Web.TLSMinVersion = strings.TrimSpace(cfg.Web.TLSMinVersion)
	normalizedDNS, err := NormalizeDNSServers(cfg.Web.DNSServers)
	if err != nil {
		return nil, "", err
	}
	cfg.Web.DNSServers = normalizedDNS
	applyConfigDefaults(&cfg)

	generatedToken := ""
	if cfg.Web.AdminTokenSHA == "" {
		token, err := GenerateToken()
		if err != nil {
			return nil, "", err
		}
		generatedToken = token
		cfg.Web.AdminTokenSHA = HashToken(token)
	}
	if err := Validate(cfg); err != nil {
		return nil, "", err
	}

	if generatedToken != "" && tokenFile != "" {
		if err := writeSecret(tokenFile, generatedToken+"\n"); err != nil {
			return nil, "", fmt.Errorf("write token file: %w", err)
		}
	}
	s := &Store{path: path, cfg: cfg}
	if err := s.saveLocked(); err != nil {
		return nil, "", err
	}
	return s, generatedToken, nil
}

func generateNFTConntrackMark() (uint32, error) {
	for {
		var random [4]byte
		if _, err := rand.Read(random[:]); err != nil {
			return 0, fmt.Errorf("generate nftables instance mark: %w", err)
		}
		if mark := binary.BigEndian.Uint32(random[:]); mark != 0 {
			return mark, nil
		}
	}
}

func (s *Store) Path() string { return s.path }

func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.cfg)
}

func (s *Store) Update(fn func(*Config) error) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.updateLocked(fn)
}

func (s *Store) updateLocked(fn func(*Config) error) (Config, error) {
	candidate := clone(s.cfg)
	if err := fn(&candidate); err != nil {
		return Config{}, err
	}
	candidate.Version = CurrentVersion
	if err := Validate(candidate); err != nil {
		return Config{}, err
	}
	old := s.cfg
	s.cfg = candidate
	if err := s.saveLocked(); err != nil {
		s.cfg = old
		return Config{}, err
	}
	return clone(candidate), nil
}

func (s *Store) saveLocked() error {
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	if err := writeFileAtomic(s.path, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func writeSecret(path, value string) error {
	return writeFileAtomic(path, []byte(value), 0o600)
}

// writeFileAtomic creates an unpredictable temporary file in the destination
// directory and renames it into place. This avoids following a pre-created
// temporary-file symlink while keeping credentials and configuration on the
// same filesystem for an atomic replacement.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write temporary file: %w", err)
	}
	// CreateTemp starts at 0600. Keep that restrictive mode while data is
	// incomplete, then apply the final mode before publishing the file.
	if err := tmp.Chmod(mode); err != nil {
		return fmt.Errorf("set temporary file mode: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace destination: %w", err)
	}
	return nil
}

func (s *Store) RotateAdminToken(tokenFile string) (string, error) {
	token, err := GenerateToken()
	if err != nil {
		return "", err
	}
	// Serialize the entire two-file transaction, including rollback. Locking
	// only the configuration update allows concurrent rotations to publish
	// the token file and its hash in different orders.
	s.mu.Lock()
	defer s.mu.Unlock()
	var oldToken []byte
	oldTokenExisted := false
	if tokenFile != "" {
		// #nosec G304 -- tokenFile is an administrator-selected startup path, not remote input.
		if data, readErr := os.ReadFile(tokenFile); readErr == nil {
			oldToken, oldTokenExisted = data, true
		} else if !errors.Is(readErr, os.ErrNotExist) {
			return "", fmt.Errorf("read previous token file: %w", readErr)
		}
		if err := writeSecret(tokenFile, token+"\n"); err != nil {
			return "", fmt.Errorf("write token file: %w", err)
		}
	}
	if _, err := s.updateLocked(func(c *Config) error {
		c.Web.AdminTokenSHA = HashToken(token)
		return nil
	}); err != nil {
		if tokenFile != "" {
			// A failed rollback leaves the token file inconsistent with the
			// persisted hash; startup reports this and --reset-admin-token
			// recovers. Never silently swallow the restore failure.
			var rollbackErr error
			if oldTokenExisted {
				rollbackErr = writeSecret(tokenFile, string(oldToken))
			} else {
				rollbackErr = os.Remove(tokenFile)
			}
			if rollbackErr != nil {
				return "", fmt.Errorf("rotate admin token: %w; additionally failed to restore the previous token file: %w; stop the service and run 'portbridge --reset-admin-token' with the same config/token paths and file owner, then restart", err, rollbackErr)
			}
		}
		return "", err
	}
	return token, nil
}

// TokenFileConsistent reports whether the token file content matches the
// configured admin-token hash. A mismatch or an unreadable file means an
// interrupted rotation or a deleted token file: the service keeps running on
// the configured hash, but the file no longer holds a usable token and must
// be recovered with 'portbridge --reset-admin-token'.
func TokenFileConsistent(path, adminTokenSHA string) bool {
	if path == "" || adminTokenSHA == "" {
		return true
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is an administrator-selected startup path, not remote input.
	if err != nil {
		return false
	}
	return HashToken(strings.TrimSpace(string(data))) == adminTokenSHA
}

func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate admin token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func NewRuleID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func NormalizeRule(r Rule) Rule {
	r.Name = strings.TrimSpace(r.Name)
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	r.DataPlane = strings.ToLower(strings.TrimSpace(r.DataPlane))
	if r.DataPlane == "" {
		r.DataPlane = RuleDataPlaneNFT
	}
	r.ListenHost = normalizeHost(r.ListenHost)
	r.TargetHost = normalizeHost(r.TargetHost)
	if r.ListenHost == "" {
		r.ListenHost = "*"
	}
	if r.ConnectTimeoutSeconds == 0 {
		r.ConnectTimeoutSeconds = 10
	}
	if r.TCPIdleTimeoutSeconds == 0 {
		r.TCPIdleTimeoutSeconds = 300
	}
	if r.MaxTCPConnections == 0 {
		r.MaxTCPConnections = 2048
	}
	if r.MaxTCPConnectionsPerIP == 0 {
		r.MaxTCPConnectionsPerIP = 256
	}
	if r.UDPIdleTimeoutSeconds == 0 {
		r.UDPIdleTimeoutSeconds = 60
	}
	if r.MaxUDPSessions == 0 {
		r.MaxUDPSessions = 4096
	}
	if r.MaxUDPSessionsPerIP == 0 {
		r.MaxUDPSessionsPerIP = 512
	}
	if r.UDPNewSessionsPerSec == 0 {
		r.UDPNewSessionsPerSec = 1000
	}
	if r.UDPPacketsPerSec == 0 {
		r.UDPPacketsPerSec = 100000
	}
	if r.UDPBatchSize == 0 {
		r.UDPBatchSize = 64
	}
	if r.UDPPacketBufferSize == 0 {
		r.UDPPacketBufferSize = 2048
	}
	if r.UDPListenerBufferBytes == 0 {
		r.UDPListenerBufferBytes = 4 * 1024 * 1024
	}
	if r.UDPSessionBufferBytes == 0 {
		r.UDPSessionBufferBytes = 64 * 1024
	}
	for i := range r.TargetCIDRAllowlist {
		r.TargetCIDRAllowlist[i] = strings.TrimSpace(r.TargetCIDRAllowlist[i])
	}
	if normalized, err := NormalizeTargetCIDRs(r.TargetCIDRAllowlist); err == nil {
		r.TargetCIDRAllowlist = normalized
	}
	return r
}

func (r Rule) LastListenPort() int {
	if r.ListenPortEnd == 0 {
		return r.ListenPort
	}
	return r.ListenPortEnd
}

func (r Rule) LastTargetPort() int {
	if r.TargetPortEnd == 0 {
		return r.TargetPort
	}
	return r.TargetPortEnd
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	if len(host) >= 2 && strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimSpace(host[1 : len(host)-1])
	}
	return host
}

func applyConfigDefaults(cfg *Config) {
	if cfg.Limits.MaxTCPConnections == 0 {
		cfg.Limits.MaxTCPConnections = 8192
	}
	if cfg.Limits.MaxUDPSessions == 0 {
		cfg.Limits.MaxUDPSessions = 16384
	}
	if cfg.Limits.MaxUDPMemoryBytes == 0 {
		cfg.Limits.MaxUDPMemoryBytes = 1024 * 1024 * 1024
	}
	if cfg.NFT.ConntrackMark == 0 {
		cfg.NFT.ConntrackMark = DefaultNFTConntrackMark
	}
}

// migrateV1 preserves the behavior of an existing configuration-version-1 deployment while
// recording every security-sensitive exception explicitly in the v2 schema.
// Unprepared development configurations use loopback HTTP; installers provision
// required HTTPS before the first service start. Local/private targets are denied.
func migrateV1(cfg *Config) {
	cfg.Version = CurrentVersion
	if cfg.Web.TLSCertFile == "" && cfg.Web.TLSKeyFile == "" && webHasNonLoopbackListener(cfg.Web) {
		cfg.Web.AllowInsecureHTTP = true
	}
	cfg.NFT.ConntrackMark = DefaultNFTConntrackMark
	cfg.NFT.EnableFlowtable = true
	applyConfigDefaults(cfg)
	legacyPrivateCIDRs := []string{"10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}
	for i := range cfg.Rules {
		legacy := cfg.Rules[i]
		// Translate the old release defaults to the new bounded defaults. Without
		// this step, a normal v1 max_udp_sessions value (65536) exceeds the new
		// global default and prevents the service from starting after upgrade.
		if legacy.MaxUDPSessions == 65536 {
			legacy.MaxUDPSessions = 0
		}
		if legacy.UDPSessionBufferBytes == 256*1024 {
			legacy.UDPSessionBufferBytes = 0
		}
		r := NormalizeRule(legacy)
		if r.MaxTCPConnections > cfg.Limits.MaxTCPConnections {
			r.MaxTCPConnections = cfg.Limits.MaxTCPConnections
		}
		if r.MaxTCPConnectionsPerIP > r.MaxTCPConnections {
			r.MaxTCPConnectionsPerIP = r.MaxTCPConnections
		}
		if r.MaxUDPSessions > cfg.Limits.MaxUDPSessions {
			r.MaxUDPSessions = cfg.Limits.MaxUDPSessions
		}
		if r.MaxUDPSessionsPerIP > r.MaxUDPSessions {
			r.MaxUDPSessionsPerIP = r.MaxUDPSessions
		}
		// Old configurations allowed any resolved destination. Preserve local
		// forwarding only through an explicit, bounded exception list.
		r.AllowPrivateTarget = true
		if len(r.TargetCIDRAllowlist) == 0 {
			r.TargetCIDRAllowlist = append([]string(nil), legacyPrivateCIDRs...)
		}
		cfg.Rules[i] = r
	}
}

func webHasNonLoopbackListener(web WebConfig) bool {
	for _, raw := range []string{web.ListenIPv4, web.ListenIPv6} {
		if raw == "" {
			continue
		}
		ip, err := netip.ParseAddr(raw)
		if err == nil && !ip.IsLoopback() {
			return true
		}
	}
	return false
}

func Validate(cfg Config) error {
	if cfg.Version != CurrentVersion {
		return fmt.Errorf("unsupported config version %d", cfg.Version)
	}
	if cfg.Web.Port < 1 || cfg.Web.Port > 65535 {
		return errors.New("web port must be 1-65535")
	}
	for _, host := range []string{cfg.Web.ListenIPv4, cfg.Web.ListenIPv6} {
		if host == "" {
			continue
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("web listen address %q must be an IP literal", host)
		}
		if ip.IsMulticast() || ip.IsUnspecified() && host != "0.0.0.0" && host != "::" {
			return fmt.Errorf("invalid web listen address %q", host)
		}
	}
	if cfg.Web.TLSCertFile == "" && cfg.Web.TLSKeyFile == "" && webHasNonLoopbackListener(cfg.Web) && !cfg.Web.AllowInsecureHTTP {
		return errors.New("non-loopback web listeners require TLS, or the explicit allow_insecure_http risk acknowledgement")
	}
	normalizedWhitelist, err := NormalizeWhitelist(cfg.Web.Whitelist)
	if err != nil {
		return err
	}
	certFile := strings.TrimSpace(cfg.Web.TLSCertFile)
	keyFile := strings.TrimSpace(cfg.Web.TLSKeyFile)
	if cfg.Web.RequireHTTPS && (certFile == "" || keyFile == "" || cfg.Web.AllowInsecureHTTP) {
		return errors.New("this deployment requires HTTPS: certificate/key cannot be cleared and insecure HTTP cannot be enabled")
	}
	if (certFile == "") != (keyFile == "") {
		return errors.New("web TLS certificate and key files must be configured together")
	}
	switch cfg.Web.TLSMinVersion {
	case "", TLSMinVersion12, TLSMinVersion13:
	default:
		return fmt.Errorf("web tls_min_version must be %q or %q", TLSMinVersion12, TLSMinVersion13)
	}
	for label, path := range map[string]string{"certificate": certFile, "key": keyFile} {
		if path != "" && !filepath.IsAbs(path) {
			return fmt.Errorf("web TLS %s file must use an absolute path", label)
		}
	}
	for _, raw := range normalizedWhitelist {
		prefix := netip.MustParsePrefix(raw)
		if prefix.Bits() == 0 && !cfg.Web.AllowUnsafeAllACL {
			return fmt.Errorf("web whitelist rejects all-address prefix %q unless allow_unsafe_all_address_acl is explicitly enabled", raw)
		}
	}
	if cfg.Web.StrictIPAllowlist {
		if cfg.Web.AutoLANACL {
			return errors.New("strict IP allowlist mode cannot be combined with automatic LAN ACL")
		}
		if len(normalizedWhitelist) == 0 {
			return errors.New("strict IP allowlist mode requires at least one explicit whitelist entry")
		}
		if certFile == "" {
			return errors.New("strict IP allowlist mode requires native TLS certificate and key files")
		}
		for _, raw := range normalizedWhitelist {
			if netip.MustParsePrefix(raw).Bits() == 0 {
				return fmt.Errorf("strict IP allowlist mode rejects all-address prefix %q", raw)
			}
		}
	}
	if cfg.Limits.MaxTCPConnections < 1 || cfg.Limits.MaxTCPConnections > 1_000_000 {
		return errors.New("global max TCP connections must be 1-1000000")
	}
	if cfg.Limits.MaxUDPSessions < 1 || cfg.Limits.MaxUDPSessions > 10_000_000 {
		return errors.New("global max UDP sessions must be 1-10000000")
	}
	if cfg.Limits.MaxUDPMemoryBytes < 64*1024*1024 || cfg.Limits.MaxUDPMemoryBytes > 1<<40 {
		return errors.New("global UDP memory budget must be 67108864-1099511627776 bytes")
	}
	if cfg.NFT.ConntrackMark == 0 {
		return errors.New("nftables conntrack mark must be non-zero")
	}
	if cfg.Web.AdminTokenSHA != "" {
		tokenHash, err := hex.DecodeString(cfg.Web.AdminTokenSHA)
		if err != nil || len(tokenHash) != sha256.Size {
			return errors.New("admin token SHA-256 must contain exactly 64 hexadecimal characters")
		}
	}
	if _, err := NormalizeDNSServers(cfg.Web.DNSServers); err != nil {
		return err
	}
	if len(cfg.Rules) > MaxRules {
		return fmt.Errorf("configuration may contain at most %d rules", MaxRules)
	}

	seenIDs := make(map[string]struct{}, len(cfg.Rules))
	for i := range cfg.Rules {
		r := NormalizeRule(cfg.Rules[i])
		if r.ID == "" {
			return fmt.Errorf("rule %d has empty id", i)
		}
		if _, ok := seenIDs[r.ID]; ok {
			return fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seenIDs[r.ID] = struct{}{}
		if r.Name == "" {
			return fmt.Errorf("rule %q name is empty", r.ID)
		}
		if len(r.Name) > 80 {
			return fmt.Errorf("rule %q name may contain at most 80 bytes", r.ID)
		}
		if len(r.ID) > 128 {
			return fmt.Errorf("rule id may contain at most 128 bytes")
		}
		if r.Protocol != ProtocolTCP && r.Protocol != ProtocolUDP && r.Protocol != ProtocolBoth {
			return fmt.Errorf("rule %q protocol must be tcp, udp, or both", r.ID)
		}
		if r.DataPlane != RuleDataPlaneNFT && r.DataPlane != RuleDataPlaneGo {
			return fmt.Errorf("rule %q data plane must be nftables or go", r.ID)
		}
		listenEnd, targetEnd := r.LastListenPort(), r.LastTargetPort()
		if r.ListenPort < 1 || r.ListenPort > 65535 || listenEnd < 1 || listenEnd > 65535 ||
			r.TargetPort < 1 || r.TargetPort > 65535 || targetEnd < 1 || targetEnd > 65535 {
			return fmt.Errorf("rule %q port must be 1-65535", r.ID)
		}
		if listenEnd < r.ListenPort {
			return fmt.Errorf("rule %q listen port range end must not be less than start", r.ID)
		}
		if targetEnd < r.TargetPort {
			return fmt.Errorf("rule %q target port range end must not be less than start", r.ID)
		}
		if listenEnd-r.ListenPort != targetEnd-r.TargetPort {
			return fmt.Errorf("rule %q listen and target port ranges must have the same size", r.ID)
		}
		if listenEnd-r.ListenPort+1 > MaxPortRangeSize {
			return fmt.Errorf("rule %q port range may contain at most %d ports", r.ID, MaxPortRangeSize)
		}
		if r.TargetHost == "" {
			return fmt.Errorf("rule %q target host is empty", r.ID)
		}
		if len(r.TargetHost) > 253 {
			return fmt.Errorf("rule %q target host may contain at most 253 bytes", r.ID)
		}
		if r.ListenHost != "*" {
			ip, err := netip.ParseAddr(r.ListenHost)
			if err != nil {
				return fmt.Errorf("rule %q listen host must be *, IPv4, or IPv6 literal", r.ID)
			}
			if ip.IsMulticast() {
				return fmt.Errorf("rule %q listen host cannot be multicast", r.ID)
			}
		}
		if r.ConnectTimeoutSeconds < 1 || r.ConnectTimeoutSeconds > 300 {
			return fmt.Errorf("rule %q connect timeout must be 1-300 seconds", r.ID)
		}
		if r.TCPIdleTimeoutSeconds < 5 || r.TCPIdleTimeoutSeconds > 86400 {
			return fmt.Errorf("rule %q TCP idle timeout must be 5-86400 seconds", r.ID)
		}
		if r.MaxTCPConnections < 1 || r.MaxTCPConnections > cfg.Limits.MaxTCPConnections {
			return fmt.Errorf("rule %q max TCP connections must be 1-%d", r.ID, cfg.Limits.MaxTCPConnections)
		}
		if r.MaxTCPConnectionsPerIP < 1 || r.MaxTCPConnectionsPerIP > r.MaxTCPConnections {
			return fmt.Errorf("rule %q per-source TCP limit must be 1-%d", r.ID, r.MaxTCPConnections)
		}
		if r.UDPIdleTimeoutSeconds < 5 || r.UDPIdleTimeoutSeconds > 86400 {
			return fmt.Errorf("rule %q UDP idle timeout must be 5-86400 seconds", r.ID)
		}
		if r.MaxUDPSessions < 1 || r.MaxUDPSessions > 10_000_000 {
			return fmt.Errorf("rule %q max UDP sessions must be 1-10000000", r.ID)
		}
		if r.MaxUDPSessions > cfg.Limits.MaxUDPSessions {
			return fmt.Errorf("rule %q max UDP sessions exceeds global limit %d", r.ID, cfg.Limits.MaxUDPSessions)
		}
		if r.MaxUDPSessionsPerIP < 1 || r.MaxUDPSessionsPerIP > r.MaxUDPSessions {
			return fmt.Errorf("rule %q per-source UDP session limit must be 1-%d", r.ID, r.MaxUDPSessions)
		}
		if r.UDPNewSessionsPerSec < 1 || r.UDPNewSessionsPerSec > 10_000_000 {
			return fmt.Errorf("rule %q UDP new-session rate must be 1-10000000 per second", r.ID)
		}
		if r.UDPPacketsPerSec < 1 || r.UDPPacketsPerSec > 100_000_000 {
			return fmt.Errorf("rule %q UDP packet rate must be 1-100000000 per second", r.ID)
		}
		if r.UDPWorkers < 0 || r.UDPWorkers > 128 {
			return fmt.Errorf("rule %q UDP workers must be 0-128 (0 means auto)", r.ID)
		}
		if r.UDPBatchSize < 1 || r.UDPBatchSize > 256 {
			return fmt.Errorf("rule %q UDP batch size must be 1-256", r.ID)
		}
		if r.UDPPacketBufferSize < 512 || r.UDPPacketBufferSize > 65535 {
			return fmt.Errorf("rule %q UDP packet buffer size must be 512-65535 bytes", r.ID)
		}
		if r.UDPListenerBufferBytes < 64*1024 || r.UDPListenerBufferBytes > 256*1024*1024 {
			return fmt.Errorf("rule %q UDP listener buffer must be 65536-268435456 bytes", r.ID)
		}
		if r.UDPSessionBufferBytes < 64*1024 || r.UDPSessionBufferBytes > 16*1024*1024 {
			return fmt.Errorf("rule %q UDP session buffer must be 65536-16777216 bytes", r.ID)
		}
		normalizedTargets, err := NormalizeTargetCIDRs(r.TargetCIDRAllowlist)
		if err != nil {
			return fmt.Errorf("rule %q: %w", r.ID, err)
		}
		if r.AllowPrivateTarget && len(normalizedTargets) == 0 {
			return fmt.Errorf("rule %q allows local/private targets but has no target CIDR allowlist", r.ID)
		}
		if address, err := netip.ParseAddr(r.TargetHost); err == nil {
			if err := ValidateTargetAddress(r, address); err != nil {
				return fmt.Errorf("rule %q target: %w", r.ID, err)
			}
		}
	}
	if err := validateRuleConflicts(cfg.Rules); err != nil {
		return err
	}
	return nil
}

func NormalizeWhitelist(items []string) ([]string, error) {
	set := make(map[string]struct{})
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if ip, err := netip.ParseAddr(s); err == nil {
			ip = ip.Unmap()
			bits := 128
			if ip.Is4() {
				bits = 32
			}
			set[netip.PrefixFrom(ip, bits).String()] = struct{}{}
			continue
		}
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid whitelist entry %q; use an IP or CIDR", s)
		}
		if prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("IPv4-mapped IPv6 whitelist entry %q is not supported; use plain IPv4 CIDR", s)
		}
		set[prefix.Masked().String()] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) > MaxWhitelistEntries {
		return nil, fmt.Errorf("whitelist may contain at most %d entries", MaxWhitelistEntries)
	}
	return out, nil
}

func NormalizeTargetCIDRs(items []string) ([]string, error) {
	const maxTargetCIDRs = 64
	set := make(map[string]struct{})
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid target CIDR %q", s)
		}
		if prefix.Addr().Is4In6() {
			return nil, fmt.Errorf("IPv4-mapped IPv6 target CIDR %q is not supported", s)
		}
		prefix = prefix.Masked()
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("target CIDR allowlist rejects all-address prefix %q", s)
		}
		set[prefix.String()] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for prefix := range set {
		out = append(out, prefix)
	}
	sort.Strings(out)
	if len(out) > maxTargetCIDRs {
		return nil, fmt.Errorf("target CIDR allowlist may contain at most %d entries", maxTargetCIDRs)
	}
	return out, nil
}

var restrictedTargetPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("100.100.100.200/32"),
}

// ValidateTargetAddress is applied both to literal targets and every DNS
// refresh result. This prevents DNS rebinding from bypassing the configured
// local/private destination policy.
func ValidateTargetAddress(rule Rule, address netip.Addr) error {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() ||
		(!address.IsGlobalUnicast() && !address.IsLoopback() && !address.IsLinkLocalUnicast()) {
		return fmt.Errorf("address %q is not a valid unicast target", address)
	}
	restricted := address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsPrivate()
	for _, prefix := range restrictedTargetPrefixes {
		if prefix.Contains(address) {
			restricted = true
			break
		}
	}
	if !restricted {
		return nil
	}
	if !rule.AllowPrivateTarget {
		return fmt.Errorf("local/private target %s is denied by default", address)
	}
	allowlist, err := NormalizeTargetCIDRs(rule.TargetCIDRAllowlist)
	if err != nil {
		return err
	}
	for _, raw := range allowlist {
		if netip.MustParsePrefix(raw).Contains(address) {
			return nil
		}
	}
	return fmt.Errorf("local/private target %s is outside target_cidr_allowlist", address)
}

func NormalizeDNSServers(items []string) ([]string, error) {
	const maxDNSServers = 8
	seen := make(map[string]struct{})
	out := make([]string, 0, len(items))
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		host, port := s, "53"
		if ip, err := netip.ParseAddr(s); err == nil {
			host = ip.Unmap().String()
		} else {
			var splitErr error
			host, port, splitErr = net.SplitHostPort(s)
			if splitErr != nil {
				return nil, fmt.Errorf("invalid DNS server %q; use an IP or IP:port", s)
			}
			ip, parseErr := netip.ParseAddr(host)
			if parseErr != nil {
				return nil, fmt.Errorf("DNS server %q must use an IP literal", s)
			}
			host = ip.Unmap().String()
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, fmt.Errorf("DNS server %q port must be 1-65535", s)
		}
		endpoint := net.JoinHostPort(host, strconv.Itoa(portNumber))
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		out = append(out, endpoint)
		if len(out) > maxDNSServers {
			return nil, fmt.Errorf("at most %d DNS servers may be configured", maxDNSServers)
		}
	}
	return out, nil
}

func validateRuleConflicts(rules []Rule) error {
	for i := 0; i < len(rules); i++ {
		a := NormalizeRule(rules[i])
		if !a.Enabled {
			continue
		}
		for j := i + 1; j < len(rules); j++ {
			b := NormalizeRule(rules[j])
			if !b.Enabled || !protocolsOverlap(a.Protocol, b.Protocol) || !portRangesOverlap(a, b) {
				continue
			}
			if listenHostsOverlap(a.ListenHost, b.ListenHost) {
				return fmt.Errorf("enabled rules %q and %q have overlapping %s listen address on ports %s and %s", a.Name, b.Name, a.Protocol, portRangeText(a.ListenPort, a.LastListenPort()), portRangeText(b.ListenPort, b.LastListenPort()))
			}
		}
	}
	return nil
}

func protocolsOverlap(a, b string) bool {
	return a == b || a == ProtocolBoth || b == ProtocolBoth
}

func portRangesOverlap(a, b Rule) bool {
	return a.ListenPort <= b.LastListenPort() && b.ListenPort <= a.LastListenPort()
}

func portRangeText(start, end int) string {
	if start == end {
		return fmt.Sprintf("%d", start)
	}
	return fmt.Sprintf("%d-%d", start, end)
}

func listenHostsOverlap(a, b string) bool {
	if a == "*" || b == "*" {
		return true
	}
	ia, ea := netip.ParseAddr(a)
	ib, eb := netip.ParseAddr(b)
	if ea != nil || eb != nil || ia.BitLen() != ib.BitLen() {
		return false
	}
	if ia == ib {
		return true
	}
	if ia.IsUnspecified() || ib.IsUnspecified() {
		return true
	}
	return false
}

func clone(cfg Config) Config {
	out := cfg
	// Keep empty JSON collections as [] instead of changing them to null.
	// API consumers expect the same collection types that are persisted in
	// config.json, including when no whitelist entries or rules exist.
	out.Web.Whitelist = append([]string{}, cfg.Web.Whitelist...)
	out.Web.DNSServers = append([]string{}, cfg.Web.DNSServers...)
	out.Rules = append([]Rule{}, cfg.Rules...)
	for i := range out.Rules {
		out.Rules[i].TargetCIDRAllowlist = append([]string{}, cfg.Rules[i].TargetCIDRAllowlist...)
	}
	return out
}
