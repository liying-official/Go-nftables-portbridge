package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rewriteNFTRecord(t *testing.T, path string, mutate func(*nftDiskRecord)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env nftDiskEnvelope
	var record nftDiskRecord
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(env.Payload, &record); err != nil {
		t.Fatal(err)
	}
	mutate(&record)
	env.Payload, err = json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(env.Payload)
	env.SHA256 = hex.EncodeToString(sum[:])
	data, err = json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestNFTIndependentStoreRejectsUntrustedRecords(t *testing.T) {
	for _, kind := range []string{"corrupt", "truncated", "schema", "namespace", "cookie", "boot", "config", "mark", "service", "symlink", "hardlink", "permissions", "oversize", "lock-symlink", "busy-lock"} {
		t.Run(kind, func(t *testing.T) {
			a, _ := reviewAB()
			k := newCausalNFTKernel(a)
			ct := &memoryConntrack{}
			path := privateNFTConfig(t)
			n := reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{a}); err != nil {
				t.Fatal(err)
			}
			one := conntrackUnitEntry(a, 45000)
			ct.entries = []conntrackEntry{one}
			file := path + ".nft-state.json"
			switch kind {
			case "corrupt":
				if err := os.WriteFile(file, []byte(`{"payload":{},"sha256":"wrong"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.Truncate(file, 15); err != nil {
					t.Fatal(err)
				}
			case "schema":
				rewriteNFTRecord(t, file, func(r *nftDiskRecord) { r.Schema++ })
			case "namespace":
				rewriteNFTRecord(t, file, func(r *nftDiskRecord) { r.Context.NetInode++ })
			case "cookie":
				rewriteNFTRecord(t, file, func(r *nftDiskRecord) { r.Context.NetCookie++ })
			case "boot":
				rewriteNFTRecord(t, file, func(r *nftDiskRecord) { r.Context.BootID = "00000000-0000-0000-0000-000000000000" })
			case "config":
				rewriteNFTRecord(t, file, func(r *nftDiskRecord) { r.Context.ConfigSHA256 = strings.Repeat("0", 64) })
			case "mark":
				rewriteNFTRecord(t, file, func(r *nftDiskRecord) { r.Context.Owner = "other" })
			case "service":
				rewriteNFTRecord(t, file, func(r *nftDiskRecord) { r.Context.UID++ })
			case "symlink":
				if err := os.Rename(file, file+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(file+".saved", file); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, file+".link"); err != nil {
					t.Fatal(err)
				}
			case "permissions":
				if err := os.Chmod(file, 0640); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.Truncate(file, maxNFTDiskBytes+1); err != nil {
					t.Fatal(err)
				}
			case "lock-symlink":
				if err := os.Remove(file + ".lock"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(file, file+".lock"); err != nil {
					t.Fatal(err)
				}
			case "busy-lock":
				session, err := n.store.begin(n.ownerMarker)
				if err != nil {
					t.Fatal(err)
				}
				defer session.close()
			}
			k.objects = nil
			writes := k.writes
			n = reviewBackend(k, ct, path)
			if err := n.Replace(nil); err == nil {
				t.Fatal("invalid history accepted")
			}
			requireNFTEntries(t, ct, one)
			if k.writes != writes || ct.deletes != 0 {
				t.Fatal("untrusted history authorized a mutation")
			}
		})
	}
}
func TestNFTIndependentStoreDirectoryAndJSONBounds(t *testing.T) {
	path := privateNFTConfig(t)
	directory := filepath.Dir(path)
	if err := os.Chmod(directory, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := newNFTStateStore(path).begin(nftOwnerMarker(1)); err == nil {
		t.Fatal("group writable directory accepted")
	}
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	alias := directory + "-alias"
	if err := os.Symlink(directory, alias); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(alias)
	if _, err := newNFTStateStore(filepath.Join(alias, "config.json")).begin(nftOwnerMarker(1)); err == nil {
		t.Fatal("symlink directory accepted")
	}
	for _, raw := range []string{`{"schema":1,"schema":1}`, `{"unknown":1}`, `{} {}`, strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65)} {
		var record nftDiskRecord
		if err := strictNFTDiskJSON([]byte(raw), &record); err == nil {
			t.Fatalf("ambiguous or unbounded JSON accepted: %.30s", raw)
		}
	}
}
func TestNFTIndependentStoreMigrationAndConfigIsolation(t *testing.T) {
	a, b := reviewAB()
	k := newCausalNFTKernel(a, b)
	ct := &memoryConntrack{}
	path := privateNFTConfig(t)
	legacy := reviewBackend(k, ct, "")
	if err := legacy.Replace([]nftRuleSpec{a, b}); err != nil {
		t.Fatal(err)
	}
	one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
	ct.entries = []conntrackEntry{one, two}
	n := reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{a, b}); err != nil {
		t.Fatal(err)
	}
	requireNFTEntries(t, ct, one, two)
	if _, err := os.Stat(path + ".nft-state.json"); err != nil {
		t.Fatal("verified pb_state migration did not persist independently")
	}
	other := reviewBackend(k, ct, privateNFTConfig(t))
	writes := k.writes
	if err := other.Replace(nil); err == nil {
		t.Fatal("another config adopted a bound table")
	}
	requireNFTEntries(t, ct, one, two)
	if k.writes != writes || ct.deletes != 0 {
		t.Fatal("config conflict mutated current instance")
	}
	n = reviewBackend(k, ct, path)
	if err := n.Delete(); err != nil {
		t.Fatal(err)
	}
	if len(k.objects) != 0 || len(ct.entries) != 0 {
		t.Fatal("cleanup did not use the same independent store")
	}
}
func TestNFTIndependentStoreRecoveryListAndReadbackFailures(t *testing.T) {
	for _, kind := range []string{"list", "readback", "transaction"} {
		t.Run(kind, func(t *testing.T) {
			a, b := reviewAB()
			k := newCausalNFTKernel(a, b)
			ct := &memoryConntrack{}
			path := privateNFTConfig(t)
			n := reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{a, b}); err != nil {
				t.Fatal(err)
			}
			one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
			ct.entries = []conntrackEntry{one, two}
			n = reviewBackend(k, ct, path)
			switch kind {
			case "list":
				ct.listErr = context.DeadlineExceeded
			case "readback":
				k.afterApply = func([]nftObject) { k.readErr = errors.New("readback denied") }
			case "transaction":
				k.applyErr = context.DeadlineExceeded
			}
			if err := n.Replace([]nftRuleSpec{b}); err == nil {
				t.Fatal("injected failure hidden")
			}
			requireNFTEntries(t, ct, one, two)
			ct.listErr = nil
			k.readErr = nil
			k.afterApply = nil
			k.applyErr = nil
			n = reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{b}); err != nil {
				t.Fatal(err)
			}
			requireNFTEntries(t, ct, two)
		})
	}
}
func TestNFTIndependentStoreCompletedDeleteBeforeFinalCheckpoint(t *testing.T) {
	a, b := reviewAB()
	k := newCausalNFTKernel(a, b)
	ct := &memoryConntrack{}
	path := privateNFTConfig(t)
	n := reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{a, b}); err != nil {
		t.Fatal(err)
	}
	one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
	ct.entries = []conntrackEntry{one, two}
	calls := 0
	n.store.fault = func(stage string) error {
		if stage == "rename" {
			calls++
			if calls == 4 {
				return errors.New("final checkpoint lost")
			}
		}
		return nil
	}
	if err := n.Replace([]nftRuleSpec{b}); err == nil {
		t.Fatal("final checkpoint failure hidden")
	}
	requireNFTEntries(t, ct, two)
	k.objects = nil
	n = reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{b}); err != nil {
		t.Fatal(err)
	}
	requireNFTEntries(t, ct, two)
	if len(ct.deleted) != 1 {
		t.Fatal("retry broadened connection deletion after completed A")
	}
}

func TestNFTIndependentStoreNewBootRequiresIndependentScopeProof(t *testing.T) {
	a, _ := reviewAB()
	path := privateNFTConfig(t)
	k := newCausalNFTKernel(a)
	ct := &memoryConntrack{}
	n := reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{a}); err != nil {
		t.Fatal(err)
	}
	file := path + ".nft-state.json"
	rewriteNFTRecord(t, file, func(r *nftDiskRecord) { r.Context.BootID = "00000000-0000-0000-0000-000000000000" })
	old, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	k.objects = nil
	n = reviewBackend(k, ct, path)
	ct.entries = []conntrackEntry{conntrackUnitEntry(a, 45100)} // CURRENT candidate, even with an identical old tuple
	if err := n.Replace(nil); err == nil {
		t.Fatal("boot mismatch alone was treated as a clean-current-network proof")
	}
	if _, err := os.Stat(file + ".previous-boot"); !os.IsNotExist(err) {
		t.Fatal("failed proof changed history")
	}
	// Remove the simulated CURRENT candidate, not by the production cleanup.
	// The real scoped reader now verifies both inventories and the mark filter.
	ct.entries = nil
	if err := n.Replace(nil); err != nil {
		t.Fatal(err)
	}
	archived, err := os.ReadFile(file + ".previous-boot")
	if err != nil || string(archived) != string(old) {
		t.Fatal("lifecycle rollover lost the preserved previous-boot record")
	}
	if len(k.objects) != 0 || ct.deletes != 0 {
		t.Fatal("new-boot rollover guessed at connection ownership")
	}
}

func TestNFTRecoveryProcSubsetIdentity(t *testing.T) {
	if os.Getenv("PB_REVIEW_PROC_SUBSET") != "1" {
		t.Skip("requires a fresh mount/PID/network namespace with ProcSubset=pid and the narrow read-only boot bind")
	}
	mounts, err := os.ReadFile("/proc/self/mounts")
	if err != nil || !strings.Contains(string(mounts), "subset=pid") {
		t.Fatal("the actual proc mount does not use subset=pid")
	}
	verifyNFTBootBindIdentity(t)
}

func verifyNFTBootBindIdentity(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/proc/sys/kernel/random/boot_id"); !os.IsNotExist(err) {
		t.Fatal("ProcSubset fixture did not hide /proc/sys")
	}
	mountinfo, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(string(mountinfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 6 && fields[4] == "/run/portbridge-boot-id" && strings.Contains(","+fields[5]+",", ",ro,") {
			found = true
		}
	}
	if !found {
		t.Fatal("kernel boot identity is not a separately read-only bind")
	}
	store := newNFTStateStore(privateNFTConfig(t))
	session, err := store.begin(nftOwnerMarker(1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.binding(""); err != nil {
		t.Fatal(err)
	}
	empty := diskNFTSnapshot(nil, nil, nil)
	if err := session.prepare(empty, empty); err != nil {
		t.Fatal(err)
	}
	if err := session.checkpoint(empty); err != nil {
		t.Fatal(err)
	}
	session.close()
	session, err = store.begin(nftOwnerMarker(1))
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()
	if session.record == nil || session.context.NetCookie == 0 || session.context.BootID == "" {
		t.Fatal("sandbox-compatible identity/checkpoint not recovered")
	}
}

// This separately labelled component test exercises the actual read-only
// procfs bind with /proc/sys hidden. It is NOT full ProcSubset/systemd proof.
func TestNFTRecoveryBootBindComponent(t *testing.T) {
	if os.Getenv("PB_REVIEW_BOOT_BIND_COMPONENT") != "1" {
		t.Skip("requires a fresh mount/network namespace with the boot-file bind and hidden /proc/sys")
	}
	netns, _ := os.Readlink("/proc/self/ns/net")
	mntns, _ := os.Readlink("/proc/self/ns/mnt")
	if os.Getenv("PARENT_NET") == "" || os.Getenv("PARENT_MNT") == "" || netns == os.Getenv("PARENT_NET") || mntns == os.Getenv("PARENT_MNT") {
		t.Fatal("isolated component fixture not established")
	}
	verifyNFTBootBindIdentity(t)
}
