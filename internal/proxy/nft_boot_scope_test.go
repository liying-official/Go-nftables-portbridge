package proxy

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"

	"portbridge/internal/config"
)

const fixOldBoot = "00000000-0000-0000-0000-000000000000"

func fixUnrelatedFirewall() []nftObject {
	return []nftObject{
		{"table": map[string]any{"family": "inet", "name": "unrelated-host-firewall"}},
		{"chain": map[string]any{"family": "inet", "table": "unrelated-host-firewall", "name": "input", "hook": "input", "type": "filter", "prio": 0, "policy": "accept"}},
	}
}

// This evolves the supplied independent boot probe: Tables and Chains now
// include the same external inventory; no unconditional success callback is
// substituted. The actual store, mark-filtered reader and transactions execute.
// The old disk boot ID is simulated. This is L1, NOT an actual machine reboot.
func TestReview246BootRolloverWithUnrelatedFirewall(t *testing.T) {
	for _, external := range []bool{false, true} {
		name := "empty-inventory"
		if external {
			name = "unrelated-firewall-present"
		}
		t.Run(name, func(t *testing.T) {
			a, _ := reviewAB()
			k := newCausalNFTKernel(a)
			ct := &memoryConntrack{}
			path := privateNFTConfig(t)
			n := reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{a}); err != nil {
				t.Fatal(err)
			}
			rewriteNFTRecord(t, path+".nft-state.json", func(r *nftDiskRecord) { r.Context.BootID = fixOldBoot })
			old, err := os.ReadFile(path + ".nft-state.json")
			if err != nil {
				t.Fatal(err)
			}
			k.objects = nil
			control := conntrackUnitEntry(a, 45000) // reuse the OLD tuple, but different mark
			control.mark++
			if external {
				k.external = fixUnrelatedFirewall()
				ct.entries = []conntrackEntry{control}
			}
			externalBefore := string(nftTestJSON(k.external))
			n = reviewBackend(k, ct, path)
			// This MUST NOT be consulted by the NFT boot scope proof. It still
			// represents global nonemptiness, which remains a CLI-free Go limit.
			n.store.verifyEmpty = func() error { return errors.New("global inventory is nonempty") }
			beforeWrites, beforeLists := k.writes, ct.ownedLists
			m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
			m.Apply([]config.Rule{ruleFromNFTSpec(a)})
			row, _ := runtimeByID(m, a.RuleID)
			t.Logf("L1 simulated_old_boot=true unrelated_firewall=%t initialized=%t nft_writes_delta=%d owned_lists_delta=%d kernel_state=%s", external, n.initialized, k.writes-beforeWrites, ct.ownedLists-beforeLists, row.KernelState)
			if !n.initialized || row.GoRunning || len(n.activeSpecs) != 1 {
				t.Fatalf("boot compatibility failed: %+v", row)
			}
			if ct.ownedLists-beforeLists < 3 || ct.deletes != 0 || string(nftTestJSON(k.external)) != externalBefore {
				t.Fatal("scope proof was not executed or unrelated state was modified")
			}
			if external {
				requireNFTEntries(t, ct, control)
			}
			archived, err := os.ReadFile(path + ".nft-state.json.previous-boot")
			if err != nil || string(archived) != string(old) {
				t.Fatal("the protected previous-boot record was not preserved")
			}
		})
	}
}

func TestNFTBootScopeProtocolFamilyAndOldTupleReuse(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, protocol := range []string{"tcp", "udp"} {
			name := protocol + "/ipv4"
			if family == 6 {
				name = protocol + "/ipv6"
			}
			t.Run(name, func(t *testing.T) {
				a, b := reviewAB()
				for _, spec := range []*nftRuleSpec{&a, &b} {
					spec.Family, spec.Protocol = family, protocol
					if family == 6 {
						spec.ListenHost = netip.MustParseAddr("2001:db8:1::1")
						spec.TargetHost = netip.MustParseAddr("2001:db8:2::2")
					}
				}
				k := newCausalNFTKernel(a, b)
				ct := &memoryConntrack{}
				path := privateNFTConfig(t)
				n := reviewBackend(k, ct, path)
				if err := n.Replace([]nftRuleSpec{a}); err != nil {
					t.Fatal(err)
				}
				var oldInstance string
				rewriteNFTRecord(t, path+".nft-state.json", func(r *nftDiskRecord) {
					r.Context.BootID = fixOldBoot
					oldInstance = r.Instance
				})
				k.objects = nil
				entry := conntrackUnitEntry(a, 45100)
				if family == 6 {
					entry.original.source = netip.MustParseAddr("2001:db8:1::2")
					entry.reply.destination = netip.MustParseAddr("2001:db8:2::1")
				}
				entry.mark++
				ct.entries = []conntrackEntry{entry}
				k.external = fixUnrelatedFirewall()
				n = reviewBackend(k, ct, path)
				if err := n.Replace([]nftRuleSpec{b}); err != nil {
					t.Fatal(err)
				}
				requireNFTEntries(t, ct, entry)
				if ct.deletes != 0 || len(n.pendingSpecs)+len(n.suspendedSpecs) != 0 {
					t.Fatal("old history leaked into current retirement")
				}
				session, err := n.store.begin(n.ownerMarker)
				if err != nil {
					t.Fatal(err)
				}
				defer session.close()
				r := session.record
				if r == nil || r.Context.BootID == fixOldBoot || r.Instance == oldInstance || r.Generation != 1 || r.Phase != "checkpoint" || len(r.Confirmed.Active) != 1 || r.Confirmed.Active[0].Identity != nftRuleIdentity(b) {
					t.Fatal("new lifecycle did not establish independent current history")
				}
			})
		}
	}
}

type fixScopeReadKernel struct {
	nftKernelIO
	tables func() ([]byte, error)
	chains func() ([]byte, error)
}

func (k *fixScopeReadKernel) Tables() ([]byte, error) {
	if k.tables != nil {
		return k.tables()
	}
	return k.nftKernelIO.Tables()
}
func (k *fixScopeReadKernel) Chains() ([]byte, error) {
	if k.chains != nil {
		return k.chains()
	}
	return k.nftKernelIO.Chains()
}

func TestNFTBootScopeRejectsCurrentRiskWithoutDeletion(t *testing.T) {
	for _, scenario := range []string{"foreign-name", "owned-object", "same-mark-old-tuple", "same-mark-other-tuple", "same-mark-zone", "copied-owner", "current-binding", "missing-conntrack", "conntrack-timeout", "nft-read-failure", "malformed-json", "duplicate-json-key", "dangling-chain", "unknown-family", "concurrent-tables"} {
		t.Run(scenario, func(t *testing.T) {
			a, _ := reviewAB()
			k := newCausalNFTKernel(a)
			ct := &memoryConntrack{}
			path := privateNFTConfig(t)
			n := reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{a}); err != nil {
				t.Fatal(err)
			}
			rewriteNFTRecord(t, path+".nft-state.json", func(r *nftDiskRecord) { r.Context.BootID = fixOldBoot })
			old, err := os.ReadFile(path + ".nft-state.json")
			if err != nil {
				t.Fatal(err)
			}
			owned := cloneNFTTestObjects(k.objects)
			k.objects = nil
			n = reviewBackend(k, ct, path)
			switch scenario {
			case "foreign-name":
				k.external = []nftObject{{"table": map[string]any{"family": "inet", "name": nftTableName, "comment": "foreign"}}}
			case "owned-object":
				k.objects = owned
			case "same-mark-old-tuple", "same-mark-other-tuple", "same-mark-zone":
				entry := conntrackUnitEntry(a, 45100)
				if scenario == "same-mark-other-tuple" {
					entry.original.destinationPort++
				}
				if scenario == "same-mark-zone" {
					entry.zone = 23
				}
				ct.entries = []conntrackEntry{entry}
			case "copied-owner":
				k.external = []nftObject{{"table": map[string]any{"family": "inet", "name": "restored-copy", "comment": n.ownerMarker}}}
			case "current-binding":
				c, err := nftCurrentDiskContext(path, n.ownerMarker)
				if err != nil {
					t.Fatal(err)
				}
				k.external = fixUnrelatedFirewall()
				k.external[1]["chain"].(map[string]any)["comment"] = "pb-disk:v1:" + c.ConfigSHA256 + ":" + strings.Repeat("a", 32)
			case "missing-conntrack":
				ct.availableErr = errors.New("missing trusted tool")
			case "conntrack-timeout":
				ct.listErr = context.DeadlineExceeded
			case "nft-read-failure":
				k.readErr = errors.New("nft read denied")
			case "malformed-json":
				n.kernel = &fixScopeReadKernel{nftKernelIO: k, tables: func() ([]byte, error) { return []byte(`{"nftables":[`), nil }}
			case "duplicate-json-key":
				n.kernel = &fixScopeReadKernel{nftKernelIO: k, tables: func() ([]byte, error) {
					return []byte(`{"nftables":[{"table":{"family":"inet","name":"portbridge","name":"other"}}]}`), nil
				}}
			case "dangling-chain":
				k.external = fixUnrelatedFirewall()[1:]
			case "unknown-family":
				k.external = []nftObject{{"table": map[string]any{"family": "unknown", "name": "other"}}}
			case "concurrent-tables":
				calls := 0
				n.kernel = &fixScopeReadKernel{nftKernelIO: k, tables: func() ([]byte, error) {
					calls++
					if calls == 2 {
						k.external = fixUnrelatedFirewall()
					}
					return k.Tables()
				}}
			}
			before := k.writes
			entries := append([]conntrackEntry(nil), ct.entries...)
			if err := n.Replace([]nftRuleSpec{a}); err == nil {
				t.Fatal("current risk or failed proof was accepted")
			}
			after, err := os.ReadFile(path + ".nft-state.json")
			if err != nil || string(after) != string(old) {
				t.Fatal("failed proof destroyed the primary record")
			}
			if _, err := os.Lstat(path + ".nft-state.json.previous-boot"); !os.IsNotExist(err) {
				t.Fatal("failed proof archived current history")
			}
			if k.writes != before || ct.deletes != 0 {
				t.Fatal("scope proof performed mutations")
			}
			requireNFTEntries(t, ct, entries...)
		})
	}
}

func TestNFTBootRolloverInterruptedCommitAndRetry(t *testing.T) {
	for _, stage := range []string{"boot-archive", "boot-directory-sync", "create", "write", "file-sync", "rename", "directory-sync", "checkpoint-rename"} {
		t.Run(stage, func(t *testing.T) {
			a, b := reviewAB()
			k := newCausalNFTKernel(a, b)
			ct := &memoryConntrack{}
			path := privateNFTConfig(t)
			n := reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{a}); err != nil {
				t.Fatal(err)
			}
			rewriteNFTRecord(t, path+".nft-state.json", func(r *nftDiskRecord) { r.Context.BootID = fixOldBoot })
			old, err := os.ReadFile(path + ".nft-state.json")
			if err != nil {
				t.Fatal(err)
			}
			k.objects = nil
			k.external = fixUnrelatedFirewall()
			control := conntrackUnitEntry(a, 45100)
			control.mark++
			ct.entries = []conntrackEntry{control}
			n = reviewBackend(k, ct, path)
			renames := 0
			n.store.fault = func(s string) error {
				if s == "rename" {
					renames++
				}
				if s == stage || (stage == "checkpoint-rename" && s == "rename" && renames == 2) {
					return errors.New("injected boot commit failure")
				}
				return nil
			}
			if err := n.Replace([]nftRuleSpec{b}); err == nil {
				t.Fatal("commit failure was hidden")
			}
			primary, _ := os.ReadFile(path + ".nft-state.json")
			previous, _ := os.ReadFile(path + ".nft-state.json.previous-boot")
			if string(primary) != string(old) && string(previous) != string(old) {
				t.Fatal("only valid previous lifecycle record was lost")
			}
			n = reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{b}); err != nil {
				t.Fatal(err)
			}
			if len(n.activeSpecs) != 1 || !nftIdentityMatchesRule(n.activeSpecs[0], b.RuleID) || len(n.pendingSpecs) != 0 {
				t.Fatal("retry imported old lifetime into current state")
			}
			requireNFTEntries(t, ct, control)
			if ct.deletes != 0 {
				t.Fatal("boot retry deleted an unrelated connection")
			}
			previous, err = os.ReadFile(path + ".nft-state.json.previous-boot")
			if err != nil || string(previous) != string(old) {
				t.Fatal("retry lost protected old history")
			}
		})
	}
}

func TestNFTBootArchiveOnlyStillRequiresCurrentProof(t *testing.T) {
	a, _ := reviewAB()
	k := newCausalNFTKernel(a)
	ct := &memoryConntrack{}
	path := privateNFTConfig(t)
	n := reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{a}); err != nil {
		t.Fatal(err)
	}
	rewriteNFTRecord(t, path+".nft-state.json", func(r *nftDiskRecord) { r.Context.BootID = fixOldBoot })
	k.objects = nil
	n = reviewBackend(k, ct, path)
	n.store.fault = func(s string) error {
		if s == "boot-directory-sync" {
			return errors.New("crash after archive")
		}
		return nil
	}
	if err := n.Replace(nil); err == nil {
		t.Fatal("archive failure hidden")
	}
	if _, err := os.Stat(path + ".nft-state.json"); !os.IsNotExist(err) {
		t.Fatal("fixture did not reach archive-only window")
	}
	old, err := os.ReadFile(path + ".nft-state.json.previous-boot")
	if err != nil {
		t.Fatal(err)
	}
	ct.entries = []conntrackEntry{conntrackUnitEntry(a, 45100)}
	n = reviewBackend(k, ct, path)
	if err := n.Delete(); err == nil {
		t.Fatal("archive-only absence became first-use or old-history ownership")
	}
	if ct.deletes != 0 {
		t.Fatal("old archive authorized a current tuple deletion")
	}
	current, err := os.ReadFile(path + ".nft-state.json.previous-boot")
	if err != nil || string(current) != string(old) {
		t.Fatal("refused archive-only retry changed history")
	}
	// CLI-free Go must also notice the archive; a missing primary is not enough.
	n.store.verifyEmpty = func() error { return errors.New("global inventory not empty") }
	if err := n.store.checkExisting(n.ownerMarker); err == nil {
		t.Fatal("CLI-free path ignored archive-only recovery identity")
	}
	ct.entries = nil
	n = reviewBackend(k, ct, path)
	if err := n.Delete(); err != nil {
		t.Fatal(err)
	}
}

func TestNFTBootScopeContextMismatchAndArchiveProtection(t *testing.T) {
	for _, scenario := range []string{"same-boot-namespace", "same-boot-cookie", "uid", "config", "mark", "zero-old-cookie", "archive-permissions", "archive-current-boot", "archive-corrupt", "archive-symlink", "lock-contention"} {
		t.Run(scenario, func(t *testing.T) {
			a, _ := reviewAB()
			k := newCausalNFTKernel(a)
			ct := &memoryConntrack{}
			path := privateNFTConfig(t)
			n := reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{a}); err != nil {
				t.Fatal(err)
			}
			var held *nftDiskSession
			if scenario == "lock-contention" {
				var err error
				held, err = n.store.begin(n.ownerMarker)
				if err != nil {
					t.Fatal(err)
				}
				defer held.close()
			}
			current, err := os.ReadFile(path + ".nft-state.json")
			if err != nil {
				t.Fatal(err)
			}
			rewriteNFTRecord(t, path+".nft-state.json", func(r *nftDiskRecord) {
				if !strings.HasPrefix(scenario, "same-boot-") {
					r.Context.BootID = fixOldBoot
				}
				switch scenario {
				case "same-boot-namespace":
					r.Context.NetInode++
				case "same-boot-cookie":
					r.Context.NetCookie++
				case "uid":
					r.Context.UID++
				case "config":
					r.Context.ConfigSHA256 = strings.Repeat("b", 64)
				case "mark":
					r.Context.Owner = "foreign"
				case "zero-old-cookie":
					r.Context.NetCookie = 0
				}
			})
			file := path + ".nft-state.json"
			old, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			archive := file + ".previous-boot"
			switch scenario {
			case "archive-permissions":
				if err := os.WriteFile(archive, old, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(archive, 0644); err != nil {
					t.Fatal(err)
				}
			case "archive-current-boot":
				if err := os.WriteFile(archive, current, 0600); err != nil {
					t.Fatal(err)
				}
			case "archive-corrupt":
				if err := os.WriteFile(archive, []byte("bad"), 0600); err != nil {
					t.Fatal(err)
				}
			case "archive-symlink":
				if err := os.Symlink(file, archive); err != nil {
					t.Fatal(err)
				}
			}
			k.objects = nil
			n = reviewBackend(k, ct, path)
			before := k.writes
			if err := n.Replace(nil); err == nil {
				t.Fatal("unsafe identity/archive/lock inherited")
			}
			after, err := os.ReadFile(file)
			if err != nil || string(after) != string(old) || k.writes != before || ct.deletes != 0 {
				t.Fatal("refusal changed primary record or kernel state")
			}
		})
	}
}
