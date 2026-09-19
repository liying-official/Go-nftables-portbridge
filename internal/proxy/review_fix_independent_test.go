package proxy

import (
	"errors"
	"net/netip"
	"os"
	"portbridge/internal/config"
	"testing"
)

// Independent fixture: all three inventory operations project the SAME
// applied object and external-rule store. Apply is the original causal
// transaction interpreter. This is NOT a real nft parser or Linux dataplane.
type reviewFixInventory struct {
	*causalNFTKernel
	reads int
}

func (k *reviewFixInventory) inventory(kinds ...string) []nftObject {
	all := append(cloneNFTTestObjects(k.objects), cloneNFTTestObjects(k.external)...)
	var out []nftObject
	for _, o := range all {
		for _, kind := range kinds {
			if _, ok := o[kind]; ok {
				out = append(out, o)
				break
			}
		}
	}
	return out
}
func (k *reviewFixInventory) Tables() ([]byte, error) {
	if k.readErr != nil {
		return nil, k.readErr
	}
	return nftTestJSON(k.inventory("table")), nil
}
func (k *reviewFixInventory) Chains() ([]byte, error) {
	if k.readErr != nil {
		return nil, k.readErr
	}
	return nftTestJSON(k.inventory("table", "chain")), nil
}
func (k *reviewFixInventory) Ruleset() ([]byte, error) {
	k.reads++
	if k.readErr != nil {
		return nil, k.readErr
	}
	return nftTestJSON(append(cloneNFTTestObjects(k.objects), cloneNFTTestObjects(k.external)...)), nil
}
func reviewFixHook(rule string) []nftObject {
	x := []nftObject{
		{"table": map[string]any{"family": "inet", "name": "review-external"}},
		{"chain": map[string]any{"family": "inet", "table": "review-external", "name": "post", "type": "filter", "hook": "postrouting", "prio": 0, "policy": "accept"}},
	}
	if rule != "" {
		x = append(x, nftObject{"rule": map[string]any{"family": "inet", "table": "review-external", "chain": "post", "expr": []any{map[string]any{rule: nil}}}})
	}
	return x
}
func reviewFixRuleSpec(s nftRuleSpec, family int, protocol string) nftRuleSpec {
	s.Family = family
	s.Protocol = protocol
	if family == 6 {
		s.ListenHost = netip.MustParseAddr("2001:db8:1::1")
		s.TargetHost = netip.MustParseAddr("2001:db8:2::2")
	}
	return s
}
func reviewFixEntry(s nftRuleSpec, port uint16) conntrackEntry {
	e := conntrackUnitEntry(s, port)
	if s.Family == 6 {
		e.original.source = netip.MustParseAddr("2001:db8:1::2")
		e.reply.destination = netip.MustParseAddr("2001:db8:2::1")
	}
	return e
}
func reviewFixAdmission(t *testing.T, rule string, wantAdmission bool) {
	t.Helper()
	for _, family := range []int{4, 6} {
		for _, protocol := range []string{"tcp", "udp"} {
			name := protocol + "/ipv4"
			if family == 6 {
				name = protocol + "/ipv6"
			}
			t.Run(name, func(t *testing.T) {
				a, b := reviewAB()
				a = reviewFixRuleSpec(a, family, protocol)
				b = reviewFixRuleSpec(b, family, protocol)
				k := &reviewFixInventory{causalNFTKernel: newCausalNFTKernel(a, b)}
				ct := &memoryConntrack{}
				n := reviewBackend(k.causalNFTKernel, ct, privateNFTConfig(t))
				n.kernel = k
				m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
				ra, rb := ruleFromNFTSpec(a), ruleFromNFTSpec(b)
				m.Apply([]config.Rule{ra, rb})
				if !n.initialized {
					t.Fatal("setup not initialized")
				}
				ea, eb := reviewFixEntry(a, 45000), reviewFixEntry(b, 45001)
				control := eb
				control.mark++
				ct.entries = []conntrackEntry{ea, eb, control}
				k.external = reviewFixHook(rule)
				externalBefore := string(nftTestJSON(k.external))
				ra.Enabled = false
				m.Apply([]config.Rule{ra, rb})
				requireNFTEntries(t, ct, eb, control)
				if len(ct.deleted) != 1 || ct.deleted[0] != ea {
					t.Fatal("A not exclusively revoked")
				}
				row, _ := runtimeByID(m, b.RuleID)
				installed := false
				for _, o := range k.objects {
					if r, ok := o["rule"].(map[string]any); ok && nftRuleInspectionKey(r) == nftRuleInspectionKey(nftExpectedRule(b, "prerouting")) {
						installed = true
					}
				}
				if externalBefore != string(nftTestJSON(k.external)) {
					t.Fatal("external firewall modified")
				}
				t.Logf("L1 rule=%q A_old=false B_old=true foreign=true B_NAT_rule=%t B_kernel_state=%s complete_ruleset_reads=%d", rule, installed, row.KernelState, k.reads)
				if installed != wantAdmission {
					t.Fatalf("B admission contract not met: got=%t want=%t; preserving conntrack alone is insufficient", installed, wantAdmission)
				}
				if wantAdmission {
					if !nftSpecInstalled(b, n.activeSpecs) || !b.EnableFlowtable || row.KernelState != "active-verified" {
						t.Fatal("B eligibility/runtime mismatch")
					}
					observed, err := n.observe()
					if err != nil {
						t.Fatal(err)
					}
					for _, hook := range []string{"output", "postrouting", "forward"} {
						found := false
						for _, o := range observed.objects {
							if r, ok := o["rule"].(map[string]any); ok && nftRuleInspectionKey(r) == nftRuleInspectionKey(nftExpectedRule(b, hook)) {
								found = true
							}
						}
						if !found {
							t.Fatalf("missing real fixture rule %s", hook)
						}
					}
				}
			})
		}
	}
}
func TestReviewFixIndependentEmptyHookPermitsB(t *testing.T) { reviewFixAdmission(t, "", true) }

// This deliberately expresses the broader release contract: an actual
// unconditional accept RULE does not deny B, but is outside the fix grammar.
func TestReviewFixIndependentLegalAcceptRulePermitsB(t *testing.T) {
	reviewFixAdmission(t, "accept", true)
}
func TestReviewFixIndependentDropRuleIsNotBypassed(t *testing.T) {
	reviewFixAdmission(t, "drop", false)
}

func TestReviewFixIndependentBootForeignAndCurrentRisk(t *testing.T) {
	for _, sameMark := range []bool{false, true} {
		name := "unrelated-different-mark"
		if sameMark {
			name = "current-same-mark-old-tuple"
		}
		t.Run(name, func(t *testing.T) {
			a, b := reviewAB()
			k := &reviewFixInventory{causalNFTKernel: newCausalNFTKernel(a, b)}
			ct := &memoryConntrack{}
			path := privateNFTConfig(t)
			n := reviewBackend(k.causalNFTKernel, ct, path)
			n.kernel = k
			if err := n.Replace([]nftRuleSpec{a}); err != nil {
				t.Fatal(err)
			}
			rewriteNFTRecord(t, path+".nft-state.json", func(r *nftDiskRecord) { r.Context.BootID = "00000000-0000-0000-0000-000000000000" })
			before, err := os.ReadFile(path + ".nft-state.json")
			if err != nil {
				t.Fatal(err)
			}
			k.objects = nil
			k.external = []nftObject{{"table": map[string]any{"family": "inet", "name": "review-other"}}, {"chain": map[string]any{"family": "inet", "table": "review-other", "name": "input", "type": "filter", "hook": "input", "prio": 0, "policy": "accept"}}}
			e := conntrackUnitEntry(a, 45678)
			if !sameMark {
				e.mark++
			}
			ct.entries = []conntrackEntry{e}
			n = reviewBackend(k.causalNFTKernel, ct, path)
			n.kernel = k
			globalProofCalls := 0
			n.store.verifyEmpty = func() error { globalProofCalls++; return errors.New("independent global inventory is nonempty") }
			err = n.Replace([]nftRuleSpec{b})
			requireNFTEntries(t, ct, e)
			t.Logf("L1 simulated_boot=true same_mark=%t initialized=%t global_empty_calls=%d deletes=%d error=%v", sameMark, n.initialized, globalProofCalls, ct.deletes, err)
			if ct.deletes != 0 {
				t.Fatal("old boot scope deleted current connection")
			}
			if sameMark {
				if err == nil {
					t.Fatal("current unattributed same-mark connection accepted")
				}
				after, _ := os.ReadFile(path + ".nft-state.json")
				if string(before) != string(after) {
					t.Fatal("refusal changed primary")
				}
			} else {
				if err != nil || !n.initialized {
					t.Fatal("unrelated firewall prevents safe new boot rollover", err)
				}
				archived, err := os.ReadFile(path + ".nft-state.json.previous-boot")
				if err != nil || string(archived) != string(before) {
					t.Fatal("old record not retained")
				}
				if len(n.pendingSpecs) != 0 || !nftSpecInstalled(b, n.activeSpecs) {
					t.Fatal("old historical scope imported")
				}
			}
		})
	}
}
