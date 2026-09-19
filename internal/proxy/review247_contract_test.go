package proxy

import (
	"fmt"
	"portbridge/internal/config"
	"testing"
)

// This is a release-contract probe, not a claim that arbitrary policies are
// included in the v2.4.7 minimum accept-only grammar. The external chain has
// accept policy and a side-effect-free port equality followed by accept; both
// the match and non-match paths accept. A and B are disjoint owned scopes.
func TestReview247RemainingConditionalAcceptContract(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, protocol := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("ipv%d/%s", family, protocol), func(t *testing.T) {
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
					t.Fatal("initial admission not installed")
				}
				ea, eb := reviewFixEntry(a, 45111), reviewFixEntry(b, 45112)
				foreign := eb
				foreign.mark++
				ct.entries = []conntrackEntry{ea, eb, foreign}
				k.external = reviewFixHook("accept")
				r := k.external[2]["rule"].(map[string]any)
				r["expr"] = []any{
					map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": protocol, "field": "dport"}}, "right": b.TargetPort}},
					map[string]any{"accept": nil},
				}
				before := string(nftTestJSON(k.external))
				ra.Enabled = false
				m.Apply([]config.Rule{ra, rb})
				requireNFTEntries(t, ct, eb, foreign)
				if len(ct.deleted) != 1 || ct.deleted[0] != ea {
					t.Fatal("retirement was not exclusive to A")
				}
				if before != string(nftTestJSON(k.external)) {
					t.Fatal("external policy was altered")
				}
				row, _ := runtimeByID(m, b.RuleID)
				installed := false
				flow := false
				for _, obj := range k.objects {
					if r, ok := obj["rule"].(map[string]any); ok && nftRuleInspectionKey(r) == nftRuleInspectionKey(nftExpectedRule(b, "prerouting")) {
						installed = true
					}
					if _, ok := obj["flowtable"]; ok {
						flow = true
					}
				}
				t.Logf("L1 conditional-accept policy=accept A_old=false B_old=true foreign=true B_new_NAT=%t requested_flowtable=%t flowtable_present=%t state=%s error=%s", installed, b.EnableFlowtable, flow, row.KernelState, row.Stats.LastError)
				if !installed {
					t.Error("general legal-policy availability contract remains unresolved; narrow accept-only support is not universal compatibility")
				}
			})
		}
	}
}

// Independent end-to-end controller check of multiple pure accept rules and
// exact chain identities. Equal chain names in different tables must not merge
// permission, and any separate drop chain keeps its own risk gate.
func TestReview247IndependentMultiChainLifecycle(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, protocol := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("ipv%d/%s", family, protocol), func(t *testing.T) {
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
					t.Fatal("initial install")
				}
				ea, eb := reviewFixEntry(a, 45211), reviewFixEntry(b, 45212)
				foreign := eb
				foreign.mark++
				ct.entries = []conntrackEntry{ea, eb, foreign}
				safe := reviewFixHook("accept")
				safe = append(safe, cloneNFTTestObjects(safe[2:])...)
				k.external = safe
				ra.Enabled = false
				m.Apply([]config.Rule{ra, rb})
				requireNFTEntries(t, ct, eb, foreign)
				if !nftSpecInstalled(b, n.activeSpecs) || !specsUseFlowtable(n.activeSpecs) {
					t.Fatal("multi accept B not installed with requested offload")
				}
				different := reviewFixHook("drop")
				different[0]["table"].(map[string]any)["name"] = "different-policy"
				different[1]["chain"].(map[string]any)["table"] = "different-policy"
				different[2]["rule"].(map[string]any)["table"] = "different-policy"
				k.external = append(cloneNFTTestObjects(safe), different...)
				m.Refresh([]config.Rule{ra, rb})
				if nftSpecInstalled(b, n.activeSpecs) {
					t.Fatal("same-name separate drop chain bypassed")
				}
				if specsUseFlowtable(n.activeSpecs) {
					t.Fatal("unproven acceleration retained")
				}
				requireNFTEntries(t, ct, eb, foreign)
				k.external = safe
				m.Refresh([]config.Rule{ra, rb})
				if !nftSpecInstalled(b, n.activeSpecs) || !specsUseFlowtable(n.activeSpecs) {
					t.Fatal("compatible restoration did not restore B")
				}
				if len(ct.deleted) != 1 || ct.deleted[0] != ea {
					t.Fatal("B/foreign collateral deletion")
				}
				t.Log("L1 multi-accept -> separate-table same-name drop -> multi-accept: admission gated/restored; only A retired; B/foreign retained")
			})
		}
	}
}
