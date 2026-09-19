package proxy

import (
	"errors"
	"fmt"
	"net/netip"
	"portbridge/internal/config"
	"strings"
	"testing"
)

func selectiveRule(proto, field, op string, value any) nftObject {
	return nftObject{"rule": map[string]any{"family": "inet", "table": "review-external", "chain": "post",
		"expr": []any{map[string]any{"match": map[string]any{
			"left": map[string]any{"payload": map[string]any{"protocol": proto, "field": field}},
			"op":   op, "right": value}}, map[string]any{"accept": nil}}}}
}
func selectivePolicy(s nftRuleSpec, priority int, replyPort int) []nftObject {
	objects := reviewFixHook("")
	objects[1]["chain"].(map[string]any)["policy"] = "drop"
	objects[1]["chain"].(map[string]any)["prio"] = priority
	return cloneNFTTestObjects(append(objects, selectiveRule(s.Protocol, "dport", "==", s.TargetPort),
		selectiveRule(s.Protocol, "sport", "==", replyPort)))
}
func proveSelective(t *testing.T, objects []nftObject, specs ...nftRuleSpec) []nftRuleSpec {
	t.Helper()
	objects = cloneNFTTestObjects(objects)
	if _, err := nftProvablyCompatibleHooks(objects); err != nil {
		t.Fatal(err)
	}
	conflicts, err := nftConflictingHooks(objects)
	if err != nil {
		t.Fatal(err)
	}
	allowed, _, err := nftProveSelectiveScopes(objects, conflicts, specs)
	if err != nil {
		t.Fatal(err)
	}
	return allowed
}
func TestNFTSelectiveACLNATAndDirections(t *testing.T) {
	for _, family := range []int{4, 6} {
		for _, proto := range []string{"tcp", "udp"} {
			t.Run(fmt.Sprintf("ipv%d/%s", family, proto), func(t *testing.T) {
				s := reviewFixRuleSpec(nftUnitSpec(), family, proto)
				if len(proveSelective(t, selectivePolicy(s, 0, s.TargetPort), s)) != 1 {
					t.Fatal("pre-SNAT bidirectional ACL rejected")
				}
				if len(proveSelective(t, selectivePolicy(s, 200, s.TargetPort), s)) != 0 {
					t.Fatal("target sport guessed after reverse NAT")
				}
				if len(proveSelective(t, selectivePolicy(s, 200, s.ListenPort), s)) != 1 {
					t.Fatal("post-SNAT listen sport rejected")
				}
				equal := selectivePolicy(s, 100, s.TargetPort)
				if len(proveSelective(t, equal, s)) != 0 {
					t.Fatal("equal-priority NAT order guessed")
				}
				equal = append(equal, selectiveRule(proto, "sport", "==", s.ListenPort))
				if len(proveSelective(t, equal, s)) != 1 {
					t.Fatal("both NAT orderings not recognized")
				}
				one := selectivePolicy(s, 0, s.TargetPort)[:3]
				if len(proveSelective(t, one, s)) != 0 {
					t.Fatal("one-way permission authorized bidirectional offload")
				}
			})
		}
	}
}
func TestNFTSelectiveACLUnknownAndSideEffects(t *testing.T) {
	s := nftUnitSpec()
	for _, kind := range []string{"drop", "counter", "log", "ct", "jump", "wrong-port", "client-address", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			objects := selectivePolicy(s, 0, s.TargetPort)
			switch kind {
			case "wrong-port":
				objects = selectivePolicy(s, 0, s.TargetPort+1)
			case "client-address":
				r := selectiveRule("ip", "saddr", "==", "192.0.2.2")
				objects[2] = r
			case "malformed":
				objects[2]["rule"].(map[string]any)["expr"] = []any{map[string]any{"match": nil}, map[string]any{"accept": nil}}
			default:
				// Even an unreachable side effect or explicit verdict is not
				// silently ignored by this deliberately bounded grammar.
				objects = append(objects, nftObject{"rule": map[string]any{"family": "inet", "table": "review-external", "chain": "post",
					"expr": []any{map[string]any{kind: nil}, map[string]any{"accept": nil}}}})
			}
			if len(proveSelective(t, objects, s)) != 0 {
				t.Fatal("unproved ACL granted permission")
			}
		})
	}
	// Do not project NAT through another mutating chain.
	objects := selectivePolicy(s, 0, s.TargetPort)
	objects = append(objects, nftObject{"chain": map[string]any{"family": "inet", "table": "review-external", "name": "translate", "type": "nat", "hook": "prerouting", "prio": -150, "policy": "accept"}},
		nftObject{"rule": map[string]any{"family": "inet", "table": "review-external", "chain": "translate", "expr": []any{map[string]any{"accept": nil}}}})
	if len(proveSelective(t, objects, s)) != 0 {
		t.Fatal("external NAT assumed not to change tuples")
	}
}
func TestNFTSelectiveACLUniversalPortDomain(t *testing.T) {
	for lo := uint64(0); lo <= 5; lo++ {
		for hi := lo; hi <= 5; hi++ {
			for value := uint64(0); value <= 6; value++ {
				for _, op := range []string{"==", "!=", "<", "<=", ">", ">="} {
					want := true
					for p := lo; p <= hi; p++ {
						match := false
						switch op {
						case "==":
							match = p == value
						case "!=":
							match = p != value
						case "<":
							match = p < value
						case "<=":
							match = p <= value
						case ">":
							match = p > value
						case ">=":
							match = p >= value
						}
						want = want && match
					}
					if nftACLPortAlways(nftACLPort{lo, hi}, op, value) != want {
						t.Fatal("domain was tested as a sample instead of universally")
					}
				}
			}
		}
	}
	s := nftUnitSpec()
	s.ListenPortEnd += 2
	s.TargetPortEnd += 2
	if len(proveSelective(t, selectivePolicy(s, 0, s.TargetPort), s)) != 0 {
		t.Fatal("only one port authorized a whole range")
	}
	objects := selectivePolicy(s, 0, s.TargetPort)
	objects[2] = selectiveRule(s.Protocol, "dport", ">=", s.TargetPort)
	objects[3] = selectiveRule(s.Protocol, "sport", ">=", s.TargetPort)
	if len(proveSelective(t, objects, s)) != 1 {
		t.Fatal("whole range comparison not recognized")
	}
	s.ListenHost = netip.IPv4Unspecified()
	if len(proveSelective(t, objects, s)) != 1 {
		t.Fatal("port-only proof should not guess or require wildcard address")
	}
}
func TestNFTSelectiveACLPerRuleAndSameFamilyTransition(t *testing.T) {
	a, b := reviewAB()
	c := b
	c.RuleID = "C"
	c.ListenPort++
	c.ListenPortEnd++
	k := &reviewFixInventory{causalNFTKernel: newCausalNFTKernel(a, b, c)}
	ct := &memoryConntrack{}
	path := privateNFTConfig(t)
	n := reviewBackend(k.causalNFTKernel, ct, path)
	n.kernel = k
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
	ra, rb, rc := ruleFromNFTSpec(a), ruleFromNFTSpec(b), ruleFromNFTSpec(c)
	m.Apply([]config.Rule{ra, rb, rc})
	if !n.initialized {
		t.Fatal("initial setup")
	}
	ea, eb, ec := reviewFixEntry(a, 45100), reviewFixEntry(b, 45101), reviewFixEntry(c, 45102)
	foreign := eb
	foreign.mark++
	ct.entries = []conntrackEntry{ea, eb, ec, foreign}
	k.external = selectivePolicy(b, 200, b.ListenPort)
	ra.Enabled = false
	m.Apply([]config.Rule{ra, rb, rc})
	requireNFTEntries(t, ct, eb, ec, foreign)
	if len(ct.deleted) != 1 || ct.deleted[0] != ea {
		t.Fatal("retirement widened beyond A")
	}
	if !nftSpecInstalled(b, n.activeSpecs) || nftSpecInstalled(c, n.activeSpecs) {
		t.Fatal("rule-specific permission widened to family")
	}
	oldWrites := len(k.scripts)
	k.external = selectivePolicy(c, 200, c.ListenPort)
	before := string(nftTestJSON(k.external))
	m.Refresh([]config.Rule{ra, rb, rc})
	if !nftSpecInstalled(c, n.activeSpecs) || nftSpecInstalled(b, n.activeSpecs) {
		t.Fatal("same-family permission transition failed")
	}
	rebuilt := false
	for _, script := range k.scripts[oldWrites:] {
		if strings.Contains(script, "delete table inet portbridge") {
			rebuilt = true
		}
	}
	if !rebuilt {
		t.Fatal("newly denied B retained cached flowtable within unchanged family mask")
	}
	requireNFTEntries(t, ct, eb, ec, foreign)
	if before != string(nftTestJSON(k.external)) {
		t.Fatal("external ACL was modified")
	}
	oldWrites = len(k.scripts)
	m.Refresh([]config.Rule{ra, rb, rc})
	if len(k.scripts) != oldWrites {
		t.Fatal("stable selective state caused repeated writes")
	}
}

type selectiveChangingReader struct {
	first, second []byte
	reads         int
}

func (r *selectiveChangingReader) Ruleset() ([]byte, error) {
	r.reads++
	if r.reads == 1 {
		return r.first, nil
	}
	if r.second == nil {
		return nil, errors.New("injected read failure")
	}
	return r.second, nil
}
func TestNFTSelectiveACLTwoSnapshots(t *testing.T) {
	s := nftUnitSpec()
	first := selectivePolicy(s, 0, s.TargetPort)
	conflicts, err := nftConflictingHooks(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]nftObject{selectivePolicy(s, 0, s.TargetPort+1), nil} {
		r := &selectiveChangingReader{first: nftTestJSON(first)}
		if changed != nil {
			r.second = nftTestJSON(changed)
		}
		if _, _, allowed, err := verifyNFTSelectiveExternalHooks(r, conflicts, []nftRuleSpec{s}); err == nil || len(allowed) != 0 {
			t.Fatal("stale first-snapshot permission escaped")
		}
	}
}
func TestNFTSelectiveACLFlowEntryIsOriginalTupleScoped(t *testing.T) {
	s := nftUnitSpec()
	for _, family := range []int{4, 6} {
		spec := reviewFixRuleSpec(s, family, "udp")
		script := renderNFTScript([]nftRuleSpec{spec}, false, []string{"test0"})
		var flow string
		for _, line := range strings.Split(script, "\n") {
			if strings.Contains(line, "flow add") {
				flow = line
			}
		}
		if !strings.Contains(flow, fmt.Sprintf("ct original proto-dst %d", spec.ListenPort)) ||
			!strings.Contains(flow, "daddr "+spec.ListenHost.String()) {
			t.Fatal("flow add only scoped by shared target/mark")
		}
	}
}

func TestNFTSelectiveACLProtocolAndBudgetBoundaries(t *testing.T) {
	s := nftUnitSpec()
	metaRule := func(value any) nftObject {
		return nftObject{"rule": map[string]any{"family": "inet", "table": "review-external", "chain": "post", "expr": []any{
			map[string]any{"match": map[string]any{"left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "op": "==", "right": value}},
			map[string]any{"accept": nil}}}}
	}
	for _, value := range []any{"icmp", "ipv6-icmp", 0, 1, 58, 255} {
		objects := append(selectivePolicy(s, 0, s.TargetPort), metaRule(value))
		if len(proveSelective(t, objects, s)) != 1 {
			t.Fatalf("literal protocol allowance rejected: %v", value)
		}
	}
	for _, value := range []any{"58", "unknown-protocol", -1, 256, 1.5, nil, true, map[string]any{"numgen": "random"}} {
		objects := append(selectivePolicy(s, 0, s.TargetPort), metaRule(value))
		if len(proveSelective(t, objects, s)) != 0 {
			t.Fatalf("invalid protocol allowance accepted: %v", value)
		}
	}
	objects := selectivePolicy(s, 0, s.TargetPort)
	chain := nftACLChain{object: objects[1], fields: objects[1]["chain"].(map[string]any), parent: objects[0], rules: objects[2:]}
	if ok, err := nftACLChainAccepts(chain, s, &nftACLWork{0}); ok || err == nil {
		t.Fatal("work bound was not enforced")
	}
	// A valid earlier chain is also part of a selective scope's proof. It must
	// not be ignored merely because it precedes our final-priority forward hook.
	earlier := reviewFixHook("drop")
	earlier[0]["table"].(map[string]any)["name"] = "earlier-policy"
	earlier[1]["chain"].(map[string]any)["table"] = "earlier-policy"
	earlier[1]["chain"].(map[string]any)["hook"] = "forward"
	earlier[2]["rule"].(map[string]any)["table"] = "earlier-policy"
	if len(proveSelective(t, append(objects, earlier...), s)) != 0 {
		t.Fatal("another earlier DROP chain was ignored")
	}
}
func TestNFTSelectiveACLScopedPermissionIdentity(t *testing.T) {
	s := nftUnitSpec()
	s.ListenPortEnd += 4
	s.TargetPortEnd += 4
	part := s
	part.ListenPort++
	part.TargetPort++
	if !nftSelectiveScopeCovers(s, part) {
		t.Fatal("contained offset-preserving interval rejected")
	}
	for _, change := range []func(*nftRuleSpec){
		func(x *nftRuleSpec) { x.RuleID += "other" },
		func(x *nftRuleSpec) { x.ConntrackMark++ },
		func(x *nftRuleSpec) { x.ListenPortEnd++ },
		func(x *nftRuleSpec) { x.TargetPort++ },
		func(x *nftRuleSpec) { x.TargetHost = netip.MustParseAddr("198.51.100.99") },
		func(x *nftRuleSpec) { x.ListenHost = netip.IPv4Unspecified() },
	} {
		other := s
		change(&other)
		if nftSelectiveScopeCovers(s, other) {
			t.Fatal("permission escaped the verified rule/tuple domain")
		}
	}
}
