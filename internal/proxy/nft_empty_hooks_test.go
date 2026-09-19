package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"portbridge/internal/config"
)

// Unlike a Chains-only fixture, this implements the COMPLETE ruleset operation
// explicitly. All reads project the same stored objects/rules; Apply still runs
// the existing causal transaction interpreter. Negative tests populate actual
// rule objects and prove that an accept policy does not imply emptiness.
// This is L1, not nft syntax acceptance or real packet/OFFLOAD observation.
type fixFullRulesKernel struct {
	*causalNFTKernel
	ruleReads int
	ruleErr   error
	raw       []byte
	afterRead func(int)
}

func (k *fixFullRulesKernel) Ruleset() ([]byte, error) {
	k.ruleReads++
	if k.afterRead != nil {
		k.afterRead(k.ruleReads)
	}
	if k.ruleErr != nil {
		return nil, k.ruleErr
	}
	if k.raw != nil {
		return k.raw, nil
	}
	if k.readErr != nil {
		return nil, k.readErr
	}
	objects := append(cloneNFTTestObjects(k.objects), cloneNFTTestObjects(k.external)...)
	return nftTestJSON(objects), nil
}
func fixEmptyHook(family, hook string) []nftObject {
	priority := 0
	if hook == "forward" {
		priority = nftForwardPriority
	}
	return []nftObject{
		{"table": map[string]any{"family": family, "name": "external-control"}},
		{"chain": map[string]any{"family": family, "table": "external-control", "name": "after", "type": "filter", "hook": hook, "prio": priority, "policy": "accept"}},
	}
}
func fixHookRule(family string, expr any) nftObject {
	return nftObject{"rule": map[string]any{"family": family, "table": "external-control", "chain": "after", "expr": []any{expr}}}
}
func fixFullBackend(k *fixFullRulesKernel, ct conntrackKernelIO, path string) *commandNFTBackend {
	n := reviewBackend(k.causalNFTKernel, ct, path)
	n.kernel = k
	return n
}
func requireFixBAdmission(t *testing.T, n *commandNFTBackend, m *Manager, b nftRuleSpec) {
	t.Helper()
	if !n.initialized || !nftSpecInstalled(b, n.activeSpecs) || len(n.suspendedSpecs) != 0 {
		t.Fatalf("B admission not installed without degradation: %+v", n.retirementState())
	}
	row, ok := runtimeByID(m, b.RuleID)
	if !ok || row.KernelState != "active-verified" || row.GoRunning || !row.Stats.Running || row.Stats.LastError != "" {
		t.Fatalf("B runtime disagrees with active objects: %+v", row)
	}
	// Look at ACTUALLY applied fixture objects, not just activeSpecs.
	observed, err := n.observe()
	if err != nil {
		t.Fatal(err)
	}
	for _, hook := range []string{"prerouting", "output", "postrouting", "forward"} {
		want := nftRuleInspectionKey(nftExpectedRule(b, hook))
		found := false
		for _, object := range observed.objects {
			if r, ok := object["rule"].(map[string]any); ok && nftRuleInspectionKey(r) == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("B has no installed %s object", hook)
		}
	}
	session, err := n.store.begin(n.ownerMarker)
	if err != nil {
		t.Fatal(err)
	}
	defer session.close()
	if session.record == nil || session.record.Phase != "checkpoint" || len(session.record.Confirmed.Suspended) != 0 {
		t.Fatal("B disk state disagrees with verified admission")
	}
	found := false
	for _, path := range session.record.Confirmed.Active {
		if path.Identity == nftRuleIdentity(b) && path.Spec.EnableFlowtable {
			found = true
		}
	}
	if !found {
		t.Fatal("B flowtable eligibility was silently removed from durable state")
	}
}

// Mapping of the supplied failure probe: same A/B/foreign assertions, plus a
// complete external table+chain+rule store and actual installed NAT/flow rules.
// A descriptor-only fake is intentionally still unable to certify emptiness.
func TestReview246UnrelatedRuleNewAdmissionContract(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			a, b := reviewAB()
			a.Protocol = protocol
			b.Protocol = protocol
			k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a, b)}
			ct := &memoryConntrack{}
			n := fixFullBackend(k, ct, privateNFTConfig(t))
			m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
			ra, rb := ruleFromNFTSpec(a), ruleFromNFTSpec(b)
			m.Apply([]config.Rule{ra, rb})
			if !n.initialized {
				t.Fatal("fixture setup failed")
			}
			one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
			control := one
			control.mark++
			ct.entries = []conntrackEntry{one, two, control}
			k.external = fixEmptyHook("inet", "postrouting")
			external := string(nftTestJSON(k.external))
			ra.Enabled = false
			m.Apply([]config.Rule{ra, rb})
			requireNFTEntries(t, ct, two, control)
			if len(ct.deleted) != 1 || ct.deleted[0] != one {
				t.Fatal("A was not exclusively retired")
			}
			requireFixBAdmission(t, n, m, b)
			if k.ruleReads < 4 || string(nftTestJSON(k.external)) != external {
				t.Fatal("complete proof was not read or external objects changed")
			}
			t.Logf("L1 A_old_conntrack=false B_old_conntrack=true foreign_conntrack=true B_new_admission=true B_kernel_state=active-verified flowtable_requested=true full_ruleset_reads=%d; no real kernel OFFLOAD claim", k.ruleReads)
		})
	}
}

func startFixDNSServer(t *testing.T, initial netip.Addr) (string, func(netip.Addr), func()) {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var value atomic.Value
	value.Store(initial)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, peer, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:n]...)
			if len(q) < 17 {
				continue
			}
			pos := 12
			for pos < len(q) && q[pos] != 0 {
				if q[pos] > 63 {
					pos = len(q)
					break
				}
				pos += int(q[pos]) + 1
			}
			if pos+5 > len(q) {
				continue
			}
			pos++
			typeID := binary.BigEndian.Uint16(q[pos : pos+2])
			addr := value.Load().(netip.Addr)
			count := uint16(0)
			if (typeID == 1 && addr.Is4()) || (typeID == 28 && addr.Is6()) {
				count = 1
			}
			r := make([]byte, 12)
			copy(r, q[:2])
			binary.BigEndian.PutUint16(r[2:], 0x8180)
			binary.BigEndian.PutUint16(r[4:], 1)
			binary.BigEndian.PutUint16(r[6:], count)
			r = append(r, q[12:pos+4]...)
			if count == 1 {
				raw := addr.AsSlice()
				r = append(r, 0xc0, 0x0c, byte(typeID>>8), byte(typeID), 0, 1, 0, 0, 0, 0, 0, byte(len(raw)))
				r = append(r, raw...)
			}
			_, _ = c.WriteToUDP(r, peer)
		}
	}()
	stop := func() { _ = c.Close(); <-done }
	t.Cleanup(stop)
	return c.LocalAddr().String(), func(a netip.Addr) { value.Store(a) }, stop
}
func fixFamilySpec(s nftRuleSpec, family int) nftRuleSpec {
	s.Family = family
	if family == 6 {
		s.ListenHost = netip.MustParseAddr("2001:db8:1::1")
		s.TargetHost = netip.MustParseAddr("2001:db8:2::2")
	}
	return s
}
func fixFamilyEntry(s nftRuleSpec, port uint16) conntrackEntry {
	e := conntrackUnitEntry(s, port)
	if s.Family == 6 {
		e.original.source = netip.MustParseAddr("2001:db8:1::2")
		e.reply.destination = netip.MustParseAddr("2001:db8:2::1")
	}
	return e
}
func TestNFTEmptyHookRetirementMatrix(t *testing.T) {
	testNFTCompatibleHookRetirementMatrix(t, false)
}

func TestNFTAcceptHookRetirementMatrix(t *testing.T) {
	testNFTCompatibleHookRetirementMatrix(t, true)
}

func testNFTCompatibleHookRetirementMatrix(t *testing.T, acceptOnly bool) {
	testNFTCompatibleHookRetirementMatrixWithPolicy(t, acceptOnly, nil)
}

func testNFTCompatibleHookRetirementMatrixWithPolicy(t *testing.T, acceptOnly bool, policy func() []nftObject) {
	t.Helper()
	for _, family := range []int{4, 6} {
		for _, protocol := range []string{"tcp", "udp"} {
			for _, operation := range []string{"disable", "delete", "change-target", "authorization-withdrawn", "dns-address-changed", "dns-failed-cached-authorization-withdrawn", "nft-to-go"} {
				t.Run(fmt.Sprintf("ipv%d/%s/%s", family, protocol, operation), func(t *testing.T) {
					a, b := reviewAB()
					a = fixFamilySpec(a, family)
					b = fixFamilySpec(b, family)
					a.Protocol = protocol
					b.Protocol = protocol
					a.TargetHost = netip.MustParseAddr("10.23.0.2")
					if family == 6 {
						a.TargetHost = netip.MustParseAddr("fd42:23::2")
					}
					changed := a
					changed.TargetHost = netip.MustParseAddr("10.23.0.3")
					if family == 6 {
						changed.TargetHost = netip.MustParseAddr("fd42:23::3")
					}
					k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a, b, changed)}
					ct := &memoryConntrack{}
					n := fixFullBackend(k, ct, privateNFTConfig(t))
					ra, rb := ruleFromNFTSpec(a), ruleFromNFTSpec(b)
					ra.AllowPrivateTarget = true
					bits := 32
					if family == 6 {
						bits = 128
					}
					ra.TargetCIDRAllowlist = []string{a.TargetHost.String() + "/" + strconv.Itoa(bits), changed.TargetHost.String() + "/" + strconv.Itoa(bits)}
					ra.ConnectTimeoutSeconds = 1
					var servers []string
					var setDNS func(netip.Addr)
					var stopDNS func()
					if strings.HasPrefix(operation, "dns-") {
						server, set, stop := startFixDNSServer(t, a.TargetHost)
						servers = []string{server}
						setDNS = set
						stopDNS = stop
						ra.TargetHost = "controlled.portbridge.test"
					}
					m := newManagerWithNFT(testLogger(), NewDNSResolver(servers), n)
					defer m.Stop()
					m.Apply([]config.Rule{ra, rb})
					if !n.initialized || len(n.activeSpecs) != 2 {
						t.Fatalf("matrix setup failed: %+v", m.Runtime())
					}
					one, two := fixFamilyEntry(a, 45000), fixFamilyEntry(b, 45001)
					control := one
					control.mark++
					ct.entries = []conntrackEntry{one, two, control}
					k.external = fixEmptyHook("inet", "postrouting")
					if acceptOnly {
						for i := 0; i < 3; i++ {
							k.external = append(k.external, fixHookRule("inet", map[string]any{"accept": nil}))
						}
					}
					if policy != nil {
						k.external = policy()
					}
					external := string(nftTestJSON(k.external))
					desired := []config.Rule{ra, rb}
					var goEndpoint, goNetwork string
					switch operation {
					case "disable":
						ra.Enabled = false
					case "delete":
						desired = []config.Rule{rb}
					case "change-target":
						ra.TargetHost = changed.TargetHost.String()
					case "authorization-withdrawn":
						ra.AllowPrivateTarget = false
						ra.TargetCIDRAllowlist = nil
					case "dns-address-changed":
						setDNS(changed.TargetHost)
					case "dns-failed-cached-authorization-withdrawn":
						stopDNS()
						ra.AllowPrivateTarget = false
						ra.TargetCIDRAllowlist = nil
					case "nft-to-go":
						host := "127.0.0.1"
						suffix := "4"
						if family == 6 {
							host = "::1"
							suffix = "6"
						}
						goNetwork = protocol + suffix
						var targetPort int
						var stop func()
						if protocol == "tcp" {
							_, targetPort, stop = startTCPEcho(t, goNetwork, net.JoinHostPort(host, "0"))
							ra.ListenPort = freeTCPPort(t, goNetwork, net.JoinHostPort(host, "0"))
						} else {
							_, targetPort, stop = startUDPEcho(t, goNetwork, net.JoinHostPort(host, "0"))
							ra.ListenPort = freeUDPPort(t, goNetwork, net.JoinHostPort(host, "0"))
						}
						defer stop()
						ra.DataPlane = config.RuleDataPlaneGo
						ra.ListenHost = host
						ra.ListenPortEnd = ra.ListenPort
						ra.TargetHost = host
						ra.TargetPort = targetPort
						ra.TargetPortEnd = targetPort
						ra.TargetCIDRAllowlist = []string{host + "/" + strconv.Itoa(bits)}
						goEndpoint = net.JoinHostPort(host, strconv.Itoa(ra.ListenPort))
					}
					if operation != "delete" {
						desired = []config.Rule{ra, rb}
					}
					m.Refresh(desired)
					requireNFTEntries(t, ct, two, control)
					if len(ct.deleted) != 1 || ct.deleted[0] != one || len(n.pendingSpecs) != 0 {
						t.Fatal("matrix retirement was not exact")
					}
					requireFixBAdmission(t, n, m, b)
					if policy != nil {
						requireTransparentFlowtable(t, k.objects)
					}
					if string(nftTestJSON(k.external)) != external {
						t.Fatal("external state changed")
					}
					for _, s := range n.activeSpecs {
						if nftIdentityMatchesRule(s, a.RuleID) && s.TargetHost == a.TargetHost {
							t.Fatal("A old path was re-admitted")
						}
					}
					if operation == "change-target" || operation == "dns-address-changed" {
						if !nftSpecInstalled(changed, n.activeSpecs) {
							t.Fatal("authorized new A path not installed")
						}
					}
					if operation == "nft-to-go" {
						row, _ := runtimeByID(m, a.RuleID)
						if !row.GoRunning {
							t.Fatalf("explicit Go transition did not run: %+v", row)
						}
						c, err := net.DialTimeout(goNetwork, goEndpoint, time.Second)
						if err != nil {
							t.Fatal(err)
						}
						defer c.Close()
						_ = c.SetDeadline(time.Now().Add(2 * time.Second))
						payload := []byte("explicit-go-transition")
						if _, err := c.Write(payload); err != nil {
							t.Fatal(err)
						}
						buf := make([]byte, len(payload))
						if _, err := io.ReadFull(c, buf); err != nil || string(buf) != string(payload) {
							t.Fatalf("actual Go echo failed: %v", err)
						}
					}
					beforeWrites, beforeLists := k.writes, ct.ownedLists+ct.lists
					m.Refresh(desired)
					if k.writes != beforeWrites || ct.ownedLists+ct.lists != beforeLists {
						t.Fatal("unchanged empty-hook refresh rebuilt objects or scanned connections")
					}
				})
			}
		}
	}
}

func TestNFTEmptyHookUnknownPolicyAndReadFailuresPreserveRetirement(t *testing.T) {
	for _, scenario := range []string{"drop-rule", "counter-accept-still-unsupported", "counter-rule", "unknown-expression", "drop-policy", "unknown-chain-metadata", "ruleset-timeout", "incomplete-ruleset", "missing-table", "dangling-rule", "duplicate-chain", "changed-during-proof", "new-conflict-family"} {
		t.Run(scenario, func(t *testing.T) {
			a, b := reviewAB()
			k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a, b)}
			ct := &memoryConntrack{}
			n := fixFullBackend(k, ct, privateNFTConfig(t))
			m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
			ra, rb := ruleFromNFTSpec(a), ruleFromNFTSpec(b)
			m.Apply([]config.Rule{ra, rb})
			if !n.initialized {
				t.Fatal("setup")
			}
			one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
			ct.entries = []conntrackEntry{one, two}
			k.external = fixEmptyHook("inet", "postrouting")
			switch scenario {
			case "drop-rule":
				k.external = append(k.external, fixHookRule("inet", map[string]any{"drop": nil}))
			case "counter-accept-still-unsupported":
				r := fixHookRule("inet", map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}})
				r["rule"].(map[string]any)["expr"] = append(r["rule"].(map[string]any)["expr"].([]any), map[string]any{"accept": nil})
				k.external = append(k.external, r)
			case "counter-rule":
				k.external = append(k.external, fixHookRule("inet", map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}))
			case "unknown-expression":
				k.external = append(k.external, fixHookRule("inet", map[string]any{"unknown": true}))
			case "drop-policy":
				k.external[1]["chain"].(map[string]any)["policy"] = "drop"
			case "unknown-chain-metadata":
				k.external[1]["chain"].(map[string]any)["packets"] = 0
			case "ruleset-timeout":
				k.ruleErr = context.DeadlineExceeded
			case "incomplete-ruleset":
				k.raw = []byte(`{"nftables":[`)
			case "missing-table":
				k.external = k.external[1:]
			case "dangling-rule":
				r := fixHookRule("inet", map[string]any{"drop": nil})
				r["rule"].(map[string]any)["chain"] = "unlisted"
				k.external = append(k.external, r)
			case "duplicate-chain":
				k.external = append(k.external, cloneNFTTestObjects(k.external[1:])[0])
			case "changed-during-proof":
				k.afterRead = func(count int) {
					if count == 2 {
						k.external = append(k.external, fixHookRule("inet", map[string]any{"drop": nil}))
					}
				}
			case "new-conflict-family":
				k.external = fixEmptyHook("ip", "postrouting")
				k.afterRead = func(count int) {
					if count == 1 {
						k.external = append(k.external, fixEmptyHook("inet", "postrouting")...)
						k.external = append(k.external, fixHookRule("inet", map[string]any{"drop": nil}))
					}
				}
			}
			ra.Enabled = false
			m.Apply([]config.Rule{ra, rb})
			requireNFTEntries(t, ct, two)
			if len(ct.deleted) != 1 || ct.deleted[0] != one || len(n.activeSpecs) != 0 || len(n.suspendedSpecs) != 1 {
				t.Fatalf("unsafe compatibility acceptance or A retirement short circuit: %+v", m.Runtime())
			}
			row, _ := runtimeByID(m, b.RuleID)
			if row.KernelState != "admission-suspended" || row.GoRunning {
				t.Fatal("rejection was disguised as active/fallback")
			}
			if scenario == "counter-accept-still-unsupported" {
				t.Log("UNRESOLVED broader compatibility: counter accept has side effects and is outside the pure-accept grammar; unproved is not a proven external deny")
			}
		})
	}
}

func TestNFTEmptyHookConflictLifecycleAndFamilyScope(t *testing.T) {
	a, b := reviewAB()
	b = fixFamilySpec(b, 6)
	k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a, b)}
	ct := &memoryConntrack{}
	path := privateNFTConfig(t)
	n := fixFullBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{a, b}); err != nil {
		t.Fatal(err)
	}
	one, two := fixFamilyEntry(a, 45000), fixFamilyEntry(b, 45001)
	ct.entries = []conntrackEntry{one, two}
	k.external = append(fixEmptyHook("ip", "postrouting"), fixHookRule("ip", map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}))
	if err := n.Replace([]nftRuleSpec{a, b}); err == nil {
		t.Fatal("nonempty IPv4 policy accepted")
	}
	if len(n.suspendedSpecs) != 1 || !nftSpecInstalled(b, n.activeSpecs) {
		t.Fatal("IPv4 conflict expanded into unrelated IPv6")
	}
	k.external = append(fixEmptyHook("inet", "postrouting"), fixHookRule("inet", map[string]any{"drop": nil}))
	if err := n.Replace([]nftRuleSpec{a, b}); err == nil {
		t.Fatal("expanded policy accepted")
	}
	if len(n.activeSpecs) != 0 || len(n.suspendedSpecs) != 2 {
		t.Fatal("expanded family gate not reflected")
	}
	for _, o := range k.objects {
		if _, ok := o["flowtable"]; ok {
			t.Fatal("cached acceleration object remained after increased rejection")
		}
	}
	// Reconstruct the process under a persistent conflict, then delete suspended B.
	n = fixFullBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{a}); err == nil {
		t.Fatal("remaining A conflict hidden")
	}
	requireNFTEntries(t, ct, one)
	if len(ct.deleted) != 1 || ct.deleted[0] != two {
		t.Fatal("suspended B deletion broadened into A")
	}
	// Empty the actual external rule store. Restore A's unchanged flowtable policy.
	k.external = fixEmptyHook("inet", "postrouting")
	if err := n.Replace([]nftRuleSpec{a}); err != nil {
		t.Fatal(err)
	}
	if !nftSpecInstalled(a, n.activeSpecs) || len(n.suspendedSpecs) != 0 {
		t.Fatal("empty-chain recovery did not restore A")
	}
	before := k.writes
	lists := ct.ownedLists + ct.lists
	reads := k.ruleReads
	if err := n.Replace([]nftRuleSpec{a}); err != nil {
		t.Fatal(err)
	}
	if k.writes != before || ct.ownedLists+ct.lists != lists || k.ruleReads != reads+2 {
		t.Fatal("unchanged refresh cached rule proof or changed objects/connections")
	}
	k.external = nil
	if err := n.Replace([]nftRuleSpec{a}); err != nil {
		t.Fatal(err)
	}
	requireNFTEntries(t, ct, one)
}

func TestNFTEmptyHookDescriptorOnlyIsNotRuleProof(t *testing.T) {
	a, _ := reviewAB()
	k := newCausalNFTKernel(a)
	k.external = fixEmptyHook("inet", "postrouting")
	n := reviewBackend(k, &memoryConntrack{}, "")
	var typed *nftAdmissionError
	if err := n.checkAdmissionFor([]nftRuleSpec{a}); !errors.As(err, &typed) {
		t.Fatal("descriptor-only fake certified real-chain emptiness")
	}
}

// Ensure the previous strict decoder's empty/nonempty distinction is unchanged
// by the scoped boot and rule-empty proof helpers. This file never forges the
// success of verifyEmptyNetfilter or uses an environment trust override.
func TestNFTEmptyHookProofRejectsDuplicateAndOversizedInventory(t *testing.T) {
	for _, data := range [][]byte{[]byte(`{"nftables":[],"nftables":[]}`), []byte(`{"nftables":null}`), []byte(`{"nftables":[]} trailing`), []byte(strings.Repeat(" ", maxNFTOutputBytes+1))} {
		if _, err := decodeNFTProofObjects(data); err == nil {
			t.Fatal("ambiguous/unbounded proof inventory accepted")
		}
	}
	// Keep os referenced for the explicit namespace evidence in test logs.
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("L1 proof decoder namespace=%s (not kernel flow verification)", ns)
}

// An inconsistent snapshot must fail. A later complete stable snapshot may
// succeed: bounded fresh reinspection is not an optimistic cached admission.
func TestNFTEmptyHookChangedFamilyRejectsSnapshotThenRechecks(t *testing.T) {
	a, _ := reviewAB()
	k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a)}
	k.external = fixEmptyHook("ip", "postrouting")
	initial, err := nftConflictingHooks(cloneNFTTestObjects(k.external))
	if err != nil {
		t.Fatal(err)
	}
	k.afterRead = func(count int) {
		if count == 1 {
			k.external = append(k.external, fixEmptyHook("ip6", "postrouting")...)
		}
	}
	if _, _, err := verifyNFTCompatibleExternalHooks(k, initial); err == nil {
		t.Fatal("changed snapshot certified emptiness")
	}
	initial, err = nftConflictingHooks(cloneNFTTestObjects(k.external))
	if err != nil {
		t.Fatal(err)
	}
	before := k.ruleReads
	remaining, _, err := verifyNFTCompatibleExternalHooks(k, initial)
	if err != nil || len(remaining) != 0 || k.ruleReads != before+2 {
		t.Fatalf("fresh two-pass proof failed: %v", err)
	}
}

func TestNFTEmptyHookForwardAndManualModeBoundaries(t *testing.T) {
	for _, hook := range []string{"forward", "postrouting"} {
		for _, family := range []string{"ip", "ip6", "inet"} {
			t.Run(hook+"/"+family, func(t *testing.T) {
				a, b := reviewAB()
				b = fixFamilySpec(b, 6)
				k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a, b)}
				k.external = fixEmptyHook(family, hook)
				n := fixFullBackend(k, &memoryConntrack{}, privateNFTConfig(t))
				if err := n.Replace([]nftRuleSpec{a, b}); err != nil {
					t.Fatal(err)
				}
				if k.ruleReads != 2 || len(n.activeSpecs) != 2 {
					t.Fatal("complete empty proof not selected")
				}
			})
		}
	}
	a, _ := reviewAB()
	a.EnableFlowtable = false
	k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a)}
	k.external = append(fixEmptyHook("inet", "postrouting"), fixHookRule("inet", map[string]any{"drop": nil}))
	n := fixFullBackend(k, &memoryConntrack{}, privateNFTConfig(t))
	if err := n.Replace([]nftRuleSpec{a}); err != nil {
		t.Fatal("explicit NAT-only mode changed:", err)
	}
	if n.activeSpecs[0].EnableFlowtable {
		t.Fatal("manual mode silently changed")
	}
	k.external = nil
	before := k.ruleReads
	if err := n.Replace([]nftRuleSpec{a}); err != nil {
		t.Fatal(err)
	}
	if k.ruleReads != before {
		t.Fatal("no-conflict refresh added full ruleset reads")
	}
}
