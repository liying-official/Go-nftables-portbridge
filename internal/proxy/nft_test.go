package proxy

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"portbridge/internal/config"
)

type fakeNFTBackend struct {
	specs       []nftRuleSpec
	replaceErr  error
	replaceCall int
	deleteCall  int
	deleteErr   error
	topologyKey string
}

func (f *fakeNFTBackend) Replace(specs []nftRuleSpec) error {
	f.replaceCall++
	f.specs = append([]nftRuleSpec(nil), specs...)
	return f.replaceErr
}

func (f *fakeNFTBackend) Delete() error {
	f.deleteCall++
	return f.deleteErr
}

func (f *fakeNFTBackend) TopologyKey() string { return f.topologyKey }

func TestRenderNFTScriptDualStackRanges(t *testing.T) {
	specs := []nftRuleSpec{
		{
			RuleID: "v4", Family: 4, ListenHost: netip.IPv4Unspecified(),
			ListenPort: 10000, ListenPortEnd: 10002,
			TargetHost: netip.MustParseAddr("192.0.2.20"),
			TargetPort: 20000, TargetPortEnd: 20002, Protocol: "tcp",
			ConntrackMark: config.DefaultNFTConntrackMark, EnableFlowtable: true,
		},
		{
			RuleID: "v6", Family: 6, ListenHost: netip.MustParseAddr("2001:db8::10"),
			ListenPort: 30000, ListenPortEnd: 30000,
			TargetHost: netip.MustParseAddr("2001:db8:1::20"),
			TargetPort: 40000, TargetPortEnd: 40000, Protocol: "udp",
			ConntrackMark: config.DefaultNFTConntrackMark, EnableFlowtable: true,
		},
	}
	script := renderNFTScript(specs, false, []string{"eth1", "eth0"})
	for _, want := range []string{
		"add table inet portbridge",
		"comment \"Go-nftables-portbridge:managed:v1:50420001\"",
		"add flowtable inet portbridge fastpath { hook ingress priority filter; devices = { \"eth0\", \"eth1\" }; counter; }",
		"type filter hook forward priority filter",
		"type nat hook prerouting priority dstnat",
		"type nat hook output priority dstnat",
		"type nat hook postrouting priority srcnat",
		"meta nfproto ipv4 fib daddr type local tcp dport 10000-10002",
		"meta nfproto ipv4 ip daddr != 127.0.0.0/8 fib daddr type local",
		"dnat ip to 192.0.2.20 : tcp dport map { 10000 : 20000, 10001 : 20001, 10002 : 20002 }",
		"meta nfproto ipv6 ip6 daddr 2001:db8::10 udp dport 30000",
		"dnat ip6 to [2001:db8:1::20]:40000",
		"ct mark set 0x50420001",
		"postrouting ct mark 0x50420001",
		"forward ct mark 0x50420001",
		"ct state established,related flow add @fastpath counter accept",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script does not contain %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, "ct status dnat") {
		t.Fatalf("managed nftables rules must not match unrelated DNAT state: %s", script)
	}
	if strings.Contains(script, "comment \"") && strings.Contains(script, "\" dnat") {
		t.Fatalf("nft comment must be the final statement: %s", script)
	}
}

func TestRenderNFTChainRefreshPreservesFlowtable(t *testing.T) {
	specs := []nftRuleSpec{{
		RuleID: "v4", Family: 4, ListenHost: netip.IPv4Unspecified(),
		ListenPort: 10000, ListenPortEnd: 10002,
		TargetHost: netip.MustParseAddr("192.0.2.20"),
		TargetPort: 20000, TargetPortEnd: 20002, Protocol: "udp",
		ConntrackMark: config.DefaultNFTConntrackMark, EnableFlowtable: true,
	}}
	script := renderNFTChainRefreshScript(specs)
	for _, want := range []string{
		"flush chain inet portbridge prerouting",
		"flush chain inet portbridge output",
		"flush chain inet portbridge postrouting",
		"flush chain inet portbridge forward",
		"dnat ip to 192.0.2.20 : udp dport map { 10000 : 20000, 10001 : 20001, 10002 : 20002 }",
		"flow add @fastpath",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("refresh script does not contain %q:\n%s", want, script)
		}
	}
	for _, unwanted := range []string{"flush table", "add table", "add flowtable", "delete flowtable"} {
		if strings.Contains(script, unwanted) {
			t.Fatalf("refresh script unexpectedly contains %q:\n%s", unwanted, script)
		}
	}
}

func TestRenderNFTWithoutFlowtable(t *testing.T) {
	spec := nftRuleSpec{
		RuleID: "no-flow", Family: 4, ListenHost: netip.IPv4Unspecified(),
		ListenPort: 10000, ListenPortEnd: 10000,
		TargetHost: netip.MustParseAddr("192.0.2.20"),
		TargetPort: 20000, TargetPortEnd: 20000, Protocol: config.ProtocolTCP,
		ConntrackMark: config.DefaultNFTConntrackMark,
	}
	script := renderNFTScript([]nftRuleSpec{spec}, false, nil)
	if strings.Contains(script, "flowtable") || strings.Contains(script, "flow add") {
		t.Fatalf("flowtable-disabled script contains flowtable statements: %s", script)
	}
	if !strings.Contains(script, "forward ct mark 0x50420001") || !strings.Contains(script, "counter accept") {
		t.Fatalf("flowtable-disabled forward rule is incomplete: %s", script)
	}
}

func TestNFTRangeUsesDeterministicPortMap(t *testing.T) {
	spec := nftRuleSpec{
		Family: 6, ListenHost: netip.MustParseAddr("2001:db8::10"),
		ListenPort: 41000, ListenPortEnd: 41002,
		TargetHost: netip.MustParseAddr("2001:db8:1::20"),
		TargetPort: 51000, TargetPortEnd: 51002, Protocol: config.ProtocolUDP,
	}
	got := nftDNAT(spec)
	want := "dnat ip6 to [2001:db8:1::20] : udp dport map { 41000 : 51000, 41001 : 51001, 41002 : 51002 }"
	if got != want {
		t.Fatalf("nftDNAT() = %q, want %q", got, want)
	}
	if strings.Contains(got, ":51000-51002") {
		t.Fatalf("DNAT range must not use a nondeterministic NAT port pool: %s", got)
	}
}

func TestManagerRefreshesNFTOnTopologyChange(t *testing.T) {
	backend := &fakeNFTBackend{topologyKey: "eth0"}
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), backend)
	rule := config.NormalizeRule(config.Rule{
		ID: "topology", Name: "topology", Protocol: config.ProtocolTCP,
		ListenHost: "192.0.2.10", ListenPort: 10001,
		TargetHost: "192.0.2.1", TargetPort: 20001, Enabled: true,
	})
	m.Apply([]config.Rule{rule})
	m.Refresh([]config.Rule{rule})
	if backend.replaceCall != 1 {
		t.Fatalf("unchanged topology replaced nftables rules: %d", backend.replaceCall)
	}
	backend.topologyKey = "eth0\x00eth1"
	m.Refresh([]config.Rule{rule})
	if backend.replaceCall != 2 {
		t.Fatalf("topology change did not replace nftables rules: %d", backend.replaceCall)
	}
}

func TestBuildPlanSelectsDataPlane(t *testing.T) {
	backend := &fakeNFTBackend{}
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), backend)
	rules := []config.Rule{
		config.NormalizeRule(config.Rule{
			ID: "same", Name: "same", Protocol: config.ProtocolTCP,
			ListenHost: "192.0.2.10", ListenPort: 10001,
			TargetHost: "192.0.2.1", TargetPort: 20001, Enabled: true,
		}),
		config.NormalizeRule(config.Rule{
			ID: "cross", Name: "cross", Protocol: config.ProtocolUDP,
			ListenHost: "0.0.0.0", ListenPort: 10002,
			TargetHost: "2001:db8::1", TargetPort: 20002, Enabled: true,
		}),
		config.NormalizeRule(config.Rule{
			ID: "wildcard", Name: "wildcard", Protocol: config.ProtocolBoth,
			ListenHost: "*", ListenPort: 10003,
			TargetHost: "192.0.2.3", TargetPort: 20003, Enabled: true,
		}),
		config.NormalizeRule(config.Rule{
			ID: "forced-go", Name: "forced-go", Protocol: config.ProtocolTCP,
			DataPlane:  config.RuleDataPlaneGo,
			ListenHost: "192.0.2.10", ListenPort: 10004,
			TargetHost: "192.0.2.4", TargetPort: 20004, Enabled: true,
		}),
	}
	plan := m.buildPlan(rules, false)
	if got := plan.dataPlanes["same"]; got != DataPlaneNFT {
		t.Fatalf("same-family data plane = %q", got)
	}
	if got := plan.dataPlanes["cross"]; got != DataPlaneGo {
		t.Fatalf("cross-family data plane = %q", got)
	}
	if got := plan.dataPlanes["wildcard"]; got != DataPlaneHybrid {
		t.Fatalf("wildcard data plane = %q", got)
	}
	if got := plan.dataPlanes["forced-go"]; got != DataPlaneGo {
		t.Fatalf("forced Go data plane = %q", got)
	}
	if len(plan.nftSpecs) != 3 {
		t.Fatalf("nft specs = %d, want 3", len(plan.nftSpecs))
	}
	var crossTargets, wildcardListeners, forcedGoListeners []string
	for _, path := range plan.goRules {
		if path.RuleID == "cross" {
			crossTargets = append(crossTargets, path.Rule.TargetHost)
		}
		if path.RuleID == "wildcard" {
			wildcardListeners = append(wildcardListeners, path.Rule.ListenHost)
		}
		if path.RuleID == "forced-go" {
			forcedGoListeners = append(forcedGoListeners, path.Rule.ListenHost)
		}
	}
	if len(crossTargets) != 1 || crossTargets[0] != "2001:db8::1" {
		t.Fatalf("cross targets = %v", crossTargets)
	}
	if len(wildcardListeners) != 2 || !containsString(wildcardListeners, "127.0.0.1") || !containsString(wildcardListeners, "::") {
		t.Fatalf("wildcard Go listeners = %v", wildcardListeners)
	}
	if len(forcedGoListeners) != 1 || forcedGoListeners[0] != "192.0.2.10" {
		t.Fatalf("forced Go listeners = %v", forcedGoListeners)
	}
}

func TestBuildPlanSharesUDPWorkersAcrossGoPaths(t *testing.T) {
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), &fakeNFTBackend{})
	rule := config.NormalizeRule(config.Rule{
		ID: "workers", Name: "workers", Protocol: config.ProtocolUDP,
		DataPlane: config.RuleDataPlaneGo, UDPWorkers: 4,
		ListenHost: "*", ListenPort: 10000, ListenPortEnd: 10000,
		TargetHost: "192.0.2.1", TargetPort: 20000, TargetPortEnd: 20000, Enabled: true,
	})
	plan := m.buildPlan([]config.Rule{rule}, false)
	if len(plan.goRules) != 2 {
		t.Fatalf("Go paths = %d, want 2", len(plan.goRules))
	}
	total := 0
	for _, path := range plan.goRules {
		if path.Rule.UDPWorkers != 2 {
			t.Fatalf("path workers = %d, want 2", path.Rule.UDPWorkers)
		}
		total += path.Rule.UDPWorkers
	}
	if total != 4 {
		t.Fatalf("total workers = %d, want 4", total)
	}

	rule.ListenHost = "127.0.0.1"
	rule.ListenPortEnd = 10007
	rule.TargetPortEnd = 20007
	plan = m.buildPlan([]config.Rule{rule}, false)
	for _, path := range plan.goRules {
		if path.Rule.UDPWorkers != 8 {
			t.Fatalf("range workers = %d, want minimum 8", path.Rule.UDPWorkers)
		}
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestManagerReportsNFTStatus(t *testing.T) {
	backend := &fakeNFTBackend{}
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), backend)
	rule := config.NormalizeRule(config.Rule{
		ID: "same", Name: "same", Protocol: config.ProtocolTCP,
		ListenHost: "192.0.2.10", ListenPort: 10001,
		TargetHost: "192.0.2.1", TargetPort: 20001, Enabled: true,
	})
	m.Apply([]config.Rule{rule})
	runtime := m.Runtime()
	if len(runtime) != 1 || runtime[0].DataPlane != DataPlaneNFT || !runtime[0].Stats.Running {
		t.Fatalf("unexpected runtime: %+v", runtime)
	}
	if backend.replaceCall != 1 || len(backend.specs) != 1 {
		t.Fatalf("unexpected backend calls=%d specs=%d", backend.replaceCall, len(backend.specs))
	}
	m.Refresh([]config.Rule{rule})
	if backend.replaceCall != 1 {
		t.Fatalf("unchanged refresh replaced nftables rules: %d", backend.replaceCall)
	}
	m.Stop()
	if backend.deleteCall != 1 {
		t.Fatalf("delete calls = %d", backend.deleteCall)
	}
}

func TestManagerReportsNFTApplyFailure(t *testing.T) {
	backend := &fakeNFTBackend{replaceErr: errors.New("permission denied")}
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), backend)
	rule := config.NormalizeRule(config.Rule{
		ID: "same", Name: "same", Protocol: config.ProtocolTCP,
		ListenHost: "192.0.2.10", ListenPort: 10001,
		TargetHost: "192.0.2.1", TargetPort: 20001, Enabled: true,
	})
	m.Apply([]config.Rule{rule})
	runtime := m.Runtime()
	if len(runtime) != 1 || runtime[0].Stats.Running || !strings.Contains(runtime[0].Stats.LastError, "permission denied") {
		t.Fatalf("unexpected runtime: %+v", runtime)
	}
	if backend.deleteCall != 1 {
		t.Fatalf("failed nftables apply did not trigger fail-closed cleanup: delete calls = %d", backend.deleteCall)
	}
}

func TestManagerDoesNotHideStaleNFTForwardingWhenCleanupFails(t *testing.T) {
	backend := &fakeNFTBackend{}
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), backend)
	rule := config.NormalizeRule(config.Rule{
		ID: "stale", Name: "stale", Protocol: config.ProtocolTCP,
		ListenHost: "192.0.2.10", ListenPort: 10001,
		TargetHost: "192.0.2.1", TargetPort: 20001, Enabled: true,
	})
	m.Apply([]config.Rule{rule})

	backend.replaceErr = errors.New("replace denied")
	backend.deleteErr = errors.New("delete denied")
	disabled := rule
	disabled.Enabled = false
	m.Refresh([]config.Rule{disabled})
	runtime := m.Runtime()
	if len(runtime) != 1 || !runtime[0].Stats.Running || !strings.Contains(runtime[0].Stats.LastError, "may still be active") {
		t.Fatalf("stale disabled rule was hidden: %+v", runtime)
	}

	m.Refresh(nil)
	runtime = m.Runtime()
	if len(runtime) != 1 || !runtime[0].Stats.Running || !strings.Contains(runtime[0].Stats.LastError, "may still be active") {
		t.Fatalf("stale deleted rule tombstone was hidden: %+v", runtime)
	}

	backend.replaceErr = nil
	backend.deleteErr = nil
	m.Refresh(nil)
	if runtime = m.Runtime(); len(runtime) != 0 {
		t.Fatalf("rule tombstone remained after successful cleanup: %+v", runtime)
	}
}
