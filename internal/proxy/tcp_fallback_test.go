package proxy

import (
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"portbridge/internal/config"
)

func TestGoTCPBackupAfterPrimaryConnectFailure(t *testing.T) {
	backup, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	go func() {
		for {
			conn, err := backup.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	manager := newManagerWithNFT(testLogger(), NewDNSResolver(nil), &fakeNFTBackend{})
	defer manager.Stop()
	primaryPort := freeTCPPort(t, "tcp4", "127.0.0.1:0")
	rule := config.NormalizeRule(config.Rule{
		ID: "backup-connect", Name: "backup-connect", Protocol: config.ProtocolTCP,
		DataPlane: config.RuleDataPlaneGo, Enabled: true, ListenHost: "127.0.0.1",
		ListenPort: freeTCPPort(t, "tcp4", "127.0.0.1:0"), TargetHost: "127.0.0.1", TargetPort: primaryPort,
		BackupTargetHost: "127.0.0.1", BackupTargetPort: backup.Addr().(*net.TCPAddr).Port,
		TCPHealthIntervalSeconds: 5, TCPHealthTimeoutSeconds: 1,
		AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"},
	})
	if err := config.Validate(config.Config{Version: config.CurrentVersion, Web: config.Default().Web, Limits: config.Default().Limits, NFT: config.Default().NFT, Rules: []config.Rule{rule}}); err != nil {
		t.Fatal(err)
	}
	manager.Apply([]config.Rule{rule})
	client, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(rule.ListenPort)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	assertTCPEcho(t, client, "backup")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rows := manager.Runtime()
		if len(rows) == 1 && rows[0].BackendConnectivity.Status == "backup_reachable" && rows[0].Stats.TCPFallbacks > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("backup connect check/fallback not observed: %+v", manager.Runtime())
}

func TestDNSFailureCacheHasBoundedValidity(t *testing.T) {
	m := newManagerWithNFT(testLogger(), NewDNSResolver([]string{"127.0.0.1:1"}), &fakeNFTBackend{})
	rule := config.NormalizeRule(config.Rule{
		ID: "bounded-cache", Name: "bounded-cache", TargetHost: "cache.portbridge.test", ConnectTimeoutSeconds: 1,
		DNSCacheTTLSeconds: 5, AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"},
	})
	m.resolved[rule.ID] = resolvedTarget{host: rule.TargetHost, addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, fetchedAt: time.Now().Add(-6 * time.Second)}
	if got, err := m.resolveTarget(rule, true); err == nil {
		t.Fatalf("expired DNS cache was reused: %v", got)
	}
	m.resolved[rule.ID] = resolvedTarget{host: rule.TargetHost, addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, fetchedAt: time.Now()}
	if got, err := m.resolveTarget(rule, true); err != nil || len(got) != 1 || got[0].String() != "127.0.0.1" {
		t.Fatalf("fresh authorized cache not reused: %v, %v", got, err)
	}
	rule.AllowPrivateTarget = false
	if got, err := m.resolveTarget(rule, true); err == nil {
		t.Fatalf("cached target bypassed authorization: %v", got)
	}
}

func TestBackendConnectivityAggregatesAllDerivedGoRunners(t *testing.T) {
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), &fakeNFTBackend{})
	rule := config.NormalizeRule(config.Rule{ID: "multi-path", Name: "multi-path", Protocol: config.ProtocolTCP, DataPlane: config.RuleDataPlaneGo})
	m.rules[rule.ID] = rule
	m.stats[rule.ID] = &Stats{}
	reachable := &tcpTargetState{}
	reachable.primaryReachable.Store(true)
	reachable.checkedUnixNano.Store(time.Now().UnixNano())
	unreachable := &tcpTargetState{}
	unreachable.checkedUnixNano.Store(time.Now().UnixNano())
	m.runners["first"] = &runner{rule: rule, healthStates: []*tcpTargetState{reachable}}
	m.runners["second"] = &runner{rule: rule, healthStates: []*tcpTargetState{unreachable}}
	rows := m.Runtime()
	if len(rows) != 1 || rows[0].BackendConnectivity.Status != "unreachable" {
		t.Fatalf("multi-path status masked an unreachable runner: %+v", rows)
	}
}
