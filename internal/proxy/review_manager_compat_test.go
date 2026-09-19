package proxy

import (
	"bytes"
	"io"
	"net"
	"portbridge/internal/config"
	"testing"
	"time"
)

// Run in a newly-created user/network namespace to prove the absence of
// old kernel forwarding state. No nft CLI is used or host firewall changed.
func TestReviewCleanForcedGoWithoutNFT(t *testing.T) {
	requireCleanReviewNamespace(t)
	host, targetPort, stopEcho := startTCPEcho(t, "tcp4", "127.0.0.1:0")
	defer stopEcho()
	listenPort := freeTCPPort(t, "tcp4", "127.0.0.1:0")
	rule := config.NormalizeRule(config.Rule{ID: "review-clean-go", Name: "review-clean-go", Enabled: true,
		Protocol: "tcp", DataPlane: config.RuleDataPlaneGo, ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: host, TargetPort: targetPort, AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"}})
	m := NewManager(testLogger())
	if err := m.SetNFTStateConfigPath(privateNFTConfig(t)); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	m.Apply([]config.Rule{rule})
	for _, row := range m.Runtime() {
		t.Logf("runtime id=%s running=%t plane=%s error=%q", row.Rule.ID, row.Stats.Running, row.DataPlane, row.Stats.LastError)
	}
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", portString(listenPort)), time.Second)
	if err != nil {
		t.Fatalf("explicit, authorized pure-Go path cannot accept: %v; actual Go runners=%d", err, len(m.runners))
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("clean-go-compatibility")
	if _, err = conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("echo corrupted")
	}
}
