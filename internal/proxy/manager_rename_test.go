package proxy

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"portbridge/internal/config"
)

func startManagedTCPConnection(t *testing.T) (*Manager, config.Rule, net.Conn) {
	t.Helper()
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	go func() {
		conn, acceptErr := target.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	manager := newManagerWithNFT(testLogger(), NewDNSResolver(nil), &fakeNFTBackend{})
	t.Cleanup(manager.Stop)
	rule := config.NormalizeRule(config.Rule{
		ID: "rename-connection", Name: "original", Protocol: config.ProtocolTCP,
		DataPlane: config.RuleDataPlaneGo, ListenHost: "127.0.0.1",
		ListenPort: freeTCPPort(t, "tcp4", "127.0.0.1:0"),
		TargetHost: "127.0.0.1", TargetPort: target.Addr().(*net.TCPAddr).Port,
		Enabled: true, AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"},
	})
	manager.Apply([]config.Rule{rule})
	client, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(rule.ListenPort)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	assertTCPEcho(t, client, "before")
	return manager, rule, client
}

func assertTCPEcho(t *testing.T, conn net.Conn, text string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(text)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(text))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != text {
		t.Fatalf("echo = %q, want %q", got, text)
	}
}

func TestManagerRenameKeepsGoTCPConnection(t *testing.T) {
	manager, rule, client := startManagedTCPConnection(t)
	if len(manager.runners) != 1 {
		t.Fatalf("runners before rename = %d", len(manager.runners))
	}
	var original *runner
	for _, current := range manager.runners {
		original = current
	}
	rule.Name = "renamed"
	manager.Apply([]config.Rule{rule})
	if len(manager.runners) != 1 {
		t.Fatalf("runners after rename = %d", len(manager.runners))
	}
	for _, current := range manager.runners {
		if current != original {
			t.Fatal("display-only rename rebuilt the Go runner")
		}
		if current.name() != "renamed" {
			t.Fatalf("running log name = %q, want renamed", current.name())
		}
	}
	if rows := manager.Runtime(); len(rows) != 1 || rows[0].Rule.Name != "renamed" {
		t.Fatalf("runtime name did not update: %+v", rows)
	}
	assertTCPEcho(t, client, "after")
}

func TestManagerSecurityAndForwardingChangesCloseGoTCPConnection(t *testing.T) {
	cases := []struct {
		name   string
		change func(config.Rule) []config.Rule
	}{
		{"disable", func(rule config.Rule) []config.Rule { rule.Enabled = false; return []config.Rule{rule} }},
		{"delete", func(config.Rule) []config.Rule { return nil }},
		{"tighten target authorization", func(rule config.Rule) []config.Rule {
			rule.TargetCIDRAllowlist = []string{"127.0.0.2/32"}
			return []config.Rule{rule}
		}},
		{"change target port", func(rule config.Rule) []config.Rule { rule.TargetPort++; return []config.Rule{rule} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manager, rule, client := startManagedTCPConnection(t)
			manager.Apply(tc.change(rule))
			if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := client.Read(make([]byte, 1)); err == nil {
				t.Fatal("old TCP connection stayed open after forwarding or security change")
			} else if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("old TCP connection was not revoked")
			}
		})
	}
}
