package proxy

import (
	"testing"

	"portbridge/internal/config"
)

func TestCachedDNSRechecksWithdrawnTargetAuthorization(t *testing.T) {
	server, closeServer := startTestDNSServer(t)
	defer closeServer()
	m := newManagerWithNFT(testLogger(), NewDNSResolver([]string{server}), &fakeNFTBackend{})
	rule := config.NormalizeRule(config.Rule{
		ID: "cached-authorization", TargetHost: "revocation.portbridge.test", ConnectTimeoutSeconds: 1,
		AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"},
	})
	addresses, err := m.resolveTarget(rule, false)
	if err != nil || len(addresses) != 1 || addresses[0].String() != "127.0.0.1" {
		t.Fatalf("authorized DNS baseline failed: %v %v", addresses, err)
	}
	closeServer()
	rule.AllowPrivateTarget = false
	rule.TargetCIDRAllowlist = nil
	if addresses, err := m.resolveTarget(rule, true); err == nil {
		t.Fatalf("DNS failure reused a now-unauthorized cached target: %v", addresses)
	}
}
