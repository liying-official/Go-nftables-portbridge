package acl

import (
	"net/netip"
	"testing"
)

func TestWhitelistSingleIPAndCIDR(t *testing.T) {
	m, err := New(false, false, []string{"192.0.2.10", "2001:db8:10::/64"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip      string
		allowed bool
	}{
		{"127.0.0.1", true},
		{"192.0.2.10", true},
		{"192.0.2.11", false},
		{"2001:db8:10::99", true},
		{"2001:db8:11::1", false},
	}
	for _, tc := range cases {
		if got := m.Allowed(netip.MustParseAddr(tc.ip)); got != tc.allowed {
			t.Errorf("Allowed(%s)=%v, want %v", tc.ip, got, tc.allowed)
		}
	}
}

func TestStrictAllowlistExcludesAutomaticAndBootstrapPrefixes(t *testing.T) {
	m, err := New(false, true, []string{"192.0.2.10"}, []string{"198.51.100.20"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ip      string
		allowed bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"192.0.2.10", true},
		{"192.0.2.11", false},
		{"198.51.100.20", false},
	} {
		if got := m.Allowed(netip.MustParseAddr(tc.ip)); got != tc.allowed {
			t.Errorf("Allowed(%s)=%v, want %v", tc.ip, got, tc.allowed)
		}
	}
	snap := m.Snapshot()
	if !snap.Strict || len(snap.Bootstrap) != 0 {
		t.Fatalf("strict snapshot = %#v", snap)
	}
}

func TestStrictAllowlistRejectsBroadImplicitAccess(t *testing.T) {
	if _, err := New(true, true, []string{"192.0.2.10"}, nil); err == nil {
		t.Fatal("strict mode accepted automatic LAN ACL")
	}
	if _, err := New(false, true, nil, nil); err == nil {
		t.Fatal("strict mode accepted an empty explicit whitelist")
	}
}
