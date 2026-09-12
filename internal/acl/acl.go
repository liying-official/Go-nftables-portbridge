package acl

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync/atomic"

	"portbridge/internal/config"
)

type Snapshot struct {
	Auto      []netip.Prefix
	Whitelist []netip.Prefix
	Bootstrap []netip.Prefix
	Strict    bool
}

type Manager struct {
	snapshot atomic.Pointer[Snapshot]
}

func New(autoLAN, strict bool, whitelist, bootstrap []string) (*Manager, error) {
	m := &Manager{}
	if err := m.Refresh(autoLAN, strict, whitelist, bootstrap); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) Refresh(autoLAN, strict bool, whitelist, bootstrap []string) error {
	white, err := parsePrefixes(whitelist)
	if err != nil {
		return err
	}
	boot, err := parsePrefixes(bootstrap)
	if err != nil {
		return fmt.Errorf("bootstrap allowlist: %w", err)
	}
	if strict && autoLAN {
		return fmt.Errorf("strict IP allowlist mode cannot be combined with automatic LAN ACL")
	}
	if strict && len(white) == 0 {
		return fmt.Errorf("strict IP allowlist mode requires an explicit whitelist")
	}
	auto := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
	if autoLAN && !strict {
		detected, err := DetectLANPrefixes()
		if err != nil {
			return err
		}
		auto = append(auto, detected...)
	}
	if strict {
		// Bootstrap prefixes are intentionally excluded in strict mode. They are
		// command-line recovery aids and can otherwise remain as a hidden,
		// broader permission after the persistent whitelist is configured.
		boot = nil
	}
	auto = dedupe(auto)
	m.snapshot.Store(&Snapshot{Auto: auto, Whitelist: white, Bootstrap: boot, Strict: strict})
	return nil
}

func (m *Manager) Allowed(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	s := m.snapshot.Load()
	if s == nil {
		return false
	}
	for _, list := range [][]netip.Prefix{s.Auto, s.Whitelist, s.Bootstrap} {
		for _, p := range list {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

func (m *Manager) Snapshot() Snapshot {
	s := m.snapshot.Load()
	if s == nil {
		return Snapshot{}
	}
	return Snapshot{
		Auto:      append([]netip.Prefix(nil), s.Auto...),
		Whitelist: append([]netip.Prefix(nil), s.Whitelist...),
		Bootstrap: append([]netip.Prefix(nil), s.Bootstrap...),
		Strict:    s.Strict,
	}
}

func DetectLANPrefixes() ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var out []netip.Prefix
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, raw := range addrs {
			prefix, err := netip.ParsePrefix(raw.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr()
			if ip.Is4In6() {
				ip = ip.Unmap()
				prefix = netip.PrefixFrom(ip, prefix.Bits()-96)
			}
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
				out = append(out, prefix.Masked())
			}
		}
	}
	return dedupe(out), nil
}

func parsePrefixes(items []string) ([]netip.Prefix, error) {
	normalized, err := config.NormalizeWhitelist(items)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Prefix, 0, len(normalized))
	for _, s := range normalized {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func dedupe(in []netip.Prefix) []netip.Prefix {
	set := make(map[string]netip.Prefix, len(in))
	for _, p := range in {
		p = p.Masked()
		set[p.String()] = p
	}
	out := make([]netip.Prefix, 0, len(set))
	for _, p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return strings.Compare(out[i].String(), out[j].String()) < 0 })
	return out
}
