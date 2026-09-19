package proxy

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"portbridge/internal/config"
)

const (
	DataPlaneDisabled = "disabled"
	DataPlaneNFT      = "nftables"
	DataPlaneGo       = "go-proxy"
	DataPlaneHybrid   = "hybrid"
)

type resolvedTarget struct {
	host  string
	addrs []netip.Addr
}

type forwardingPlan struct {
	nftSpecs   []nftRuleSpec
	goRules    map[string]goPath
	dataPlanes map[string]string
	errors     map[string]error
	usesNFT    map[string]bool
	usesGo     map[string]bool
}

type goPath struct {
	RuleID string
	Rule   config.Rule
}

type listenFamily struct {
	family int
	host   netip.Addr
}

func (m *Manager) buildPlan(rules []config.Rule, allowCachedDNS bool) forwardingPlan {
	plan := forwardingPlan{
		goRules:    make(map[string]goPath),
		dataPlanes: make(map[string]string),
		errors:     make(map[string]error),
		usesNFT:    make(map[string]bool),
		usesGo:     make(map[string]bool),
	}
	for _, raw := range rules {
		rule := config.NormalizeRule(raw)
		if !rule.Enabled {
			plan.dataPlanes[rule.ID] = DataPlaneDisabled
			continue
		}
		addresses, err := m.resolveTarget(rule, allowCachedDNS)
		if err != nil {
			plan.errors[rule.ID] = err
			continue
		}

		hasNFT, hasGo := false, false
		for _, listener := range listenFamilies(rule.ListenHost) {
			target, sameFamily := firstAddressForFamily(addresses, listener.family)
			if rule.DataPlane == config.RuleDataPlaneGo {
				if !sameFamily {
					target, _ = firstAddressForOtherFamily(addresses, listener.family)
				}
				if !target.IsValid() {
					plan.errors[rule.ID] = fmt.Errorf("target %q has no usable address for IPv%d ingress", rule.TargetHost, listener.family)
					continue
				}
				plan.addGoPath(rule, listener.host, target, "forced")
				hasGo = true
				continue
			}
			if sameFamily && target.Zone() == "" && !listener.host.IsLoopback() {
				protocols := []string{rule.Protocol}
				if rule.Protocol == config.ProtocolBoth {
					protocols = []string{config.ProtocolTCP, config.ProtocolUDP}
				}
				for _, protocol := range protocols {
					plan.nftSpecs = append(plan.nftSpecs, nftRuleSpec{
						RuleID: rule.ID, Family: listener.family, ListenHost: listener.host,
						ListenPort: rule.ListenPort, ListenPortEnd: rule.LastListenPort(),
						TargetHost: target, TargetPort: rule.TargetPort,
						TargetPortEnd: rule.LastTargetPort(), Protocol: protocol,
						ConntrackMark: m.nftMark, EnableFlowtable: m.nftFlowtable,
					})
				}
				hasNFT = true
				plan.usesNFT[rule.ID] = true
				if listener.host.IsUnspecified() {
					loopback := netip.IPv6Loopback()
					if listener.family == 4 {
						loopback = netip.MustParseAddr("127.0.0.1")
					}
					plan.addGoPath(rule, loopback, target, "loopback")
					hasGo = true
				}
				continue
			}

			if !sameFamily {
				target, _ = firstAddressForOtherFamily(addresses, listener.family)
			}
			if !target.IsValid() {
				plan.errors[rule.ID] = fmt.Errorf("target %q has no usable address for IPv%d ingress", rule.TargetHost, listener.family)
				continue
			}
			plan.addGoPath(rule, listener.host, target, "proxy")
			hasGo = true
		}

		switch {
		case hasNFT && hasGo:
			plan.dataPlanes[rule.ID] = DataPlaneHybrid
		case hasNFT:
			plan.dataPlanes[rule.ID] = DataPlaneNFT
		case hasGo:
			plan.dataPlanes[rule.ID] = DataPlaneGo
		default:
			plan.dataPlanes[rule.ID] = DataPlaneDisabled
		}
	}
	plan.distributeGoUDPWorkers(rules)
	return plan
}

// distributeGoUDPWorkers turns the user-facing rule-wide worker budget into
// per-runner budgets after wildcard and hybrid rules have been split into Go
// paths. Every listen socket still gets one worker, while extra workers are
// balanced across address families instead of being multiplied by each path.
func (p *forwardingPlan) distributeGoUDPWorkers(rules []config.Rule) {
	for _, raw := range rules {
		rule := config.NormalizeRule(raw)
		if rule.Protocol != config.ProtocolUDP && rule.Protocol != config.ProtocolBoth {
			continue
		}
		keys := make([]string, 0, 2)
		for key, path := range p.goRules {
			if path.RuleID == rule.ID {
				keys = append(keys, key)
			}
		}
		if len(keys) == 0 {
			continue
		}
		sort.Strings(keys)
		endpointsPerPath := rule.LastListenPort() - rule.ListenPort + 1
		totalEndpoints := endpointsPerPath * len(keys)
		totalWorkers := effectiveUDPWorkers(rule.UDPWorkers)
		if totalWorkers < totalEndpoints {
			totalWorkers = totalEndpoints
		}
		extra := totalWorkers - totalEndpoints
		for i, key := range keys {
			pathWorkers := endpointsPerPath + extra/len(keys)
			if i < extra%len(keys) {
				pathWorkers++
			}
			path := p.goRules[key]
			path.Rule.UDPWorkers = pathWorkers
			p.goRules[key] = path
		}
	}
}

func (p *forwardingPlan) addGoPath(rule config.Rule, listenHost, targetHost netip.Addr, kind string) {
	derived := rule
	derived.ListenHost = listenHost.String()
	derived.TargetHost = targetHost.String()
	key := fmt.Sprintf("%s|%s|%s|%s", rule.ID, kind, listenHost, targetHost)
	p.goRules[key] = goPath{RuleID: rule.ID, Rule: derived}
	p.usesGo[rule.ID] = true
}

func (m *Manager) resolveTarget(rule config.Rule, allowCached bool) ([]netip.Addr, error) {
	if address, err := netip.ParseAddr(rule.TargetHost); err == nil {
		address = address.Unmap()
		if err := config.ValidateTargetAddress(rule, address); err != nil {
			return nil, err
		}
		return []netip.Addr{address}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rule.ConnectTimeoutSeconds)*time.Second)
	defer cancel()
	addresses, err := m.resolver.LookupNetIP(ctx, rule.TargetHost)
	if err != nil || len(addresses) == 0 {
		if cached, ok := m.resolved[rule.ID]; allowCached && ok && cached.host == rule.TargetHost && len(cached.addrs) > 0 {
			for _, address := range cached.addrs {
				if policyErr := config.ValidateTargetAddress(rule, address); policyErr != nil {
					return nil, fmt.Errorf("cached target authorization failed: %w", policyErr)
				}
			}
			m.logger.Warn("DNS refresh failed; retaining previous target", "rule", rule.Name, "target", rule.TargetHost, "error", err)
			return append([]netip.Addr(nil), cached.addrs...), nil
		}
		if err == nil {
			err = fmt.Errorf("no addresses returned")
		}
		return nil, fmt.Errorf("resolve target %q: %w", rule.TargetHost, err)
	}
	unique := make(map[string]netip.Addr)
	for _, address := range addresses {
		address = address.Unmap()
		if address.IsValid() {
			if err := config.ValidateTargetAddress(rule, address); err != nil {
				return nil, fmt.Errorf("resolve target %q: %w", rule.TargetHost, err)
			}
			unique[address.String()] = address
		}
	}
	addresses = addresses[:0]
	for _, address := range unique {
		addresses = append(addresses, address)
	}
	sort.Slice(addresses, func(i, j int) bool {
		if addresses[i].BitLen() != addresses[j].BitLen() {
			return addresses[i].BitLen() < addresses[j].BitLen()
		}
		return addresses[i].Less(addresses[j])
	})
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolve target %q: no usable IP addresses returned", rule.TargetHost)
	}
	m.resolved[rule.ID] = resolvedTarget{host: rule.TargetHost, addrs: append([]netip.Addr(nil), addresses...)}
	return addresses, nil
}

func listenFamilies(host string) []listenFamily {
	if host == "*" {
		return []listenFamily{
			{family: 4, host: netip.IPv4Unspecified()},
			{family: 6, host: netip.IPv6Unspecified()},
		}
	}
	address, _ := netip.ParseAddr(strings.TrimSpace(host))
	address = address.Unmap()
	if address.Is4() {
		return []listenFamily{{family: 4, host: address}}
	}
	return []listenFamily{{family: 6, host: address}}
}

func firstAddressForFamily(addresses []netip.Addr, family int) (netip.Addr, bool) {
	for _, address := range addresses {
		if family == 4 && address.Is4() || family == 6 && address.Is6() {
			return address, true
		}
	}
	return netip.Addr{}, false
}

func firstAddressForOtherFamily(addresses []netip.Addr, family int) (netip.Addr, bool) {
	other := 4
	if family == 4 {
		other = 6
	}
	return firstAddressForFamily(addresses, other)
}
