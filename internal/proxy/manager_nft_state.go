package proxy

import (
	"net/netip"
	"strconv"
	"strings"

	"portbridge/internal/config"
)

type nftRetirementReporter interface {
	retirementState() nftRetirementState
}

func nftIdentityMatchesRule(spec nftRuleSpec, id string) bool {
	want := nftRuleIdentity(nftRuleSpec{RuleID: id})
	got := nftRuleIdentity(spec)
	return want == got || (len(got) == 13 && got[0] == 'l' && strings.HasPrefix(want, got[1:]))
}
func nftSpecInstalled(spec nftRuleSpec, active []nftRuleSpec) bool {
	for _, current := range active {
		if nftRetirementKey(current) == nftRetirementKey(spec) && current.EnableFlowtable == spec.EnableFlowtable {
			return true
		}
	}
	return false
}
func goRuleOverlapsNFT(rule config.Rule, spec nftRuleSpec) bool {
	if rule.Protocol != config.ProtocolBoth && rule.Protocol != spec.Protocol {
		return false
	}
	if rule.LastListenPort() < spec.ListenPort || rule.ListenPort > nftLastPort(spec) {
		return false
	}
	for _, listener := range listenFamilies(rule.ListenHost) {
		if listener.family == spec.Family && (listener.host.IsUnspecified() || spec.ListenHost.IsUnspecified() || listener.host == spec.ListenHost) {
			return true
		}
	}
	return false
}

func (m *Manager) nftTombstoneID(base, identity string, desired map[string]config.Rule) string {
	for i := 0; i <= len(m.rules)+len(desired); i++ {
		id := base
		if i > 0 {
			id += "-" + strconv.Itoa(i)
		}
		if _, exists := desired[id]; exists {
			continue
		}
		if _, exists := m.rules[id]; exists && m.nftTombstones[id] != identity {
			continue
		}
		m.nftTombstones[id] = identity
		return id
	}
	panic("bounded tombstone identifier space exhausted")
}

// Adds runtime-only tombstones, never configuration or new forwarding paths.
func (m *Manager) nftRetirementStatus(desired map[string]config.Rule, plan forwardingPlan, nftErr error, inspectionFailed bool) (map[string]bool, map[string]bool) {
	blocked, verified := make(map[string]bool), make(map[string]bool)
	reporter, aware := m.nft.(nftRetirementReporter)
	if nftErr == nil {
		return blocked, verified
	}
	if !aware {
		return blocked, verified
	}
	state := reporter.retirementState()
	if inspectionFailed {
		state.Verified = false
	}
	potential := uniqueNFTSpecs(state.Pending, state.Suspended)
	if !state.Verified {
		potential = uniqueNFTSpecs(potential, state.Active)
	}
	mark := func(spec nftRuleSpec) {
		found := false
		for id := range desired {
			if nftIdentityMatchesRule(spec, id) {
				blocked[id] = true
				found = true
			}
		}
		for id := range m.rules {
			if nftIdentityMatchesRule(spec, id) {
				blocked[id] = true
				found = true
			}
		}
		if found {
			return
		}
		base := "kernel-pending-" + nftRuleIdentity(spec)
		id := m.nftTombstoneID(base, nftRuleIdentity(spec), desired)
		rule := config.Rule{ID: id, Name: "Previous kernel path requires cleanup", Protocol: spec.Protocol, DataPlane: config.RuleDataPlaneNFT,
			ListenHost: spec.ListenHost.String(), ListenPort: spec.ListenPort, ListenPortEnd: nftLastPort(spec),
			TargetHost: spec.TargetHost.String(), TargetPort: spec.TargetPort, TargetPortEnd: spec.TargetPortEnd, Enabled: false}
		m.rules[id] = rule
		if m.stats[id] == nil {
			m.stats[id] = &Stats{}
		}
		if m.budgets[id] == nil {
			m.budgets[id] = &ruleBudget{}
		}
		m.dataPlanes[id] = DataPlaneNFT
		blocked[id] = true
	}
	for _, spec := range potential {
		mark(spec)
	}
	if state.Unknown {
		for id := range desired {
			blocked[id] = true
		}
		id := m.nftTombstoneID("kernel-recovery-unverified", "unknown", desired)
		m.rules[id] = config.Rule{ID: id, Name: "Previous kernel state could not be verified", Protocol: config.ProtocolBoth,
			DataPlane: config.RuleDataPlaneNFT, ListenHost: netip.IPv4Unspecified().String(), Enabled: false}
		if m.stats[id] == nil {
			m.stats[id] = &Stats{}
		}
		if m.budgets[id] == nil {
			m.budgets[id] = &ruleBudget{}
		}
		m.dataPlanes[id] = DataPlaneNFT
		blocked[id] = true
	}
	for _, path := range plan.goRules {
		for _, spec := range potential {
			if goRuleOverlapsNFT(path.Rule, spec) {
				blocked[path.RuleID] = true
				break
			}
		}
	}
	if state.Verified && !state.Unknown {
		for id := range plan.usesNFT {
			ok := true
			for _, spec := range plan.nftSpecs {
				if spec.RuleID == id && !nftSpecInstalled(spec, state.Active) {
					ok = false
					break
				}
			}
			verified[id] = ok && !blocked[id]
		}
	}
	return blocked, verified
}

// nftRuleState describes kernel evidence separately from actual Go listeners.
// A suspended rule may still have established ordinary NAT connections; it is
// not equivalent to a completed retirement or an available new-flow path.
func (m *Manager) nftRuleState(id string) (string, bool) {
	reporter, ok := m.nft.(nftRetirementReporter)
	if !ok {
		return "not-reported", false
	}
	state := reporter.retirementState()
	for _, s := range state.Pending {
		if nftIdentityMatchesRule(s, id) {
			return "retirement-pending", true
		}
	}
	for _, s := range state.Suspended {
		if nftIdentityMatchesRule(s, id) {
			return "admission-suspended", true
		}
	}
	for _, s := range state.Active {
		if nftIdentityMatchesRule(s, id) {
			if state.Verified && !state.Unknown {
				return "active-verified", true
			}
			return "active-unverified", true
		}
	}
	if state.Unknown {
		return "unknown", false
	}
	if state.Verified {
		return "inactive-verified", false
	}
	return "unverified", false
}

// Per-path decisions must not broaden an exact pending TCP/IPv4 range to all
// protocols/families belonging to the same logical rule. Runtime tombstones
// remain rule-wide; runner admission uses the actual ingress overlap instead.
func (m *Manager) goPathBlockedByNFT(rule config.Rule, nftErr error, inspectionFailed bool) bool {
	if nftErr == nil {
		return false
	}
	reporter, ok := m.nft.(nftRetirementReporter)
	if !ok {
		return false
	}
	state := reporter.retirementState()
	if state.Unknown {
		return true
	}
	potential := uniqueNFTSpecs(state.Pending, state.Suspended)
	if !state.Verified || inspectionFailed {
		potential = uniqueNFTSpecs(potential, state.Active)
	}
	for _, spec := range potential {
		if goRuleOverlapsNFT(rule, spec) {
			return true
		}
	}
	return false
}
