package proxy

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// v2.4.4 has no journal. Recover only exact renderer-shaped prerouting rules
// from an already ownership-verified table; never infer ownership from mark alone.
func recoverLegacyNFTSpecs(objects []nftObject, owner string) ([]nftRuleSpec, error) {
	flowtable := false
	for _, object := range objects {
		if _, ok := object["flowtable"]; ok {
			flowtable = true
		}
	}
	var specs []nftRuleSpec
	for _, object := range objects {
		rule, ok := object["rule"].(map[string]any)
		if !ok || rule["chain"] != "prerouting" {
			continue
		}
		comment, _ := rule["comment"].(string)
		parts := strings.Split(comment, ":")
		if len(parts) != 5 || parts[0] != "pb" || parts[4] != "prerouting" || !validNFTIdentity("l"+parts[1]) {
			return nil, errors.New("cannot recover an unrecognized owned NAT rule")
		}
		family, err := strconv.Atoi(parts[2])
		if err != nil {
			return nil, err
		}
		spec := nftRuleSpec{RuleID: "kernel-l" + parts[1], ruleIdentity: "l" + parts[1], Family: family, Protocol: parts[3], EnableFlowtable: flowtable}
		ipProtocol := "ip6"
		if family == 4 {
			ipProtocol = "ip"
		}
		expr, ok := rule["expr"].([]any)
		if !ok {
			return nil, errors.New("missing legacy NAT expressions")
		}
		for _, item := range expr {
			protocol, field, right, ok := nftPayloadMatch(item)
			if ok {
				if protocol == ipProtocol && field == "daddr" {
					raw, _ := right.(string)
					spec.ListenHost, err = netip.ParseAddr(raw)
				}
				if protocol == spec.Protocol && field == "dport" {
					spec.ListenPort, spec.ListenPortEnd, err = nftJSONPortRange(right)
				}
				if err != nil {
					return nil, errors.New("invalid legacy NAT match")
				}
			}
			value, ok := item.(map[string]any)
			if !ok {
				return nil, errors.New("invalid NAT expression")
			}
			if mangle, ok := value["mangle"].(map[string]any); ok {
				if key, ok := mangle["key"].(map[string]any); ok {
					if ct, ok := key["ct"].(map[string]any); ok && ct["key"] == "mark" {
						mark, e := nftJSONUint(mangle["value"], 32)
						if e != nil {
							return nil, e
						}
						spec.ConntrackMark = uint32(mark)
					}
				}
			}
			if match, ok := value["match"].(map[string]any); ok {
				if left, ok := match["left"].(map[string]any); ok {
					if _, ok := left["fib"]; ok {
						if family == 4 {
							spec.ListenHost = netip.IPv4Unspecified()
						} else {
							spec.ListenHost = netip.IPv6Unspecified()
						}
					}
				}
			}
			if dnat, ok := value["dnat"].(map[string]any); ok {
				raw, _ := dnat["addr"].(string)
				spec.TargetHost, err = netip.ParseAddr(raw)
				if err != nil {
					return nil, errors.New("invalid legacy NAT target")
				}
				port := dnat["port"]
				if object, ok := port.(map[string]any); ok {
					mapping, ok := object["map"].(map[string]any)
					if !ok {
						return nil, errors.New("unsupported legacy NAT port mapping")
					}
					data, ok := mapping["data"].(map[string]any)
					if !ok {
						return nil, errors.New("invalid legacy NAT port map")
					}
					pairs, ok := data["set"].([]any)
					if !ok || len(pairs) == 0 || len(pairs) > 4096 {
						return nil, errors.New("invalid legacy NAT map size")
					}
					type pair struct{ listen, target int }
					ports := make([]pair, 0, len(pairs))
					for _, rawPair := range pairs {
						values, ok := rawPair.([]any)
						if !ok || len(values) != 2 {
							return nil, errors.New("invalid legacy NAT map pair")
						}
						a, e := nftJSONUint(values[0], 16)
						if e != nil {
							return nil, e
						}
						b, e := nftJSONUint(values[1], 16)
						if e != nil {
							return nil, e
						}
						ports = append(ports, pair{int(a), int(b)})
					}
					sort.Slice(ports, func(i, j int) bool { return ports[i].listen < ports[j].listen })
					for i, p := range ports {
						if p.listen != ports[0].listen+i || p.target != ports[0].target+i {
							return nil, errors.New("non-deterministic legacy port map")
						}
					}
					spec.TargetPort = ports[0].target
					spec.TargetPortEnd = spec.TargetPort + len(ports) - 1
				} else {
					spec.TargetPort, spec.TargetPortEnd, err = nftJSONPortRange(port)
					if err != nil {
						return nil, err
					}
				}
			}
		}
		if err := validateRetirementSpec(spec); err != nil || nftOwnerMarker(spec.ConntrackMark) != owner {
			return nil, errors.New("legacy NAT ownership tuple is invalid")
		}
		want := nftExpectedRule(spec, "prerouting")
		want["comment"] = comment
		if nftRuleInspectionKey(rule) != nftRuleInspectionKey(want) {
			return nil, errors.New("legacy NAT rule contains unrecognized policy expressions")
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func resolveNFTIdentities(specs, desired []nftRuleSpec) []nftRuleSpec {
	result := append([]nftRuleSpec(nil), specs...)
	for i := range result {
		id := nftRuleIdentity(result[i])
		candidates := make(map[string]string)
		for _, want := range desired {
			full := nftRuleIdentity(want)
			if full == id || (len(id) == 13 && id[0] == 'l' && strings.HasPrefix(full, id[1:])) {
				if _, exists := candidates[full]; !exists {
					candidates[full] = want.RuleID
				}
			}
		}
		if len(candidates) == 1 {
			for full, raw := range candidates {
				result[i].RuleID = raw
				result[i].ruleIdentity = full
			}
		}
	}
	return result
}

func nftRetirementKey(spec nftRuleSpec) string {
	end := spec.ListenPortEnd
	if end == 0 {
		end = spec.ListenPort
	}
	targetEnd := spec.TargetPortEnd
	if targetEnd == 0 {
		targetEnd = spec.TargetPort
	}
	return fmt.Sprintf("%s|%d|%s|%d-%d|%s|%d-%d|%s|%08x", nftRuleIdentity(spec), spec.Family,
		spec.ListenHost, spec.ListenPort, end, spec.TargetHost, spec.TargetPort, targetEnd, spec.Protocol, spec.ConntrackMark)
}
func uniqueNFTSpecs(groups ...[]nftRuleSpec) []nftRuleSpec {
	seen := make(map[string]nftRuleSpec)
	for _, group := range groups {
		for _, spec := range group {
			seen[nftRetirementKey(spec)] = spec
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]nftRuleSpec, 0, len(keys))
	for _, key := range keys {
		result = append(result, seen[key])
	}
	return result
}

type nftPortInterval struct{ first, last int }

func nftSubtractPortRange(parts []nftPortInterval, first, last int) []nftPortInterval {
	var out []nftPortInterval
	for _, part := range parts {
		if last < part.first || first > part.last {
			out = append(out, part)
			continue
		}
		if first > part.first {
			out = append(out, nftPortInterval{part.first, first - 1})
		}
		if last < part.last {
			out = append(out, nftPortInterval{last + 1, part.last})
		}
	}
	return out
}
func nftSlicePorts(spec nftRuleSpec, part nftPortInterval) nftRuleSpec {
	target := spec.TargetPort + part.first - spec.ListenPort
	spec.ListenPort, spec.ListenPortEnd = part.first, part.last
	spec.TargetPort, spec.TargetPortEnd = target, target+part.last-part.first
	return spec
}
func nftLastPort(spec nftRuleSpec) int {
	if spec.ListenPortEnd == 0 {
		return spec.ListenPort
	}
	return spec.ListenPortEnd
}
func retiredNFTSpecs(old, desired []nftRuleSpec) []nftRuleSpec {
	var retired []nftRuleSpec
	for _, previous := range old {
		parts := []nftPortInterval{{previous.ListenPort, nftLastPort(previous)}}
		for _, next := range desired {
			if nftRuleIdentity(previous) != nftRuleIdentity(next) || previous.Family != next.Family || previous.Protocol != next.Protocol ||
				previous.ConntrackMark != next.ConntrackMark || previous.ListenHost != next.ListenHost || previous.TargetHost != next.TargetHost ||
				previous.TargetPort-previous.ListenPort != next.TargetPort-next.ListenPort {
				continue
			}
			parts = nftSubtractPortRange(parts, next.ListenPort, nftLastPort(next))
		}
		for _, part := range parts {
			retired = append(retired, nftSlicePorts(previous, part))
		}
	}
	return uniqueNFTSpecs(retired)
}
func gateNFTReplacements(desired, pending []nftRuleSpec) []nftRuleSpec {
	var gated []nftRuleSpec
	for _, next := range desired {
		parts := []nftPortInterval{{next.ListenPort, nftLastPort(next)}}
		for _, old := range pending {
			if old.Family != next.Family || old.Protocol != next.Protocol ||
				(!old.ListenHost.IsUnspecified() && !next.ListenHost.IsUnspecified() && old.ListenHost != next.ListenHost) {
				continue
			}
			parts = nftSubtractPortRange(parts, old.ListenPort, nftLastPort(old))
		}
		for _, part := range parts {
			gated = append(gated, nftSlicePorts(next, part))
		}
	}
	return gated
}
