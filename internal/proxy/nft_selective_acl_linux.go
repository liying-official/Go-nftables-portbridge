package proxy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
)

// A deliberately sufficient (not complete) proof for stateless selective ACLs.
// Every relevant external chain must be accepted for the WHOLE configured flow
// domain in both directions. Unknown clients are never guessed from a sample.
// Exact Core predicates and bounded literal IPPROTO allowances followed by
// accept are supported; the global G248 proof grammar is unchanged.
// Explicit drop/reject, effects, jumps, sets and external NAT remain unproved.
const maxNFTSelectiveWork = 1 << 20

type nftACLPort struct{ first, last uint64 }
type nftACLView struct {
	source, destination netip.Addr // invalid means arbitrary/unknown
	sport, dport        nftACLPort
	family              int
	protocol            string
}
type nftACLChain struct {
	object nftObject
	fields map[string]any
	parent nftObject
	rules  []nftObject
}
type nftACLWork struct{ remaining int }

// The selective proof also permits protocol-only ICMP allowances commonly
// needed for IPv6 neighbour discovery. This does not broaden the G248 global
// transparent-chain grammar; values are still literal IPPROTO numbers/names.
func nftACLRuleSyntax(rule map[string]any, family string) bool {
	if family != "ip" && family != "ip6" && family != "inet" {
		return false
	}
	if !nftHookMetadata(rule, "rule") {
		return false
	}
	expr, ok := rule["expr"].([]any)
	if !ok || len(expr) < 1 || len(expr) > nftTransparentMaxMatches+1 {
		return false
	}
	last, ok := expr[len(expr)-1].(map[string]any)
	if !ok || !nftTransparentKeys(last, "accept") || last["accept"] != nil {
		return false
	}
	for _, item := range expr[:len(expr)-1] {
		if nftTransparentMatch(item, family) {
			continue
		}
		statement, ok := item.(map[string]any)
		if !ok || !nftTransparentKeys(statement, "match") {
			return false
		}
		match, ok := statement["match"].(map[string]any)
		if !ok || !nftTransparentKeys(match, "left", "op", "right") {
			return false
		}
		if match["op"] != "==" && match["op"] != "!=" {
			return false
		}
		if nftTransparentSelector(match["left"], family) != nftTransparentL4Proto {
			return false
		}
		if name, ok := match["right"].(string); ok {
			if name != "icmp" && name != "ipv6-icmp" {
				return false
			}
		} else if n, ok := nftTransparentUint(match["right"]); !ok || n > 255 {
			return false
		}
	}
	return true
}
func (b *nftACLWork) take(n int) bool {
	b.remaining -= n
	return b.remaining >= 0
}
func nftACLPortRange(first, last int) nftACLPort {
	if last == 0 {
		last = first
	}
	return nftACLPort{uint64(first), uint64(last)}
}
func nftACLViews(spec nftRuleSpec, hook string, priority int64) []nftACLView {
	anyPort := nftACLPort{0, 65535}
	original := nftACLView{destination: spec.TargetHost, sport: anyPort,
		dport: nftACLPortRange(spec.TargetPort, spec.TargetPortEnd), family: spec.Family, protocol: spec.Protocol}
	reply := nftACLView{source: spec.TargetHost, sport: original.dport, dport: anyPort,
		family: spec.Family, protocol: spec.Protocol}
	listen := spec.ListenHost
	if listen.IsUnspecified() {
		listen = netip.Addr{}
	}
	if hook == "prerouting" && priority <= -100 {
		before := original
		before.destination = listen
		before.dport = nftACLPortRange(spec.ListenPort, spec.ListenPortEnd)
		if priority == -100 {
			return []nftACLView{before, original, reply}
		}
		return []nftACLView{before, reply}
	}
	if hook == "postrouting" && priority >= 100 {
		after := reply
		after.source = listen
		after.sport = nftACLPortRange(spec.ListenPort, spec.ListenPortEnd)
		// At equal hook priority either NAT ordering is possible. Prove both.
		if priority == 100 {
			return []nftACLView{original, reply, after}
		}
		return []nftACLView{original, after}
	}
	return []nftACLView{original, reply}
}
func nftACLPortAlways(domain nftACLPort, op string, value uint64) bool {
	switch op {
	case "==":
		return domain.first == value && domain.last == value
	case "!=":
		return value < domain.first || value > domain.last
	case "<":
		return domain.last < value
	case "<=":
		return domain.last <= value
	case ">":
		return domain.first > value
	case ">=":
		return domain.first >= value
	}
	return false
}
func nftACLMatchAlways(statement any, view nftACLView) bool {
	// Called only after the complete rule has passed the unchanged Core grammar.
	match := statement.(map[string]any)["match"].(map[string]any)
	left := match["left"].(map[string]any)
	op := match["op"].(string)
	right := match["right"]
	if raw, ok := left["meta"]; ok {
		key := raw.(map[string]any)["key"]
		var actual uint64
		symbol := ""
		if key == "nfproto" {
			actual, symbol = 2, "ipv4"
			if view.family == 6 {
				actual, symbol = 10, "ipv6"
			}
		} else {
			actual, symbol = 6, "tcp"
			if view.protocol == "udp" {
				actual, symbol = 17, "udp"
			}
		}
		equal := false
		if s, ok := right.(string); ok {
			equal = s == symbol
		} else {
			value, _ := nftTransparentUint(right)
			equal = value == actual
		}
		if op == "!=" {
			return !equal
		}
		return equal
	}
	payload := left["payload"].(map[string]any)
	protocol := payload["protocol"].(string)
	field := payload["field"].(string)
	if protocol == "tcp" || protocol == "udp" {
		if protocol != view.protocol {
			return false
		} // never infer a read of a different transport
		port := view.dport
		if field == "sport" {
			port = view.sport
		}
		value, _ := nftTransparentUint(right)
		return nftACLPortAlways(port, op, value)
	}
	if (protocol == "ip") != (view.family == 4) {
		return false
	}
	address := view.destination
	if field == "saddr" {
		address = view.source
	}
	if !address.IsValid() {
		return false
	}
	value, err := netip.ParseAddr(right.(string))
	if err != nil {
		return false
	}
	equal := address == value
	if op == "!=" {
		return !equal
	}
	return equal
}
func nftACLChainAccepts(chain nftACLChain, spec nftRuleSpec, work *nftACLWork) (bool, error) {
	if !work.take(1) {
		return false, errors.New("selective ACL proof work limit exceeded")
	}
	fields := chain.fields
	parent, _ := chain.parent["table"].(map[string]any)
	if !nftHookMetadata(fields, "chain") || !nftHookMetadata(parent, "table") {
		return false, nil
	}
	priority, err := strconv.ParseInt(fmt.Sprint(fields["prio"]), 10, 32)
	if err != nil {
		return false, nil
	}
	if fields["type"] == "nat" {
		// Additional NAT invalidates the owned DNAT/reverse-NAT projection.
		return len(chain.rules) == 0 && fields["policy"] == "accept", nil
	}
	hook, _ := fields["hook"].(string)
	if fields["type"] != "filter" || (hook != "prerouting" && hook != "forward" && hook != "postrouting") {
		return len(chain.rules) == 0 && fields["policy"] == "accept", nil
	}
	policy := fields["policy"]
	if policy != "accept" && policy != "drop" {
		return false, nil
	}
	family, _ := fields["family"].(string)
	for _, object := range chain.rules {
		rule := object["rule"].(map[string]any)
		expr, _ := rule["expr"].([]any)
		if !work.take(len(expr) + 1) {
			return false, errors.New("selective ACL proof work limit exceeded")
		}
		if !nftACLRuleSyntax(rule, family) {
			return false, nil
		}
	}
	if policy == "accept" {
		return true, nil
	}
	for _, view := range nftACLViews(spec, hook, priority) {
		accepted := false
		for _, object := range chain.rules {
			rule := object["rule"].(map[string]any)
			expr := rule["expr"].([]any)
			if !work.take(len(expr) + 1) {
				return false, errors.New("selective ACL proof work limit exceeded")
			}
			matches := true
			for _, statement := range expr[:len(expr)-1] {
				if !nftACLMatchAlways(statement, view) {
					matches = false
					break
				}
			}
			if matches {
				accepted = true
				break
			}
		}
		if !accepted {
			return false, nil
		}
	}
	return true, nil
}
func nftSelectiveScopeCovers(allowed, actual nftRuleSpec) bool {
	return allowed.EnableFlowtable && nftRuleIdentity(allowed) == nftRuleIdentity(actual) &&
		allowed.Family == actual.Family && allowed.Protocol == actual.Protocol &&
		allowed.ConntrackMark == actual.ConntrackMark && allowed.ListenHost == actual.ListenHost &&
		allowed.TargetHost == actual.TargetHost && allowed.ListenPort <= actual.ListenPort &&
		nftLastPort(allowed) >= nftLastPort(actual) &&
		allowed.TargetPort-allowed.ListenPort == actual.TargetPort-actual.ListenPort
}

// The caller has already validated complete inventory, parent membership and
// duplicates with nftProvablyCompatibleHooks. No live-traffic tuple is used as
// a permission oracle. Counter-bearing managed rules are not proof inputs.
func nftProveSelectiveScopes(objects, conflicts []nftObject, specs []nftRuleSpec) ([]nftRuleSpec, string, error) {
	if len(specs) == 0 || len(conflicts) == 0 {
		return nil, "", nil
	}
	work := &nftACLWork{maxNFTSelectiveWork}
	tables := make(map[string]nftObject)
	chains := make(map[string]*nftACLChain)
	var chainOrder []string
	for _, object := range objects {
		if !work.take(1) {
			return nil, "", errors.New("selective ACL proof work limit exceeded")
		}
		if fields, ok := object["table"].(map[string]any); ok {
			tables[fmt.Sprint(fields["family"])+"\x00"+fmt.Sprint(fields["name"])] = object
		}
		if fields, ok := object["chain"].(map[string]any); ok {
			key := nftHookIdentity(fields)
			chains[key] = &nftACLChain{object: object, fields: fields}
			chainOrder = append(chainOrder, key)
		}
	}
	for _, object := range objects {
		if fields, ok := object["rule"].(map[string]any); ok {
			c := chains[nftHookRuleIdentity(fields)]
			if c == nil {
				return nil, "", errors.New("selective ACL rule has no parent")
			}
			c.rules = append(c.rules, object)
		}
	}
	for _, chain := range chains {
		chain.parent = tables[fmt.Sprint(chain.fields["family"])+"\x00"+fmt.Sprint(chain.fields["table"])]
		if chain.parent == nil {
			return nil, "", errors.New("selective ACL chain has no table")
		}
	}
	affected := nftHookFamilies(conflicts)
	used := make(map[string]bool)
	var allowed []nftRuleSpec
	for _, spec := range specs {
		mask := uint8(1)
		if spec.Family == 6 {
			mask = 2
		}
		if !spec.EnableFlowtable || affected&mask == 0 {
			continue
		}
		if validateRetirementSpec(spec) != nil {
			continue
		}
		valid := true
		var selected []string
		for _, key := range chainOrder {
			chain := chains[key]
			family := chain.fields["family"]
			hook := chain.fields["hook"]
			if hook == nil || hook == "input" || hook == "output" {
				continue
			}
			if family == "inet" && chain.fields["table"] == nftTableName {
				continue
			}
			if (family == "ip" && spec.Family != 4) || (family == "ip6" && spec.Family != 6) {
				continue
			}
			// No bridge/netdev translation model is silently assumed.
			if family != "ip" && family != "ip6" && family != "inet" {
				valid = false
				break
			}
			ok, err := nftACLChainAccepts(*chain, spec, work)
			if err != nil {
				return nil, "", err
			}
			if !ok {
				valid = false
				break
			}
			selected = append(selected, key)
		}
		if valid {
			allowed = append(allowed, spec)
			for _, key := range selected {
				used[key] = true
			}
		}
	}
	var proof []nftObject
	for _, key := range chainOrder {
		if used[key] {
			chain := chains[key]
			proof = append(proof, chain.parent, chain.object)
			proof = append(proof, chain.rules...)
		}
	}
	return allowed, nftProofInventoryKey(proof), nil
}
