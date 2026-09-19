package proxy

import (
	"encoding/json"
	"net/netip"
	"strconv"
)

// This is a fixed-depth syntax proof, not packet evaluation. A certified rule
// either accepts, or a read/comparison does not match and evaluation proceeds to
// the next rule. The caller must independently certify EVERY rule and the base
// chain's accept policy. No stateful getters, writes or observable side effects
// are part of this grammar. In particular, a terminal accept alone is not proof.
const nftTransparentMaxMatches = 16

type nftTransparentDomain uint8

const (
	nftTransparentUnknown nftTransparentDomain = iota
	nftTransparentPort
	nftTransparentNFProto
	nftTransparentL4Proto
	nftTransparentIPv4
	nftTransparentIPv6
)

func nftTransparentKeys(object map[string]any, keys ...string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, present := object[key]; !present {
			return false
		}
	}
	return true
}

func nftTransparentSelector(value any, family string) nftTransparentDomain {
	left, ok := value.(map[string]any)
	if !ok || len(left) != 1 {
		return nftTransparentUnknown
	}
	if raw, present := left["payload"]; present {
		payload, ok := raw.(map[string]any)
		if !ok || !nftTransparentKeys(payload, "protocol", "field") {
			return nftTransparentUnknown
		}
		protocol, protocolOK := payload["protocol"].(string)
		field, fieldOK := payload["field"].(string)
		if !protocolOK || !fieldOK {
			return nftTransparentUnknown
		}
		switch protocol {
		case "tcp", "udp":
			if field == "sport" || field == "dport" {
				return nftTransparentPort
			}
		case "ip":
			if family != "ip6" && (field == "saddr" || field == "daddr") {
				return nftTransparentIPv4
			}
		case "ip6":
			if family != "ip" && (field == "saddr" || field == "daddr") {
				return nftTransparentIPv6
			}
		}
	}
	if raw, present := left["meta"]; present {
		meta, ok := raw.(map[string]any)
		if !ok || !nftTransparentKeys(meta, "key") {
			return nftTransparentUnknown
		}
		switch meta["key"] {
		case "nfproto":
			return nftTransparentNFProto
		case "l4proto":
			return nftTransparentL4Proto
		}
	}
	return nftTransparentUnknown
}

// Only the production decoder's canonical unsigned decimal json.Number is
// admitted. In particular, port zero is a valid comparison constant; this is
// deliberately separate from the nonzero listening/target port validation.
func nftTransparentUint(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	s := string(number)
	if len(s) == 0 || len(s) > 5 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 16)
	return n, err == nil
}

func nftTransparentConstant(domain nftTransparentDomain, op string, value any) bool {
	if op != "==" && op != "!=" {
		if domain != nftTransparentPort || (op != "<" && op != "<=" && op != ">" && op != ">=") {
			return false
		}
	}
	switch domain {
	case nftTransparentPort:
		_, ok := nftTransparentUint(value)
		return ok
	case nftTransparentNFProto, nftTransparentL4Proto:
		if symbol, ok := value.(string); ok {
			if domain == nftTransparentNFProto {
				return symbol == "ipv4" || symbol == "ipv6"
			}
			return symbol == "tcp" || symbol == "udp"
		}
		n, ok := nftTransparentUint(value)
		if !ok {
			return false
		}
		if domain == nftTransparentNFProto {
			// Linux UAPI linux/netfilter.h: NFPROTO_IPV4=2, NFPROTO_IPV6=10.
			// These are not IP version numbers or IPPROTO_* values.
			return n == 2 || n == 10
		}
		// Linux UAPI linux/in.h: IPPROTO_TCP=6, IPPROTO_UDP=17.
		return n == 6 || n == 17
	case nftTransparentIPv4, nftTransparentIPv6:
		literal, ok := value.(string)
		if !ok {
			return false
		}
		addr, err := netip.ParseAddr(literal)
		if err != nil || addr.Zone() != "" {
			return false
		}
		// A mapped IPv6 literal remains a 128-bit IPv6 constant. Never Unmap,
		// strip a zone or perform name/service resolution in this proof.
		if domain == nftTransparentIPv4 {
			return addr.Is4()
		}
		return addr.Is6()
	}
	return false
}

func nftTransparentMatch(value any, family string) bool {
	statement, ok := value.(map[string]any)
	if !ok || !nftTransparentKeys(statement, "match") {
		return false
	}
	match, ok := statement["match"].(map[string]any)
	if !ok || !nftTransparentKeys(match, "left", "op", "right") {
		return false
	}
	domain := nftTransparentSelector(match["left"], family)
	op, ok := match["op"].(string)
	return ok && domain != nftTransparentUnknown && nftTransparentConstant(domain, op, match["right"])
}

func nftTransparentAcceptRule(rule map[string]any, family string) bool {
	if family != "ip" && family != "ip6" && family != "inet" {
		return false
	}
	expr, ok := rule["expr"].([]any)
	if !ok || len(expr) < 1 || len(expr) > nftTransparentMaxMatches+1 {
		return false
	}
	if len(expr) == 1 {
		return nftPureAcceptRule(rule)
	}
	if !nftHookMetadata(rule, "rule") {
		return false
	}
	verdict, ok := expr[len(expr)-1].(map[string]any)
	if !ok || !nftTransparentKeys(verdict, "accept") || verdict["accept"] != nil {
		return false
	}
	for _, statement := range expr[:len(expr)-1] {
		if !nftTransparentMatch(statement, family) {
			return false
		}
	}
	return true
}
