package proxy

import (
	"encoding/json"
)

// This is an inspection projection of the existing text renderer, not another
// data-plane writer. It verifies every policy expression after the atomic write.
// nft 1.1.3 can crash in JSON --echo while deleting rules, so inspection uses
// normal writes followed by structured readback instead of relying on echo.
func nftRuleInspectionKey(rule map[string]any) string {
	value := map[string]any{
		"family": rule["family"], "table": rule["table"], "chain": rule["chain"],
		"comment": rule["comment"], "expr": rule["expr"],
	}
	data, _ := json.Marshal(normalizeNFTValue(value, ""))
	return string(data)
}

func nftExpectedRule(spec nftRuleSpec, hook string) map[string]any {
	m := func(op string, left, right any) any {
		return map[string]any{"match": map[string]any{"op": op, "left": left, "right": right}}
	}
	payload := func(protocol, field string) any {
		return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
	}
	ct := func(key string) any { return map[string]any{"ct": map[string]any{"key": key}} }
	port := func(first, last int) any {
		if last == 0 || first == last {
			return first
		}
		return map[string]any{"range": []any{first, last}}
	}
	family, nfproto := "ip6", "ipv6"
	if spec.Family == 4 {
		family, nfproto = "ip", "ipv4"
	}
	var expr []any
	commentHook := hook
	if hook == "prerouting" || hook == "output" {
		if spec.ListenHost.IsUnspecified() {
			if hook == "output" {
				var loopback any = "::1"
				if spec.Family == 4 {
					loopback = map[string]any{"prefix": map[string]any{"addr": "127.0.0.0", "len": 8}}
				}
				expr = append(expr, m("!=", payload(family, "daddr"), loopback))
			} else {
				expr = append(expr, m("==", map[string]any{"meta": map[string]any{"key": "nfproto"}}, nfproto))
			}
			expr = append(expr, m("==", map[string]any{"fib": map[string]any{"result": "type", "flags": []any{"daddr"}}}, "local"))
		} else {
			expr = append(expr, m("==", payload(family, "daddr"), spec.ListenHost.String()))
		}
		expr = append(expr, m("==", payload(spec.Protocol, "dport"), port(spec.ListenPort, spec.ListenPortEnd)),
			map[string]any{"mangle": map[string]any{"key": ct("mark"), "value": spec.ConntrackMark}},
			map[string]any{"counter": map[string]any{}})
		var destinationPort any = port(spec.TargetPort, spec.TargetPortEnd)
		if spec.ListenPortEnd > spec.ListenPort {
			pairs := make([]any, 0, spec.ListenPortEnd-spec.ListenPort+1)
			for p := spec.ListenPort; p <= spec.ListenPortEnd; p++ {
				pairs = append(pairs, []any{p, spec.TargetPort + p - spec.ListenPort})
			}
			destinationPort = map[string]any{"map": map[string]any{
				"key": payload(spec.Protocol, "dport"), "data": map[string]any{"set": pairs},
			}}
		}
		expr = append(expr, map[string]any{"dnat": map[string]any{"family": family, "addr": spec.TargetHost.String(), "port": destinationPort}})
	} else {
		expr = append(expr, m("==", ct("mark"), spec.ConntrackMark),
			m("==", payload(family, "daddr"), spec.TargetHost.String()),
			m("==", payload(spec.Protocol, "dport"), port(spec.TargetPort, spec.TargetPortEnd)))
		if hook == "forward" && spec.EnableFlowtable {
			expr = append(expr, m("==", map[string]any{"ct": map[string]any{"key": "proto-dst", "dir": "original"}}, port(spec.ListenPort, spec.ListenPortEnd)))
			if !spec.ListenHost.IsUnspecified() {
				expr = append(expr, m("==", map[string]any{"ct": map[string]any{"key": family + " daddr", "dir": "original"}}, spec.ListenHost.String()))
			}
			expr = append(expr, m("in", ct("state"), []any{"established", "related"}),
				map[string]any{"flow": map[string]any{"op": "add", "flowtable": "@" + nftFlowtableName}})
			commentHook = "flowtable"
		}
		expr = append(expr, map[string]any{"counter": map[string]any{}})
		if hook == "forward" {
			expr = append(expr, map[string]any{"accept": nil})
		} else {
			expr = append(expr, map[string]any{"masquerade": nil})
		}
	}
	return map[string]any{"family": "inet", "table": nftTableName, "chain": hook, "comment": nftComment(spec, commentHook), "expr": expr}
}
