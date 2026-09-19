package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"portbridge/internal/config"
)

func transparentPayload(protocol, field, op string, right any) map[string]any {
	return map[string]any{"match": map[string]any{"left": map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}, "op": op, "right": right}}
}

func transparentMeta(key, op string, right any) map[string]any {
	return map[string]any{"match": map[string]any{"left": map[string]any{"meta": map[string]any{"key": key}}, "op": op, "right": right}}
}

func transparentObjects(family, hook string, predicates ...any) []nftObject {
	o := acceptHookObjects(family, hook, 1)
	expr := append([]any(nil), predicates...)
	o[2]["rule"].(map[string]any)["expr"] = append(expr, map[string]any{"accept": nil})
	return o
}

func transparentPolicy(count int) []nftObject {
	o := fixEmptyHook("inet", "postrouting")
	for i := 0; i < count; i++ {
		x := transparentObjects("inet", "postrouting",
			transparentMeta("nfproto", "!=", "ipv6"),
			transparentMeta("l4proto", "==", "tcp"),
			transparentPayload("tcp", "sport", ">=", 0),
			transparentPayload("udp", "dport", "!=", 65535))
		x[2]["rule"].(map[string]any)["handle"] = i + 10
		o = append(o, x[2])
	}
	return o
}

func transparentCheck(t *testing.T, objects []nftObject, raw []byte, want bool) {
	t.Helper()
	if raw == nil {
		raw = nftTestJSON(objects)
	}
	got, err := acceptHookProof(raw)
	if got != want {
		t.Fatalf("production two-read proof=%t want=%t error=%v JSON=%s", got, want, err, raw)
	}
	if out := os.Getenv("AUDIT_TRANSPARENT_SCHEMA"); out != "" {
		name := strings.NewReplacer("/", "_", "<", "lt", ">", "gt", "=", "eq", "!", "not").Replace(t.Name())
		if err := os.WriteFile(filepath.Join(out, name+".json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNFTTransparentAcceptRuleSyntax(t *testing.T) {
	for _, family := range []string{"ip", "ip6", "inet"} {
		for _, hook := range []string{"forward", "postrouting"} {
			t.Run(family+"/"+hook, func(t *testing.T) {
				t.Run("empty", func(t *testing.T) { transparentCheck(t, fixEmptyHook(family, hook), nil, true) })
				t.Run("pure", func(t *testing.T) { transparentCheck(t, transparentObjects(family, hook), nil, true) })
				for _, protocol := range []string{"tcp", "udp"} {
					for _, field := range []string{"sport", "dport"} {
						for _, op := range []string{"==", "!=", "<", "<=", ">", ">="} {
							for _, port := range []int{0, 65535} {
								t.Run(fmt.Sprintf("%s-%s-%s-%d", protocol, field, op, port), func(t *testing.T) {
									transparentCheck(t, transparentObjects(family, hook, transparentPayload(protocol, field, op, port)), nil, true)
								})
							}
						}
					}
				}
				for _, key := range []string{"nfproto", "l4proto"} {
					values := []any{"ipv4", "ipv6", 2, 10}
					if key == "l4proto" {
						values = []any{"tcp", "udp", 6, 17}
					}
					for _, op := range []string{"==", "!="} {
						for _, value := range values {
							t.Run(fmt.Sprintf("%s-%s-%v", key, op, value), func(t *testing.T) {
								transparentCheck(t, transparentObjects(family, hook, transparentMeta(key, op, value)), nil, true)
							})
						}
					}
				}
				for _, protocol := range []string{"ip", "ip6"} {
					for _, field := range []string{"saddr", "daddr"} {
						for _, op := range []string{"==", "!="} {
							address := "192.0.2.99"
							if protocol == "ip6" {
								address = "2001:db8::99"
							}
							want := family == "inet" || family == protocol
							t.Run(protocol+"-"+field+"-"+op, func(t *testing.T) {
								transparentCheck(t, transparentObjects(family, hook, transparentPayload(protocol, field, op, address)), nil, want)
							})
						}
					}
				}
			})
		}
	}
	t.Run("mixed-multiple-rules", func(t *testing.T) { transparentCheck(t, transparentPolicy(8), nil, true) })
	t.Run("mapped-ipv6-remains-128-bit", func(t *testing.T) {
		transparentCheck(t, transparentObjects("ip6", "postrouting", transparentPayload("ip6", "saddr", "==", "::ffff:192.0.2.1")), nil, true)
	})
	t.Run("contradictory-still-read-only", func(t *testing.T) {
		transparentCheck(t, transparentObjects("inet", "postrouting", transparentMeta("nfproto", "==", "ipv4"), transparentMeta("nfproto", "==", "ipv6")), nil, true)
	})
}

func TestNFTTransparentAcceptMalformedAndSideEffects(t *testing.T) {
	type mutation struct {
		name string
		edit func(map[string]any)
	}
	mutations := []mutation{
		{"null-match", func(m map[string]any) { m["match"] = nil }},
		{"match-scalar", func(m map[string]any) { m["match"] = true }},
		{"match-array", func(m map[string]any) { m["match"] = []any{} }},
		{"statement-extra", func(m map[string]any) { m["log"] = nil }},
	}
	for _, key := range []string{"left", "op", "right"} {
		key := key
		mutations = append(mutations, mutation{"missing-" + key, func(m map[string]any) { delete(m["match"].(map[string]any), key) }})
	}
	mutations = append(mutations,
		mutation{"match-extra", func(m map[string]any) { m["match"].(map[string]any)["flags"] = nil }},
		mutation{"left-extra", func(m map[string]any) {
			m["match"].(map[string]any)["left"].(map[string]any)["ct"] = map[string]any{"key": "state"}
		}},
	)
	for _, key := range []string{"protocol", "field"} {
		key := key
		mutations = append(mutations, mutation{"payload-missing-" + key, func(m map[string]any) {
			delete(m["match"].(map[string]any)["left"].(map[string]any)["payload"].(map[string]any), key)
		}})
	}
	for _, key := range []string{"offset", "len", "base", "set", "unknown"} {
		key := key
		mutations = append(mutations, mutation{"payload-extra-" + key, func(m map[string]any) {
			m["match"].(map[string]any)["left"].(map[string]any)["payload"].(map[string]any)[key] = 0
		}})
	}
	for _, item := range mutations {
		t.Run(item.name, func(t *testing.T) {
			p := transparentPayload("tcp", "dport", "==", 443)
			item.edit(p)
			transparentCheck(t, transparentObjects("inet", "postrouting", p), nil, false)
		})
	}
	for i, value := range []any{nil, true, false, "443", -1, 65536, 1.5, json.Number("1e2"), json.Number("443.0"), json.Number("-0"), []any{443}, map[string]any{}, map[string]any{"range": []any{1, 65535}}, map[string]any{"prefix": map[string]any{"addr": "192.0.2.0", "len": 24}}} {
		t.Run(fmt.Sprintf("wrong-port-type-%d", i), func(t *testing.T) {
			transparentCheck(t, transparentObjects("inet", "postrouting", transparentPayload("tcp", "sport", "==", value)), nil, false)
		})
	}
	for _, op := range []any{"in", "&", "=", "eq", "== ", "", nil, 1, true, []any{"=="}} {
		t.Run(fmt.Sprintf("operator-%v", op), func(t *testing.T) {
			p := transparentPayload("udp", "dport", "==", 53)
			p["match"].(map[string]any)["op"] = op
			transparentCheck(t, transparentObjects("inet", "postrouting", p), nil, false)
		})
	}
	for _, key := range []string{"counter", "log", "limit", "quota", "queue", "reject", "drop", "mangle", "dnat", "snat", "notrack", "dup", "fwd", "flow", "jump", "goto", "return", "continue", "vmap", "ct", "numgen", "random", "jhash", "symhash", "fib", "rt", "socket", "osf", "exthdr", "concat", "&", "+", "set", "map", "unknown"} {
		t.Run("injected-"+key, func(t *testing.T) {
			for position := 0; position <= 2; position++ {
				o := transparentObjects("inet", "postrouting", transparentPayload("tcp", "dport", "==", 443))
				r := o[2]["rule"].(map[string]any)
				old := r["expr"].([]any)
				x := append([]any(nil), old[:position]...)
				x = append(x, map[string]any{key: nil})
				x = append(x, old[position:]...)
				r["expr"] = x
				transparentCheck(t, o, nil, false)
			}
			p := transparentPayload("tcp", "dport", "==", map[string]any{key: map[string]any{"accept": nil}})
			transparentCheck(t, transparentObjects("inet", "postrouting", p), nil, false)
			p["match"].(map[string]any)["left"] = map[string]any{key: map[string]any{"key": "state"}}
			p["match"].(map[string]any)["right"] = 443
			transparentCheck(t, transparentObjects("inet", "postrouting", p), nil, false)
		})
	}
	for _, key := range []string{"nfproto", "l4proto"} {
		for i, value := range []any{"IPv4", "TCP", "6", "ipv5", "icmp", 0, 4, 41, 255, nil, true, []any{}, map[string]any{"numgen": nil}} {
			t.Run(fmt.Sprintf("bad-enum-%s-%d", key, i), func(t *testing.T) {
				transparentCheck(t, transparentObjects("inet", "postrouting", transparentMeta(key, "==", value)), nil, false)
			})
		}
		for _, variant := range []string{"missing", "set", "nonstring", "ordering"} {
			t.Run(key+"-"+variant, func(t *testing.T) {
				value := "tcp"
				if key == "nfproto" {
					value = "ipv4"
				}
				p := transparentMeta(key, "==", value)
				m := p["match"].(map[string]any)
				meta := m["left"].(map[string]any)["meta"].(map[string]any)
				switch variant {
				case "missing":
					delete(meta, "key")
				case "set":
					meta["set"] = nil
				case "nonstring":
					meta["key"] = map[string]any{}
				case "ordering":
					m["op"] = "<"
				}
				transparentCheck(t, transparentObjects("inet", "postrouting", p), nil, false)
			})
		}
	}
	for _, protocol := range []string{"ip", "ip6"} {
		for i, address := range []any{"localhost", "example.test", "192.0.2.1/32", "2001:db8::/64", "fe80::1%eth0", "192.0.2.1\x00", " 192.0.2.1", "192.000.2.1", "[::1]", "", nil, 123, true} {
			t.Run(fmt.Sprintf("address-%s-%d", protocol, i), func(t *testing.T) {
				transparentCheck(t, transparentObjects("inet", "postrouting", transparentPayload(protocol, "saddr", "==", address)), nil, false)
			})
		}
	}
	for _, item := range []struct {
		name, protocol, field string
		right                 any
	}{
		{"v4-as-v6", "ip6", "saddr", "192.0.2.1"}, {"v6-as-v4", "ip", "daddr", "::ffff:192.0.2.1"}, {"raw-protocol", "th", "dport", 443}, {"unknown-protocol", "sctp", "dport", 443}, {"unknown-field", "tcp", "flags", 0},
	} {
		t.Run(item.name, func(t *testing.T) {
			transparentCheck(t, transparentObjects("inet", "postrouting", transparentPayload(item.protocol, item.field, "==", item.right)), nil, false)
		})
	}
	for _, variant := range []string{"missing-expr", "null-expr", "object-expr", "missing-verdict", "early-accept", "accept-non-null", "verdict-extra", "unknown-metadata", "orphan", "duplicate-handle", "missing-parent", "duplicate-chain", "drop-policy", "later-drop", "earlier-pure-then-bad"} {
		t.Run(variant, func(t *testing.T) {
			o := transparentPolicy(1)
			r := o[2]["rule"].(map[string]any)
			expr := r["expr"].([]any)
			switch variant {
			case "missing-expr":
				delete(r, "expr")
			case "null-expr":
				r["expr"] = nil
			case "object-expr":
				r["expr"] = map[string]any{}
			case "missing-verdict":
				r["expr"] = expr[:len(expr)-1]
			case "early-accept":
				r["expr"] = append([]any{map[string]any{"accept": nil}}, expr...)
			case "accept-non-null":
				expr[len(expr)-1] = map[string]any{"accept": false}
			case "verdict-extra":
				expr[len(expr)-1] = map[string]any{"accept": nil, "drop": nil}
			case "unknown-metadata":
				r["position"] = 1
			case "orphan":
				r["chain"] = "missing"
			case "duplicate-handle":
				o = append(o, cloneNFTTestObjects(o[2:])...)
			case "missing-parent":
				o = o[1:]
			case "duplicate-chain":
				o = append(o, cloneNFTTestObjects(o[1:2])...)
			case "drop-policy":
				o[1]["chain"].(map[string]any)["policy"] = "drop"
			case "later-drop":
				o = append(o, fixHookRule("inet", map[string]any{"drop": nil}))
			case "earlier-pure-then-bad":
				o = append(o[:2], fixHookRule("inet", map[string]any{"accept": nil}), fixHookRule("inet", map[string]any{"match": nil}))
			}
			transparentCheck(t, o, nil, false)
		})
	}
	for _, key := range []string{"left", "op", "right", "payload", "protocol", "field", "match", "accept"} {
		t.Run("duplicate-json-"+key, func(t *testing.T) {
			raw := nftTestJSON(transparentObjects("inet", "postrouting", transparentPayload("tcp", "dport", "==", 443)))
			needle := []byte(`"` + key + `":`)
			raw = bytes.Replace(raw, needle, []byte(`"`+key+`":null,"`+key+`":`), 1)
			transparentCheck(t, nil, raw, false)
		})
	}
	// Direct helper callers must not use Go integers/floats or invalid json.Number
	// to justify broadening the production UseNumber contract.
	for _, value := range []any{443, float64(443), json.Number("+1"), json.Number("01"), json.Number(""), json.Number("-0"), json.Number("1e2")} {
		if _, ok := nftTransparentUint(value); ok {
			t.Fatalf("noncanonical direct numeric value accepted: %T %v", value, value)
		}
	}
}

// An independent abstract execution oracle: each match's result (including a
// missing header/read failure) is a supplied boolean. It does not call any
// production certifier or try to interpret Linux expressions. Exhausting these
// outcomes is stronger than evaluating only one B tuple, but is NOT a kernel test.
func transparentReference(rules [][]any, outcomes uint64) (verdict string, effects int) {
	bit := uint(0)
	for _, rule := range rules {
		matched := true
		for _, raw := range rule {
			statement, ok := raw.(map[string]any)
			if !ok || len(statement) != 1 {
				return "invalid", effects
			}
			for key := range statement {
				switch key {
				case "match":
					value := outcomes&(uint64(1)<<bit) != 0
					bit++
					matched = matched && value
				case "accept":
					if matched {
						return "accept", effects
					}
				case "drop":
					if matched {
						return "drop", effects
					}
				default:
					if matched {
						effects++
					}
				}
			}
		}
	}
	return "accept", effects // Independently specified base chain policy.
}

func TestNFTTransparentAcceptBothBranches(t *testing.T) {
	t.Run("exhaustive-abstract-outcomes", func(t *testing.T) {
		for _, order := range []bool{false, true} {
			o := transparentObjects("inet", "postrouting", transparentPayload("tcp", "sport", ">", 0), transparentPayload("tcp", "dport", "<=", 65535))
			r := transparentObjects("inet", "postrouting", transparentMeta("nfproto", "==", 2), transparentMeta("l4proto", "!=", 17))[2]
			r["rule"].(map[string]any)["handle"] = 11
			o = append(o, r)
			if order {
				o[2], o[3] = o[3], o[2]
			}
			transparentCheck(t, o, nil, true)
			rules := [][]any{o[2]["rule"].(map[string]any)["expr"].([]any), o[3]["rule"].(map[string]any)["expr"].([]any)}
			for mask := uint64(0); mask < 16; mask++ {
				if v, e := transparentReference(rules, mask); v != "accept" || e != 0 {
					t.Fatalf("mask=%d verdict=%s effects=%d", mask, v, e)
				}
			}
		}
	})
	for _, family := range []int{4, 6} {
		for _, proto := range []string{"tcp", "udp"} {
			for _, branch := range []string{"match", "miss", "later-match", "all-miss", "multiple-predicates"} {
				t.Run(fmt.Sprintf("ipv%d/%s/%s", family, proto, branch), func(t *testing.T) {
					a, b := reviewAB()
					a = reviewFixRuleSpec(a, family, proto)
					b = reviewFixRuleSpec(b, family, proto)
					k := &reviewFixInventory{causalNFTKernel: newCausalNFTKernel(a, b)}
					ct := &memoryConntrack{}
					n := reviewBackend(k.causalNFTKernel, ct, privateNFTConfig(t))
					n.kernel = k
					m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
					defer m.Stop()
					ra, rb := ruleFromNFTSpec(a), ruleFromNFTSpec(b)
					m.Apply([]config.Rule{ra, rb})
					if len(n.activeSpecs) != 2 {
						t.Fatal("A/B setup failed")
					}
					ea, eb := reviewFixEntry(a, 45000), reviewFixEntry(b, 45001)
					foreign := eb
					foreign.mark++
					ct.entries = []conntrackEntry{ea, eb, foreign}
					port := b.TargetPort
					if branch != "match" && branch != "multiple-predicates" {
						port = 0
					}
					k.external = transparentObjects("inet", "postrouting", transparentPayload(proto, "dport", "==", port))
					if branch == "later-match" || branch == "all-miss" {
						p := b.TargetPort
						if branch == "all-miss" {
							p = 65535
						}
						extra := transparentObjects("inet", "postrouting", transparentPayload(proto, "dport", "==", p))[2]
						extra["rule"].(map[string]any)["handle"] = 11
						k.external = append(k.external, extra)
					}
					if branch == "multiple-predicates" {
						nf := "ipv4"
						addrProto := "ip"
						if family == 6 {
							nf = "ipv6"
							addrProto = "ip6"
						}
						k.external = transparentObjects("inet", "postrouting", transparentMeta("nfproto", "==", nf), transparentMeta("l4proto", "==", proto), transparentPayload(proto, "dport", "==", b.TargetPort), transparentPayload(addrProto, "daddr", "==", b.TargetHost.String()))
					}
					before := string(nftTestJSON(k.external))
					ra.Enabled = false
					m.Apply([]config.Rule{ra, rb})
					requireFixBAdmission(t, n, m, b)
					requireTransparentFlowtable(t, k.objects)
					requireNFTEntries(t, ct, eb, foreign)
					if len(ct.deleted) != 1 || ct.deleted[0] != ea {
						t.Fatal("retirement did not exclusively delete A")
					}
					if before != string(nftTestJSON(k.external)) {
						t.Fatal("external rules changed")
					}
					for _, o := range k.objects {
						if r, ok := o["rule"].(map[string]any); ok && nftRuleInspectionKey(r) == nftRuleInspectionKey(nftExpectedRule(a, "prerouting")) {
							t.Fatal("old A NAT admission survived")
						}
					}
					t.Logf("L1 ONLY branch=%s ipv%d %s A-retired B-four-hooks/flowtable/runtime/disk-active foreign-preserved", branch, family, proto)
				})
			}
		}
	}
}

func requireTransparentFlowtable(t *testing.T, objects []nftObject) {
	t.Helper()
	for _, o := range objects {
		if f, ok := o["flowtable"].(map[string]any); ok && f["name"] == nftFlowtableName && f["table"] == nftTableName {
			return
		}
	}
	t.Fatal("requested flowtable is absent from actual fixture objects")
}

func TestNFTTransparentAcceptMultiChainAndFamily(t *testing.T) {
	for _, badFamily := range []string{"none", "ip", "ip6", "inet"} {
		for _, bad := range []string{"drop", "counter", "unknown", "policy"} {
			for _, first := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/first-%t", badFamily, bad, first), func(t *testing.T) {
					o := append(transparentObjects("ip", "postrouting", transparentPayload("tcp", "dport", "==", 1)), transparentObjects("ip6", "forward", transparentPayload("udp", "sport", ">=", 0))...)
					want := uint8(0)
					if badFamily != "none" {
						x := transparentObjects(badFamily, "postrouting", transparentPayload("udp", "dport", "!=", 53))
						x[0]["table"].(map[string]any)["name"] = "other"
						x[1]["chain"].(map[string]any)["table"] = "other"
						x[2]["rule"].(map[string]any)["table"] = "other"
						if bad == "policy" {
							x[1]["chain"].(map[string]any)["policy"] = "drop"
						} else {
							x[2]["rule"].(map[string]any)["expr"] = []any{map[string]any{bad: nil}, map[string]any{"accept": nil}}
						}
						if first {
							o = append(x, o...)
						} else {
							o = append(o, x...)
						}
						want = 3
						if badFamily == "ip" {
							want = 1
						}
						if badFamily == "ip6" {
							want = 2
						}
					}
					decoded, err := decodeNFTObjects(nftTestJSON(o))
					if err != nil {
						t.Fatal(err)
					}
					initial, err := nftConflictingHooks(decoded)
					if err != nil {
						t.Fatal(err)
					}
					k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(), raw: nftTestJSON(o)}
					remaining, _, err := verifyNFTCompatibleExternalHooks(k, initial)
					if err != nil || nftHookFamilies(remaining) != want {
						t.Fatalf("family gate got=%d want=%d err=%v", nftHookFamilies(remaining), want, err)
					}
				})
			}
		}
	}
}

func TestNFTTransparentAcceptSnapshotChanges(t *testing.T) {
	for _, change := range []string{"constant", "selector", "operator", "expression-order", "policy", "side-effect", "unknown", "new-table", "new-family", "missing-parent", "timeout", "truncated", "incomplete", "unsupported-to-transparent", "object-reorder"} {
		t.Run(change, func(t *testing.T) {
			k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel()}
			k.external = transparentPolicy(1)
			if change == "unsupported-to-transparent" {
				k.external[2]["rule"].(map[string]any)["expr"] = []any{map[string]any{"counter": nil}, map[string]any{"accept": nil}}
			}
			initial, _ := nftConflictingHooks(k.external)
			k.afterRead = func(count int) {
				if count != 2 {
					return
				}
				r := k.external[2]["rule"].(map[string]any)
				expr := r["expr"].([]any)
				switch change {
				case "constant":
					expr[2].(map[string]any)["match"].(map[string]any)["right"] = 1
				case "selector":
					expr[2].(map[string]any)["match"].(map[string]any)["left"] = map[string]any{"payload": map[string]any{"protocol": "udp", "field": "dport"}}
				case "operator":
					expr[2].(map[string]any)["match"].(map[string]any)["op"] = "<="
				case "expression-order":
					expr[0], expr[1] = expr[1], expr[0]
				case "policy":
					k.external[1]["chain"].(map[string]any)["policy"] = "drop"
				case "side-effect":
					expr[0] = map[string]any{"counter": nil}
				case "unknown":
					expr[0] = map[string]any{"unknown": nil}
				case "new-table":
					x := transparentPolicy(1)
					x[0]["table"].(map[string]any)["name"] = "other"
					x[1]["chain"].(map[string]any)["table"] = "other"
					x[2]["rule"].(map[string]any)["table"] = "other"
					k.external = append(k.external, x...)
				case "new-family":
					k.external = append(k.external, transparentObjects("ip6", "postrouting", transparentPayload("udp", "dport", "==", 53))...)
				case "missing-parent":
					k.external = k.external[1:]
				case "timeout":
					k.ruleErr = context.DeadlineExceeded
				case "truncated":
					k.raw = []byte(`{"nftables":[`)
				case "incomplete":
					k.raw = []byte(`{"nftables":[]}`)
				case "unsupported-to-transparent":
					k.external = transparentPolicy(1)
				case "object-reorder":
					k.external = []nftObject{k.external[2], k.external[0], k.external[1]}
				}
			}
			remaining, _, err := verifyNFTCompatibleExternalHooks(k, initial)
			got := err == nil && len(remaining) == 0
			if got != (change == "object-reorder") {
				t.Fatalf("changed proof accepted=%t err=%v", got, err)
			}
			if k.ruleReads != 2 {
				t.Fatalf("not two reads: %d", k.ruleReads)
			}
		})
	}
}

func TestNFTTransparentAcceptRetirementMatrix(t *testing.T) {
	testNFTCompatibleHookRetirementMatrixWithPolicy(t, true, func() []nftObject { return transparentPolicy(3) })
}

func TestNFTTransparentAcceptRecoveryAndFailures(t *testing.T) {
	t.Run("suspended-record-revalidation", func(t *testing.T) { testNFTAcceptHookSuspendedRecordRevalidation(t, transparentPolicy) })
	t.Run("fault-retry", func(t *testing.T) { testNFTAcceptHookFailureRetry(t, transparentPolicy) })
}

func TestNFTTransparentAcceptBounds(t *testing.T) {
	for _, count := range []int{0, 1, 16, 17, 64} {
		t.Run(fmt.Sprintf("predicates-%d", count), func(t *testing.T) {
			var predicates []any
			for i := 0; i < count; i++ {
				predicates = append(predicates, transparentPayload("tcp", "dport", "!=", i))
			}
			transparentCheck(t, transparentObjects("inet", "postrouting", predicates...), nil, count <= 16)
		})
	}
	t.Run("bytes", func(t *testing.T) {
		raw := append(nftTestJSON(transparentPolicy(1)), bytes.Repeat([]byte(" "), maxNFTOutputBytes)...)
		if _, err := decodeNFTProofObjects(raw); err == nil {
			t.Fatal("output bound removed")
		}
	})
	t.Run("objects", func(t *testing.T) {
		raw := []byte(`{"nftables":[` + strings.Repeat(`{"metainfo":{}},`, maxNFTProofObjects) + `{"metainfo":{}}]}`)
		if _, err := decodeNFTProofObjects(raw); err == nil {
			t.Fatal("object bound removed")
		}
	})
	t.Run("depth", func(t *testing.T) {
		raw := []byte(`{"nftables":[` + strings.Repeat(`{"x":`, 80) + `null` + strings.Repeat(`}`, 80) + `]}`)
		if _, err := decodeNFTProofObjects(raw); err == nil {
			t.Fatal("depth bound removed")
		}
	})
}

func FuzzNFTTransparentAcceptProof(f *testing.F) {
	for _, raw := range [][]byte{nftTestJSON(transparentPolicy(1)), nftTestJSON(transparentObjects("ip6", "postrouting", transparentPayload("ip6", "saddr", "==", "::1"))), nftTestJSON(acceptHookObjects("inet", "forward", 1)), []byte(`{"nftables":[`), []byte(`{"nftables":[]}`)} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64<<10 {
			return
		}
		proved, err := acceptHookProof(raw)
		if !proved || err != nil {
			return
		}
		objects, err := decodeNFTProofObjects(raw)
		if err != nil {
			t.Fatal("accepted malformed input")
		}
		compatible, err := nftProvablyCompatibleHooks(objects)
		if err != nil {
			t.Fatal(err)
		}
		for i, o := range objects {
			r, ok := o["rule"].(map[string]any)
			if !ok || !compatible[nftHookRuleIdentity(r)] {
				continue
			}
			expr, ok := r["expr"].([]any)
			if !ok {
				t.Fatal("accepted non-array")
			}
			// Test all-false/read-failure and all-true, independently of the proof.
			for _, mask := range []uint64{0, ^uint64(0), 0x5555, 0xaaaa} {
				if v, e := transparentReference([][]any{expr}, mask); v != "accept" || e != 0 {
					t.Fatalf("proved nontransparent rule: %s %d", v, e)
				}
			}
			// An unsupported side effect at any position must revoke this rule's
			// chain proof, including positions made unreachable by an accept.
			for position := 0; position <= len(expr); position++ {
				mutated := cloneNFTTestObjects(objects)
				mr := mutated[i]["rule"].(map[string]any)
				old := mr["expr"].([]any)
				x := append([]any(nil), old[:position]...)
				x = append(x, map[string]any{"counter": nil})
				x = append(x, old[position:]...)
				mr["expr"] = x
				decoded, err := decodeNFTProofObjects(nftTestJSON(mutated))
				if err != nil {
					continue
				}
				proof, err := nftProvablyCompatibleHooks(decoded)
				if err == nil && proof[nftHookRuleIdentity(mr)] {
					t.Fatal("side effect remained certified")
				}
			}
		}
	})
}
