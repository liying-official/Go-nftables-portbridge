package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"portbridge/internal/config"
)

func acceptHookObjects(family, hook string, count int) []nftObject {
	objects := fixEmptyHook(family, hook)
	for i := 0; i < count; i++ {
		rule := fixHookRule(family, map[string]any{"accept": nil})
		rule["rule"].(map[string]any)["handle"] = 10 + i
		objects = append(objects, rule)
	}
	return objects
}

// This invokes the production two-snapshot proof, not a parallel test parser.
func acceptHookProof(data []byte) (bool, error) {
	objects, err := decodeNFTObjects(data)
	if err != nil {
		return false, err
	}
	initial, err := nftConflictingHooks(objects)
	if err != nil {
		return false, err
	}
	if len(initial) == 0 {
		return false, errors.New("fixture has no candidate conflict")
	}
	k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(), raw: data}
	remaining, _, err := verifyNFTCompatibleExternalHooks(k, initial)
	return err == nil && len(remaining) == 0, err
}

func TestNFTAcceptHookProofSyntax(t *testing.T) {
	type sample struct {
		name string
		want bool
		edit func([]nftObject) []nftObject
		raw  string
	}
	ruleEdit := func(fn func(map[string]any)) func([]nftObject) []nftObject {
		return func(o []nftObject) []nftObject { fn(o[2]["rule"].(map[string]any)); return o }
	}
	samples := []sample{
		{name: "single-accept", want: true},
		{name: "empty", want: true, edit: func(o []nftObject) []nftObject { return o[:2] }},
		{name: "many-accepts", want: true, edit: func([]nftObject) []nftObject { return acceptHookObjects("inet", "postrouting", 128) }},
		{name: "metadata-is-not-authorization", want: true, edit: ruleEdit(func(r map[string]any) { r["index"] = 0; r["comment"] = "drop; accept; 拒绝; unknown" })},
		{name: "uint64-handle", want: true, raw: `{"nftables":[{"table":{"family":"inet","name":"external-control"}},{"chain":{"family":"inet","table":"external-control","name":"after","type":"filter","hook":"postrouting","prio":0,"policy":"accept"}},{"rule":{"family":"inet","table":"external-control","chain":"after","handle":18446744073709551615,"expr":[{"accept":null}]}}]}`},
		{name: "unicode-identities", want: true, edit: func(o []nftObject) []nftObject {
			o[0]["table"].(map[string]any)["name"] = "表α"
			c := o[1]["chain"].(map[string]any)
			c["table"] = "表α"
			c["name"] = "链β"
			r := o[2]["rule"].(map[string]any)
			r["table"] = "表α"
			r["chain"] = "链β"
			return o
		}},
		{name: "object-order", want: true, edit: func(o []nftObject) []nftObject { return []nftObject{o[2], o[0], o[1]} }},
		{name: "repeated-no-handle-pure-rules", want: true, edit: func(o []nftObject) []nftObject {
			delete(o[2]["rule"].(map[string]any), "handle")
			return append(o, cloneNFTTestObjects(o[2:])...)
		}},
		{name: "missing-expr", edit: ruleEdit(func(r map[string]any) { delete(r, "expr") })},
		{name: "null-expr", edit: ruleEdit(func(r map[string]any) { r["expr"] = nil })},
		{name: "string-expr", edit: ruleEdit(func(r map[string]any) { r["expr"] = "accept" })},
		{name: "object-expr", edit: ruleEdit(func(r map[string]any) { r["expr"] = map[string]any{"accept": nil} })},
		{name: "empty-expr", edit: ruleEdit(func(r map[string]any) { r["expr"] = []any{} })},
		{name: "string-statement", edit: ruleEdit(func(r map[string]any) { r["expr"] = []any{"accept"} })},
		{name: "null-statement", edit: ruleEdit(func(r map[string]any) { r["expr"] = []any{nil} })},
		{name: "absent-accept-is-not-null", edit: ruleEdit(func(r map[string]any) { r["expr"] = []any{map[string]any{"unknown": nil}} })},
		{name: "empty-statement-map", edit: ruleEdit(func(r map[string]any) { r["expr"] = []any{map[string]any{}} })},
		{name: "multiple-verdict-keys", edit: ruleEdit(func(r map[string]any) { r["expr"] = []any{map[string]any{"accept": nil, "drop": nil}} })},
		{name: "extra-expression", edit: ruleEdit(func(r map[string]any) {
			r["expr"] = []any{map[string]any{"accept": nil}, map[string]any{"unknown": nil}}
		})},
		{name: "unknown-rule-metadata", edit: ruleEdit(func(r map[string]any) { r["verdict"] = "accept" })},
		{name: "comment-wrong-type", edit: ruleEdit(func(r map[string]any) { r["comment"] = map[string]any{"accept": nil} })},
		{name: "duplicate-rule-handle", edit: func(o []nftObject) []nftObject { return append(o, cloneNFTTestObjects(o[2:])...) }},
		{name: "duplicate-rule-index", edit: func(o []nftObject) []nftObject {
			r := o[2]["rule"].(map[string]any)
			delete(r, "handle")
			r["index"] = 1
			return append(o, cloneNFTTestObjects(o[2:])...)
		}},
		{name: "duplicate-table", edit: func(o []nftObject) []nftObject { return append(o, cloneNFTTestObjects(o[:1])...) }},
		{name: "duplicate-chain", edit: func(o []nftObject) []nftObject { return append(o, cloneNFTTestObjects(o[1:2])...) }},
		{name: "missing-parent", edit: func(o []nftObject) []nftObject { return o[1:] }},
		{name: "orphan-rule", edit: ruleEdit(func(r map[string]any) { r["chain"] = "another" })},
		{name: "rule-wrong-family", edit: ruleEdit(func(r map[string]any) { r["family"] = "ip6" })},
		{name: "nul-chain-identity", edit: ruleEdit(func(r map[string]any) { r["chain"] = "after\x00wrong" })},
		{name: "unknown-parent-metadata", edit: func(o []nftObject) []nftObject { o[0]["table"].(map[string]any)["flags"] = []any{"dormant"}; return o }},
		{name: "unknown-chain-metadata", edit: func(o []nftObject) []nftObject { o[1]["chain"].(map[string]any)["packets"] = 0; return o }},
		{name: "chain-comment-wrong-type", edit: func(o []nftObject) []nftObject { o[1]["chain"].(map[string]any)["comment"] = true; return o }},
		{name: "parent-handle-wrong-type", edit: func(o []nftObject) []nftObject { o[0]["table"].(map[string]any)["handle"] = "1"; return o }},
		{name: "priority-string", edit: func(o []nftObject) []nftObject { o[1]["chain"].(map[string]any)["prio"] = "0"; return o }},
		{name: "drop-policy", edit: func(o []nftObject) []nftObject { o[1]["chain"].(map[string]any)["policy"] = "drop"; return o }},
		{name: "accept-followed-by-drop", edit: func(o []nftObject) []nftObject { return append(o, fixHookRule("inet", map[string]any{"drop": nil})) }},
		{name: "drop-followed-by-accept", edit: func(o []nftObject) []nftObject {
			return append(o[:2], fixHookRule("inet", map[string]any{"drop": nil}), o[2])
		}},
		{name: "external-set", edit: func(o []nftObject) []nftObject {
			return append(o, nftObject{"set": map[string]any{"family": "inet", "table": "external-control", "name": "unused"}})
		}},
		{name: "external-flowtable", edit: func(o []nftObject) []nftObject {
			return append(o, nftObject{"flowtable": map[string]any{"family": "inet", "table": "external-control", "name": "foreign"}})
		}},
		{name: "duplicate-metainfo", edit: func(o []nftObject) []nftObject {
			return append(o, nftObject{"metainfo": map[string]any{}}, nftObject{"metainfo": map[string]any{}})
		}},
		{name: "duplicate-json-key", raw: `{"nftables":[{"table":{"family":"inet","name":"external-control"}},{"chain":{"family":"inet","table":"external-control","name":"after","type":"filter","hook":"postrouting","prio":0,"policy":"accept"}},{"rule":{"family":"inet","table":"external-control","chain":"after","expr":[{"accept":null,"accept":null}]}}]}`},
		{name: "truncated-json", raw: `{"nftables":[`},
	}
	for _, value := range []any{true, false, 0, "accept", map[string]any{}, []any{}} {
		v := value
		samples = append(samples, sample{name: fmt.Sprintf("accept-non-null-%T-%v", v, v), edit: ruleEdit(func(r map[string]any) { r["expr"] = []any{map[string]any{"accept": v}} })})
	}
	for _, field := range []string{"handle", "index"} {
		for i, value := range []any{"1", -1, 1.5, true, nil} {
			key, v := field, value
			samples = append(samples, sample{name: fmt.Sprintf("invalid-%s-%d", key, i), edit: ruleEdit(func(r map[string]any) { r[key] = v })})
		}
	}
	for _, key := range []string{"counter", "log", "limit", "quota", "queue", "reject", "drop", "mangle", "dnat", "snat", "flow", "jump", "goto", "return", "continue", "match", "vmap", "ct helper", "unknown"} {
		key := key
		samples = append(samples, sample{name: "unsupported-" + strings.ReplaceAll(key, " ", "-"), edit: ruleEdit(func(r map[string]any) { r["expr"] = []any{map[string]any{key: nil}} })})
	}
	samples = append(samples, sample{name: "counter-accept", edit: ruleEdit(func(r map[string]any) {
		r["expr"] = []any{map[string]any{"counter": map[string]any{"packets": 0, "bytes": 0}}, map[string]any{"accept": nil}}
	})})
	for _, item := range samples {
		t.Run(item.name, func(t *testing.T) {
			objects := acceptHookObjects("inet", "postrouting", 1)
			if item.edit != nil {
				objects = item.edit(objects)
			}
			data := nftTestJSON(objects)
			if item.raw != "" {
				data = []byte(item.raw)
			}
			got, err := acceptHookProof(data)
			if got != item.want {
				t.Fatalf("proof=%t want=%t error=%v", got, item.want, err)
			}
			if out := os.Getenv("AUDIT_ACCEPT_SCHEMA"); out != "" {
				if err := os.WriteFile(filepath.Join(out, item.name+".json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestNFTAcceptHookMultiChainAndFamily(t *testing.T) {
	for _, hook := range []string{"forward", "postrouting"} {
		for _, dropFamily := range []string{"none", "ip", "ip6", "inet"} {
			for _, first := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/drop-first-%t", hook, dropFamily, first), func(t *testing.T) {
					objects := append(acceptHookObjects("ip", hook, 3), acceptHookObjects("ip6", hook, 2)...)
					want := uint8(0)
					if dropFamily != "none" {
						extra := acceptHookObjects(dropFamily, hook, 1)
						extra[0]["table"].(map[string]any)["name"] = "other-policy"
						extra[1]["chain"].(map[string]any)["table"] = "other-policy"
						r := extra[2]["rule"].(map[string]any)
						r["table"] = "other-policy"
						r["expr"] = []any{map[string]any{"drop": nil}}
						if first {
							objects = append(extra, objects...)
						} else {
							objects = append(objects, extra...)
						}
						switch dropFamily {
						case "ip":
							want = 1
						case "ip6":
							want = 2
						case "inet":
							want = 3
						}
					}
					k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel()}
					k.external = objects
					n := fixFullBackend(k, &memoryConntrack{}, "")
					err := n.checkFlowtableAdmission()
					var typed *nftAdmissionError
					if want == 0 {
						if err != nil {
							t.Fatal(err)
						}
					} else if !errors.As(err, &typed) || typed.families != want {
						t.Fatalf("family gate=%v want=%d", err, want)
					}
				})
			}
		}
	}
}

func TestNFTAcceptHookChangingSnapshots(t *testing.T) {
	cases := []struct {
		name   string
		want   bool
		change func(*fixFullRulesKernel)
	}{
		{"accept-to-drop", false, func(k *fixFullRulesKernel) {
			k.external[2]["rule"].(map[string]any)["expr"] = []any{map[string]any{"drop": nil}}
		}},
		{"accept-to-unknown", false, func(k *fixFullRulesKernel) {
			k.external[2]["rule"].(map[string]any)["expr"] = []any{map[string]any{"unknown": nil}}
		}},
		{"more-accept-rules", false, func(k *fixFullRulesKernel) {
			k.external = append(k.external, fixHookRule("ip", map[string]any{"accept": nil}))
		}},
		{"accept-to-empty", false, func(k *fixFullRulesKernel) { k.external = k.external[:2] }},
		{"new-chain", false, func(k *fixFullRulesKernel) {
			x := cloneNFTTestObjects(k.external[1:2])
			x[0]["chain"].(map[string]any)["name"] = "new"
			k.external = append(k.external, x...)
		}},
		{"new-family", false, func(k *fixFullRulesKernel) {
			k.external = append(k.external, acceptHookObjects("ip6", "postrouting", 1)...)
		}},
		{"rule-handle", false, func(k *fixFullRulesKernel) { k.external[2]["rule"].(map[string]any)["handle"] = 11 }},
		{"rule-comment", false, func(k *fixFullRulesKernel) { k.external[2]["rule"].(map[string]any)["comment"] = "changed" }},
		{"parent-handle", false, func(k *fixFullRulesKernel) { k.external[0]["table"].(map[string]any)["handle"] = 99 }},
		{"missing-parent", false, func(k *fixFullRulesKernel) { k.external = k.external[1:] }},
		{"read-timeout", false, func(k *fixFullRulesKernel) { k.ruleErr = context.DeadlineExceeded }},
		{"whole-object-order", true, func(k *fixFullRulesKernel) { k.external = []nftObject{k.external[2], k.external[0], k.external[1]} }},
		{"metainfo-not-permission", true, func(k *fixFullRulesKernel) {
			k.external = append(k.external, nftObject{"metainfo": map[string]any{"version": "display-only"}})
		}},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel()}
			k.external = acceptHookObjects("ip", "postrouting", 1)
			initial, err := nftConflictingHooks(k.external)
			if err != nil {
				t.Fatal(err)
			}
			k.afterRead = func(count int) {
				if count == 2 {
					item.change(k)
				}
			}
			remaining, _, err := verifyNFTCompatibleExternalHooks(k, initial)
			if got := err == nil && len(remaining) == 0; got != item.want {
				t.Fatalf("proof=%t want=%t error=%v", got, item.want, err)
			}
		})
	}
	t.Run("first-unsupported-second-safe", func(t *testing.T) {
		k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel()}
		k.external = acceptHookObjects("ip", "postrouting", 1)
		k.external[2]["rule"].(map[string]any)["expr"] = []any{map[string]any{"drop": nil}}
		initial, _ := nftConflictingHooks(k.external)
		k.afterRead = func(count int) {
			if count == 2 {
				k.external = acceptHookObjects("ip", "postrouting", 1)
			}
		}
		if _, _, err := verifyNFTCompatibleExternalHooks(k, initial); err == nil {
			t.Fatal("first failed proof was discarded")
		}
	})
}

func TestNFTAcceptHookSuspendedRecordRevalidation(t *testing.T) {
	testNFTAcceptHookSuspendedRecordRevalidation(t, func(count int) []nftObject { return acceptHookObjects("inet", "postrouting", count) })
}

func testNFTAcceptHookSuspendedRecordRevalidation(t *testing.T, policy func(int) []nftObject) {
	a, b := reviewAB()
	k := newCausalNFTKernel(a, b)
	ct := &memoryConntrack{}
	path := privateNFTConfig(t)
	// The descriptor-only reader retains the old fix's rejection and writes an
	// actual suspended record. Reconstruct with the new full reader, same identity.
	old := reviewBackend(k, ct, path)
	if err := old.Replace([]nftRuleSpec{a, b}); err != nil {
		t.Fatal(err)
	}
	one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
	foreign := two
	foreign.mark++
	ct.entries = []conntrackEntry{one, two, foreign}
	k.external = policy(2)
	if err := old.Replace([]nftRuleSpec{b}); err == nil {
		t.Fatal("old reader unexpectedly supplied rule proof")
	}
	requireNFTEntries(t, ct, two, foreign)
	if len(old.suspendedSpecs) != 1 {
		t.Fatal("old suspended record fixture not established")
	}
	full := &fixFullRulesKernel{causalNFTKernel: k}
	n := fixFullBackend(full, ct, path)
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
	rb := ruleFromNFTSpec(b)
	m.Apply([]config.Rule{rb})
	requireFixBAdmission(t, n, m, b)
	requireTransparentFlowtable(t, k.objects)
	deletes := ct.deletes
	// Same chain: a later unsupported rule invalidates the whole proof, even
	// though an earlier unconditional accept would win within this chain.
	k.external = append(k.external, fixHookRule("inet", map[string]any{"drop": nil}))
	m.Refresh([]config.Rule{rb})
	if len(n.activeSpecs) != 0 || len(n.suspendedSpecs) != 1 {
		t.Fatal("fresh conflict did not suspend B")
	}
	for _, o := range k.objects {
		if _, ok := o["flowtable"]; ok {
			t.Fatal("cached acceleration survived detected conflict")
		}
	}
	requireNFTEntries(t, ct, two, foreign)
	if ct.deletes != deletes {
		t.Fatal("policy change deleted B or foreign conntrack")
	}
	// Recreating the process while the conflict persists must not trust history.
	n = fixFullBackend(full, ct, path)
	m = newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
	m.Apply([]config.Rule{rb})
	if len(n.activeSpecs) != 0 || len(n.suspendedSpecs) != 1 {
		t.Fatal("restart revived unproved B")
	}
	k.external = policy(3)
	m.Refresh([]config.Rule{rb})
	requireFixBAdmission(t, n, m, b)
	requireTransparentFlowtable(t, k.objects)
	reads, writes, lists := full.ruleReads, k.writes, ct.lists+ct.ownedLists
	m.Refresh([]config.Rule{rb})
	if full.ruleReads != reads+2 || k.writes != writes || ct.lists+ct.ownedLists != lists {
		t.Fatal("unchanged Manager cached proof, wrote objects or dumped conntrack")
	}
	requireNFTEntries(t, ct, two, foreign)
	if ct.deletes != deletes {
		t.Fatal("recovery changed unrelated connections")
	}
	// Explicit deletion is distinct from suspension and must retire B exactly.
	m.Apply(nil)
	requireNFTEntries(t, ct, foreign)
}

func TestNFTAcceptHookFailureRetry(t *testing.T) {
	testNFTAcceptHookFailureRetry(t, func(count int) []nftObject { return acceptHookObjects("inet", "postrouting", count) })
}

func testNFTAcceptHookFailureRetry(t *testing.T, policy func(int) []nftObject) {
	for _, failure := range []string{"nft-write", "nft-readback", "prepare-write", "checkpoint-write", "ct-list", "ct-delete"} {
		t.Run(failure, func(t *testing.T) {
			a, b := reviewAB()
			k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a, b)}
			ct := &memoryConntrack{}
			n := fixFullBackend(k, ct, privateNFTConfig(t))
			if err := n.Replace([]nftRuleSpec{a, b}); err != nil {
				t.Fatal(err)
			}
			one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
			foreign := two
			foreign.mark++
			ct.entries = []conntrackEntry{one, two, foreign}
			k.external = policy(2)
			switch failure {
			case "nft-write":
				k.applyErr = context.DeadlineExceeded
			case "nft-readback":
				k.afterApply = func([]nftObject) { k.readErr = context.DeadlineExceeded }
			case "prepare-write", "checkpoint-write":
				calls := 0
				n.store.fault = func(stage string) error {
					if stage == "write" {
						calls++
						if (failure == "prepare-write" && calls == 1) || (failure == "checkpoint-write" && calls == 2) {
							return context.DeadlineExceeded
						}
					}
					return nil
				}
			case "ct-list":
				ct.listErr = context.DeadlineExceeded
			case "ct-delete":
				ct.deleteErr = context.DeadlineExceeded
			}
			err := n.Replace([]nftRuleSpec{b})
			if err == nil {
				t.Fatalf("fault was not selected: %s", failure)
			}
			for _, e := range ct.deleted {
				if e == two || e == foreign {
					t.Fatal("failure deleted unrelated flow")
				}
			}
			k.applyErr = nil
			k.afterApply = nil
			k.readErr = nil
			n.store.fault = nil
			ct.listErr = nil
			ct.deleteErr = nil
			m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
			m.Apply([]config.Rule{ruleFromNFTSpec(b)})
			requireFixBAdmission(t, n, m, b)
			requireTransparentFlowtable(t, k.objects)
			requireNFTEntries(t, ct, two, foreign)
		})
	}
}

func TestNFTAcceptHookProofObjectLimit(t *testing.T) {
	// The parser must reject the object bound before evaluating any proof.
	data := []byte(`{"nftables":[` + strings.Repeat(`{"metainfo":{}},`, maxNFTProofObjects) + `{"metainfo":{}}]}`)
	if _, err := decodeNFTProofObjects(data); err == nil {
		t.Fatal("proof-object limit was removed")
	}
}
