package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"portbridge/internal/config"
	"runtime"
	"testing"
)

// These measurements include Healthy, planning, Replace when necessary, and
// real protected-file IO. The causal backend is NOT a kernel/CLI latency model.
// The identical probe can be built with v2.4.6-fix; active-paths distinguishes
// its rejected accept-only state from the candidate's successful admission.
func BenchmarkNFTAcceptManager(b *testing.B) {
	for _, mode := range []string{"no-conflict", "empty", "accept-1", "accept-32", "chains-8", "accept-1024", "conflict-cycle"} {
		b.Run(mode, func(b *testing.B) {
			dir, err := os.MkdirTemp("/tmp", "pb-accept-manager-")
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = os.RemoveAll(dir) })
			a, other := reviewAB()
			k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a, other)}
			ct := &memoryConntrack{}
			n := fixFullBackend(k, ct, filepath.Join(dir, "config.json"))
			m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
			desired := []config.Rule{ruleFromNFTSpec(a), ruleFromNFTSpec(other)}
			m.Apply(desired)
			if !n.initialized {
				b.Fatal("initial admission failed")
			}
			safe := fixEmptyHook("inet", "postrouting")
			count := 0
			switch mode {
			case "no-conflict":
				safe = nil
			case "accept-1", "conflict-cycle", "chains-8":
				count = 1
			case "accept-32":
				count = 32
			case "accept-1024":
				count = 1024
			}
			for i := 0; i < count; i++ {
				r := fixHookRule("inet", map[string]any{"accept": nil})
				r["rule"].(map[string]any)["handle"] = 10 + i
				safe = append(safe, r)
			}
			if mode == "chains-8" {
				for i := 1; i < 8; i++ {
					name := fmt.Sprintf("after-%d", i)
					safe = append(safe, nftObject{"chain": map[string]any{"family": "inet", "table": "external-control", "name": name, "type": "filter", "hook": "postrouting", "prio": 0, "policy": "accept"}}, nftObject{"rule": map[string]any{"family": "inet", "table": "external-control", "chain": name, "handle": 10, "expr": []any{map[string]any{"accept": nil}}}})
				}
			}
			k.external = safe
			m.Refresh(desired)
			writes, lists, reads := k.writes, ct.lists+ct.ownedLists, k.ruleReads
			syncs := 0
			n.store.fault = func(stage string) error {
				if stage == "file-sync" {
					syncs++
				}
				return nil
			}
			fd0, _ := os.ReadDir("/proc/self/fd")
			g0 := runtime.NumGoroutine()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if mode == "conflict-cycle" {
					k.external = append(cloneNFTTestObjects(safe), fixHookRule("inet", map[string]any{"drop": nil}))
					m.Refresh(desired)
					if len(n.activeSpecs) != 0 {
						b.Fatal("drop chain permitted admission")
					}
					k.external = safe
				}
				m.Refresh(desired)
			}
			b.StopTimer()
			if mode != "conflict-cycle" && (syncs != 0 || k.writes != writes || ct.lists+ct.ownedLists != lists) {
				b.Fatal("steady refresh performed persistence, conntrack scans or object reconstruction")
			}
			if mode == "no-conflict" && k.ruleReads != reads {
				b.Fatal("no-conflict refresh read full ruleset")
			}
			b.ReportMetric(float64(k.ruleReads-reads)/float64(b.N), "ruleset-reads/op")
			b.ReportMetric(float64(k.writes-writes)/float64(b.N), "nft-writes/op")
			b.ReportMetric(float64(ct.lists+ct.ownedLists-lists)/float64(b.N), "ct-lists/op")
			b.ReportMetric(float64(syncs)/float64(b.N), "file-syncs/op")
			b.ReportMetric(float64(len(n.activeSpecs)), "active-paths")
			fd1, _ := os.ReadDir("/proc/self/fd")
			b.ReportMetric(float64(len(fd1)-len(fd0)), "fd-delta")
			b.ReportMetric(float64(runtime.NumGoroutine()-g0), "goroutine-delta")
			if ct.deletes != 0 {
				b.Fatal("proof cost measurement deleted unrelated connections")
			}
			m.Stop()
		})
	}
}

func BenchmarkNFTManagerRecovery(b *testing.B) {
	for _, count := range []int{32, 128, 512} {
		b.Run(fmt.Sprintf("scopes-%d", count), func(b *testing.B) {
			dir, err := os.MkdirTemp("/tmp", "pb-manager-recovery-")
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = os.RemoveAll(dir) })
			path := filepath.Join(dir, "config.json")
			specs := make([]nftRuleSpec, count)
			desired := make([]config.Rule, count)
			for i := range specs {
				specs[i] = nftUnitSpec()
				specs[i].RuleID = fmt.Sprintf("recovery-%d", i)
				specs[i].ListenPort = 18000 + i
				specs[i].ListenPortEnd = 18000 + i
				desired[i] = ruleFromNFTSpec(specs[i])
			}
			k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(specs...)}
			ct := &memoryConntrack{}
			n := fixFullBackend(k, ct, path)
			m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
			m.Apply(desired)
			if !n.initialized {
				b.Fatal("initial admission failed")
			}
			writes, lists, reads := k.writes, ct.lists+ct.ownedLists, k.ruleReads
			syncs := 0
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n = fixFullBackend(k, ct, path)
				n.store.fault = func(stage string) error {
					if stage == "file-sync" {
						syncs++
					}
					return nil
				}
				m = newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
				m.Apply(desired)
				if !n.initialized || len(n.activeSpecs) != count {
					b.Fatal("manager recovery failed")
				}
			}
			b.StopTimer()
			if syncs != 0 || k.writes != writes {
				b.Fatal("ordinary recovery rewrote stable state")
			}
			b.ReportMetric(float64(k.ruleReads-reads)/float64(b.N), "ruleset-reads/op")
			b.ReportMetric(float64(k.writes-writes)/float64(b.N), "nft-writes/op")
			b.ReportMetric(float64(ct.lists+ct.ownedLists-lists)/float64(b.N), "ct-lists/op")
			b.ReportMetric(float64(syncs)/float64(b.N), "file-syncs/op")
			m.Stop()
		})
	}
}
