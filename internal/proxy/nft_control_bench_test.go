package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"portbridge/internal/config"
)

// Control-plane measurements use the causal typed renderer fixture plus REAL
// protected-file writes/fsync. They do not time nft/conntrack subprocesses or
// claim kernel throughput. Forwarding limits and packet paths are untouched.
func BenchmarkNFTIndependentControl(b *testing.B) {
	for _, mode := range []string{"unchanged-refresh", "single-rule-change"} {
		b.Run(mode, func(b *testing.B) {
			dir, err := os.MkdirTemp("/tmp", "pb-nft-control-bench-")
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = os.RemoveAll(dir) })
			path := filepath.Join(dir, "config.json")
			a, other := reviewAB()
			changed := a
			changed.TargetPort++
			changed.TargetPortEnd++
			kernel := newCausalNFTKernel(a, other, changed)
			ct := &memoryConntrack{}
			backend := reviewBackend(kernel, ct, path)
			manager := newManagerWithNFT(testLogger(), NewDNSResolver(nil), backend)
			original := []config.Rule{ruleFromNFTSpec(a), ruleFromNFTSpec(other)}
			alternate := []config.Rule{ruleFromNFTSpec(changed), ruleFromNFTSpec(other)}
			manager.Apply(original)
			if !backend.initialized {
				b.Fatal("control fixture did not install")
			}
			syncs := 0
			backend.store.fault = func(stage string) error {
				if stage == "file-sync" {
					syncs++
				}
				return nil
			}
			writes, lists := kernel.writes, ct.lists+ct.ownedLists
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if mode == "unchanged-refresh" {
					manager.Refresh(original)
				} else if i%2 == 0 {
					manager.Apply(alternate)
				} else {
					manager.Apply(original)
				}
				if !backend.initialized {
					b.Fatal("control reconciliation failed")
				}
			}
			b.StopTimer()
			if mode == "unchanged-refresh" && (syncs != 0 || kernel.writes != writes || ct.lists+ct.ownedLists != lists) {
				b.Fatal("unchanged refresh performed persistence or conntrack mutation")
			}
			b.ReportMetric(float64(syncs)/float64(b.N), "file-syncs/op")
			b.ReportMetric(float64(kernel.writes-writes)/float64(b.N), "nft-writes/op")
			b.ReportMetric(float64(ct.lists+ct.ownedLists-lists)/float64(b.N), "ct-lists/op")
			stat, err := os.Stat(path + ".nft-state.json")
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(stat.Size()), "checkpoint-B")
			manager.Stop()
		})
	}
}

func BenchmarkNFTIndependentRecovery(b *testing.B) {
	for _, count := range []int{32, 128, 512} {
		b.Run(fmt.Sprintf("scopes-%d", count), func(b *testing.B) {
			dir, err := os.MkdirTemp("/tmp", "pb-nft-recover-bench-")
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = os.RemoveAll(dir) })
			path := filepath.Join(dir, "config.json")
			specs := make([]nftRuleSpec, count)
			for i := range specs {
				specs[i] = nftUnitSpec()
				specs[i].RuleID = fmt.Sprintf("bounded-%d", i)
				specs[i].ListenPort = 18000 + i
				specs[i].ListenPortEnd = 18000 + i
			}
			kernel := newCausalNFTKernel(specs...)
			ct := &memoryConntrack{}
			backend := reviewBackend(kernel, ct, path)
			if err := backend.Replace(specs); err != nil {
				b.Fatal(err)
			}
			stat, err := os.Stat(path + ".nft-state.json")
			if err != nil {
				b.Fatal(err)
			}
			writes := kernel.writes
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				recovered := reviewBackend(kernel, ct, path)
				recovered.store.fault = func(stage string) error {
					if stage == "file-sync" {
						return fmt.Errorf("normal recovery attempted a redundant checkpoint")
					}
					return nil
				}
				if err := recovered.Replace(specs); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if kernel.writes != writes {
				b.Fatal("normal recovery unnecessarily rebuilt objects")
			}
			b.ReportMetric(float64(stat.Size()), "checkpoint-B")
			b.ReportMetric(float64(count), "scopes")
		})
	}
}
