package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// New costs are isolated from the baseline comparison. These benchmarks use
// causal objects and actual protected-file IO, NOT kernel packets/CLI timing.
func BenchmarkNFTFixCompatibility(b *testing.B) {
	for _, mode := range []string{"empty-hook-unchanged", "conflict-appear-disappear", "simulated-boot-rollover"} {
		b.Run(mode, func(b *testing.B) {
			dir, err := os.MkdirTemp("/tmp", "pb-fix-bench-")
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() { _ = os.RemoveAll(dir) })
			path := filepath.Join(dir, "config.json")
			a, other := reviewAB()
			k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a, other)}
			ct := &memoryConntrack{}
			n := fixFullBackend(k, ct, path)
			wanted := []nftRuleSpec{a, other}
			if err := n.Replace(wanted); err != nil {
				b.Fatal(err)
			}
			data, err := os.ReadFile(path + ".nft-state.json")
			if err != nil {
				b.Fatal(err)
			}
			var envelope nftDiskEnvelope
			var old nftDiskRecord
			if err := json.Unmarshal(data, &envelope); err != nil {
				b.Fatal(err)
			}
			if err := json.Unmarshal(envelope.Payload, &old); err != nil {
				b.Fatal(err)
			}
			old.Context.BootID = fixOldBoot
			payload, err := json.Marshal(old)
			if err != nil {
				b.Fatal(err)
			}
			hash := sha256.Sum256(payload)
			oldData, err := json.Marshal(nftDiskEnvelope{Payload: payload, SHA256: hex.EncodeToString(hash[:])})
			if err != nil {
				b.Fatal(err)
			}
			k.external = fixEmptyHook("inet", "postrouting")
			if mode == "simulated-boot-rollover" {
				k.external = fixUnrelatedFirewall()
			}
			syncs := 0
			setFault := func() {
				n.store.fault = func(stage string) error {
					if stage == "file-sync" {
						syncs++
					}
					return nil
				}
			}
			setFault()
			writes, lists, reads := k.writes, ct.lists+ct.ownedLists, k.ruleReads
			fds0, _ := os.ReadDir("/proc/self/fd")
			g0 := runtime.NumGoroutine()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				switch mode {
				case "empty-hook-unchanged":
					if err := n.Replace(wanted); err != nil {
						b.Fatal(err)
					}
				case "conflict-appear-disappear":
					k.external = append(fixEmptyHook("inet", "postrouting"), fixHookRule("inet", map[string]any{"drop": nil}))
					if err := n.Replace(wanted); err == nil {
						b.Fatal("unsupported rule accepted")
					}
					k.external = fixEmptyHook("inet", "postrouting")
					if err := n.Replace(wanted); err != nil {
						b.Fatal(err)
					}
				case "simulated-boot-rollover":
					b.StopTimer()
					// Fixture setup only: simulate a previous lifecycle and discard kernel
					// objects. These writes are EXCLUDED; all production rollover IO is timed.
					if err := os.WriteFile(path+".nft-state.json", oldData, 0600); err != nil {
						b.Fatal(err)
					}
					k.objects = nil
					n = fixFullBackend(k, ct, path)
					setFault()
					b.StartTimer()
					if err := n.Replace(wanted); err != nil {
						b.Fatal(err)
					}
				}
			}
			b.StopTimer()
			if mode == "empty-hook-unchanged" && (syncs != 0 || writes != k.writes || lists != ct.lists+ct.ownedLists) {
				b.Fatal("unchanged path performed writes or conntrack scans")
			}
			b.ReportMetric(float64(syncs)/float64(b.N), "file-syncs/op")
			b.ReportMetric(float64(k.writes-writes)/float64(b.N), "nft-writes/op")
			b.ReportMetric(float64(ct.lists+ct.ownedLists-lists)/float64(b.N), "ct-lists/op")
			b.ReportMetric(float64(k.ruleReads-reads)/float64(b.N), "ruleset-reads/op")
			fds1, _ := os.ReadDir("/proc/self/fd")
			b.ReportMetric(float64(len(fds1)-len(fds0)), "fd-delta")
			b.ReportMetric(float64(runtime.NumGoroutine()-g0), "goroutine-delta")
			if ct.deletes != 0 {
				b.Fatal("compatibility timing unexpectedly deleted connections")
			}
			if err := n.Delete(); err != nil {
				b.Fatal(fmt.Errorf("benchmark cleanup: %w", err))
			}
		})
	}
}
