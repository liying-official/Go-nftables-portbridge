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

	"portbridge/internal/config"
)

// This benchmark is self-contained with respect to the new proof: the same
// file is overlaid on a separate .7 comparison tree. It exercises a full Manager
// cycle with causal objects and real file IO, NOT Linux nft/conntrack latency.
// active-paths MUST accompany times: .7 suspends the new conditional cases.
func BenchmarkNFTTransparentManager(b *testing.B) {
	for _, mode := range []string{"no-conflict", "empty", "pure-accept", "single-condition", "multi-condition", "rules-32", "chains-8", "core-maximum", "rules-1024", "transparent-unsupported-cycle"} {
		b.Run(mode, func(b *testing.B) {
			dir, err := os.MkdirTemp("/tmp", "pb-transparent-bench-")
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
			if !n.initialized || len(n.activeSpecs) != 2 {
				b.Fatal("initial Manager admission failed")
			}
			safe := fixEmptyHook("inet", "postrouting")
			rules, conditions := 1, 1
			switch mode {
			case "no-conflict":
				safe = nil
				rules = 0
			case "empty":
				rules = 0
			case "pure-accept":
				conditions = 0
			case "multi-condition":
				conditions = 4
			case "rules-32":
				rules = 32
			case "rules-1024":
				rules = 1024
			case "core-maximum":
				conditions = 16
			}
			makeRule := func(chain string, handle int) nftObject {
				var expr []any
				for i := 0; i < conditions; i++ {
					expr = append(expr, map[string]any{"match": map[string]any{"left": map[string]any{"payload": map[string]any{"protocol": "tcp", "field": "dport"}}, "op": "!=", "right": i}})
				}
				expr = append(expr, map[string]any{"accept": nil})
				return nftObject{"rule": map[string]any{"family": "inet", "table": "external-control", "chain": chain, "handle": handle, "expr": expr}}
			}
			for i := 0; i < rules; i++ {
				safe = append(safe, makeRule("after", i+10))
			}
			if mode == "chains-8" {
				for i := 1; i < 8; i++ {
					name := fmt.Sprintf("after-%d", i)
					safe = append(safe, nftObject{"chain": map[string]any{"family": "inet", "table": "external-control", "name": name, "type": "filter", "hook": "postrouting", "prio": 0, "policy": "accept"}}, makeRule(name, 10))
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
				if mode == "transparent-unsupported-cycle" {
					k.external = append(cloneNFTTestObjects(safe), fixHookRule("inet", map[string]any{"counter": nil}))
					m.Refresh(desired)
					if len(n.activeSpecs) != 0 {
						b.Fatal("side-effect chain accepted")
					}
					k.external = safe
				}
				m.Refresh(desired)
			}
			b.StopTimer()
			if mode != "transparent-unsupported-cycle" && (syncs != 0 || k.writes != writes || ct.lists+ct.ownedLists != lists) {
				b.Fatal("steady Manager refresh performed persistence, scans or reconstruction")
			}
			if mode == "no-conflict" && k.ruleReads != reads {
				b.Fatal("no-conflict path gained ruleset reads")
			}
			b.ReportMetric(float64(k.ruleReads-reads)/float64(b.N), "ruleset-reads/op")
			b.ReportMetric(float64(k.writes-writes)/float64(b.N), "nft-writes/op")
			b.ReportMetric(float64(ct.lists+ct.ownedLists-lists)/float64(b.N), "ct-lists/op")
			b.ReportMetric(float64(syncs)/float64(b.N), "file-syncs/op")
			b.ReportMetric(float64(len(n.activeSpecs)), "active-paths")
			b.ReportMetric(float64(len(n.suspendedSpecs)), "suspended-paths")
			fd1, _ := os.ReadDir("/proc/self/fd")
			b.ReportMetric(float64(len(fd1)-len(fd0)), "fd-delta")
			b.ReportMetric(float64(runtime.NumGoroutine()-g0), "goroutine-delta")
			if ct.deletes != 0 {
				b.Fatal("proof benchmark deleted unrelated connections")
			}
			m.Stop()
		})
	}
}

func BenchmarkNFTTransparentScopedBootManager(b *testing.B) {
	dir, err := os.MkdirTemp("/tmp", "pb-transparent-boot-bench-")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "config.json")
	a, other := reviewAB()
	k := &fixFullRulesKernel{causalNFTKernel: newCausalNFTKernel(a, other)}
	ct := &memoryConntrack{}
	n := fixFullBackend(k, ct, path)
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
	desired := []config.Rule{ruleFromNFTSpec(a), ruleFromNFTSpec(other)}
	m.Apply(desired)
	if len(n.activeSpecs) != 2 {
		b.Fatal("initial setup failed")
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
	k.external = fixUnrelatedFirewall()
	foreign := conntrackUnitEntry(a, 45000)
	foreign.mark++
	ct.entries = []conntrackEntry{foreign}
	writes, reads, lists := k.writes, k.ruleReads, ct.lists+ct.ownedLists
	syncs := 0
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Simulated boot fixture preparation is excluded. Never reboot the host.
		if err := os.WriteFile(path+".nft-state.json", oldData, 0600); err != nil {
			b.Fatal(err)
		}
		k.objects = nil
		n = fixFullBackend(k, ct, path)
		n.store.fault = func(stage string) error {
			if stage == "file-sync" {
				syncs++
			}
			return nil
		}
		m = newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
		b.StartTimer()
		m.Apply(desired)
		if !n.initialized || len(n.activeSpecs) != 2 || ct.deletes != 0 {
			b.Fatal("scoped rollover failed or deleted foreign connection")
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(k.ruleReads-reads)/float64(b.N), "ruleset-reads/op")
	b.ReportMetric(float64(k.writes-writes)/float64(b.N), "nft-writes/op")
	b.ReportMetric(float64(ct.lists+ct.ownedLists-lists)/float64(b.N), "ct-lists/op")
	b.ReportMetric(float64(syncs)/float64(b.N), "file-syncs/op")
	b.ReportMetric(float64(len(n.activeSpecs)), "active-paths")
	m.Stop()
}
