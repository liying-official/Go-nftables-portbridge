//go:build linux

package proxy

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"portbridge/internal/config"
	"runtime"
	"sort"
	"testing"
	"time"
)

// Identical fixture is overlaid on the unmodified v2.4.4 baseline for comparison.
// This is bounded request/reply latency, not saturation or a NIC PPS ceiling.
func BenchmarkComparisonUDP(b *testing.B) {
	sizes := []int{64, 256, 512, 1400}
	if os.Getenv("PB_BENCH_EMPTY") == "1" {
		sizes = []int{0}
	}
	for _, wildcard := range []bool{false, true} {
		for _, workers := range []int{1, 4} {
			for _, load := range []struct{ flows, sources int }{{1, 1}, {16, 1}, {16, 16}} {
				for _, size := range sizes {
					name := fmt.Sprintf("wildcard_%t/workers_%d/flows_%d/sources_%d/bytes_%d", wildcard, workers, load.flows, load.sources, size)
					b.Run(name, func(b *testing.B) { comparisonUDP(b, wildcard, workers, load.flows, load.sources, size) })
				}
			}
		}
	}
}
func comparisonUDP(b *testing.B, wildcard bool, workers, flows, sources, size int) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		payload := make([]byte, 2048)
		for {
			n, peer, err := target.ReadFromUDPAddrPort(payload)
			if err != nil {
				return
			}
			if _, err := target.WriteToUDPAddrPort(payload[:n], peer); err != nil {
				return
			}
		}
	}()
	defer func() { _ = target.Close(); <-done }()
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	bind := "127.0.0.1"
	if wildcard {
		bind = "0.0.0.0"
	}
	rule := config.NormalizeRule(config.Rule{ID: "comparison-udp", Enabled: true, Protocol: config.ProtocolUDP, DataPlane: config.RuleDataPlaneGo,
		ListenHost: bind, ListenPort: port, TargetHost: "127.0.0.1", TargetPort: target.LocalAddr().(*net.UDPAddr).Port,
		UDPWorkers: workers, MaxUDPSessions: 64, MaxUDPSessionsPerIP: 64, UDPPacketsPerSec: 1000000, UDPNewSessionsPerSec: 1000,
		UDPBatchSize: 64, UDPPacketBufferSize: 2048, UDPListenerBufferBytes: 4 << 20, UDPSessionBufferBytes: 64 << 10,
		AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"}})
	r := newRunner(rule, &Stats{}, testLogger())
	if err := r.start(); err != nil {
		b.Fatal(err)
	}
	defer r.stop()
	clients := make([]*net.UDPConn, 0, flows)
	defer func() {
		for _, c := range clients {
			_ = c.Close()
		}
	}()
	for i := 0; i < flows; i++ {
		c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, byte(2+i%sources))}, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		if err != nil {
			b.Fatal(err)
		}
		clients = append(clients, c)
	}
	payload := bytes.Repeat([]byte{0x35}, size)
	reply := make([]byte, size+1)
	exchange := func(c *net.UDPConn) {
		if err := c.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			b.Fatal(err)
		}
		if n, err := c.Write(payload); err != nil || n != size {
			b.Fatalf("write n=%d err=%v", n, err)
		}
		if n, err := c.Read(reply); err != nil || n != size || !bytes.Equal(payload, reply[:n]) {
			b.Fatalf("reply n=%d err=%v", n, err)
		}
	}
	for _, c := range clients {
		exchange(c)
	}
	reserved := r.resources.udpMemory.Load()
	fdEntries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		b.Fatal(err)
	}
	goroutines := runtime.NumGoroutine()
	latencies := make([]int64, 2048)
	var before, after unix.Rusage
	if err := unix.Getrusage(unix.RUSAGE_SELF, &before); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(size))
	b.ResetTimer()
	started := time.Now()
	for i := 0; i < b.N; i++ {
		packetStart := time.Now()
		exchange(clients[i%flows])
		latencies[i%len(latencies)] = time.Since(packetStart).Nanoseconds()
	}
	elapsed := time.Since(started)
	b.StopTimer()
	if err := unix.Getrusage(unix.RUSAGE_SELF, &after); err != nil {
		b.Fatal(err)
	}
	cpu := func(r unix.Rusage) int64 { return (r.Utime.Sec+r.Stime.Sec)*1e9 + (r.Utime.Usec+r.Stime.Usec)*1000 }
	count := b.N
	if count > len(latencies) {
		count = len(latencies)
	}
	sort.Slice(latencies[:count], func(i, j int) bool { return latencies[i] < latencies[j] })
	b.ReportMetric(float64(latencies[(count-1)*99/100]), "p99-ns")
	b.ReportMetric(float64(cpu(after)-cpu(before))/float64(b.N), "cpu-ns/op")
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "roundtrips/s")
	b.ReportMetric(float64(size*8)*float64(b.N)/elapsed.Seconds()/1e9, "payload-Gbps")
	b.ReportMetric(float64(reserved), "reserved-B")
	b.ReportMetric(float64(len(fdEntries)), "fds")
	b.ReportMetric(float64(goroutines), "goroutines")
	r.stop()
	if r.stats.snapshot().UDPDrops != 0 || r.resources.activeUDP.Load() != 0 || r.resources.udpMemory.Load() != 0 {
		b.Fatal("unexpected packet drop or retained reservation")
	}
	b.ReportMetric(0, "drops/op")
}
