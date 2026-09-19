package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"

	"portbridge/internal/config"
)

func repairTCPPair(t *testing.T, idleSeconds int) (*runner, *net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_ = ln.SetDeadline(time.Now().Add(3 * time.Second))
	port := freeTCPPort(t, "tcp4", "127.0.0.1:0")
	rule := config.NormalizeRule(config.Rule{
		ID: "tcp-repair", Protocol: config.ProtocolTCP, DataPlane: config.RuleDataPlaneGo,
		ListenHost: "127.0.0.1", ListenPort: port, TargetHost: "127.0.0.1",
		TargetPort: ln.Addr().(*net.TCPAddr).Port, Enabled: true, TCPIdleTimeoutSeconds: idleSeconds,
		MaxTCPConnections: 4, MaxTCPConnectionsPerIP: 4,
		AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"},
	})
	r := newRunner(rule, &Stats{}, testLogger())
	if err := r.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.stop)
	client, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	target, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	_ = client.SetDeadline(time.Now().Add(8 * time.Second))
	_ = target.SetDeadline(time.Now().Add(8 * time.Second))
	// Synchronize on actual payload in both directions before inducing failure.
	if _, err := client.Write([]byte{'q'}); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(target, b[:]); err != nil || b[0] != 'q' {
		t.Fatalf("upstream handshake: %v", err)
	}
	if _, err := target.Write([]byte{'a'}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, b[:]); err != nil || b[0] != 'a' {
		t.Fatalf("downstream handshake: %v", err)
	}
	return r, client, target
}

func waitTCPReservationsReturned(t *testing.T, r *runner, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for r.stats.activeTCP.Load() != 0 || r.resources.activeTCP.Load() != 0 || r.budget.activeTCP.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("TCP reservations not returned: stats=%d global=%d rule=%d",
				r.stats.activeTCP.Load(), r.resources.activeTCP.Load(), r.budget.activeTCP.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	source := netip.MustParseAddr("127.0.0.1")
	shard := &r.budget.sources[sourceShard(source)]
	shard.mu.Lock()
	count := shard.counts[source]
	shard.mu.Unlock()
	if count != 0 {
		t.Fatalf("source reservation remains: %d", count)
	}
}

func TestTCPResetReclaimsResources(t *testing.T) {
	for _, direction := range []string{"upstream", "client"} {
		t.Run(direction, func(t *testing.T) {
			r, client, target := repairTCPPair(t, 300)
			reset := target
			if direction == "client" {
				reset = client
			}
			if err := reset.SetLinger(0); err != nil {
				t.Fatal(err)
			}
			if err := reset.Close(); err != nil {
				t.Fatal(err)
			}
			// The other write half deliberately stays open. No idle-expiry wait.
			waitTCPReservationsReturned(t, r, 2*time.Second)
			s := r.stats.snapshot()
			if s.BytesUp != 1 || s.BytesDown != 1 {
				t.Fatalf("direction bytes must settle exactly once: %+v", s)
			}
		})
	}
}

func TestTCPClientResetDuringResponseReclaimsResources(t *testing.T) {
	r, client, target := repairTCPPair(t, 300)
	writerDone := make(chan error, 1)
	go func() {
		_, err := io.CopyN(target, bytes.NewReader(bytes.Repeat([]byte{0x5a}, 8<<20)), 8<<20)
		writerDone <- err
	}()
	buf := make([]byte, 4096)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	_ = client.SetLinger(0)
	_ = client.Close()
	waitTCPReservationsReturned(t, r, 2*time.Second)
	select {
	case <-writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream writer did not wake after failed response forwarding")
	}
	if s := r.stats.snapshot(); s.BytesUp != 1 || s.BytesDown < 4097 {
		t.Fatalf("partial copy bytes were lost: %+v", s)
	}
}

func TestTCPHalfCloseLargeResponseTail(t *testing.T) {
	r, client, target := repairTCPPair(t, 300)
	payload := bytes.Repeat([]byte("large-response-tail"), 128<<10)
	done := make(chan error, 1)
	go func() {
		if _, err := io.ReadAll(target); err != nil {
			done <- err
			return
		}
		_, err := target.Write(payload)
		if err == nil {
			err = target.CloseWrite()
		}
		done <- err
	}()
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("response tail: got=%d want=%d err=%v", len(got), len(payload), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitTCPReservationsReturned(t, r, 2*time.Second)
	if s := r.stats.snapshot(); s.BytesUp != 1 || s.BytesDown != uint64(len(payload)+1) {
		t.Fatalf("half-close byte settlement mismatch: %+v", s)
	}
}

func TestTCPConcurrentStopReturnsResources(t *testing.T) {
	r, _, _ := repairTCPPair(t, 300)
	done := make(chan struct{})
	go func() {
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); r.stop() }()
		}
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("concurrent Stop did not complete")
	}
	waitTCPReservationsReturned(t, r, time.Second)
}

func TestTCPIdleReclaimsResources(t *testing.T) {
	r, _, _ := repairTCPPair(t, 5)
	waitTCPReservationsReturned(t, r, 8*time.Second)
}

func TestTCPDialFailureReturnsResources(t *testing.T) {
	port := freeTCPPort(t, "tcp4", "127.0.0.1:0")
	targetPort := freeTCPPort(t, "tcp4", "127.0.0.1:0")
	rule := config.NormalizeRule(config.Rule{
		ID: "dial-failure", Protocol: config.ProtocolTCP, DataPlane: config.RuleDataPlaneGo,
		ListenHost: "127.0.0.1", ListenPort: port, TargetHost: "127.0.0.1", TargetPort: targetPort, Enabled: true,
		AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"},
	})
	r := newRunner(rule, &Stats{}, testLogger())
	if err := r.start(); err != nil {
		t.Fatal(err)
	}
	defer r.stop()
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("failed dial unexpectedly produced data")
	}
	waitTCPReservationsReturned(t, r, time.Second)
}

func TestTCPDialCancellation(t *testing.T) {
	r := newRunner(config.NormalizeRule(config.Rule{TCPIdleTimeoutSeconds: 300}), &Stats{}, testLogger())
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	entered := make(chan struct{})
	dialer := &net.Dialer{ControlContext: func(ctx context.Context, _, _ string, _ syscall.RawConn) error {
		close(entered)
		<-ctx.Done()
		return ctx.Err()
	}}
	done := make(chan struct{})
	var active sync.Map
	go func() { r.handleTCP(client, &active, "127.0.0.1:9", dialer); close(done) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial did not enter the synchronized control hook")
	}
	r.stop()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt dial")
	}
	active.Range(func(_, _ any) bool { t.Error("cancelled dial left an active upstream"); return true })
	if !errors.Is(r.ctx.Err(), context.Canceled) {
		t.Fatal("runner was not cancelled")
	}
}
