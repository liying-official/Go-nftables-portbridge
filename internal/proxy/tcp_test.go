package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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

type trackingReaderFromConn struct {
	net.Conn
	called bool
}

func (c *trackingReaderFromConn) ReadFrom(r io.Reader) (int64, error) {
	c.called = true
	return io.Copy(io.Discard, r)
}

func TestCopyTCPStreamPrefersReaderFrom(t *testing.T) {
	source, sourceWriter := net.Pipe()
	destination, destinationPeer := net.Pipe()
	defer source.Close()
	defer destination.Close()
	defer destinationPeer.Close()

	payload := bytes.Repeat([]byte("portbridge-fast-path"), 1024)
	go func() {
		_, _ = sourceWriter.Write(payload)
		_ = sourceWriter.Close()
	}()

	tracked := &trackingReaderFromConn{Conn: destination}
	n, err := copyTCPStream(tracked, source)
	if err != nil {
		t.Fatal(err)
	}
	if !tracked.called {
		t.Fatal("ReaderFrom fast path was not used")
	}
	if n != int64(len(payload)) {
		t.Fatalf("copied %d bytes, want %d", n, len(payload))
	}
}

func TestCopyTCPStreamBufferedFallback(t *testing.T) {
	source, sourceWriter := net.Pipe()
	destination, destinationPeer := net.Pipe()
	defer source.Close()
	defer destinationPeer.Close()

	payload := bytes.Repeat([]byte("portbridge-buffered-path"), 1024)
	copyDone := make(chan error, 1)
	go func() {
		_, err := copyTCPStream(destination, source)
		_ = destination.Close()
		copyDone <- err
	}()
	go func() {
		_, _ = sourceWriter.Write(payload)
		_ = sourceWriter.Close()
	}()

	got, err := io.ReadAll(destinationPeer)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-copyDone; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("copied payload differs: got %d bytes, want %d", len(got), len(payload))
	}
}

func TestTCPProxyPreservesHalfClose(t *testing.T) {
	targetListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("network unavailable: %v", err)
	}
	defer targetListener.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := targetListener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		request, readErr := io.ReadAll(conn)
		if readErr != nil {
			serverDone <- readErr
			return
		}
		_, writeErr := conn.Write(append([]byte("ack:"), request...))
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		serverDone <- writeErr
	}()

	targetAddress := targetListener.Addr().(*net.TCPAddr)
	proxyPort := freeTCPPort(t, "tcp4", "127.0.0.1:0")
	rule := config.NormalizeRule(config.Rule{
		ID: "half-close", Name: "half-close", Protocol: "tcp",
		ListenHost: "127.0.0.1", ListenPort: proxyPort,
		TargetHost: "127.0.0.1", TargetPort: targetAddress.Port, Enabled: true,
	})
	runner := newRunner(rule, &Stats{}, testLogger())
	if err := runner.start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer runner.stop()

	clientConn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := clientConn.(*net.TCPConn)
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))

	payload := []byte("request-needs-eof")
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte("ack:"), payload...)
	if !bytes.Equal(response, want) {
		t.Fatalf("response %q, want %q", response, want)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

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

func auditTCPPair(tb testing.TB) (*net.TCPConn, *net.TCPConn) {
	tb.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tb.Fatal(err)
	}
	defer ln.Close()
	a, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		tb.Fatal(err)
	}
	z, err := ln.AcceptTCP()
	if err != nil {
		a.Close()
		tb.Fatal(err)
	}
	tb.Cleanup(func() { a.Close(); z.Close() })
	return a, z
}

func BenchmarkAuditTCPActivitySignature(b *testing.B) {
	a, z := auditTCPPair(b)
	conns := []net.Conn{a, z}
	if _, ok := tcpActivitySignature(conns); !ok {
		b.Fatal("TCP_INFO not supported")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := tcpActivitySignature(conns); !ok {
			b.Fatal("TCP_INFO failed")
		}
	}
}

type auditPlainConn struct{ net.Conn }

func BenchmarkAuditTCPCopy(b *testing.B) {
	for _, buffered := range []bool{false, true} {
		b.Run(fmt.Sprintf("forced_buffered_%t", buffered), func(b *testing.B) {
			a, src := auditTCPPair(b)
			dst, z := auditTCPPair(b)
			var from, to net.Conn = src, dst
			if buffered {
				from = auditPlainConn{src}
				to = auditPlainConn{dst}
			}
			done := make(chan error, 1)
			go func() { _, err := copyTCPStream(to, from); dst.CloseWrite(); done <- err }()
			payload := bytes.Repeat([]byte{0x35}, 64<<10)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := a.Write(payload); err != nil {
					b.Fatal(err)
				}
				if _, err := io.ReadFull(z, payload); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			a.CloseWrite()
			if err := <-done; err != nil {
				b.Fatal(err)
			}
		})
	}
}
