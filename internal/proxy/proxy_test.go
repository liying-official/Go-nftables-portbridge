package proxy

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"portbridge/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// Only explicit address-family/protocol absence is an environmental skip.
// Malformed addresses, missing ports, occupied ports and permission failures fail.
func testListenFailure(t testing.TB, network, address string, err error) {
	t.Helper()
	if _, _, parseErr := net.SplitHostPort(address); parseErr != nil {
		t.Fatalf("invalid test listen address %q: %v", address, parseErr)
	}
	if testNetworkUnsupported(err) {
		t.Skipf("%s is unsupported by this environment: %v", network, err)
	}
	t.Fatalf("listen %s %s failed: %v", network, address, err)
}

func testNetworkUnsupported(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT)
}

func TestListenFailuresDoNotHideTestErrors(t *testing.T) {
	for _, err := range []error{&net.AddrError{Err: "missing port in address", Addr: "127.0.0.1"}, syscall.EADDRINUSE, syscall.EACCES, syscall.EINVAL} {
		if testNetworkUnsupported(err) {
			t.Fatalf("test/configuration error classified as missing capability: %v", err)
		}
	}
	for _, err := range []error{syscall.EAFNOSUPPORT, &net.OpError{Err: syscall.EPROTONOSUPPORT}} {
		if !testNetworkUnsupported(err) {
			t.Fatalf("explicit unsupported network was not recognized: %v", err)
		}
	}
}

func TestInfoLogDoesNotExposeRuleTopology(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logGoPathStarted(logger, goPath{
		RuleID: "0123456789abcdef",
		Rule: config.Rule{
			Name: "private-rule-name", Protocol: config.ProtocolTCP,
			ListenHost: "192.0.2.10", ListenPort: 10000,
			TargetHost: "198.51.100.20", TargetPort: 20000,
		},
	})
	got := output.String()
	for _, secret := range []string{"private-rule-name", "192.0.2.10", "198.51.100.20", "10000", "20000"} {
		if strings.Contains(got, secret) {
			t.Fatalf("info log exposes %q: %s", secret, got)
		}
	}
	for _, want := range []string{"Go proxy path started", "0123456789abcdef", "tcp"} {
		if !strings.Contains(got, want) {
			t.Fatalf("info log is missing %q: %s", want, got)
		}
	}
}

func freeTCPPort(t *testing.T, network, address string) int {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		testListenFailure(t, network, address, err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func startTCPEcho(t *testing.T, network, address string) (host string, port int, closeFn func()) {
	t.Helper()
	ln, err := net.Listen(network, address)
	if err != nil {
		testListenFailure(t, network, address, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	tcpAddr := ln.Addr().(*net.TCPAddr)
	return tcpAddr.IP.String(), tcpAddr.Port, func() { _ = ln.Close() }
}

func runTCPCase(t *testing.T, listenHost, targetHost string, targetPort int, dialNetwork, dialAddr string) {
	t.Helper()
	port := freeTCPPort(t, dialNetwork, net.JoinHostPort(dialAddr, "0"))
	rule := config.NormalizeRule(config.Rule{
		ID: "test", Name: "test", Protocol: "tcp", ListenHost: listenHost, ListenPort: port,
		TargetHost: targetHost, TargetPort: targetPort, Enabled: true,
	})
	r := newRunner(rule, &Stats{}, testLogger())
	if err := r.start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer r.stop()
	conn, err := net.DialTimeout(dialNetwork, net.JoinHostPort(dialAddr, portString(port)), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	payload := []byte("portbridge-tcp-test")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q want %q", got, payload)
	}
}

func TestTCPIPv4ToIPv4(t *testing.T) {
	host, port, closeEcho := startTCPEcho(t, "tcp4", "127.0.0.1:0")
	defer closeEcho()
	runTCPCase(t, "127.0.0.1", host, port, "tcp4", "127.0.0.1")
}

func TestTCPIPv4ToIPv6(t *testing.T) {
	host, port, closeEcho := startTCPEcho(t, "tcp6", "[::1]:0")
	defer closeEcho()
	runTCPCase(t, "127.0.0.1", host, port, "tcp4", "127.0.0.1")
}

func TestTCPIPv6ToIPv4(t *testing.T) {
	host, port, closeEcho := startTCPEcho(t, "tcp4", "127.0.0.1:0")
	defer closeEcho()
	runTCPCase(t, "::1", host, port, "tcp6", "::1")
}

func TestManagerReplacesGoTargetWithoutBindOutage(t *testing.T) {
	port := freeTCPPort(t, "tcp4", "127.0.0.1:0")
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), &fakeNFTBackend{})
	defer m.Stop()
	rule := config.NormalizeRule(config.Rule{
		ID: "target-refresh", Name: "target-refresh", Protocol: config.ProtocolTCP,
		DataPlane: config.RuleDataPlaneGo, ListenHost: "127.0.0.1", ListenPort: port,
		TargetHost: "127.0.0.1", TargetPort: 9, Enabled: true,
		AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.0/8"},
	})
	m.Apply([]config.Rule{rule})
	if runtime := m.Runtime(); len(runtime) != 1 || !runtime[0].Stats.Running {
		t.Fatalf("initial Go path is not running: %+v", runtime)
	}

	rule.TargetHost = "127.0.0.2"
	m.Refresh([]config.Rule{rule})
	if runtime := m.Runtime(); len(runtime) != 1 || !runtime[0].Stats.Running || runtime[0].Stats.LastError != "" {
		t.Fatalf("refreshed Go path is not running: %+v", runtime)
	}
}

func startUDPEcho(t *testing.T, network, address string) (host string, port int, closeFn func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP(network, addr)
	if err != nil {
		testListenFailure(t, network, address, err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], peer)
		}
	}()
	udpAddr := conn.LocalAddr().(*net.UDPAddr)
	return udpAddr.IP.String(), udpAddr.Port, func() { _ = conn.Close() }
}

func freeUDPPort(t *testing.T, network, address string) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP(network, addr)
	if err != nil {
		testListenFailure(t, network, address, err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func runUDPCase(t *testing.T, listenHost, targetHost string, targetPort int, network, dialHost string) {
	t.Helper()
	port := freeUDPPort(t, network, net.JoinHostPort(dialHost, "0"))
	rule := config.NormalizeRule(config.Rule{
		ID: "test", Name: "test", Protocol: "udp", ListenHost: listenHost, ListenPort: port,
		TargetHost: targetHost, TargetPort: targetPort, Enabled: true, UDPIdleTimeoutSeconds: 5,
	})
	r := newRunner(rule, &Stats{}, testLogger())
	if err := r.start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer r.stop()
	remote, err := net.ResolveUDPAddr(network, net.JoinHostPort(dialHost, portString(port)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialUDP(network, nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := []byte("portbridge-udp-test")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("got %q want %q", buf[:n], payload)
	}
}

func TestUDPIPv4ToIPv4(t *testing.T) {
	host, port, closeEcho := startUDPEcho(t, "udp4", "127.0.0.1:0")
	defer closeEcho()
	runUDPCase(t, "127.0.0.1", host, port, "udp4", "127.0.0.1")
}

func TestUDPIPv4ToIPv6(t *testing.T) {
	host, port, closeEcho := startUDPEcho(t, "udp6", "[::1]:0")
	defer closeEcho()
	runUDPCase(t, "127.0.0.1", host, port, "udp4", "127.0.0.1")
}

func TestUDPIPv6ToIPv4(t *testing.T) {
	host, port, closeEcho := startUDPEcho(t, "udp4", "127.0.0.1:0")
	defer closeEcho()
	runUDPCase(t, "::1", host, port, "udp6", "::1")
}

func TestUDPIPv6ToIPv6(t *testing.T) {
	host, port, closeEcho := startUDPEcho(t, "udp6", "[::1]:0")
	defer closeEcho()
	runUDPCase(t, "::1", host, port, "udp6", "::1")
}

func startBothEcho(t *testing.T) (host string, port int, closeFn func()) {
	t.Helper()
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port = tcpListener.Addr().(*net.TCPAddr).Port
	udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("127.0.0.1", portString(port)))
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, peer, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpConn.WriteToUDP(buf[:n], peer)
		}
	}()
	return "127.0.0.1", port, func() {
		_ = tcpListener.Close()
		_ = udpConn.Close()
	}
}

func freeBothPort(t *testing.T) int {
	t.Helper()
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("127.0.0.1", portString(port)))
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	udpConn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		_ = tcpListener.Close()
		t.Fatal(err)
	}
	_ = udpConn.Close()
	_ = tcpListener.Close()
	return port
}

func TestBothTCPAndUDPIPv4(t *testing.T) {
	targetHost, targetPort, closeEcho := startBothEcho(t)
	defer closeEcho()
	listenPort := freeBothPort(t)
	stats := &Stats{}
	rule := config.NormalizeRule(config.Rule{
		ID: "both", Name: "both", Protocol: config.ProtocolBoth,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: targetHost, TargetPort: targetPort, Enabled: true,
		UDPIdleTimeoutSeconds: 5,
	})
	runner := newRunner(rule, stats, testLogger())
	if err := runner.start(); err != nil {
		t.Fatalf("start TCP+UDP proxy: %v", err)
	}
	defer runner.stop()

	tcpConn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", portString(listenPort)), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	tcpPayload := []byte("both-tcp")
	if _, err := tcpConn.Write(tcpPayload); err != nil {
		_ = tcpConn.Close()
		t.Fatal(err)
	}
	_ = tcpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	tcpReply := make([]byte, len(tcpPayload))
	if _, err := io.ReadFull(tcpConn, tcpReply); err != nil {
		_ = tcpConn.Close()
		t.Fatal(err)
	}
	_ = tcpConn.Close()
	if !bytes.Equal(tcpReply, tcpPayload) {
		t.Fatalf("TCP got %q want %q", tcpReply, tcpPayload)
	}

	udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("127.0.0.1", portString(listenPort)))
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpPayload := []byte("both-udp")
	if _, err := udpConn.Write(udpPayload); err != nil {
		t.Fatal(err)
	}
	_ = udpConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	udpReply := make([]byte, len(udpPayload))
	if _, err := io.ReadFull(udpConn, udpReply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(udpReply, udpPayload) {
		t.Fatalf("UDP got %q want %q", udpReply, udpPayload)
	}

	snapshot := stats.snapshot()
	if snapshot.TotalTCP != 1 || snapshot.TotalUDPSessions != 1 {
		t.Fatalf("unexpected totals: TCP=%d UDP=%d", snapshot.TotalTCP, snapshot.TotalUDPSessions)
	}
}

func listenConsecutiveTCPPorts(t *testing.T) (int, []net.Listener) {
	t.Helper()
	for base := 30000; base < 60000; base++ {
		first, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", portString(base)))
		if err != nil {
			continue
		}
		second, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", portString(base+1)))
		if err != nil {
			_ = first.Close()
			continue
		}
		return base, []net.Listener{first, second}
	}
	t.Fatal("cannot reserve two consecutive TCP ports")
	return 0, nil
}

func TestTCPPortRangeMapping(t *testing.T) {
	targetBase, targets := listenConsecutiveTCPPorts(t)
	for i, listener := range targets {
		prefix := byte('A' + i)
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer conn.Close()
					buf := make([]byte, 64)
					n, _ := conn.Read(buf)
					_, _ = conn.Write(append([]byte{prefix, ':'}, buf[:n]...))
				}()
			}
		}(listener)
	}
	defer func() {
		for _, listener := range targets {
			_ = listener.Close()
		}
	}()

	listenBase, reservations := listenConsecutiveTCPPorts(t)
	for _, listener := range reservations {
		_ = listener.Close()
	}
	rule := config.NormalizeRule(config.Rule{
		ID: "range", Name: "range", Protocol: config.ProtocolTCP,
		ListenHost: "127.0.0.1", ListenPort: listenBase, ListenPortEnd: listenBase + 1,
		TargetHost: "127.0.0.1", TargetPort: targetBase, TargetPortEnd: targetBase + 1,
		Enabled: true,
	})
	runner := newRunner(rule, &Stats{}, testLogger())
	if err := runner.start(); err != nil {
		t.Fatalf("start port range: %v", err)
	}
	defer runner.stop()
	for offset, wantPrefix := range []string{"A:range", "B:range"} {
		conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", portString(listenBase+offset)), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte("range"))
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(wantPrefix))
		_, err = io.ReadFull(conn, buf)
		_ = conn.Close()
		if err != nil {
			t.Fatal(err)
		}
		if string(buf) != wantPrefix {
			t.Fatalf("offset %d got %q want %q", offset, buf, wantPrefix)
		}
	}
}

func portString(port int) string {
	return fmtInt(port)
}

func fmtInt(v int) string {
	// strconv.Itoa kept behind a tiny helper to make address construction easy to scan in tests.
	return strconv.Itoa(v)
}
