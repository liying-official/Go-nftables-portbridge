// Audit-only probes. Original project files are unchanged.
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
	"portbridge/internal/config"
)

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

func TestAuditExportNFTRules(t *testing.T) {
	dir := os.Getenv("AUDIT_EVIDENCE")
	if dir == "" {
		t.Skip("AUDIT_EVIDENCE is not set")
	}
	specs := []nftRuleSpec{}
	for _, family := range []int{4, 6} {
		listen, target := "192.0.2.1", "198.51.100.2"
		if family == 6 {
			listen, target = "2001:db8:1::1", "2001:db8:2::2"
		}
		for _, proto := range []string{"tcp", "udp"} {
			specs = append(specs, nftRuleSpec{RuleID: fmt.Sprintf("audit-%d-%s", family, proto), Family: family,
				ListenHost: netip.MustParseAddr(listen), ListenPort: 18080, ListenPortEnd: 18082,
				TargetHost: netip.MustParseAddr(target), TargetPort: 28080, TargetPortEnd: 28082,
				Protocol: proto, ConntrackMark: config.DefaultNFTConntrackMark, EnableFlowtable: true})
		}
	}
	scripts := map[string]string{
		"nft-initial.nft":             renderNFTScript(specs, false, []string{"wan0", "lan0"}),
		"nft-topology-refresh.nft":    renderNFTScript(specs, true, []string{"wan0", "lan0", "new0"}),
		"nft-remove-rule-refresh.nft": renderNFTChainRefreshScript(specs[1:]),
	}
	for i := range specs {
		specs[i].EnableFlowtable = false
	}
	scripts["nft-disable-flowtable-existing.nft"] = renderNFTScript(specs, true, nil)
	scripts["nft-disabled-initial.nft"] = renderNFTScript(specs, false, nil)
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("exported %d scripts from unmodified renderer", len(scripts))
}

// This is a desired-behavior regression. It fails on the submitted version.
func TestAuditRegressionZeroLengthUDP(t *testing.T) {
	for _, emptyReply := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty_reply_%t", emptyReply), func(t *testing.T) {
			server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go func() {
				buf := make([]byte, 1024)
				for {
					n, addr, e := server.ReadFromUDP(buf)
					if e != nil {
						return
					}
					reply := buf[:n]
					if emptyReply {
						reply = nil
					}
					server.WriteToUDP(reply, addr)
				}
			}()
			check := func(port int) error {
				c, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
				if e != nil {
					return e
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(350 * time.Millisecond))
				var payload []byte
				if emptyReply {
					payload = []byte("request")
				}
				if _, e = c.Write(payload); e != nil {
					return e
				}
				n, e := c.Read(make([]byte, 1024))
				if e == nil && n != 0 {
					return fmt.Errorf("reply length=%d", n)
				}
				return e
			}
			targetPort := server.LocalAddr().(*net.UDPAddr).Port
			if err := check(targetPort); err != nil {
				t.Fatalf("direct UDP control failed: %v", err)
			}
			port := freeUDPPort(t, "udp4", "127.0.0.1:0")
			rule := config.NormalizeRule(config.Rule{ID: "audit-zero", Name: "audit-zero", Protocol: "udp", DataPlane: config.RuleDataPlaneGo,
				ListenHost: "127.0.0.1", ListenPort: port, TargetHost: "127.0.0.1", TargetPort: targetPort, Enabled: true, UDPWorkers: 1})
			stats := &Stats{}
			r := newRunner(rule, stats, testLogger())
			if err := r.start(); err != nil {
				t.Fatal(err)
			}
			defer r.stop()
			if err := check(port); err != nil {
				t.Fatalf("direct UDP succeeded; proxy must forward legal zero-length datagrams; got %v; stats=%+v", err, stats.snapshot())
			}
		})
	}
}

// A hard upstream reset is not a normal half-close. Its peer must be reclaimed.
func TestAuditRegressionTCPResetReleasesSession(t *testing.T) {
	server, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	reset := make(chan struct{})
	go func() {
		c, e := server.AcceptTCP()
		if e == nil {
			time.Sleep(30 * time.Millisecond)
			c.SetLinger(0)
			c.Close()
		}
		close(reset)
	}()
	port := freeTCPPort(t, "tcp4", "127.0.0.1:0")
	rule := config.NormalizeRule(config.Rule{ID: "audit-rst", Name: "audit-rst", Protocol: "tcp", DataPlane: config.RuleDataPlaneGo,
		ListenHost: "127.0.0.1", ListenPort: port, TargetHost: "127.0.0.1", TargetPort: server.Addr().(*net.TCPAddr).Port, Enabled: true, TCPIdleTimeoutSeconds: 300})
	stats := &Stats{}
	r := newRunner(rule, stats, testLogger())
	if err := r.start(); err != nil {
		t.Fatal(err)
	}
	defer r.stop()
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(time.Second))
	_, readErr := c.Read(make([]byte, 1))
	<-reset
	t.Logf("client read after upstream RST: %v", readErr)
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) && stats.activeTCP.Load() != 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if n := stats.activeTCP.Load(); n != 0 {
		t.Fatalf("upstream hard-reset session still reserves %d TCP slots; client write half remains open", n)
	}
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

func BenchmarkAuditUDPSourceBudget(b *testing.B) {
	for _, shared := range []bool{true, false} {
		b.Run(fmt.Sprintf("shared_source_%t", shared), func(b *testing.B) {
			budget := &ruleBudget{}
			var ids atomic.Uint32
			now := time.Now()
			limits := udpSourceLimits{maxSessions: 1000000, newSessionsRate: 1000000000, packetRate: 1000000000, maxTrackedSource: 65536}
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				id := ids.Add(1)
				if shared {
					id = 1
				}
				source := netip.AddrFrom4([4]byte{192, 0, 2, byte(id)})
				for pb.Next() {
					if !budget.reserveUDPPacket(source, false, now, limits) {
						b.Error("unexpected budget exhaustion")
						return
					}
				}
			})
		})
	}
}

func BenchmarkAuditUDPBatchLoopback(b *testing.B) {
	for _, batch := range []int{1, 32, 64} {
		b.Run(fmt.Sprintf("batch_%d_payload_512", batch), func(b *testing.B) {
			recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				b.Fatal(err)
			}
			defer recv.Close()
			recv.SetReadBuffer(4 << 20)
			send, err := net.DialUDP("udp4", nil, recv.LocalAddr().(*net.UDPAddr))
			if err != nil {
				b.Fatal(err)
			}
			defer send.Close()
			send.SetWriteBuffer(4 << 20)
			rx, tx := newUDPBatchConn(recv, false), newUDPBatchConn(send, false)
			messages := make([]ipv4.Message, batch)
			for i := range messages {
				messages[i].Buffers = [][]byte{make([]byte, 512)}
			}
			reads := makeUDPMessages(batch, 512, false)
			b.SetBytes(int64(batch * 512))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sent, err := writeUDPBatch(tx, messages)
				if err != nil || sent != batch {
					b.Fatalf("sent=%d err=%v", sent, err)
				}
				got := 0
				for got < batch {
					n, e := rx.ReadBatch(reads, 0)
					if e != nil {
						b.Fatal(e)
					}
					got += n
				}
			}
		})
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

// Wildcard proxy responses should use the destination IP selected by the client.
func TestAuditRegressionUDPWildcardReplyAddress(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, a, e := target.ReadFromUDP(buf)
			if e != nil {
				return
			}
			target.WriteToUDP(buf[:n], a)
		}
	}()
	port := freeUDPPort(t, "udp4", "0.0.0.0:0")
	rule := config.NormalizeRule(config.Rule{ID: "audit-wildcard", Name: "audit-wildcard", Protocol: "udp", DataPlane: config.RuleDataPlaneGo, ListenHost: "0.0.0.0", ListenPort: port, TargetHost: "127.0.0.1", TargetPort: target.LocalAddr().(*net.UDPAddr).Port, Enabled: true, UDPWorkers: 1})
	r := newRunner(rule, &Stats{}, testLogger())
	if err := r.start(); err != nil {
		t.Fatal(err)
	}
	defer r.stop()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	dst := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port}
	c.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("wildcard-address-check")
	if _, err = c.WriteToUDP(payload, dst); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, reply, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatal("payload mismatch")
	}
	if !reply.IP.Equal(dst.IP) || reply.Port != dst.Port {
		t.Fatalf("sent to %s, reply came from %s; connected UDP clients will reject wrong-source replies", dst, reply)
	}
}
