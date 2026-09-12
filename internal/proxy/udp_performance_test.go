package proxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/ipv4"

	"portbridge/internal/config"
)

type invalidCountUDPBatch struct {
	readCount  int
	writeCount int
}

func (b invalidCountUDPBatch) ReadBatch([]ipv4.Message, int) (int, error) {
	return b.readCount, nil
}

func (b invalidCountUDPBatch) WriteBatch([]ipv4.Message, int) (int, error) {
	return b.writeCount, nil
}

func TestEffectiveUDPWorkers(t *testing.T) {
	if got := effectiveUDPWorkers(3); got != 3 {
		t.Fatalf("configured workers = %d, want 3", got)
	}
	if got := effectiveUDPWorkers(0); got < 1 || got > maxAutomaticUDPWorkers {
		t.Fatalf("automatic workers = %d", got)
	}
}

func TestUDPBatchRejectsInvalidKernelCounts(t *testing.T) {
	messages := make([]ipv4.Message, 2)
	for _, count := range []int{-1, len(messages) + 1} {
		if _, err := writeUDPBatch(invalidCountUDPBatch{writeCount: count}, messages); !errors.Is(err, errUDPBatchCount) {
			t.Fatalf("write count %d error = %v, want %v", count, err, errUDPBatchCount)
		}
		worker := &udpWorker{inboundBatch: invalidCountUDPBatch{readCount: count}, readMessages: messages}
		if err := worker.readInbound(time.Now()); !errors.Is(err, errUDPBatchCount) {
			t.Fatalf("read count %d error = %v, want %v", count, err, errUDPBatchCount)
		}
	}
}

func TestDistributeUDPWorkersUsesRuleWideBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		budget    int
		endpoints int
		want      []int
	}{
		{name: "single endpoint", budget: 4, endpoints: 1, want: []int{4}},
		{name: "range capped by budget", budget: 4, endpoints: 8, want: []int{1, 1, 1, 1, 1, 1, 1, 1}},
		{name: "balanced remainder", budget: 10, endpoints: 3, want: []int{4, 3, 3}},
		{name: "no UDP endpoint", budget: 4, endpoints: 0, want: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := distributeUDPWorkers(tc.budget, tc.endpoints)
			if len(got) != len(tc.want) {
				t.Fatalf("worker plan = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("worker plan = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestUDPBatchGroupsInterleavedSessions(t *testing.T) {
	w := &udpWorker{
		sessions:       make(map[netip.AddrPort]*udpSession),
		packetNext:     make([]int, 4),
		activeSessions: make([]*udpSession, 0, 4),
	}
	first := &udpSession{}
	second := &udpSession{}
	w.beginPacketBatch()
	w.queuePacket(0, first)
	w.queuePacket(1, second)
	w.queuePacket(2, first)
	w.queuePacket(3, second)
	if len(w.activeSessions) != 2 || w.activeSessions[0] != first || w.activeSessions[1] != second {
		t.Fatalf("active sessions = %v", w.activeSessions)
	}
	assertPacketChain(t, w, first, []int{0, 2})
	assertPacketChain(t, w, second, []int{1, 3})
}

func TestUDPBatchGroupingAllocations(t *testing.T) {
	w := &udpWorker{
		sessions:       make(map[netip.AddrPort]*udpSession),
		packetNext:     make([]int, 64),
		activeSessions: make([]*udpSession, 0, 64),
	}
	sessions := []*udpSession{{}, {}, {}, {}}
	allocations := testing.AllocsPerRun(1000, func() {
		w.beginPacketBatch()
		for i := range w.packetNext {
			w.queuePacket(i, sessions[i%len(sessions)])
		}
	})
	if allocations != 0 {
		t.Fatalf("batch grouping allocations = %f, want 0", allocations)
	}
}

func assertPacketChain(t *testing.T, w *udpWorker, session *udpSession, want []int) {
	t.Helper()
	got := make([]int, 0, len(want))
	for i := session.batchHead; i >= 0; i = w.packetNext[i] {
		got = append(got, i)
	}
	if len(got) != len(want) {
		t.Fatalf("packet chain = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("packet chain = %v, want %v", got, want)
		}
	}
}

func TestUDPBatchReusesAddress(t *testing.T) {
	listener, err := listenUDPWorker(context.Background(), "udp4", "127.0.0.1:0", false, 1024*1024)
	if err != nil {
		t.Skipf("network unavailable: %v", err)
	}
	defer listener.Close()
	client, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	messages := makeUDPMessages(2, 2048, false)
	address := messages[0].Addr
	batch := newUDPBatchConn(listener, false)
	for i := 0; i < 2; i++ {
		if _, err := client.Write([]byte("address-reuse")); err != nil {
			t.Fatal(err)
		}
		_ = listener.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := batch.ReadBatch(messages, 0)
		if err != nil {
			t.Fatal(err)
		}
		if n < 1 {
			t.Fatal("batch read returned no messages")
		}
		if messages[0].Addr != address {
			t.Fatal("batch read replaced the preallocated UDP address")
		}
	}
}

func TestUDPAddrPortFlowLookupAllocations(t *testing.T) {
	address := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10).To4(), Port: 12345}
	flows := map[netip.AddrPort]int{address.AddrPort(): 1}
	allocations := testing.AllocsPerRun(1000, func() {
		if flows[address.AddrPort()] != 1 {
			panic("missing flow")
		}
	})
	if allocations != 0 {
		t.Fatalf("flow lookup allocations = %f, want 0", allocations)
	}
}

func TestUDPTimeWheelDefersActiveSession(t *testing.T) {
	w := &udpWorker{idleSeconds: 60, wheel: make([]*udpSession, udpWheelSlots)}
	now := time.Unix(1_700_000_000, 0)
	session := &udpSession{wheelSlot: -1}
	w.touchSession(session, now)
	originalSlot := session.wheelSlot
	session.expiresAt += 30
	w.expireWheelSlot(now.Unix() + 60)
	if session.wheelSlot < 0 || session.wheelSlot == originalSlot {
		t.Fatalf("active session was not rescheduled: old=%d new=%d", originalSlot, session.wheelSlot)
	}
	if session.closed {
		t.Fatal("active session was expired")
	}
}

func TestUDPReusePortWorkersAndPayloadSizes(t *testing.T) {
	host, targetPort, closeEcho := startUDPEcho(t, "udp4", "127.0.0.1:0")
	defer closeEcho()
	proxyPort := freeUDPPort(t, "udp4", "127.0.0.1:0")
	rule := config.NormalizeRule(config.Rule{
		ID: "udp-performance", Name: "udp-performance", Protocol: config.ProtocolUDP,
		DataPlane: config.RuleDataPlaneGo, ListenHost: "127.0.0.1", ListenPort: proxyPort,
		TargetHost: host, TargetPort: targetPort, Enabled: true,
		UDPWorkers: 2, UDPBatchSize: 64, UDPPacketBufferSize: 2048,
	})
	r := newRunner(rule, &Stats{}, testLogger())
	if err := r.start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer r.stop()

	remote, err := net.ResolveUDPAddr("udp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{64, 256, 512, 1400} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			client, err := net.DialUDP("udp4", nil, remote)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			payload := bytes.Repeat([]byte{byte(size)}, size)
			_ = client.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := client.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, size)
			n, err := client.Read(got)
			if err != nil {
				t.Fatal(err)
			}
			if n != size || !bytes.Equal(got[:n], payload) {
				t.Fatalf("payload mismatch: got=%d want=%d", n, size)
			}
		})
	}
}

func TestUDPDropsOversizedDatagram(t *testing.T) {
	host, targetPort, closeEcho := startUDPEcho(t, "udp4", "127.0.0.1:0")
	defer closeEcho()
	proxyPort := freeUDPPort(t, "udp4", "127.0.0.1:0")
	stats := &Stats{}
	rule := config.NormalizeRule(config.Rule{
		ID: "udp-truncation", Name: "udp-truncation", Protocol: config.ProtocolUDP,
		DataPlane: config.RuleDataPlaneGo, ListenHost: "127.0.0.1", ListenPort: proxyPort,
		TargetHost: host, TargetPort: targetPort, Enabled: true,
		UDPWorkers: 1, UDPBatchSize: 32, UDPPacketBufferSize: 512,
	})
	r := newRunner(rule, stats, testLogger())
	if err := r.start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer r.stop()

	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort}
	client, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := client.Write(make([]byte, 1400)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1400)); err == nil {
		t.Fatal("oversized datagram was unexpectedly forwarded")
	}
	time.Sleep(udpMaintenanceInterval + 50*time.Millisecond)
	if drops := stats.snapshot().UDPDrops; drops != 1 {
		t.Fatalf("UDP drops = %d, want 1", drops)
	}
}

func TestUDPGlobalSessionLimitAcrossWorkers(t *testing.T) {
	host, targetPort, closeEcho := startUDPEcho(t, "udp4", "127.0.0.1:0")
	defer closeEcho()
	proxyPort := freeUDPPort(t, "udp4", "127.0.0.1:0")
	stats := &Stats{}
	rule := config.NormalizeRule(config.Rule{
		ID: "udp-limit", Name: "udp-limit", Protocol: config.ProtocolUDP,
		DataPlane: config.RuleDataPlaneGo, ListenHost: "127.0.0.1", ListenPort: proxyPort,
		TargetHost: host, TargetPort: targetPort, Enabled: true,
		UDPWorkers: 2, MaxUDPSessions: 1,
	})
	r := newRunner(rule, stats, testLogger())
	if err := r.start(); err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer r.stop()

	remote := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: proxyPort}
	first, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	_ = first.SetDeadline(time.Now().Add(time.Second))
	if _, err := first.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	firstReply := make([]byte, 16)
	if _, err := first.Read(firstReply); err != nil {
		t.Fatalf("first session: %v", err)
	}

	second, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := second.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Read(make([]byte, 16)); err == nil {
		t.Fatal("second session exceeded the global limit")
	}
	time.Sleep(udpMaintenanceInterval + 50*time.Millisecond)
	snapshot := stats.snapshot()
	if snapshot.ActiveUDPSessions != 1 || snapshot.TotalUDPSessions != 1 || snapshot.UDPDrops != 1 {
		t.Fatalf("unexpected UDP stats: active=%d total=%d drops=%d", snapshot.ActiveUDPSessions, snapshot.TotalUDPSessions, snapshot.UDPDrops)
	}
}
