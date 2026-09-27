//go:build linux

package proxy

import (
	"bytes"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"portbridge/internal/config"
)

func receivedPacketInfo(address netip.Addr, index uint32) []byte {
	if address.Is4() {
		return unix.PktInfo4(&unix.Inet4Pktinfo{Ifindex: int32(index), Addr: address.As4(), Spec_dst: address.As4()})
	}
	return unix.PktInfo6(&unix.Inet6Pktinfo{Ifindex: index, Addr: address.As16()})
}

func TestUDPPacketInfoValidationAndOwnership(t *testing.T) {
	for _, address := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")} {
		t.Run(address.String(), func(t *testing.T) {
			oob := receivedPacketInfo(address, 7)
			message := ipv4.Message{OOB: oob, NN: len(oob)}
			local, err := parseUDPLocalEndpoint(&message, address.Is6())
			if err != nil || local.address != address || local.ifIndex != 7 {
				t.Fatalf("local endpoint=%+v err=%v", local, err)
			}
			reply := udpReplyPacketInfo(local.forClient(netip.MustParseAddrPort("[2001:db8::2]:1234")), address.Is6())
			before := append([]byte(nil), reply...)
			clear(oob)
			if local.address != address || !bytes.Equal(before, reply) {
				t.Fatal("session metadata aliases the reused receive control buffer")
			}
			valid := receivedPacketInfo(address, 7)
			cases := map[string]ipv4.Message{
				"missing": {}, "negative NN": {OOB: valid, NN: -1},
				"NN exceeds buffer": {OOB: valid, NN: len(valid) + 1},
				"CTRUNC":            {OOB: valid, NN: len(valid), Flags: unix.MSG_CTRUNC},
				"short header":      {OOB: valid[:unix.CmsgLen(0)-1], NN: unix.CmsgLen(0) - 1},
				"short payload":     {OOB: valid[:unix.CmsgLen(0)], NN: unix.CmsgLen(0)},
				"zero header":       {OOB: make([]byte, len(valid)), NN: len(valid)},
			}
			duplicate := append(append([]byte(nil), valid...), valid...)
			cases["duplicate"] = ipv4.Message{OOB: duplicate, NN: len(duplicate)}
			trailing := append(append([]byte(nil), valid...), 1)
			cases["trailing garbage"] = ipv4.Message{OOB: trailing, NN: len(trailing)}
			for name, m := range cases {
				t.Run(name, func(t *testing.T) {
					if _, err := parseUDPLocalEndpoint(&m, address.Is6()); err == nil {
						t.Fatal("invalid/missing destination information was accepted")
					}
				})
			}
			message = ipv4.Message{OOB: valid, NN: len(valid)}
			if _, err := parseUDPLocalEndpoint(&message, !address.Is6()); err == nil {
				t.Fatal("opposite-family packet information was accepted")
			}
		})
	}
}

func TestUDPReplyControlScopeAndRouting(t *testing.T) {
	client := netip.MustParseAddrPort("192.0.2.2:1234")
	for _, address := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")} {
		local := (udpLocalEndpoint{address: address, ifIndex: 7}).forClient(client)
		if local.ifIndex != 0 {
			t.Fatal("global destination pinned replies to ingress instead of routing")
		}
	}
	scoped := udpLocalEndpoint{address: netip.MustParseAddr("fe80::1"), ifIndex: 7}
	if scoped.forClient(netip.MustParseAddrPort("[fe80::2%test0]:1234")).ifIndex != 7 {
		t.Fatal("link-local interface identity lost")
	}
	first := udpFlowKey{client: netip.MustParseAddrPort("[fe80::2%test0]:1234"), local: scoped}
	second := first
	second.local.ifIndex++
	if first == second {
		t.Fatal("different scoped interfaces share a session key")
	}
}

func TestUDPLocalFlowLookupAllocations(t *testing.T) {
	client := netip.MustParseAddrPort("192.0.2.2:1234")
	oob := receivedPacketInfo(netip.MustParseAddr("192.0.2.1"), 7)
	message := ipv4.Message{OOB: oob, NN: len(oob)}
	local, err := parseUDPLocalEndpoint(&message, false)
	if err != nil {
		t.Fatal(err)
	}
	key := udpFlowKey{client: client, local: local.forClient(client)}
	flows := map[udpFlowKey]int{key: 1}
	if allocations := testing.AllocsPerRun(1000, func() {
		local, err := parseUDPLocalEndpoint(&message, false)
		if err != nil || flows[udpFlowKey{client: client, local: local.forClient(client)}] != 1 {
			panic("invalid local flow")
		}
	}); allocations != 0 {
		t.Fatalf("packet-info parsing and wildcard lookup allocations=%f, want 0", allocations)
	}
}

func TestUDPSendControlIsolation(t *testing.T) {
	message := makeUDPSendMessages(1)[0]
	client := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 1234}
	oob := receivedPacketInfo(netip.MustParseAddr("192.0.2.1"), 7)
	message.N, message.NN, message.Flags = 91, 92, 93
	prepareUDPSend(&message, []byte("down"), client, oob)
	if message.N != 0 || message.NN != 0 || message.Flags != 0 || message.Addr != client || len(message.OOB) == 0 {
		t.Fatal("downstream message retained stale fields")
	}
	prepareUDPSend(&message, nil, nil, nil) // legal empty upstream datagram
	if len(message.Buffers) != 1 || len(message.Buffers[0]) != 0 || message.Addr != nil || message.OOB != nil || message.NN != 0 || message.Flags != 0 {
		t.Fatal("upstream message retained downstream address/control")
	}
}

func TestUDPPacketInfoMemoryReservation(t *testing.T) {
	metadata := unsafe.Sizeof(udpLocalEndpoint{}) + unsafe.Sizeof([]byte(nil))
	if metadata > udpLocalSessionMetadataReserve {
		t.Fatalf("local session metadata=%d exceeds reservation", metadata)
	}
	delta := unsafe.Sizeof(udpFlowKey{}) - unsafe.Sizeof(netip.AddrPort{})
	if delta*4 > udpWildcardMapSlotReserve {
		t.Fatalf("wildcard map key growth=%d exceeds slot reservation", delta)
	}
	if int(delta*4)+udpPacketInfoSpace(true) > udpWildcardSessionReserve {
		t.Fatal("wildcard session control/map allowance is insufficient")
	}
	if got := udpWildcardMemory(64, 4, 32, true); got != 16*udpWildcardMapSlotReserve+32*int64(udpPacketInfoSpace(true)) {
		t.Fatalf("worker packet-info memory reservation=%d", got)
	}
}

type repairBatchFixture struct {
	incoming  []ipv4.Message
	payloads  [][]byte
	controls  [][]byte
	addresses []net.Addr
}

func (f *repairBatchFixture) ReadBatch(messages []ipv4.Message, _ int) (int, error) {
	if len(f.incoming) > len(messages) {
		return len(f.incoming), nil
	}
	n := copy(messages, f.incoming)
	f.incoming = nil
	return n, nil
}
func (f *repairBatchFixture) WriteBatch(messages []ipv4.Message, _ int) (int, error) {
	for _, m := range messages {
		f.payloads = append(f.payloads, append([]byte(nil), m.Buffers[0]...))
		f.controls = append(f.controls, append([]byte(nil), m.OOB...))
		f.addresses = append(f.addresses, m.Addr)
	}
	return len(messages), nil
}
func repairManualWorker(t *testing.T) *udpWorker {
	t.Helper()
	inbound, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	rule := config.NormalizeRule(config.Rule{ID: "manual-udp", Protocol: config.ProtocolUDP, ListenHost: "0.0.0.0", ListenPort: inbound.LocalAddr().(*net.UDPAddr).Port, TargetHost: "127.0.0.1", TargetPort: target.LocalAddr().(*net.UDPAddr).Port, MaxUDPSessions: 32, UDPBatchSize: 8, UDPIdleTimeoutSeconds: 1})
	runner := newRunner(rule, &Stats{}, testLogger())
	w, err := newUDPWorker(runner, inbound, false, target.LocalAddr().(*net.UDPAddr), rule, 1)
	if err != nil {
		_ = inbound.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { w.cleanup(); runner.cancel() })
	return w
}
func repairManualSession(t *testing.T, w *udpWorker, client netip.AddrPort, local udpLocalEndpoint, now time.Time) *udpSession {
	t.Helper()
	if !w.runner.budget.reserveUDPPacket(client.Addr(), true, now, w.sourceLimits) {
		t.Fatal("fixture source reservation failed")
	}
	session, err := w.newSession(client, local, now)
	if err != nil {
		w.runner.budget.rollbackUDPSourceSession(client.Addr(), w.sourceLimits.newSessionsRate)
		t.Fatal(err)
	}
	return session
}
func TestUDPInvalidPacketInfoRejectedBeforeReservation(t *testing.T) {
	for _, six := range []bool{false, true} {
		for _, kind := range []string{"missing", "ctrunc", "length", "duplicate", "wrong-family", "unspecified"} {
			t.Run(kind+map[bool]string{true: "-v6", false: "-v4"}[six], func(t *testing.T) {
				address := netip.MustParseAddr("192.0.2.1")
				client := netip.MustParseAddrPort("192.0.2.2:45000")
				if six {
					address = netip.MustParseAddr("2001:db8::1")
					client = netip.MustParseAddrPort("[2001:db8::2]:45000")
				}
				control := receivedPacketInfo(address, 3)
				message := ipv4.Message{Buffers: [][]byte{nil}, Addr: net.UDPAddrFromAddrPort(client), OOB: control, NN: len(control)}
				switch kind {
				case "missing":
					message.NN = 0
				case "ctrunc":
					message.Flags = unix.MSG_CTRUNC
				case "length":
					message.NN++
				case "duplicate":
					message.OOB = append(message.OOB, control...)
					message.NN = len(message.OOB)
				case "wrong-family":
					other := netip.IPv6Loopback()
					if six {
						other = netip.MustParseAddr("127.0.0.1")
					}
					message.OOB = receivedPacketInfo(other, 3)
					message.NN = len(message.OOB)
				case "unspecified":
					other := netip.IPv4Unspecified()
					if six {
						other = netip.IPv6Unspecified()
					}
					message.OOB = receivedPacketInfo(other, 3)
					message.NN = len(message.OOB)
				}
				r := newRunner(config.NormalizeRule(config.Rule{}), &Stats{}, testLogger())
				defer r.cancel()
				w := &udpWorker{runner: r, packetInfo: true, inboundIPv6: six, inboundBatch: &repairBatchFixture{incoming: []ipv4.Message{message}}, readMessages: makeUDPMessages(1, 64, six)}
				if err := w.readInbound(time.Now()); err != nil {
					t.Fatal(err)
				}
				if w.drops != 1 || r.resources.activeUDP.Load() != 0 || r.resources.udpMemory.Load() != 0 || r.stats.totalUDP.Load() != 0 {
					t.Fatal("invalid control data reached session reservation")
				}
				for i := range r.budget.udpSources {
					if len(r.budget.udpSources[i].states) != 0 {
						t.Fatal("invalid OOB consumed a source token/state")
					}
				}
			})
		}
	}
}
func TestUDPMixedEmptyBatchAndControlOwnership(t *testing.T) {
	w := repairManualWorker(t)
	now := time.Now()
	client := netip.MustParseAddrPort("127.0.0.1:45000")
	first := udpLocalEndpoint{address: netip.MustParseAddr("127.0.0.1")}
	second := udpLocalEndpoint{address: netip.MustParseAddr("127.0.0.2")}
	a := repairManualSession(t, w, client, first, now)
	b := repairManualSession(t, w, client, second, now)
	upstreamA, upstreamB := &repairBatchFixture{}, &repairBatchFixture{}
	a.batch, b.batch = upstreamA, upstreamB
	incoming := make([]ipv4.Message, 4)
	for i := range incoming {
		local := first
		if i%2 == 1 {
			local = second
		}
		payload := []byte(nil)
		if i >= 2 {
			payload = []byte{byte('A' + i%2)}
		}
		oob := receivedPacketInfo(local.address, 1)
		incoming[i] = ipv4.Message{Buffers: [][]byte{payload}, N: len(payload), Addr: net.UDPAddrFromAddrPort(client), OOB: oob, NN: len(oob)}
	}
	inbound := &repairBatchFixture{incoming: incoming}
	w.inboundBatch = inbound
	if err := w.readInbound(now); err != nil {
		t.Fatal(err)
	}
	for i, upstream := range []*repairBatchFixture{upstreamA, upstreamB} {
		if len(upstream.payloads) != 2 || len(upstream.payloads[0]) != 0 || !bytes.Equal(upstream.payloads[1], []byte{byte('A' + i)}) {
			t.Fatal("mixed empty batch dropped or reordered")
		}
		for j := range upstream.controls {
			if len(upstream.controls[j]) != 0 || upstream.addresses[j] != nil {
				t.Fatal("inbound pktinfo/address leaked upstream")
			}
		}
	}
	for _, s := range []*udpSession{a, b} {
		f := s.batch.(*repairBatchFixture)
		f.incoming = []ipv4.Message{{Buffers: [][]byte{nil}}, {Buffers: [][]byte{[]byte("r")}, N: 1}}
		if err := w.readResponses(s, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(inbound.payloads) != 4 || w.packetsUp != 4 || w.packetsDown != 4 || w.bytesUp != 2 || w.bytesDown != 2 || w.drops != 0 {
		t.Fatal("mixed empty packet accounting is incorrect")
	}
	for i, control := range inbound.controls {
		session := a
		if i >= 2 {
			session = b
		}
		if !bytes.Equal(control, session.replyOOB) || inbound.addresses[i] != session.clientAddr {
			t.Fatal("reply metadata crossed local sessions")
		}
	}
	for _, m := range w.sendMessages {
		if m.OOB != nil || m.Addr != nil || m.NN != 0 {
			t.Fatal("send metadata not reset")
		}
	}
}
func TestUDPWildcardExpirationFDReuseAndReservations(t *testing.T) {
	w := repairManualWorker(t)
	fdSnapshot := func() map[string]string {
		files, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, f := range files {
			target, err := os.Readlink("/proc/self/fd/" + f.Name())
			if err == nil {
				out[f.Name()] = target
			}
		}
		return out
	}
	fds := func() int {
		files, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(files)
	}
	baselineFD, baselineG := fds(), runtime.NumGoroutine()
	beforeFDs := fdSnapshot()
	previous := make(map[int]bool)
	reused := false
	now := time.Now()
	client := netip.MustParseAddrPort("127.0.0.1:45001")
	for i := 0; i < 12; i++ {
		local := udpLocalEndpoint{address: netip.AddrFrom4([4]byte{127, 0, 0, byte(1 + i%2)})}
		s := repairManualSession(t, w, client, local, now)
		if previous[s.fd] {
			reused = true
		}
		previous[s.fd] = true
		ownedSocket, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(s.fd))
		if err != nil || !strings.HasPrefix(ownedSocket, "socket:[") {
			t.Fatalf("fixture socket identity unavailable: %v", err)
		}
		w.maintain(now.Add(2 * time.Second))
		if !s.closed || len(w.localSessions) != 0 || len(w.sessionsByFD) != 0 {
			t.Fatal("expired local key or fd entry retained")
		}
		w.closeSession(s) // idempotence must not release twice.
		if w.runner.stats.activeUDP.Load() != 0 || w.runner.resources.activeUDP.Load() != 0 || w.runner.resources.udpMemory.Load() != 0 || udpActiveSessionsForTest(w.runner.budget, client.Addr()) != 0 {
			t.Fatal("expiration retained/overreleased reservations")
		}
		// Check the exact socket identity, not just a reused FD number. A
		// decrease in GLOBAL FD count is not a leak: Go's splice-pipe pool can
		// asynchronously close unrelated pipes during garbage collection.
		currentFDs := fdSnapshot()
		for fd, identity := range currentFDs {
			if identity == ownedSocket {
				t.Fatalf("expired UDP socket still open on descriptor %s: %s", fd, identity)
			}
		}
		if after := fds(); after > baselineFD {
			t.Fatalf("descriptor growth after UDP expiry: before=%d after=%d baseline=%v current=%v", baselineFD, after, beforeFDs, currentFDs)
		}
		now = now.Add(3 * time.Second)
	}
	if !reused {
		t.Fatal("fixture did not actually reuse a descriptor")
	}
	if runtime.NumGoroutine() > baselineG {
		t.Fatal("manual session churn spawned a goroutine")
	}
	t.Logf("12 expiration/reuse cycles: FDs start=%d end=%d goroutines=%d; exact UDP sockets closed and session/source/memory reservations zero", baselineFD, fds(), baselineG)
}
