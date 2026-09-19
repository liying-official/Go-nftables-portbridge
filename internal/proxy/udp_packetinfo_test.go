//go:build linux

package proxy

import (
	"bytes"
	"net"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
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
