//go:build linux

package proxy

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

var errUDPPacketInfo = errors.New("missing, truncated or invalid UDP packet information")

// The interface is part of a scoped address, not an unconditional reply route.
type udpLocalEndpoint struct {
	address netip.Addr
	ifIndex uint32
}

type udpFlowKey struct {
	client netip.AddrPort
	local  udpLocalEndpoint
}

const (
	udpLocalSessionMetadataReserve = 64
	udpWildcardSessionReserve      = 192
	// Conservatively allow four times the 32-byte larger key per preallocated
	// slot (load-factor slack and map growth). Defaults are not increased.
	udpWildcardMapSlotReserve = 128
)

func udpInitialSessionCapacity(maximum, workers int) int {
	capacity := (maximum + workers - 1) / workers
	if capacity < 1 {
		return 1
	}
	if capacity > 65536 {
		return 65536
	}
	return capacity
}

func udpPacketInfoSpace(ipv6Socket bool) int {
	if ipv6Socket {
		return unix.CmsgSpace(unix.SizeofInet6Pktinfo)
	}
	return unix.CmsgSpace(unix.SizeofInet4Pktinfo)
}

func udpWildcardMemory(ruleSessions, workers, batch int, ipv6Socket bool) int64 {
	return int64(udpInitialSessionCapacity(ruleSessions, workers))*udpWildcardMapSlotReserve +
		int64(batch*udpPacketInfoSpace(ipv6Socket))
}

func enableUDPPacketInfo(batch udpBatchConn, ipv6Socket bool) error {
	if ipv6Socket {
		return batch.(*ipv6.PacketConn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	}
	return batch.(*ipv4.PacketConn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
}

func addUDPPacketInfoBuffers(messages []ipv4.Message, ipv6Socket bool) {
	size := udpPacketInfoSpace(ipv6Socket)
	slab := make([]byte, len(messages)*size)
	for i := range messages {
		messages[i].OOB = slab[i*size : (i+1)*size]
	}
}

// ParseOne avoids the per-packet slice allocation of ControlMessage.Parse.
// Validate the header's minimum size before entering the vendored Unix parser.
func parseUDPLocalEndpoint(message *ipv4.Message, ipv6Socket bool) (udpLocalEndpoint, error) {
	var local udpLocalEndpoint
	if message.Flags&unix.MSG_CTRUNC != 0 || message.NN <= 0 || message.NN > len(message.OOB) {
		return local, errUDPPacketInfo
	}
	data := message.OOB[:message.NN]
	found := false
	for len(data) > 0 {
		if len(data) < unix.CmsgLen(0) {
			return udpLocalEndpoint{}, errUDPPacketInfo
		}
		header, value, rest, err := unix.ParseOneSocketControlMessage(data)
		if err != nil {
			return udpLocalEndpoint{}, errUDPPacketInfo
		}
		data = rest
		switch {
		case header.Level == unix.SOL_IP && header.Type == unix.IP_PKTINFO:
			if ipv6Socket || found || len(value) != unix.SizeofInet4Pktinfo {
				return udpLocalEndpoint{}, errUDPPacketInfo
			}
			var address [4]byte
			copy(address[:], value[8:12]) // ipi_addr, the packet's destination.
			local.address = netip.AddrFrom4(address)
			local.ifIndex = binary.NativeEndian.Uint32(value[:4])
			found = true
		case header.Level == unix.SOL_IPV6 && header.Type == unix.IPV6_PKTINFO:
			if !ipv6Socket || found || len(value) != unix.SizeofInet6Pktinfo {
				return udpLocalEndpoint{}, errUDPPacketInfo
			}
			var address [16]byte
			copy(address[:], value[:16])
			local.address = netip.AddrFrom16(address)
			local.ifIndex = binary.NativeEndian.Uint32(value[16:20])
			found = true
		}
	}
	if !found || local.ifIndex == 0 || local.ifIndex > 1<<31-1 ||
		!local.address.IsValid() || local.address.IsUnspecified() || local.address.IsMulticast() ||
		local.address.Is4In6() || local.address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return udpLocalEndpoint{}, errUDPPacketInfo
	}
	return local, nil
}

func (local udpLocalEndpoint) forClient(client netip.AddrPort) udpLocalEndpoint {
	if !local.address.IsLinkLocalUnicast() && !client.Addr().IsLinkLocalUnicast() {
		// Preserve the exact source address without pinning global-address
		// replies to ingress; routing may legitimately be asymmetric.
		local.ifIndex = 0
	}
	return local
}

func udpReplyPacketInfo(local udpLocalEndpoint, ipv6Socket bool) []byte {
	if ipv6Socket {
		return unix.PktInfo6(&unix.Inet6Pktinfo{Addr: local.address.As16(), Ifindex: local.ifIndex})
	}
	return unix.PktInfo4(&unix.Inet4Pktinfo{
		Spec_dst: local.address.As4(),
		Ifindex:  int32(local.ifIndex), // #nosec G115 -- parseUDPLocalEndpoint bounds the interface index.
	})
}

// Reset every reused field, including fields potentially filled by an injected
// batch implementation. Upstream writes always pass nil ancillary information.
func prepareUDPSend(message *ipv4.Message, payload []byte, address net.Addr, oob []byte) {
	buffers := message.Buffers
	buffers[0] = payload
	*message = ipv4.Message{Buffers: buffers, Addr: address, OOB: oob}
}
