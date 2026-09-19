//go:build linux

package proxy

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"portbridge/internal/config"
)

type udpRepairSeen struct {
	payload string
	peer    netip.AddrPort
}

func startUDPRepair(t *testing.T, listen, targetHost string, workers, sourceLimit, packetRate int, emptyReply bool) (*runner, int, <-chan udpRepairSeen) {
	t.Helper()
	targetIP := netip.MustParseAddr(targetHost)
	network := "udp4"
	if targetIP.Is6() {
		network = "udp6"
	}
	target, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(targetIP, 0)))
	if err != nil {
		testListenFailure(t, network, net.JoinHostPort(targetHost, "0"), err)
	}
	seen := make(chan udpRepairSeen, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 2048)
		for {
			n, peer, err := target.ReadFromUDPAddrPort(buffer)
			if err != nil {
				return
			}
			select {
			case seen <- udpRepairSeen{payload: string(buffer[:n]), peer: peer}:
			default:
			}
			reply := buffer[:n]
			if emptyReply {
				reply = nil
			}
			_, _ = target.WriteToUDPAddrPort(reply, peer)
		}
	}()
	t.Cleanup(func() { _ = target.Close(); <-done })
	network = "udp4"
	if strings.Contains(listen, ":") {
		network = "udp6"
	}
	port := freeUDPPort(t, network, net.JoinHostPort(listen, "0"))
	rule := config.NormalizeRule(config.Rule{
		ID: "udp-repair", Protocol: config.ProtocolUDP, DataPlane: config.RuleDataPlaneGo,
		ListenHost: listen, ListenPort: port, TargetHost: targetHost,
		TargetPort: target.LocalAddr().(*net.UDPAddr).Port, Enabled: true,
		UDPWorkers: workers, MaxUDPSessions: 64, MaxUDPSessionsPerIP: sourceLimit,
		UDPPacketsPerSec: packetRate, UDPNewSessionsPerSec: 1000,
		UDPListenerBufferBytes: 64 << 10, UDPSessionBufferBytes: 16 << 10,
		AllowPrivateTarget: true, TargetCIDRAllowlist: []string{targetHost + "/" + strconv.Itoa(targetIP.BitLen())},
	})
	r := newRunner(rule, &Stats{}, testLogger())
	if err := r.start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.stop)
	return r, port, seen
}

func assertUDPRepairReleased(t *testing.T, r *runner) {
	t.Helper()
	r.stop()
	if r.stats.activeUDP.Load() != 0 || r.resources.activeUDP.Load() != 0 || r.resources.udpMemory.Load() != 0 {
		t.Fatalf("UDP reservations remain: sessions=%d global=%d bytes=%d",
			r.stats.activeUDP.Load(), r.resources.activeUDP.Load(), r.resources.udpMemory.Load())
	}
	for i := range r.budget.udpSources {
		shard := &r.budget.udpSources[i]
		shard.mu.Lock()
		for _, state := range shard.states {
			if state.activeSessions != 0 {
				t.Errorf("source session reservation remains: %d", state.activeSessions)
			}
		}
		shard.mu.Unlock()
	}
}

func TestUDPEmptyDatagramsAndCounters(t *testing.T) {
	for _, listen := range []string{"127.0.0.1", "0.0.0.0"} {
		for _, emptyReply := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/empty-reply-%t", listen, emptyReply), func(t *testing.T) {
				r, port, _ := startUDPRepair(t, listen, "127.0.0.1", 1, 64, 100000, emptyReply)
				host := "127.0.0.1"
				if listen == "0.0.0.0" {
					host = "127.0.0.2"
				}
				c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: port})
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				var up, down uint64
				// Mix empty and nonempty datagrams in the same established flow.
				for _, payload := range [][]byte{nil, []byte("data"), {}, []byte("tail")} {
					_ = c.SetDeadline(time.Now().Add(time.Second))
					if _, err := c.Write(payload); err != nil {
						t.Fatal(err)
					}
					got := make([]byte, 32)
					n, err := c.Read(got)
					want := payload
					if emptyReply {
						want = nil
					}
					if err != nil || !bytes.Equal(got[:n], want) {
						t.Fatalf("zero/mixed datagram reply: n=%d err=%v", n, err)
					}
					up += uint64(len(payload))
					down += uint64(len(want))
				}
				_ = c.Close()
				assertUDPRepairReleased(t, r)
				s := r.stats.snapshot()
				if s.UDPPacketsUp != 4 || s.UDPPacketsDown != 4 || s.BytesUp != up || s.BytesDown != down || s.UDPDrops != 0 || s.TotalUDPSessions != 1 {
					t.Fatalf("empty datagrams not counted exactly: %+v", s)
				}
			})
		}
	}
}

func TestUDPEmptyDatagramConsumesPacketBudget(t *testing.T) {
	r, port, _ := startUDPRepair(t, "0.0.0.0", "127.0.0.1", 1, 64, 1, false)
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write(nil); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(make([]byte, 1)); err != nil || n != 0 {
		t.Fatalf("first empty datagram: n=%d err=%v", n, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, _ = c.Write(nil)
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("empty datagram bypassed packet token budget")
	}
	_ = c.Close()
	assertUDPRepairReleased(t, r)
	s := r.stats.snapshot()
	if s.UDPPacketsUp != 1 || s.UDPPacketsDown != 1 || s.UDPDrops != 1 || s.BytesUp != 0 || s.BytesDown != 0 {
		t.Fatalf("empty packet budget accounting: %+v", s)
	}
}

func TestUDPWildcardLocalAddressIsolation(t *testing.T) {
	for _, workers := range []int{1, 4} {
		for _, ingress6 := range []bool{false, true} {
			for _, target6 := range []bool{false, true} {
				t.Run(fmt.Sprintf("workers-%d/v6-%t-to-%t", workers, ingress6, target6), func(t *testing.T) {
					listen, network, source, first, second := "0.0.0.0", "udp4", "127.0.0.1", "127.0.0.1", "127.0.0.2"
					if ingress6 {
						if os.Getenv("PB_V245_IPV6_MULTI") != "1" {
							t.Skip("multiple IPv6 addresses require the isolated repair test driver")
						}
						listen, network, source, first, second = "::", "udp6", "::1", "2001:db8:55::1", "2001:db8:55::2"
					}
					target := "127.0.0.1"
					if target6 {
						target = "::1"
					}
					r, port, seen := startUDPRepair(t, listen, target, workers, 64, 100000, false)
					client, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(source)})
					if err != nil {
						t.Fatal(err)
					}
					defer client.Close()
					_ = client.SetDeadline(time.Now().Add(2 * time.Second))
					destinations := []string{first, second}
					for i := 0; i < 8; i++ {
						_, err := client.WriteToUDP([]byte(fmt.Sprintf("%d-%d", i%2, i)), &net.UDPAddr{IP: net.ParseIP(destinations[i%2]), Port: port})
						if err != nil {
							t.Fatal(err)
						}
					}
					targetPeers := make(map[byte]netip.AddrPort)
					for i := 0; i < 8; i++ {
						buf := make([]byte, 32)
						n, peer, err := client.ReadFromUDP(buf)
						if err != nil || n < 3 {
							t.Fatalf("interleaved reply: n=%d err=%v", n, err)
						}
						group := int(buf[0] - '0')
						if group < 0 || group > 1 || !peer.IP.Equal(net.ParseIP(destinations[group])) || peer.Port != port {
							t.Fatalf("wrong local reply address: payload=%q peer=%v", buf[:n], peer)
						}
						select {
						case received := <-seen:
							label := received.payload[0]
							if previous, ok := targetPeers[label]; ok && previous != received.peer {
								t.Fatalf("one local destination changed upstream session: %v != %v", previous, received.peer)
							}
							targetPeers[label] = received.peer
						case <-time.After(time.Second):
							t.Fatal("missing target observation")
						}
					}
					if len(targetPeers) != 2 || targetPeers['0'] == targetPeers['1'] {
						t.Fatal("same client port and different local addresses share an upstream session")
					}
					// Connected clients reject a reply from any other local IP.
					for _, destination := range destinations {
						c, err := net.DialUDP(network, nil, &net.UDPAddr{IP: net.ParseIP(destination), Port: port})
						if err != nil {
							t.Fatal(err)
						}
						_ = c.SetDeadline(time.Now().Add(time.Second))
						_, err = c.Write(nil)
						if err == nil {
							var n int
							n, err = c.Read(make([]byte, 1))
							if n != 0 {
								t.Error("empty reply gained payload")
							}
						}
						_ = c.Close()
						if err != nil {
							t.Fatalf("connected wildcard client: %v", err)
						}
					}
					_ = client.Close()
					assertUDPRepairReleased(t, r)
				})
			}
		}
	}
}

func TestUDPWildcardDestinationsShareSourceLimit(t *testing.T) {
	for _, workers := range []int{1, 4} {
		t.Run(strconv.Itoa(workers), func(t *testing.T) {
			r, port, _ := startUDPRepair(t, "0.0.0.0", "127.0.0.1", workers, 1, 100000, false)
			c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			first := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
			second := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: port}
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_, _ = c.WriteToUDP(nil, first)
			if n, _, err := c.ReadFromUDP(make([]byte, 1)); err != nil || n != 0 {
				t.Fatalf("first source session: %v", err)
			}
			_ = c.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
			_, _ = c.WriteToUDP(nil, second)
			if _, _, err := c.ReadFromUDP(make([]byte, 1)); err == nil {
				t.Fatal("different local address bypassed the shared source-IP session limit")
			}
			_ = c.Close()
			assertUDPRepairReleased(t, r)
			if s := r.stats.snapshot(); s.TotalUDPSessions != 1 || s.UDPDrops != 1 {
				t.Fatalf("wrong shared source budget: %+v", s)
			}
		})
	}
}
