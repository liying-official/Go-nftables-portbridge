package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"portbridge/internal/config"
)

// A local, bounded DNS fixture; unlike a prefilled resolver cache it exercises
// the production DNS-success and DNS-failure/cache-authorization call chains.
func startReviewDNSServer(t *testing.T, initial netip.Addr) (string, func(netip.Addr), func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var answer atomic.Uint32
	set := func(addr netip.Addr) { a := addr.As4(); answer.Store(binary.BigEndian.Uint32(a[:])) }
	set(initial)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			size, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			q := append([]byte(nil), buf[:size]...)
			if len(q) < 17 {
				continue
			}
			pos := 12
			for pos < len(q) && q[pos] != 0 {
				if q[pos] > 63 {
					pos = len(q)
					break
				}
				pos += int(q[pos]) + 1
			}
			if pos+5 > len(q) {
				continue
			}
			pos++
			count := uint16(0)
			if binary.BigEndian.Uint16(q[pos:pos+2]) == 1 {
				count = 1
			}
			response := make([]byte, 12)
			copy(response, q[:2])
			binary.BigEndian.PutUint16(response[2:], 0x8180)
			binary.BigEndian.PutUint16(response[4:], 1)
			binary.BigEndian.PutUint16(response[6:], count)
			response = append(response, q[12:pos+4]...)
			if count == 1 {
				response = append(response, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4)
				var a [4]byte
				binary.BigEndian.PutUint32(a[:], answer.Load())
				response = append(response, a[:]...)
			}
			_, _ = conn.WriteToUDP(response, peer)
		}
	}()
	stop := func() { _ = conn.Close(); <-done }
	t.Cleanup(stop)
	return conn.LocalAddr().String(), set, stop
}
func TestReviewAdmissionAuthorizationDNSAndGoTransition(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, operation := range []string{"authorization-withdrawn", "dns-failed-cached-authorization-withdrawn", "dns-address-changed", "nft-to-go"} {
			t.Run(protocol+"/"+operation, func(t *testing.T) {
				a, b := reviewAB()
				a.Protocol = protocol
				b.Protocol = protocol
				a.TargetHost = netip.MustParseAddr("10.23.0.2")
				changed := a
				changed.TargetHost = netip.MustParseAddr("10.23.0.3")
				k := newCausalNFTKernel(a, b, changed)
				ct := &memoryConntrack{}
				n := reviewBackend(k, ct, privateNFTConfig(t))
				server, setDNS, stopDNS := startReviewDNSServer(t, a.TargetHost)
				m := newManagerWithNFT(testLogger(), NewDNSResolver([]string{server}), n)
				defer m.Stop()
				ra, rb := ruleFromNFTSpec(a), ruleFromNFTSpec(b)
				ra.AllowPrivateTarget = true
				ra.TargetCIDRAllowlist = []string{"10.23.0.2/32", "10.23.0.3/32"}
				ra.ConnectTimeoutSeconds = 1
				if operation == "dns-failed-cached-authorization-withdrawn" || operation == "dns-address-changed" {
					ra.TargetHost = "controlled.portbridge.test"
				}
				m.Apply([]config.Rule{ra, rb})
				if !n.initialized || len(n.activeSpecs) != 2 {
					t.Fatalf("A/B initial DNS/authorization fixture failed: %+v", m.Runtime())
				}
				one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
				control := one
				control.mark++
				ct.entries = []conntrackEntry{one, two, control}
				k.conflict(true)
				switch operation {
				case "authorization-withdrawn":
					ra.AllowPrivateTarget = false
					ra.TargetCIDRAllowlist = nil
				case "dns-failed-cached-authorization-withdrawn":
					stopDNS()
					ra.AllowPrivateTarget = false
					ra.TargetCIDRAllowlist = nil
				case "dns-address-changed":
					setDNS(changed.TargetHost)
				case "nft-to-go":
					var host string
					var targetPort int
					var closeEcho func()
					if protocol == "tcp" {
						host, targetPort, closeEcho = startTCPEcho(t, "tcp4", "127.0.0.1:0")
						ra.ListenPort = freeTCPPort(t, "tcp4", "127.0.0.1:0")
					} else {
						host, targetPort, closeEcho = startUDPEcho(t, "udp4", "127.0.0.1:0")
						ra.ListenPort = freeUDPPort(t, "udp4", "127.0.0.1:0")
					}
					defer closeEcho()
					ra.DataPlane = config.RuleDataPlaneGo
					ra.ListenHost = "127.0.0.1"
					ra.ListenPortEnd = ra.ListenPort
					ra.TargetHost = host
					ra.TargetPort = targetPort
					ra.TargetPortEnd = targetPort
					ra.TargetCIDRAllowlist = []string{"127.0.0.1/32"}
				}
				m.Refresh([]config.Rule{ra, rb})
				requireNFTEntries(t, ct, two, control)
				if len(n.pendingSpecs) != 0 || len(n.activeSpecs) != 0 || len(n.suspendedSpecs) != 1 || !nftIdentityMatchesRule(n.suspendedSpecs[0], b.RuleID) {
					t.Fatalf("incorrect edge retirement result: %+v", m.Runtime())
				}
				if operation == "nft-to-go" {
					row, _ := runtimeByID(m, a.RuleID)
					if !row.GoRunning || !row.Stats.Running {
						t.Fatalf("explicit nonoverlapping Go path did not start after A retirement: %+v", row)
					}
				}
			})
		}
	}
}

type partialReviewConntrack struct {
	*memoryConntrack
	once bool
}

func (c *partialReviewConntrack) Delete(ctx context.Context, entries []conntrackEntry) error {
	if c.once && len(entries) > 1 {
		c.once = false
		if err := c.memoryConntrack.Delete(ctx, entries[:1]); err != nil {
			return err
		}
		return context.DeadlineExceeded
	}
	return c.memoryConntrack.Delete(ctx, entries)
}
func TestNFTIndependentStorePartialDeleteCrash(t *testing.T) {
	a, b := reviewAB()
	k := newCausalNFTKernel(a, b)
	inner := &memoryConntrack{}
	ct := &partialReviewConntrack{memoryConntrack: inner, once: true}
	path := privateNFTConfig(t)
	n := reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{a, b}); err != nil {
		t.Fatal(err)
	}
	first, second, other := conntrackUnitEntry(a, 45000), conntrackUnitEntry(a, 45001), conntrackUnitEntry(b, 45002)
	inner.entries = []conntrackEntry{first, second, other}
	if err := n.Replace([]nftRuleSpec{b}); err == nil {
		t.Fatal("partial delete error hidden")
	}
	requireNFTEntries(t, inner, second, other)
	k.objects = nil
	n = reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{b}); err != nil {
		t.Fatal(err)
	}
	requireNFTEntries(t, inner, other)
	if len(inner.deleted) != 2 || inner.deleted[0] != first || inner.deleted[1] != second {
		t.Fatal("partial restart widened deletion")
	}
}
func TestNFTAdmissionFamilyScopeAndMalformedInventory(t *testing.T) {
	a, _ := reviewAB()
	v6 := a
	v6.Family = 6
	v6.ListenHost = netip.MustParseAddr("2001:db8:1::1")
	v6.TargetHost = netip.MustParseAddr("2001:db8:2::1")
	k := newCausalNFTKernel(a, v6)
	n := reviewBackend(k, &memoryConntrack{}, "")
	k.conflict(true)
	chain := k.external[0]["chain"].(map[string]any)
	chain["family"] = "ip"
	if err := n.checkAdmissionFor([]nftRuleSpec{v6}); err != nil {
		t.Fatal("IPv4-only policy conflict blocked IPv6 admission")
	}
	var rejected *nftAdmissionError
	if err := n.checkAdmissionFor([]nftRuleSpec{a}); !errors.As(err, &rejected) {
		t.Fatal("IPv4 policy conflict not typed/rejected")
	}
	chain["hook"] = "forward"
	chain["prio"] = nftForwardPriority - 1
	if err := n.checkAdmissionFor([]nftRuleSpec{a}); err != nil {
		t.Fatal("ordinary earlier forward hook rejected")
	}
	chain["prio"] = nftForwardPriority
	if err := n.checkAdmissionFor([]nftRuleSpec{a}); err == nil {
		t.Fatal("equal-priority forward accepted")
	}
	for _, field := range []string{"family", "table", "name", "type", "prio"} {
		t.Run(field, func(t *testing.T) {
			saved := chain[field]
			delete(chain, field)
			defer func() { chain[field] = saved }()
			var typed *nftAdmissionError
			if err := n.checkAdmissionFor([]nftRuleSpec{a}); err == nil || errors.As(err, &typed) {
				t.Fatal("incomplete inventory was mistaken for a known policy rejection/healthy state")
			}
		})
	}
}
