package proxy

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"portbridge/internal/config"
)

func TestTCPResourceBudgets(t *testing.T) {
	resources := newResourceBudget(config.ResourceLimits{
		MaxTCPConnections: 2, MaxUDPSessions: 2, MaxUDPMemoryBytes: 1024,
	})
	rule := &ruleBudget{}
	sourceA := netip.MustParseAddr("192.0.2.1")
	sourceB := netip.MustParseAddr("192.0.2.2")
	if !resources.reserveTCP(rule, sourceA, 2, 1) {
		t.Fatal("first TCP reservation was rejected")
	}
	if resources.reserveTCP(rule, sourceA, 2, 1) {
		t.Fatal("per-source TCP limit was bypassed")
	}
	if !resources.reserveTCP(rule, sourceB, 2, 1) {
		t.Fatal("second source TCP reservation was rejected")
	}
	if resources.reserveTCP(rule, netip.MustParseAddr("192.0.2.3"), 3, 1) {
		t.Fatal("global TCP limit was bypassed")
	}
	resources.releaseTCP(rule, sourceA)
	resources.releaseTCP(rule, sourceB)
}

func TestUDPGlobalSessionAndMemoryBudgets(t *testing.T) {
	resources := newResourceBudget(config.ResourceLimits{
		MaxTCPConnections: 1, MaxUDPSessions: 2, MaxUDPMemoryBytes: 100,
	})
	if !resources.reserveUDP(60) {
		t.Fatal("first UDP reservation was rejected")
	}
	if resources.reserveUDP(60) {
		t.Fatal("UDP memory budget was bypassed")
	}
	resources.releaseUDP(60)
	if !resources.reserveUDP(100) {
		t.Fatal("UDP memory budget was not released")
	}
	resources.releaseUDP(100)
}

func TestUDPRuleWideSessionLimitAcrossWorkers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		workers int
		limit   int
	}{
		{name: "workers-16-limit-1", workers: 16, limit: 1},
		{name: "workers-32-limit-3", workers: 32, limit: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := &ruleBudget{}
			limits := testUDPSourceLimits(tc.limit, 1000, 1000)
			source := netip.MustParseAddr("192.0.2.10")
			accepted := reserveUDPConcurrently(budget, source, true, time.Now(), limits, tc.workers)
			if accepted != tc.limit {
				t.Fatalf("accepted sessions = %d, want exact rule-wide limit %d", accepted, tc.limit)
			}
			for range accepted {
				budget.releaseUDPSourceSession(source, time.Now())
			}
		})
	}
}

func TestUDPRuleWideNewSessionRateAcrossWorkers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		workers int
		rate    int
	}{
		{name: "workers-16-rate-1", workers: 16, rate: 1},
		{name: "workers-32-rate-10", workers: 32, rate: 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			budget := &ruleBudget{}
			limits := testUDPSourceLimits(64, tc.rate, 1000)
			source := netip.MustParseAddr("198.51.100.20")
			accepted := reserveUDPConcurrently(budget, source, true, time.Now(), limits, tc.workers)
			if accepted != tc.rate {
				t.Fatalf("accepted new sessions = %d, want shared rate burst %d", accepted, tc.rate)
			}
			for range accepted {
				budget.releaseUDPSourceSession(source, time.Now())
			}
		})
	}
}

func TestUDPRuleWidePacketRateAcrossWorkers(t *testing.T) {
	budget := &ruleBudget{}
	limits := testUDPSourceLimits(64, 64, 10)
	source := netip.MustParseAddr("203.0.113.30")
	if accepted := reserveUDPConcurrently(budget, source, false, time.Now(), limits, 16); accepted != 10 {
		t.Fatalf("accepted packets = %d, want shared burst 10", accepted)
	}
}

func TestUDPSourceBudgetExistingSessionHotPathAllocations(t *testing.T) {
	budget := &ruleBudget{}
	limits := testUDPSourceLimits(64, 1_000_000, 1_000_000)
	source := netip.MustParseAddr("203.0.113.31")
	now := time.Now()
	if !budget.reserveUDPPacket(source, false, now, limits) {
		t.Fatal("initial packet reservation failed")
	}
	allocations := testing.AllocsPerRun(1000, func() {
		if !budget.reserveUDPPacket(source, false, now, limits) {
			t.Fatal("existing-session packet reservation unexpectedly failed")
		}
	})
	if allocations != 0 {
		t.Fatalf("existing-session source budget allocated %.2f objects per packet", allocations)
	}
}

func TestUDPSourceBudgetsShareRuleButSeparateSourceIPs(t *testing.T) {
	now := time.Now()
	limits := testUDPSourceLimits(1, 1, 1)
	budget := &ruleBudget{}
	v4 := netip.MustParseAddr("192.0.2.40")
	v6 := netip.MustParseAddr("2001:db8::40")
	if !budget.reserveUDPPacket(v4, true, now, limits) || !budget.reserveUDPPacket(v6, true, now, limits) {
		t.Fatal("distinct IPv4 and IPv6 sources incorrectly shared one source budget")
	}
	if budget.reserveUDPPacket(v4, true, now, limits) || budget.reserveUDPPacket(v6, true, now, limits) {
		t.Fatal("a per-source session limit was bypassed")
	}
	budget.releaseUDPSourceSession(v4, now)
	budget.releaseUDPSourceSession(v6, now)
}

func TestUDPSourceBudgetSharedAcrossRulePaths(t *testing.T) {
	for _, topology := range []string{"port-range", "wildcard-fallback", "hybrid-runners"} {
		t.Run(topology, func(t *testing.T) {
			budget := &ruleBudget{}
			// Each reference represents a separate worker, listen port, address
			// family, or Go runner. Manager assigns the same ruleBudget to all.
			paths := []*ruleBudget{budget, budget, budget, budget}
			limits := testUDPSourceLimits(1, 100, 100)
			source := netip.MustParseAddr("192.0.2.50")
			accepted := 0
			for _, path := range paths {
				if path.reserveUDPPacket(source, true, time.Now(), limits) {
					accepted++
				}
			}
			if accepted != 1 {
				t.Fatalf("accepted sessions across %s = %d, want 1", topology, accepted)
			}
			budget.releaseUDPSourceSession(source, time.Now())
		})
	}
}

func TestUDPSourceReservationFailureRollback(t *testing.T) {
	now := time.Now()
	limits := testUDPSourceLimits(1, 1, 100)
	budget := &ruleBudget{}
	source := netip.MustParseAddr("192.0.2.60")
	if !budget.reserveUDPPacket(source, true, now, limits) {
		t.Fatal("initial source reservation failed")
	}
	budget.rollbackUDPSourceSession(source, limits.newSessionsRate)
	if !budget.reserveUDPPacket(source, true, now, limits) {
		t.Fatal("failed socket creation did not roll back session count and new-session token")
	}
	budget.releaseUDPSourceSession(source, now)
}

func TestUDPSourceSessionTimeoutRelease(t *testing.T) {
	now := time.Now()
	limits := testUDPSourceLimits(1, 2, 100)
	budget := &ruleBudget{}
	source := netip.MustParseAddr("192.0.2.61")
	if !budget.reserveUDPPacket(source, true, now, limits) {
		t.Fatal("initial source reservation failed")
	}
	budget.releaseUDPSourceSession(source, now)
	if !budget.reserveUDPPacket(source, true, now, limits) {
		t.Fatal("timeout release did not return the active-session capacity")
	}
	budget.releaseUDPSourceSession(source, now)
}

func TestUDPSourceSessionsShutdownRelease(t *testing.T) {
	now := time.Now()
	limits := testUDPSourceLimits(3, 6, 100)
	budget := &ruleBudget{}
	source := netip.MustParseAddr("192.0.2.62")
	for i := 0; i < 3; i++ {
		if !budget.reserveUDPPacket(source, true, now, limits) {
			t.Fatalf("session %d reservation failed", i+1)
		}
	}
	for i := 0; i < 3; i++ {
		budget.releaseUDPSourceSession(source, now)
	}
	if active := udpActiveSessionsForTest(budget, source); active != 0 {
		t.Fatalf("shutdown left %d source sessions reserved", active)
	}
	for i := 0; i < 3; i++ {
		if !budget.reserveUDPPacket(source, true, now, limits) {
			t.Fatalf("post-shutdown session %d reservation failed", i+1)
		}
	}
	for i := 0; i < 3; i++ {
		budget.releaseUDPSourceSession(source, now)
	}
}

func TestUDPSourceStateCleanupIsBoundedAndPreservesActive(t *testing.T) {
	base := time.Now()
	limits := testUDPSourceLimits(2048, 10000, 10000)
	budget := &ruleBudget{}
	active := netip.MustParseAddr("2001:db8::1")
	if !budget.reserveUDPPacket(active, true, base, limits) {
		t.Fatal("active source reservation failed")
	}
	for i := 1; i <= 1500; i++ {
		source := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), byte(i >> 4)})
		if budget.reserveUDPPacket(source, true, base, limits) {
			budget.rollbackUDPSourceSession(source, limits.newSessionsRate)
		}
	}

	inspected := budget.maintainUDPSources(base.Add(2*time.Minute), time.Minute)
	if maximum := udpCleanupShardsPerSweep * udpCleanupEntriesPerShard; inspected > maximum {
		t.Fatalf("cleanup inspected %d states, bounded maximum is %d", inspected, maximum)
	}
	for i := 1; i < sourceBudgetShards/udpCleanupShardsPerSweep; i++ {
		budget.maintainUDPSources(base.Add(2*time.Minute+time.Duration(i)*time.Second), time.Minute)
	}
	if activeSessions := udpActiveSessionsForTest(budget, active); activeSessions != 1 {
		t.Fatalf("cleanup changed active source sessions to %d", activeSessions)
	}
	budget.releaseUDPSourceSession(active, base.Add(3*time.Minute))
	for i := 0; i < sourceBudgetShards/udpCleanupShardsPerSweep; i++ {
		budget.maintainUDPSources(base.Add(5*time.Minute+time.Duration(i)*time.Second), time.Minute)
	}
	if count := budget.udpSourceCount.Load(); count != 0 {
		t.Fatalf("inactive source-state count after incremental cleanup = %d, want 0", count)
	}
}

func testUDPSourceLimits(maxSessions, newRate, packetRate int) udpSourceLimits {
	return udpSourceLimits{
		maxSessions: maxSessions, newSessionsRate: newRate, packetRate: packetRate, maxTrackedSource: 4096,
	}
}

func reserveUDPConcurrently(budget *ruleBudget, source netip.Addr, newSession bool, now time.Time, limits udpSourceLimits, attempts int) int {
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(attempts)
	var accepted atomic.Int64
	for range attempts {
		go func() {
			defer done.Done()
			start.Wait()
			if budget.reserveUDPPacket(source, newSession, now, limits) {
				accepted.Add(1)
			}
		}()
	}
	start.Done()
	done.Wait()
	return int(accepted.Load())
}

func udpActiveSessionsForTest(budget *ruleBudget, source netip.Addr) int {
	shard := &budget.udpSources[sourceShard(source)]
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if state := shard.states[source.Unmap()]; state != nil {
		return state.activeSessions
	}
	return 0
}
