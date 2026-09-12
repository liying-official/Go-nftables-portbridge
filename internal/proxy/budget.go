package proxy

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"portbridge/internal/config"
)

const (
	sourceBudgetShards          = 64
	udpCleanupShardsPerSweep    = 4
	udpCleanupEntriesPerShard   = 256
	udpSourceCleanupMinInterval = time.Second
)

type resourceBudget struct {
	maxTCP       atomic.Int64
	maxUDP       atomic.Int64
	maxUDPMemory atomic.Int64
	activeTCP    atomic.Int64
	activeUDP    atomic.Int64
	udpMemory    atomic.Int64
}

type sourceCounterShard struct {
	mu     sync.Mutex
	counts map[netip.Addr]int
}

type ruleBudget struct {
	activeTCP        atomic.Int64
	sources          [sourceBudgetShards]sourceCounterShard
	udpSources       [sourceBudgetShards]udpSourceBudgetShard
	udpSourceCount   atomic.Int64
	udpCleanupCursor atomic.Uint32
	nextUDPCleanup   atomic.Int64
}

type udpSourceLimits struct {
	maxSessions      int
	newSessionsRate  int
	packetRate       int
	maxTrackedSource int
}

type udpSourceBudgetShard struct {
	mu     sync.Mutex
	states map[netip.Addr]*udpSourceBudgetState
}

type udpSourceBudgetState struct {
	activeSessions int
	newTokens      float64
	packetTokens   float64
	lastRefill     time.Time
	lastSeen       time.Time
}

func newResourceBudget(limits config.ResourceLimits) *resourceBudget {
	b := &resourceBudget{}
	b.setLimits(limits)
	return b
}

func (b *resourceBudget) setLimits(limits config.ResourceLimits) {
	b.maxTCP.Store(int64(limits.MaxTCPConnections))
	b.maxUDP.Store(int64(limits.MaxUDPSessions))
	b.maxUDPMemory.Store(limits.MaxUDPMemoryBytes)
}

func (b *resourceBudget) reserveTCP(rule *ruleBudget, source netip.Addr, ruleMax, sourceMax int) bool {
	if !reserveAtomic(&b.activeTCP, b.maxTCP.Load()) {
		return false
	}
	if !reserveAtomic(&rule.activeTCP, int64(ruleMax)) {
		b.activeTCP.Add(-1)
		return false
	}
	shard := &rule.sources[sourceShard(source)]
	shard.mu.Lock()
	if shard.counts == nil {
		shard.counts = make(map[netip.Addr]int)
	}
	if shard.counts[source] >= sourceMax {
		shard.mu.Unlock()
		rule.activeTCP.Add(-1)
		b.activeTCP.Add(-1)
		return false
	}
	shard.counts[source]++
	shard.mu.Unlock()
	return true
}

func (b *resourceBudget) releaseTCP(rule *ruleBudget, source netip.Addr) {
	shard := &rule.sources[sourceShard(source)]
	shard.mu.Lock()
	if count := shard.counts[source]; count <= 1 {
		delete(shard.counts, source)
	} else {
		shard.counts[source] = count - 1
	}
	shard.mu.Unlock()
	rule.activeTCP.Add(-1)
	b.activeTCP.Add(-1)
}

func (b *resourceBudget) reserveUDP(bytes int64) bool {
	if !reserveAtomic(&b.activeUDP, b.maxUDP.Load()) {
		return false
	}
	if !b.reserveUDPMemory(bytes) {
		b.activeUDP.Add(-1)
		return false
	}
	return true
}

func (b *resourceBudget) reserveUDPMemory(bytes int64) bool {
	return reserveAtomicN(&b.udpMemory, bytes, b.maxUDPMemory.Load())
}

func (b *resourceBudget) releaseUDPMemory(bytes int64) {
	b.udpMemory.Add(-bytes)
}

func (b *resourceBudget) releaseUDP(bytes int64) {
	b.releaseUDPMemory(bytes)
	b.activeUDP.Add(-1)
}

// reserveUDPPacket enforces one logical source-IP budget for the whole rule.
// All Go runners, address families, listen ports, and SO_REUSEPORT workers for
// a rule share the same ruleBudget. The shard lock is held only while updating
// counters and token buckets; no socket or other blocking operation occurs in
// the critical section.
func (b *ruleBudget) reserveUDPPacket(source netip.Addr, newSession bool, now time.Time, limits udpSourceLimits) bool {
	source = source.Unmap()
	shard := &b.udpSources[sourceShard(source)]
	shard.mu.Lock()
	defer shard.mu.Unlock()

	state := shard.states[source]
	if state == nil {
		if !reserveAtomic(&b.udpSourceCount, int64(limits.maxTrackedSource)) {
			return false
		}
		if shard.states == nil {
			shard.states = make(map[netip.Addr]*udpSourceBudgetState)
		}
		state = &udpSourceBudgetState{
			newTokens:    float64(limits.newSessionsRate),
			packetTokens: float64(limits.packetRate),
			lastRefill:   now,
			lastSeen:     now,
		}
		shard.states[source] = state
	} else {
		refillUDPSourceTokens(state, now, limits)
		state.lastSeen = now
	}

	if state.packetTokens < 1 {
		return false
	}
	if newSession && (state.activeSessions >= limits.maxSessions || state.newTokens < 1) {
		return false
	}
	state.packetTokens--
	if newSession {
		state.activeSessions++
		state.newTokens--
	}
	return true
}

// rollbackUDPSourceSession returns both the active-session reservation and the
// new-session token because no session was actually created. The packet token
// remains consumed: the inbound packet still traversed the rate-limited path.
func (b *ruleBudget) rollbackUDPSourceSession(source netip.Addr, newSessionsRate int) {
	source = source.Unmap()
	shard := &b.udpSources[sourceShard(source)]
	shard.mu.Lock()
	if state := shard.states[source]; state != nil {
		if state.activeSessions > 0 {
			state.activeSessions--
		}
		state.newTokens++
		if maximum := float64(newSessionsRate); state.newTokens > maximum {
			state.newTokens = maximum
		}
	}
	shard.mu.Unlock()
}

func (b *ruleBudget) releaseUDPSourceSession(source netip.Addr, now time.Time) {
	source = source.Unmap()
	shard := &b.udpSources[sourceShard(source)]
	shard.mu.Lock()
	if state := shard.states[source]; state != nil {
		if state.activeSessions > 0 {
			state.activeSessions--
		}
		state.lastSeen = now
	}
	shard.mu.Unlock()
}

func refillUDPSourceTokens(state *udpSourceBudgetState, now time.Time, limits udpSourceLimits) {
	if elapsed := now.Sub(state.lastRefill).Seconds(); elapsed > 0 {
		state.newTokens += elapsed * float64(limits.newSessionsRate)
		state.packetTokens += elapsed * float64(limits.packetRate)
		state.lastRefill = now
	}
	if maximum := float64(limits.newSessionsRate); state.newTokens > maximum {
		state.newTokens = maximum
	}
	if maximum := float64(limits.packetRate); state.packetTokens > maximum {
		state.packetTokens = maximum
	}
}

// maintainUDPSources performs bounded, incremental cleanup outside the packet
// path. At most four shards and 256 entries in each shard are inspected by one
// worker per second, regardless of the number of workers sharing this budget.
func (b *ruleBudget) maintainUDPSources(now time.Time, idle time.Duration) int {
	nowSecond := now.Unix()
	for {
		next := b.nextUDPCleanup.Load()
		if nowSecond < next {
			return 0
		}
		if b.nextUDPCleanup.CompareAndSwap(next, now.Add(udpSourceCleanupMinInterval).Unix()) {
			break
		}
	}

	start := int(b.udpCleanupCursor.Add(udpCleanupShardsPerSweep)-udpCleanupShardsPerSweep) % sourceBudgetShards
	cutoff := now.Add(-idle)
	totalInspected := 0
	for offset := 0; offset < udpCleanupShardsPerSweep; offset++ {
		shard := &b.udpSources[(start+offset)%sourceBudgetShards]
		shard.mu.Lock()
		inspected := 0
		deleted := int64(0)
		for source, state := range shard.states {
			if inspected >= udpCleanupEntriesPerShard {
				break
			}
			inspected++
			if state.activeSessions == 0 && !state.lastSeen.After(cutoff) {
				delete(shard.states, source)
				deleted++
			}
		}
		totalInspected += inspected
		shard.mu.Unlock()
		if deleted != 0 {
			b.udpSourceCount.Add(-deleted)
		}
	}
	return totalInspected
}

func reserveAtomic(counter *atomic.Int64, maximum int64) bool {
	return reserveAtomicN(counter, 1, maximum)
}

func reserveAtomicN(counter *atomic.Int64, amount, maximum int64) bool {
	for {
		current := counter.Load()
		if amount <= 0 || maximum <= 0 || current > maximum-amount {
			return false
		}
		if counter.CompareAndSwap(current, current+amount) {
			return true
		}
	}
}

func sourceShard(address netip.Addr) uint64 {
	address = address.Unmap()
	if address.Is4() {
		value := address.As4()
		return uint64(value[0]^value[1]^value[2]^value[3]) % sourceBudgetShards
	}
	value := address.As16()
	var folded byte
	for _, part := range value {
		folded ^= part
	}
	return uint64(folded) % sourceBudgetShards
}
