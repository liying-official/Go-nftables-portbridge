package proxy

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Go counters represent payload; nft/conntrack counters represent L3 packets.
// They are deliberately not added together. Conntrack sampling is best effort:
// short-lived flows and asynchronous offload sync can be missed.
type TrafficSeries struct {
	BytesUp              uint64    `json:"bytes_up"`
	BytesDown            uint64    `json:"bytes_down"`
	PacketsUp            uint64    `json:"packets_up"`
	PacketsDown          uint64    `json:"packets_down"`
	BytesUpPerSecond     float64   `json:"bytes_up_per_second"`
	BytesDownPerSecond   float64   `json:"bytes_down_per_second"`
	PacketsUpPerSecond   float64   `json:"packets_up_per_second"`
	PacketsDownPerSecond float64   `json:"packets_down_per_second"`
	SampledAt            time.Time `json:"sampled_at"`
	IntervalSeconds      float64   `json:"interval_seconds"`
	Available            bool      `json:"available"`
	RateReady            bool      `json:"rate_ready"`
}

type NFTHookCounter struct {
	Hook    string `json:"hook"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
}

type TrafficSnapshot struct {
	Go                TrafficSeries    `json:"go"`
	NFT               TrafficSeries    `json:"nft"`
	NFTHooks          []NFTHookCounter `json:"nft_hooks"`
	NFTHooksAt        time.Time        `json:"nft_hooks_sampled_at"`
	NFTHooksAvailable bool             `json:"nft_hooks_available"`
	NFTBestEffort     bool             `json:"nft_best_effort"`
	NFTStatus         string           `json:"nft_status"`
	CounterResets     uint64           `json:"counter_resets"`
}

type trafficInput struct {
	id    string
	stats *Stats
	nft   bool
	count trafficCount
}
type trafficHistory struct {
	identity                *Stats
	view                    TrafficSnapshot
	goPrevious, nftPrevious trafficCount
	hooks                   map[string]nftCounterPoint
	flows                   map[string]trafficCount
	hookTotals              map[string]NFTHookCounter
}
type trafficCollector struct {
	mu              sync.Mutex
	poll            sync.Mutex
	rows            map[string]*trafficHistory
	life            sync.Mutex
	started, closed bool
	stopCh, done    chan struct{}
}

func newTrafficCollector() *trafficCollector {
	return &trafficCollector{rows: map[string]*trafficHistory{}, stopCh: make(chan struct{}), done: make(chan struct{})}
}

func (m *Manager) StartTelemetry() {
	if m.telemetry == nil {
		return
	}
	c := m.telemetry
	c.life.Lock()
	defer c.life.Unlock()
	if c.started || c.closed {
		return
	}
	c.started = true
	go func() {
		defer close(c.done)
		m.SampleTelemetry()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.SampleTelemetry()
			case <-c.stopCh:
				return
			}
		}
	}()
}
func (c *trafficCollector) stop() {
	c.life.Lock()
	if !c.closed {
		close(c.stopCh)
		c.closed = true
	}
	started := c.started
	c.life.Unlock()
	if started {
		<-c.done
	}
}

// SampleTelemetry runs in a single background collector, never on HTTP scrape
// or packet paths. Contended control-plane locks skip a sample instead of
// extending the forwarding/reconfiguration critical section.
func (m *Manager) SampleTelemetry() {
	c := m.telemetry
	if c == nil || !c.poll.TryLock() {
		return
	}
	defer c.poll.Unlock()
	if !m.mu.TryLock() {
		return
	}
	inputs := make([]trafficInput, 0, len(m.rules))
	needNFT := false
	for id := range m.rules {
		s := m.stats[id]
		if s == nil {
			continue
		}
		use := dataPlaneUsesNFT(m.dataPlanes[id])
		needNFT = needNFT || use
		inputs = append(inputs, trafficInput{id: id, stats: s, nft: use})
	}
	backend := m.nft
	m.mu.Unlock()
	var nft nftTelemetry
	status := "not_applicable"
	if needNFT {
		status = "unavailable"
		if reader, ok := backend.(interface{ readTelemetry() (nftTelemetry, error) }); ok {
			if value, err := reader.readTelemetry(); err == nil {
				nft = value
				status = "sampled"
			}
		}
	}
	for i := range inputs {
		s := inputs[i].stats
		up, down := s.trafficBytes()
		inputs[i].count = trafficCount{up, down, s.udpUp.Load(), s.udpDown.Load()}
	}
	c.update(time.Now(), inputs, nft, status)
}

func addTraffic(a, b uint64) uint64 {
	if math.MaxUint64-a < b {
		return math.MaxUint64
	}
	return a + b
}
func deltaTraffic(current, previous uint64) (uint64, bool) {
	if current < previous {
		return current, true
	}
	return current - previous, false
}
func countDelta(current, previous trafficCount) (trafficCount, bool) {
	a, r1 := deltaTraffic(current.up, previous.up)
	b, r2 := deltaTraffic(current.down, previous.down)
	c, r3 := deltaTraffic(current.packetsUp, previous.packetsUp)
	d, r4 := deltaTraffic(current.packetsDown, previous.packetsDown)
	return trafficCount{a, b, c, d}, r1 || r2 || r3 || r4
}
func seriesCount(s TrafficSeries) trafficCount {
	return trafficCount{s.BytesUp, s.BytesDown, s.PacketsUp, s.PacketsDown}
}
func setSeries(s *TrafficSeries, current, previous trafficCount, now time.Time, available bool) {
	last, wasAvailable := s.SampledAt, s.Available
	s.BytesUp, s.BytesDown, s.PacketsUp, s.PacketsDown = current.up, current.down, current.packetsUp, current.packetsDown
	s.BytesUpPerSecond, s.BytesDownPerSecond, s.PacketsUpPerSecond, s.PacketsDownPerSecond = 0, 0, 0, 0
	s.Available = available
	s.RateReady = false
	s.IntervalSeconds = 0
	if !available {
		return
	}
	s.SampledAt = now
	interval := now.Sub(last).Seconds()
	delta, reset := countDelta(current, previous)
	if wasAvailable && !last.IsZero() && interval > 0 && interval <= 5 && !reset {
		s.IntervalSeconds = interval
		s.RateReady = true
		s.BytesUpPerSecond = float64(delta.up) / interval
		s.BytesDownPerSecond = float64(delta.down) / interval
		s.PacketsUpPerSecond = float64(delta.packetsUp) / interval
		s.PacketsDownPerSecond = float64(delta.packetsDown) / interval
	}
}

func (c *trafficCollector) update(now time.Time, inputs []trafficInput, nft nftTelemetry, status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	live := map[string]bool{}
	hooks := map[string][]nftCounterPoint{}
	flows := map[string][]nftFlowPoint{}
	for _, p := range nft.hooks {
		hooks[p.rule] = append(hooks[p.rule], p)
	}
	for _, p := range nft.flows {
		flows[p.rule] = append(flows[p.rule], p)
	}
	for _, in := range inputs {
		live[in.id] = true
		row := c.rows[in.id]
		if row == nil || row.identity != in.stats {
			row = &trafficHistory{identity: in.stats, hooks: map[string]nftCounterPoint{}, flows: map[string]trafficCount{}, hookTotals: map[string]NFTHookCounter{}}
			c.rows[in.id] = row
		}
		setSeries(&row.view.Go, in.count, row.goPrevious, now, true)
		row.goPrevious = in.count
		previousResets := row.view.CounterResets
		row.view.NFTBestEffort = in.nft
		row.view.NFTStatus = status
		row.view.NFTHooksAvailable = false
		nftCount := seriesCount(row.view.NFT)
		accounted := false
		if !in.nft {
			row.view.NFTStatus = "not_applicable"
			row.hooks = map[string]nftCounterPoint{}
			row.flows = map[string]trafficCount{}
		}
		if in.nft && status == "sampled" {
			row.view.NFTHooksAvailable = true
			row.view.NFTHooksAt = now
			nextHooks := map[string]nftCounterPoint{}
			for _, p := range hooks[in.id] {
				old := row.hooks[p.key]
				db, r1 := deltaTraffic(p.bytes, old.bytes)
				dp, r2 := deltaTraffic(p.packets, old.packets)
				if r1 || r2 {
					row.view.CounterResets++
				}
				total := row.hookTotals[p.hook]
				total.Hook = p.hook
				total.Bytes = addTraffic(total.Bytes, db)
				total.Packets = addTraffic(total.Packets, dp)
				row.hookTotals[p.hook] = total
				nextHooks[p.key] = p
			}
			row.hooks = nextHooks
			accounted = nft.rules[in.id]
			if accounted {
				nextFlows := map[string]trafficCount{}
				for _, p := range flows[in.id] {
					delta, reset := countDelta(p.count, row.flows[p.key])
					if reset {
						row.view.CounterResets++
					}
					nftCount.up = addTraffic(nftCount.up, delta.up)
					nftCount.down = addTraffic(nftCount.down, delta.down)
					nftCount.packetsUp = addTraffic(nftCount.packetsUp, delta.packetsUp)
					nftCount.packetsDown = addTraffic(nftCount.packetsDown, delta.packetsDown)
					nextFlows[p.key] = p.count
				}
				row.flows = nextFlows
			}
			if !accounted {
				row.view.NFTStatus = "accounting_unavailable"
			}
		}
		setSeries(&row.view.NFT, nftCount, row.nftPrevious, now, accounted)
		if row.view.CounterResets != previousResets {
			row.view.NFT.RateReady = false
		}
		row.nftPrevious = nftCount
		row.view.NFTHooks = make([]NFTHookCounter, 0, len(row.hookTotals))
		for _, h := range row.hookTotals {
			row.view.NFTHooks = append(row.view.NFTHooks, h)
		}
		sort.Slice(row.view.NFTHooks, func(i, j int) bool { return row.view.NFTHooks[i].Hook < row.view.NFTHooks[j].Hook })
	}
	for id := range c.rows {
		if !live[id] {
			delete(c.rows, id)
		}
	}
}

func (c *trafficCollector) snapshot(id string, identity *Stats) TrafficSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	row := c.rows[id]
	if row == nil || row.identity != identity {
		return TrafficSnapshot{NFTStatus: "pending", NFTHooks: []NFTHookCounter{}}
	}
	view := row.view
	if time.Since(view.Go.SampledAt) > 3*time.Second {
		view.Go.Available = false
		view.Go.RateReady = false
	}
	if time.Since(view.NFT.SampledAt) > 3*time.Second {
		view.NFT.Available = false
		view.NFT.RateReady = false
	}
	if time.Since(view.NFTHooksAt) > 3*time.Second {
		view.NFTHooksAvailable = false
		if view.NFTBestEffort {
			view.NFTStatus = "stale"
		}
	}
	return view
}
