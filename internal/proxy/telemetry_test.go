package proxy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"portbridge/internal/config"
)

func TestTrafficSamplerRatesResetAndOutage(t *testing.T) {
	c := newTrafficCollector()
	stats := &Stats{}
	now := time.Now()
	sample := func(second int, goBytes, ctBytes, hookBytes uint64, available bool) {
		n := nftTelemetry{rules: map[string]bool{"r": available}, hooks: []nftCounterPoint{{"r", "forward", "handle-1", hookBytes, hookBytes / 10}}}
		if available {
			n.flows = []nftFlowPoint{{"r", "flow-1", trafficCount{ctBytes, ctBytes / 2, ctBytes / 10, ctBytes / 20}}}
		}
		c.update(now.Add(time.Duration(second)*time.Second), []trafficInput{{id: "r", stats: stats, nft: true, count: trafficCount{up: goBytes}}}, n, "sampled")
	}
	sample(0, 100, 1000, 100, true)
	if c.rows["r"].view.NFT.RateReady {
		t.Fatal("first sample must warm up")
	}
	sample(1, 300, 1600, 160, true)
	v := c.rows["r"].view
	if v.Go.BytesUpPerSecond != 200 || v.NFT.BytesUpPerSecond != 600 || v.NFT.BytesUp != 1600 || v.NFTHooks[0].Bytes != 160 {
		t.Fatalf("bad independent counters: %+v", v)
	}
	sample(2, 400, 0, 170, false)
	if c.rows["r"].view.NFT.RateReady || c.rows["r"].view.NFT.Available {
		t.Fatal("unavailable reported as live")
	}
	sample(3, 500, 2000, 180, true)
	v = c.rows["r"].view
	if v.NFT.BytesUp != 2000 || v.NFT.RateReady {
		t.Fatalf("outage doubled counters or emitted rate: %+v", v)
	}
	sample(4, 600, 20, 5, true)
	v = c.rows["r"].view
	if v.NFT.BytesUp != 2020 || v.NFTHooks[0].Bytes != 185 || v.CounterResets != 2 {
		t.Fatalf("reset not accumulated safely: %+v", v)
	}
	if c.snapshot("r", &Stats{}).Go.Available {
		t.Fatal("reused rule ID adopted old statistics")
	}
	c.update(now.Add(5*time.Second), nil, nftTelemetry{}, "not_applicable")
	if len(c.rows) != 0 {
		t.Fatal("deleted rules leaked telemetry")
	}
}

func TestNFTHookCounterIdentityAndIntegers(t *testing.T) {
	spec := nftRuleSpec{RuleID: "r", Family: 4, Protocol: "udp"}
	raw := fmt.Sprintf(`{"nftables":[{"table":{"family":"inet","name":"portbridge","handle":1,"comment":"owner"}},{"rule":{"family":"inet","table":"portbridge","chain":"forward","handle":9,"comment":%q,"expr":[{"counter":{"bytes":9007199254740993,"packets":7}}]}}]}`, nftComment(spec, "forward"))
	objects, err := decodeNFTObjects([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	points, err := parseNFTHookCounters(objects, []nftRuleSpec{spec}, "owner", 1)
	if err != nil || len(points) != 1 || points[0].bytes != 9007199254740993 {
		t.Fatalf("precision/parse: %+v %v", points, err)
	}
	if _, err := parseNFTHookCounters(objects, []nftRuleSpec{spec}, "foreign", 1); err == nil {
		t.Fatal("foreign owner accepted")
	}
	rule := objects[1]["rule"].(map[string]any)
	rule["chain"] = "prerouting"
	if _, err := parseNFTHookCounters(objects, []nftRuleSpec{spec}, "owner", 1); err == nil {
		t.Fatal("wrong hook accepted")
	}
	rule["chain"] = "forward"
	rule["expr"].([]any)[0].(map[string]any)["counter"].(map[string]any)["bytes"] = json.Number("-1")
	if _, err := parseNFTHookCounters(objects, []nftRuleSpec{spec}, "owner", 1); err == nil {
		t.Fatal("negative counter accepted")
	}
}

func TestNFTConntrackAccountingCounters(t *testing.T) {
	spec := nftRuleSpec{RuleID: "r", Family: 4, Protocol: "udp", ConntrackMark: 1234, ListenHost: netip.MustParseAddr("192.0.2.1"), ListenPort: 9000, TargetHost: netip.MustParseAddr("198.51.100.2"), TargetPort: 8000}
	raw := `<conntrack><flow><meta direction="original"><layer3 protoname="ipv4"><src>192.0.2.10</src><dst>192.0.2.1</dst></layer3><layer4 protoname="udp"><sport>32100</sport><dport>9000</dport></layer4><counters><packets>3</packets><bytes>100</bytes></counters></meta><meta direction="reply"><layer3 protoname="ipv4"><src>198.51.100.2</src><dst>198.51.100.1</dst></layer3><layer4 protoname="udp"><sport>8000</sport><dport>32100</dport></layer4><counters><packets>2</packets><bytes>80</bytes></counters></meta><meta direction="independent"><mark>1234</mark><zone>2</zone><id>123</id></meta></flow></conntrack>`
	available := map[string]bool{"r": true}
	flows, err := parseNFTFlowCounters([]byte(raw), []nftRuleSpec{spec}, available)
	if err != nil || len(flows) != 1 || flows[0].count != (trafficCount{100, 80, 3, 2}) {
		t.Fatalf("parse failed: %+v %v", flows, err)
	}
	wrong := spec
	wrong.RuleID = "shared"
	wrong.ListenPort = 9001
	flows, err = parseNFTFlowCounters([]byte(raw), []nftRuleSpec{wrong}, map[string]bool{"shared": true})
	if err != nil || len(flows) != 0 {
		t.Fatal("shared backend misattributed")
	}
	missing := strings.ReplaceAll(raw, "<counters><packets>3</packets><bytes>100</bytes></counters>", "")
	available = map[string]bool{"r": true}
	flows, err = parseNFTFlowCounters([]byte(missing), []nftRuleSpec{spec}, available)
	if err != nil || len(flows) != 0 || available["r"] {
		t.Fatalf("missing accounting was reported as zero: %+v %v", flows, err)
	}
}

func TestTrafficSamplerStaleDoesNotReportZeroRate(t *testing.T) {
	c := newTrafficCollector()
	stats := &Stats{}
	old := time.Now().Add(-10 * time.Second)
	c.update(old, []trafficInput{{id: "r", stats: stats, count: trafficCount{up: 10}}}, nftTelemetry{}, "not_applicable")
	if v := c.snapshot("r", stats); v.Go.Available || v.Go.RateReady {
		t.Fatalf("stale sample: %+v", v)
	}
}

type blockedTelemetryBackend struct {
	entered chan struct{}
	release chan struct{}
	reads   atomic.Int64
}

func (b *blockedTelemetryBackend) Replace([]nftRuleSpec) error { return nil }
func (b *blockedTelemetryBackend) Delete() error               { return nil }
func (b *blockedTelemetryBackend) TopologyKey() string         { return "test" }
func (b *blockedTelemetryBackend) readTelemetry() (nftTelemetry, error) {
	b.reads.Add(1)
	close(b.entered)
	<-b.release
	return nftTelemetry{rules: map[string]bool{"r": true}}, nil
}

func TestTrafficSamplerDoesNotBlockRuntime(t *testing.T) {
	backend := &blockedTelemetryBackend{entered: make(chan struct{}), release: make(chan struct{})}
	manager := newManagerWithNFT(nil, nil, backend)
	manager.rules["r"] = config.Rule{ID: "r", Name: "sample", Protocol: "udp"}
	manager.stats["r"] = &Stats{}
	manager.dataPlanes["r"] = DataPlaneNFT
	manager.StartTelemetry()
	<-backend.entered
	defer manager.Stop()
	defer close(backend.release)
	done := make(chan struct{})
	go func() { manager.Runtime(); manager.SampleTelemetry(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cached runtime blocked behind kernel read")
	}
	if backend.reads.Load() != 1 {
		t.Fatal("overlapping collection")
	}
}
