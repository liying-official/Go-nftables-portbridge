package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"

	"portbridge/internal/config"
)

// A typed in-memory command substitute. Its passes are not kernel evidence.
type memoryNFTKernel struct {
	objects, wanted   []nftObject
	wantedQueue       [][]nftObject
	readErr, applyErr error
	afterApply        func([]nftObject)
	writes            int
}

func nftTestJSON(objects []nftObject) []byte {
	if objects == nil {
		objects = []nftObject{}
	}
	b, _ := json.Marshal(map[string]any{"nftables": objects})
	return b
}
func cloneNFTTestObjects(objects []nftObject) []nftObject {
	result, err := decodeNFTObjects(nftTestJSON(objects))
	if err != nil {
		panic(err)
	}
	return result
}
func (k *memoryNFTKernel) Tables() ([]byte, error) {
	if k.readErr != nil {
		return nil, k.readErr
	}
	var objects []nftObject
	for _, object := range k.objects {
		if _, ok := object["table"]; ok {
			objects = append(objects, object)
		}
	}
	return nftTestJSON(objects), nil
}
func (k *memoryNFTKernel) Chains() ([]byte, error) {
	if k.readErr != nil {
		return nil, k.readErr
	}
	return nftTestJSON(k.objects), nil
}
func (k *memoryNFTKernel) Table() ([]byte, error) {
	if k.readErr != nil {
		return nil, k.readErr
	}
	return nftTestJSON(k.objects), nil
}
func (k *memoryNFTKernel) Apply(script string) ([]byte, error) {
	k.writes++
	if k.applyErr != nil {
		return nil, k.applyErr
	}
	if strings.TrimSpace(script) == "delete table inet portbridge" {
		k.objects = nil
		return nil, nil
	}
	if len(k.wantedQueue) > 0 {
		k.wanted = k.wantedQueue[0]
		k.wantedQueue = k.wantedQueue[1:]
	}
	k.objects = cloneNFTTestObjects(k.wanted)
	if k.afterApply != nil {
		k.afterApply(k.objects)
	}
	return nil, nil
}

func nftUnitSpec() nftRuleSpec {
	return nftRuleSpec{RuleID: "state-unit", Family: 4, ListenHost: netip.MustParseAddr("192.0.2.1"),
		ListenPort: 10000, ListenPortEnd: 10000, TargetHost: netip.MustParseAddr("198.51.100.2"),
		TargetPort: 20000, TargetPortEnd: 20000, Protocol: "tcp", ConntrackMark: config.DefaultNFTConntrackMark, EnableFlowtable: true}
}
func nftUnitObjects(spec nftRuleSpec) []nftObject {
	return nftUnitStateObjects([]nftRuleSpec{spec}, nil, false)
}
func nftUnitStateObjects(active, pending []nftRuleSpec, keepFlowtable bool) []nftObject {
	mark := config.DefaultNFTConntrackMark
	if len(active) > 0 {
		mark = active[0].ConntrackMark
	} else if len(pending) > 0 {
		mark = pending[0].ConntrackMark
	}
	objects := []nftObject{{"table": map[string]any{"family": "inet", "name": nftTableName, "handle": 1, "comment": nftOwnerMarker(mark)}}}
	for _, name := range []string{"prerouting", "output", "postrouting", "forward"} {
		priority, kind := -100, "nat"
		if name == "postrouting" {
			priority = 100
		}
		if name == "forward" {
			priority, kind = nftForwardPriority, "filter"
		}
		objects = append(objects, nftObject{"chain": map[string]any{"family": "inet", "table": nftTableName, "name": name, "type": kind, "hook": name, "prio": priority, "policy": "accept", "handle": 2}})
	}
	if specsUseFlowtable(active) || keepFlowtable {
		objects = append(objects, nftObject{"flowtable": map[string]any{"family": "inet", "table": nftTableName, "name": nftFlowtableName, "hook": "ingress", "prio": 0, "dev": []any{"a", "b"}, "handle": 3}})
	}
	if len(active)+len(pending) > 0 {
		objects = append(objects, nftObject{"chain": map[string]any{"family": "inet", "table": nftTableName, "name": nftStateChainName, "handle": 5}})
	}
	for _, spec := range active {
		for _, hook := range []string{"prerouting", "output", "postrouting", "forward"} {
			rule := nftExpectedRule(spec, hook)
			rule["handle"] = 4
			objects = append(objects, nftObject{"rule": rule})
		}
		objects = append(objects, nftObject{"rule": nftExpectedJournalRule(spec, false)})
	}
	for _, spec := range pending {
		objects = append(objects, nftObject{"rule": nftExpectedJournalRule(spec, true)})
	}
	return cloneNFTTestObjects(objects)
}
func nftUnitBackend(k *memoryNFTKernel) *commandNFTBackend {
	return &commandNFTBackend{kernel: k, conntrack: &memoryConntrack{}, logger: testLogger(), ownerMarker: nftOwnerMarker(config.DefaultNFTConntrackMark),
		interfaces: func() ([]net.Interface, error) {
			return []net.Interface{{Name: "a", Index: 2}, {Name: "b", Index: 3}}, nil
		}}
}

func TestNFTStateFingerprintIgnoresOnlyNonsemanticNoise(t *testing.T) {
	spec := nftUnitSpec()
	k := &memoryNFTKernel{wanted: nftUnitObjects(spec)}
	n := nftUnitBackend(k)
	if err := n.Replace([]nftRuleSpec{spec}); err != nil {
		t.Fatal(err)
	}
	before := k.writes
	for i, j := 0, len(k.objects)-1; i < j; i, j = i+1, j-1 {
		k.objects[i], k.objects[j] = k.objects[j], k.objects[i]
	}
	for _, object := range k.objects {
		for _, value := range object {
			m := value.(map[string]any)
			m["handle"] = 999
			if expr, ok := m["expr"].([]any); ok {
				for _, item := range expr {
					if counter, ok := item.(map[string]any)["counter"].(map[string]any); ok {
						counter["packets"], counter["bytes"] = 123, 456
					}
				}
			}
			if dev, ok := m["dev"].([]any); ok {
				dev[0], dev[1] = dev[1], dev[0]
			}
		}
	}
	if healthy, err := n.Healthy([]nftRuleSpec{spec}); err != nil || !healthy {
		t.Fatalf("noise caused drift: %t %v", healthy, err)
	}
	if err := n.Replace([]nftRuleSpec{spec}); err != nil || k.writes != before {
		t.Fatalf("noise caused rewrite: %v", err)
	}
	for _, object := range k.objects {
		if rule, ok := object["rule"].(map[string]any); ok && rule["chain"] == "prerouting" {
			expr := rule["expr"].([]any)
			expr[len(expr)-1].(map[string]any)["dnat"].(map[string]any)["addr"] = "203.0.113.99"
			break
		}
	}
	if healthy, err := n.Healthy([]nftRuleSpec{spec}); err != nil || healthy {
		t.Fatalf("target drift not detected: %t %v", healthy, err)
	}
}

func TestNFTCachesOnlyAcknowledgedVerifiedSuccess(t *testing.T) {
	spec := nftUnitSpec()
	k := &memoryNFTKernel{wanted: nftUnitObjects(spec)}
	n := nftUnitBackend(k)
	if err := n.Replace([]nftRuleSpec{spec}); err != nil {
		t.Fatal(err)
	}
	oldKey, oldDevices := n.appliedSpecKey, n.devicesKey
	next := spec
	next.EnableFlowtable = false
	k.wanted = nftUnitObjects(next)
	k.applyErr = context.DeadlineExceeded
	if err := n.Replace([]nftRuleSpec{next}); err == nil {
		t.Fatal("timeout was ignored")
	}
	if n.appliedSpecKey != oldKey || n.devicesKey != oldDevices {
		t.Fatal("failed transaction committed desired cache")
	}
	k.applyErr = nil
	k.afterApply = func(objects []nftObject) {
		for _, object := range objects {
			if rule, ok := object["rule"].(map[string]any); ok && rule["chain"] == "prerouting" {
				expr := rule["expr"].([]any)
				expr[len(expr)-1].(map[string]any)["dnat"].(map[string]any)["addr"] = "203.0.113.99"
				break
			}
		}
	}
	if err := n.Replace([]nftRuleSpec{next}); err == nil || n.initialized {
		t.Fatal("unverified observed drift was cached as applied")
	}
}

func TestNFTInventoryReadFailureIsNotAbsence(t *testing.T) {
	k := &memoryNFTKernel{readErr: errors.New("No such file or directory in a failed inspection")}
	n := nftUnitBackend(k)
	if err := n.Delete(); err == nil || k.writes != 0 {
		t.Fatal("failed read was treated as table absence or allowed a write")
	}
	k.readErr = context.DeadlineExceeded
	if healthy, err := n.Healthy(nil); err == nil || healthy {
		t.Fatal("timeout was treated as healthy")
	}
}

func TestNFTBoundedAndStrictJSONInspection(t *testing.T) {
	b := nftBoundedOutput{limit: 4}
	if _, ok := any(&b).(io.ReaderFrom); ok {
		t.Fatal("promoted ReaderFrom bypasses output bound")
	}
	if _, err := b.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Write([]byte("5")); !errors.Is(err, errNFTOutputLimit) || b.Len() != 4 {
		t.Fatal("output was not bounded")
	}
	for _, data := range []string{`{"nftables":[]} {}`, `{"other":[]}`, `{"nftables":null}`, `not-json`} {
		if _, err := decodeNFTObjects([]byte(data)); err == nil {
			t.Fatalf("invalid JSON accepted: %s", data)
		}
	}
}

type healthNFTBackend struct {
	fakeNFTBackend
	healthy   bool
	healthErr error
}

func (f *healthNFTBackend) Healthy([]nftRuleSpec) (bool, error) { return f.healthy, f.healthErr }

func TestManagerReconcilesDriftAndRetainsInspectionErrors(t *testing.T) {
	f := &healthNFTBackend{healthy: true}
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), f)
	rule := config.NormalizeRule(config.Rule{ID: "health", Protocol: "tcp", ListenHost: "192.0.2.1", ListenPort: 18080,
		TargetHost: "198.51.100.2", TargetPort: 28080, Enabled: true})
	m.Apply([]config.Rule{rule})
	f.healthy = false
	m.Refresh([]config.Rule{rule})
	if f.replaceCall != 2 {
		t.Fatal("unchanged desired key hid object drift")
	}
	key := m.nftKey
	f.healthErr = context.DeadlineExceeded
	m.Refresh([]config.Rule{rule})
	if f.replaceCall != 2 || f.deleteCall != 0 || m.nftKey != key {
		t.Fatal("failed inspection mutated or committed kernel state")
	}
	if rows := m.Runtime(); len(rows) != 1 || !strings.Contains(rows[0].Stats.LastError, "inspect nftables") {
		t.Fatal("inspection failure was hidden")
	}
}

func TestManagerNATOnlyIgnoresUnrelatedTopology(t *testing.T) {
	f := &fakeNFTBackend{topologyKey: "a#1"}
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), f)
	cfg := config.Default()
	cfg.NFT.EnableFlowtable = false
	m.SetRuntimeConfig(cfg.Limits, cfg.NFT)
	rule := config.NormalizeRule(config.Rule{ID: "nat-only", Protocol: "udp", ListenHost: "192.0.2.1", ListenPort: 18080,
		TargetHost: "198.51.100.2", TargetPort: 28080, Enabled: true})
	m.Apply([]config.Rule{rule})
	f.topologyKey = "a#99"
	m.Refresh([]config.Rule{rule})
	if f.replaceCall != 1 {
		t.Fatal("NAT-only mode rebuilt for an unrelated device change")
	}
}
