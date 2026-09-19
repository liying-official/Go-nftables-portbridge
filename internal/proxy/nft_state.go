package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
)

type nftObject map[string]any

type nftObservedState struct {
	exists      bool
	owned       bool
	objects     []nftObject
	fingerprint string
}

type nftDevice struct {
	name  string
	index int
}

type nftTopologySnapshot struct {
	devices []nftDevice
	err     error
}

func (s nftTopologySnapshot) key() string {
	if s.err != nil {
		return "error:" + s.err.Error()
	}
	var parts []string
	for _, device := range s.devices {
		parts = append(parts, device.name+"#"+strconv.Itoa(device.index))
	}
	return strings.Join(parts, "\x00")
}

func (s nftTopologySnapshot) names() []string {
	names := make([]string, len(s.devices))
	for i, d := range s.devices {
		names[i] = d.name
	}
	return names
}

func collectNFTTopology(list func() ([]net.Interface, error)) nftTopologySnapshot {
	interfaces, err := list()
	if err != nil {
		return nftTopologySnapshot{err: err}
	}
	s := nftTopologySnapshot{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Name == "" || iface.Index <= 0 {
			return nftTopologySnapshot{err: errors.New("invalid flowtable interface identity")}
		}
		s.devices = append(s.devices, nftDevice{name: iface.Name, index: iface.Index})
	}
	sort.Slice(s.devices, func(i, j int) bool {
		if s.devices[i].name != s.devices[j].name {
			return s.devices[i].name < s.devices[j].name
		}
		return s.devices[i].index < s.devices[j].index
	})
	return s
}

func decodeNFTObjects(data []byte) ([]nftObject, error) {
	if len(data) > maxNFTOutputBytes {
		return nil, errNFTOutputLimit
	}
	var document struct {
		Objects []nftObject `json:"nftables"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil || document.Objects == nil {
		return nil, errors.New("invalid nftables JSON inspection result")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("unexpected trailing nftables JSON data")
	}
	return document.Objects, nil
}

func tableDescriptor(object nftObject) (map[string]any, bool) {
	table, ok := object["table"].(map[string]any)
	return table, ok && table["family"] == "inet" && table["name"] == nftTableName
}

func (n *commandNFTBackend) observe() (nftObservedState, error) {
	tables, err := n.kernel.Tables()
	if err != nil {
		return nftObservedState{}, err
	}
	objects, err := decodeNFTObjects(tables)
	if err != nil {
		return nftObservedState{}, err
	}
	exists := false
	for _, object := range objects {
		if _, match := tableDescriptor(object); match {
			if exists {
				return nftObservedState{}, errors.New("duplicate managed table in nftables inventory")
			}
			exists = true
		}
	}
	if !exists {
		return nftObservedState{}, nil
	}
	data, err := n.kernel.Table()
	if err != nil {
		// An unsuccessful read is not equivalent to absence or health.
		return nftObservedState{}, err
	}
	objects, err = decodeNFTObjects(data)
	if err != nil {
		return nftObservedState{}, err
	}
	state := nftObservedState{exists: true}
	found := false
	for _, object := range objects {
		if _, meta := object["metainfo"]; meta {
			continue
		}
		if table, match := tableDescriptor(object); match {
			if found {
				return nftObservedState{}, errors.New("duplicate managed table descriptor")
			}
			found = true
			state.owned = table["comment"] == n.ownerMarker
		}
		state.objects = append(state.objects, object)
	}
	if !found {
		return nftObservedState{}, errors.New("nftables table inspection has no matching table object")
	}
	state.fingerprint = nftObjectsFingerprint(state.objects)
	return state, nil
}

func normalizeNFTValue(value any, field string) any {
	switch v := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(v))
		for key, item := range v {
			if key == "handle" || key == "index" {
				continue
			}
			if field == "counter" && (key == "packets" || key == "bytes") {
				continue
			}
			result[key] = normalizeNFTValue(item, key)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, item := range v {
			result[i] = normalizeNFTValue(item, "")
		}
		if field == "dev" || field == "flags" || field == "set" || field == "right" {
			sort.Slice(result, func(i, j int) bool {
				a, _ := json.Marshal(result[i])
				b, _ := json.Marshal(result[j])
				return bytes.Compare(a, b) < 0
			})
		}
		return result
	default:
		return v
	}
}

func nftObjectsFingerprint(objects []nftObject) string {
	parts := make([]string, 0, len(objects))
	for _, object := range objects {
		normalized := normalizeNFTValue(map[string]any(object), "")
		data, _ := json.Marshal(normalized)
		parts = append(parts, string(data))
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return fmt.Sprintf("%x", sum[:])
}

func validateNFTState(objects []nftObject, specs []nftRuleSpec, devices []string, owner string, journal ...nftRenderState) error {
	chains := map[string]int{"prerouting": -100, "output": -100, "postrouting": 100, "forward": nftForwardPriority}
	var state nftRenderState
	if len(journal) > 0 {
		state = journal[0]
	}
	if len(specs)+len(state.retired)+len(state.suspended) > 0 {
		chains[nftStateChainName] = 0
	}
	seenChains := make(map[string]bool)
	wantRules := make(map[string]int)
	for _, spec := range specs {
		for _, hook := range []string{"prerouting", "output", "postrouting", "forward"} {
			wantRules[nftRuleInspectionKey(nftExpectedRule(spec, hook))]++
		}
		wantRules[nftRuleInspectionKey(nftExpectedJournalRule(spec, false))]++
	}
	for _, spec := range state.retired {
		wantRules[nftRuleInspectionKey(nftExpectedJournalRule(spec, true))]++
	}
	for _, spec := range state.suspended {
		wantRules[nftRuleInspectionKey(nftExpectedJournalRole(spec, "s"))]++
	}
	tables, flows := 0, 0
	for _, object := range objects {
		if len(object) != 1 {
			return errors.New("invalid installed nftables object")
		}
		for kind := range object {
			if kind != "table" && kind != "chain" && kind != "rule" && kind != "flowtable" {
				return errors.New("unexpected object in managed nftables table")
			}
		}
		if table, ok := tableDescriptor(object); ok {
			tables++
			if table["comment"] != owner {
				return errors.New("acknowledged table owner differs")
			}
		}
		if chain, ok := object["chain"].(map[string]any); ok {
			name, _ := chain["name"].(string)
			priority, exists := chains[name]
			if name == nftStateChainName {
				if !exists || seenChains[name] || chain["family"] != "inet" || chain["table"] != nftTableName || chain["hook"] != nil || chain["type"] != nil || chain["policy"] != nil {
					return errors.New("nftables state journal must be an unhooked regular chain")
				}
				if state.binding != "" && chain["comment"] != state.binding {
					return errors.New("acknowledged recovery binding differs")
				}
				seenChains[name] = true
				continue
			}
			kind := "nat"
			if name == "forward" {
				kind = "filter"
			}
			if chain["family"] != "inet" || chain["table"] != nftTableName || !exists || seenChains[name] || chain["type"] != kind || chain["hook"] != name ||
				fmt.Sprint(chain["prio"]) != strconv.Itoa(priority) || chain["policy"] != "accept" {
				return errors.New("acknowledged managed chain differs")
			}
			seenChains[name] = true
		}
		if rule, ok := object["rule"].(map[string]any); ok {
			key := nftRuleInspectionKey(rule)
			if wantRules[key] <= 0 {
				return errors.New("installed nftables rule differs from the authorized plan")
			}
			wantRules[key]--
		}
		if flow, ok := object["flowtable"].(map[string]any); ok {
			flows++
			if flow["name"] != nftFlowtableName || flow["hook"] != "ingress" || fmt.Sprint(flow["prio"]) != "0" {
				return errors.New("acknowledged flowtable differs")
			}
			raw, ok := flow["dev"].([]any)
			if single, scalar := flow["dev"].(string); scalar {
				raw, ok = []any{single}, true
			}
			if !ok || len(raw) != len(devices) {
				return errors.New("acknowledged flowtable device set differs")
			}
			names := make([]string, len(raw))
			for i, value := range raw {
				var ok bool
				names[i], ok = value.(string)
				if !ok {
					return errors.New("invalid flowtable device name")
				}
			}
			sort.Strings(names)
			want := append([]string(nil), devices...)
			sort.Strings(want)
			if strings.Join(names, "\x00") != strings.Join(want, "\x00") {
				return errors.New("acknowledged flowtable device set differs")
			}
		}
	}
	wantFlowtable := specsUseFlowtable(specs) || state.keepFlowtable
	if tables != 1 || len(seenChains) != len(chains) || (wantFlowtable && flows != 1) || (!wantFlowtable && flows != 0) {
		return errors.New("acknowledged nftables objects are incomplete")
	}
	for _, count := range wantRules {
		if count != 0 {
			return errors.New("acknowledged nftables rules are incomplete")
		}
	}
	return nil
}
