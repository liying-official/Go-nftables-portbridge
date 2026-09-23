package proxy

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type trafficCount struct{ up, down, packetsUp, packetsDown uint64 }
type nftCounterPoint struct {
	rule, hook, key string
	bytes, packets  uint64
}
type nftFlowPoint struct {
	rule, key string
	count     trafficCount
}
type nftTelemetry struct {
	hooks []nftCounterPoint
	flows []nftFlowPoint
	rules map[string]bool // false means at least one owned flow lacks accounting.
}

func (k *nftCommandIO) telemetryTable() ([]byte, error) {
	return k.command(400*time.Millisecond, "", "-j", "list", "table", "inet", nftTableName)
}

func (n *commandNFTBackend) readTelemetry() (nftTelemetry, error) {
	var result nftTelemetry
	if !n.mu.TryLock() {
		return result, errors.New("kernel_busy")
	}
	ready := n.initialized && !n.unknownState
	epoch, owner, fingerprint := n.metricsEpoch, n.ownerMarker, n.fingerprint
	kernel := n.kernel
	ct, ok := n.conntrack.(*commandConntrack)
	active := append([]nftRuleSpec(nil), n.activeSpecs...)
	known := uniqueNFTSpecs(n.activeSpecs, n.pendingSpecs, n.suspendedSpecs)
	n.mu.Unlock()
	if !ready || !ok || fingerprint == "" {
		return result, errors.New("kernel_unverified")
	}
	var data []byte
	var err error
	if reader, ok := kernel.(interface{ telemetryTable() ([]byte, error) }); ok {
		data, err = reader.telemetryTable()
	} else {
		data, err = kernel.Table()
	}
	if err != nil {
		return result, errors.New("nft_read_failed")
	}
	objects, err := decodeNFTObjects(data)
	if err != nil {
		return result, errors.New("nft_read_failed")
	}
	filtered := objects[:0]
	for _, object := range objects {
		if _, meta := object["metainfo"]; !meta {
			filtered = append(filtered, object)
		}
	}
	objects = filtered
	if nftObjectsFingerprint(objects) != fingerprint {
		return result, errors.New("nft_state_changed")
	}
	hooks, err := parseNFTHookCounters(objects, active, owner, epoch)
	if err != nil {
		return result, err
	}
	result.hooks = hooks
	result.rules = make(map[string]bool)
	for _, spec := range known {
		result.rules[spec.RuleID] = true
	}
	if len(known) == 0 {
		return result, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	// One bounded dump per used family (conntrack defaults to IPv4), under a
	// shared deadline. This read never revokes or authorizes connections.
	families := map[int]bool{}
	for _, spec := range known {
		families[spec.Family] = true
	}
	for _, family := range []int{4, 6} {
		if !families[family] {
			continue
		}
		raw, readErr := ct.command(ctx, "", false, "-L", "-f", fmt.Sprintf("ipv%d", family), "--mark", fmt.Sprintf("0x%08x/0xffffffff", known[0].ConntrackMark), "-o", "xml,id")
		var flows []nftFlowPoint
		if readErr == nil {
			flows, readErr = parseNFTFlowCounters(raw, known, result.rules)
		}
		if readErr != nil || len(result.flows)+len(flows) > maxConntrackRecords {
			for id := range result.rules {
				result.rules[id] = false
			}
			break
		}
		result.flows = append(result.flows, flows...)
	}
	// Retain the previous complete baseline across errors/unaccounted flows.
	// Never partially advance it and later count the same bytes again.
	incomplete := false
	for _, available := range result.rules {
		incomplete = incomplete || !available
	}
	if incomplete {
		result.flows = nil
		for id := range result.rules {
			result.rules[id] = false
		}
	}
	if !n.mu.TryLock() {
		return nftTelemetry{}, errors.New("kernel_busy")
	}
	unchanged := n.metricsEpoch == epoch && n.fingerprint == fingerprint && n.initialized && !n.unknownState
	n.mu.Unlock()
	if !unchanged {
		return nftTelemetry{}, errors.New("nft_state_changed")
	}
	return result, nil
}

func telemetryUint(v any) (uint64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, errors.New("invalid_counter_number")
	}
	return strconv.ParseUint(n.String(), 10, 64)
}

func parseNFTHookCounters(objects []nftObject, specs []nftRuleSpec, owner string, epoch uint64) ([]nftCounterPoint, error) {
	type identity struct{ rule, hook string }
	expected := make(map[string]identity)
	for _, s := range specs {
		for _, hook := range []string{"prerouting", "output", "postrouting", "forward", "flowtable"} {
			comment := nftComment(s, hook)
			if prior, ok := expected[comment]; ok && prior.rule != s.RuleID {
				return nil, errors.New("counter_identity_collision")
			}
			expected[comment] = identity{s.RuleID, hook}
		}
	}
	owned := false
	tableHandle := ""
	for _, o := range objects {
		if table, ok := tableDescriptor(o); ok {
			if owned || table["comment"] != owner {
				return nil, errors.New("counter_table_not_owned")
			}
			owned = true
			tableHandle = fmt.Sprint(table["handle"])
		}
	}
	if !owned {
		return nil, errors.New("counter_table_missing")
	}
	var points []nftCounterPoint
	seen := map[string]bool{}
	for _, o := range objects {
		rule, ok := o["rule"].(map[string]any)
		if !ok {
			continue
		}
		comment, _ := rule["comment"].(string)
		id, ok := expected[comment]
		if !ok {
			continue
		}
		chain := id.hook
		if chain == "flowtable" {
			chain = "forward"
		}
		if rule["family"] != "inet" || rule["table"] != nftTableName || rule["chain"] != chain || seen[comment] {
			return nil, errors.New("counter_identity_invalid")
		}
		seen[comment] = true
		expr, ok := rule["expr"].([]any)
		if !ok {
			return nil, errors.New("counter_expression_invalid")
		}
		count := 0
		for _, v := range expr {
			e, ok := v.(map[string]any)
			if !ok {
				continue
			}
			counter, ok := e["counter"].(map[string]any)
			if !ok {
				continue
			}
			count++
			b, err := telemetryUint(counter["bytes"])
			if err != nil {
				return nil, err
			}
			p, err := telemetryUint(counter["packets"])
			if err != nil {
				return nil, err
			}
			handle, err := telemetryUint(rule["handle"])
			if err != nil {
				return nil, err
			}
			points = append(points, nftCounterPoint{id.rule, id.hook, fmt.Sprintf("%d/%s/%d/%s", epoch, tableHandle, handle, comment), b, p})
		}
		if count != 1 {
			return nil, errors.New("counter_expression_invalid")
		}
	}
	return points, nil
}

func parseNFTFlowCounters(data []byte, specs []nftRuleSpec, available map[string]bool) ([]nftFlowPoint, error) {
	// Reuse the strict tuple decoder, keeping accounting out of its decisions.
	entries, err := parseConntrackXML(data)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	var document struct {
		Flows []conntrackXMLFlow `xml:"flow"`
	}
	if err = xml.Unmarshal(data, &document); err != nil || len(document.Flows) != len(entries) {
		return nil, errors.New("counter_xml_invalid")
	}
	var result []nftFlowPoint
	seen := map[string]bool{}
	steps := 0
	for i, entry := range entries {
		id := ""
		for _, spec := range specs {
			steps++
			if steps > 1<<20 {
				return nil, errors.New("counter_match_budget")
			}
			if conntrackMatchesSpec(entry, spec) {
				if id != "" && id != spec.RuleID {
					return nil, errors.New("counter_ambiguous_flow")
				}
				id = spec.RuleID
			}
		}
		if id == "" {
			continue
		}
		var c trafficCount
		flowID := ""
		directions := 0
		for _, meta := range document.Flows[i].Meta {
			if meta.Direction == "independent" {
				flowID = meta.ID
				continue
			}
			if meta.Counters == nil {
				continue
			}
			b, err := strconv.ParseUint(meta.Counters.Bytes, 10, 64)
			if err != nil {
				return nil, err
			}
			p, err := strconv.ParseUint(meta.Counters.Packets, 10, 64)
			if err != nil {
				return nil, err
			}
			if meta.Direction == "original" {
				c.up, c.packetsUp = b, p
				directions |= 1
			} else if meta.Direction == "reply" {
				c.down, c.packetsDown = b, p
				directions |= 2
			}
		}
		if _, err := strconv.ParseUint(flowID, 10, 32); err != nil || directions != 3 {
			available[id] = false
			continue
		}
		key := fmt.Sprintf("%s/%d/%s/%d/%d/%s/%d/%s/%d/%s/%d/%s/%d", flowID, entry.family, entry.protocol, entry.mark, entry.zone, entry.original.source, entry.original.sourcePort, entry.original.destination, entry.original.destinationPort, entry.reply.source, entry.reply.sourcePort, entry.reply.destination, entry.reply.destinationPort)
		if seen[key] {
			return nil, errors.New("counter_duplicate_flow")
		}
		seen[key] = true
		result = append(result, nftFlowPoint{id, strings.Clone(key), c})
	}
	return result, nil
}
