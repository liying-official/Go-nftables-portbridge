package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const maxNFTProofObjects = 65536

// Additional inventory proofs are uncommon control-plane operations, never
// packet-path work. Reject duplicate JSON keys, partial/unknown envelopes and
// excessive object counts before using an observation to narrow a safety gate.
func decodeNFTProofObjects(data []byte) ([]nftObject, error) {
	if len(data) > maxNFTOutputBytes {
		return nil, errNFTOutputLimit
	}
	var envelope struct {
		Objects []json.RawMessage `json:"nftables"`
	}
	if err := strictNFTDiskJSON(data, &envelope); err != nil {
		return nil, fmt.Errorf("unverifiable nft inventory: %w", err)
	}
	if envelope.Objects == nil || len(envelope.Objects) > maxNFTProofObjects {
		return nil, errors.New("missing or oversized nft proof inventory")
	}
	return decodeNFTObjects(data)
}

// The kernel CLI may include metainfo, but every other inventory descriptor
// must have an unambiguous kind and a known family. This is not rule evaluation.
func nftProofObject(object nftObject) (string, map[string]any, error) {
	if len(object) != 1 {
		return "", nil, errors.New("ambiguous nft inventory object")
	}
	for kind, value := range object {
		fields, ok := value.(map[string]any)
		if !ok {
			return "", nil, errors.New("invalid nft inventory descriptor")
		}
		if kind == "metainfo" {
			return kind, fields, nil
		}
		switch fields["family"] {
		case "ip", "ip6", "inet", "arp", "bridge", "netdev":
		default:
			return "", nil, errors.New("unknown nft inventory family")
		}
		return kind, fields, nil
	}
	return "", nil, errors.New("empty nft inventory object")
}

func nftProofName(fields map[string]any, key string) (string, error) {
	value, ok := fields[key].(string)
	if !ok || value == "" || strings.ContainsRune(value, '\x00') {
		return "", errors.New("incomplete nft inventory identity")
	}
	return value, nil
}

// Preserve handles here: replacement with the same names between snapshots is
// a contradictory observation, not a stable proof. Order of inventory objects
// is irrelevant; no rule-order inference is made by this helper.
func nftProofInventoryKey(objects []nftObject) string {
	parts := make([]string, 0, len(objects))
	for _, object := range objects {
		if _, meta := object["metainfo"]; meta {
			continue
		}
		data, _ := json.Marshal(object)
		parts = append(parts, string(data))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}

// Called with the writer lock and the session's OS thread held. A different
// trusted boot is checked by the store BEFORE entering this function. Unlike
// verifyEmptyNetfilter, this only excludes CURRENT instance risks. It neither
// imports old history nor deletes any table or connection, even on failure.
func (n *commandNFTBackend) verifyNewBootScope(expected nftDiskContext) error {
	if n.store == nil || n.kernel == nil || n.conntrack == nil || n.initErr != nil {
		return errors.New("boot scope readers are unavailable")
	}
	if err := n.conntrack.Available(); err != nil {
		return fmt.Errorf("boot scope conntrack reader unavailable: %w", err)
	}
	mark, err := n.configuredMark()
	if err != nil || expected.Owner != n.ownerMarker {
		return errors.New("boot scope instance identity mismatch")
	}
	checkContext := func() error {
		current, err := nftCurrentDiskContext(n.store.configPath, n.ownerMarker)
		if err != nil || current != expected {
			return errors.New("boot scope lifecycle or namespace changed")
		}
		return nil
	}
	if err := checkContext(); err != nil {
		return err
	}
	var previous string
	for pass := 0; pass < 2; pass++ {
		key, err := n.readBootScopeInventory(expected)
		if err != nil {
			return err
		}
		if pass != 0 && key != previous {
			return errors.New("nft inventory changed during boot scope verification")
		}
		previous = key
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		entries, err := n.conntrack.ListOwned(ctx, mark)
		cancel()
		if err != nil {
			return fmt.Errorf("read boot scope connection candidates: %w", err)
		}
		// A mark is only a risk filter. Even an identical old tuple is NOT
		// attributed to old Confirmed/Intent and MUST NOT be deleted here.
		if len(entries) != 0 {
			return errors.New("current marked connection candidates prevent boot rollover; current ownership proof is required")
		}
		if err := checkContext(); err != nil {
			return err
		}
	}
	return nil
}

func (n *commandNFTBackend) readBootScopeInventory(expected nftDiskContext) (string, error) {
	data, err := n.kernel.Tables()
	if err != nil {
		return "", fmt.Errorf("read boot scope tables: %w", err)
	}
	tables, err := decodeNFTProofObjects(data)
	if err != nil {
		return "", err
	}
	seen := make(map[string]bool)
	checkTable := func(fields map[string]any) (string, error) {
		name, err := nftProofName(fields, "name")
		if err != nil {
			return "", err
		}
		if name == nftTableName || fields["comment"] == expected.Owner {
			return "", errors.New("current managed-name or instance-marked table prevents boot rollover")
		}
		return fmt.Sprint(fields["family"]) + "\x00" + name, nil
	}
	for _, object := range tables {
		kind, fields, err := nftProofObject(object)
		if err != nil {
			return "", err
		}
		if kind == "metainfo" {
			continue
		}
		if kind != "table" {
			return "", errors.New("unexpected object in boot table inventory")
		}
		key, err := checkTable(fields)
		if err != nil {
			return "", err
		}
		if seen[key] {
			return "", errors.New("duplicate table in boot inventory")
		}
		seen[key] = true
	}
	data, err = n.kernel.Chains()
	if err != nil {
		return "", fmt.Errorf("read boot scope bindings: %w", err)
	}
	chains, err := decodeNFTProofObjects(data)
	if err != nil {
		return "", err
	}
	chainIDs := make(map[string]bool)
	listedTables := make(map[string]bool)
	for _, object := range chains {
		kind, fields, err := nftProofObject(object)
		if err != nil {
			return "", err
		}
		switch kind {
		case "metainfo":
			continue
		case "table":
			key, err := checkTable(fields)
			if err != nil {
				return "", err
			}
			if !seen[key] || listedTables[key] {
				return "", errors.New("inconsistent boot table/chain inventory")
			}
			listedTables[key] = true
		case "chain":
			table, err := nftProofName(fields, "table")
			if err != nil {
				return "", err
			}
			name, err := nftProofName(fields, "name")
			if err != nil {
				return "", err
			}
			parent := fmt.Sprint(fields["family"]) + "\x00" + table
			key := parent + "\x00" + name
			if !seen[parent] || chainIDs[key] {
				return "", errors.New("unbound or duplicate boot chain descriptor")
			}
			chainIDs[key] = true
			if comment, ok := fields["comment"].(string); ok && strings.HasPrefix(comment, "pb-disk:v1:"+expected.ConfigSHA256+":") {
				return "", errors.New("current recovery binding prevents boot rollover")
			}
		default:
			return "", errors.New("unexpected object in boot chain inventory")
		}
	}
	return nftProofInventoryKey(tables) + "\nchains:\n" + nftProofInventoryKey(chains), nil
}
