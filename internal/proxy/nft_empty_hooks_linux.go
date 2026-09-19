package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
)

// This is deliberately NOT a firewall interpreter. Only a known filter base
// chain with policy accept and zero or more restricted transparent accept rules
// is eligible. Every node is checked; unproved conditions, side effects and
// unknown syntax keep the gate. Chains() alone cannot establish this proof.
func verifyNFTCompatibleExternalHooks(reader nftRulesetReader, initial []nftObject) ([]nftObject, uint8, error) {
	remaining, families, _, err := verifyNFTSelectiveExternalHooks(reader, initial, nil)
	return remaining, families, err
}

func verifyNFTSelectiveExternalHooks(reader nftRulesetReader, initial []nftObject, specs []nftRuleSpec) ([]nftObject, uint8, []nftRuleSpec, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, err := os.Readlink("/proc/thread-self/ns/net")
	leader, leaderErr := os.Readlink("/proc/self/ns/net")
	if err != nil || leaderErr != nil || before != leader {
		return nil, 3, nil, errors.New("external-hook proof namespace is not verified")
	}
	var remaining []nftObject
	var permitted []nftRuleSpec
	var firstKey string
	for pass := 0; pass < 2; pass++ {
		data, err := reader.Ruleset()
		if err != nil {
			return nil, 3, nil, err
		}
		objects, err := decodeNFTProofObjects(data)
		if err != nil {
			return nil, 3, nil, err
		}
		current, err := nftConflictingHooks(objects)
		if err != nil {
			return nil, 3, nil, err
		}
		if nftProofInventoryKey(current) != nftProofInventoryKey(initial) {
			return nil, nftHookFamilies(current), nil, errors.New("external hook descriptors changed during rule inspection")
		}
		compatible, err := nftProvablyCompatibleHooks(objects)
		if err != nil {
			return nil, 3, nil, err
		}
		remaining = nil
		for _, object := range current {
			chain := object["chain"].(map[string]any)
			if !compatible[nftHookIdentity(chain)] {
				remaining = append(remaining, object)
			}
		}
		// Compare the entire proof-bearing structure, including rule membership and
		// expressions, not an accept count or a boolean. Unproved chains keep their
		// family gate; their changing counters are never treated as permission.
		var scopedKey string
		permitted, scopedKey, err = nftProveSelectiveScopes(objects, remaining, specs)
		if err != nil {
			return nil, 3, nil, err
		}
		key := nftProofInventoryKey(remaining) + "\nproved:\n" + nftCompatibleHookKey(objects, current, compatible) +
			"\nselective:\n" + scopedKey + "\nscopes:\n" + nftSpecsKey(permitted)
		if pass != 0 && key != firstKey {
			return nil, nftHookFamilies(initial), nil, errors.New("external rules changed during compatibility proof")
		}
		firstKey = key
	}
	after, err := os.Readlink("/proc/thread-self/ns/net")
	leader, leaderErr = os.Readlink("/proc/self/ns/net")
	if err != nil || leaderErr != nil || after != before || after != leader {
		return nil, 3, nil, errors.New("external-hook proof namespace changed")
	}
	return remaining, 0, permitted, nil
}

func nftHookIdentity(chain map[string]any) string {
	return fmt.Sprint(chain["family"]) + "\x00" + fmt.Sprint(chain["table"]) + "\x00" + fmt.Sprint(chain["name"])
}

func nftHookRuleIdentity(rule map[string]any) string {
	return fmt.Sprint(rule["family"]) + "\x00" + fmt.Sprint(rule["table"]) + "\x00" + fmt.Sprint(rule["chain"])
}

// decodeNFTObjects uses json.Number. Display metadata is optional but, when
// present, must have its actual JSON type; strings that look numeric do not count.
func nftHookUint(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	_, err := strconv.ParseUint(string(number), 10, 64)
	return err == nil
}

func nftHookMetadata(fields map[string]any, kind string) bool {
	for key, value := range fields {
		switch key {
		case "family": // already checked by nftProofObject
		case "table":
			if kind == "table" {
				return false
			}
		case "name":
			if kind == "rule" {
				return false
			}
		case "chain", "expr":
			if kind != "rule" {
				return false
			}
		case "type", "hook", "policy":
			if kind != "chain" {
				return false
			}
		case "prio":
			number, ok := value.(json.Number)
			if kind != "chain" || !ok {
				return false
			}
			if _, err := strconv.ParseInt(string(number), 10, 32); err != nil {
				return false
			}
		case "handle":
			if !nftHookUint(value) {
				return false
			}
		case "index":
			if kind != "rule" || !nftHookUint(value) {
				return false
			}
		case "comment":
			if _, ok := value.(string); !ok {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func nftPureAcceptRule(rule map[string]any) bool {
	if !nftHookMetadata(rule, "rule") {
		return false
	}
	expr, ok := rule["expr"].([]any)
	if !ok || len(expr) != 1 {
		return false
	}
	verdict, ok := expr[0].(map[string]any)
	if !ok || len(verdict) != 1 {
		return false
	}
	value, present := verdict["accept"]
	return present && value == nil
}

func nftProvablyCompatibleHooks(objects []nftObject) (map[string]bool, error) {
	tables := make(map[string]map[string]any)
	chains := make(map[string]map[string]any)
	var rules []map[string]any
	flowSeen, metaSeen := false, false
	for _, object := range objects {
		kind, fields, err := nftProofObject(object)
		if err != nil {
			return nil, err
		}
		switch kind {
		case "metainfo":
			if metaSeen {
				return nil, errors.New("duplicate metainfo in external-hook proof")
			}
			metaSeen = true
		case "table":
			name, err := nftProofName(fields, "name")
			if err != nil {
				return nil, err
			}
			key := fmt.Sprint(fields["family"]) + "\x00" + name
			if tables[key] != nil {
				return nil, errors.New("duplicate table in external-hook proof")
			}
			tables[key] = fields
		case "chain":
			if _, err := nftProofName(fields, "table"); err != nil {
				return nil, err
			}
			if _, err := nftProofName(fields, "name"); err != nil {
				return nil, err
			}
			key := nftHookIdentity(fields)
			if chains[key] != nil {
				return nil, errors.New("duplicate chain in external-hook proof")
			}
			chains[key] = fields
		case "rule":
			if _, err := nftProofName(fields, "table"); err != nil {
				return nil, err
			}
			if _, err := nftProofName(fields, "chain"); err != nil {
				return nil, err
			}
			rules = append(rules, fields)
		case "flowtable":
			// Only the existing managed flowtable is in this proof grammar.
			if fields["family"] != "inet" || fields["table"] != nftTableName || fields["name"] != nftFlowtableName || flowSeen {
				return nil, errors.New("external or duplicate flowtable is outside the compatibility proof grammar")
			}
			flowSeen = true
		default:
			return nil, errors.New("external object is outside the compatibility proof grammar")
		}
	}
	if flowSeen && tables["inet\x00"+nftTableName] == nil {
		return nil, errors.New("flowtable has no table in external-hook proof")
	}
	compatible := make(map[string]bool)
	for key, chain := range chains {
		parent := fmt.Sprint(chain["family"]) + "\x00" + fmt.Sprint(chain["table"])
		if tables[parent] == nil {
			return nil, errors.New("chain has no table in external-hook proof")
		}
		_, hasPriority := chain["prio"]
		compatible[key] = chain["policy"] == "accept" && chain["type"] == "filter" &&
			(chain["hook"] == "forward" || chain["hook"] == "postrouting") && hasPriority &&
			nftHookMetadata(chain, "chain") && nftHookMetadata(tables[parent], "table")
	}
	seen := make(map[string]bool)
	for _, rule := range rules {
		key := nftHookRuleIdentity(rule)
		if chains[key] == nil {
			return nil, errors.New("rule has no chain in external-hook proof")
		}
		for _, field := range []string{"handle", "index"} {
			if value, exists := rule[field]; exists && nftHookUint(value) {
				identity := key + "\x00" + field + "\x00" + fmt.Sprint(value)
				if seen[identity] {
					return nil, errors.New("duplicate rule identity in external-hook proof")
				}
				seen[identity] = true
			}
		}
		// A later accept must never undo an earlier unsupported rule.
		family, _ := chains[key]["family"].(string)
		compatible[key] = nftTransparentAcceptRule(rule, family) && compatible[key]
	}
	return compatible, nil
}

// Whole-object order does not change this local all-transparent-accept proof:
// every certified rule can only accept or fall through, without side effects.
// This does not permit reordering unproved rules. Expression arrays (including
// every selector/operator/constant), identities and rule multiplicity remain.
// Managed packet counters and unrelated unproved rules are not proof inputs.
func nftCompatibleHookKey(objects, conflicts []nftObject, compatible map[string]bool) string {
	chains, tables := make(map[string]bool), make(map[string]bool)
	for _, object := range conflicts {
		chain := object["chain"].(map[string]any)
		if key := nftHookIdentity(chain); compatible[key] {
			chains[key] = true
			tables[fmt.Sprint(chain["family"])+"\x00"+fmt.Sprint(chain["table"])] = true
		}
	}
	var proof []nftObject
	for _, object := range objects {
		if chain, ok := object["chain"].(map[string]any); ok && chains[nftHookIdentity(chain)] {
			proof = append(proof, object)
		}
		if rule, ok := object["rule"].(map[string]any); ok && chains[nftHookRuleIdentity(rule)] {
			proof = append(proof, object)
		}
		if table, ok := object["table"].(map[string]any); ok && tables[fmt.Sprint(table["family"])+"\x00"+fmt.Sprint(table["name"])] {
			proof = append(proof, object)
		}
	}
	return nftProofInventoryKey(proof)
}
