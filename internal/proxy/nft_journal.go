package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Avoid contextual nft lexer keywords (notably TCP's "state").
const nftStateChainName = "pb_state"
const maxNFTRetiredSpecs = configMaxNFTPaths * 4
const configMaxNFTPaths = 4096

type nftJournalState struct {
	active, retired, suspended []nftRuleSpec
	binding                    string
	present                    bool
}

func nftRuleIdentity(spec nftRuleSpec) string {
	if spec.ruleIdentity != "" {
		return spec.ruleIdentity
	}
	sum := sha256.Sum256([]byte(spec.RuleID))
	return hex.EncodeToString(sum[:])
}

func (n *commandNFTBackend) configuredMark() (uint32, error) {
	const prefix = nftOwnerPrefix + ":"
	if !strings.HasPrefix(n.ownerMarker, prefix) {
		return 0, errors.New("invalid configured nftables owner")
	}
	mark, err := strconv.ParseUint(strings.TrimPrefix(n.ownerMarker, prefix), 16, 32)
	if err != nil || mark == 0 {
		return 0, errors.New("invalid configured nftables mark")
	}
	return uint32(mark), nil
}
func nftRuleShortTag(spec nftRuleSpec) string {
	id := nftRuleIdentity(spec)
	if len(id) == 13 && id[0] == 'l' {
		return id[1:]
	}
	return id[:12]
}
func nftJournalComment(spec nftRuleSpec, retired bool) string {
	role := "a"
	if retired {
		role = "r"
	}
	return nftJournalRoleComment(spec, role)
}
func nftJournalRoleComment(spec nftRuleSpec, role string) string {
	flag := "0"
	if spec.EnableFlowtable {
		flag = "1"
	}
	return fmt.Sprintf("pb-state:v1:%s:%d:%s:%s:%s", nftRuleIdentity(spec), spec.Family, spec.Protocol, role, flag)
}

type nftJournalOptions struct {
	suspended []nftRuleSpec
	binding   string
}

func writeNFTJournal(b *strings.Builder, active, retired []nftRuleSpec, create bool, options ...nftJournalOptions) {
	var opt nftJournalOptions
	if len(options) > 0 {
		opt = options[0]
	}
	if create {
		if opt.binding != "" {
			fmt.Fprintf(b, "add chain inet %s %s { comment %q; }\n", nftTableName, nftStateChainName, opt.binding)
		} else {
			fmt.Fprintf(b, "add chain inet %s %s\n", nftTableName, nftStateChainName)
		}
	} else {
		fmt.Fprintf(b, "flush chain inet %s %s\n", nftTableName, nftStateChainName)
	}
	for index, specs := range [][]nftRuleSpec{active, retired, opt.suspended} {
		for _, spec := range specs {
			family := "ip6"
			if spec.Family == 4 {
				family = "ip"
			}
			// This regular chain has no hook and is never jumped to. Its
			// counter-only records preserve identities across process failure.
			fmt.Fprintf(b, "add rule inet %s %s %s daddr %s %s saddr %s %s sport %s %s dport %s ct mark 0x%08x counter comment %q\n",
				nftTableName, nftStateChainName, family, spec.ListenHost, family, spec.TargetHost, spec.Protocol,
				portText(spec.TargetPort, spec.TargetPortEnd), spec.Protocol, portText(spec.ListenPort, spec.ListenPortEnd),
				spec.ConntrackMark, nftJournalRoleComment(spec, []string{"a", "r", "s"}[index]))
		}
	}
}
func nftExpectedJournalRule(spec nftRuleSpec, retired bool) map[string]any {
	role := "a"
	if retired {
		role = "r"
	}
	return nftExpectedJournalRole(spec, role)
}
func nftExpectedJournalRole(spec nftRuleSpec, role string) map[string]any {
	family := "ip6"
	if spec.Family == 4 {
		family = "ip"
	}
	match := func(left, right any) any {
		return map[string]any{"match": map[string]any{"op": "==", "left": left, "right": right}}
	}
	payload := func(protocol, field string) any {
		return map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}
	}
	port := func(first, last int) any {
		if last == 0 || last == first {
			return first
		}
		return map[string]any{"range": []any{first, last}}
	}
	return map[string]any{"family": "inet", "table": nftTableName, "chain": nftStateChainName, "comment": nftJournalRoleComment(spec, role),
		"expr": []any{match(payload(family, "daddr"), spec.ListenHost.String()), match(payload(family, "saddr"), spec.TargetHost.String()),
			match(payload(spec.Protocol, "sport"), port(spec.TargetPort, spec.TargetPortEnd)),
			match(payload(spec.Protocol, "dport"), port(spec.ListenPort, spec.ListenPortEnd)),
			match(map[string]any{"ct": map[string]any{"key": "mark"}}, spec.ConntrackMark), map[string]any{"counter": map[string]any{}}}}
}

func nftJSONUint(value any, bits int) (uint64, error) {
	return strconv.ParseUint(fmt.Sprint(value), 10, bits)
}
func nftJSONPortRange(value any) (int, int, error) {
	if m, ok := value.(map[string]any); ok {
		pair, ok := m["range"].([]any)
		if !ok || len(pair) != 2 {
			return 0, 0, errors.New("invalid nftables port range")
		}
		a, err := nftJSONUint(pair[0], 16)
		if err != nil {
			return 0, 0, err
		}
		b, err := nftJSONUint(pair[1], 16)
		if err != nil || a == 0 || b < a {
			return 0, 0, errors.New("invalid nftables port range")
		}
		return int(a), int(b), nil
	}
	port, err := nftJSONUint(value, 16)
	if err != nil || port == 0 {
		return 0, 0, errors.New("invalid nftables port")
	}
	return int(port), int(port), nil
}
func nftPayloadMatch(expression any) (protocol, field string, right any, ok bool) {
	object, ok := expression.(map[string]any)
	if !ok {
		return "", "", nil, false
	}
	match, ok := object["match"].(map[string]any)
	if !ok || match["op"] != "==" {
		return "", "", nil, false
	}
	left, ok := match["left"].(map[string]any)
	if !ok {
		return "", "", nil, false
	}
	payload, ok := left["payload"].(map[string]any)
	if !ok {
		return "", "", nil, false
	}
	protocol, _ = payload["protocol"].(string)
	field, _ = payload["field"].(string)
	return protocol, field, match["right"], true
}
func validNFTIdentity(id string) bool {
	raw := id
	if len(id) == 13 && id[0] == 'l' {
		raw = id[1:]
	} else if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}
func decodeNFTJournal(objects []nftObject, owner string) (nftJournalState, error) {
	var journal nftJournalState
	for _, object := range objects {
		if chain, ok := object["chain"].(map[string]any); ok && chain["name"] == nftStateChainName {
			if journal.present || chain["hook"] != nil || chain["type"] != nil || chain["policy"] != nil {
				return journal, errors.New("invalid hooked nftables state journal")
			}
			journal.present = true
			if chain["family"] != "inet" || chain["table"] != nftTableName {
				return journal, errors.New("foreign nftables recovery chain")
			}
			if v, exists := chain["comment"]; exists {
				var ok bool
				journal.binding, ok = v.(string)
				if !ok {
					return journal, errors.New("invalid recovery binding")
				}
			}
		}
	}
	if !journal.present {
		return journal, nil
	}
	for _, object := range objects {
		rule, ok := object["rule"].(map[string]any)
		if !ok || rule["chain"] != nftStateChainName {
			continue
		}
		if len(journal.active)+len(journal.retired)+len(journal.suspended) >= maxNFTRetiredSpecs {
			return journal, errors.New("nftables state journal exceeds limit")
		}
		comment, _ := rule["comment"].(string)
		parts := strings.Split(comment, ":")
		if len(parts) != 7 || parts[0] != "pb-state" || parts[1] != "v1" || !validNFTIdentity(parts[2]) || (parts[5] != "a" && parts[5] != "r" && parts[5] != "s") || (parts[6] != "0" && parts[6] != "1") {
			return journal, errors.New("invalid nftables state journal identity")
		}
		family, err := strconv.Atoi(parts[3])
		if err != nil {
			return journal, errors.New("invalid journal family")
		}
		spec := nftRuleSpec{RuleID: "kernel-" + parts[2], ruleIdentity: parts[2], Family: family, Protocol: parts[4], EnableFlowtable: parts[6] == "1"}
		expr, ok := rule["expr"].([]any)
		if !ok {
			return journal, errors.New("invalid journal expressions")
		}
		ipProtocol := "ip6"
		if family == 4 {
			ipProtocol = "ip"
		}
		for _, item := range expr {
			protocol, field, right, ok := nftPayloadMatch(item)
			if ok {
				switch {
				case protocol == ipProtocol && field == "daddr":
					raw, _ := right.(string)
					spec.ListenHost, err = netip.ParseAddr(raw)
				case protocol == ipProtocol && field == "saddr":
					raw, _ := right.(string)
					spec.TargetHost, err = netip.ParseAddr(raw)
				case protocol == spec.Protocol && field == "dport":
					spec.ListenPort, spec.ListenPortEnd, err = nftJSONPortRange(right)
				case protocol == spec.Protocol && field == "sport":
					spec.TargetPort, spec.TargetPortEnd, err = nftJSONPortRange(right)
				}
				if err != nil {
					return journal, errors.New("invalid journal tuple")
				}
			}
			if item, ok := item.(map[string]any); ok {
				if match, ok := item["match"].(map[string]any); ok {
					if left, ok := match["left"].(map[string]any); ok {
						if ct, ok := left["ct"].(map[string]any); ok && ct["key"] == "mark" {
							mark, e := nftJSONUint(match["right"], 32)
							if e != nil {
								return journal, e
							}
							spec.ConntrackMark = uint32(mark)
						}
					}
				}
			}
		}
		if err := validateRetirementSpec(spec); err != nil || nftOwnerMarker(spec.ConntrackMark) != owner {
			return journal, errors.New("journal does not belong to the configured nftables instance")
		}
		if nftRuleInspectionKey(rule) != nftRuleInspectionKey(nftExpectedJournalRole(spec, parts[5])) {
			return journal, errors.New("journal policy fields are malformed")
		}
		if parts[5] == "r" {
			journal.retired = append(journal.retired, spec)
		} else if parts[5] == "s" {
			journal.suspended = append(journal.suspended, spec)
		} else {
			journal.active = append(journal.active, spec)
		}
	}
	return journal, nil
}
