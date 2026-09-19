package proxy

import (
	"errors"
	"fmt"
	"strconv"
)

// A policy rejection is different from an unreadable/unowned kernel. Only this
// typed result permits the Manager to proceed to attributable retirement.
type nftAdmissionError struct {
	families      uint8
	inspectionErr error         // a failed OPTIONAL compatibility proof does not stop safe retirement
	permitted     []nftRuleSpec // ephemeral, rule-scoped proof from two current snapshots
}

func (e *nftAdmissionError) Error() string {
	message := "external firewall hook compatibility is not proven for acceleration; affected new NFT admission is suspended, previous unrelated conntrack is retained; explicit policy/mode coordination is required"
	if e.inspectionErr != nil {
		message += "; restricted transparent-accept compatibility proof unavailable: " + e.inspectionErr.Error()
	}
	return message
}
func (e *nftAdmissionError) Unwrap() error { return e.inspectionErr }
func (e *nftAdmissionError) affects(spec nftRuleSpec) bool {
	mask := uint8(1)
	if spec.Family == 6 {
		mask = 2
	}
	if !spec.EnableFlowtable || e.families&mask == 0 {
		return false
	}
	for _, allowed := range e.permitted {
		if nftSelectiveScopeCovers(allowed, spec) {
			return false
		}
	}
	return true
}

// Hook placement only: never infer the semantics of arbitrary firewall rules.
func (n *commandNFTBackend) checkFlowtableAdmission() error {
	return n.checkFlowtableAdmissionFor(nil)
}
func (n *commandNFTBackend) checkFlowtableAdmissionFor(specs []nftRuleSpec) error {
	data, err := n.kernel.Chains()
	if err != nil {
		return fmt.Errorf("inspect firewall hook ordering: %w", err)
	}
	objects, err := decodeNFTObjects(data)
	if err != nil {
		return err
	}
	conflicts, err := nftConflictingHooks(objects)
	if err != nil {
		return err
	}
	if len(conflicts) == 0 {
		return nil
	}
	rejected := nftHookFamilies(conflicts)
	var permitted []nftRuleSpec
	if reader, ok := n.kernel.(nftRulesetReader); ok {
		remaining, extraFamilies, allowed, proofErr := verifyNFTSelectiveExternalHooks(reader, conflicts, specs)
		if proofErr != nil {
			// Chains already established a policy risk. Failing an optional
			// narrowing proof must not restore that admission OR short-circuit
			// independently owned A retirement in Manager/Replace.
			return &nftAdmissionError{families: rejected | extraFamilies, inspectionErr: proofErr}
		}
		rejected = nftHookFamilies(remaining)
		permitted = allowed
	}
	if rejected != 0 {
		return &nftAdmissionError{families: rejected, permitted: permitted}
	}
	return nil
}

// Descriptor-only fakes/readers retain the original conservative gate. Empty
// policy metadata alone never proves that a real chain contains no rules.
func nftConflictingHooks(objects []nftObject) ([]nftObject, error) {
	var conflicts []nftObject
	for _, object := range objects {
		chain, ok := object["chain"].(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"family", "table", "name"} {
			if value, ok := chain[field].(string); !ok || value == "" {
				return nil, errors.New("incomplete firewall chain descriptor")
			}
		}
		if chain["hook"] == nil {
			continue
		}
		if hook, ok := chain["hook"].(string); !ok || hook == "" {
			return nil, errors.New("invalid firewall base-chain hook")
		}
		if kind, ok := chain["type"].(string); !ok || kind == "" {
			return nil, errors.New("incomplete firewall base-chain type")
		}
		if _, err := strconv.ParseInt(fmt.Sprint(chain["prio"]), 10, 32); err != nil {
			return nil, errors.New("cannot verify external hook priority")
		}
		family := chain["family"]
		switch family {
		case "inet", "ip", "ip6":
		default:
			continue
		}
		if family == "inet" && chain["table"] == nftTableName {
			continue
		}
		if chain["hook"] == "forward" {
			priority, err := strconv.ParseInt(fmt.Sprint(chain["prio"]), 10, 32)
			if err != nil {
				return nil, errors.New("cannot verify external forward hook priority")
			}
			if priority >= nftForwardPriority {
				conflicts = append(conflicts, nftObject{"chain": chain})
			}
		}
		if chain["hook"] == "postrouting" && chain["type"] != "nat" {
			conflicts = append(conflicts, nftObject{"chain": chain})
		}
	}
	return conflicts, nil
}

func nftHookFamilies(chains []nftObject) uint8 {
	var mask uint8
	for _, object := range chains {
		chain, _ := object["chain"].(map[string]any)
		switch chain["family"] {
		case "ip":
			mask |= 1
		case "ip6":
			mask |= 2
		case "inet":
			mask |= 3
		}
	}
	return mask
}

func (n *commandNFTBackend) checkAdmissionFor(specs []nftRuleSpec) error {
	err := n.checkFlowtableAdmissionFor(specs)
	var admission *nftAdmissionError
	if !errors.As(err, &admission) {
		return err
	}
	for _, spec := range specs {
		if admission.affects(spec) {
			return admission
		}
	}
	return nil
}
