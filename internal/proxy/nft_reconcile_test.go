package proxy

import (
	"errors"
	"strings"
	"testing"

	"portbridge/internal/config"
)

func ruleFromNFTSpec(spec nftRuleSpec) config.Rule {
	return config.NormalizeRule(config.Rule{ID: spec.RuleID, Name: spec.RuleID, Protocol: spec.Protocol, Enabled: true,
		ListenHost: spec.ListenHost.String(), ListenPort: spec.ListenPort, ListenPortEnd: spec.ListenPortEnd,
		TargetHost: spec.TargetHost.String(), TargetPort: spec.TargetPort, TargetPortEnd: spec.TargetPortEnd})
}
func runtimeByID(m *Manager, id string) (RuleRuntime, bool) {
	for _, row := range m.Runtime() {
		if row.Rule.ID == id {
			return row, true
		}
	}
	return RuleRuntime{}, false
}

func TestNFTRetirementFailureSurvivesRecoveryAndKeepsOtherRule(t *testing.T) {
	a := nftUnitSpec()
	b := a
	b.RuleID = "other-rule"
	b.ListenPort++
	b.ListenPortEnd++
	k := &memoryNFTKernel{wanted: nftUnitStateObjects([]nftRuleSpec{a, b}, nil, false)}
	ct := &memoryConntrack{}
	backend := nftUnitBackend(k)
	backend.conntrack = ct
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), backend)
	ra, rb := ruleFromNFTSpec(a), ruleFromNFTSpec(b)
	m.Apply([]config.Rule{ra, rb})
	if row, ok := runtimeByID(m, ra.ID); !ok || !row.Stats.Running {
		t.Fatal("initial native paths not installed")
	}
	one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
	control := one
	control.mark++
	ct.entries = []conntrackEntry{one, two, control}
	ct.deleteErr = errors.New("injected deletion failure")
	k.wanted = nftUnitStateObjects([]nftRuleSpec{b}, []nftRuleSpec{a}, true)
	ra.Enabled = false
	m.Apply([]config.Rule{ra, rb})
	for _, manager := range []*Manager{m} {
		row, _ := runtimeByID(manager, ra.ID)
		if !row.Stats.Running || !strings.Contains(row.Stats.LastError, "revocation") {
			t.Fatal("unsafe disable was presented as complete")
		}
		row, _ = runtimeByID(manager, rb.ID)
		if !row.Stats.Running || row.Stats.LastError != "" {
			t.Fatalf("unrelated verified B was marked broken: %+v", row)
		}
	}
	journal, err := decodeNFTJournal(k.objects, backend.ownerMarker)
	if err != nil || len(journal.retired) != 1 || len(journal.active) != 1 {
		t.Fatalf("pending journal missing: %+v %v", journal, err)
	}
	// A fresh backend/manager has no old process memory. Its only recovery
	// input is the same structured kernel journal.
	recovered := nftUnitBackend(k)
	recovered.conntrack = ct
	m2 := newManagerWithNFT(testLogger(), NewDNSResolver(nil), recovered)
	m2.Apply([]config.Rule{ra, rb})
	if row, _ := runtimeByID(m2, ra.ID); !row.Stats.Running || row.Stats.LastError == "" {
		t.Fatal("recovery lost pending retirement")
	}
	m2.Apply([]config.Rule{rb})
	m2.SetDNSServers(nil)
	if _, present := m2.desiredRules[ra.ID]; present {
		t.Fatal("DNS change resurrected a deleted rule")
	}
	for _, spec := range recovered.activeSpecs {
		if nftIdentityMatchesRule(spec, ra.ID) {
			t.Fatal("deleted admission was reinstalled")
		}
	}
	ct.deleteErr = nil
	k.wanted = nftUnitStateObjects([]nftRuleSpec{b}, nil, false)
	m2.Refresh([]config.Rule{rb})
	if _, present := runtimeByID(m2, ra.ID); present {
		t.Fatal("retirement tombstone was not removed after verified cleanup")
	}
	if len(ct.entries) != 2 || ct.entries[0] != two || ct.entries[1] != control {
		t.Fatal("revocation damaged B or another instance")
	}
	if row, _ := runtimeByID(m2, rb.ID); !row.Stats.Running || row.Stats.LastError != "" {
		t.Fatal("B did not remain healthy")
	}
}

func TestNFTRecoveryRefusesUnattributableOrphan(t *testing.T) {
	spec := nftUnitSpec()
	k := &memoryNFTKernel{}
	ct := &memoryConntrack{entries: []conntrackEntry{conntrackUnitEntry(spec, 45000)}}
	n := nftUnitBackend(k)
	n.conntrack = ct
	if err := n.Replace([]nftRuleSpec{spec}); err == nil {
		t.Fatal("orphaned state was guessed from a shared mark")
	}
	if k.writes != 0 || ct.deletes != 0 || !n.retirementState().Unknown {
		t.Fatal("unknown state was mutated or hidden")
	}
}

func TestNFTJournalLongRuleIdentityAndNoHook(t *testing.T) {
	spec := nftUnitSpec()
	spec.RuleID = strings.Repeat("q", 128)
	objects := nftUnitStateObjects([]nftRuleSpec{spec}, []nftRuleSpec{spec}, false)
	journal, err := decodeNFTJournal(objects, nftOwnerMarker(spec.ConntrackMark))
	if err != nil || !journal.present || len(journal.active) != 1 || len(journal.retired) != 1 {
		t.Fatalf("journal decode: %+v %v", journal, err)
	}
	if nftRuleIdentity(journal.active[0]) != nftRuleIdentity(spec) {
		t.Fatal("long rule identity did not survive recovery")
	}
	if len(nftJournalComment(spec, true)) > 127 {
		t.Fatal("journal comment exceeds nft comment bound")
	}
	for _, object := range objects {
		if chain, ok := object["chain"].(map[string]any); ok && chain["name"] == nftStateChainName {
			chain["hook"] = "forward"
		}
	}
	if _, err := decodeNFTJournal(objects, nftOwnerMarker(spec.ConntrackMark)); err == nil {
		t.Fatal("hooked metadata chain was accepted")
	}
}
