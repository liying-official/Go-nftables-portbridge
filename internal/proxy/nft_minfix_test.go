package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"portbridge/internal/config"
)

// This bounded, test-only interpreter applies the emitted transaction, rather
// than copying a wanted terminal state. Only explicitly registered rule texts
// are accepted. It checks object existence and changes objects in command order
// on a private transaction copy. Its expression projections reuse test helpers:
// it proves control flow/selection, NOT Linux parser or flow behaviour (L1).
type causalNFTKernel struct {
	*memoryNFTKernel
	rules    map[string]nftObject
	external []nftObject
	scripts  []string
}

func newCausalNFTKernel(specs ...nftRuleSpec) *causalNFTKernel {
	k := &causalNFTKernel{memoryNFTKernel: &memoryNFTKernel{}, rules: map[string]nftObject{}}
	k.register(specs...)
	return k
}
func (k *causalNFTKernel) register(specs ...nftRuleSpec) {
	for _, s := range specs {
		for _, flow := range []bool{false, true} {
			s.EnableFlowtable = flow
			for _, recovered := range []bool{false, true} {
				spec := s
				if recovered {
					spec.ruleIdentity = nftRuleIdentity(s)
					spec.RuleID = "kernel-" + spec.ruleIdentity
				}
				var b strings.Builder
				writeNFTRules(&b, []nftRuleSpec{spec})
				for i, line := range strings.Split(strings.TrimSpace(b.String()), "\n") {
					hook := []string{"prerouting", "output", "postrouting", "forward"}[i]
					k.rules[line] = nftObject{"rule": nftExpectedRule(spec, hook)}
				}
				for _, role := range []string{"a", "r", "s"} {
					b.Reset()
					var active, pending, suspended []nftRuleSpec
					switch role {
					case "a":
						active = []nftRuleSpec{spec}
					case "r":
						pending = []nftRuleSpec{spec}
					case "s":
						suspended = []nftRuleSpec{spec}
					}
					writeNFTJournal(&b, active, pending, true, nftJournalOptions{suspended: suspended})
					lines := strings.Split(strings.TrimSpace(b.String()), "\n")
					k.rules[lines[len(lines)-1]] = nftObject{"rule": nftExpectedJournalRole(spec, role)}
				}
			}
		}
	}
}

// Both inventories project the same stored objects, including external tables.
// Neither operation supplies a wanted post-transaction state.
func (k *causalNFTKernel) Tables() ([]byte, error) {
	return k.inventory(false)
}
func (k *causalNFTKernel) Chains() ([]byte, error) {
	return k.inventory(true)
}
func (k *causalNFTKernel) inventory(chains bool) ([]byte, error) {
	if k.readErr != nil {
		return nil, k.readErr
	}
	objects := make([]nftObject, 0)
	for _, group := range [][]nftObject{k.objects, k.external} {
		for _, object := range group {
			_, table := object["table"]
			_, chain := object["chain"]
			if table || (chains && chain) {
				objects = append(objects, object)
			}
		}
	}
	return nftTestJSON(objects), nil
}
func (k *causalNFTKernel) Apply(script string) ([]byte, error) {
	k.writes++
	k.scripts = append(k.scripts, script)
	if k.applyErr != nil {
		return nil, k.applyErr
	}
	objects := cloneNFTTestObjects(k.objects)
	exists := func(kind, name string) bool {
		for _, o := range objects {
			if m, ok := o[kind].(map[string]any); ok && m["name"] == name {
				return true
			}
		}
		return false
	}
	comment := func(line string) (string, error) {
		i := strings.Index(line, "comment ")
		if i < 0 {
			return "", nil
		}
		return strconv.Unquote(strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line[i+8:]), "; }")))
	}
	for _, line := range strings.Split(strings.TrimSpace(script), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "inet" || fields[3] != nftTableName {
			return nil, fmt.Errorf("fixture rejects non-owned transaction %q", line)
		}
		switch {
		case strings.HasPrefix(line, "delete table inet portbridge"):
			if line != "delete table inet portbridge" || !exists("table", nftTableName) {
				return nil, errors.New("fixture delete of absent/unrecognized table")
			}
			objects = nil
		case strings.HasPrefix(line, "add table inet portbridge "):
			if exists("table", nftTableName) {
				return nil, errors.New("fixture table already exists")
			}
			owner, err := comment(line)
			if err != nil {
				return nil, err
			}
			objects = append(objects, nftObject{"table": map[string]any{"family": "inet", "name": nftTableName, "comment": owner}})
		case strings.HasPrefix(line, "add chain inet portbridge "):
			if len(fields) < 5 || !exists("table", nftTableName) || exists("chain", fields[4]) {
				return nil, errors.New("fixture chain creation ordering")
			}
			name := fields[4]
			chain := map[string]any{"family": "inet", "table": nftTableName, "name": name}
			if name == nftStateChainName {
				binding, err := comment(line)
				if err != nil {
					return nil, err
				}
				if binding != "" {
					chain["comment"] = binding
				}
				if strings.Contains(line, "hook ") {
					return nil, errors.New("journal must be unhooked")
				}
			} else {
				priority, kind := -100, "nat"
				if name == "postrouting" {
					priority = 100
				}
				if name == "forward" {
					priority = nftForwardPriority
					kind = "filter"
				}
				expected := fmt.Sprintf("add chain inet portbridge %s { type %s hook %s priority ", name, kind, name)
				if !strings.HasPrefix(line, expected) || !strings.HasSuffix(line, "; policy accept; }") {
					return nil, errors.New("unsupported fixture base chain")
				}
				value := strings.TrimSuffix(strings.TrimPrefix(line, expected), "; policy accept; }")
				if value != "dstnat" && value != "srcnat" && value != strconv.Itoa(priority) {
					return nil, errors.New("fixture rejects unexpected priority")
				}
				chain["type"], chain["hook"], chain["prio"], chain["policy"] = kind, name, priority, "accept"
			}
			objects = append(objects, nftObject{"chain": chain})
		case strings.HasPrefix(line, "add flowtable inet portbridge "):
			if !exists("table", nftTableName) || exists("flowtable", nftFlowtableName) || line != `add flowtable inet portbridge fastpath { hook ingress priority filter; devices = { "a", "b" }; counter; }` {
				return nil, fmt.Errorf("unsupported fixture flowtable %q", line)
			}
			objects = append(objects, nftObject{"flowtable": map[string]any{"family": "inet", "table": nftTableName, "name": nftFlowtableName, "hook": "ingress", "prio": 0, "dev": []any{"a", "b"}}})
		case strings.HasPrefix(line, "flush chain inet portbridge "):
			if len(fields) != 5 || !exists("chain", fields[4]) {
				return nil, errors.New("fixture flush of absent chain")
			}
			kept := objects[:0]
			for _, o := range objects {
				if r, ok := o["rule"].(map[string]any); ok && r["chain"] == fields[4] {
					continue
				}
				kept = append(kept, o)
			}
			objects = kept
		case strings.HasPrefix(line, "add rule inet portbridge "):
			rule, ok := k.rules[line]
			if !ok || len(fields) < 5 || !exists("chain", fields[4]) {
				return nil, fmt.Errorf("unregistered or unordered fixture rule %q", line)
			}
			if strings.Contains(line, "flow add @") && !exists("flowtable", nftFlowtableName) {
				return nil, errors.New("fixture rule references missing flowtable")
			}
			objects = append(objects, cloneNFTTestObjects([]nftObject{rule})[0])
		default:
			return nil, fmt.Errorf("unsupported fixture command %q", line)
		}
	}
	k.objects = objects
	if k.afterApply != nil {
		k.afterApply(k.objects)
	}
	return nil, nil
}
func (k *causalNFTKernel) conflict(enabled bool) {
	k.external = nil
	if enabled {
		k.external = []nftObject{{"chain": map[string]any{"family": "inet", "table": "external-control", "name": "after", "type": "filter", "hook": "postrouting", "prio": 0, "policy": "accept"}}}
	}
}
func reviewAB() (nftRuleSpec, nftRuleSpec) {
	a := nftUnitSpec()
	a.RuleID = "review-A"
	b := a
	b.RuleID = "review-B"
	b.ListenPort++
	b.ListenPortEnd++
	return a, b
}
func reviewBackend(k *causalNFTKernel, ct conntrackKernelIO, path string) *commandNFTBackend {
	n := nftUnitBackend(k.memoryNFTKernel)
	n.kernel = k
	n.conntrack = ct
	if path != "" {
		n.store = newNFTStateStore(path)
	}
	return n
}
func privateNFTConfig(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "pb-nft-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "config.json")
}
func requireNFTEntries(t *testing.T, ct *memoryConntrack, want ...conntrackEntry) {
	t.Helper()
	if !reflect.DeepEqual(ct.entries, want) {
		t.Fatalf("unexpected surviving connection identities: got=%d want=%d", len(ct.entries), len(want))
	}
}
func TestReviewAdmissionConflictMustNotPreventRetirement(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, operation := range []string{"disable", "delete", "change-target"} {
			t.Run(protocol+"/"+operation, func(t *testing.T) {
				a, b := reviewAB()
				a.Protocol = protocol
				b.Protocol = protocol
				changed := a
				changed.TargetPort++
				changed.TargetPortEnd++
				k := newCausalNFTKernel(a, b, changed)
				ct := &memoryConntrack{}
				n := reviewBackend(k, ct, privateNFTConfig(t))
				m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
				ra, rb := ruleFromNFTSpec(a), ruleFromNFTSpec(b)
				m.Apply([]config.Rule{ra, rb})
				if !n.initialized || len(n.activeSpecs) != 2 {
					t.Fatalf("A/B setup failed: %+v", m.Runtime())
				}
				one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
				control := one
				control.mark++
				ct.entries = []conntrackEntry{one, two, control}
				beforeWrites := k.writes
				k.conflict(true)
				external := nftTestJSON(k.external)
				var desired []config.Rule
				switch operation {
				case "disable":
					ra.Enabled = false
					desired = []config.Rule{ra, rb}
				case "delete":
					desired = []config.Rule{rb}
				case "change-target":
					ra = ruleFromNFTSpec(changed)
					desired = []config.Rule{ra, rb}
				}
				m.Apply(desired)
				if len(n.activeSpecs) != 0 || len(n.pendingSpecs) != 0 || len(n.suspendedSpecs) != 1 || !nftIdentityMatchesRule(n.suspendedSpecs[0], b.RuleID) {
					t.Fatalf("incorrect retirement/suspension: %+v rows=%+v", n.retirementState(), m.Runtime())
				}
				requireNFTEntries(t, ct, two, control)
				if len(ct.deleted) != 1 || ct.deleted[0] != one {
					t.Fatal("A was not exclusively retired")
				}
				if string(external) != string(nftTestJSON(k.external)) {
					t.Fatal("external chain changed")
				}
				for _, o := range k.objects {
					if r, ok := o["rule"].(map[string]any); ok && r["chain"] != nftStateChainName {
						t.Fatal("unsafe new admission retained")
					}
					if _, ok := o["flowtable"]; ok {
						t.Fatal("policy-incompatible acceleration retained")
					}
				}
				row, _ := runtimeByID(m, b.RuleID)
				if row.KernelState != "admission-suspended" || row.GoRunning || row.Stats.LastError == "" {
					t.Fatalf("B business impact hidden: %+v", row)
				}
				beforeIdle := k.writes
				beforeLists := ct.lists + ct.ownedLists
				m.Refresh(desired)
				m.Refresh(desired)
				if k.writes != beforeIdle || ct.lists+ct.ownedLists != beforeLists {
					t.Fatal("unchanged policy suspension caused writes/connection scans")
				}
				for _, script := range k.scripts[beforeWrites:] {
					t.Logf("L1 actual nft transaction:\n%s", script)
				}
				args, err := conntrackDeleteArguments(one)
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("L1 exact delete selector: %s", strings.Join(args, " "))
				t.Log("A admission removed; A connection retired; new acceleration absent; B conntrack preserved but B NEW admission explicitly suspended (global compatibility remains a release limitation)")
				k.conflict(false)
				m.Refresh(desired)
				if len(n.suspendedSpecs) != 0 || !n.initialized {
					t.Fatalf("conflict removal did not recover: %+v", m.Runtime())
				}
				requireNFTEntries(t, ct, two, control)
				if operation == "delete" {
					m.SetDNSServers(nil)
					if _, ok := runtimeByID(m, a.RuleID); ok {
						t.Fatal("deleted A resurrected on DNS-server update")
					}
				}
			})
		}
	}
}
func TestNFTIndependentStoreTableAndMemoryLoss(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			a, b := reviewAB()
			a.Protocol = protocol
			b.Protocol = protocol
			k := newCausalNFTKernel(a, b)
			ct := &memoryConntrack{}
			path := privateNFTConfig(t)
			n := reviewBackend(k, ct, path)
			m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
			m.Apply([]config.Rule{ruleFromNFTSpec(a), ruleFromNFTSpec(b)})
			if !n.initialized {
				t.Fatalf("setup: %+v", m.Runtime())
			}
			one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
			control := one
			control.mark++
			ct.entries = []conntrackEntry{one, two, control}
			k.objects = nil // loss of the entire table and pb_state, not a simulated read failure
			n = reviewBackend(k, ct, path)
			m = newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
			m.Apply([]config.Rule{ruleFromNFTSpec(b)})
			if !n.initialized || len(n.pendingSpecs) != 0 || len(n.activeSpecs) != 1 {
				t.Fatalf("confirmed independent recovery failed: %+v", m.Runtime())
			}
			requireNFTEntries(t, ct, two, control)
			if len(ct.deleted) != 1 || ct.deleted[0] != one {
				t.Fatal("recovered cleanup crossed A ownership")
			}
			// A subsequent process restart and refresh must not touch B or rewrite state.
			writes := k.writes
			data, err := os.ReadFile(path + ".nft-state.json")
			if err != nil {
				t.Fatal(err)
			}
			n = reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{b}); err != nil {
				t.Fatal(err)
			}
			if k.writes != writes {
				t.Fatal("normal restart changed B objects")
			}
			requireNFTEntries(t, ct, two, control)
			after, err := os.ReadFile(path + ".nft-state.json")
			if err != nil || string(after) != string(data) {
				t.Fatal("unchanged recovery checkpoint changed")
			}
		})
	}
}
func TestNFTIndependentStoreIntentIsNotOwnership(t *testing.T) {
	a, _ := reviewAB()
	k := newCausalNFTKernel(a)
	ct := &memoryConntrack{}
	path := privateNFTConfig(t)
	n := reviewBackend(k, ct, path)
	k.applyErr = context.DeadlineExceeded
	if err := n.Replace([]nftRuleSpec{a}); err == nil {
		t.Fatal("write timeout hidden")
	}
	if len(k.objects) != 0 {
		t.Fatal("failed transaction changed objects")
	}
	k.applyErr = nil
	one := conntrackUnitEntry(a, 45000)
	ct.entries = []conntrackEntry{one}
	before := k.writes
	n = reviewBackend(k, ct, path)
	if err := n.Replace(nil); err == nil {
		t.Fatal("prepare-only tuple was treated as confirmed historical ownership")
	}
	requireNFTEntries(t, ct, one)
	if k.writes != before || ct.deletes != 0 {
		t.Fatal("unconfirmed orphan mutated")
	}
}
func TestNFTIndependentStorePostApplyCheckpointCrash(t *testing.T) {
	a, b := reviewAB()
	k := newCausalNFTKernel(a, b)
	ct := &memoryConntrack{}
	path := privateNFTConfig(t)
	n := reviewBackend(k, ct, path)
	calls := 0
	n.store.fault = func(stage string) error {
		if stage == "rename" {
			calls++
			if calls == 2 {
				return errors.New("checkpoint crash")
			}
		}
		return nil
	}
	if err := n.Replace([]nftRuleSpec{a, b}); err == nil {
		t.Fatal("checkpoint failure hidden")
	}
	if len(k.objects) == 0 || n.initialized {
		t.Fatal("post-apply failure not exposed")
	}
	one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
	ct.entries = []conntrackEntry{one, two}
	n = reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{b}); err != nil {
		t.Fatal(err)
	}
	requireNFTEntries(t, ct, two)
}
func TestNFTIndependentStoreWriteFailuresStillGateKnownAdmission(t *testing.T) {
	for _, stage := range []string{"create", "write", "file-sync", "rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			a, b := reviewAB()
			k := newCausalNFTKernel(a, b)
			ct := &memoryConntrack{}
			path := privateNFTConfig(t)
			n := reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{a, b}); err != nil {
				t.Fatal(err)
			}
			one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
			ct.entries = []conntrackEntry{one, two}
			n.store.fault = func(s string) error {
				if s == stage {
					return errors.New("injected disk failure")
				}
				return nil
			}
			if err := n.Replace([]nftRuleSpec{b}); err == nil {
				t.Fatal("durability failure hidden")
			}
			for _, s := range n.activeSpecs {
				if nftIdentityMatchesRule(s, a.RuleID) {
					t.Fatal("disk failure prevented independently safe admission withdrawal")
				}
			}
			requireNFTEntries(t, ct, one, two)
			if len(n.pendingSpecs) == 0 {
				t.Fatal("failed durability lost retirement scope")
			}
			n = reviewBackend(k, ct, path)
			if err := n.Replace([]nftRuleSpec{b}); err != nil {
				t.Fatal(err)
			}
			requireNFTEntries(t, ct, two)
		})
	}
}
func TestNFTIndependentStoreDeleteFailureSurvivesRecreation(t *testing.T) {
	a, b := reviewAB()
	k := newCausalNFTKernel(a, b)
	ct := &memoryConntrack{}
	path := privateNFTConfig(t)
	n := reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{a, b}); err != nil {
		t.Fatal(err)
	}
	one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
	ct.entries = []conntrackEntry{one, two}
	ct.deleteErr = context.DeadlineExceeded
	if err := n.Replace([]nftRuleSpec{b}); err == nil {
		t.Fatal("delete deadline hidden")
	}
	k.objects = nil
	n = reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{b}); err == nil {
		t.Fatal("restart cleared delete failure")
	}
	requireNFTEntries(t, ct, one, two)
	ct.deleteErr = nil
	n = reviewBackend(k, ct, path)
	if err := n.Replace([]nftRuleSpec{b}); err != nil {
		t.Fatal(err)
	}
	requireNFTEntries(t, ct, two)
}
