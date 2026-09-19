package proxy

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type memoryConntrack struct {
	entries, deleted                 []conntrackEntry
	availableErr, listErr, deleteErr error
	lists, deletes, ownedLists       int
}

func (c *memoryConntrack) Available() error { return c.availableErr }
func (c *memoryConntrack) List(ctx context.Context, _ nftRuleSpec) ([]conntrackEntry, error) {
	c.lists++
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if c.listErr != nil {
		return nil, c.listErr
	}
	return append([]conntrackEntry(nil), c.entries...), nil
}
func (c *memoryConntrack) ListOwned(ctx context.Context, mark uint32) ([]conntrackEntry, error) {
	c.ownedLists++
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if c.listErr != nil {
		return nil, c.listErr
	}
	var entries []conntrackEntry
	for _, entry := range c.entries {
		if entry.mark == mark {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}
func (c *memoryConntrack) Delete(ctx context.Context, entries []conntrackEntry) error {
	c.deletes++
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if c.deleteErr != nil {
		return c.deleteErr
	}
	c.deleted = append(c.deleted, entries...)
	var keep []conntrackEntry
	for _, current := range c.entries {
		remove := false
		for _, entry := range entries {
			if entry == current {
				remove = true
				break
			}
		}
		if !remove {
			keep = append(keep, current)
		}
	}
	c.entries = keep
	return nil
}

func conntrackUnitEntry(spec nftRuleSpec, sourcePort uint16) conntrackEntry {
	originalDst := spec.ListenHost
	if originalDst.IsUnspecified() {
		originalDst = netip.MustParseAddr("192.0.2.1")
	}
	return conntrackEntry{family: spec.Family, protocol: spec.Protocol, mark: spec.ConntrackMark,
		original: conntrackTuple{source: netip.MustParseAddr("192.0.2.2"), destination: originalDst, sourcePort: sourcePort, destinationPort: uint16(spec.ListenPort)},
		reply:    conntrackTuple{source: spec.TargetHost, destination: netip.MustParseAddr("198.51.100.1"), sourcePort: uint16(spec.TargetPort), destinationPort: sourcePort}}
}

func TestConntrackRetirementScopesExactRuleAndZone(t *testing.T) {
	a := nftUnitSpec()
	b := a
	b.RuleID = "other-rule"
	b.ListenPort++
	b.ListenPortEnd++
	one, two := conntrackUnitEntry(a, 45000), conntrackUnitEntry(b, 45001)
	control := one
	control.mark++
	zone := one
	zone.zone = 23
	zone.original.sourcePort++
	k := &memoryConntrack{entries: []conntrackEntry{one, two, control, zone}}
	if err := revokeNFTConnections(k, []nftRuleSpec{a}); err != nil {
		t.Fatal(err)
	}
	if len(k.entries) != 2 || k.entries[0] != two || k.entries[1] != control {
		t.Fatalf("unrelated entries changed: %+v", k.entries)
	}
	if len(k.deleted) != 2 {
		t.Fatal("matching zone entries were not retired")
	}
	args, err := conntrackDeleteArguments(zone)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(args, " ")
	for _, part := range []string{"--orig-src 192.0.2.2", "--orig-dst 192.0.2.1", "--sport 45001", "--dport 10000", "--reply-src 198.51.100.2", "--reply-dst 198.51.100.1", "--reply-port-src 20000", "--reply-port-dst 45000", "--mark 0x50420001/0xffffffff", "--zone 23"} {
		if !strings.Contains(text, part) {
			t.Fatalf("missing exact delete selector %q", part)
		}
	}
}

func TestConntrackPortOffsetAndWildcardOwnership(t *testing.T) {
	spec := nftUnitSpec()
	spec.ListenHost = netip.IPv4Unspecified()
	spec.ListenPortEnd += 2
	spec.TargetPortEnd += 2
	entry := conntrackUnitEntry(spec, 45000)
	entry.original.destinationPort += 2
	entry.reply.sourcePort += 2
	if !conntrackMatchesSpec(entry, spec) {
		t.Fatal("valid wildcard offset tuple was rejected")
	}
	entry.reply.sourcePort--
	if conntrackMatchesSpec(entry, spec) {
		t.Fatal("wrong target port was classified by mark alone")
	}
	entry.reply.sourcePort++
	entry.original.destinationPort++
	if conntrackMatchesSpec(entry, spec) {
		t.Fatal("another listen port range was classified as owned")
	}
}

func TestConntrackErrorsDoNotReportSuccessfulRevocation(t *testing.T) {
	spec := nftUnitSpec()
	entry := conntrackUnitEntry(spec, 45000)
	for _, kind := range []string{"missing", "read", "delete"} {
		t.Run(kind, func(t *testing.T) {
			k := &memoryConntrack{entries: []conntrackEntry{entry}}
			switch kind {
			case "missing":
				k.availableErr = errors.New("missing trusted binary")
			case "read":
				k.listErr = context.DeadlineExceeded
			case "delete":
				k.deleteErr = errors.New("delete denied")
			}
			if err := revokeNFTConnections(k, []nftRuleSpec{spec}); err == nil {
				t.Fatal("failure reported as success")
			}
			if len(k.entries) != 1 {
				t.Fatal("failed operation changed unrelated state")
			}
		})
	}
}

func TestConntrackXMLTupleAndZoneParsing(t *testing.T) {
	if entries, err := parseConntrackXML(nil); err != nil || len(entries) != 0 {
		t.Fatal("successful empty dump was not recognized")
	}
	data := `<?xml version="1.0"?><conntrack><flow><meta direction="original"><layer3 protoname="ipv6"><src>2001:db8:1::2</src><dst>2001:db8:1::1</dst></layer3><layer4 protoname="tcp"><sport>45001</sport><dport>18081</dport></layer4></meta><meta direction="reply"><layer3 protoname="ipv6"><src>2001:db8:2::2</src><dst>2001:db8:2::1</dst></layer3><layer4 protoname="tcp"><sport>28081</sport><dport>45001</dport></layer4></meta><meta direction="independent"><mark>1346502657</mark><zone>23</zone></meta></flow></conntrack>`
	entries, err := parseConntrackXML([]byte(data))
	if err != nil || len(entries) != 1 || entries[0].zone != 23 || entries[0].family != 6 {
		t.Fatalf("XML decode: %v %v", entries, err)
	}
	if _, err := conntrackDeleteArguments(entries[0]); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{data + "<extra/>", data + strings.TrimSuffix(strings.TrimPrefix(data, `<?xml version="1.0"?><conntrack>`), "</conntrack>"), strings.TrimSuffix(data, "</conntrack>"), strings.Replace(data, "45001", "70000", 1), strings.Replace(data, `<meta direction="reply">`, `<meta direction="original">`, 1), `<conntrack><flow></flow></conntrack>`} {
		if _, err := parseConntrackXML([]byte(bad)); err == nil {
			t.Fatal("malformed XML identity was accepted")
		}
	}
}

func TestNFTRetirementDiffPreservesUnchangedPortsAndAccelerationOnly(t *testing.T) {
	old := nftUnitSpec()
	old.ListenPortEnd += 9
	old.TargetPortEnd += 9
	next := old
	next.EnableFlowtable = false
	if len(retiredNFTSpecs([]nftRuleSpec{old}, []nftRuleSpec{next})) != 0 {
		t.Fatal("acceleration toggle retired normal NAT sessions")
	}
	next.ListenPort += 2
	next.TargetPort += 2
	next.ListenPortEnd -= 2
	next.TargetPortEnd -= 2
	retired := retiredNFTSpecs([]nftRuleSpec{old}, []nftRuleSpec{next})
	if len(retired) != 2 || retired[0].ListenPort != old.ListenPort || nftLastPort(retired[0]) != old.ListenPort+1 || retired[1].ListenPort != old.ListenPort+8 {
		t.Fatalf("wrong range retirement: %+v", retired)
	}
	other := old
	other.RuleID = "replacement"
	if len(gateNFTReplacements([]nftRuleSpec{other}, []nftRuleSpec{old})) != 0 {
		t.Fatal("overlapping replacement admitted before old tuple retirement")
	}
	other.ListenHost = netip.MustParseAddr("192.0.2.3")
	if len(gateNFTReplacements([]nftRuleSpec{other}, []nftRuleSpec{old})) != 1 {
		t.Fatal("unrelated local endpoint was gated")
	}
}
