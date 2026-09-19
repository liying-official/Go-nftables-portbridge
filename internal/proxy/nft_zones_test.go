//go:build linux

package proxy

import (
	"context"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func trafficConntrackZones(t *testing.T) {
	t.Helper()
	t.Run("exact-common-zone-delete", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		kernel := newCommandConntrack()
		for _, family := range []int{4, 6} {
			for _, protocol := range []string{"tcp", "udp"} {
				spec := nftUnitSpec()
				spec.Family = family
				spec.Protocol = protocol
				spec.ListenPort = 18200
				spec.ListenPortEnd = 18200
				if family == 6 {
					spec.ListenHost = netip.MustParseAddr("2001:db8:1::1")
					spec.TargetHost = netip.MustParseAddr("2001:db8:2::2")
				}
				entry := conntrackUnitEntry(nftUnitSpec(), 45123)
				entry.family = family
				entry.protocol = protocol
				entry.original.destination = spec.ListenHost
				entry.original.destinationPort = 18200
				entry.reply.source = spec.TargetHost
				if family == 6 {
					entry.original.source = netip.MustParseAddr("2001:db8:1::2")
					entry.reply.destination = netip.MustParseAddr("2001:db8:2::1")
				}
				control := entry
				control.zone = 24
				control.mark++
				zoned := entry
				zoned.zone = 23
				for _, item := range []conntrackEntry{entry, zoned, control} {
					args, err := conntrackDeleteArguments(item)
					if err != nil {
						t.Fatal(err)
					}
					// Insert infers the family from the complete fixture tuple;
					// conntrack -I does not accept -f in the tested CLI.
					insert := append([]string{"-I"}, args[3:]...)
					insert = append(insert, "--timeout", "60")
					if protocol == "tcp" {
						insert = append(insert, "--state", "ESTABLISHED")
					}
					if _, err := kernel.command(ctx, "", false, insert...); err != nil {
						t.Fatalf("insert synthetic zone %d/%s: %v", family, protocol, err)
					}
				}
				entries, err := kernel.List(ctx, spec)
				if err != nil || len(entries) != 2 {
					t.Fatalf("zone dump %d/%s: entries=%d err=%v", family, protocol, len(entries), err)
				}
				if err := kernel.Delete(ctx, []conntrackEntry{entry}); err != nil {
					t.Fatal(err)
				}
				entries, err = kernel.List(ctx, spec)
				if err != nil || len(entries) != 1 || entries[0].zone != 23 {
					t.Fatal("exact zone-0 delete removed/missed zone-23 entry")
				}
				if err := revokeNFTConnections(kernel, []nftRuleSpec{spec}); err != nil {
					t.Fatal(err)
				}
				entries, err = kernel.List(ctx, spec)
				if err != nil || len(entries) != 0 {
					t.Fatal("owned zone retirement incomplete")
				}
				other := spec
				other.ConntrackMark++
				entries, err = kernel.List(ctx, other)
				if err != nil || len(entries) != 1 || entries[0].mark != control.mark || entries[0].zone != 24 {
					t.Fatal("other-mark exact tuple was removed")
				}
				if err := kernel.Delete(ctx, []conntrackEntry{control}); err != nil {
					t.Fatal(err)
				}
				t.Log("real conntrack synthetic tuple isolation verified: IPv" + strconv.Itoa(family) + " " + protocol + " zones 0/23 and other mark (not an offload traffic claim)")
			}
		}
	})
}
