//go:build linux

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"portbridge/internal/config"
)

type countingNFTKernel struct {
	nftKernelIO
	writes int
}

func (k *countingNFTKernel) Ruleset() ([]byte, error) {
	reader, ok := k.nftKernelIO.(nftRulesetReader)
	if !ok {
		return nil, errors.New("complete ruleset reader unavailable")
	}
	return reader.Ruleset()
}

func (k *countingNFTKernel) Apply(script string) ([]byte, error) {
	k.writes++
	return k.nftKernelIO.Apply(script)
}

func TestNFTKernelLifecycle(t *testing.T) {
	parentNS := os.Getenv("PB_NFT_PARENT_NS")
	if os.Getenv("PB_NFT_KERNEL_CHILD") != "1" {
		current, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, "/usr/bin/unshare", "--net", exe, "-test.run", "^TestNFTKernelLifecycle$", "-test.v")
		command.Env = append(os.Environ(), "PB_NFT_KERNEL_CHILD=1", "PB_NFT_PARENT_NS="+current)
		output, err := command.CombinedOutput()
		if err != nil {
			if os.Getenv("PB_REQUIRE_NFT") != "1" && (strings.Contains(string(output), "Operation not permitted") || errors.Is(err, os.ErrNotExist)) {
				t.Skipf("isolated nft integration capability unavailable: %v", err)
			}
			t.Fatalf("isolated nft integration failed: %v\n%s", err, output)
		}
		t.Logf("real-kernel isolated child:\n%s", output)
		return
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || parentNS == "" || current == parentNS {
		t.Fatal("refusing real nft mutation outside a new network namespace")
	}
	tool := func(t *testing.T, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "/usr/sbin/ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated ip operation failed: %v %s", err, out)
		}
	}
	tool(t, "link", "set", "lo", "up")
	for _, name := range []string{"pba", "pbb"} {
		tool(t, "link", "add", name, "type", "veth", "peer", "name", name+"p")
		tool(t, "link", "set", name, "up")
		tool(t, "link", "set", name+"p", "up")
	}
	n := newCommandNFTBackend(testLogger())
	n.store = newNFTStateStore(privateNFTConfig(t))
	k := &countingNFTKernel{nftKernelIO: n.kernel}
	n.kernel = k
	defer func() {
		// The entire child namespace is reclaimed even after a failed test.
		_ = n.Delete()
	}()
	spec := nftRuleSpec{
		RuleID: "kernel-lifecycle", Family: 4, ListenHost: netip.MustParseAddr("192.0.2.1"),
		ListenPort: 18080, ListenPortEnd: 18081, TargetHost: netip.MustParseAddr("198.51.100.2"),
		TargetPort: 28080, TargetPortEnd: 28081, Protocol: "udp",
		ConntrackMark: config.DefaultNFTConntrackMark, EnableFlowtable: true,
	}
	identity := func(t *testing.T) string {
		t.Helper()
		s, err := n.observe()
		if err != nil {
			t.Fatal(err)
		}
		table, flow := "", ""
		for _, obj := range s.objects {
			if v, ok := obj["table"].(map[string]any); ok {
				table = fmt.Sprint(v["handle"])
			}
			if v, ok := obj["flowtable"].(map[string]any); ok {
				flow = fmt.Sprint(v["handle"])
			}
		}
		return table + ":" + flow
	}
	apply := func(t *testing.T) {
		t.Helper()
		if err := n.Replace([]nftRuleSpec{spec}); err != nil {
			if data, readErr := k.Table(); readErr == nil {
				if objects, decodeErr := decodeNFTObjects(data); decodeErr == nil {
					for _, object := range objects {
						if rule, ok := object["rule"].(map[string]any); ok && rule["chain"] == "forward" {
							t.Logf("isolated actual forward: %s", nftRuleInspectionKey(rule))
						}
					}
				}
			}
			t.Logf("expected forward: %s", nftRuleInspectionKey(nftExpectedRule(spec, "forward")))
			t.Fatal(err)
		}
		if healthy, err := n.Healthy([]nftRuleSpec{spec}); err != nil || !healthy {
			t.Fatalf("applied state not healthy: healthy=%t err=%v", healthy, err)
		}
	}
	t.Run("initial-and-idempotent", func(t *testing.T) {
		apply(t)
		before := k.writes
		apply(t)
		if k.writes != before {
			t.Fatal("unchanged state caused a write")
		}
	})
	old := identity(t)
	t.Run("ordinary-chain-refresh-preserves-flowtable", func(t *testing.T) {
		spec.TargetPort, spec.TargetPortEnd = 29080, 29081
		apply(t)
		if identity(t) != old {
			t.Fatal("ordinary refresh replaced flowtable object")
		}
	})
	t.Run("disable-removes-real-object-and-retains-NAT", func(t *testing.T) {
		spec.EnableFlowtable = false
		apply(t)
		s, err := n.observe()
		if err != nil {
			t.Fatal(err)
		}
		rules := 0
		for _, obj := range s.objects {
			if _, ok := obj["flowtable"]; ok {
				t.Fatal("disabled flowtable remains in kernel")
			}
			if rule, ok := obj["rule"].(map[string]any); ok && rule["chain"] != nftStateChainName {
				rules++
			}
		}
		if rules != 4 {
			t.Fatalf("NAT-only rules=%d, want 4", rules)
		}
	})
	t.Run("reenable-recreates-object", func(t *testing.T) {
		spec.EnableFlowtable = true
		apply(t)
		if identity(t) == old || strings.HasSuffix(identity(t), ":") {
			t.Fatal("flowtable was not recreated")
		}
	})
	t.Run("same-name-new-ifindex", func(t *testing.T) {
		before := n.TopologyKey()
		old := identity(t)
		tool(t, "link", "del", "pba")
		tool(t, "link", "add", "pba", "type", "veth", "peer", "name", "pbap")
		tool(t, "link", "set", "pba", "up")
		tool(t, "link", "set", "pbap", "up")
		if n.TopologyKey() == before {
			t.Fatal("same-name interface replacement was not detected")
		}
		apply(t)
		if identity(t) == old {
			t.Fatal("ifindex change did not recreate objects")
		}
	})
	for name, mutation := range map[string]string{
		"rule-drift":        "flush chain inet portbridge prerouting\n",
		"chain-missing":     "flush chain inet portbridge prerouting\ndelete chain inet portbridge prerouting\n",
		"flowtable-missing": "flush chain inet portbridge forward\ndelete flowtable inet portbridge fastpath\n",
		"table-missing":     "delete table inet portbridge\n",
	} {
		t.Run(name, func(t *testing.T) {
			apply(t)
			if _, err := k.Apply(mutation); err != nil {
				t.Fatal(err)
			}
			if healthy, err := n.Healthy([]nftRuleSpec{spec}); err != nil || healthy {
				t.Fatalf("drift not detected: healthy=%t err=%v", healthy, err)
			}
			apply(t)
		})
	}
	t.Run("real-table-owner-not-rule-comment", func(t *testing.T) {
		apply(t)
		script := "delete table inet portbridge\nadd table inet portbridge { comment \"foreign-test-fixture\"; }\n" +
			"add chain inet portbridge marker\nadd rule inet portbridge marker counter comment " + fmt.Sprintf("%q", n.ownerMarker) + "\n"
		if _, err := k.Apply(script); err != nil {
			t.Fatal(err)
		}
		before := k.writes
		if err := n.Replace([]nftRuleSpec{spec}); err == nil {
			t.Fatal("spoofed rule comment granted table ownership")
		}
		if err := n.Delete(); err == nil {
			t.Fatal("foreign table was deleted")
		}
		if k.writes != before {
			t.Fatal("foreign table received a write")
		}
		// Remove only this fixture, after checking its exact real table comment.
		state, err := n.observe()
		if err != nil {
			t.Fatal(err)
		}
		for _, object := range state.objects {
			if table, ok := tableDescriptor(object); ok && table["comment"] == "foreign-test-fixture" {
				if _, err := k.Apply("delete table inet portbridge\n"); err != nil {
					t.Fatal(err)
				}
				return
			}
		}
		t.Fatal("foreign test fixture identity changed; refusing cleanup")
	})
	t.Run("fix-empty-external-hook-real-objects", func(t *testing.T) {
		if _, err := k.Apply("add table inet pb_fix_empty\nadd chain inet pb_fix_empty post { type filter hook postrouting priority 0; policy accept; }\n"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := k.Apply("delete table inet pb_fix_empty\n"); err != nil {
				t.Error(err)
			}
		}()
		apply(t)
		before := k.writes
		apply(t)
		if k.writes != before {
			t.Fatal("empty-hook proof rebuilt unchanged objects")
		}
		if _, err := k.Apply("add rule inet pb_fix_empty post counter\n"); err != nil {
			t.Fatal(err)
		}
		if err := n.Replace([]nftRuleSpec{spec}); err == nil {
			t.Fatal("real per-packet counter bypassed")
		}
		if len(n.suspendedSpecs) != 1 {
			t.Fatal("nonempty-hook suspension missing")
		}
		if _, err := k.Apply("flush chain inet pb_fix_empty post\n"); err != nil {
			t.Fatal(err)
		}
		apply(t)
	})
	t.Run("fix-simulated-boot-real-unrelated-inventory", func(t *testing.T) {
		if err := n.Delete(); err != nil {
			t.Fatal(err)
		}
		path := n.store.configPath
		rewriteNFTRecord(t, path+".nft-state.json", func(r *nftDiskRecord) { r.Context.BootID = "11111111-1111-4111-8111-111111111111" })
		if _, err := k.Apply("add table inet pb_fix_foreign\nadd chain inet pb_fix_foreign input { type filter hook input priority 0; policy accept; }\n"); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := k.Apply("delete table inet pb_fix_foreign\n"); err != nil {
				t.Error(err)
			}
		}()
		dataBefore, err := k.Ruleset()
		if err != nil {
			t.Fatal(err)
		}
		n = newCommandNFTBackend(testLogger())
		n.store = newNFTStateStore(path)
		k = &countingNFTKernel{nftKernelIO: n.kernel}
		n.kernel = k
		apply(t)
		if _, err := os.Stat(path + ".nft-state.json.previous-boot"); err != nil {
			t.Fatal(err)
		}
		dataAfter, err := k.Ruleset()
		if err != nil {
			t.Fatal(err)
		}
		foreignKey := func(data []byte) string {
			objects, err := decodeNFTProofObjects(data)
			if err != nil {
				t.Fatal(err)
			}
			var foreign []nftObject
			for _, o := range objects {
				for _, raw := range o {
					fields, ok := raw.(map[string]any)
					if ok && (fields["name"] == "pb_fix_foreign" || fields["table"] == "pb_fix_foreign") {
						foreign = append(foreign, o)
					}
				}
			}
			return nftProofInventoryKey(foreign)
		}
		if foreignKey(dataBefore) == "" || foreignKey(dataBefore) != foreignKey(dataAfter) {
			t.Fatal("unrelated real objects changed")
		}
		t.Log("L2 inventory/object test only: record boot edited; NOT an actual reboot or full service test")
	})

}

func TestNFTTopologyIdentityAndOrder(t *testing.T) {
	interfaces := []net.Interface{{Index: 3, Name: "b"}, {Index: 1, Name: "lo", Flags: net.FlagLoopback}, {Index: 2, Name: "a"}}
	a := collectNFTTopology(func() ([]net.Interface, error) { return interfaces, nil })
	interfaces[0], interfaces[2] = interfaces[2], interfaces[0]
	b := collectNFTTopology(func() ([]net.Interface, error) { return interfaces, nil })
	if a.key() != b.key() {
		t.Fatal("enumeration order changed the topology key")
	}
	interfaces[0].Index = 9
	c := collectNFTTopology(func() ([]net.Interface, error) { return interfaces, nil })
	if b.key() == c.key() {
		t.Fatal("ifindex is missing from topology identity")
	}
}
