//go:build linux

package proxy

import (
	"encoding/json"
	"portbridge/internal/config"
	"strconv"
	"strings"
	"testing"
)

func trafficApplyReady(t *testing.T, control *trafficPeer, rules []config.Rule, accelerate bool) map[string]any {
	t.Helper()
	result := control.call(t, map[string]any{"op": "apply", "rules": rules, "flowtable": accelerate})
	requireFixtureOK(t, result)
	data, _ := json.Marshal(result["runtime"])
	var rows []RuleRuntime
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(rules) {
		t.Fatalf("unexpected runtime rows: %v", result)
	}
	for _, row := range rows {
		if !row.Stats.Running || row.Stats.LastError != "" {
			t.Fatalf("rule is not ready: %v", result)
		}
	}
	return result
}
func trafficExchange(t *testing.T, peer *trafficPeer, family int, proto, source, host string, port int, want string) {
	t.Helper()
	requireFixtureOK(t, peer.call(t, map[string]any{"op": "open", "id": "edge", "family": family, "protocol": proto, "host": host, "port": port, "source": source}))
	for i := 0; i < 4; i++ {
		response := peer.call(t, map[string]any{"op": "request", "id": "edge", "data": "edge-" + strconv.Itoa(i)})
		requireFixtureOK(t, response)
		if response["data"] != want+"|edge-"+strconv.Itoa(i) {
			t.Fatalf("wrong range/address reply: %v", response)
		}
	}
	requireFixtureOK(t, peer.call(t, map[string]any{"op": "close", "id": "edge"}))
}
func trafficEdgeCases(t *testing.T, client, localClient, control *trafficPeer, run func(...string) string) {
	t.Run("wildcard-range-hybrid-output", func(t *testing.T) {
		rule := config.NormalizeRule(config.Rule{ID: "edges", Name: "edges", Enabled: true, Protocol: config.ProtocolBoth, ListenHost: "*", ListenPort: 18110, ListenPortEnd: 18111, TargetHost: "198.51.100.2", TargetPort: 28080, TargetPortEnd: 28081, UDPWorkers: 4})
		// IPv4 native, IPv6 cross-family Go, and loopback fallback coexist.
		result := trafficApplyReady(t, control, []config.Rule{rule}, true)
		data, _ := json.Marshal(result["runtime"])
		var rows []RuleRuntime
		_ = json.Unmarshal(data, &rows)
		if rows[0].DataPlane != DataPlaneHybrid {
			t.Fatal("hybrid path not selected")
		}
		for _, proto := range []string{"tcp", "udp"} {
			for offset := 0; offset < 2; offset++ {
				want := "198.51.100.2:" + strconv.Itoa(28080+offset)
				for _, host := range []string{"192.0.2.1", "192.0.2.3"} {
					trafficExchange(t, client, 4, proto, "192.0.2.2", host, 18110+offset, want)
				}
				for _, host := range []string{"2001:db8:1::1", "2001:db8:1::3"} {
					trafficExchange(t, client, 6, proto, "2001:db8:1::2", host, 18110+offset, want)
				}
				trafficExchange(t, localClient, 4, proto, "192.0.2.1", "192.0.2.3", 18110+offset, want)
				trafficExchange(t, localClient, 4, proto, "127.0.0.1", "127.0.0.1", 18110+offset, want)
			}
		}
		trafficApplyReady(t, control, nil, true)
		// Forced Go exercises both families and both mapped ports.
		for _, target := range []string{"198.51.100.2", "2001:db8:2::2"} {
			rule.DataPlane = config.RuleDataPlaneGo
			rule.TargetHost = target
			trafficApplyReady(t, control, []config.Rule{rule}, true)
			for offset := 0; offset < 2; offset++ {
				want := target + ":" + strconv.Itoa(28080+offset)
				trafficExchange(t, client, 4, "udp", "192.0.2.2", "192.0.2.3", 18110+offset, want)
				trafficExchange(t, client, 6, "udp", "2001:db8:1::2", "2001:db8:1::3", 18110+offset, want)
			}
			result = trafficApplyReady(t, control, nil, true)
			if result["udp"].(float64) != 0 || result["udp_memory"].(float64) != 0 || result["tcp"].(float64) != 0 {
				t.Fatalf("stopped edge paths retain reservations: %v", result)
			}
		}
		t.Log("verified wildcard ranges, IPv4 OUTPUT NAT, hybrid cross-family Go, loopback fallback, and released budgets")
	})
	t.Run("scoped-and-asymmetric-udp", func(t *testing.T) {
		rule := config.NormalizeRule(config.Rule{ID: "route", Name: "route", Enabled: true, Protocol: config.ProtocolUDP, DataPlane: config.RuleDataPlaneGo, ListenHost: "*", ListenPort: 18120, TargetHost: "198.51.100.2", TargetPort: 28080, UDPWorkers: 4})
		trafficApplyReady(t, control, []config.Rule{rule}, true)
		trafficExchange(t, client, 6, "udp", "fe80::2%cli", "fe80::1%cli", 18120, "198.51.100.2:28080")
		run("/usr/sbin/ip", "addr", "add", "2001:db8:3::1/64", "dev", "ralt", "nodad")
		run("/usr/sbin/ip", "netns", "exec", "pc", "/usr/sbin/ip", "addr", "add", "2001:db8:3::2/64", "dev", "alt", "nodad")
		run("/usr/sbin/sysctl", "-q", "-w", "net.ipv4.conf.rcli.rp_filter=0", "net.ipv4.conf.ralt.rp_filter=0")
		run("/usr/sbin/ip", "netns", "exec", "pc", "/usr/sbin/sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.alt.rp_filter=0")
		run("/usr/sbin/ip", "route", "add", "192.0.2.2/32", "via", "203.0.113.2", "dev", "ralt")
		run("/usr/sbin/ip", "-6", "route", "add", "2001:db8:1::2/128", "via", "2001:db8:3::2", "dev", "ralt")
		before := run("/usr/sbin/ip", "-j", "-s", "link", "show", "dev", "ralt")
		trafficExchange(t, client, 4, "udp", "192.0.2.2", "192.0.2.3", 18120, "198.51.100.2:28080")
		trafficExchange(t, client, 6, "udp", "2001:db8:1::2", "2001:db8:1::3", 18120, "198.51.100.2:28080")
		packets := func(raw string) float64 {
			var links []map[string]any
			if err := json.Unmarshal([]byte(raw), &links); err != nil {
				t.Fatal(err)
			}
			return links[0]["stats64"].(map[string]any)["tx"].(map[string]any)["packets"].(float64)
		}
		if packets(run("/usr/sbin/ip", "-j", "-s", "link", "show", "dev", "ralt"))-packets(before) < 8 {
			t.Fatal("replies did not use independently routed egress")
		}
		trafficApplyReady(t, control, nil, true)
		run("/usr/sbin/ip", "route", "del", "192.0.2.2/32")
		run("/usr/sbin/ip", "-6", "route", "del", "2001:db8:1::2/128")
		t.Log("verified IPv6 link-local scope and IPv4/IPv6 global replies over a different egress interface")
	})
}
func trafficConntrackID(t *testing.T, run func(...string) string, family int, proto, source, destination string, sport, dport int) string {
	t.Helper()
	raw := run("/usr/sbin/conntrack", "-L", "-f", "ipv"+strconv.Itoa(family), "-p", proto, "--orig-src", source, "--orig-dst", destination, "--sport", strconv.Itoa(sport), "--dport", strconv.Itoa(dport), "-o", "extended,id")
	id := ""
	for _, word := range strings.Fields(raw) {
		if strings.HasPrefix(word, "id=") {
			if id != "" {
				t.Fatal("ambiguous conntrack identity")
			}
			id = word
		}
	}
	if id == "" {
		t.Fatalf("missing exact connection identity: %s", raw)
	}
	return id
}

func trafficAdmissionPreflight(t *testing.T, control *trafficPeer) {
	for _, kind := range []string{"same-priority", "postrouting-filter"} {
		t.Run("preflight-"+kind, func(t *testing.T) {
			kernel := newCommandNFTBackend(testLogger()).kernel
			hook := "forward priority 2147483647"
			if kind == "postrouting-filter" {
				hook = "postrouting priority 200"
			}
			script := "add table inet pb_fixture_policy\nadd chain inet pb_fixture_policy boundary { type filter hook " + hook + "; policy accept; }\n"
			if _, err := kernel.Apply(script); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if _, err := kernel.Apply("delete table inet pb_fixture_policy\n"); err != nil {
					t.Error(err)
				}
			}()
			rule := config.NormalizeRule(config.Rule{ID: "preflight", Name: "preflight", Enabled: true, Protocol: config.ProtocolUDP, ListenHost: "192.0.2.1", ListenPort: 18130, TargetHost: "198.51.100.2", TargetPort: 28080})
			// Empty accept chains have been supported since v2.4.6. Keep the
			// negative gate test by introducing an actual per-packet side effect.
			trafficApplyReady(t, control, []config.Rule{rule}, true)
			if _, err := kernel.Apply("add rule inet pb_fixture_policy boundary counter\n"); err != nil {
				t.Fatal(err)
			}
			result := control.call(t, map[string]any{"op": "apply", "rules": []config.Rule{rule}, "flowtable": true})
			requireFixtureOK(t, result)
			data, _ := json.Marshal(result["runtime"])
			var rows []RuleRuntime
			_ = json.Unmarshal(data, &rows)
			if len(rows) != 1 || rows[0].KernelState != "admission-suspended" || rows[0].GoRunning || rows[0].Stats.LastError == "" {
				t.Fatalf("unsafe hook ordering did not report failure: %v", result)
			}
			installed, err := kernel.Table()
			if err != nil {
				t.Fatal(err)
			}
			objects, err := decodeNFTObjects(installed)
			if err != nil {
				t.Fatal(err)
			}
			for _, object := range objects {
				if _, exists := object["flowtable"]; exists {
					t.Fatal("unproved counter hook retained acceleration")
				}
				if rule, ok := object["rule"].(map[string]any); ok &&
					(rule["chain"] == "prerouting" || rule["chain"] == "output" || rule["chain"] == "forward") {
					t.Fatal("unproved counter hook retained actual new admission")
				}
			}
			trafficApplyReady(t, control, []config.Rule{rule}, false)
			trafficApplyReady(t, control, nil, false)
			data, err = kernel.Tables()
			if err != nil || !strings.Contains(string(data), "pb_fixture_policy") {
				t.Fatal("external policy was removed")
			}
		})
	}
}
