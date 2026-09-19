//go:build linux

package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"portbridge/internal/config"
	"strconv"
	"strings"
	"testing"
)

// Uses the existing private router/client/target and restricted non-root
// controller. No call is made until namespace identity checks have completed.
func trafficSelectiveACL(t *testing.T, client, control *trafficPeer, run func(...string) string) {
	for _, family := range []int{4, 6} {
		for _, proto := range []string{"tcp", "udp"} {
			for _, priority := range []int{0, 200} {
				t.Run(fmt.Sprintf("ipv%d/%s/priority%d", family, proto, priority), func(t *testing.T) {
					listen, target, source := "192.0.2.1", "198.51.100.2", "192.0.2.2"
					if family == 6 {
						listen, target, source = "2001:db8:1::1", "2001:db8:2::2", "2001:db8:1::2"
					}
					a := config.NormalizeRule(config.Rule{ID: "sa", Name: "A", Enabled: true, Protocol: proto, DataPlane: config.RuleDataPlaneNFT, ListenHost: listen, ListenPort: 18150, TargetHost: target, TargetPort: 28080})
					b := a
					b.ID = "sb"
					b.Name = "B"
					b.ListenPort = 18151
					c := a
					c.ID = "sc"
					c.Name = "C"
					c.ListenPort = 18152
					if priority == 0 {
						c.TargetPort = 28081
					}
					trafficApplyReady(t, control, []config.Rule{a, b, c}, true)
					ports := make(map[string]int)
					open := func(id string, port int, host string) {
						result := client.call(t, map[string]any{"op": "open", "id": id, "family": family, "protocol": proto, "source": source, "host": host, "port": port})
						requireFixtureOK(t, result)
						ports[id] = int(result["source_port"].(float64))
					}
					request := func(id string, targetPort int) {
						payload := "selective-" + id
						result := client.call(t, map[string]any{"op": "request", "id": id, "data": payload})
						requireFixtureOK(t, result)
						if result["data"] != target+":"+strconv.Itoa(targetPort)+"|"+payload {
							t.Fatalf("payload/source association failed: %v", result)
						}
					}
					deny := func(id string) {
						result := client.call(t, map[string]any{"op": "request", "id": id, "data": "must-be-denied"})
						if result["ok"] == true {
							t.Fatalf("denied path still forwards: %v", result)
						}
					}
					closeAll := func() {
						for _, id := range []string{"sa", "sb", "sc", "foreign", "new-b", "new-c", "new-a", "restored-b"} {
							requireFixtureOK(t, client.call(t, map[string]any{"op": "close", "id": id}))
						}
					}
					open("sa", a.ListenPort, listen)
					open("sb", b.ListenPort, listen)
					open("sc", c.ListenPort, listen)
					open("foreign", 28080, target)
					for i := 0; i < 8; i++ {
						request("sa", 28080)
						request("sb", 28080)
						request("sc", c.TargetPort)
						request("foreign", 28080)
					}
					ct := func(id string, listenPort, targetPort int) string {
						return run("/usr/sbin/conntrack", "-L", "-f", "ipv"+strconv.Itoa(family), "-p", proto,
							"--orig-src", source, "--orig-dst", listen, "--sport", strconv.Itoa(ports[id]), "--dport", strconv.Itoa(listenPort),
							"--reply-src", target, "--reply-port-src", strconv.Itoa(targetPort), "--mark", "0x50420001/0xffffffff", "-o", "extended,id")
					}
					for _, x := range []struct {
						id           string
						port, target int
					}{{"sa", a.ListenPort, 28080}, {"sb", b.ListenPort, 28080}, {"sc", c.ListenPort, c.TargetPort}} {
						if !strings.Contains(ct(x.id, x.port, x.target), "[OFFLOAD]") {
							t.Fatal("initial exact flow did not offload", x.id)
						}
					}
					bID := trafficConntrackID(t, run, family, proto, source, listen, ports["sb"], b.ListenPort)
					cID := trafficConntrackID(t, run, family, proto, source, listen, ports["sc"], c.ListenPort)
					foreignID := trafficConntrackID(t, run, family, proto, source, target, ports["foreign"], 28080)
					kernel := newCommandNFTBackend(testLogger()).kernel
					reversePort := 28080
					if priority >= 100 {
						reversePort = b.ListenPort
					}
					script := fmt.Sprintf("add table inet pb_selective_fixture\nadd chain inet pb_selective_fixture post { type filter hook postrouting priority %d; policy drop; }\n", priority) +
						fmt.Sprintf("add rule inet pb_selective_fixture post %s dport 28080 accept\nadd rule inet pb_selective_fixture post %s sport %d accept\n", proto, proto, reversePort) +
						"add rule inet pb_selective_fixture post meta l4proto ipv6-icmp accept\n"
					if reversePort != 28080 {
						script += fmt.Sprintf("add rule inet pb_selective_fixture post %s sport 28080 accept\n", proto)
					}
					if _, err := kernel.Apply(script); err != nil {
						t.Fatal(err)
					}
					defer func() { _, _ = kernel.Apply("delete table inet pb_selective_fixture\n") }()
					external := run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_selective_fixture")
					a.Enabled = false
					result := control.call(t, map[string]any{"op": "apply", "rules": []config.Rule{a, b, c}, "flowtable": true})
					requireFixtureOK(t, result)
					data, _ := json.Marshal(result["runtime"])
					var rows []RuleRuntime
					if err := json.Unmarshal(data, &rows); err != nil {
						t.Fatal(err)
					}
					active, suspended := false, false
					for _, row := range rows {
						if row.Rule.ID == b.ID {
							active = row.Stats.Running && row.KernelState == "active-verified" && !row.GoRunning && row.Stats.LastError == ""
						}
						if row.Rule.ID == c.ID {
							suspended = row.KernelState == "admission-suspended" && !row.GoRunning
						}
					}
					if !active || !suspended || result["pending"].(float64) != 0 {
						t.Fatalf("selective runtime state: %v", result)
					}
					deny("sa")
					for i := 0; i < 3; i++ {
						deny("sc")
						request("sb", 28080)
						request("foreign", 28080)
					}
					if strings.Contains(ct("sc", c.ListenPort, c.TargetPort), "[OFFLOAD]") {
						t.Fatal("denied old C borrowed B's shared-target flow-add rule")
					}
					if trafficConntrackID(t, run, family, proto, source, listen, ports["sb"], b.ListenPort) != bID ||
						trafficConntrackID(t, run, family, proto, source, listen, ports["sc"], c.ListenPort) != cID ||
						trafficConntrackID(t, run, family, proto, source, target, ports["foreign"], 28080) != foreignID {
						t.Fatal("B/C/foreign conntrack was deleted")
					}
					open("new-b", b.ListenPort, listen)
					if ports["new-b"] == ports["sb"] {
						t.Fatal("new B reused the old source port")
					}
					for i := 0; i < 8; i++ {
						request("new-b", 28080)
					}
					if !strings.Contains(ct("new-b", b.ListenPort, 28080), "[OFFLOAD]") {
						t.Fatal("new B has no exact tuple OFFLOAD")
					}
					for _, x := range []struct {
						id   string
						port int
					}{{"new-c", c.ListenPort}, {"new-a", a.ListenPort}} {
						opened := client.call(t, map[string]any{"op": "open", "id": x.id, "family": family, "protocol": proto, "source": source, "host": listen, "port": x.port})
						if opened["ok"] == true {
							if proto == "tcp" {
								t.Fatal("new denied TCP admitted", x.id)
							}
							deny(x.id)
						}
					}
					if external != run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_selective_fixture") {
						t.Fatal("product rewrote external ACL")
					}
					if directory := os.Getenv("AUDIT_EVIDENCE"); directory != "" {
						path := filepath.Join(directory, fmt.Sprintf("selective-ipv%d-%s-prio%d.json", family, proto, priority))
						if err := os.WriteFile(path, []byte(run("/usr/sbin/nft", "-j", "list", "ruleset")), 0600); err != nil {
							t.Fatal(err)
						}
					}
					// An explicit DROP is never excused by a previous accept.
					if _, err := kernel.Apply("insert rule inet pb_selective_fixture post drop\n"); err != nil {
						t.Fatal(err)
					}
					result = control.call(t, map[string]any{"op": "refresh", "rules": []config.Rule{a, b, c}})
					requireFixtureOK(t, result)
					deny("new-b")
					if strings.Contains(run("/usr/sbin/nft", "-j", "list", "table", "inet", nftTableName), `"flowtable"`) {
						t.Fatal("explicit DROP retained cached acceleration")
					}
					if trafficConntrackID(t, run, family, proto, source, listen, ports["sb"], b.ListenPort) != bID ||
						trafficConntrackID(t, run, family, proto, source, listen, ports["sc"], c.ListenPort) != cID ||
						trafficConntrackID(t, run, family, proto, source, target, ports["foreign"], 28080) != foreignID {
						t.Fatal("DROP coordination deleted retained conntrack")
					}
					closeAll()
					requireFixtureOK(t, control.call(t, map[string]any{"op": "apply", "rules": []config.Rule{}}))
					t.Logf("V249_SELECTIVE_ACL_VERIFIED family=%d protocol=%s priority=%d A_retired=true B_old_new_payload=true exact_OFFLOAD=true C_not_reoffloaded=true foreign_CT_preserved=true external_unchanged=true DROP_enforced=true", family, proto, priority)
				})
			}
		}
	}
}
