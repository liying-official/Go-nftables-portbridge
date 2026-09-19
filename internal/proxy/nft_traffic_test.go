//go:build linux

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"portbridge/internal/config"
)

type fixtureConntrack struct {
	conntrackKernelIO
	fail bool
}
type trafficNFTIO struct{ nftKernelIO }

// Preserve the real reader's optional complete-inventory capability through
// this diagnostic wrapper. Descriptor-only test fakes do not gain it.
func (k trafficNFTIO) Ruleset() ([]byte, error) {
	reader, ok := k.nftKernelIO.(nftRulesetReader)
	if !ok {
		return nil, errors.New("complete ruleset reader unavailable")
	}
	return reader.Ruleset()
}

func (k trafficNFTIO) Apply(script string) ([]byte, error) {
	out, err := k.nftKernelIO.Apply(script)
	if err != nil {
		cmd := exec.Command("/usr/sbin/nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		diagnostic, _ := cmd.CombinedOutput()
		_, _ = os.Stderr.Write(diagnostic)
	}
	return out, err
}
func (f *fixtureConntrack) Delete(ctx context.Context, entries []conntrackEntry) error {
	if f.fail {
		return errors.New("injected fixture revocation failure")
	}
	return f.conntrackKernelIO.Delete(ctx, entries)
}

func TestMain(m *testing.M) {
	if os.Getenv("PB_NFT_CONTROLLER_PEER") == "1" {
		os.Exit(runNFTControllerPeer())
	}
	os.Exit(m.Run())
}
func runNFTControllerPeer() int {
	ns, err := os.Readlink("/proc/self/ns/net")
	if err != nil || ns != os.Getenv("PB_NFT_ROUTER_NS") || ns == os.Getenv("PB_NFT_TRAFFIC_PARENT_NS") {
		return 2
	}
	mnt, err := os.Readlink("/proc/self/ns/mnt")
	statePath := os.Getenv("PB_NFT_RECOVERY_CONFIG")
	if err != nil || mnt != os.Getenv("PB_NFT_ROUTER_MOUNT_NS") || mnt == os.Getenv("PB_NFT_PARENT_MOUNT_NS") ||
		!strings.HasPrefix(statePath, "/run/portbridge-recovery-test-") || filepath.Base(statePath) != "config.json" || filepath.Clean(statePath) != statePath {
		return 2
	}
	// The isolated router owns this directory's lifecycle; every recreated
	// service process must use the SAME service-owned durable identity.
	n := newCommandNFTBackend(testLogger())
	n.store = newNFTStateStore(statePath)
	n.kernel = trafficNFTIO{n.kernel}
	fault := &fixtureConntrack{conntrackKernelIO: n.conntrack}
	n.conntrack = fault
	manager := newManagerWithNFT(testLogger(), NewDNSResolver([]string{os.Getenv("PB_NFT_FIXTURE_DNS")}), n)
	defer manager.Stop()
	encode := json.NewEncoder(os.Stdout)
	probe, probeErr := exec.Command("/usr/sbin/nft", "list", "tables").CombinedOutput()
	probeError := ""
	if probeErr != nil {
		probeError = probeErr.Error()
	}
	_ = encode.Encode(map[string]any{"ready": true, "pid": os.Getpid(), "uid": os.Geteuid(), "nft_probe": string(probe), "nft_probe_error": probeError})
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 1<<20)
	flowtable := true
	for scan.Scan() {
		var q struct {
			Op         string
			Rules      []config.Rule
			Flowtable  *bool
			Faildelete *bool
		}
		if err := json.Unmarshal(scan.Bytes(), &q); err != nil {
			return 2
		}
		if q.Faildelete != nil {
			fault.fail = *q.Faildelete
		}
		if q.Flowtable != nil {
			flowtable = *q.Flowtable
		}
		switch q.Op {
		case "apply", "refresh":
			cfg := config.Default()
			cfg.Rules = q.Rules
			cfg.NFT.EnableFlowtable = flowtable
			if err := config.Validate(cfg); err != nil {
				_ = encode.Encode(map[string]any{"ok": false, "error": err.Error()})
				continue
			}
			manager.SetRuntimeConfig(cfg.Limits, cfg.NFT)
			if q.Op == "refresh" {
				manager.Refresh(q.Rules)
			} else {
				manager.Apply(q.Rules)
			}
		case "fault":
		case "stop":
			manager.Stop()
		default:
			return 2
		}
		state := n.retirementState()
		_ = encode.Encode(map[string]any{"ok": true, "runtime": manager.Runtime(), "pending": len(state.Pending), "unknown": state.Unknown,
			"tcp": manager.resources.activeTCP.Load(), "udp": manager.resources.activeUDP.Load(), "udp_memory": manager.resources.udpMemory.Load()})
	}
	if scan.Err() != nil {
		return 1
	}
	return 0
}

type trafficLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *trafficLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.b.Len() < 8192 {
		left := 8192 - b.b.Len()
		if len(p) > left {
			p = p[:left]
		}
		_, _ = b.b.Write(p)
	}
	return n, nil
}
func (b *trafficLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return b.b.String() }

type trafficPeer struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	replies chan []byte
	stop    chan struct{}
	once    sync.Once
	log     trafficLog
	ready   map[string]any
}

func startTrafficPeer(t *testing.T, args []string, env []string, extra ...*os.File) *trafficPeer {
	t.Helper()
	p := &trafficPeer{cmd: exec.Command(args[0], args[1:]...), replies: make(chan []byte, 1), stop: make(chan struct{})}
	p.cmd.Env = append(os.Environ(), env...)
	p.cmd.ExtraFiles = extra
	p.cmd.Stderr = &p.log
	var err error
	p.input, err = p.cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(p.replies)
		scan := bufio.NewScanner(out)
		scan.Buffer(make([]byte, 4096), 1<<20)
		for scan.Scan() {
			line := append([]byte(nil), scan.Bytes()...)
			select {
			case p.replies <- line:
			case <-p.stop:
				return
			}
		}
	}()
	t.Cleanup(p.kill)
	ready := p.receive(t)
	p.ready = ready
	if ready["ready"] != true {
		t.Fatalf("fixture not ready: %v %s", ready, p.log.String())
	}
	return p
}
func (p *trafficPeer) kill() {
	p.once.Do(func() {
		close(p.stop)
		if p.cmd.Process != nil {
			_ = p.cmd.Process.Kill()
		}
		_ = p.input.Close()
		_ = p.cmd.Wait()
	})
}
func (p *trafficPeer) receive(t *testing.T) map[string]any {
	t.Helper()
	select {
	case line, ok := <-p.replies:
		if !ok {
			t.Fatalf("fixture exited: %s", p.log.String())
		}
		var result map[string]any
		if err := json.Unmarshal(line, &result); err != nil {
			t.Fatalf("invalid fixture reply: %q %s", line, p.log.String())
		}
		return result
	case <-time.After(20 * time.Second):
		t.Fatalf("fixture response timeout: %s", p.log.String())
	}
	return nil
}
func (p *trafficPeer) call(t *testing.T, q map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = p.input.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	return p.receive(t)
}
func requireFixtureOK(t *testing.T, result map[string]any) {
	t.Helper()
	if result["ok"] != true {
		t.Fatalf("fixture operation failed: %v", result)
	}
}

func TestNFTTrafficIsolation(t *testing.T) {
	runNFTTrafficTopology(t, false)
}
func TestNFTSelectiveTrafficIsolation(t *testing.T) {
	runNFTTrafficTopology(t, true)
}
func runNFTTrafficTopology(t *testing.T, selective bool) {
	if os.Getenv("PB_NFT_TRAFFIC_CHILD") != "1" {
		ns, err := os.Readlink("/proc/self/ns/net")
		if err != nil {
			t.Fatal(err)
		}
		mountNS, err := os.Readlink("/proc/self/ns/mnt")
		if err != nil {
			t.Fatal(err)
		}
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 210*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/usr/bin/unshare", "--mount", "--net", "--pid", "--fork", "--mount-proc", exe, "-test.run", "^"+t.Name()+"$", "-test.v")
		cmd.Env = append(os.Environ(), "PB_NFT_TRAFFIC_CHILD=1", "PB_NFT_TRAFFIC_PARENT_NS="+ns, "PB_NFT_PARENT_MOUNT_NS="+mountNS)
		output, err := cmd.CombinedOutput()
		if err != nil {
			if os.Getenv("PB_REQUIRE_NFT") != "1" && (errors.Is(err, os.ErrNotExist) || strings.Contains(string(output), "Operation not permitted")) {
				t.Skipf("isolated topology capability unavailable: %v", err)
			}
			t.Fatalf("real forwarding topology failed: %v\n%s", err, output)
		}
		t.Logf("real forwarding topology:\n%s", output)
		return
	}
	ns, _ := os.Readlink("/proc/self/ns/net")
	mnt, _ := os.Readlink("/proc/self/ns/mnt")
	if ns == os.Getenv("PB_NFT_TRAFFIC_PARENT_NS") || mnt == os.Getenv("PB_NFT_PARENT_MOUNT_NS") || os.Getenv("PB_NFT_TRAFFIC_PARENT_NS") == "" {
		t.Fatal("isolated network/mount namespaces required")
	}
	run := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			t.Fatalf("isolated fixture command failed: %v: %s", err, out)
		}
		return string(out)
	}
	run("/usr/bin/mount", "--make-rprivate", "/")
	run("/usr/bin/mount", "-t", "tmpfs", "-o", "nosuid,nodev,noexec", "tmpfs", "/run")
	if err := os.MkdirAll("/run/netns", 0755); err != nil {
		t.Fatal(err)
	}
	ip := func(args ...string) { run(append([]string{"/usr/sbin/ip"}, args...)...) }
	ip("link", "set", "lo", "up")
	for _, name := range []string{"pc", "pt"} {
		ip("netns", "add", name)
		ip("netns", "exec", name, "/usr/sbin/ip", "link", "set", "lo", "up")
	}
	for _, pair := range []struct{ router, peer, ns string }{{"rcli", "cli", "pc"}, {"rtgt", "tgt", "pt"}, {"ralt", "alt", "pc"}} {
		ip("link", "add", pair.router, "type", "veth", "peer", "name", pair.peer)
		ip("link", "set", pair.peer, "netns", pair.ns)
		ip("link", "set", pair.router, "up")
		ip("netns", "exec", pair.ns, "/usr/sbin/ip", "link", "set", pair.peer, "up")
	}
	addr := func(ns, dev, address string) {
		args := []string{"/usr/sbin/ip", "addr", "add", address, "dev", dev}
		if strings.Contains(address, ":") {
			args = append(args, "nodad")
		}
		if ns != "" {
			args = append([]string{"/usr/sbin/ip", "netns", "exec", ns}, args...)
		}
		run(args...)
	}
	for _, a := range []string{"192.0.2.1/24", "192.0.2.3/24", "2001:db8:1::1/64", "2001:db8:1::3/64", "fe80::1/64"} {
		addr("", "rcli", a)
	}
	for _, a := range []string{"198.51.100.1/24", "10.245.0.1/24", "2001:db8:2::1/64", "fd42:245::1/64"} {
		addr("", "rtgt", a)
	}
	addr("", "ralt", "203.0.113.1/24")
	for _, a := range []string{"192.0.2.2/24", "2001:db8:1::2/64", "fe80::2/64"} {
		addr("pc", "cli", a)
	}
	addr("pc", "alt", "203.0.113.2/24")
	targets := []string{"198.51.100.2", "198.51.100.3", "10.245.0.2", "2001:db8:2::2", "2001:db8:2::3", "fd42:245::2"}
	for _, a := range targets {
		bits := "/24"
		if strings.Contains(a, ":") {
			bits = "/64"
		}
		addr("pt", "tgt", a+bits)
	}
	for _, entry := range []struct{ ns, family, gateway string }{{"pc", "-4", "192.0.2.1"}, {"pc", "-6", "2001:db8:1::1"}, {"pt", "-4", "198.51.100.1"}, {"pt", "-6", "2001:db8:2::1"}} {
		ip("netns", "exec", entry.ns, "/usr/sbin/ip", entry.family, "route", "add", "default", "via", entry.gateway)
	}
	run("/usr/sbin/sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", "net.ipv4.conf.all.rp_filter=0")
	peerScript, err := filepath.Abs("testdata/nft_traffic_peer.py")
	if err != nil {
		t.Fatal(err)
	}
	addressJSON, _ := json.Marshal(targets)
	server := startTrafficPeer(t, []string{"/usr/sbin/ip", "netns", "exec", "pt", "/usr/bin/python3", "-u", peerScript, "server", string(addressJSON), "[28080,28081]"}, nil)
	_ = server
	client := startTrafficPeer(t, []string{"/usr/sbin/ip", "netns", "exec", "pc", "/usr/bin/python3", "-u", peerScript, "client"}, nil)
	localClient := startTrafficPeer(t, []string{"/usr/bin/python3", "-u", peerScript, "client"}, nil)
	dns := startTrafficPeer(t, []string{"/usr/bin/python3", "-u", peerScript, "dns"}, nil)
	dnsAddress := "127.0.0.1:" + strconv.Itoa(int(dns.ready["port"].(float64)))
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	controllerExecutable, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = controllerExecutable.Close() })
	stateDir, err := os.MkdirTemp("/run", "portbridge-recovery-test-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(stateDir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	controller := func() *trafficPeer {
		return startTrafficPeer(t, []string{"/usr/bin/setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs", "--bounding-set=-all,+net_admin,+net_bind_service", "--inh-caps=-all,+net_admin,+net_bind_service", "--ambient-caps=-all,+net_admin,+net_bind_service", "/proc/self/fd/3"},
			[]string{"PB_NFT_CONTROLLER_PEER=1", "PB_NFT_ROUTER_NS=" + ns, "PB_NFT_ROUTER_MOUNT_NS=" + mnt,
				"PB_NFT_RECOVERY_CONFIG=" + filepath.Join(stateDir, "config.json"), "PB_NFT_FIXTURE_DNS=" + dnsAddress}, controllerExecutable)
	}
	control := controller()
	t.Logf("controller fixture ready: %v", control.ready)
	if selective {
		trafficSelectiveACL(t, client, control, run)
		trafficAdmissionPreflight(t, control)
		return
	}
	for _, family := range []int{4, 6} {
		t.Run("ipv"+strconv.Itoa(family), func(t *testing.T) {
			listen, target, changed, private, source := "192.0.2.1", "198.51.100.2", "198.51.100.3", "10.245.0.2", "192.0.2.2"
			if family == 6 {
				listen, target, changed, private, source = "2001:db8:1::1", "2001:db8:2::2", "2001:db8:2::3", "fd42:245::2", "2001:db8:1::2"
			}
			a := config.NormalizeRule(config.Rule{ID: "a" + strconv.Itoa(family), Name: "A", Enabled: true, Protocol: config.ProtocolBoth,
				ListenHost: listen, ListenPort: 18080, TargetHost: target, TargetPort: 28080})
			b := a
			b.ID = "b" + strconv.Itoa(family)
			b.Name = "B"
			b.ListenPort = 18081
			apply := func(rules []config.Rule, flow bool) map[string]any {
				result := control.call(t, map[string]any{"op": "apply", "rules": rules, "flowtable": flow})
				requireFixtureOK(t, result)
				data, _ := json.Marshal(result["runtime"])
				var rows []RuleRuntime
				_ = json.Unmarshal(data, &rows)
				for _, row := range rows {
					if row.Stats.LastError != "" {
						t.Logf("controller rule=%s plane=%s running=%t error=%s fixture=%s", row.Rule.ID, row.DataPlane, row.Stats.Running, row.Stats.LastError, control.log.String())
					}
				}
				return result
			}
			open := func(id, proto, host string, port int) int {
				result := client.call(t, map[string]any{"op": "open", "id": id, "family": family, "protocol": proto, "host": host, "port": port, "source": source})
				requireFixtureOK(t, result)
				return int(result["source_port"].(float64))
			}
			request := func(id, want string) {
				t.Helper()
				result := client.call(t, map[string]any{"op": "request", "id": id, "data": "sequence"})
				if result["ok"] != true {
					t.Fatalf("flow %s expected target %s: %v", id, want, result)
				}
				if result["data"] != want+"|sequence" {
					t.Fatalf("wrong target/payload: %v want=%s", result, want)
				}
			}
			denied := func(id string) {
				result := client.call(t, map[string]any{"op": "request", "id": id, "data": "after-revocation"})
				if result["ok"] == true {
					t.Fatalf("retired path still forwards: %v", result)
				}
			}
			oldMarker := target + ":28080"
			ports := make(map[string]int)
			reopenA := func() {
				ports["at"] = open("at", "tcp", listen, 18080)
				ports["au"] = open("au", "udp", listen, 18080)
			}
			otherIDs := make(map[string]string)
			getOtherID := func(id string) string {
				proto := "tcp"
				if strings.HasSuffix(id, "u") {
					proto = "udp"
				}
				host, port := listen, 18081
				if strings.HasPrefix(id, "c") {
					host, port = target, 28080
				}
				return trafficConntrackID(t, run, family, proto, source, host, ports[id], port)
			}
			checkOthers := func() {
				for _, id := range []string{"bt", "bu", "ct", "cu"} {
					request(id, oldMarker)
					if previous := otherIDs[id]; previous != "" && getOtherID(id) != previous {
						t.Fatalf("unrelated %s conntrack identity changed", id)
					}
				}
			}
			initial := apply([]config.Rule{a, b}, true)
			data, _ := json.Marshal(initial["runtime"])
			var initialRows []RuleRuntime
			_ = json.Unmarshal(data, &initialRows)
			for _, row := range initialRows {
				if !row.Stats.Running || row.Stats.LastError != "" {
					t.Logf("actual rules: %s", run("/usr/sbin/nft", "-j", "list", "table", "inet", nftTableName))
					t.Fatalf("initial controller state is not ready: %v", initial)
				}
			}
			reopenA()
			ports["bt"] = open("bt", "tcp", listen, 18081)
			ports["bu"] = open("bu", "udp", listen, 18081)
			ports["ct"] = open("ct", "tcp", target, 28080)
			ports["cu"] = open("cu", "udp", target, 28080)
			for i := 0; i < 8; i++ {
				request("at", oldMarker)
				request("au", oldMarker)
				checkOthers()
			}
			for _, item := range []struct {
				id, proto string
				port      int
			}{{"at", "tcp", 18080}, {"au", "udp", 18080}, {"bt", "tcp", 18081}, {"bu", "udp", 18081}} {
				out := run("/usr/sbin/conntrack", "-L", "-f", "ipv"+strconv.Itoa(family), "-p", item.proto, "--orig-src", source, "--orig-dst", listen,
					"--sport", strconv.Itoa(ports[item.id]), "--dport", strconv.Itoa(item.port), "--mark", "0x50420001/0xffffffff", "-o", "extended,id")
				if !strings.Contains(out, "[OFFLOAD]") {
					t.Fatalf("specific warmed flow has no OFFLOAD evidence: %s", out)
				}
				t.Logf("verified software OFFLOAD family=%d protocol=%s rule=%s", family, item.proto, item.id)
			}
			// Delete A; B and the unmarked direct controls retain the same sockets.
			for _, id := range []string{"bt", "bu", "ct", "cu"} {
				otherIDs[id] = getOtherID(id)
			}
			apply([]config.Rule{b}, true)
			denied("at")
			denied("au")
			checkOthers()
			fresh := client.call(t, map[string]any{"op": "open", "id": "new-disabled", "family": family, "protocol": "tcp", "host": listen, "port": 18080, "source": source})
			if fresh["ok"] == true {
				t.Fatal("new connection entered deleted rule")
			}
			apply([]config.Rule{a, b}, true)
			reopenA()
			request("at", oldMarker)
			request("au", oldMarker)
			a.Enabled = false
			apply([]config.Rule{a, b}, true)
			denied("at")
			denied("au")
			checkOthers()
			a.Enabled = true
			apply([]config.Rule{a, b}, true)
			reopenA()
			request("at", oldMarker)
			request("au", oldMarker)
			a.TargetPort = 28081
			apply([]config.Rule{a, b}, true)
			denied("at")
			request("au", target+":28081")
			checkOthers()
			reopenA()
			request("at", target+":28081")
			a.TargetHost = changed
			apply([]config.Rule{a, b}, true)
			denied("at")
			request("au", changed+":28081")
			checkOthers()
			alias := "alias" + strconv.Itoa(family) + ".portbridge.test"
			requireFixtureOK(t, dns.call(t, map[string]any{"op": "set", "name": alias, "address": target}))
			a.TargetHost = alias
			apply([]config.Rule{a, b}, true)
			reopenA()
			request("at", target+":28081")
			request("au", target+":28081")
			requireFixtureOK(t, dns.call(t, map[string]any{"op": "set", "name": alias, "address": changed}))
			requireFixtureOK(t, control.call(t, map[string]any{"op": "refresh", "rules": []config.Rule{a, b}}))
			denied("at")
			request("au", changed+":28081")
			checkOthers()
			reopenA()
			request("at", changed+":28081")
			requireFixtureOK(t, dns.call(t, map[string]any{"op": "fail", "value": true}))
			requireFixtureOK(t, control.call(t, map[string]any{"op": "refresh", "rules": []config.Rule{a, b}}))
			request("at", changed+":28081")
			request("au", changed+":28081")
			checkOthers()
			requireFixtureOK(t, dns.call(t, map[string]any{"op": "fail", "value": false}))
			policy := "policy" + strconv.Itoa(family) + ".portbridge.test"
			requireFixtureOK(t, dns.call(t, map[string]any{"op": "set", "name": policy, "address": private}))
			a.TargetHost = policy
			a.AllowPrivateTarget = true
			bits := "/32"
			if family == 6 {
				bits = "/128"
			}
			a.TargetCIDRAllowlist = []string{private + bits}
			apply([]config.Rule{a, b}, true)
			reopenA()
			request("at", private+":28081")
			request("au", private+":28081")
			a.AllowPrivateTarget = false
			a.TargetCIDRAllowlist = nil
			// Domain rules remain valid configuration; withdrawal is enforced by
			// address authorization even when DNS fails and cached data exists.
			requireFixtureOK(t, dns.call(t, map[string]any{"op": "fail", "value": true}))
			result := control.call(t, map[string]any{"op": "refresh", "rules": []config.Rule{a, b}})
			requireFixtureOK(t, result)
			denied("at")
			denied("au")
			checkOthers()
			requireFixtureOK(t, dns.call(t, map[string]any{"op": "fail", "value": false}))
			a.TargetHost = target
			a.TargetPort = 28080
			apply([]config.Rule{a, b}, true)
			reopenA()
			request("at", oldMarker)
			request("au", oldMarker)
			a.DataPlane = config.RuleDataPlaneGo
			apply([]config.Rule{a, b}, true)
			denied("at")
			request("au", oldMarker)
			checkOthers()
			reopenA()
			request("at", oldMarker)
			a.DataPlane = config.RuleDataPlaneNFT
			apply([]config.Rule{a, b}, true)
			denied("at")
			reopenA()
			request("at", oldMarker)
			request("au", oldMarker)
			checkOthers()
			apply([]config.Rule{a, b}, false)
			request("at", oldMarker)
			request("au", oldMarker)
			checkOthers()
			if out := run("/usr/sbin/nft", "-j", "list", "table", "inet", "portbridge"); strings.Contains(out, `"flowtable"`) {
				t.Fatal("NAT-only mode retains flowtable")
			}
			apply([]config.Rule{a, b}, true)
			for i := 0; i < 4; i++ {
				request("at", oldMarker)
				request("au", oldMarker)
				checkOthers()
			}
			// Combined loss: only the verified owned table is removed, then the
			// actual controller process dies. Durable service-owned history stays.
			inspector := newCommandNFTBackend(testLogger())
			if _, err := inspector.observe(); err != nil {
				t.Fatal(err)
			}
			if _, err := inspector.kernel.Apply("add table inet pb_fixture_nat_lifetime\nadd chain inet pb_fixture_nat_lifetime pre { type nat hook prerouting priority -101; policy accept; }\nadd chain inet pb_fixture_nat_lifetime post { type nat hook postrouting priority 101; policy accept; }\nadd chain inet pb_fixture_nat_lifetime ct_lifetime\nadd rule inet pb_fixture_nat_lifetime ct_lifetime ct state established accept\n"); err != nil {
				t.Fatal(err)
			}
			defer run("/usr/sbin/nft", "delete", "table", "inet", "pb_fixture_nat_lifetime")
			t.Log("COMBINED_LOSS_FIXTURE: independent empty NAT hooks and an unhooked conntrack reference retain kernel translation plumbing; no forwarding policy is added")
			run("/usr/sbin/nft", "delete", "table", "inet", nftTableName)
			request("at", oldMarker)
			request("au", oldMarker)
			checkOthers() // Object deletion alone must not stand in for revocation.
			control.kill()
			control = controller()
			a.Enabled = false
			result = apply([]config.Rule{a, b}, true)
			if result["pending"].(float64) != 0 || result["unknown"] == true {
				t.Fatalf("durable combined-loss recovery failed: %v", result)
			}
			denied("at")
			denied("au")
			checkOthers()
			a.Enabled = true
			apply([]config.Rule{a, b}, true)
			reopenA()
			request("at", oldMarker)
			request("au", oldMarker)

			// C1 positive: the actual full external chain is empty and policy
			// accept. Prove both old and NEW B traffic; do not substitute CT
			// existence or an active array for packets and tuple-bound OFFLOAD.
			if _, err := inspector.kernel.Apply("add table inet pb_fixture_dynamic_policy\nadd chain inet pb_fixture_dynamic_policy post { type filter hook postrouting priority 200; policy accept; }\n"); err != nil {
				t.Fatal(err)
			}
			external := run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_fixture_dynamic_policy")
			a.Enabled = false
			result = apply([]config.Rule{a, b}, true)
			denied("at")
			denied("au")
			checkOthers()
			if external != run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_fixture_dynamic_policy") {
				t.Fatal("controller changed empty external policy")
			}
			data, _ = json.Marshal(result["runtime"])
			var conflictRows []RuleRuntime
			if err := json.Unmarshal(data, &conflictRows); err != nil {
				t.Fatal(err)
			}
			bActive := false
			for _, row := range conflictRows {
				if row.Rule.ID == b.ID {
					bActive = row.KernelState == "active-verified" && row.Stats.Running && !row.GoRunning && row.Stats.LastError == ""
				}
			}
			if !bActive {
				t.Fatalf("empty-chain proof did not preserve B policy: %v", result)
			}
			for _, proto := range []string{"tcp", "udp"} {
				id := "new-b-empty-" + proto
				port := open(id, proto, listen, 18081)
				for warm := 0; warm < 8; warm++ {
					request(id, oldMarker)
				}
				out := run("/usr/sbin/conntrack", "-L", "-f", "ipv"+strconv.Itoa(family), "-p", proto, "--orig-src", source, "--orig-dst", listen,
					"--sport", strconv.Itoa(port), "--dport", "18081", "--mark", "0x50420001/0xffffffff", "-o", "extended,id")
				if !strings.Contains(out, "[OFFLOAD]") {
					t.Fatalf("new B lacks tuple-bound OFFLOAD: %s", out)
				}
				requireFixtureOK(t, client.call(t, map[string]any{"op": "close", "id": id}))
			}
			t.Log("C1 EMPTY-HOOK: old/new TCP+UDP B and tuple-specific OFFLOAD passed; A retired; foreign objects unchanged")

			// F1: nonempty pure accept is supported without changing B's requested
			// flowtable mode. Fresh source ports and both-direction tuple filters
			// distinguish these streams from the previously warmed B connections.
			if _, err := inspector.kernel.Apply("add rule inet pb_fixture_dynamic_policy post accept\n"); err != nil {
				t.Fatal(err)
			}
			seenBPorts := map[string]map[int]bool{"tcp": {ports["bt"]: true}, "udp": {ports["bu"]: true}}
			verifyNewB := func(t *testing.T, label string) {
				t.Helper()
				externalBefore := run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_fixture_dynamic_policy")
				result = apply([]config.Rule{a, b}, true)
				checkOthers()
				data, _ = json.Marshal(result["runtime"])
				conflictRows = nil
				if err := json.Unmarshal(data, &conflictRows); err != nil {
					t.Fatal(err)
				}
				active := false
				for _, row := range conflictRows {
					if row.Rule.ID == b.ID {
						active = row.KernelState == "active-verified" && row.Stats.Running && !row.GoRunning && row.Stats.LastError == ""
					}
				}
				if !active {
					t.Fatalf("accept-only B state is not active: %v", result)
				}
				for _, proto := range []string{"tcp", "udp"} {
					t.Run(proto, func(t *testing.T) {
						id := label + "-" + proto
						opened := client.call(t, map[string]any{"op": "open", "id": id, "family": family, "protocol": proto, "host": listen, "port": 18081, "source": source})
						requireFixtureOK(t, opened)
						port := int(opened["source_port"].(float64))
						if seenBPorts[proto][port] {
							t.Fatal("new-B probe reused a previously warmed source port")
						}
						seenBPorts[proto][port] = true
						for warm := 0; warm < 8; warm++ {
							reply := client.call(t, map[string]any{"op": "request", "id": id, "data": "accept-only-payload"})
							requireFixtureOK(t, reply)
							if reply["data"] != oldMarker+"|accept-only-payload" {
								t.Fatalf("wrong accept-only B payload: %v", reply)
							}
						}
						out := run("/usr/sbin/conntrack", "-L", "-f", "ipv"+strconv.Itoa(family), "-p", proto, "--orig-src", source, "--orig-dst", listen,
							"--sport", strconv.Itoa(port), "--dport", "18081", "--reply-src", target, "--reply-port-src", "28080", "--mark", "0x50420001/0xffffffff", "-o", "extended,id")
						if !strings.Contains(out, "[OFFLOAD]") {
							t.Fatalf("specific new B tuple lacks software OFFLOAD: %s", out)
						}
						t.Logf("V247_ACCEPT_ONLY_NEW_B_VERIFIED family=%d protocol=%s source_port=%d phase=%s software_offload=true", family, proto, port, label)
						if strings.HasPrefix(label, "conditional-") {
							t.Logf("V248_TRANSPARENT_NEW_B_VERIFIED level=L3 family=%d protocol=%s source_port=%d phase=%s payload_verified=true exact_tuple=true software_offload=true", family, proto, port, label)
						}
						requireFixtureOK(t, client.call(t, map[string]any{"op": "close", "id": id}))
					})
				}
				if strings.HasPrefix(label, "conditional-") {
					if !strings.Contains(run("/usr/sbin/nft", "-j", "list", "table", "inet", nftTableName), `"flowtable"`) {
						t.Fatal("conditional acceptance lost the requested flowtable")
					}
					if out := os.Getenv("AUDIT_EVIDENCE"); out != "" {
						actual := run("/usr/sbin/nft", "-j", "list", "ruleset")
						if err := os.WriteFile(filepath.Join(out, "real-nft-ipv"+strconv.Itoa(family)+"-"+label+".json"), []byte(actual), 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
				if externalBefore != run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_fixture_dynamic_policy") {
					t.Fatal("controller modified external accept-only rules")
				}
			}
			t.Run("accept-only-new-B", func(t *testing.T) { verifyNewB(t, "single-accept") })
			if _, err := inspector.kernel.Apply("add rule inet pb_fixture_dynamic_policy post accept\nadd rule inet pb_fixture_dynamic_policy post accept\n"); err != nil {
				t.Fatal(err)
			}
			t.Run("multiple-accept-new-B", func(t *testing.T) { verifyNewB(t, "multiple-accept") })

			// G248: remove the earlier unconditional rules so the real packets
			// exercise matching and policy-fall-through branches. Each phase
			// retires a newly warmed A while checking old and NEW B and foreign.
			for _, phase := range []string{"conditional-match", "conditional-miss", "conditional-multi", "conditional-multichain"} {
				a.Enabled = true
				apply([]config.Rule{a, b}, true)
				reopenA()
				for warm := 0; warm < 4; warm++ {
					request("at", oldMarker)
					request("au", oldMarker)
				}
				run("/usr/sbin/nft", "flush", "chain", "inet", "pb_fixture_dynamic_policy", "post")
				rules := "add rule inet pb_fixture_dynamic_policy post tcp dport 28080 accept\nadd rule inet pb_fixture_dynamic_policy post udp dport 28080 accept\n"
				if phase == "conditional-miss" {
					rules = "add rule inet pb_fixture_dynamic_policy post tcp dport 1 accept\nadd rule inet pb_fixture_dynamic_policy post udp dport 1 accept\n"
				}
				if phase == "conditional-multi" || phase == "conditional-multichain" {
					ip, nf := "ip", "ipv4"
					if family == 6 {
						ip, nf = "ip6", "ipv6"
					}
					rules = ""
					for _, proto := range []string{"tcp", "udp"} {
						rules += "add rule inet pb_fixture_dynamic_policy post meta nfproto " + nf + " meta l4proto " + proto + " " + ip + " daddr " + target + " " + proto + " sport >= 0 " + proto + " dport 28080 accept\n"
					}
				}
				if _, err := inspector.kernel.Apply(rules); err != nil {
					t.Fatal(err)
				}
				second := ""
				if phase == "conditional-multichain" {
					if _, err := inspector.kernel.Apply("add table inet pb_fixture_transparent_second\nadd chain inet pb_fixture_transparent_second post { type filter hook postrouting priority 202; policy accept; }\nadd rule inet pb_fixture_transparent_second post meta l4proto tcp tcp sport != 0 accept\n"); err != nil {
						t.Fatal(err)
					}
					second = run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_fixture_transparent_second")
				}
				a.Enabled = false
				t.Run(phase+"-new-B", func(t *testing.T) { verifyNewB(t, phase); denied("at"); denied("au") })
				if second != "" {
					if second != run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_fixture_transparent_second") {
						t.Fatal("controller modified the second transparent chain")
					}
					run("/usr/sbin/nft", "delete", "table", "inet", "pb_fixture_transparent_second")
				}
			}

			// A later counter/accept is deliberately unproved even after an earlier
			// accept. Keep the former negative branch, but not its obsolete pure-
			// accept expectation. Old B conntrack/payload survives, new B is gated.
			if _, err := inspector.kernel.Apply("add rule inet pb_fixture_dynamic_policy post counter accept\n"); err != nil {
				t.Fatal(err)
			}
			result = apply([]config.Rule{a, b}, true)
			checkOthers()
			data, _ = json.Marshal(result["runtime"])
			if err := json.Unmarshal(data, &conflictRows); err != nil {
				t.Fatal(err)
			}
			bSuspended := false
			for _, row := range conflictRows {
				if row.Rule.ID == b.ID {
					bSuspended = row.KernelState == "admission-suspended"
				}
			}
			if !bSuspended {
				t.Fatalf("unsupported side-effect rule was certified: %v", result)
			}
			for _, proto := range []string{"tcp", "udp"} {
				id := "new-b-unsupported-" + proto
				opened := client.call(t, map[string]any{"op": "open", "id": id, "family": family, "protocol": proto, "host": listen, "port": 18081, "source": source})
				if opened["ok"] == true {
					if proto == "tcp" {
						t.Fatal("unproved new TCP admission survived gate")
					}
					denied(id)
				}
				requireFixtureOK(t, client.call(t, map[string]any{"op": "close", "id": id}))
			}
			if strings.Contains(run("/usr/sbin/nft", "-j", "list", "table", "inet", nftTableName), `"flowtable"`) {
				t.Fatal("cached acceleration survived detected unsupported policy")
			}
			// Only the fixture changes its own external table; no global flush.
			// Reprove the current conditional rules; the prior active record is
			// not permission. Fresh tuples must work after detected suspension.
			run("/usr/sbin/nft", "flush", "chain", "inet", "pb_fixture_dynamic_policy", "post")
			if _, err := inspector.kernel.Apply("add rule inet pb_fixture_dynamic_policy post tcp dport 1 accept\nadd rule inet pb_fixture_dynamic_policy post udp dport 1 accept\n"); err != nil {
				t.Fatal(err)
			}
			t.Run("conditional-restored-new-B", func(t *testing.T) { verifyNewB(t, "conditional-restored") })
			run("/usr/sbin/nft", "flush", "chain", "inet", "pb_fixture_dynamic_policy", "post")
			if _, err := inspector.kernel.Apply("add rule inet pb_fixture_dynamic_policy post accept\n"); err != nil {
				t.Fatal(err)
			}
			t.Run("accept-restored-new-B", func(t *testing.T) { verifyNewB(t, "restored-accept") })

			// One accept base chain must not mask a separate actual drop chain.
			// Dedicated cached B streams observe the detection window and the
			// post-coordination deny without contaminating the original B sockets
			// with deliberately timed-out application requests.
			for _, proto := range []string{"tcp", "udp"} {
				id := "cached-policy-" + proto
				port := open(id, proto, listen, 18081)
				for warm := 0; warm < 8; warm++ {
					request(id, oldMarker)
				}
				out := run("/usr/sbin/conntrack", "-L", "-f", "ipv"+strconv.Itoa(family), "-p", proto, "--orig-src", source, "--orig-dst", listen,
					"--sport", strconv.Itoa(port), "--dport", "18081", "--reply-src", target, "--reply-port-src", "28080", "--mark", "0x50420001/0xffffffff", "-o", "extended,id")
				if !strings.Contains(out, "[OFFLOAD]") {
					t.Fatalf("policy-window B tuple was not cached before the change: %s", out)
				}
			}
			if _, err := inspector.kernel.Apply("add table inet pb_fixture_second_policy\nadd chain inet pb_fixture_second_policy post { type filter hook postrouting priority 201; policy accept; }\nadd rule inet pb_fixture_second_policy post ct mark 0x50420001 drop\n"); err != nil {
				t.Fatal(err)
			}
			secondBefore := run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_fixture_second_policy")
			for _, proto := range []string{"tcp", "udp"} {
				observed := client.call(t, map[string]any{"op": "request", "id": "cached-policy-" + proto, "data": "before-refresh"})
				t.Logf("V247_POLICY_WINDOW phase=before-refresh time=%s family=%d protocol=%s reply_ok=%v", time.Now().UTC().Format(time.RFC3339Nano), family, proto, observed["ok"])
			}
			result = apply([]config.Rule{a, b}, true)
			t.Logf("V247_POLICY_WINDOW phase=coordination-complete time=%s family=%d", time.Now().UTC().Format(time.RFC3339Nano), family)
			for _, proto := range []string{"tcp", "udp"} {
				id := "cached-policy-" + proto
				denied(id)
				requireFixtureOK(t, client.call(t, map[string]any{"op": "close", "id": id}))
				id = "new-b-drop-" + proto
				opened := client.call(t, map[string]any{"op": "open", "id": id, "family": family, "protocol": proto, "host": listen, "port": 18081, "source": source})
				if opened["ok"] == true {
					if proto == "tcp" {
						t.Fatal("new TCP bypassed a separate drop chain")
					}
					denied(id)
				}
				requireFixtureOK(t, client.call(t, map[string]any{"op": "close", "id": id}))
			}
			for _, id := range []string{"ct", "cu"} {
				request(id, oldMarker)
			}
			for _, id := range []string{"bt", "bu", "ct", "cu"} {
				if getOtherID(id) != otherIDs[id] {
					t.Fatal("policy suspension deleted unrelated conntrack", id)
				}
			}
			if strings.Contains(run("/usr/sbin/nft", "-j", "list", "table", "inet", nftTableName), `"flowtable"`) {
				t.Fatal("flowtable survived detected separate drop policy")
			}
			if secondBefore != run("/usr/sbin/nft", "-j", "list", "table", "inet", "pb_fixture_second_policy") {
				t.Fatal("controller changed the separate external drop policy")
			}
			run("/usr/sbin/nft", "delete", "table", "inet", "pb_fixture_second_policy")
			t.Run("separate-drop-removed-new-B", func(t *testing.T) { verifyNewB(t, "drop-removed") })
			t.Logf("V247_DYNAMIC_POLICY_VERIFIED family=%d accept / unsupported / accept / separate-drop / accept; no zero-window guarantee", family)
			run("/usr/sbin/nft", "delete", "table", "inet", "pb_fixture_dynamic_policy")
			a.Enabled = true
			apply([]config.Rule{a, b}, true)
			reopenA()
			request("at", oldMarker)
			request("au", oldMarker)
			checkOthers()

			// Persist a failed retirement, kill the real controller process, then
			// recover from kernel state in a new process with the same B sockets.
			requireFixtureOK(t, control.call(t, map[string]any{"op": "fault", "faildelete": true}))
			a.Enabled = false
			result = apply([]config.Rule{a, b}, true)
			if result["pending"].(float64) == 0 {
				t.Fatal("injected retirement failure lost pending state")
			}
			checkOthers()
			oldPID := control.cmd.Process.Pid
			control.kill()
			objects, err := decodeNFTObjects([]byte(run("/usr/sbin/nft", "-j", "list", "table", "inet", "portbridge")))
			if err != nil {
				t.Fatal(err)
			}
			journal, err := decodeNFTJournal(objects, nftOwnerMarker(config.DefaultNFTConntrackMark))
			if err != nil || len(journal.retired) == 0 {
				t.Fatalf("crash did not leave the pending kernel journal: %v", err)
			}
			control = controller()
			if control.cmd.Process.Pid == oldPID {
				t.Fatal("controller was not recreated")
			}
			result = apply([]config.Rule{a, b}, true)
			if result["pending"].(float64) != 0 || result["unknown"] == true {
				t.Fatalf("restart did not recover retirement: %v", result)
			}
			denied("at")
			denied("au")
			checkOthers()
			apply(nil, true)
			for _, id := range []string{"at", "au", "bt", "bu", "ct", "cu", "new-disabled"} {
				requireFixtureOK(t, client.call(t, map[string]any{"op": "close", "id": id}))
			}
			t.Logf("verified old/new flow revocation, NAT-only, mode switch, recovery and A/B/control isolation for IPv%d", family)
		})
	}
	trafficFirewallAdmission(t, client, control)
	trafficEdgeCases(t, client, localClient, control, run)
	trafficAdmissionPreflight(t, control)
	trafficConntrackZones(t)
}

func trafficFirewallAdmission(t *testing.T, client, control *trafficPeer) {
	t.Helper()
	for _, family := range []int{4, 6} {
		for _, proto := range []string{"tcp", "udp"} {
			t.Run("firewall-ipv"+strconv.Itoa(family)+"-"+proto, func(t *testing.T) {
				listen, target, source, ip := "192.0.2.1", "198.51.100.2", "192.0.2.2", "ip"
				if family == 6 {
					listen, target, source, ip = "2001:db8:1::1", "2001:db8:2::2", "2001:db8:1::2", "ip6"
				}
				kernel := newCommandNFTBackend(testLogger()).kernel
				script := "add table inet pb_fixture_filter\nadd chain inet pb_fixture_filter admission { type filter hook forward priority 10; policy accept; }\n" +
					"add rule inet pb_fixture_filter admission " + ip + " daddr " + target + " " + proto + " dport 28080 ct state established counter drop\n"
				if _, err := kernel.Apply(script); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if _, err := kernel.Apply("delete table inet pb_fixture_filter\n"); err != nil {
						t.Error(err)
					}
				}()
				rule := config.NormalizeRule(config.Rule{ID: "firewall", Name: "firewall", Enabled: true, Protocol: proto, ListenHost: listen, ListenPort: 18090, TargetHost: target, TargetPort: 28080})
				for _, accelerate := range []bool{false, true} {
					result := control.call(t, map[string]any{"op": "apply", "rules": []config.Rule{rule}, "flowtable": accelerate})
					requireFixtureOK(t, result)
					data, _ := json.Marshal(result["runtime"])
					var rows []RuleRuntime
					_ = json.Unmarshal(data, &rows)
					for _, row := range rows {
						if !row.Stats.Running || row.Stats.LastError != "" {
							t.Fatalf("firewall test rule not ready: %v", result)
						}
					}
					id := "firewall"
					requireFixtureOK(t, client.call(t, map[string]any{"op": "open", "id": id, "family": family, "protocol": proto, "host": listen, "port": 18090, "source": source}))
					if proto == "udp" {
						requireFixtureOK(t, client.call(t, map[string]any{"op": "request", "id": id, "data": "new-state-allowed"}))
					}
					for i := 0; i < 3; i++ {
						response := client.call(t, map[string]any{"op": "request", "id": id, "data": "established-state-denied"})
						if response["ok"] == true {
							t.Fatalf("external forward deny bypassed: family=%d proto=%s flowtable=%t attempt=%d", family, proto, accelerate, i)
						}
					}
					requireFixtureOK(t, client.call(t, map[string]any{"op": "close", "id": id}))
					requireFixtureOK(t, control.call(t, map[string]any{"op": "apply", "rules": []config.Rule{}, "flowtable": accelerate}))
				}
				t.Log("external priority 10 deny retained for new/established traffic in NAT-only and flowtable modes")
			})
		}
	}
}
