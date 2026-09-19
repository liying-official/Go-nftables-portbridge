package proxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"portbridge/internal/config"
)

func TestNFTEmptyProofRejectsIncompleteOrNonemptyDumps(t *testing.T) {
	valid := make([]byte, 20)
	binary.NativeEndian.PutUint32(valid, 20)
	binary.NativeEndian.PutUint16(valid[4:], unix.NLMSG_DONE)
	binary.NativeEndian.PutUint16(valid[6:], unix.NLM_F_MULTI)
	binary.NativeEndian.PutUint32(valid[8:], 1)
	binary.NativeEndian.PutUint32(valid[12:], 2)
	if done, err := emptyNetfilterReply(valid, 1, 2); !done || err != nil {
		t.Fatal("valid completion rejected")
	}
	for _, kind := range []string{"short", "long", "length", "sequence", "recipient", "ack", "object", "interrupted", "filtered", "errno"} {
		t.Run(kind, func(t *testing.T) {
			data := append([]byte(nil), valid...)
			switch kind {
			case "short":
				data = data[:19]
			case "long":
				data = append(data, 0)
			case "length":
				data[0]++
			case "sequence":
				data[8]++
			case "recipient":
				data[12]++
			case "ack":
				binary.NativeEndian.PutUint16(data[4:], unix.NLMSG_ERROR)
			case "object":
				binary.NativeEndian.PutUint16(data[4:], 0xa00)
			case "interrupted":
				binary.NativeEndian.PutUint16(data[6:], unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR)
			case "filtered":
				binary.NativeEndian.PutUint16(data[6:], unix.NLM_F_MULTI|unix.NLM_F_DUMP_FILTERED)
			case "errno":
				data[16] = 1
			}
			if _, err := emptyNetfilterReply(data, 1, 2); err == nil {
				t.Fatal("non-proof treated as empty kernel")
			}
		})
	}
	if err := emptyNetfilterDump(0x0a00, time.Now()); err == nil {
		t.Fatal("write opcode accepted by read-only helper")
	}
}
func requireCleanReviewNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("PB_REVIEW_CLEAN_NETNS") != "1" {
		t.Skip("requires independently created clean network namespace")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	parent := os.Getenv("PB_REVIEW_PARENT_NS")
	if err != nil || parent == "" || current == parent {
		t.Fatal("clean socket probe lacks verified parent/child namespace separation")
	}
	for _, p := range []string{"/usr/sbin/nft", "/usr/bin/nft"} {
		if _, err := os.Stat(p); err == nil {
			t.Skip("CLI-free socket probe requires a genuinely absent nft executable")
		}
	}
}
func TestReviewCleanGoSocketMatrix(t *testing.T) {
	requireCleanReviewNamespace(t)
	for _, protocol := range []string{"tcp", "udp"} {
		for _, pair := range [][2]string{{"127.0.0.1", "127.0.0.1"}, {"::1", "::1"}, {"127.0.0.1", "::1"}, {"::1", "127.0.0.1"}} {
			t.Run(protocol+"/"+pair[0]+"-to-"+pair[1], func(t *testing.T) {
				family := func(host string) string {
					if host == "::1" {
						return "6"
					}
					return "4"
				}
				var targetPort, listenPort int
				var stopEcho func()
				if protocol == "tcp" {
					_, targetPort, stopEcho = startTCPEcho(t, protocol+family(pair[1]), net.JoinHostPort(pair[1], "0"))
					listenPort = freeTCPPort(t, protocol+family(pair[0]), net.JoinHostPort(pair[0], "0"))
				} else {
					_, targetPort, stopEcho = startUDPEcho(t, protocol+family(pair[1]), net.JoinHostPort(pair[1], "0"))
					listenPort = freeUDPPort(t, protocol+family(pair[0]), net.JoinHostPort(pair[0], "0"))
				}
				defer stopEcho()
				cidr := pair[1] + "/32"
				if pair[1] == "::1" {
					cidr = pair[1] + "/128"
				}
				rule := config.NormalizeRule(config.Rule{ID: "clean-matrix", Name: "clean-matrix", Enabled: true, Protocol: protocol, DataPlane: config.RuleDataPlaneGo, ListenHost: pair[0], ListenPort: listenPort, TargetHost: pair[1], TargetPort: targetPort, AllowPrivateTarget: true, TargetCIDRAllowlist: []string{cidr}})
				m := NewManager(testLogger())
				defer m.Stop()
				path := privateNFTConfig(t)
				if err := m.SetNFTStateConfigPath(path); err != nil {
					t.Fatal(err)
				}
				m.Apply([]config.Rule{rule})
				for iteration := 0; iteration < 3; iteration++ {
					row, ok := runtimeByID(m, rule.ID)
					if !ok || !row.Stats.Running || !row.GoRunning || row.KernelState != "inactive-verified" {
						t.Fatalf("state disagrees with proven Go listener: %+v", row)
					}
					conn, err := net.DialTimeout(protocol+family(pair[0]), net.JoinHostPort(pair[0], portString(listenPort)), time.Second)
					if err != nil {
						t.Fatal(err)
					}
					if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					payload := []byte("manager-lifecycle-recovery")
					if _, err := conn.Write(payload); err != nil {
						t.Fatal(err)
					}
					reply := make([]byte, len(payload))
					if protocol == "tcp" {
						_, err = io.ReadFull(conn, reply)
					} else {
						var count int
						count, err = conn.Read(reply)
						if count != len(payload) {
							t.Fatal("short UDP reply")
						}
					}
					conn.Close()
					if err != nil || !bytes.Equal(reply, payload) {
						t.Fatalf("actual socket exchange failed: %v", err)
					}
					m.Refresh([]config.Rule{rule})
				}
				m.Stop()
				if len(m.runners) != 0 || m.resources.activeTCP.Load() != 0 || m.resources.activeUDP.Load() != 0 || m.resources.udpMemory.Load() != 0 {
					t.Fatal("Manager Stop leaked listeners/session budgets")
				}
				if _, err := os.Stat(path + ".nft-state.json"); !os.IsNotExist(err) {
					t.Fatal("CLI-free Go created an unnecessary historical ownership record")
				}
			})
		}
	}
}
func TestNFTUnknownStopsAlreadyRunningGoListener(t *testing.T) {
	host, targetPort, closeEcho := startTCPEcho(t, "tcp4", "127.0.0.1:0")
	defer closeEcho()
	rule := config.NormalizeRule(config.Rule{ID: "unknown-go", Enabled: true, Protocol: "tcp", DataPlane: config.RuleDataPlaneGo, ListenHost: "127.0.0.1", ListenPort: freeTCPPort(t, "tcp4", "127.0.0.1:0"), TargetHost: host, TargetPort: targetPort, AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"}})
	// The fake models already obtained kernel evidence, not a production bypass.
	n := &commandNFTBackend{kernel: &memoryNFTKernel{}, conntrack: &memoryConntrack{}, ownerMarker: nftOwnerMarker(config.DefaultNFTConntrackMark), initErr: errors.New("missing CLI"), cleanProbe: func() error { return nil }}
	m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
	defer m.Stop()
	m.Apply([]config.Rule{rule})
	if len(m.runners) != 1 {
		t.Fatal("fixture failed to start known-clean Go runner")
	}
	n.cleanProbe = func() error { return errors.New("nonempty or unknown kernel inventory") }
	m.Refresh([]config.Rule{rule})
	row, _ := runtimeByID(m, rule.ID)
	if len(m.runners) != 0 || row.GoRunning || row.Stats.Running || row.KernelState != "unknown" || row.DataPlane != DataPlaneGo {
		t.Fatalf("unknown state retained/misrepresented a Go listener: %+v", row)
	}
}

func TestNFTPendingBlocksOnlyOverlappingGoPath(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			var host string
			var targetPort int
			var closeEcho func()
			if protocol == "tcp" {
				host, targetPort, closeEcho = startTCPEcho(t, "tcp4", "127.0.0.1:0")
			} else {
				host, targetPort, closeEcho = startUDPEcho(t, "udp4", "127.0.0.1:0")
			}
			defer closeEcho()
			a, _ := reviewAB()
			a.ListenHost = netip.IPv4Unspecified()
			a.ListenPort = freeTCPPort(t, "tcp4", "127.0.0.1:0")
			a.ListenPortEnd = a.ListenPort
			k := newCausalNFTKernel(a)
			ct := &memoryConntrack{}
			n := reviewBackend(k, ct, privateNFTConfig(t))
			m := newManagerWithNFT(testLogger(), NewDNSResolver(nil), n)
			defer func() { ct.deleteErr = nil; m.Stop() }()
			m.Apply([]config.Rule{ruleFromNFTSpec(a)})
			if !n.initialized {
				t.Fatal("initial wildcard NFT setup failed")
			}
			ct.entries = []conntrackEntry{conntrackUnitEntry(a, 45000)}
			ct.deleteErr = errors.New("deliberate pending TCP retirement")
			next := config.NormalizeRule(config.Rule{ID: a.RuleID, Enabled: true, Protocol: protocol, DataPlane: config.RuleDataPlaneGo, ListenHost: "127.0.0.1", ListenPort: a.ListenPort, TargetHost: host, TargetPort: targetPort, AllowPrivateTarget: true, TargetCIDRAllowlist: []string{"127.0.0.1/32"}})
			m.Apply([]config.Rule{next})
			row, _ := runtimeByID(m, a.RuleID)
			if protocol == "tcp" {
				if len(m.runners) != 0 || row.GoRunning {
					t.Fatal("overlapping TCP replacement started before retirement")
				}
				return
			}
			if len(m.runners) != 1 || !row.GoRunning || row.KernelState != "retirement-pending" {
				t.Fatalf("pending TCP unnecessarily blocked nonoverlapping UDP: %+v", row)
			}
			conn, err := net.DialTimeout("udp4", net.JoinHostPort("127.0.0.1", portString(a.ListenPort)), time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte("nonoverlap")); err != nil {
				t.Fatal(err)
			}
			payload := make([]byte, 32)
			count, err := conn.Read(payload)
			if err != nil || string(payload[:count]) != "nonoverlap" {
				t.Fatalf("nonoverlap real UDP failed: %v", err)
			}
		})
	}
}
