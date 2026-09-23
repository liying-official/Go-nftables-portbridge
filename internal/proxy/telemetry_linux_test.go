//go:build linux

package proxy

import (
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"portbridge/internal/config"
)

func TestNFTTelemetryLive(t *testing.T) {
	parent := os.Getenv("PB_METRICS_PARENT_NS")
	if parent == "" {
		t.Skip("explicit isolated kernel test required")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || current == parent {
		t.Fatal("refusing a host-network test")
	}
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v %s", args, err, out)
		}
	}
	run("ip", "link", "set", "lo", "up")
	run("ip", "link", "add", "pbmetrics0", "type", "dummy")
	run("ip", "link", "set", "pbmetrics0", "up")
	for _, ip := range []string{"192.0.2.1/24", "192.0.2.10/24", "198.51.100.2/24"} {
		run("ip", "addr", "add", ip, "dev", "pbmetrics0")
	}
	for _, ip := range []string{"2001:db8:1::1/64", "2001:db8:1::10/64", "2001:db8:2::2/64"} {
		run("ip", "-6", "addr", "add", ip, "dev", "pbmetrics0", "nodad")
	}
	run("sysctl", "-qw", "net.netfilter.nf_conntrack_acct=1")
	for _, family := range []string{"udp4", "udp6"} {
		t.Run(family, func(t *testing.T) {
			listen, target, clientIP := "192.0.2.1", "198.51.100.2", "192.0.2.10"
			if family == "udp6" {
				listen, target, clientIP = "2001:db8:1::1", "2001:db8:2::2", "2001:db8:1::10"
			}
			server, err := net.ListenUDP(family, &net.UDPAddr{IP: net.ParseIP(target), Port: 29982})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			go func() {
				buffer := make([]byte, 2048)
				for {
					n, peer, err := server.ReadFromUDP(buffer)
					if err != nil {
						return
					}
					_, _ = server.WriteToUDP(buffer[:n], peer)
				}
			}()
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.json")
			store, _, err := config.LoadOrCreate(cfgPath, filepath.Join(dir, "admin.token"))
			if err != nil {
				t.Fatal(err)
			}
			rule := config.NormalizeRule(config.Rule{ID: "telemetry-" + family, Name: "Telemetry", Protocol: "udp", DataPlane: "nftables", ListenHost: listen, ListenPort: 29981, TargetHost: target, TargetPort: 29982, Enabled: true})
			cfg, err := store.Update(func(c *config.Config) error { c.Rules = []config.Rule{rule}; c.NFT.EnableFlowtable = false; return nil })
			if err != nil {
				t.Fatal(err)
			}
			manager := NewManager(slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err := manager.SetNFTStateConfigPath(cfgPath); err != nil {
				t.Fatal(err)
			}
			manager.SetRuntimeConfig(cfg.Limits, cfg.NFT)
			manager.Apply(cfg.Rules)
			defer manager.Stop()
			rows := manager.Runtime()
			if len(rows) != 1 || rows[0].Stats.LastError != "" {
				t.Fatalf("rule not active: %+v", rows)
			}
			client, err := net.DialUDP(family, &net.UDPAddr{IP: net.ParseIP(clientIP)}, &net.UDPAddr{IP: net.ParseIP(listen), Port: 29981})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_ = client.SetDeadline(time.Now().Add(4 * time.Second))
			send := func() {
				for i := 0; i < 5; i++ {
					if _, err := client.Write([]byte("sampled traffic")); err != nil {
						t.Fatal(err)
					}
					reply := make([]byte, 128)
					if _, err := client.Read(reply); err != nil {
						t.Fatal(err)
					}
				}
			}
			send()
			manager.SampleTelemetry()
			first := manager.Runtime()[0].Traffic
			if !first.NFTHooksAvailable || !first.NFT.Available || first.NFT.BytesUp == 0 || first.NFT.BytesDown == 0 {
				t.Fatalf("native counters unavailable: %+v", first)
			}
			time.Sleep(50 * time.Millisecond)
			send()
			manager.SampleTelemetry()
			second := manager.Runtime()[0].Traffic
			if !second.NFT.RateReady || second.NFT.BytesUpPerSecond <= 0 || second.NFT.BytesUp <= first.NFT.BytesUp {
				t.Fatalf("live rate missing: %+v", second)
			}
		})
	}
}
