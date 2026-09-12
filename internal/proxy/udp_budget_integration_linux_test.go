//go:build linux

package proxy

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"portbridge/internal/config"
)

func TestUDPSourceLimitAcrossReusePortWorkersAndLifecycle(t *testing.T) {
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		buffer := make([]byte, 512)
		for {
			n, peer, readErr := backend.ReadFromUDP(buffer)
			if readErr != nil {
				return
			}
			if _, writeErr := backend.WriteToUDP(buffer[:n], peer); writeErr != nil {
				return
			}
		}
	}()
	defer func() {
		_ = backend.Close()
		<-backendDone
	}()

	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listenPort := probe.LocalAddr().(*net.UDPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	backendPort := backend.LocalAddr().(*net.UDPAddr).Port
	rule := config.NormalizeRule(config.Rule{
		ID: "udp-shared-budget-integration", Name: "udp-shared-budget-integration",
		Enabled: true, Protocol: config.ProtocolUDP, DataPlane: config.RuleDataPlaneGo,
		ListenHost: "127.0.0.1", ListenPort: listenPort,
		TargetHost: "127.0.0.1", TargetPort: backendPort,
		UDPWorkers: 16, MaxUDPSessions: 64, MaxUDPSessionsPerIP: 1,
		UDPNewSessionsPerSec: 100, UDPPacketsPerSec: 1000,
		UDPBatchSize: 8, UDPPacketBufferSize: 512,
		UDPListenerBufferBytes: 64 << 10, UDPSessionBufferBytes: 16 << 10,
		UDPIdleTimeoutSeconds: 1,
	})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	run := newRunner(rule, &Stats{}, logger)
	run.resources = newResourceBudget(config.ResourceLimits{
		MaxTCPConnections: 16, MaxUDPSessions: 128, MaxUDPMemoryBytes: 64 << 20,
	})
	if err := run.start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			run.stop()
		}
	}()

	destination := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(listenPort))) // #nosec G115 -- OS-selected port is valid.
	first, err := net.DialUDP("udp4", nil, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := udpIntegrationRoundTrip(first, 500*time.Millisecond); err != nil {
		t.Fatalf("first UDP session failed: %v", err)
	}

	second, err := net.DialUDP("udp4", nil, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err := second.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	if err := second.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	if _, err := second.Read(buffer); err == nil {
		t.Fatal("second source-port session bypassed the source-IP limit across workers")
	} else if netErr := new(net.Error); !errors.As(err, netErr) || !(*netErr).Timeout() {
		t.Fatalf("second session read error = %v, want timeout", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := udpIntegrationRoundTrip(second, 300*time.Millisecond); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("expired UDP session did not release the shared source-IP capacity")
		}
		time.Sleep(100 * time.Millisecond)
	}

	run.stop()
	stopped = true
	if active := udpActiveSessionsForTest(run.budget, netip.MustParseAddr("127.0.0.1")); active != 0 {
		t.Fatalf("runner shutdown left %d shared source sessions reserved", active)
	}
}

func udpIntegrationRoundTrip(connection *net.UDPConn, timeout time.Duration) error {
	payload := []byte("portbridge-udp-budget")
	if _, err := connection.Write(payload); err != nil {
		return err
	}
	if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	buffer := make([]byte, len(payload))
	n, err := connection.Read(buffer)
	if err != nil {
		return err
	}
	if string(buffer[:n]) != string(payload) {
		return errors.New("unexpected UDP echo payload")
	}
	return nil
}
