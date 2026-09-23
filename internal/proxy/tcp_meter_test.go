//go:build linux

package proxy

import (
	"bytes"
	"io"
	"testing"
	"time"
)

func TestTCPMeterTracksLiveSpliceWithoutDoubleCounting(t *testing.T) {
	r, client, target := repairTCPPair(t, 300)
	payload := bytes.Repeat([]byte("m"), 32768)
	done := make(chan error, 1)
	go func() { _, err := io.CopyN(io.Discard, target, int64(len(payload))); done <- err }()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	limit := time.Now().Add(2 * time.Second)
	live := uint64(0)
	for time.Now().Before(limit) {
		live, _ = r.stats.trafficBytes()
		if live >= uint64(len(payload)+1) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if live != uint64(len(payload)+1) {
		t.Fatalf("live payload invisible: %d", live)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	_ = target.Close()
	waitTCPReservationsReturned(t, r, 2*time.Second)
	up, _ := r.stats.trafficBytes()
	if up != live {
		t.Fatalf("closed copy double counted: live=%d final=%d", live, up)
	}
}
