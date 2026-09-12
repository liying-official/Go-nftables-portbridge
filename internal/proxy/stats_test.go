package proxy

import (
	"testing"
	"time"
)

func TestSetRunningPreservesStartTimeWhileAlreadyRunning(t *testing.T) {
	stats := &Stats{}
	stats.setRunning(true, "")
	started := stats.snapshot().StartedAt
	if started.IsZero() {
		t.Fatal("start time was not recorded")
	}
	time.Sleep(time.Millisecond)
	stats.setRunning(true, "")
	if got := stats.snapshot().StartedAt; !got.Equal(started) {
		t.Fatalf("start time changed during a running refresh: got %s, want %s", got, started)
	}
	stats.setRunning(false, "stopped")
	time.Sleep(time.Millisecond)
	stats.setRunning(true, "")
	if got := stats.snapshot().StartedAt; !got.After(started) {
		t.Fatalf("start time was not renewed after restart: got %s, old %s", got, started)
	}
}
