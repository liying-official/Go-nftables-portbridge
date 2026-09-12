package config

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConcurrentTokenRotationsKeepFileAndHashConsistent(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	store, _, err := LoadOrCreate(filepath.Join(dir, "config.json"), tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 8; round++ {
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 24 {
			wg.Go(func() {
				<-start
				if _, err := store.RotateAdminToken(tokenPath); err != nil {
					t.Error(err)
				}
			})
		}
		close(start)
		wg.Wait()
		if !TokenFileConsistent(tokenPath, store.Get().Web.AdminTokenSHA) {
			t.Fatalf("round %d: concurrent successful rotations left an unusable token file", round)
		}
	}
}

func TestTokenRotationDoesNotPublishDuringAnotherStoreTransaction(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	store, original, err := LoadOrCreate(filepath.Join(dir, "config.json"), tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	done := make(chan error, 1)
	go func() { _, err := store.RotateAdminToken(tokenPath); done <- err }()
	changed := false
	deadline := time.Now().Add(150 * time.Millisecond)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(tokenPath)
		if err != nil {
			store.mu.Unlock()
			<-done
			t.Fatal(err)
		}
		if strings.TrimSpace(string(data)) != original {
			changed = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	store.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("token file changed while an earlier store transaction was still in progress")
	}
}

func TestTokenRotationRollsBackWhenConfigCannotBeSaved(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "admin.token")
	store, original, err := LoadOrCreate(filepath.Join(dir, "config.json"), tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.path = filepath.Join(blocker, "config.json")
	if _, err := store.RotateAdminToken(tokenPath); err == nil {
		t.Fatal("expected save failure")
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != original || !TokenFileConsistent(tokenPath, store.Get().Web.AdminTokenSHA) {
		t.Fatal("failed rotation did not restore the original token and hash")
	}
}
