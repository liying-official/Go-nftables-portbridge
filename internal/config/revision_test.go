package config

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestConfigRevisionRejectsStaleAtomicUpdate(t *testing.T) {
	dir := t.TempDir()
	store, _, err := LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	_, initial := store.GetWithRevision()
	updated, err := store.UpdateIfRevision(initial, func(c *Config) error {
		c.Web.Port++
		return nil
	})
	if err != nil || Revision(updated) == initial {
		t.Fatalf("versioned update failed: %v", err)
	}
	if _, err := store.UpdateIfRevision(initial, func(c *Config) error {
		c.Web.Port++
		return nil
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale update error = %v", err)
	}
	current, revision := store.GetWithRevision()
	if current.Web.Port != updated.Web.Port || revision != Revision(updated) {
		t.Fatal("stale update changed persisted configuration")
	}
}
