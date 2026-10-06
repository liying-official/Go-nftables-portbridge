package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadOnlyDoesNotSaveDefaultsOrCreateMissingFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := ReadOnly(path); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing configuration was created")
	}
	data := []byte(`{"version":2,"rules":[]}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := ReadOnly(path)
	if err != nil || cfg.Web.AdminTokenSHA != "" || cfg.Web.Port != 9080 {
		t.Fatalf("read-only default decoding: %+v %v", cfg, err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(data, after) {
		t.Fatal("read-only inspection persisted defaults")
	}
}
