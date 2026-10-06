package web

import (
	"bytes"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"portbridge/internal/acl"
	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

func TestDiagnosticsReadPermissionsAndNoConfigurationMutation(t *testing.T) {
	dir := t.TempDir()
	configPath, tokenPath := filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token")
	store, admin, err := config.LoadOrCreate(configPath, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := store.RotateMonitorToken()
	if err != nil {
		t.Fatal(err)
	}
	access, _ := acl.New(false, false, nil, nil)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := proxy.NewManager(logger)
	server, err := New(store, access, manager, logger, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(configPath)
	beforeToken, _ := os.ReadFile(tokenPath)
	for _, test := range []struct {
		method, token, remote string
		status                int
	}{
		{"GET", admin, "127.0.0.1:1111", 200}, {"GET", monitor, "127.0.0.1:1111", 200},
		{"GET", "", "127.0.0.1:1111", 401}, {"GET", monitor, "192.0.2.10:1111", 403},
		{"POST", admin, "127.0.0.1:1111", 405},
	} {
		r := httptest.NewRequest(test.method, "/api/diagnostics", nil)
		r.RemoteAddr = test.remote
		if test.token != "" {
			r.Header.Set("Authorization", "Bearer "+test.token)
		}
		w := httptest.NewRecorder()
		server.routes().ServeHTTP(w, r)
		if w.Code != test.status {
			t.Fatalf("%s/%s: %d %s", test.method, test.remote, w.Code, w.Body.String())
		}
		if w.Code == 200 {
			for _, secret := range []string{admin, monitor, config.HashToken(admin), config.HashToken(monitor)} {
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("diagnosis leaked credentials")
				}
			}
			if !strings.Contains(w.Body.String(), `"read_only":true`) || !strings.Contains(w.Body.String(), `"business_health":"not_checked"`) {
				t.Fatal("diagnostic boundaries missing")
			}
		}
	}
	after, _ := os.ReadFile(configPath)
	afterToken, _ := os.ReadFile(tokenPath)
	if !bytes.Equal(before, after) || !bytes.Equal(beforeToken, afterToken) {
		t.Fatal("diagnosis changed configuration or token")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Fatal("diagnosis created recovery state")
	}
}
