package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"portbridge/internal/acl"
	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

func TestTLSSettingsPreservePolicyAndPendingRestart(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	acls, err := acl.New(false, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store, acls, proxy.NewManager(logger), logger, "")
	if err != nil {
		t.Fatal(err)
	}
	send := func(field string) bool {
		body := `{"port":9080,"listen_ipv4":"127.0.0.1","listen_ipv6":"::1","whitelist":[],"dns_servers":[]` + field + `}`
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:12345"
		server.handleSettings(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("settings: %d %s", rr.Code, rr.Body.String())
		}
		var result struct {
			Restart bool `json:"restart_required"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Restart
	}
	if !send(`,"tls_min_version":"1.3"`) {
		t.Error("policy change must require restart")
	}
	if !send(`,"tls_min_version":"1.3"`) {
		t.Error("saving again hid the still-pending TLS restart")
	}
	if !send("") {
		t.Error("legacy client hid the still-pending TLS restart")
	}
	if got := store.Get().Web.TLSMinVersion; got != "1.3" {
		t.Errorf("omitting the new field downgraded TLS policy to %q", got)
	}
	if send(`,"tls_min_version":"1.2"`) {
		t.Error("reverting to the active TLS policy should clear the pending restart")
	}
}
