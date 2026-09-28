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

func TestMonitoringTokenIsReadOnlyAndRevocable(t *testing.T) {
	dir := t.TempDir()
	store, admin, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	access, err := acl.New(false, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := proxy.NewManager(logger)
	t.Cleanup(manager.Stop)
	server, err := New(store, access, manager, logger, filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	server.authFailures = newAuthFailureLimiter()
	server.authFailures.perIPBurst = 1000
	request := func(method, path, bearer string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", "Bearer "+bearer)
		if method != http.MethodGet {
			r.Header.Set("X-PortBridge-CSRF", server.csrf)
		}
		w := httptest.NewRecorder()
		server.routes().ServeHTTP(w, r)
		return w
	}
	if got := request(http.MethodGet, "/api/status", admin).Code; got != http.StatusOK {
		t.Fatalf("administrator status = %d", got)
	}
	firstResponse := request(http.MethodPost, "/api/monitor-token/rotate", admin)
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("create monitoring token = %d: %s", firstResponse.Code, firstResponse.Body.String())
	}
	var first struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(firstResponse.Body.Bytes(), &first); err != nil || len(first.Token) != 64 {
		t.Fatalf("invalid generated token: %v", err)
	}
	for _, path := range []string{"/api/status", "/metrics"} {
		if got := request(http.MethodGet, path, first.Token).Code; got != http.StatusOK {
			t.Fatalf("monitoring token %s = %d", path, got)
		}
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/bootstrap"}, {http.MethodGet, "/api/config"}, {http.MethodGet, "/api/rules/template"},
		{http.MethodPost, "/api/rules"}, {http.MethodPut, "/api/settings"},
		{http.MethodPost, "/api/rules/validate"}, {http.MethodPost, "/api/rules/preview"}, {http.MethodPut, "/api/rules"},
		{http.MethodPost, "/api/token/rotate"}, {http.MethodPost, "/api/monitor-token/rotate"},
		{http.MethodDelete, "/api/monitor-token"}, {http.MethodPost, "/api/tls/reload"},
	} {
		if got := request(tc.method, tc.path, first.Token).Code; got != http.StatusUnauthorized {
			t.Fatalf("monitoring token unexpectedly authorized %s %s: %d", tc.method, tc.path, got)
		}
	}
	denied := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	denied.RemoteAddr = "192.0.2.1:1234"
	denied.Header.Set("Authorization", "Bearer "+first.Token)
	deniedResponse := httptest.NewRecorder()
	server.routes().ServeHTTP(deniedResponse, denied)
	if deniedResponse.Code != http.StatusForbidden {
		t.Fatalf("monitoring token bypassed management ACL: %d", deniedResponse.Code)
	}
	configResponse := request(http.MethodGet, "/api/config", admin)
	if configResponse.Code != http.StatusOK || !strings.Contains(configResponse.Body.String(), `"monitor_token_configured":true`) || strings.Contains(configResponse.Body.String(), first.Token) || strings.Contains(configResponse.Body.String(), config.HashToken(first.Token)) {
		t.Fatal("administrator config response leaked a monitoring credential or omitted its configured state")
	}
	secondResponse := request(http.MethodPost, "/api/monitor-token/rotate", admin)
	var second struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(secondResponse.Body.Bytes(), &second); err != nil || second.Token == first.Token {
		t.Fatal("rotation did not produce a different token")
	}
	if got := request(http.MethodGet, "/metrics", first.Token).Code; got != http.StatusUnauthorized {
		t.Fatalf("old token after rotation = %d", got)
	}
	if got := request(http.MethodGet, "/metrics", second.Token).Code; got != http.StatusOK {
		t.Fatalf("new token after rotation = %d", got)
	}
	if got := request(http.MethodDelete, "/api/monitor-token", admin).Code; got != http.StatusNoContent {
		t.Fatalf("revoke token = %d", got)
	}
	if got := request(http.MethodGet, "/api/status", second.Token).Code; got != http.StatusUnauthorized {
		t.Fatalf("revoked token = %d", got)
	}
	if got := request(http.MethodGet, "/api/status", admin).Code; got != http.StatusOK {
		t.Fatalf("administrator after monitoring revocation = %d", got)
	}
}
