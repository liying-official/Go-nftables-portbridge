package web

import (
	"bytes"
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

func TestRuleValidationPreviewBatchRevisionAndOperation(t *testing.T) {
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
	request := func(method, path, bearer, revision string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Authorization", "Bearer "+bearer)
		if method != http.MethodGet {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-PortBridge-CSRF", server.csrf)
		}
		if revision != "" {
			r.Header.Set("If-Match", `"`+revision+`"`)
		}
		w := httptest.NewRecorder()
		server.routes().ServeHTTP(w, r)
		return w
	}
	configResponse := request(http.MethodGet, "/api/config", admin, "", nil)
	var configuration struct {
		ConfigRevision string `json:"config_revision"`
	}
	if err := json.Unmarshal(configResponse.Body.Bytes(), &configuration); err != nil || len(configuration.ConfigRevision) != 64 || configResponse.Header().Get("ETag") != `"`+configuration.ConfigRevision+`"` {
		t.Fatalf("configuration revision not exposed: %v", err)
	}
	rule := config.NormalizeRule(config.Rule{ID: "portable-one", Name: "portable-one", Protocol: config.ProtocolTCP, DataPlane: config.RuleDataPlaneGo,
		ListenHost: "127.0.0.1", ListenPort: 20001, TargetHost: "203.0.113.10", TargetPort: 20002, Enabled: false})
	body, _ := json.Marshal(map[string]any{"rules": []config.Rule{rule}})
	for _, path := range []string{"/api/rules/validate", "/api/rules/preview"} {
		w := request(http.MethodPost, path, admin, "", body)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"saved":false`) {
			t.Fatalf("%s changed state or failed: %d %s", path, w.Code, w.Body.String())
		}
	}
	if got := store.Get().Rules; len(got) != 0 {
		t.Fatalf("dry run saved rules: %+v", got)
	}
	if got := request(http.MethodPut, "/api/rules", admin, "", body).Code; got != http.StatusPreconditionRequired {
		t.Fatalf("batch without revision = %d", got)
	}
	w := request(http.MethodPut, "/api/rules", admin, strings.Repeat("0", 64), body)
	if w.Code != http.StatusPreconditionFailed || len(store.Get().Rules) != 0 {
		t.Fatalf("stale batch was accepted: %d", w.Code)
	}
	w = request(http.MethodPut, "/api/rules", admin, configuration.ConfigRevision, body)
	if w.Code != http.StatusOK || w.Header().Get("X-PortBridge-Operation-ID") == "" || w.Header().Get("X-PortBridge-Config-Revision") == configuration.ConfigRevision {
		t.Fatalf("atomic batch save failed: %d %s", w.Code, w.Body.String())
	}
	operationID := w.Header().Get("X-PortBridge-Operation-ID")
	opResponse := request(http.MethodGet, "/api/operations/"+operationID, admin, "", nil)
	var op ApplyOperation
	if err := json.Unmarshal(opResponse.Body.Bytes(), &op); err != nil || op.ID != operationID || op.BusinessHealth != "not_checked" || op.State == "saved" || op.State == "applying" {
		t.Fatalf("operation did not reach a qualified result: %v %+v", err, op)
	}
	if op.ConfigRevision != config.Revision(store.Get()) {
		t.Fatal("operation revision does not match persisted configuration")
	}
	if got := request(http.MethodGet, "/api/rules/template", admin, "", nil).Body.String(); strings.Contains(got, `"admin_token_sha256"`) || strings.Contains(got, `"monitor_token_sha256"`) || strings.Contains(got, `"conntrack_mark"`) || strings.Contains(got, `"id":"portable-one"`) {
		t.Fatalf("template included instance identity or credentials: %s", got)
	}
	monitor, err := store.RotateMonitorToken()
	if err != nil {
		t.Fatal(err)
	}
	if got := request(http.MethodGet, "/api/operations/"+operationID, monitor, "", nil).Code; got != http.StatusOK {
		t.Fatalf("monitor cannot read operation state: %d", got)
	}
	if got := request(http.MethodPut, "/api/rules", monitor, config.Revision(store.Get()), body).Code; got != http.StatusUnauthorized {
		t.Fatalf("monitor can write batch rules: %d", got)
	}
}
