package web

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"portbridge/internal/acl"
	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

func TestTablerAssetsKeepManagementSecurityHeadersAndACL(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	access, err := acl.New(false, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := New(store, access, proxy.NewManager(logger), logger, filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/static/i18n.js", "/static/tabler-icons.svg", "/static/vendor/tabler.min.css", "/static/vendor/tabler.min.js"} {
		for _, remote := range []string{"127.0.0.1:1234", "192.0.2.1:1234"} {
			request := httptest.NewRequest("GET", path, nil)
			request.RemoteAddr = remote
			response := httptest.NewRecorder()
			server.routes().ServeHTTP(response, request)
			want := 200
			if strings.HasPrefix(remote, "192.") {
				want = 403
			}
			if response.Code != want {
				t.Fatalf("%s from %s: got %d, want %d", path, remote, response.Code, want)
			}
			policy := response.Header().Get("Content-Security-Policy")
			if !strings.Contains(policy, "script-src 'self'") || !strings.Contains(policy, "style-src 'self'") || strings.Contains(policy, "unsafe-") || !strings.Contains(policy, "frame-ancestors 'none'") {
				t.Fatalf("asset route weakened CSP: %q", policy)
			}
		}
	}
	for _, path := range []string{"/static/vendor/LICENSES.txt", "/static/config.json", "/static/admin.token"} {
		request := httptest.NewRequest("GET", path, nil)
		request.RemoteAddr = "127.0.0.1:1234"
		response := httptest.NewRecorder()
		server.routes().ServeHTTP(response, request)
		if response.Code != 404 {
			t.Fatalf("unregistered asset path %s exposed: %d", path, response.Code)
		}
	}
}

func TestUnifiedUIHasLocalAssetsAndNoInlineExecutableContent(t *testing.T) {
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, unwanted := range []string{"https://", "http://", "<script>", " onclick=", " onload=", " style="} {
		if strings.Contains(string(index), unwanted) {
			t.Fatalf("unexpected remote/inline UI content: %s", unwanted)
		}
	}
	for _, required := range []string{"data-language=\"en-US\"", "data-language=\"zh-CN\"", "data-default-language=", "vendor/tabler.min.js", "vendor/tabler.min.css", "tabler-icons.svg", "id=\"confirmDialog\""} {
		if !strings.Contains(string(index), required) {
			t.Fatalf("missing bilingual Tabler control: %s", required)
		}
	}
	i18n, err := staticFS.ReadFile("static/i18n.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(i18n), "localStorage.setItem('portbridge_language',value)") || strings.Contains(string(i18n), "setItem('portbridge_token'") {
		t.Fatal("language preference must not persist administrator credentials")
	}
	css, err := staticFS.ReadFile("static/vendor/tabler.min.css")
	if err != nil || strings.Contains(string(css), "@import") {
		t.Fatal("Tabler CSS must not import remote fonts/styles")
	}
}
