package web

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"portbridge/internal/acl"
	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

func TestWebStartKeepsAvailableAddressWhenAnotherBindFails(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "admin.token")
	store, _, err := config.LoadOrCreate(configPath, tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Update(func(cfg *config.Config) error {
		cfg.Web.Port = port
		cfg.Web.ListenIPv4 = "127.0.0.1"
		cfg.Web.ListenIPv6 = "2001:db8::dead"
		cfg.Web.AllowInsecureHTTP = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	aclManager, err := acl.New(false, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store, aclManager, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("one unavailable address made the available listener fail: %v", err)
	}
	defer server.Close()
	if got := len(server.listeners); got != 1 {
		t.Fatalf("active web listeners = %d, want 1 degraded-but-available listener", got)
	}
}

func TestStaticAssetsAreNotCachedAcrossUpgrades(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	(&Server{}).serveStatic("static/app.js", "text/javascript; charset=utf-8").ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := recorder.Header().Get("Content-Type"); got != "text/javascript; charset=utf-8" {
		t.Fatalf("Content-Type = %q", got)
	}
}

func TestSecurityHeaders(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	server := &Server{}
	server.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, request)

	for header, want := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"X-Frame-Options":              "DENY",
		"Referrer-Policy":              "no-referrer",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
	} {
		if got := recorder.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := recorder.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"object-src 'none'", "worker-src 'none'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directive) {
			t.Errorf("Content-Security-Policy is missing %q: %q", directive, csp)
		}
	}
	if got := recorder.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HTTP response unexpectedly contains HSTS: %q", got)
	}
	tlsRecorder := httptest.NewRecorder()
	tlsRequest := httptest.NewRequest(http.MethodGet, "https://portbridge.example/", nil)
	tlsRequest.TLS = &tls.ConnectionState{}
	server.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(tlsRecorder, tlsRequest)
	if got := tlsRecorder.Header().Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Fatalf("HTTPS HSTS = %q", got)
	}
}

func TestBearerAuthenticationAndCSRF(t *testing.T) {
	dir := t.TempDir()
	store, token, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{store: store, csrf: "test-csrf"}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	for name, tc := range map[string]struct {
		authorization string
		want          int
	}{
		"missing": {want: http.StatusUnauthorized},
		"wrong":   {authorization: "Bearer wrong", want: http.StatusUnauthorized},
		"valid":   {authorization: "Bearer " + token, want: http.StatusNoContent},
	} {
		t.Run("auth-"+name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
			request.Header.Set("Authorization", tc.authorization)
			server.requireAuth(ok).ServeHTTP(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.want)
			}
		})
	}

	for name, tc := range map[string]struct {
		csrf string
		want int
	}{
		"missing": {want: http.StatusForbidden},
		"wrong":   {csrf: "wrong", want: http.StatusForbidden},
		"valid":   {csrf: "test-csrf", want: http.StatusNoContent},
	} {
		t.Run("csrf-"+name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/rules", nil)
			request.Header.Set("X-PortBridge-CSRF", tc.csrf)
			server.requireCSRF(ok).ServeHTTP(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.want)
			}
		})
	}
}

func TestAuthenticationFailureRateLimitDoesNotBlockValidToken(t *testing.T) {
	dir := t.TempDir()
	store, token, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	limiter := newAuthFailureLimiter()
	limiter.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	limiter.perIPBurst = 2
	limiter.perIPRate = 0
	server := &Server{store: store, authFailures: limiter}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	for attempt, want := range []int{http.StatusUnauthorized, http.StatusUnauthorized, http.StatusTooManyRequests} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		request.RemoteAddr = "192.0.2.10:12345"
		request.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
		server.requireAuth(ok).ServeHTTP(recorder, request)
		if recorder.Code != want {
			t.Fatalf("attempt %d status = %d, want %d", attempt+1, recorder.Code, want)
		}
	}

	valid := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	valid.RemoteAddr = "192.0.2.10:12345"
	valid.Header.Set("Authorization", "Bearer "+token)
	validRecorder := httptest.NewRecorder()
	server.requireAuth(ok).ServeHTTP(validRecorder, valid)
	if validRecorder.Code != http.StatusNoContent {
		t.Fatalf("valid token was rate limited: %d", validRecorder.Code)
	}

	afterReset := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	afterReset.RemoteAddr = "192.0.2.10:12345"
	afterReset.Header.Set("Authorization", "Bearer "+strings.Repeat("0", 64))
	afterResetRecorder := httptest.NewRecorder()
	server.requireAuth(ok).ServeHTTP(afterResetRecorder, afterReset)
	if afterResetRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("successful authentication did not reset the per-IP bucket: %d", afterResetRecorder.Code)
	}
}

func TestBearerTokenParserRejectsAmbiguousHeaders(t *testing.T) {
	valid := strings.Repeat("a", 64)
	for name, values := range map[string][]string{
		"missing":        nil,
		"multiple":       {"Bearer " + valid, "Bearer " + valid},
		"wrong scheme":   {"Basic " + valid},
		"wrong length":   {"Bearer short"},
		"extra material": {"Bearer " + valid + " trailing"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, ok := bearerToken(values); ok {
				t.Fatalf("ambiguous bearer header accepted: %v", values)
			}
		})
	}
	if token, ok := bearerToken([]string{"bearer " + valid}); !ok || token != valid {
		t.Fatal("valid bearer token rejected")
	}
}

func TestBrowserSameOriginProtection(t *testing.T) {
	server := &Server{}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for name, tc := range map[string]struct {
		origin string
		site   string
		want   int
	}{
		"CLI without browser headers": {want: http.StatusNoContent},
		"same origin":                 {origin: "https://portbridge.example", site: "same-origin", want: http.StatusNoContent},
		"wrong scheme":                {origin: "http://portbridge.example", site: "same-origin", want: http.StatusForbidden},
		"origin with path":            {origin: "https://portbridge.example/forged", site: "same-origin", want: http.StatusForbidden},
		"cross origin":                {origin: "https://attacker.example", site: "cross-site", want: http.StatusForbidden},
		"forged origin only":          {origin: "https://attacker.example", want: http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "https://portbridge.example/api/rules", nil)
			request.Host = "portbridge.example"
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			if tc.site != "" {
				request.Header.Set("Sec-Fetch-Site", tc.site)
			}
			server.requireBrowserSameOrigin(ok).ServeHTTP(recorder, request)
			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d", recorder.Code, tc.want)
			}
		})
	}

	for _, header := range []string{"Origin", "Sec-Fetch-Site"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "https://portbridge.example/api/rules", nil)
		request.Host = "portbridge.example"
		if header == "Origin" {
			request.Header[header] = []string{"https://portbridge.example", "https://portbridge.example"}
		} else {
			request.Header[header] = []string{"same-origin", "same-origin"}
		}
		server.requireBrowserSameOrigin(ok).ServeHTTP(recorder, request)
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("duplicate %s status = %d, want %d", header, recorder.Code, http.StatusForbidden)
		}
	}
}

func TestDecodeJSONRequiresContentTypeAndEnforcesSize(t *testing.T) {
	for name, tc := range map[string]struct {
		contentType string
		body        string
		wantError   string
	}{
		"valid":         {contentType: "application/json; charset=utf-8", body: `{"ok":true}`},
		"wrong type":    {contentType: "text/plain", body: `{"ok":true}`, wantError: "Content-Type"},
		"oversized":     {contentType: "application/json", body: `{"value":"` + strings.Repeat("a", maxJSONBodyBytes) + `"}`, wantError: "不能超过"},
		"second object": {contentType: "application/json", body: `{} {}`, wantError: "只能包含一个"},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(tc.body))
			if tc.contentType != "" {
				request.Header.Set("Content-Type", tc.contentType)
			}
			var value map[string]any
			err := decodeJSON(recorder, request, &value)
			if tc.wantError == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantError != "" && (err == nil || !strings.Contains(err.Error(), tc.wantError)) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantError)
			}
		})
	}
}

func TestStrictAllowlistCannotBeEnabledBeforeHTTPSOrWithoutCurrentClient(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := writeTestCertificate(t)
	server := &Server{store: store}

	requestBody := settingsRequest{
		AutoLANACL:        false,
		StrictIPAllowlist: true,
		Whitelist:         []string{"192.0.2.10/32"},
		Port:              9080,
		ListenIPv4:        "0.0.0.0",
		ListenIPv6:        "::",
		TLSCertFile:       certFile,
		TLSKeyFile:        keyFile,
	}
	body, err := json.Marshal(requestBody)
	if err != nil {
		t.Fatal(err)
	}

	for name, tlsState := range map[string]*tls.ConnectionState{
		"HTTP migration window":  nil,
		"missing current client": {},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			request.RemoteAddr = "192.0.2.11:12345"
			request.TLS = tlsState
			server.handleSettings(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
		})
	}
}

func TestSettingsTLSMinVersionValidationAndPersistence(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	aclManager, err := acl.New(false, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{store: store, acl: aclManager, proxies: proxy.NewManager(logger), logger: logger}

	send := func(minVersion string) *httptest.ResponseRecorder {
		body, err := json.Marshal(settingsRequest{
			Port: 9080, ListenIPv4: "127.0.0.1", ListenIPv6: "::1",
			Whitelist: []string{}, DNSServers: []string{},
			TLSMinVersion: minVersion,
		})
		if err != nil {
			t.Fatal(err)
		}
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		request.RemoteAddr = "127.0.0.1:12345"
		server.handleSettings(recorder, request)
		return recorder
	}

	if got := send("tls1.3"); got.Code != http.StatusBadRequest {
		t.Fatalf("invalid tls_min_version status = %d, want %d", got.Code, http.StatusBadRequest)
	}
	valid := send(config.TLSMinVersion13)
	if valid.Code != http.StatusOK {
		t.Fatalf("valid tls_min_version status = %d, want %d: %s", valid.Code, http.StatusOK, valid.Body.String())
	}
	if got := store.Get().Web.TLSMinVersion; got != config.TLSMinVersion13 {
		t.Fatalf("persisted tls_min_version = %q, want %q", got, config.TLSMinVersion13)
	}
	var response map[string]any
	if err := json.Unmarshal(valid.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["restart_required"] != true {
		t.Fatal("changing tls_min_version must require restart")
	}
	if got := send(config.TLSMinVersion13); got.Code != http.StatusOK {
		t.Fatalf("unchanged tls_min_version status = %d", got.Code)
	}
}

func TestStatusPollingIsSerialized(t *testing.T) {
	data, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		"let polling=false;let statusRequest=null",
		"if(statusRequest)return statusRequest",
		"setTimeout(poll,500)",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("app.js does not contain %q", want)
		}
	}
	if strings.Contains(source, "setInterval(loadStatus,500)") {
		t.Fatal("status polling can overlap through setInterval")
	}
}

func TestBootstrapRequiresBearerAndPublicSecurityControlsAreEmbedded(t *testing.T) {
	data, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	if !strings.Contains(source, "api('/api/bootstrap')") {
		t.Fatal("bootstrap is not fetched through the authenticated API helper")
	}
	if strings.Contains(source, "fetch('/api/bootstrap'") {
		t.Fatal("bootstrap CSRF token is still fetched without authentication")
	}
	for _, control := range []string{"strict_ip_allowlist", "tls_cert_file", "tls_key_file", "showTransportWarning"} {
		if !strings.Contains(source, control) {
			t.Fatalf("app.js is missing public-management control %q", control)
		}
	}
	for _, control := range []string{"clearManagementView()", "if(!token||token!==requestToken)return", "syncStrictUI();bootstrap()"} {
		if !strings.Contains(source, control) {
			t.Fatalf("app.js is missing stale-session protection %q", control)
		}
	}
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{`id="insecureWarning"`, `id="strictAllowlist"`, `id="tlsCertFile"`, `id="tlsKeyFile"`} {
		if !strings.Contains(string(index), id) {
			t.Fatalf("index.html is missing %s", id)
		}
	}
}

func TestUDPPerformanceControlsAndCountersAreEmbedded(t *testing.T) {
	appData, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	app := string(appData)
	for _, want := range []string{
		"udp_workers", "udp_batch_size", "udp_packet_buffer_size",
		"udp_listener_buffer_bytes", "udp_session_buffer_bytes",
		"udp_packets_up", "udp_packets_down", "udp_drops",
	} {
		if !strings.Contains(app, want) {
			t.Fatalf("app.js does not contain %q", want)
		}
	}

	indexData, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	index := string(indexData)
	for _, id := range []string{
		`id="udpWorkers"`, `id="udpBatchSize"`, `id="udpPacketBufferSize"`,
		`id="udpListenerBufferBytes"`, `id="udpSessionBufferBytes"`,
	} {
		if !strings.Contains(index, id) {
			t.Fatalf("index.html does not contain %q", id)
		}
	}
}

func TestRuleIDsAreEscapedBeforeHTMLAttributeInsertion(t *testing.T) {
	data, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{`data-edit="${esc(r.id)}"`, `data-del="${esc(r.id)}"`} {
		if !strings.Contains(source, want) {
			t.Fatalf("app.js does not safely render %q", want)
		}
	}
	for _, unsafe := range []string{`data-edit="${r.id}"`, `data-del="${r.id}"`} {
		if strings.Contains(source, unsafe) {
			t.Fatalf("app.js contains unsafe rule ID interpolation %q", unsafe)
		}
	}
}

func TestAdministratorTokenUsesSessionStorage(t *testing.T) {
	data, err := staticFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	if !strings.Contains(source, "sessionStorage") {
		t.Fatal("administrator token is not stored in sessionStorage")
	}
	if strings.Contains(source, "localStorage") {
		t.Fatal("administrator token must not persist in localStorage")
	}
	index, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), `id="tokenInput" type="password" autocomplete="off"`) {
		t.Fatal("administrator token input must disable credential autofill")
	}
}
