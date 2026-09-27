package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"portbridge/internal/config"
)

func checkAPIError(t *testing.T, response *httptest.ResponseRecorder, status int, legacy, key string) APIError {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d, want %d: %s", response.Code, status, response.Body.String())
	}
	var result APIError
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Error != legacy || result.MessageKey != key {
		t.Fatalf("API error = %+v, want legacy %q and key %q", result, legacy, key)
	}
	return result
}

func TestAPIErrorKeysPreserveSecurityAndJSONResponses(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{store: store, csrf: "expected-csrf"}
	noop := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	auth := httptest.NewRecorder()
	server.requireAuth(noop).ServeHTTP(auth, httptest.NewRequest(http.MethodGet, "/api/status", nil))
	checkAPIError(t, auth, http.StatusUnauthorized, "管理员令牌无效", "apiInvalidToken")
	if got := auth.Header().Get("WWW-Authenticate"); got != `Bearer realm="PortBridge"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	origin := httptest.NewRequest(http.MethodPost, "https://portbridge.example/api/rules", nil)
	origin.Header.Set("Origin", "https://other.example")
	for name, handler := range map[string]func(http.ResponseWriter, *http.Request){
		"origin": server.requireBrowserSameOrigin(noop),
		"csrf":   server.requireCSRF(noop),
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler(response, origin)
			legacy, key := "跨站请求被拒绝", "apiCrossSiteRejected"
			if name == "csrf" {
				legacy, key = "CSRF 校验失败，请刷新页面", "apiCSRFFailed"
			}
			checkAPIError(t, response, http.StatusForbidden, legacy, key)
		})
	}

	for name, test := range map[string]struct {
		contentType string
		body        string
		legacy      string
		key         string
	}{
		"content type":  {"text/plain", `{}`, "Content-Type 必须是 application/json", "apiJSONContentType"},
		"second object": {"application/json", `{} {}`, "请求只能包含一个 JSON 对象", "apiJSONObjectOnly"},
		"invalid JSON":  {"application/json", `{"unknown":1}`, `JSON 格式错误: json: unknown field "unknown"`, "apiInvalidJSON"},
		"too large":     {"application/json", `{"value":"` + strings.Repeat("x", maxJSONBodyBytes) + `"}`, "JSON 请求体不能超过 1048576 字节", "apiJSONTooLarge"},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/rules", strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			server.handleCreateRule(response, request)
			result := checkAPIError(t, response, http.StatusBadRequest, test.legacy, test.key)
			if test.key == "apiInvalidJSON" && result.MessageArgs["detail"] != `json: unknown field "unknown"` {
				t.Fatalf("JSON detail = %v", result.MessageArgs)
			}
			if test.key == "apiJSONTooLarge" && result.MessageArgs["limit"] != float64(maxJSONBodyBytes) {
				t.Fatalf("JSON limit = %v", result.MessageArgs)
			}
		})
	}
}

func TestAPIErrorKeysForMissingRuleAndDynamicValidation(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{store: store}
	request := httptest.NewRequest(http.MethodDelete, "/api/rules/not-found", nil)
	request.SetPathValue("id", "not-found")
	response := httptest.NewRecorder()
	server.handleDeleteRule(response, request)
	missing := checkAPIError(t, response, http.StatusNotFound, `rule "not-found" not found`, "apiRuleNotFound")
	if missing.MessageArgs["id"] != "not-found" {
		t.Fatalf("missing-rule arguments = %v", missing.MessageArgs)
	}

	request = httptest.NewRequest(http.MethodPut, "/api/settings", strings.NewReader(`{"port":0}`))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	server.handleSettings(response, request)
	validation := checkAPIError(t, response, http.StatusBadRequest, "web port must be 1-65535", "apiErrorDetail")
	if validation.MessageArgs["detail"] != validation.Error {
		t.Fatalf("validation detail differs from legacy error: %+v", validation)
	}
}
