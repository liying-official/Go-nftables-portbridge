package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"portbridge/internal/config"
	"portbridge/internal/diagnostics"
)

func TestDiagnosisMissingConfigurationDoesNotCreateFiles(t *testing.T) {
	dir := t.TempDir()
	options := commandOptions{cfgPath: filepath.Join(dir, "missing.json"), tokenPath: filepath.Join(dir, "missing.token"), diagnoseJSON: true, diagnoseLanguage: "en-US"}
	var output bytes.Buffer
	if err := runDiagnosis(options, &output); err != nil {
		t.Fatal(err)
	}
	var report diagnostics.Report
	if err := json.Unmarshal(output.Bytes(), &report); err != nil || !report.ReadOnly || report.RuntimeObserved {
		t.Fatalf("incorrect missing-service observation: %v %+v", err, report)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("diagnosis created files")
	}
	for _, mode := range []string{"reset", "cleanup", "prepare", "require", "certificate-import", "bootstrap"} {
		mutating := options
		switch mode {
		case "reset":
			mutating.resetToken = true
		case "cleanup":
			mutating.cleanupNFT = true
		case "prepare":
			mutating.prepareTLS = true
		case "require":
			mutating.requireHTTPS = true
		case "certificate-import":
			mutating.httpsOpts.cert = "certificate.pem"
		case "bootstrap":
			mutating.bootstrap = stringList{"192.0.2.1"}
		}
		if runDiagnosis(mutating, &output) == nil {
			t.Fatalf("diagnosis accepted a mutation mode: %s", mode)
		}
	}
}

func TestDiagnosisReadsLiveServiceWithoutFollowingRedirects(t *testing.T) {
	secret := strings.Repeat("1", 64)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Method != "GET" || r.URL.Path != "/api/diagnostics" || r.Header.Get("Authorization") != "Bearer "+secret {
			t.Error("unexpected diagnostic request")
		}
		if requests == 1 {
			json.NewEncoder(w).Encode(diagnostics.Report{Source: "service", ReadOnly: true, RuntimeObserved: true})
		} else {
			w.Header().Set("Location", serverLocation(r))
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer server.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	cfg := config.Default()
	cfg.Web.ListenIPv4 = host
	cfg.Web.Port, _ = strconv.Atoi(port)
	cfg.Web.AdminTokenSHA = config.HashToken(secret)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readServiceDiagnostics(cfg, tokenPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readServiceDiagnostics(cfg, tokenPath); err == nil || requests != 2 {
		t.Fatal("diagnosis accepted/followed a redirect")
	}
	cfg.Web.ListenIPv4 = "192.0.2.99"
	if _, err := readServiceDiagnostics(cfg, tokenPath); err == nil || requests != 2 {
		t.Fatal("diagnosis attempted a nonlocal listener")
	}
}

func serverLocation(r *http.Request) string { return "http://" + r.Host + "/redirected" }
