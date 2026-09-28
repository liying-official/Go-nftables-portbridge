package web

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
)

func TestValidatedTLSReloadUsesNewCertificateAndKeepsOldOnFailure(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	firstCert, firstKey := writeTestCertificate(t)
	secondCert, secondKey := writeTestCertificate(t)
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	if _, err := store.Update(func(c *config.Config) error {
		c.Web.Port = port
		c.Web.ListenIPv6 = ""
		c.Web.TLSCertFile, c.Web.TLSKeyFile = firstCert, firstKey
		c.Web.RequireHTTPS = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	access, err := acl.New(false, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(store, access, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	peerFingerprint := func() string {
		t.Helper()
		// The test compares loaded leaf fingerprints, not trust-chain behavior.
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp4", server.listeners[0].Addr().String(), &tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- local test fixture only.
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		leaf := conn.ConnectionState().PeerCertificates[0]
		digest := sha256.Sum256(leaf.Raw)
		return hex.EncodeToString(digest[:])
	}
	before := peerFingerprint()
	if _, err := store.Update(func(c *config.Config) error {
		c.Web.TLSCertFile, c.Web.TLSKeyFile = secondCert, secondKey
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/tls/reload", nil)
	w := httptest.NewRecorder()
	server.handleReloadTLS(w, request)
	if w.Code != http.StatusOK {
		t.Fatalf("TLS reload = %d: %s", w.Code, w.Body.String())
	}
	after := peerFingerprint()
	if after == before || after != server.activeTLS.SHA256 {
		t.Fatalf("certificate did not change atomically: before=%s after=%s active=%s", before, after, server.activeTLS.SHA256)
	}
	if _, err := store.Update(func(c *config.Config) error {
		c.Web.TLSCertFile = filepath.Join(dir, "missing.pem")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	server.handleReloadTLS(w, request)
	if w.Code != http.StatusBadRequest || peerFingerprint() != after {
		t.Fatalf("invalid replacement displaced working certificate: %d", w.Code)
	}
}

func TestCertificateExpiryMetrics(t *testing.T) {
	notAfter := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	output := renderMetrics(time.Now(), nil, CertificateStatus{Enabled: true, NotAfter: notAfter})
	for _, part := range []string{"portbridge_tls_certificate_loaded 1", "portbridge_tls_certificate_not_after_timestamp_seconds", "portbridge_tls_certificate_seconds_until_expiry"} {
		if !strings.Contains(output, part) {
			t.Fatalf("missing certificate metric %s", part)
		}
	}
}
