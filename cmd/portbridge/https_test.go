package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
	"time"

	"portbridge/internal/config"
	webui "portbridge/internal/web"
)

func TestHTTPSPreparationCreatesAndPreservesCertificate(t *testing.T) {
	dir := t.TempDir()
	store, token, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	opts := httpsOptions{dir: filepath.Join(dir, "tls"), gid: -1, names: stringList{"example.test", "192.0.2.10"}}
	if err := prepareHTTPS(store, opts); err != nil {
		t.Fatal(err)
	}
	web := store.Get().Web
	if !web.RequireHTTPS || web.AllowInsecureHTTP || web.AdminTokenSHA != config.HashToken(token) {
		t.Fatal("HTTPS policy or token was not preserved")
	}
	status, err := webui.InspectTLS(web)
	if err != nil || !status.SelfSigned || time.Until(status.NotAfter) < 9*365*24*time.Hour {
		t.Fatalf("unexpected certificate: %+v %v", status, err)
	}
	pair, err := tls.LoadX509KeyPair(web.TLSCertFile, web.TLSKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"localhost", "127.0.0.1", "::1", "example.test", "192.0.2.10"} {
		if err := pair.Leaf.VerifyHostname(name); err != nil {
			t.Error(err)
		}
	}
	if pair.Leaf.IsCA {
		t.Fatal("management certificate must not be a CA")
	}
	opts.names = nil
	if err := prepareHTTPS(store, opts); err != nil {
		t.Fatal(err)
	}
	after, err := webui.InspectTLS(store.Get().Web)
	if err != nil || status.SHA256 != after.SHA256 || store.Get().Web.TLSKeyFile != web.TLSKeyFile {
		t.Fatal("upgrade unexpectedly rotated the certificate")
	}
	for _, mutate := range []func(*config.Config){func(c *config.Config) { c.Web.TLSCertFile = ""; c.Web.TLSKeyFile = "" }, func(c *config.Config) { c.Web.AllowInsecureHTTP = true }} {
		if _, err := store.Update(func(c *config.Config) error { mutate(c); return nil }); err == nil {
			t.Fatal("HTTPS downgrade accepted")
		}
	}
}

func TestHTTPSPreparationRejectsInvalidCertificateAndUnsafeDirectory(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	before := store.Get()
	if err := prepareHTTPS(store, httpsOptions{dir: filepath.Join(dir, "tls"), gid: -1, cert: filepath.Join(dir, "missing.crt"), key: filepath.Join(dir, "missing.key")}); err == nil {
		t.Fatal("missing supplied pair silently replaced")
	}
	if store.Get().Web.TLSCertFile != before.Web.TLSCertFile {
		t.Fatal("failed import changed config")
	}
	bad := filepath.Join(dir, "not-directory")
	if err := os.WriteFile(bad, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareHTTPS(store, httpsOptions{dir: bad, gid: -1}); err == nil {
		t.Fatal("unsafe directory accepted")
	}
	if _, _, err := generateHTTPSCertificate(before.Web, []string{"bad/name"}); err == nil {
		t.Fatal("invalid SAN accepted")
	}
}

func TestHTTPSCertificateImportCopiesAndPreservesSource(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := generateHTTPSCertificate(store.Get().Web, nil)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "supplied.crt"), filepath.Join(dir, "supplied.key")
	if err := os.WriteFile(certFile, cert, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareHTTPS(store, httpsOptions{dir: filepath.Join(dir, "managed"), gid: -1, cert: certFile, key: keyFile}); err != nil {
		t.Fatal(err)
	}
	if store.Get().Web.TLSKeyFile == keyFile {
		t.Fatal("import did not use managed copy")
	}
	data, err := os.ReadFile(keyFile)
	if err != nil || string(data) != string(key) {
		t.Fatal("import changed source key")
	}
}
