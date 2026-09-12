package web

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"portbridge/internal/acl"
	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

func TestRequiredHTTPSCannotBeRemovedThroughSettings(t *testing.T) {
	dir := t.TempDir()
	store, _, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	cert, key := writeTestCertificate(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	_, err = store.Update(func(c *config.Config) error {
		c.Web.Port = port
		c.Web.ListenIPv6 = ""
		c.Web.TLSCertFile = cert
		c.Web.TLSKeyFile = key
		c.Web.RequireHTTPS = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	acls, err := acl.New(false, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(store, acls, proxy.NewManager(logger), logger, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	for _, insecure := range []bool{false, true} {
		req := settingsRequest{Port: port, ListenIPv4: "127.0.0.1", TLSCertFile: cert, TLSKeyFile: key, AllowInsecureHTTP: insecure}
		if !insecure {
			req.TLSCertFile = ""
			req.TLSKeyFile = ""
		}
		data, _ := json.Marshal(req)
		r := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader(data))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.handleSettings(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("downgrade accepted: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	srv.handleGetConfig(w, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	var got struct {
		HTTPS struct {
			Required    bool              `json:"required"`
			Certificate CertificateStatus `json:"certificate"`
		} `json:"https"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.HTTPS.Required || !got.HTTPS.Certificate.Enabled || !got.HTTPS.Certificate.SelfSigned || len(got.HTTPS.Certificate.SHA256) != 64 {
		t.Fatalf("missing active self-signed status: %+v", got)
	}
}
