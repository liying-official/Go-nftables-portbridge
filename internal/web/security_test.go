package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"portbridge/internal/acl"
	"portbridge/internal/config"
)

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

type sequenceListener struct {
	connections []net.Conn
	next        int
}

func (l *sequenceListener) Accept() (net.Conn, error) {
	if l.next >= len(l.connections) {
		return nil, net.ErrClosed
	}
	conn := l.connections[l.next]
	l.next++
	return conn, nil
}

func (l *sequenceListener) Close() error   { return nil }
func (l *sequenceListener) Addr() net.Addr { return testAddr("127.0.0.1:0") }

func TestManagementTLSConfigRequiresAUsableKeyPair(t *testing.T) {
	if got, err := managementTLSConfig(config.WebConfig{}); err != nil || got != nil {
		t.Fatalf("disabled TLS config = %v, %v", got, err)
	}
	if _, err := managementTLSConfig(config.WebConfig{TLSCertFile: "/missing/cert", TLSKeyFile: "/missing/key"}); err == nil {
		t.Fatal("missing TLS files were accepted")
	}

	certFile, keyFile := writeTestCertificate(t)
	got, err := managementTLSConfig(config.WebConfig{TLSCertFile: certFile, TLSKeyFile: keyFile})
	if err != nil {
		t.Fatal(err)
	}
	if got.MinVersion != tls.VersionTLS12 || len(got.Certificates) != 1 {
		t.Fatalf("unexpected TLS config: min=%x certificates=%d", got.MinVersion, len(got.Certificates))
	}
	if runtime.GOOS != "windows" {
		keyLink := filepath.Join(filepath.Dir(keyFile), "tls-link.key")
		if err := os.Symlink(keyFile, keyLink); err != nil {
			t.Fatal(err)
		}
		if _, err := managementTLSConfig(config.WebConfig{TLSCertFile: certFile, TLSKeyFile: keyLink}); err == nil {
			t.Fatal("symbolic-link TLS private key was accepted")
		}
		if err := os.Chmod(keyFile, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := managementTLSConfig(config.WebConfig{TLSCertFile: certFile, TLSKeyFile: keyFile}); err == nil {
			t.Fatal("world-readable TLS private key was accepted")
		}
		if err := os.Chmod(keyFile, 0o660); err != nil {
			t.Fatal(err)
		}
		if _, err := managementTLSConfig(config.WebConfig{TLSCertFile: certFile, TLSKeyFile: keyFile}); err == nil {
			t.Fatal("group-writable TLS private key was accepted")
		}
	}
}

func TestManagementTLSConfigMinVersion(t *testing.T) {
	certFile, keyFile := writeTestCertificate(t)
	for name, tc := range map[string]struct {
		min  string
		want uint16
	}{
		"default stays at 1.2": {"", tls.VersionTLS12},
		"explicit 1.2":         {config.TLSMinVersion12, tls.VersionTLS12},
		"explicit 1.3":         {config.TLSMinVersion13, tls.VersionTLS13},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := managementTLSConfig(config.WebConfig{
				TLSCertFile: certFile, TLSKeyFile: keyFile, TLSMinVersion: tc.min,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got.MinVersion != tc.want {
				t.Fatalf("MinVersion = %x, want %x", got.MinVersion, tc.want)
			}
		})
	}
}

func TestAuthenticationLimiterBoundsAddressState(t *testing.T) {
	limiter := newAuthFailureLimiter()
	limiter.maxEntries = 2
	limiter.now = func() time.Time { return time.Unix(1_700_000_000, 0) }
	for _, raw := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		limiter.allowFailure(netip.MustParseAddr(raw))
	}
	if got := len(limiter.perIP); got != limiter.maxEntries {
		t.Fatalf("limiter address entries = %d, want %d", got, limiter.maxEntries)
	}
}

func TestACLListenerRejectsPeerBeforeReturningConnection(t *testing.T) {
	manager, err := acl.New(false, false, []string{"192.0.2.10/32"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	deniedServer, deniedClient := net.Pipe()
	allowedServer, allowedClient := net.Pipe()
	defer deniedClient.Close()
	defer allowedClient.Close()

	denied := 0
	listener := &aclListener{
		Listener: &sequenceListener{connections: []net.Conn{
			&remoteAddrConn{Conn: deniedServer, remote: testAddr("198.51.100.20:1111")},
			&remoteAddrConn{Conn: allowedServer, remote: testAddr("192.0.2.10:2222")},
		}},
		acl: manager,
		onDeny: func(string) {
			denied++
		},
	}
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.RemoteAddr().String(); got != "192.0.2.10:2222" {
		t.Fatalf("accepted peer = %q", got)
	}
	if denied != 1 {
		t.Fatalf("denied peers = %d, want 1", denied)
	}
}

func writeTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
