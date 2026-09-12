package web

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"time"

	"portbridge/internal/acl"
	"portbridge/internal/config"
)

func managementTLSConfig(web config.WebConfig) (*tls.Config, error) {
	if web.TLSCertFile == "" && web.TLSKeyFile == "" {
		if web.RequireHTTPS {
			return nil, fmt.Errorf("this deployment requires an HTTPS certificate and key")
		}
		return nil, nil
	}
	for label, path := range map[string]string{
		"certificate": web.TLSCertFile,
		"private key": web.TLSKeyFile,
	} {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, fmt.Errorf("inspect web TLS %s: %w", label, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("web TLS %s must be a regular file", label)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Lstat(web.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("inspect web TLS private key: %w", err)
		}
		if info.Mode().Perm()&0o137 != 0 {
			return nil, fmt.Errorf("web TLS private key permissions must be limited to owner read/write and optional group read")
		}
		if err := validateTLSKeyOwner(info); err != nil {
			return nil, err
		}
	}
	certificate, err := tls.LoadX509KeyPair(web.TLSCertFile, web.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load web TLS certificate: %w", err)
	}
	if certificate.Leaf == nil {
		certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parse web TLS certificate: %w", err)
		}
	}
	// The default stays at TLS 1.2 for client compatibility; deployments that
	// terminate management TLS directly on the internet can opt into 1.3-only.
	minVersion := uint16(tls.VersionTLS12)
	if web.TLSMinVersion == config.TLSMinVersion13 {
		minVersion = tls.VersionTLS13
	}
	return &tls.Config{
		MinVersion:   minVersion,
		Certificates: []tls.Certificate{certificate},
	}, nil
}

// CertificateStatus describes the certificate actually loaded by a listener.
// A non-self-signed certificate is not necessarily trusted by every client.
type CertificateStatus struct {
	Enabled    bool      `json:"enabled"`
	SelfSigned bool      `json:"self_signed"`
	SHA256     string    `json:"sha256,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
}

func certificateStatus(cfg *tls.Config) CertificateStatus {
	if cfg == nil || len(cfg.Certificates) == 0 || cfg.Certificates[0].Leaf == nil {
		return CertificateStatus{}
	}
	leaf := cfg.Certificates[0].Leaf
	digest := sha256.Sum256(leaf.Raw)
	return CertificateStatus{
		Enabled:    true,
		SelfSigned: bytes.Equal(leaf.RawIssuer, leaf.RawSubject) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil,
		SHA256:     hex.EncodeToString(digest[:]), NotAfter: leaf.NotAfter,
	}
}

// InspectTLS validates local material before deployment or a settings change.
func InspectTLS(web config.WebConfig) (CertificateStatus, error) {
	cfg, err := managementTLSConfig(web)
	if err != nil {
		return CertificateStatus{}, err
	}
	status := certificateStatus(cfg)
	if status.Enabled {
		leaf := cfg.Certificates[0].Leaf
		now := time.Now()
		if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
			return CertificateStatus{}, fmt.Errorf("TLS certificate is expired or not yet valid")
		}
	}
	return status, nil
}

const (
	maxManagementConnections = 256
	authLimiterMaxAddresses  = 4096
)

type tokenBucket struct {
	tokens   float64
	last     time.Time
	lastSeen time.Time
}

type authFailureLimiter struct {
	mu sync.Mutex

	now         func() time.Time
	perIP       map[netip.Addr]*tokenBucket
	global      tokenBucket
	perIPRate   float64
	perIPBurst  float64
	globalRate  float64
	globalBurst float64
	maxEntries  int
}

func newAuthFailureLimiter() *authFailureLimiter {
	return &authFailureLimiter{
		now:         time.Now,
		perIP:       make(map[netip.Addr]*tokenBucket),
		perIPRate:   1.0 / 6.0,
		perIPBurst:  10,
		globalRate:  5,
		globalBurst: 100,
		maxEntries:  authLimiterMaxAddresses,
	}
}

func (l *authFailureLimiter) allowFailure(ip netip.Addr) bool {
	now := l.now()
	if ip.IsValid() {
		ip = ip.Unmap()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	refillBucket(&l.global, now, l.globalRate, l.globalBurst)
	entry := l.perIP[ip]
	if entry == nil {
		l.makeRoom(now)
		entry = &tokenBucket{}
		l.perIP[ip] = entry
	}
	refillBucket(entry, now, l.perIPRate, l.perIPBurst)
	entry.lastSeen = now

	allowed := l.global.tokens >= 1 && entry.tokens >= 1
	if l.global.tokens >= 1 {
		l.global.tokens--
	}
	if entry.tokens >= 1 {
		entry.tokens--
	}
	return allowed
}

func (l *authFailureLimiter) reset(ip netip.Addr) {
	if !ip.IsValid() {
		return
	}
	l.mu.Lock()
	delete(l.perIP, ip.Unmap())
	l.mu.Unlock()
}

func (l *authFailureLimiter) makeRoom(now time.Time) {
	if len(l.perIP) < l.maxEntries {
		return
	}
	cutoff := now.Add(-15 * time.Minute)
	for ip, entry := range l.perIP {
		if entry.lastSeen.Before(cutoff) {
			delete(l.perIP, ip)
		}
	}
	if len(l.perIP) < l.maxEntries {
		return
	}
	var oldestIP netip.Addr
	var oldest time.Time
	for ip, entry := range l.perIP {
		if oldest.IsZero() || entry.lastSeen.Before(oldest) {
			oldestIP, oldest = ip, entry.lastSeen
		}
	}
	delete(l.perIP, oldestIP)
}

func refillBucket(bucket *tokenBucket, now time.Time, rate, burst float64) {
	if bucket.last.IsZero() {
		bucket.tokens = burst
		bucket.last = now
		return
	}
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * rate
		if bucket.tokens > burst {
			bucket.tokens = burst
		}
		bucket.last = now
	}
}

// aclListener rejects a disallowed TCP peer before net/http parses request
// bytes or performs a TLS handshake. The HTTP middleware repeats the check to
// cover ACL changes after a connection has already been accepted.
type aclListener struct {
	net.Listener
	acl    *acl.Manager
	onDeny func(string)
}

func (l *aclListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, parseErr := remoteIP(conn.RemoteAddr().String())
		if parseErr == nil && l.acl.Allowed(ip) {
			return conn, nil
		}
		remote := "invalid"
		if parseErr == nil {
			remote = ip.Unmap().String()
		}
		if l.onDeny != nil {
			l.onDeny(remote)
		}
		_ = conn.Close()
	}
}

type connectionLimitListener struct {
	net.Listener
	sem      chan struct{}
	done     chan struct{}
	closeErr error
	close    sync.Once
}

func newConnectionLimitListener(listener net.Listener, limit int) net.Listener {
	if limit < 1 {
		panic("management connection limit must be positive")
	}
	return &connectionLimitListener{
		Listener: listener,
		sem:      make(chan struct{}, limit),
		done:     make(chan struct{}),
	}
}

func (l *connectionLimitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	conn, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &connectionLimitConn{Conn: conn, release: func() { <-l.sem }}, nil
}

func (l *connectionLimitListener) Close() error {
	l.close.Do(func() {
		close(l.done)
		l.closeErr = l.Listener.Close()
	})
	return l.closeErr
}

type connectionLimitConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *connectionLimitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
