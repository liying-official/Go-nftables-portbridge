package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"portbridge/internal/config"
	webui "portbridge/internal/web"
)

type httpsOptions struct {
	dir, cert, key, language string
	names                    stringList
	gid                      int
}

func prepareHTTPS(store *config.Store, opts httpsOptions) error {
	cfg := store.Get()
	if (opts.cert == "") != (opts.key == "") {
		return errors.New("--tls-cert and --tls-key must be supplied together")
	}
	if opts.cert != "" {
		cfg.Web.TLSCertFile, cfg.Web.TLSKeyFile = opts.cert, opts.key
	}
	if len(opts.names) > 0 && cfg.Web.TLSCertFile != "" {
		return errors.New("--tls-name applies only when generating a new certificate; existing certificates are preserved")
	}
	var certPEM, keyPEM []byte
	var err error
	if cfg.Web.TLSCertFile == "" && cfg.Web.TLSKeyFile == "" {
		certPEM, keyPEM, err = generateHTTPSCertificate(cfg.Web, opts.names)
		if err != nil {
			return err
		}
	} else {
		// Never silently replace an invalid administrator-supplied certificate.
		if _, err := webui.InspectTLS(cfg.Web); err != nil {
			return err
		}
		if opts.cert != "" {
			// Explicit imports are copied into the managed directory so the
			// service can read them without changing the operator's original key.
			certPEM, err = os.ReadFile(opts.cert) // #nosec G304 -- administrator-selected TLS import, validated above.
			if err != nil {
				return err
			}
			keyPEM, err = os.ReadFile(opts.key) // #nosec G304 -- administrator-selected TLS import, validated above.
			if err != nil {
				return err
			}
		}
	}
	var created string
	if certPEM != nil {
		if !filepath.IsAbs(opts.dir) {
			return errors.New("HTTPS directory must be absolute")
		}
		if err := os.MkdirAll(opts.dir, 0o750); err != nil {
			return err
		}
		info, err := os.Lstat(opts.dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return errors.New("HTTPS directory must be a non-symlink directory without group/other write permission")
		}
		created, err = os.MkdirTemp(opts.dir, "certificate-")
		if err != nil {
			return err
		}
		certFile, keyFile := filepath.Join(created, "certificate.pem"), filepath.Join(created, "private-key.pem")
		keep := false
		defer func() {
			if !keep {
				_ = os.Remove(certFile)
				_ = os.Remove(keyFile)
				_ = os.Remove(created)
			}
		}()
		createdRoot, err := os.OpenRoot(created)
		if err != nil {
			return err
		}
		defer func() { _ = createdRoot.Close() }()
		if err := createdRoot.WriteFile("certificate.pem", certPEM, 0o600); err != nil {
			return err
		}
		if err := createdRoot.WriteFile("private-key.pem", keyPEM, 0o600); err != nil {
			return err
		}
		if opts.gid >= 0 {
			for _, path := range []string{created, certFile, keyFile} {
				if err := os.Chown(path, -1, opts.gid); err != nil {
					return err
				}
			}
			// #nosec G302 -- the installer assigns the service group read/traverse only; no group write or other access.
			if err := os.Chmod(created, 0o750); err != nil {
				return err
			}
			// #nosec G302 -- the public certificate is readable only by root and the explicitly selected service group.
			if err := os.Chmod(certFile, 0o640); err != nil {
				return err
			}
			// #nosec G302 -- root-owned key with service-group read only is required by the read-only systemd TLS mount.
			if err := os.Chmod(keyFile, 0o640); err != nil {
				return err
			}
		}
		cfg.Web.TLSCertFile, cfg.Web.TLSKeyFile = certFile, keyFile
		if _, err := webui.InspectTLS(cfg.Web); err != nil {
			return err
		}
		cfg.Web.RequireHTTPS, cfg.Web.AllowInsecureHTTP = true, false
		if _, err := store.Update(func(c *config.Config) error { c.Web = cfg.Web; return nil }); err != nil {
			return err
		}
		keep = true
		return printHTTPSInfo(cfg.Web, opts.language)
	}
	cfg.Web.RequireHTTPS, cfg.Web.AllowInsecureHTTP = true, false
	if _, err := store.Update(func(c *config.Config) error { c.Web = cfg.Web; return nil }); err != nil {
		return err
	}
	return printHTTPSInfo(cfg.Web, opts.language)
}

func generateHTTPSCertificate(web config.WebConfig, extra []string) ([]byte, []byte, error) {
	if len(extra) > 32 {
		return nil, nil, errors.New("at most 32 additional TLS names are allowed")
	}
	dnsNames := map[string]bool{"localhost": true}
	ips := map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true, netip.MustParseAddr("::1"): true}
	addName := func(name string) error {
		name = strings.TrimSpace(name)
		if addr, err := netip.ParseAddr(name); err == nil {
			if addr.IsUnspecified() || addr.IsMulticast() || addr.Zone() != "" {
				return errors.New("TLS SAN must not be an unspecified, multicast, or zoned IP")
			}
			ips[addr.Unmap()] = true
			return nil
		}
		if len(name) == 0 || len(name) > 253 {
			return errors.New("invalid TLS DNS name")
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return errors.New("invalid TLS DNS name")
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return errors.New("TLS DNS names must contain ASCII labels")
				}
			}
		}
		dnsNames[strings.ToLower(name)] = true
		return nil
	}
	if hostname, err := os.Hostname(); err == nil {
		_ = addName(hostname)
	}
	for _, name := range extra {
		if err := addName(name); err != nil {
			return nil, nil, err
		}
	}
	for _, host := range []string{web.ListenIPv4, web.ListenIPv6} {
		if addr, err := netip.ParseAddr(host); err == nil && !addr.IsUnspecified() && !addr.IsMulticast() {
			ips[addr.Unmap()] = true
		}
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, nil, fmt.Errorf("discover certificate IP addresses: %w", err)
	}
	for _, address := range addresses {
		if prefix, err := netip.ParsePrefix(address.String()); err == nil {
			addr := prefix.Addr().Unmap()
			if addr.IsGlobalUnicast() || addr.IsLoopback() {
				ips[addr] = true
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	serial.Add(serial, big.NewInt(1))
	now := time.Now()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "PortBridge self-signed management"}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	for name := range dnsNames {
		template.DNSNames = append(template.DNSNames, name)
	}
	sort.Strings(template.DNSNames)
	for addr := range ips {
		template.IPAddresses = append(template.IPAddresses, net.IP(addr.AsSlice()))
	}
	sort.Slice(template.IPAddresses, func(i, j int) bool { return template.IPAddresses[i].String() < template.IPAddresses[j].String() })
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func printHTTPSInfo(web config.WebConfig, language string) error {
	status, err := webui.InspectTLS(web)
	if err != nil {
		return err
	}
	if !status.Enabled {
		return errors.New("HTTPS certificate is not configured")
	}
	if language == "zh-CN" {
		fmt.Println("管理服务强制使用 HTTPS；证书路径：", web.TLSCertFile)
		if status.SelfSigned {
			fmt.Println("注意：当前使用自签证书。请通过可信渠道核对指纹并建立客户端信任；后续可在 Web 设置中替换正式证书并重启服务。")
		}
	} else {
		fmt.Println("HTTPS is required for management; certificate:", web.TLSCertFile)
		if status.SelfSigned {
			fmt.Println("WARNING: using a self-signed certificate. Verify its fingerprint through a trusted channel before trusting it. Replace it in Web settings and restart when a CA-issued certificate is available.")
		}
	}
	if language == "zh-CN" {
		fmt.Printf("证书 SHA-256: %s\n证书到期时间: %s\n", status.SHA256, status.NotAfter.Format(time.RFC3339))
	} else {
		fmt.Printf("Certificate SHA-256: %s\nCertificate expires: %s\n", status.SHA256, status.NotAfter.Format(time.RFC3339))
	}
	for _, host := range []string{web.ListenIPv4, web.ListenIPv6} {
		if host == "" {
			continue
		}
		if host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		if host == "::" {
			host = "::1"
		}
		fmt.Printf("HTTPS URL: https://%s/\n", net.JoinHostPort(host, fmt.Sprint(web.Port)))
	}
	return nil
}

func readHTTPSInfo(path, language string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- administrator-selected read-only configuration inspection.
	if err != nil {
		return err
	}
	var cfg config.Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	return printHTTPSInfo(cfg.Web, language)
}

func checkHTTPS(path string, opts httpsOptions) error {
	if (opts.cert == "") != (opts.key == "") {
		return errors.New("--tls-cert and --tls-key must be supplied together")
	}
	cfg := config.Default()
	data, err := os.ReadFile(path) // #nosec G304 -- administrator-selected, read-only installation preflight.
	if err == nil {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if opts.cert != "" {
		cfg.Web.TLSCertFile, cfg.Web.TLSKeyFile = opts.cert, opts.key
	}
	if len(opts.names) > 0 && cfg.Web.TLSCertFile != "" {
		return errors.New("--tls-name applies only when generating a new certificate")
	}
	for _, file := range []string{cfg.Web.TLSCertFile, cfg.Web.TLSKeyFile} {
		if file != "" && !filepath.IsAbs(file) {
			return errors.New("TLS paths must be absolute")
		}
	}
	_, err = webui.InspectTLS(cfg.Web)
	return err
}
