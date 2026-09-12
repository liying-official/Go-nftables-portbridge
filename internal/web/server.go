package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"portbridge/internal/acl"
	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

//go:embed static/*
var staticFS embed.FS

const maxJSONBodyBytes = 1 << 20

type Server struct {
	store      *config.Store
	acl        *acl.Manager
	proxies    *proxy.Manager
	logger     *slog.Logger
	tokenFile  string
	startedAt  time.Time
	csrf       string
	mu         sync.Mutex
	servers    []*http.Server
	listeners  []net.Listener
	startupWeb *config.WebConfig
	activeTLS  CertificateStatus

	aclDenyLogUnix    atomic.Int64
	aclDenySuppressed atomic.Uint64
	securityOnce      sync.Once
	authFailures      *authFailureLimiter
}

type APIError struct {
	Error string `json:"error"`
}

func New(store *config.Store, aclManager *acl.Manager, proxies *proxy.Manager, logger *slog.Logger, tokenFile string) (*Server, error) {
	csrf, err := randomHex(24)
	if err != nil {
		return nil, err
	}
	web := store.Get().Web
	return &Server{
		store: store, acl: aclManager, proxies: proxies, logger: logger,
		tokenFile: tokenFile, startedAt: time.Now(), csrf: csrf, startupWeb: &web,
	}, nil
}

func (s *Server) Start() error {
	cfg := s.store.Get()
	tlsConfig, err := managementTLSConfig(cfg.Web)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.startupWeb = &cfg.Web
	s.activeTLS = certificateStatus(tlsConfig)
	s.mu.Unlock()
	if status := certificateStatus(tlsConfig); status.SelfSigned {
		s.logger.Warn("self-signed HTTPS certificate in use; verify its fingerprint through a trusted channel before trusting it, or replace it with your own certificate", "sha256", status.SHA256, "not_after", status.NotAfter)
	}
	handler := s.routes()
	addresses := []struct {
		network string
		host    string
	}{
		{network: "tcp4", host: cfg.Web.ListenIPv4},
		{network: "tcp6", host: cfg.Web.ListenIPv6},
	}
	for _, item := range addresses {
		if item.host == "" {
			continue
		}
		rawListener, err := net.Listen(item.network, net.JoinHostPort(item.host, strconv.Itoa(cfg.Web.Port)))
		if err != nil {
			s.logger.Warn("web listen address unavailable", "address", net.JoinHostPort(item.host, strconv.Itoa(cfg.Web.Port)), "error", err)
			continue
		}
		filteredListener := &aclListener{Listener: rawListener, acl: s.acl, onDeny: s.logACLDenied}
		ln := newConnectionLimitListener(filteredListener, maxManagementConnections)
		srv := &http.Server{
			Handler:             handler,
			ReadHeaderTimeout:   5 * time.Second,
			ReadTimeout:         15 * time.Second,
			WriteTimeout:        30 * time.Second,
			IdleTimeout:         60 * time.Second,
			MaxHeaderBytes:      32 << 10,
			MaxHeaderValueCount: 128,
		}
		if tlsConfig != nil {
			srv.TLSConfig = tlsConfig.Clone()
		}
		s.mu.Lock()
		s.listeners = append(s.listeners, ln)
		s.servers = append(s.servers, srv)
		s.mu.Unlock()
		go func(server *http.Server, listener net.Listener, useTLS bool) {
			var serveErr error
			if useTLS {
				serveErr = server.ServeTLS(listener, "", "")
			} else {
				serveErr = server.Serve(listener)
			}
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) && !errors.Is(serveErr, net.ErrClosed) {
				s.logger.Error("web server stopped unexpectedly", "error", serveErr)
			}
		}(srv, ln, tlsConfig != nil)
		scheme := "http"
		if tlsConfig != nil {
			scheme = "https"
		} else if hostIP, parseErr := netip.ParseAddr(item.host); parseErr == nil && !hostIP.IsLoopback() {
			s.logger.Warn("INSECURE management HTTP is exposed beyond loopback by explicit configuration", "address", ln.Addr().String())
		}
		s.logger.Info("web management listening", "address", ln.Addr().String(), "scheme", scheme, "strict_ip_allowlist", cfg.Web.StrictIPAllowlist)
	}
	if len(s.listeners) == 0 {
		return errors.New("no web listen address configured")
	}
	return nil
}

func (s *Server) Close() {
	s.mu.Lock()
	servers := append([]*http.Server(nil), s.servers...)
	listeners := append([]net.Listener(nil), s.listeners...)
	s.servers = nil
	s.listeners = nil
	s.mu.Unlock()
	for _, srv := range servers {
		_ = srv.Close()
	}
	for _, ln := range listeners {
		_ = ln.Close()
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.serveIndex)
	mux.HandleFunc("GET /static/app.js", s.serveStatic("static/app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /static/style.css", s.serveStatic("static/style.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /static/security.css", s.serveStatic("static/security.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /api/bootstrap", s.requireAuth(s.handleBootstrap))
	mux.HandleFunc("GET /api/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("GET /api/config", s.requireAuth(s.handleGetConfig))
	mux.HandleFunc("PUT /api/settings", s.requireAuth(s.requireBrowserSameOrigin(s.requireCSRF(s.handleSettings))))
	mux.HandleFunc("POST /api/token/rotate", s.requireAuth(s.requireBrowserSameOrigin(s.requireCSRF(s.handleRotateToken))))
	mux.HandleFunc("POST /api/rules", s.requireAuth(s.requireBrowserSameOrigin(s.requireCSRF(s.handleCreateRule))))
	mux.HandleFunc("PUT /api/rules/{id}", s.requireAuth(s.requireBrowserSameOrigin(s.requireCSRF(s.handleUpdateRule))))
	mux.HandleFunc("DELETE /api/rules/{id}", s.requireAuth(s.requireBrowserSameOrigin(s.requireCSRF(s.handleDeleteRule))))
	return s.securityHeaders(s.accessControl(mux))
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	data, _ := staticFS.ReadFile("static/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(data)
}

func (s *Server) serveStatic(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; worker-src 'none'; manifest-src 'none'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) accessControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, err := remoteIP(r.RemoteAddr)
		if err != nil || !s.acl.Allowed(ip) {
			remote := "invalid"
			if err == nil {
				remote = ip.Unmap().String()
			}
			s.logACLDenied(remote)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logACLDenied(remote string) {
	const intervalSeconds = int64(60)
	now := time.Now().Unix()
	for {
		last := s.aclDenyLogUnix.Load()
		if last != 0 && now-last < intervalSeconds {
			s.aclDenySuppressed.Add(1)
			return
		}
		if !s.aclDenyLogUnix.CompareAndSwap(last, now) {
			continue
		}
		suppressed := s.aclDenySuppressed.Swap(0)
		s.logger.Warn("web access denied by ACL", "remote", remote, "suppressed_since_last", suppressed)
		return
	}
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.initializeSecurityControls()
		ip, _ := remoteIP(r.RemoteAddr)
		token, parsed := bearerToken(r.Header.Values("Authorization"))
		if parsed && s.validToken(token) {
			s.authFailures.reset(ip)
			next(w, r)
			return
		}
		if !s.authFailures.allowFailure(ip) {
			writeJSON(w, http.StatusTooManyRequests, APIError{Error: "认证请求过于频繁，请稍后重试"})
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="PortBridge"`)
		writeJSON(w, http.StatusUnauthorized, APIError{Error: "管理员令牌无效"})
	}
}

func (s *Server) initializeSecurityControls() {
	s.securityOnce.Do(func() {
		if s.authFailures == nil {
			s.authFailures = newAuthFailureLimiter()
		}
	})
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	fields := strings.Fields(values[0])
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || len(fields[1]) != 64 {
		return "", false
	}
	return fields[1], true
}

func (s *Server) requireBrowserSameOrigin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sites := r.Header.Values("Sec-Fetch-Site")
		if len(sites) > 1 {
			writeJSON(w, http.StatusForbidden, APIError{Error: "跨站请求被拒绝"})
			return
		}
		if len(sites) == 1 && sites[0] != "" && sites[0] != "same-origin" && sites[0] != "none" {
			writeJSON(w, http.StatusForbidden, APIError{Error: "跨站请求被拒绝"})
			return
		}
		origins := r.Header.Values("Origin")
		if len(origins) > 1 {
			writeJSON(w, http.StatusForbidden, APIError{Error: "跨站请求被拒绝"})
			return
		}
		if len(origins) == 1 && origins[0] != "" {
			origin, err := url.Parse(origins[0])
			expectedScheme := "http"
			if r.TLS != nil {
				expectedScheme = "https"
			}
			if err != nil || origin.Scheme != expectedScheme || origin.User != nil || origin.Opaque != "" ||
				origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" || !strings.EqualFold(origin.Host, r.Host) {
				writeJSON(w, http.StatusForbidden, APIError{Error: "跨站请求被拒绝"})
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) requireCSRF(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-PortBridge-CSRF")), []byte(s.csrf)) != 1 {
			writeJSON(w, http.StatusForbidden, APIError{Error: "CSRF 校验失败，请刷新页面"})
			return
		}
		next(w, r)
	}
}

func (s *Server) validToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	expected, err := hex.DecodeString(s.store.Get().Web.AdminTokenSHA)
	if err != nil || len(expected) != sha256.Size {
		return false
	}
	actual := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(actual[:], expected) == 1
}

func (s *Server) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"csrf": s.csrf, "name": "Go-nftables-portbridge"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.acl.Snapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"uptime_seconds": int64(time.Since(s.startedAt).Seconds()),
		"rules":          s.proxies.Runtime(),
		"acl": map[string]any{
			"auto":      prefixesToStrings(snap.Auto),
			"whitelist": prefixesToStrings(snap.Whitelist),
			"bootstrap": prefixesToStrings(snap.Bootstrap),
			"strict":    snap.Strict,
		},
	})
}

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Get()
	s.mu.Lock()
	activeTLS := s.activeTLS
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"web": map[string]any{
			"port":                cfg.Web.Port,
			"listen_ipv4":         cfg.Web.ListenIPv4,
			"listen_ipv6":         cfg.Web.ListenIPv6,
			"auto_lan_acl":        cfg.Web.AutoLANACL,
			"strict_ip_allowlist": cfg.Web.StrictIPAllowlist,
			"allow_insecure_http": cfg.Web.AllowInsecureHTTP,
			"whitelist":           cfg.Web.Whitelist,
			"tls_cert_file":       cfg.Web.TLSCertFile,
			"tls_key_file":        cfg.Web.TLSKeyFile,
			"tls_min_version":     cfg.Web.TLSMinVersion,
			"dns_servers":         cfg.Web.DNSServers,
		},
		"rules": cfg.Rules,
		"https": map[string]any{"required": cfg.Web.RequireHTTPS, "certificate": activeTLS},
	})
}

type settingsRequest struct {
	AutoLANACL        bool     `json:"auto_lan_acl"`
	StrictIPAllowlist bool     `json:"strict_ip_allowlist"`
	AllowInsecureHTTP bool     `json:"allow_insecure_http"`
	Whitelist         []string `json:"whitelist"`
	Port              int      `json:"port"`
	ListenIPv4        string   `json:"listen_ipv4"`
	ListenIPv6        string   `json:"listen_ipv6"`
	TLSCertFile       string   `json:"tls_cert_file"`
	TLSKeyFile        string   `json:"tls_key_file"`
	TLSMinVersion     string   `json:"tls_min_version"`
	DNSServers        []string `json:"dns_servers"`
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		return
	}
	normalized, err := config.NormalizeWhitelist(req.Whitelist)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		return
	}
	normalizedDNS, err := config.NormalizeDNSServers(req.DNSServers)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		return
	}
	certFile := strings.TrimSpace(req.TLSCertFile)
	keyFile := strings.TrimSpace(req.TLSKeyFile)
	tlsMinVersion := strings.TrimSpace(req.TLSMinVersion)
	switch tlsMinVersion {
	case "", config.TLSMinVersion12, config.TLSMinVersion13:
	default:
		writeJSON(w, http.StatusBadRequest, APIError{Error: "tls_min_version 仅支持 1.2 或 1.3"})
		return
	}
	if certFile != "" && keyFile != "" {
		if _, err := InspectTLS(config.WebConfig{TLSCertFile: certFile, TLSKeyFile: keyFile, TLSMinVersion: tlsMinVersion}); err != nil {
			writeJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
			return
		}
	}
	if req.StrictIPAllowlist {
		if r.TLS == nil {
			writeJSON(w, http.StatusBadRequest, APIError{Error: "请先配置 TLS 并重启服务，再通过 HTTPS 启用严格 IP 白名单"})
			return
		}
		clientIP, parseErr := remoteIP(r.RemoteAddr)
		if parseErr != nil || !clientIP.IsLoopback() && !prefixStringsContain(normalized, clientIP) {
			writeJSON(w, http.StatusBadRequest, APIError{Error: "严格 IP 白名单必须包含当前客户端地址"})
			return
		}
	}
	old := s.store.Get()
	cfg, err := s.store.Update(func(c *config.Config) error {
		c.Web.AutoLANACL = req.AutoLANACL
		c.Web.StrictIPAllowlist = req.StrictIPAllowlist
		c.Web.AllowInsecureHTTP = req.AllowInsecureHTTP
		c.Web.Whitelist = normalized
		c.Web.Port = req.Port
		c.Web.ListenIPv4 = strings.TrimSpace(req.ListenIPv4)
		c.Web.ListenIPv6 = strings.TrimSpace(req.ListenIPv6)
		c.Web.TLSCertFile = certFile
		c.Web.TLSKeyFile = keyFile
		// Older clients do not send this additive security field. Preserve
		// the configured policy unless a version was explicitly selected.
		if tlsMinVersion != "" {
			c.Web.TLSMinVersion = tlsMinVersion
		}
		c.Web.DNSServers = normalizedDNS
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		return
	}
	if err := s.acl.Refresh(cfg.Web.AutoLANACL, cfg.Web.StrictIPAllowlist, cfg.Web.Whitelist, prefixesToStrings(s.acl.Snapshot().Bootstrap)); err != nil {
		_, _ = s.store.Update(func(c *config.Config) error { *c = old; return nil })
		_ = s.acl.Refresh(old.Web.AutoLANACL, old.Web.StrictIPAllowlist, old.Web.Whitelist, prefixesToStrings(s.acl.Snapshot().Bootstrap))
		writeJSON(w, http.StatusInternalServerError, APIError{Error: err.Error()})
		return
	}
	s.proxies.SetDNSServers(cfg.Web.DNSServers)
	// Compare with the listener's startup policy, not the preceding save:
	// repeated saves must not hide a restart that is still pending.
	s.mu.Lock()
	active := old.Web
	if s.startupWeb != nil {
		active = *s.startupWeb
	}
	s.mu.Unlock()
	restartRequired := active.Port != cfg.Web.Port || active.ListenIPv4 != cfg.Web.ListenIPv4 || active.ListenIPv6 != cfg.Web.ListenIPv6 || active.TLSCertFile != cfg.Web.TLSCertFile || active.TLSKeyFile != cfg.Web.TLSKeyFile || effectiveTLSMinVersion(active.TLSMinVersion) != effectiveTLSMinVersion(cfg.Web.TLSMinVersion) || active.AllowInsecureHTTP != cfg.Web.AllowInsecureHTTP
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": restartRequired})
}

func effectiveTLSMinVersion(version string) string {
	if version == "" {
		return config.TLSMinVersion12
	}
	return version
}

func (s *Server) handleRotateToken(w http.ResponseWriter, r *http.Request) {
	token, err := s.store.RotateAdminToken(s.tokenFile)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, APIError{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var rule config.Rule
	if err := decodeJSON(w, r, &rule); err != nil {
		writeJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		return
	}
	id, err := config.NewRuleID()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, APIError{Error: err.Error()})
		return
	}
	rule.ID = id
	rule = config.NormalizeRule(rule)
	cfg, err := s.store.Update(func(c *config.Config) error {
		c.Rules = append(c.Rules, rule)
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		return
	}
	s.proxies.Apply(cfg.Rules)
	writeJSON(w, http.StatusCreated, rule)
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var rule config.Rule
	if err := decodeJSON(w, r, &rule); err != nil {
		writeJSON(w, http.StatusBadRequest, APIError{Error: err.Error()})
		return
	}
	rule.ID = id
	rule = config.NormalizeRule(rule)
	found := false
	cfg, err := s.store.Update(func(c *config.Config) error {
		for i := range c.Rules {
			if c.Rules[i].ID == id {
				c.Rules[i] = rule
				found = true
				return nil
			}
		}
		return fmt.Errorf("rule %q not found", id)
	})
	if err != nil {
		status := http.StatusBadRequest
		if !found {
			status = http.StatusNotFound
		}
		writeJSON(w, status, APIError{Error: err.Error()})
		return
	}
	s.proxies.Apply(cfg.Rules)
	writeJSON(w, http.StatusOK, rule)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	found := false
	cfg, err := s.store.Update(func(c *config.Config) error {
		out := c.Rules[:0]
		for _, rule := range c.Rules {
			if rule.ID == id {
				found = true
				continue
			}
			out = append(out, rule)
		}
		if !found {
			return fmt.Errorf("rule %q not found", id)
		}
		c.Rules = out
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		if !found {
			status = http.StatusNotFound
		}
		writeJSON(w, status, APIError{Error: err.Error()})
		return
	}
	s.proxies.Apply(cfg.Rules)
	w.WriteHeader(http.StatusNoContent)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	defer r.Body.Close()
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errors.New("Content-Type 必须是 application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			return fmt.Errorf("JSON 请求体不能超过 %d 字节", maxJSONBodyBytes)
		}
		return fmt.Errorf("JSON 格式错误: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		var sizeErr *http.MaxBytesError
		if errors.As(err, &sizeErr) {
			return fmt.Errorf("JSON 请求体不能超过 %d 字节", maxJSONBodyBytes)
		}
		return errors.New("请求只能包含一个 JSON 对象")
	}
	return nil
}

func prefixStringsContain(prefixes []string, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, raw := range prefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func remoteIP(remoteAddr string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	return netip.ParseAddr(host)
}

func prefixesToStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
