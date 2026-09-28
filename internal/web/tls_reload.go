package web

import (
	"net/http"

	"portbridge/internal/config"
)

// handleReloadTLS validates a complete replacement before publishing it to
// new handshakes. Existing TLS sessions keep their negotiated certificate.
func (s *Server) handleReloadTLS(w http.ResponseWriter, _ *http.Request) {
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	if s.activeCert.Load() == nil {
		writeFixedAPIError(w, http.StatusConflict, "apiTLSReloadNeedsHTTPS", "当前监听未启用 HTTPS，须重启服务")
		return
	}
	web := s.store.Get().Web
	s.mu.Lock()
	active := config.WebConfig{}
	if s.startupWeb != nil {
		active = *s.startupWeb
	}
	s.mu.Unlock()
	if effectiveTLSMinVersion(web.TLSMinVersion) != effectiveTLSMinVersion(active.TLSMinVersion) {
		writeFixedAPIError(w, http.StatusConflict, "apiTLSReloadNeedsRestart", "TLS 最低版本变更须重启服务")
		return
	}
	tlsConfig, err := managementTLSConfig(web)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	status, err := validateLoadedTLS(tlsConfig)
	if err != nil || !status.Enabled {
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, err)
		} else {
			writeFixedAPIError(w, http.StatusBadRequest, "apiTLSReloadNeedsHTTPS", "当前配置未提供有效 HTTPS 证书")
		}
		return
	}
	certificate := tlsConfig.Certificates[0]
	s.mu.Lock()
	s.activeCert.Store(&certificate)
	s.activeTLS = status
	active.TLSCertFile = web.TLSCertFile
	active.TLSKeyFile = web.TLSKeyFile
	s.startupWeb = &active
	s.mu.Unlock()
	s.logger.Info("management TLS certificate reloaded", "sha256", status.SHA256, "not_after", status.NotAfter)
	writeJSON(w, http.StatusOK, map[string]any{"reloaded": true, "certificate": status})
}
