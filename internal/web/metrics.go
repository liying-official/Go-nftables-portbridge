package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"portbridge/internal/proxy"
)

func metricLabel(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(value)
}
func metricFlag(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Metrics uses the same listener ACL and HTTPS policy as the API. It accepts
// administrator or monitoring Bearer tokens, never exposing either credential.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.proxies == nil {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	rows := s.proxies.Runtime()
	s.mu.Lock()
	certificate := s.activeTLS
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(renderMetrics(s.startedAt, rows, certificate)))
}

func renderMetrics(startedAt time.Time, rows []proxy.RuleRuntime, certificates ...CertificateStatus) string {
	var b strings.Builder
	b.WriteString("# HELP portbridge_uptime_seconds Management process uptime.\n# TYPE portbridge_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "portbridge_uptime_seconds %.3f\n", time.Since(startedAt).Seconds())
	b.WriteString("# HELP portbridge_tls_certificate_loaded One when a management TLS certificate is loaded.\n# TYPE portbridge_tls_certificate_loaded gauge\n")
	b.WriteString("# HELP portbridge_tls_certificate_not_after_timestamp_seconds Unix expiry of the loaded management TLS certificate; absent if HTTP.\n# TYPE portbridge_tls_certificate_not_after_timestamp_seconds gauge\n")
	b.WriteString("# HELP portbridge_tls_certificate_seconds_until_expiry Seconds until the loaded management TLS certificate expires; may be negative.\n# TYPE portbridge_tls_certificate_seconds_until_expiry gauge\n")
	loaded := len(certificates) > 0 && certificates[0].Enabled
	fmt.Fprintf(&b, "portbridge_tls_certificate_loaded %d\n", metricFlag(loaded))
	if loaded {
		fmt.Fprintf(&b, "portbridge_tls_certificate_not_after_timestamp_seconds %d\n", certificates[0].NotAfter.Unix())
		fmt.Fprintf(&b, "portbridge_tls_certificate_seconds_until_expiry %.3f\n", time.Until(certificates[0].NotAfter).Seconds())
	}
	definitions := [][3]string{
		{"portbridge_rule_running", "gauge", "Manager running/risk flag; not end-to-end health."},
		{"portbridge_rule_desired_enabled", "gauge", "One when the persisted rule is administratively enabled; not proof of forwarding."},
		{"portbridge_rule_bytes_total", "counter", "Observed bytes by source and direction; Go payload, nft sampled L3; do not sum different sources as payload."},
		{"portbridge_rule_bytes_per_second", "gauge", "Sampled observed byte rate; omitted when the sample is unavailable or warming up."},
		{"portbridge_rule_sample_available", "gauge", "One when the source sample is fresh and available."},
		{"portbridge_rule_rate_ready", "gauge", "One when a valid recent delta exists."},
		{"portbridge_rule_sample_timestamp_seconds", "gauge", "Unix time of the last successful source sample."},
		{"portbridge_nft_packets_total", "counter", "Best-effort observed conntrack L3 packets, including asynchronously synchronized flowtable counters when available."},
		{"portbridge_nft_hook_bytes_total", "counter", "Observed nft rule hook bytes; hooks overlap and exclude fast-path bypass packets. Never sum hooks."},
		{"portbridge_nft_hook_packets_total", "counter", "Observed nft rule hook packets, not total forwarding traffic."},
		{"portbridge_nft_hooks_available", "gauge", "One when owned nft hook counters were sampled recently."},
		{"portbridge_nft_counter_resets_total", "counter", "Detected decreases in kernel accounting counters."},
		{"portbridge_go_active_tcp_connections", "gauge", "Current Go TCP connections."},
		{"portbridge_go_tcp_fallbacks_total", "counter", "Go TCP connections established through the configured backup after target selection; not application health."},
		{"portbridge_go_tcp_connect_status", "gauge", "Latest optional TCP connect-check status; not application-layer health."},
		{"portbridge_go_active_udp_sessions", "gauge", "Current Go UDP sessions."},
		{"portbridge_go_udp_drops_total", "counter", "Application-observed Go UDP drops, not network-wide loss."},
	}
	for _, d := range definitions {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", d[0], d[2], d[0], d[1])
	}
	for _, row := range rows {
		labels := fmt.Sprintf("rule_id=\"%s\",protocol=\"%s\"", metricLabel(row.Rule.ID), metricLabel(row.Rule.Protocol))
		fmt.Fprintf(&b, "portbridge_rule_running{%s} %d\n", labels, metricFlag(row.Stats.Running))
		fmt.Fprintf(&b, "portbridge_rule_desired_enabled{%s} %d\n", labels, metricFlag(row.Rule.Enabled))
		for _, item := range []struct {
			source string
			series proxy.TrafficSeries
		}{{"go", row.Traffic.Go}, {"nft", row.Traffic.NFT}} {
			l := labels + ",source=\"" + item.source + "\""
			v := item.series
			fmt.Fprintf(&b, "portbridge_rule_sample_available{%s} %d\nportbridge_rule_rate_ready{%s} %d\n", l, metricFlag(v.Available), l, metricFlag(v.RateReady))
			stamp := float64(0)
			if !v.SampledAt.IsZero() {
				stamp = float64(v.SampledAt.UnixNano()) / 1e9
			}
			fmt.Fprintf(&b, "portbridge_rule_sample_timestamp_seconds{%s} %.3f\n", l, stamp)
			fmt.Fprintf(&b, "portbridge_rule_bytes_total{%s,direction=\"up\"} %d\nportbridge_rule_bytes_total{%s,direction=\"down\"} %d\n", l, v.BytesUp, l, v.BytesDown)
			if v.Available && v.RateReady {
				fmt.Fprintf(&b, "portbridge_rule_bytes_per_second{%s,direction=\"up\"} %.6f\nportbridge_rule_bytes_per_second{%s,direction=\"down\"} %.6f\n", l, v.BytesUpPerSecond, l, v.BytesDownPerSecond)
			}
		}
		fmt.Fprintf(&b, "portbridge_nft_packets_total{%s,direction=\"up\"} %d\nportbridge_nft_packets_total{%s,direction=\"down\"} %d\n", labels, row.Traffic.NFT.PacketsUp, labels, row.Traffic.NFT.PacketsDown)
		fmt.Fprintf(&b, "portbridge_nft_hooks_available{%s} %d\nportbridge_nft_counter_resets_total{%s} %d\n", labels, metricFlag(row.Traffic.NFTHooksAvailable), labels, row.Traffic.CounterResets)
		for _, h := range row.Traffic.NFTHooks {
			l := labels + ",hook=\"" + metricLabel(h.Hook) + "\""
			fmt.Fprintf(&b, "portbridge_nft_hook_bytes_total{%s} %d\nportbridge_nft_hook_packets_total{%s} %d\n", l, h.Bytes, l, h.Packets)
		}
		fmt.Fprintf(&b, "portbridge_go_active_tcp_connections{%s} %d\nportbridge_go_active_udp_sessions{%s} %d\nportbridge_go_udp_drops_total{%s} %d\n", labels, row.Stats.ActiveTCP, labels, row.Stats.ActiveUDPSessions, labels, row.Stats.UDPDrops)
		fmt.Fprintf(&b, "portbridge_go_tcp_fallbacks_total{%s} %d\n", labels, row.Stats.TCPFallbacks)
		fmt.Fprintf(&b, "portbridge_go_tcp_connect_status{%s,status=\"%s\"} 1\n", labels, metricLabel(row.BackendConnectivity.Status))
	}
	return b.String()
}
