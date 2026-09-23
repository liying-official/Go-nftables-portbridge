package web

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"portbridge/internal/acl"
	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

func TestMetricsUsesManagementAuthenticationAndACL(t *testing.T) {
	dir := t.TempDir()
	store, token, err := config.LoadOrCreate(filepath.Join(dir, "config.json"), filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	access, err := acl.New(false, false, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := proxy.NewManager(logger)
	server, err := New(store, access, manager, logger, filepath.Join(dir, "admin.token"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, remote, token string
		want                int
	}{{"unauthenticated", "127.0.0.1:1234", "", 401}, {"denied-source", "192.0.2.10:1234", token, 403}, {"authenticated", "127.0.0.1:1234", token, 200}} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/metrics", nil)
			r.RemoteAddr = tc.remote
			if tc.token != "" {
				r.Header.Set("Authorization", "Bearer "+tc.token)
			}
			w := httptest.NewRecorder()
			server.routes().ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if w.Code == 200 {
				if !strings.Contains(w.Header().Get("Content-Type"), "version=0.0.4") || !strings.Contains(w.Body.String(), "# TYPE portbridge_rule_bytes_total counter") {
					t.Fatal("invalid exposition")
				}
				if strings.Contains(w.Body.String(), token) {
					t.Fatal("token leaked")
				}
			}
		})
	}
}

func TestMetricLabelEscaping(t *testing.T) {
	if got := metricLabel("x\"\n\\y"); got != "x\\\"\\n\\\\y" {
		t.Fatalf("bad escaping: %q", got)
	}
}

func TestMetricSamplesAndPrivateLabels(t *testing.T) {
	rows := []proxy.RuleRuntime{{Rule: config.Rule{ID: "rule\"\nname", Name: "PRIVATE-NAME", Protocol: "udp", TargetHost: "private.example"}, Traffic: proxy.TrafficSnapshot{Go: proxy.TrafficSeries{BytesUp: 123, Available: true, RateReady: true, BytesUpPerSecond: 10, SampledAt: time.Now()}, NFT: proxy.TrafficSeries{BytesUp: 456}}, Stats: proxy.StatsSnapshot{ActiveTCP: 2}}}
	text := renderMetrics(time.Now(), rows)
	for _, secret := range []string{"PRIVATE-NAME", "private.example"} {
		if strings.Contains(text, secret) {
			t.Fatal("private label leaked")
		}
	}
	if !strings.Contains(text, `portbridge_rule_bytes_total{rule_id="rule\"\nname",protocol="udp",source="go",direction="up"} 123`) {
		t.Fatal("counter missing or label escaping invalid")
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "portbridge_rule_bytes_per_second{") && strings.Contains(line, `source="nft"`) {
			t.Fatal("unavailable nft rate rendered as zero")
		}
	}
}
