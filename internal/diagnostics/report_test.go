package diagnostics

import (
	"encoding/json"
	"strings"
	"testing"

	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

func TestExplainsFailuresWithoutTreatingRiskAsHealth(t *testing.T) {
	for _, test := range []struct{ name, evidence, kernel, state, code string }{
		{"permission", "listen tcp: permission denied", "inactive-verified", "application_failed", "permission_denied"},
		{"dns", "resolve target example.invalid: no such host", "inactive-verified", "application_failed", "target_resolution_failed"},
		{"target policy", "resolve target: local/private target is denied by default", "inactive-verified", "application_failed", "target_policy_denied"},
		{"firewall", "external netfilter hook cannot be proved compatible", "admission-suspended", "suspended", "firewall_compatibility_rejected"},
		{"listen", "listen tcp 127.0.0.1:8080: address already in use", "inactive-verified", "application_failed", "listener_failed"},
		{"cleanup", "previous kernel forwarding may still be active; revocation is incomplete", "retirement-pending", "cleanup_pending", "cleanup_pending"},
		{"ownership", "instance ownership records cannot be verified", "unknown", "unverified", "ownership_unverified"},
		{"dependency", "no trusted root-owned nft executable was found", "inactive-verified", "application_failed", "dependency_missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := config.Default()
			rule := config.Rule{ID: "one", Name: "one", Enabled: true, DataPlane: "nftables"}
			cfg.Rules = []config.Rule{rule}
			row := proxy.RuleRuntime{Rule: rule, KernelState: test.kernel, Stats: proxy.StatsSnapshot{Running: true, LastError: test.evidence}}
			report := Build(cfg, []proxy.RuleRuntime{row}, true, Environment{})
			item := report.Rules[0]
			if item.State != test.state || report.BusinessHealth != "not_checked" || !report.ReadOnly {
				t.Fatalf("incorrect state: %+v", report)
			}
			found := false
			for _, finding := range item.Findings {
				found = found || finding.Code == test.code
			}
			if !found {
				t.Fatalf("missing %s: %+v", test.code, item)
			}
		})
	}
}

func TestActualPlaneAndDeletedCleanupRows(t *testing.T) {
	cfg := config.Default()
	rule := config.Rule{ID: "one", Name: "one", Enabled: true, DataPlane: "nftables"}
	cfg.Rules = []config.Rule{rule}
	for _, test := range []struct {
		kernel    string
		goRunning bool
		want      string
	}{
		{"inactive-verified", false, "none"}, {"inactive-verified", true, "go-proxy"},
		{"active-verified", false, "nftables"}, {"active-verified", true, "hybrid"},
		{"unknown", false, "kernel-unverified"}, {"unknown", true, "go-and-unverified-kernel"},
		{"unverified", false, "kernel-unverified"}, {"unverified", true, "go-and-unverified-kernel"},
	} {
		row := proxy.RuleRuntime{Rule: rule, KernelState: test.kernel, GoRunning: test.goRunning}
		if got := Build(cfg, []proxy.RuleRuntime{row}, true, Environment{}).Rules[0].Actual; got != test.want {
			t.Fatalf("%s/%t: %s", test.kernel, test.goRunning, got)
		}
	}
	cfg.Rules = nil
	row := proxy.RuleRuntime{Rule: rule, KernelState: "retirement-pending", Stats: proxy.StatsSnapshot{Running: true}}
	item := Build(cfg, []proxy.RuleRuntime{row}, true, Environment{}).Rules[0]
	if item.Desired != "removed" || item.State != "cleanup_pending" {
		t.Fatalf("deleted evidence lost: %+v", item)
	}
}

func TestReportsDoNotExposeCredentials(t *testing.T) {
	cfg := config.Default()
	cfg.Web.AdminTokenSHA = strings.Repeat("a", 64)
	cfg.Web.MonitorTokenSHA = strings.Repeat("b", 64)
	cfg.Web.TLSKeyFile = "/secret/private.pem"
	data, err := json.Marshal(Build(cfg, nil, false, Environment{}))
	if err != nil || strings.Contains(string(data), cfg.Web.AdminTokenSHA) || strings.Contains(string(data), cfg.Web.MonitorTokenSHA) || strings.Contains(string(data), cfg.Web.TLSKeyFile) {
		t.Fatalf("credentials/paths exposed: %s %v", data, err)
	}
	for code, text := range messages {
		if text[0].English == "" || text[0].Chinese == "" || text[1].English == "" || text[1].Chinese == "" {
			t.Fatalf("incomplete bilingual explanation: %s", code)
		}
	}
}

func TestSavedChangesAndDisabledOldPathsAreNotReportedApplied(t *testing.T) {
	cfg := config.Default()
	rule := config.Rule{ID: "one", Name: "renamed", Enabled: true, TargetPort: 9001, DataPlane: "go"}
	cfg.Rules = []config.Rule{rule}
	row := proxy.RuleRuntime{Rule: rule, GoRunning: true, KernelState: "inactive-verified"}
	row.Rule.Name = "old name"
	if got := Build(cfg, []proxy.RuleRuntime{row}, true, Environment{}).Rules[0].State; got != "applied" {
		t.Fatalf("display name is not a dataplane change: %s", got)
	}
	row.Rule.TargetPort = 9000
	if got := Build(cfg, []proxy.RuleRuntime{row}, true, Environment{}).Rules[0].State; got != "applying" {
		t.Fatalf("saved target reported applied prematurely: %s", got)
	}
	row.KernelState = "retirement-pending"
	if got := Build(cfg, []proxy.RuleRuntime{row}, true, Environment{}).Rules[0].State; got != "cleanup_pending" {
		t.Fatalf("saved change hid cleanup: %s", got)
	}
	cfg.Rules[0].Enabled = false
	row.KernelState = "active-verified"
	if got := Build(cfg, []proxy.RuleRuntime{row}, true, Environment{}).Rules[0].State; got != "cleanup_pending" {
		t.Fatalf("disabled stale path reported retired: %s", got)
	}
	row.Rule = cfg.Rules[0]
	if got := Build(cfg, []proxy.RuleRuntime{row}, true, Environment{}).Rules[0].State; got != "cleanup_pending" {
		t.Fatalf("disabled active kernel path reported retired: %s", got)
	}
}

func TestDefaultNormalizationIsReadOnlyAndDoesNotImplyPendingChange(t *testing.T) {
	cfg := config.Default()
	cfg.Rules = []config.Rule{{ID: "one", Enabled: true, DataPlane: "go", TargetCIDRAllowlist: []string{" 192.0.2.0/24 "}}}
	before, _ := json.Marshal(cfg)
	row := proxy.RuleRuntime{Rule: diagnosticRule(cfg.Rules[0]), GoRunning: true, KernelState: "inactive-verified"}
	item := Build(cfg, []proxy.RuleRuntime{row}, true, Environment{}).Rules[0]
	after, _ := json.Marshal(cfg)
	if item.State != "applied" || string(before) != string(after) {
		t.Fatalf("default interpretation altered input or implied a change: %+v", item)
	}
}
