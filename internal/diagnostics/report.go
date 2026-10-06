// Package diagnostics explains observations without applying configuration,
// probing listeners, resolving targets, or changing kernel/recovery state.
package diagnostics

import (
	"reflect"
	"strings"
	"time"

	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

// Text is shared by the command and Web UI; codes remain language independent.
type Text struct {
	English string `json:"en-US"`
	Chinese string `json:"zh-CN"`
}

func (t Text) Localized(language string) string {
	if language == "zh-CN" {
		return t.Chinese
	}
	return t.English
}

type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Summary  Text   `json:"summary"`
	Advice   Text   `json:"advice"`
	Evidence string `json:"evidence,omitempty"`
}

func Note(code, severity string) Finding {
	text, ok := messages[code]
	if !ok {
		code, text = "application_failed", messages["application_failed"]
	}
	return Finding{Code: code, Severity: severity, Summary: text[0], Advice: text[1]}
}

type Rule struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Desired     string    `json:"desired"`
	Requested   string    `json:"requested_data_plane"`
	Actual      string    `json:"actual_data_plane"`
	KernelState string    `json:"kernel_state"`
	GoRunning   bool      `json:"go_running"`
	State       string    `json:"state"`
	Evidence    string    `json:"evidence,omitempty"`
	Findings    []Finding `json:"findings"`
}

type Operation struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Revision string `json:"config_revision"`
}

type Report struct {
	GeneratedAt     time.Time   `json:"generated_at"`
	Source          string      `json:"source"`
	ReadOnly        bool        `json:"read_only"`
	RuntimeObserved bool        `json:"runtime_observed"`
	BusinessHealth  string      `json:"business_health"`
	ConfigRevision  string      `json:"config_revision,omitempty"`
	Environment     Environment `json:"environment"`
	Findings        []Finding   `json:"findings"`
	Rules           []Rule      `json:"rules"`
	LatestOperation *Operation  `json:"latest_operation,omitempty"`
}

func Build(cfg config.Config, rows []proxy.RuleRuntime, observed bool, environment Environment) Report {
	report := Report{GeneratedAt: time.Now().UTC(), Source: "service", ReadOnly: true,
		RuntimeObserved: observed, BusinessHealth: "not_checked", ConfigRevision: config.Revision(cfg),
		Environment: environment, Findings: []Finding{Note("observation_boundary", "info")}, Rules: []Rule{}}
	byID := make(map[string]proxy.RuleRuntime, len(rows))
	desired := make(map[string]bool, len(cfg.Rules))
	for _, row := range rows {
		byID[row.Rule.ID] = row
	}
	for _, rule := range cfg.Rules {
		rule = diagnosticRule(rule)
		desired[rule.ID] = true
		row, exists := byID[rule.ID]
		if exists && observed {
			item := explain(row, true)
			item.Name, item.Requested = rule.Name, rule.DataPlane
			item.Desired = "disabled"
			if rule.Enabled {
				item.Desired = "enabled"
			}
			previous, current := diagnosticRule(row.Rule), rule
			previous.Name, current.Name = "", ""
			if !reflect.DeepEqual(previous, current) {
				if item.State == "applied" || item.State == "disabled" {
					item.State = "applying"
				}
				findings := item.Findings[:0]
				for _, finding := range item.Findings {
					if finding.Code != "applied" && finding.Code != "go_path_reason" {
						findings = append(findings, finding)
					}
				}
				item.Findings = append(findings, Note("application_pending", "warning"))
				if !rule.Enabled && possiblePath(row) {
					item.State = "cleanup_pending"
					item.Findings = append(item.Findings, Note("cleanup_pending", "error"))
				}
			}
			report.Rules = append(report.Rules, item)
		} else {
			item := Rule{ID: rule.ID, Name: rule.Name, Desired: "disabled", Requested: rule.DataPlane,
				Actual: "not_observed", KernelState: "not-observed", State: "not_observed", Findings: []Finding{Note("runtime_unavailable", "warning")}}
			if rule.Enabled {
				item.Desired = "enabled"
			}
			report.Rules = append(report.Rules, item)
		}
	}
	// Runtime-only rows retain evidence of old paths even after a rule is deleted.
	for _, row := range rows {
		if !desired[row.Rule.ID] && observed {
			report.Rules = append(report.Rules, explain(row, false))
		}
	}
	return report
}

// Normalize only a copy: controller snapshots may share their rule slices.
func diagnosticRule(rule config.Rule) config.Rule {
	rule.TargetCIDRAllowlist = append([]string(nil), rule.TargetCIDRAllowlist...)
	return config.NormalizeRule(rule)
}

func explain(row proxy.RuleRuntime, wanted bool) Rule {
	item := Rule{ID: row.Rule.ID, Name: row.Rule.Name, Desired: "removed", Requested: row.Rule.DataPlane,
		Actual: "none", KernelState: row.KernelState, GoRunning: row.GoRunning, State: "disabled", Findings: []Finding{}}
	if wanted {
		item.Desired = "disabled"
		if row.Rule.Enabled {
			item.Desired = "enabled"
		}
	}
	if row.GoRunning {
		item.Actual = proxy.DataPlaneGo
	}
	switch row.KernelState {
	case "active-verified":
		item.Actual = proxy.DataPlaneNFT
		if row.GoRunning {
			item.Actual = proxy.DataPlaneHybrid
		}
	case "active-unverified", "retirement-pending", "admission-suspended", "unknown", "unverified":
		item.Actual = "kernel-unverified"
		if row.GoRunning {
			item.Actual = "go-and-unverified-kernel"
		}
	}
	errorText := strings.ToLower(row.Stats.LastError)
	if len(row.Stats.LastError) > 1024 {
		item.Evidence = strings.ToValidUTF8(row.Stats.LastError[:1024], "") + "…"
	} else {
		item.Evidence = row.Stats.LastError
	}
	cleanup := row.KernelState == "retirement-pending" || strings.Contains(errorText, "revocation is incomplete") ||
		strings.Contains(errorText, "may still be active") || strings.Contains(errorText, "failed to disable previous") ||
		strings.Contains(errorText, "failed to remove previous") || (!wanted || !row.Rule.Enabled) && possiblePath(row)
	if cleanup {
		item.State = "cleanup_pending"
		item.Findings = append(item.Findings, Note("cleanup_pending", "error"))
	} else if row.KernelState == "admission-suspended" {
		item.State = "suspended"
		item.Findings = append(item.Findings, Note("admission_suspended", "warning"))
	} else if row.KernelState == "active-unverified" || row.KernelState == "unknown" || row.KernelState == "unverified" {
		item.State = "unverified"
		item.Findings = append(item.Findings, Note("kernel_unverified", "warning"))
	} else if row.Stats.LastError != "" {
		item.State = "application_failed"
	} else if item.Desired == "enabled" {
		if row.GoRunning || row.KernelState == "active-verified" {
			item.State = "applied"
		} else {
			item.State = "not_observed"
			item.Findings = append(item.Findings, Note("runtime_unavailable", "warning"))
		}
	}
	if row.Stats.LastError != "" {
		item.Findings = append(item.Findings, Note(errorCode(errorText), "error"))
	}
	if item.State == "applied" {
		item.Findings = append(item.Findings, Note("applied", "info"))
		if row.Rule.DataPlane == config.RuleDataPlaneNFT && row.GoRunning {
			item.Findings = append(item.Findings, Note("go_path_reason", "info"))
		}
	}
	return item
}

func possiblePath(row proxy.RuleRuntime) bool {
	return row.GoRunning || row.Stats.Running || strings.HasPrefix(row.KernelState, "active-") ||
		row.KernelState == "unknown" || row.KernelState == "unverified" || row.KernelState == "admission-suspended"
}

func errorCode(message string) string {
	switch {
	case strings.Contains(message, "permission denied"), strings.Contains(message, "operation not permitted"), strings.Contains(message, "cap_net_admin"):
		return "permission_denied"
	case strings.Contains(message, "local/private target"), strings.Contains(message, "target_cidr_allowlist"), strings.Contains(message, "not a valid unicast"):
		return "target_policy_denied"
	case strings.Contains(message, "resolve target"), strings.Contains(message, "no usable address"), strings.Contains(message, "no usable ip"), strings.Contains(message, "no such host"):
		return "target_resolution_failed"
	case strings.Contains(message, "external"), strings.Contains(message, "netfilter"), strings.Contains(message, "hook"), strings.Contains(message, "firewall"):
		return "firewall_compatibility_rejected"
	case strings.Contains(message, "trusted root-owned"), strings.Contains(message, "trusted binary"), strings.Contains(message, "executable is required"):
		return "dependency_missing"
	case strings.Contains(message, "ownership"), strings.Contains(message, "owner"), strings.Contains(message, "unattributable"), strings.Contains(message, "identity"), strings.Contains(message, "journal"), strings.Contains(message, "recovery"):
		return "ownership_unverified"
	case strings.Contains(message, "listen"), strings.Contains(message, "bind"), strings.Contains(message, "address already in use"), strings.Contains(message, "cannot assign requested address"):
		return "listener_failed"
	case strings.Contains(message, "conntrack"), strings.Contains(message, "retir"), strings.Contains(message, "cleanup"), strings.Contains(message, "revocation"):
		return "cleanup_pending"
	default:
		return "application_failed"
	}
}
