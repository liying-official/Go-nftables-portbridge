package web

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

// ApplyOperation is an in-process observation of a saved configuration
// mutation. It is not an end-to-end business-health or connectivity check.
type ApplyOperation struct {
	ID             string                 `json:"id"`
	ConfigRevision string                 `json:"config_revision"`
	State          string                 `json:"state"`
	Rules          []ApplyRuleObservation `json:"rules"`
	BusinessHealth string                 `json:"business_health"`
	SavedAt        time.Time              `json:"saved_at"`
	CompletedAt    *time.Time             `json:"completed_at,omitempty"`
}

type ApplyRuleObservation struct {
	ID           string `json:"id"`
	Desired      string `json:"desired"`
	KernelState  string `json:"kernel_state"`
	GoRunning    bool   `json:"go_running"`
	ManagerError string `json:"manager_error,omitempty"`
}

var revisionHeader = regexp.MustCompile(`^"([0-9a-f]{64})"$`)

func requestedRevision(r *http.Request) (string, error) {
	values := r.Header.Values("If-Match")
	if len(values) == 0 {
		return "", nil
	}
	if len(values) != 1 {
		return "", errors.New("If-Match must contain one quoted configuration revision")
	}
	match := revisionHeader.FindStringSubmatch(values[0])
	if match == nil {
		return "", errors.New("If-Match must contain one quoted configuration revision")
	}
	return match[1], nil
}

func cloneOperation(op ApplyOperation) ApplyOperation {
	op.Rules = append([]ApplyRuleObservation(nil), op.Rules...)
	if op.CompletedAt != nil {
		completed := *op.CompletedAt
		op.CompletedAt = &completed
	}
	return op
}

func (s *Server) newApplyOperation(id string, cfg config.Config, affected []string) ApplyOperation {
	op := ApplyOperation{ID: id, ConfigRevision: config.Revision(cfg), State: "saved", BusinessHealth: "not_checked", SavedAt: time.Now(), Rules: make([]ApplyRuleObservation, 0, len(affected))}
	for _, ruleID := range affected {
		op.Rules = append(op.Rules, ApplyRuleObservation{ID: ruleID})
	}
	s.setOperation(op)
	return op
}

func (s *Server) setOperation(op ApplyOperation) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if s.operations == nil {
		s.operations = make(map[string]ApplyOperation)
	}
	if _, exists := s.operations[op.ID]; !exists {
		s.operationOrder = append(s.operationOrder, op.ID)
	}
	s.operations[op.ID] = cloneOperation(op)
	if len(s.operationOrder) > 64 {
		delete(s.operations, s.operationOrder[0])
		s.operationOrder = s.operationOrder[1:]
	}
}

func (s *Server) latestOperation() (ApplyOperation, bool) {
	s.operationMu.Lock()
	defer s.operationMu.Unlock()
	if len(s.operationOrder) == 0 {
		return ApplyOperation{}, false
	}
	op := s.operations[s.operationOrder[len(s.operationOrder)-1]]
	return cloneOperation(op), true
}

func (s *Server) handleLatestOperation(w http.ResponseWriter, _ *http.Request) {
	op, ok := s.latestOperation()
	if !ok {
		writeFixedAPIError(w, http.StatusNotFound, "apiOperationNotFound", "没有可用的应用操作")
		return
	}
	writeJSON(w, http.StatusOK, op)
}

func (s *Server) handleOperation(w http.ResponseWriter, r *http.Request) {
	s.operationMu.Lock()
	op, ok := s.operations[r.PathValue("id")]
	s.operationMu.Unlock()
	if !ok {
		writeFixedAPIError(w, http.StatusNotFound, "apiOperationNotFound", "没有可用的应用操作")
		return
	}
	writeJSON(w, http.StatusOK, cloneOperation(op))
}

func (s *Server) applyRuleOperation(op ApplyOperation, cfg config.Config) ApplyOperation {
	op.State = "applying"
	s.setOperation(op)
	s.proxies.Apply(cfg.Rules)
	runtime := s.proxies.Runtime()
	byID := make(map[string]proxy.RuleRuntime, len(runtime))
	for _, row := range runtime {
		byID[row.Rule.ID] = row
	}
	desired := make(map[string]config.Rule, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		desired[rule.ID] = rule
	}
	op.State = "applied"
	for i := range op.Rules {
		item := &op.Rules[i]
		rule, wanted := desired[item.ID]
		row, observed := byID[item.ID]
		item.Desired = "removed"
		if wanted {
			item.Desired = "disabled"
			if rule.Enabled {
				item.Desired = "enabled"
			}
		}
		if observed {
			item.KernelState = row.KernelState
			item.GoRunning = row.GoRunning
			item.ManagerError = row.Stats.LastError
		} else {
			item.KernelState = "not-reported"
		}
		pending := observed && (row.KernelState == "retirement-pending" || row.KernelState == "admission-suspended" ||
			strings.Contains(row.Stats.LastError, "previous kernel forwarding may still be active") ||
			strings.Contains(row.Stats.LastError, "revocation is incomplete") ||
			strings.Contains(row.Stats.LastError, "failed to disable previous nftables path") ||
			strings.Contains(row.Stats.LastError, "failed to remove previous nftables path"))
		if !wanted || !rule.Enabled {
			// A disabled/deleted rule cannot be considered retired while a
			// stale runtime path or unverified kernel state may still exist.
			pending = pending || observed && (row.Stats.Running || row.GoRunning || strings.HasPrefix(row.KernelState, "active-") || row.KernelState == "unknown" || row.KernelState == "unverified")
		} else if !observed || !row.Stats.Running || row.Stats.LastError != "" ||
			(row.DataPlane == proxy.DataPlaneNFT || row.DataPlane == proxy.DataPlaneHybrid) && row.KernelState != "active-verified" {
			if op.State == "applied" {
				op.State = "application_failed"
			}
		}
		if pending {
			op.State = "cleanup_pending"
		}
	}
	completed := time.Now()
	op.CompletedAt = &completed
	s.setOperation(op)
	return op
}

func writeOperationHeaders(w http.ResponseWriter, op ApplyOperation) {
	w.Header().Set("X-PortBridge-Operation-ID", op.ID)
	w.Header().Set("X-PortBridge-Config-Revision", op.ConfigRevision)
	w.Header().Set("X-PortBridge-Application-State", op.State)
}
