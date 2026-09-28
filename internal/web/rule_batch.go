package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"portbridge/internal/config"
)

type ruleSetRequest struct {
	Rules []config.Rule `json:"rules"`
}

func decodeRuleSet(w http.ResponseWriter, r *http.Request) ([]config.Rule, error) {
	var request ruleSetRequest
	if err := decodeJSON(w, r, &request); err != nil {
		return nil, err
	}
	if request.Rules == nil {
		return nil, errors.New("rules must be an array; use [] to remove all rules")
	}
	for i := range request.Rules {
		request.Rules[i] = config.NormalizeRule(request.Rules[i])
	}
	return request.Rules, nil
}

func (s *Server) validateRuleSet(w http.ResponseWriter, r *http.Request) ([]config.Rule, config.Config, string, bool) {
	rules, err := decodeRuleSet(w, r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return nil, config.Config{}, "", false
	}
	cfg, revision := s.store.GetWithRevision()
	cfg.Rules = rules
	if err := config.Validate(cfg); err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return nil, config.Config{}, "", false
	}
	return rules, cfg, revision, true
}

func (s *Server) handleValidateRules(w http.ResponseWriter, r *http.Request) {
	_, _, revision, ok := s.validateRuleSet(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "base_revision": revision, "saved": false, "applied": false})
}

func ruleChanges(before, after []config.Rule) (added, updated, removed, unchanged []string) {
	old := make(map[string]config.Rule, len(before))
	newRules := make(map[string]config.Rule, len(after))
	for _, rule := range before {
		old[rule.ID] = rule
	}
	for _, rule := range after {
		newRules[rule.ID] = rule
		previous, exists := old[rule.ID]
		if !exists {
			added = append(added, rule.ID)
			continue
		}
		a, _ := json.Marshal(previous)
		b, _ := json.Marshal(rule)
		if string(a) == string(b) {
			unchanged = append(unchanged, rule.ID)
		} else {
			updated = append(updated, rule.ID)
		}
	}
	for _, rule := range before {
		if _, exists := newRules[rule.ID]; !exists {
			removed = append(removed, rule.ID)
		}
	}
	for _, group := range [][]string{added, updated, removed, unchanged} {
		sort.Strings(group)
	}
	return
}

func (s *Server) handlePreviewRules(w http.ResponseWriter, r *http.Request) {
	rules, _, revision, ok := s.validateRuleSet(w, r)
	if !ok {
		return
	}
	current, currentRevision := s.store.GetWithRevision()
	if currentRevision != revision {
		writeFixedAPIError(w, http.StatusPreconditionFailed, "apiRevisionConflict", "配置版本已改变，请重新读取后重试")
		return
	}
	added, updated, removed, unchanged := ruleChanges(current.Rules, rules)
	writeJSON(w, http.StatusOK, map[string]any{
		"base_revision": revision, "saved": false, "applied": false,
		"added": added, "updated": updated, "removed": removed, "unchanged": unchanged,
		"notice": "Preview validates configuration only. DNS, nftables, conntrack retirement and end-to-end connectivity are not tested.",
	})
}

func (s *Server) handleReplaceRules(w http.ResponseWriter, r *http.Request) {
	expected, err := requestedRevision(r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	if expected == "" {
		writeFixedAPIError(w, http.StatusPreconditionRequired, "apiRevisionRequired", "批量更新需要 If-Match 配置版本")
		return
	}
	rules, err := decodeRuleSet(w, r)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, err)
		return
	}
	opID, err := randomHex(16)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, err)
		return
	}
	s.changeMu.Lock()
	defer s.changeMu.Unlock()
	old := s.store.Get()
	cfg, err := s.store.UpdateIfRevision(expected, func(c *config.Config) error {
		c.Rules = rules
		return nil
	})
	if err != nil {
		if errors.Is(err, config.ErrRevisionConflict) {
			writeFixedAPIError(w, http.StatusPreconditionFailed, "apiRevisionConflict", "配置版本已改变，请重新读取后重试")
		} else {
			writeAPIError(w, http.StatusBadRequest, err)
		}
		return
	}
	_, _, removed, _ := ruleChanges(old.Rules, cfg.Rules)
	// A replace reapplies unchanged rules too. Include every desired rule in
	// the operation so a no-diff request cannot hide an application failure.
	affected := append([]string(nil), removed...)
	for _, rule := range cfg.Rules {
		affected = append(affected, rule.ID)
	}
	sort.Strings(affected)
	op := s.applyRuleOperation(s.newApplyOperation(opID, cfg, affected), cfg)
	writeOperationHeaders(w, op)
	writeJSON(w, http.StatusOK, map[string]any{"saved": true, "config_revision": op.ConfigRevision, "operation_id": op.ID, "application_state": op.State})
}

func (s *Server) handleExportRuleTemplate(w http.ResponseWriter, _ *http.Request) {
	cfg := s.store.Get()
	templates := make([]map[string]any, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		data, _ := json.Marshal(rule)
		var portable map[string]any
		_ = json.Unmarshal(data, &portable)
		delete(portable, "id")
		templates = append(templates, portable)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"format": "portbridge-rule-template-v1", "rules": templates,
		"notice": "Rule IDs, administrator and monitoring credentials, instance nftables identity, certificate paths and recovery state are excluded. Review endpoints and authorization before importing.",
	})
}
