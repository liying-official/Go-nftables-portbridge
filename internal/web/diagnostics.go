package web

import (
	"net/http"

	"portbridge/internal/config"
	"portbridge/internal/diagnostics"
)

func (s *Server) handleDiagnostics(w http.ResponseWriter, _ *http.Request) {
	cfg, revision := s.store.GetWithRevision()
	rows := s.proxies.Runtime()
	report := diagnostics.Build(cfg, rows, true, diagnostics.InspectEnvironment(cfg, "service"))
	report.ConfigRevision = revision
	_, currentRevision := s.store.GetWithRevision()
	if currentRevision != revision {
		report.Findings = append(report.Findings, diagnostics.Note("snapshot_changed", "warning"))
	}
	if !config.TokenFileConsistent(s.tokenFile, cfg.Web.AdminTokenSHA) {
		report.Findings = append(report.Findings, diagnostics.Note("token_inconsistent", "error"))
	}
	if operation, ok := s.latestOperation(); ok {
		report.LatestOperation = &diagnostics.Operation{ID: operation.ID, State: operation.State, Revision: operation.ConfigRevision}
	}
	writeJSON(w, http.StatusOK, report)
}
