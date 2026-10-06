//go:build !linux

package diagnostics

import (
	"portbridge/internal/config"
	"runtime"
)

func InspectEnvironment(_ config.Config, processContext string) Environment {
	return Environment{Context: processContext, OS: runtime.GOOS, NetAdmin: "unknown", BindService: "unknown", ConntrackAccounting: "unknown", Findings: []Finding{Note("environment_unavailable", "info")}}
}
