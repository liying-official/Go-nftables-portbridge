//go:build linux

package diagnostics

import (
	"os"
	"strconv"
	"strings"

	"portbridge/internal/config"
	"portbridge/internal/proxy"
)

func InspectEnvironment(cfg config.Config, processContext string) Environment {
	nft, conntrack := proxy.DiagnosticNFTDependencies()
	env := Environment{Context: processContext, OS: "linux", NetAdmin: "unknown", BindService: "unknown",
		NFTTool: nft, ConntrackTool: conntrack, ConntrackAccounting: "unknown", Findings: []Finding{}}
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				if caps, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64); err == nil {
					env.NetAdmin, env.BindService = "absent", "absent"
					if caps&(1<<12) != 0 {
						env.NetAdmin = "present"
					}
					if caps&(1<<10) != 0 {
						env.BindService = "present"
					}
				}
			}
		}
	}
	if data, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_acct"); err == nil {
		switch strings.TrimSpace(string(data)) {
		case "0":
			env.ConntrackAccounting = "disabled"
		case "1":
			env.ConntrackAccounting = "enabled"
		}
	}
	if needsNFT(cfg) && env.NetAdmin == "absent" {
		env.Findings = append(env.Findings, Note("permission_denied", "warning"))
	}
	if needsNFT(cfg) && (!nft || !conntrack) {
		env.Findings = append(env.Findings, Note("dependency_missing", "warning"))
	}
	if env.NetAdmin == "unknown" || env.ConntrackAccounting == "unknown" {
		env.Findings = append(env.Findings, Note("environment_unavailable", "info"))
	}
	return env
}
