package diagnostics

import "portbridge/internal/config"

type Environment struct {
	Context             string    `json:"context"`
	OS                  string    `json:"os"`
	NetAdmin            string    `json:"cap_net_admin"`
	BindService         string    `json:"cap_net_bind_service"`
	NFTTool             bool      `json:"trusted_nft_available"`
	ConntrackTool       bool      `json:"trusted_conntrack_available"`
	ConntrackAccounting string    `json:"conntrack_accounting"`
	Findings            []Finding `json:"findings"`
}

func needsNFT(cfg config.Config) bool {
	for _, rule := range cfg.Rules {
		if rule.Enabled && rule.DataPlane != config.RuleDataPlaneGo {
			return true
		}
	}
	return false
}
