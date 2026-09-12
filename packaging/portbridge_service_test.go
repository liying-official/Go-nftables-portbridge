package packaging

import (
	"os"
	"strings"
	"testing"
)

func TestServiceSecurityHardening(t *testing.T) {
	data, err := os.ReadFile("portbridge.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(data)
	for _, directive := range []string{
		"User=portbridge",
		"Group=portbridge",
		"ExecStopPost=/usr/local/bin/portbridge --cleanup-nft",
		"LimitNOFILE=262144",
		"TasksMax=16384",
		"MemoryMax=2G",
		"MemoryHigh=1536M",
		"CPUQuota=800%",
		"ReadOnlyPaths=/etc/portbridge-tls",
		"LimitCORE=0",
		"UMask=0077",
		"RemoveIPC=true",
		"NoNewPrivileges=true",
		"PrivateTmp=true",
		"PrivateDevices=true",
		"ProtectSystem=strict",
		"MemoryDenyWriteExecute=true",
		"SystemCallFilter=~@clock",
		"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN",
	} {
		if !strings.Contains(unit, directive) {
			t.Errorf("systemd unit is missing %q", directive)
		}
	}
}
