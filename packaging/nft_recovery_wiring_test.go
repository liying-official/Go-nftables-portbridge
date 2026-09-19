package packaging

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestIndependentNFTRecoveryPreservesServiceBoundary(t *testing.T) {
	data, err := os.ReadFile("portbridge.service")
	if err != nil {
		t.Fatal(err)
	}
	unit := string(data)
	for _, required := range []string{"User=portbridge", "Group=portbridge", "ProtectSystem=strict", "ProcSubset=pid", "ProtectKernelTunables=true", "ReadWritePaths=/etc/portbridge", "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN", "BindReadOnlyPaths=/proc/sys/kernel/random/boot_id:/run/portbridge-boot-id", "ExecStopPost=/usr/local/bin/portbridge --cleanup-nft --config=/etc/portbridge/config.json $PORTBRIDGE_ARGS"} {
		if !strings.Contains(unit, required) {
			t.Fatalf("missing required recovery/sandbox wiring: %s", required)
		}
	}
	for _, forbidden := range []string{"User=root", "CAP_SYS_ADMIN", "ReadWritePaths=/etc\n", "ReadWritePaths=/var\n", "ProtectSystem=false"} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("recovery widened service privileges: %s", forbidden)
		}
	}
	data, err = os.ReadFile("../cmd/portbridge/main.go")
	if err != nil {
		t.Fatal(err)
	}
	main := string(data)
	for _, required := range []string{"CleanupNFTWithConfigPath(logger, cfgPath, nftConfig)", "proxyManager.SetNFTStateConfigPath(cfgPath)"} {
		if !strings.Contains(main, required) {
			t.Fatal("main and cleanup do not share the actual config identity")
		}
	}
	for _, name := range []string{"install.sh", "install.en.sh", "install.zh-CN.sh"} {
		data, err = os.ReadFile("../scripts/" + name)
		if err != nil {
			t.Fatal(err)
		}
		s := string(data)
		guard := regexp.MustCompile(`\[\[ \$OLD_UNIT_STOP_OK == true \]\] \|\| \{ echo "[^"\n]+" >&2; exit 1; \}`)
		if !strings.Contains(s, "config.json.nft-state.json") || !guard.MatchString(s) {
			t.Fatalf("%s permits unverified root fallback over service-bound recovery", name)
		}
	}
}
