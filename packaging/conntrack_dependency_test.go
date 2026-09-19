package packaging

import (
	"os"
	"strings"
	"testing"
)

func TestInstallersIncludeExactRevocationDependency(t *testing.T) {
	for _, name := range []string{"install.sh", "install.en.sh", "install.zh-CN.sh"} {
		data, err := os.ReadFile("../scripts/" + name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.Contains(text, "|| ! command -v conntrack") || !strings.Contains(text, "--no-install-recommends nftables conntrack") {
			t.Fatalf("%s misses conntrack dependency detection/install", name)
		}
		if strings.Index(text, "ssh-keygen -Y verify") >= strings.Index(text, "apt-get update") {
			t.Fatalf("%s installs packages before prebuilt signature checks", name)
		}
	}
}
