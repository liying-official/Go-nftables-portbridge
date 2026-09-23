package packaging

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func oneclickHelper(t *testing.T, args ...string) ([]byte, error) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("bootstrap helper tests require Linux")
	}
	for _, name := range []string{"bash", "python3"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(name + " unavailable")
		}
	}
	script, err := filepath.Abs("../scripts/install-oneclick.sh")
	if err != nil {
		t.Fatal(err)
	}
	command := []string{"-c", `source "$1"; shift; pb_python "$@"`, "test", script}
	return exec.Command("bash", append(command, args...)...).CombinedOutput()
}

func TestOneclickAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
	}{
		{"ipv4", "192.0.2.10", `["192.0.2.10/32"]`},
		{"normalize", "192.0.2.11/24, 192.0.2.0/24", `["192.0.2.0/24"]`},
		{"ipv6", "2001:db8::1", `["2001:db8::1/128"]`},
		{"empty", "", ""},
		{"any4", "0.0.0.0/0", ""},
		{"any6", "::/0", ""},
		{"mapped", "::ffff:192.0.2.10", ""},
		{"multicast", "224.0.0.1", ""},
		{"scoped", "fe80::1%eth0", ""},
		{"injection", "192.0.2.1;echo BAD", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := oneclickHelper(t, "whitelist", tc.input)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("unsafe input accepted: %s", out)
				}
				return
			}
			if err != nil || strings.TrimSpace(string(out)) != tc.want {
				t.Fatalf("got %s, %v", out, err)
			}
		})
	}
}

func TestOneclickLatestAssetSelection(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for _, lang := range []string{"en-US", "zh-CN"} {
			t.Run(arch+"-"+lang, func(t *testing.T) {
				name := "portbridge-v2.5.0-linux-" + arch + "-" + lang
				assets := []map[string]string{}
				for _, file := range []string{name + ".tar.gz", "SHA256SUMS", "SHA256SUMS.sig"} {
					assets = append(assets, map[string]string{"name": file, "state": "uploaded", "browser_download_url": "https://github.com/liying-official/Go-nftables-portbridge/releases/download/v2.5.0/" + file})
				}
				data, _ := json.Marshal(map[string]any{"tag_name": "v2.5.0", "draft": false, "prerelease": false, "assets": assets})
				file := filepath.Join(t.TempDir(), "release.json")
				if err := os.WriteFile(file, data, 0600); err != nil {
					t.Fatal(err)
				}
				out, err := oneclickHelper(t, "release", file, arch, lang)
				if err != nil || strings.TrimSpace(string(out)) != "v2.5.0\n"+name {
					t.Fatalf("unexpected selection: %s, %v", out, err)
				}
				assets[0]["browser_download_url"] = "https://example.invalid/package"
				data, _ = json.Marshal(map[string]any{"tag_name": "v2.5.0", "assets": assets})
				if err := os.WriteFile(file, data, 0600); err != nil {
					t.Fatal(err)
				}
				if out, err := oneclickHelper(t, "release", file, arch, lang); err == nil {
					t.Fatalf("foreign asset URL accepted: %s", out)
				}
			})
		}
	}
}

func TestOneclickManagementURLsExcludeLoopback(t *testing.T) {
	data := `[{"flags":["UP","LOOPBACK"],"addr_info":[{"local":"127.0.0.1"},{"local":"127.0.0.2"},{"local":"::1"}]},{"flags":["UP"],"addr_info":[{"local":"192.0.2.10"},{"local":"2001:db8::10"},{"local":"fe80::1"}]}]`
	file := filepath.Join(t.TempDir(), "addresses.json")
	if err := os.WriteFile(file, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, ipv6, want string
	}{
		{"dual-stack", "yes", `["192.0.2.10", "2001:db8::10"]`},
		{"ipv4-only", "no", `["192.0.2.10"]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := oneclickHelper(t, "addresses", file, tc.ipv6)
			if err != nil || strings.TrimSpace(string(out)) != tc.want {
				t.Fatalf("unexpected displayed addresses: %s, %v", out, err)
			}
		})
	}
	out, err := oneclickHelper(t, "urls", `["127.0.0.1","127.0.0.2","::1","::ffff:127.0.0.1","192.0.2.10","2001:db8::10"]`, "9080")
	want := "https://192.0.2.10:9080/\nhttps://[2001:db8::10]:9080/"
	if err != nil || strings.TrimSpace(string(out)) != want {
		t.Fatalf("unexpected management URLs: %s, %v", out, err)
	}
	out, err = oneclickHelper(t, "urls", `["127.0.0.1","::1"]`, "9080")
	if err != nil || strings.TrimSpace(string(out)) != "" {
		t.Fatalf("loopback-only input should not produce URLs: %s, %v", out, err)
	}
}
