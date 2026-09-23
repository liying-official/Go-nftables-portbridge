package packaging

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestArchitectureSpecificBundleMetadataMatchesOneclick(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("one-click runtime validation requires Linux")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		for _, language := range []string{"en-US", "zh-CN"} {
			t.Run(arch+"-"+language, func(t *testing.T) {
				root := t.TempDir()
				if err := os.Mkdir(filepath.Join(root, "dist"), 0755); err != nil {
					t.Fatal(err)
				}
				header := make([]byte, 20)
				copy(header, []byte{0x7f, 'E', 'L', 'F', 2, 1})
				header[18] = 62
				if arch == "arm64" {
					header[18] = 183
				}
				if err := os.WriteFile(filepath.Join(root, "dist", "go-nftables-portbridge-linux-"+arch), header, 0755); err != nil {
					t.Fatal(err)
				}
				var listing strings.Builder
				for _, item := range []struct{ name, value string }{{"VERSION", "2.5.0\n"}, {"PACKAGE_LANGUAGE", language + "\n"}} {
					if err := os.WriteFile(filepath.Join(root, item.name), []byte(item.value), 0644); err != nil {
						t.Fatal(err)
					}
					hash := sha256.Sum256([]byte(item.value))
					listing.WriteString(hex.EncodeToString(hash[:]) + "  ./" + item.name + "\n")
				}
				if err := os.WriteFile(filepath.Join(root, "source-tree.sha256"), []byte(listing.String()), 0644); err != nil {
					t.Fatal(err)
				}
				args := []string{"../scripts/release-metadata.py", "bundle", root, "2.5.0", strings.Repeat("a", 40), "go1.27.1", "--arch", arch, "--language", language}
				if out, err := exec.Command("python3", args...).CombinedOutput(); err != nil {
					t.Fatalf("metadata: %v: %s", err, out)
				}
				if out, err := oneclickHelper(t, "bundle", root, "2.5.0", arch); err != nil {
					t.Fatalf("one-click rejected matching bundle: %v: %s", err, out)
				}
				data, err := os.ReadFile(filepath.Join(root, "release-bundle-manifest.json"))
				if err != nil {
					t.Fatal(err)
				}
				var manifest struct {
					Binaries     map[string]string `json:"binaries"`
					WebLanguages []string          `json:"web_languages"`
				}
				if err := json.Unmarshal(data, &manifest); err != nil || len(manifest.Binaries) != 1 || len(manifest.WebLanguages) != 2 {
					t.Fatalf("unexpected architecture/language manifest: %s", data)
				}
				if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("tampered\n"), 0644); err != nil {
					t.Fatal(err)
				}
				if out, err := oneclickHelper(t, "bundle", root, "2.5.0", arch); err == nil {
					t.Fatalf("one-click accepted changed bundle: %s", out)
				}
			})
		}
	}
}

func TestReleaseOutputNamesMatchBootstrapContract(t *testing.T) {
	data, err := os.ReadFile("../scripts/package-release.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{"portbridge-v${VERSION}-linux-${arch}-${language}", "OUTPUTS=(SHA256SUMS SHA256SUMS.sig SBOM)", "release-metadata.py", "web-dependencies.json"} {
		if required == "web-dependencies.json" {
			if _, err := os.Stat(required); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if !strings.Contains(source, required) {
			t.Fatalf("release packager is missing %q", required)
		}
	}
}
