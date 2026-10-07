package packaging

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestCompactBinaryPackage(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 required for package projection")
	}
	for _, language := range []string{"en-US", "zh-CN"} {
		t.Run(language, func(t *testing.T) {
			work := t.TempDir()
			source, bundle, goRoot := filepath.Join(work, "source"), filepath.Join(work, "bundle"), filepath.Join(work, "go")
			inputs := []string{
				"README.md", "README.zh-CN.md", "RELEASE_NOTES.md", "RELEASE_NOTES.zh-CN.md",
				"CONTRIBUTING.md", "VENDOR_PATCHES.md", "SECURITY.md", "LICENSE", "VERSION",
				"docs/udp-dataplane.md", "docs/forwarding-limits.md", "packaging/scripts-zh.json",
				"packaging/portbridge.service", "packaging/90-portbridge.conf", "packaging/release-signers",
				"internal/web/static/index.html", "internal/web/static/i18n.js", "internal/web/static/vendor/LICENSES.txt",
				"vendor/golang.org/x/net/LICENSE", "vendor/golang.org/x/net/PATENTS",
				"vendor/golang.org/x/sys/LICENSE", "vendor/golang.org/x/sys/PATENTS",
			}
			for _, guide := range []string{"INSTALL", "ONECLICK", "API", "MONITORING", "DIAGNOSTICS"} {
				inputs = append(inputs, "docs/"+guide+"."+language+".md")
			}
			for _, script := range []string{"install.en.sh", "install.zh-CN.sh", "uninstall.en.sh", "uninstall.zh-CN.sh", "package-release.sh", "verify-candidate.sh", "test-clean-go-netns.sh", "test-recovery-proc-subset.sh", "test-recovery-boot-bind.sh"} {
				inputs = append(inputs, "scripts/"+script)
			}
			for _, name := range inputs {
				data, err := os.ReadFile(filepath.Join("..", name))
				if err != nil {
					t.Fatal(err)
				}
				writePackageFixture(t, filepath.Join(source, name), data)
			}
			for _, notice := range []string{"LICENSE", "PATENTS"} {
				writePackageFixture(t, filepath.Join(goRoot, notice), []byte("Go original notice\n"))
			}
			if out, err := exec.Command(python, "../scripts/localize-package.py", source, language).CombinedOutput(); err != nil {
				t.Fatalf("localize: %v: %s", err, out)
			}
			guiBefore, _ := os.ReadFile(filepath.Join(source, "internal/web/static/index.html"))
			if out, err := exec.Command(python, "../scripts/assemble-binary-package.py", source, bundle, language, "--go-root", goRoot).CombinedOutput(); err != nil {
				t.Fatalf("assemble: %v: %s", err, out)
			}
			guiAfter, _ := os.ReadFile(filepath.Join(source, "internal/web/static/index.html"))
			if !bytes.Equal(guiBefore, guiAfter) || !strings.Contains(string(guiAfter), `data-default-language="`+language+`"`) {
				t.Fatal("package projection changed the localized bilingual GUI")
			}
			files := make(map[string]bool)
			if err := filepath.WalkDir(bundle, func(path string, entry os.DirEntry, err error) error {
				if err != nil || entry.IsDir() {
					return err
				}
				relative, err := filepath.Rel(bundle, path)
				if err != nil {
					return err
				}
				files[filepath.ToSlash(relative)] = true
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if len(files) != 26 {
				t.Fatalf("unexpected runtime package file count: %d", len(files))
			}
			for _, name := range []string{"README.md", "scripts/install.sh", "scripts/uninstall.sh", "packaging/release-signers", "packaging/portbridge.service", "packaging/90-portbridge.conf", "docs/API." + language + ".md", "docs/INDEX.md", "licenses/INDEX.md", "licenses/WEB.txt", "licenses/GO-LICENSE", "licenses/GO-PATENTS", "licenses/X-NET-LICENSE", "licenses/X-NET-PATENTS", "licenses/X-SYS-LICENSE", "licenses/X-SYS-PATENTS"} {
				if !files[name] {
					t.Errorf("missing runtime package file: %s", name)
				}
			}
			foreign := "zh-CN"
			if language == "zh-CN" {
				foreign = "en-US"
			}
			links := regexp.MustCompile(`\]\(([^)]+)\)|href="([^"]+)"`)
			for name := range files {
				if !strings.HasSuffix(name, ".md") {
					continue
				}
				if strings.Contains(name, foreign) || name == "README.zh-CN.md" || name == "README.en-US.md" {
					t.Errorf("unwanted document translation: %s", name)
				}
				data, _ := os.ReadFile(filepath.Join(bundle, name))
				if strings.Contains(string(data), "liying-official.github.io") {
					t.Errorf("static demo content retained in %s", name)
				}
				for _, match := range links.FindAllStringSubmatch(string(data), -1) {
					link := match[1] + match[2]
					if strings.Contains(link, ":") || strings.HasPrefix(link, "#") {
						continue
					}
					path := strings.SplitN(link, "#", 2)[0]
					target := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(name), path)))
					if !files[target] {
						t.Errorf("broken package link in %s: %s", name, link)
					}
				}
			}
			if out, err := exec.Command(python, "../scripts/assemble-binary-package.py", source, bundle, language, "--go-root", goRoot).CombinedOutput(); err == nil {
				t.Fatalf("assembler overwrote an existing bundle: %s", out)
			}
		})
	}
}

func writePackageFixture(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}
