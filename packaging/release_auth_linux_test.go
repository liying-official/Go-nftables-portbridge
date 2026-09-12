//go:build linux

package packaging

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const (
	testSignerIdentity = "portbridge-release-v2"
	testNamespace      = "portbridge-release"
)

type testReleaseManifest struct {
	BinarySHA string            `json:"binary_sha256"`
	Sources   map[string]string `json:"sources"`
}

type testReleaseBundle struct {
	root           string
	manifest       string
	signature      string
	signerFile     string
	trustedKey     string
	attackerKey    string
	trustedSigner  string
	attackerSigner string
	trustedFP      string
}

func TestReleaseAuthenticationAttackMatrix(t *testing.T) {
	tests := []struct {
		name      string
		wantValid bool
		mutate    func(*testing.T, *testReleaseBundle)
	}{
		{name: "A-valid-signer", wantValid: true},
		{name: "B-replaced-signer", mutate: func(t *testing.T, b *testReleaseBundle) {
			writeTestFile(t, b.signerFile, b.attackerSigner+"\n", 0o644)
		}},
		{name: "C-full-attacker-substitution", mutate: func(t *testing.T, b *testReleaseBundle) {
			writeTestFile(t, filepath.Join(b.root, "portbridge"), "attacker binary\n", 0o755)
			writeTestFile(t, filepath.Join(b.root, "source.go"), "package attacker\n", 0o644)
			writeTestManifest(t, b)
			signTestManifest(t, b.attackerKey, b.manifest)
			writeTestFile(t, b.signerFile, b.attackerSigner+"\n", 0o644)
		}},
		{name: "D-manifest-tamper", mutate: func(t *testing.T, b *testReleaseBundle) {
			file, err := os.OpenFile(b.manifest, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString(" \n"); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "E-binary-tamper", mutate: func(t *testing.T, b *testReleaseBundle) {
			writeTestFile(t, filepath.Join(b.root, "portbridge"), "tampered binary\n", 0o755)
		}},
		{name: "F-source-tamper", mutate: func(t *testing.T, b *testReleaseBundle) {
			writeTestFile(t, filepath.Join(b.root, "source.go"), "package tampered\n", 0o644)
		}},
		{name: "G-signer-symlink", mutate: func(t *testing.T, b *testReleaseBundle) {
			target := filepath.Join(b.root, "trusted-signer-outside")
			writeTestFile(t, target, b.trustedSigner+"\n", 0o644)
			if err := os.Remove(b.signerFile); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, b.signerFile); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "H-second-key", mutate: func(t *testing.T, b *testReleaseBundle) {
			writeTestFile(t, b.signerFile, b.trustedSigner+"\n"+b.attackerSigner+"\n", 0o644)
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bundle := newTestReleaseBundle(t)
			if tc.mutate != nil {
				tc.mutate(t, bundle)
			}
			err := verifyTestReleaseBundle(bundle)
			if tc.wantValid && err != nil {
				t.Fatalf("valid signed bundle was rejected: %v", err)
			}
			if !tc.wantValid && err == nil {
				t.Fatal("attacked bundle was accepted")
			}
		})
	}
}

func newTestReleaseBundle(t *testing.T) *testReleaseBundle {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is required for release authentication tests")
	}
	root := t.TempDir()
	bundle := &testReleaseBundle{
		root:        root,
		manifest:    filepath.Join(root, "release-bundle-manifest.json"),
		signature:   filepath.Join(root, "release-bundle-manifest.json.sig"),
		signerFile:  filepath.Join(root, "release-signers"),
		trustedKey:  filepath.Join(root, "trusted-key"),
		attackerKey: filepath.Join(root, "attacker-key"),
	}
	bundle.trustedSigner = generateTestSigner(t, bundle.trustedKey)
	bundle.attackerSigner = generateTestSigner(t, bundle.attackerKey)
	bundle.trustedFP = testSignerFingerprint(t, bundle.signerFile, bundle.trustedSigner)
	writeTestFile(t, filepath.Join(root, "portbridge"), "trusted binary\n", 0o755)
	writeTestFile(t, filepath.Join(root, "source.go"), "package trusted\n", 0o644)
	writeTestFile(t, bundle.signerFile, bundle.trustedSigner+"\n", 0o644)
	writeTestManifest(t, bundle)
	signTestManifest(t, bundle.trustedKey, bundle.manifest)
	return bundle
}

func generateTestSigner(t *testing.T, privateKey string) string {
	t.Helper()
	command := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", privateKey)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("generate test signer: %v: %s", err, output)
	}
	command = exec.Command("ssh-keygen", "-y", "-f", privateKey)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("read test public key: %v", err)
	}
	return testSignerIdentity + " " + strings.TrimSpace(string(output))
}

func testSignerFingerprint(t *testing.T, signerPath, signer string) string {
	t.Helper()
	writeTestFile(t, signerPath, signer+"\n", 0o644)
	output, err := exec.Command("ssh-keygen", "-lf", signerPath, "-E", "sha256").Output()
	if err != nil {
		t.Fatalf("fingerprint test signer: %v", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) < 2 {
		t.Fatalf("unexpected ssh-keygen fingerprint output: %q", output)
	}
	return fields[1]
}

func writeTestManifest(t *testing.T, bundle *testReleaseBundle) {
	t.Helper()
	manifest := testReleaseManifest{
		BinarySHA: testFileSHA256(t, filepath.Join(bundle.root, "portbridge")),
		Sources:   map[string]string{"source.go": testFileSHA256(t, filepath.Join(bundle.root, "source.go"))},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, bundle.manifest, string(data)+"\n", 0o644)
}

func signTestManifest(t *testing.T, privateKey, manifest string) {
	t.Helper()
	_ = os.Remove(manifest + ".sig")
	command := exec.Command("ssh-keygen", "-Y", "sign", "-q", "-f", privateKey, "-n", testNamespace, manifest)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("sign test manifest: %v: %s", err, output)
	}
}

func verifyTestReleaseBundle(bundle *testReleaseBundle) error {
	info, err := os.Lstat(bundle.signerFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("signer is not a regular non-symlink file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Nlink != 1 {
		return fmt.Errorf("signer has unexpected hard links")
	}
	signerData, err := os.ReadFile(bundle.signerFile)
	if err != nil {
		return err
	}
	if string(signerData) != bundle.trustedSigner+"\n" && string(signerData) != bundle.trustedSigner {
		return fmt.Errorf("signer does not match pinned public key")
	}
	output, err := exec.Command("ssh-keygen", "-lf", bundle.signerFile, "-E", "sha256").Output()
	if err != nil || len(strings.Fields(string(output))) < 2 || strings.Fields(string(output))[1] != bundle.trustedFP {
		return fmt.Errorf("signer fingerprint mismatch")
	}
	manifest, err := os.Open(bundle.manifest)
	if err != nil {
		return err
	}
	verify := exec.Command("ssh-keygen", "-Y", "verify", "-q", "-f", bundle.signerFile, "-I", testSignerIdentity, "-n", testNamespace, "-s", bundle.signature)
	verify.Stdin = manifest
	err = verify.Run()
	_ = manifest.Close()
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	data, err := os.ReadFile(bundle.manifest)
	if err != nil {
		return err
	}
	var signed testReleaseManifest
	if err := json.Unmarshal(data, &signed); err != nil {
		return err
	}
	if testFileSHA256Raw(filepath.Join(bundle.root, "portbridge")) != signed.BinarySHA {
		return fmt.Errorf("binary hash mismatch")
	}
	for path, expected := range signed.Sources {
		if testFileSHA256Raw(filepath.Join(bundle.root, path)) != expected {
			return fmt.Errorf("source hash mismatch: %s", path)
		}
	}
	return nil
}

func testFileSHA256(t *testing.T, path string) string {
	t.Helper()
	result := testFileSHA256Raw(path)
	if result == "" {
		t.Fatalf("hash test file %s", path)
	}
	return result
}

func testFileSHA256Raw(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}
