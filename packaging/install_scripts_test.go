package packaging

import (
	"os"
	"strings"
	"testing"
)

func TestInstallersNormalizeValidatedStateFiles(t *testing.T) {
	for _, path := range []string{"../scripts/install.sh", "../scripts/install.en.sh"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			for _, required := range []string{
				"validate_state_file",
				`stat -c %h "$state_file"`,
				`--config=/etc/portbridge/config.json --cleanup-nft`,
				`chown --no-dereference portbridge:portbridge "$STATE_FILE"`,
				`chmod 0600 "$STATE_FILE"`,
			} {
				if !strings.Contains(script, required) {
					t.Errorf("installer is missing %q", required)
				}
			}
		})
	}
}

func TestInstallersPinReleaseSignerBeforeSystemMutation(t *testing.T) {
	const (
		signer      = "portbridge-release-v2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVc6m1afFOM3gsLO6VXuLyAlHbkvBP83wlMEqArW/0k"
		fingerprint = "SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o"
	)
	for _, path := range []string{"../scripts/install.sh", "../scripts/install.en.sh"} {
		t.Run(path, func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			script := string(data)
			for _, required := range []string{
				signer, fingerprint, `-L "$SIGNERS"`, `stat -c %F -- "$SIGNERS"`,
				`stat -c %h -- "$SIGNERS"`, `stat -c %s -- "$SIGNERS"`, `mapfile -t RELEASE_SIGNER_LINES`,
				`${#RELEASE_SIGNER_LINES[@]} -ne 1`, `ssh-keygen -lf "$SIGNERS" -E sha256`,
				`ssh-keygen -Y verify -q -f "$SIGNERS" -I portbridge-release-v2 -n portbridge-release`,
			} {
				if !strings.Contains(script, required) {
					t.Errorf("installer is missing release-authentication guard %q", required)
				}
			}
			verifyAt := strings.Index(script, `ssh-keygen -Y verify`)
			mutationAt := strings.Index(script, `apt-get update`)
			if verifyAt < 0 || mutationAt < 0 || verifyAt >= mutationAt {
				t.Error("release authenticity must be verified before persistent system mutation")
			}
		})
	}
}

func TestInstallersProvisionHTTPSBeforeFirstStart(t *testing.T) {
	for _, path := range []string{"../scripts/install.sh", "../scripts/install.en.sh"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		script := string(data)
		prepare, start := strings.Index(script, "HTTPS_ARGS=(--prepare-https"), strings.Index(script, "systemctl restart portbridge.service")
		if prepare < 0 || start < prepare || !strings.Contains(script, "runuser -u portbridge -- /usr/local/bin/portbridge --https-info") {
			t.Fatalf("%s can start before preparing readable HTTPS material", path)
		}
		if strings.Contains(script, "http://127.0.0.1") {
			t.Fatalf("%s advertises plaintext management", path)
		}
		preflight, stop := strings.Index(script, "TLS_PREFLIGHT=(--check-https)"), strings.Index(script, "systemctl stop portbridge.service")
		if preflight < 0 || preflight > stop {
			t.Fatalf("%s checks supplied TLS after stopping service", path)
		}
	}
	unit, err := os.ReadFile("portbridge.service")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "--require-https") {
		t.Fatal("systemd service does not require HTTPS")
	}
}
