# Go-nftables-portbridge — v2.5.0

[![Release](https://img.shields.io/github/v/release/liying-official/Go-nftables-portbridge)](https://github.com/liying-official/Go-nftables-portbridge/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-informational)
![Architecture: amd64 / arm64](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-informational)

[English](README.md) | [简体中文](README.zh-CN.md)

**TCP/UDP port forwarding for Linux — manage it through an easy-to-use Web GUI or an HTTP API.**

PortBridge combines nftables/flowtable acceleration for eligible same-family traffic with a Go proxy for IPv4 ↔ IPv6 forwarding. Choose the data plane per rule, update rules without restarting the service, and inspect their runtime status from the browser.

[Download a release](https://github.com/liying-official/Go-nftables-portbridge/releases/latest) · [API reference](docs/API.en-US.md) · [Forwarding limits](docs/forwarding-limits.md) · [Report an issue](https://github.com/liying-official/Go-nftables-portbridge/issues)

## Highlights

| Capability | What you get |
|---|---|
| Web GUI and API | Create, edit, enable and delete rules; configure settings; inspect runtime state; rotate the administrator token. See the [English API reference](docs/API.en-US.md). |
| Bilingual Tabler UI | Switch English / 简体中文 in the same interface, with sky-blue cards, responsive rule tables and mobile navigation. Tabler Core and Icons are served locally. |
| TCP / UDP | Forward TCP, UDP or both; map individual ports or equal-length ranges of up to 4096 ports. |
| IPv4 and IPv6 | IPv4 → IPv4, IPv6 → IPv6, IPv4 → IPv6 and IPv6 → IPv4. |
| Two data planes | Prefer nftables DNAT/SNAT with optional flowtable acceleration, or explicitly select the Go TCP/UDP proxy. |
| DNS and monitoring | Custom DNS servers, 30-second domain-target refresh, per-rule rates, Go statistics and best-effort nft/flowtable observations; [Prometheus `/metrics`](docs/MONITORING.en-US.md). |
| Secure installation | Signed, localized amd64/arm64 release packages; no Go compiler required; HTTPS management and a dedicated systemd service account. |

The language menu is available on the sign-in page, dashboard and rule dialog. Both release languages contain the same bilingual WebUI; the package language sets its initial language and the installation/documentation language. The browser remembers only the language preference in local storage; administrator tokens remain in session storage.

**Know the boundary:** the management ACL does not protect forwarding ports. Go-proxy budgets do not automatically apply to nftables traffic. The UI combines Go payload and best-effort nft L3 cumulative counters into an approximate display total; real-time rates and API/Prometheus sources remain separate. Flowtable sampling can lag or miss short flows. Flowtable eligibility depends on kernel support and the surrounding firewall; an ineligible rule is not guaranteed to fall back to Go. See [forwarding limits](docs/forwarding-limits.md) before deploying alongside other firewall/NAT software.

## Quick start

For an interactive fresh installation, see the [one-click installer](docs/ONECLICK.en-US.md). It selects the latest stable release, asks for language and a persistent strict IP allowlist, and exposes management on local interface addresses. This differs from the loopback-only manual procedure below. Existing installations are never overwritten automatically.

The one-click installer follows GitHub's latest published stable release, not the version of a local checkout or this document. The version-pinned instructions below require the v2.5.0 release assets to be published; if they are unavailable, stop and use the documentation matching an available release. Do not substitute a source archive for a prebuilt package.

Run in an interactive **root Bash terminal** (use `sudo -i` first if necessary):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/liying-official/Go-nftables-portbridge/main/scripts/install-oneclick.sh)
```

This downloads and executes the current `main` script. Only run it if you trust this repository; download and inspect the script first if needed. A download error or no installer prompts is not a successful installation.

### 1. Prepare the server

Use a **Linux host with systemd**, an **amd64 or arm64 CPU**, and root/sudo access. The host must permit nftables and network sysctl changes; a restricted container is not a substitute for a suitable host. Bash, tar/gzip, `sha256sum`, `awk`, standard GNU/account utilities and `runuser` must be available.

On Debian/Ubuntu, install the additional dependencies once. In a root shell, omit `sudo`:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends ca-certificates curl openssh-client nftables conntrack iproute2
```

Other distributions need equivalent packages installed through their own package manager. On non-APT systems, preinstall all dependencies: the installer uses `apt-get` if nftables or conntrack is missing.

### 2. Download, verify and install

The block below installs the **English v2.5.0 prebuilt release**, selecting your CPU architecture automatically. Run the entire block on the server. Root and sudo users are both supported; **Go is not required**. For an existing installation, read [Upgrade and uninstall](#upgrade-and-uninstall) first.

```bash
bash <<'BASH'
set +x
set -euo pipefail
umask 077
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo 'Unsupported CPU architecture' >&2; exit 1 ;;
esac
NAME="portbridge-v2.5.0-linux-${ARCH}-en-US"
BASE='https://github.com/liying-official/Go-nftables-portbridge/releases/download/v2.5.0'
WORK=$(mktemp -d)
cd "$WORK"
for FILE in "$NAME.tar.gz" SHA256SUMS SHA256SUMS.sig; do
  curl -q -fL --proto '=https' --proto-redir '=https' \
    -H 'Cache-Control: no-cache' -o "$FILE" "$BASE/$FILE?release=binary-v2.5.0"
done
printf '%s\n' 'portbridge-release-v2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVc6m1afFOM3gsLO6VXuLyAlHbkvBP83wlMEqArW/0k' > release-signers
ssh-keygen -Y verify -f release-signers -I portbridge-release-v2 \
  -n portbridge-release -s SHA256SUMS.sig < SHA256SUMS
awk -v file="$NAME.tar.gz" '$2 == file { print; n++ } END { if (n != 1) exit 1 }' \
  SHA256SUMS > selected-SHA256SUMS
sha256sum -c selected-SHA256SUMS
mkdir package
tar -xzf "$NAME.tar.gz" --strip-components=1 -C package
cd package
test -x "dist/go-nftables-portbridge-linux-$ARCH"
if (( EUID == 0 )); then ./scripts/install.sh; else sudo ./scripts/install.sh; fi
test "$(/usr/local/bin/portbridge -version)" = '2.5.0'
systemctl is-active --quiet portbridge
test "$(systemctl show portbridge -p SubState --value)" = running
systemctl show portbridge -p ActiveState -p SubState -p Result -p MainPID -p NRestarts
printf 'Installed; extracted release directory: %s\n' "$PWD"
BASH
```

This verifies the signed checksum list **before extracting or running the archive**, checks the selected package hash, and invokes the bundled installer. The installer then verifies the pinned release key, internal manifest, source/script hashes, binary hash and version. Any failed check stops the flow; never bypass it.

The final commands require version `2.5.0` and an `active/running` service, and display its result, PID and restart count. The installer creates the service account, provisions HTTPS, installs/enables the systemd unit, applies forwarding sysctls and starts PortBridge. Fresh installations have **no forwarding rules**.

#### Release files and signature trust

Use the attached assets on the [v2.5.0 Release](https://github.com/liying-official/Go-nftables-portbridge/releases/tag/v2.5.0), not GitHub's automatically generated **Source code** archives.

| CPU | English package | Simplified Chinese package |
|---|---|---|
| amd64 / x86_64 | `portbridge-v2.5.0-linux-amd64-en-US.tar.gz` | `portbridge-v2.5.0-linux-amd64-zh-CN.tar.gz` |
| arm64 / aarch64 | `portbridge-v2.5.0-linux-arm64-en-US.tar.gz` | `portbridge-v2.5.0-linux-arm64-zh-CN.tar.gz` |

The release also includes `SHA256SUMS`, `SHA256SUMS.sig` and `SBOM`. The quick start downloads only your selected archive and the two checksum files. It does not need the other three packages or the SBOM to install. There is no separate per-archive `.tar.gz.sig` or `release-signers` asset in this release.

The verification block pins the public key instead of trusting a key downloaded with the archive. Confirm this fingerprint through a trusted, independent channel before first use:

```text
SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o
```

Signing identity: `portbridge-release-v2`. Signature namespace: `portbridge-release`. A signature establishes integrity and origin relative to the trusted key, not that a deployment is vulnerability-free. Version `2.5.0` is deliberately pinned; use the matching instructions and trust material when upgrading.

Do not edit files inside the verified package before installation, including its README files. Those files are covered by the internal signed manifest. Repacking or modifying a release requires regenerated manifests, checksums and publisher signatures.


### 3. Open the Web GUI

By default, management listens on **HTTPS port 9080 at `127.0.0.1` and `::1` only**. It is not exposed to the Internet. On your administrator computer, replace `USER` and `SERVER` with your SSH login and server address, then keep this tunnel running:

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:9080:127.0.0.1:9080 USER@SERVER
```

Open **https://127.0.0.1:9080/** in your browser. If the installer generated a self-signed certificate, verify its SHA-256 fingerprint from the server's installation output and establish client trust before logging in. Do not blindly bypass certificate warnings.

On the **server**, read the administrator token in a private terminal:

```bash
sudo cat /etc/portbridge/admin.token
```

Use that token to sign in. It is not printed during a normal installation. Never put it in screenshots, issue reports or deployment logs. If local port 9080 is occupied, change the first `9080` in the tunnel command and use the corresponding local browser port.

## Create your first forwarding rule

In the Web GUI, add a rule with a protocol, listen address/port, target host/port and data-plane preference. Save it, check the rule's status and any error, then test traffic from an allowed client. The data-plane column shows the configured preference, not the actual path; inspect `data_plane`, `go_running` and `kernel_state` in `GET /api/status` for runtime details.

| Forwarding direction | Data-plane behavior |
|---|---|
| IPv4 → IPv4 / IPv6 → IPv6 | Eligible traffic can use nftables; select `GO` to explicitly use the proxy. |
| IPv4 → IPv6 / IPv6 → IPv4 | Uses the Go TCP/UDP proxy. |
| Wildcard `*` listener | Plans IPv4 and IPv6 separately; may use a hybrid data plane with dedicated Go loopback handling. |

For port ranges, `10000–10009 → 20000–20009` maps ports one-to-one. The two ranges must have equal lengths, with at most 4096 ports. For private destinations, explicitly set **both** `allow_private_target=true` and a narrow `target_cidr_allowlist`; do not disable target checks broadly.

A fresh installation does not load [config.example.json](config.example.json). It contains demonstration rules and targets, not ready-to-use production defaults. Configure your own endpoints and permit only the required forwarding traffic in your host/cloud firewall.

**Validate the data path:** an `active` systemd service does not prove that a rule is forwarding. Check the Web rule status and test real TCP and, when enabled, UDP request/response traffic. A UDP port probe alone is not an end-to-end application test. Firewall conflicts can keep a rule suspended even while management is healthy.

## Configuration and API

| Item | Location / behavior |
|---|---|
| Installed executable | `/usr/local/bin/portbridge` |
| Service | `portbridge.service` |
| Live configuration | `/etc/portbridge/config.json` |
| Administrator token | `/etc/portbridge/admin.token` |
| Installer-managed TLS material | `/etc/portbridge-tls/` |
| Rule, ACL and DNS edits | Applied without a service restart. |
| Management listener, port or TLS edits | Require `sudo systemctl restart portbridge`. |

The [English API reference](docs/API.en-US.md) covers authentication, configuration, rules, settings and runtime status. Management requests require Bearer authentication; write operations additionally require CSRF handling. Follow the API documentation rather than treating the service as an unauthenticated REST endpoint.

Keep loopback-only access and the SSH tunnel unless direct management access is necessary. For public management, configure valid native TLS, an explicit strict IP allowlist and a restrictive host/cloud firewall. `--allow` is a temporary bootstrap ACL option; it does **not** change the default loopback listener. ACL decisions use the direct TCP peer, not `X-Forwarded-For`, so reverse proxies must enforce the real-client allowlist themselves. See [SECURITY.md](SECURITY.md) and [the public-management example](config.public.example.json).

### Use an existing HTTPS certificate

In the verified release directory, supply a currently valid matching certificate/key pair using absolute server-local paths:

```bash
sudo ./scripts/install.sh --tls-cert /absolute/path/fullchain.pem --tls-key /absolute/path/privkey.pem
```

For a fresh install, use these options on the installer invocation in step 2 rather than running the default installation first. Imported material is copied into the managed TLS directory; the originals are not modified. Source paths must satisfy the installer's ownership, permission and non-symlink checks. Existing valid certificates are preserved during upgrades; invalid configured material causes installation to stop.

Run `./scripts/install.sh --help` in the release directory for all options. `--no-start` prepares files and credentials without starting the service; skip the quick-start `systemctl is-active` check when intentionally using it. Avoid `--show-token` in captured logs.


## Operations and troubleshooting

```bash
systemctl show portbridge -p ActiveState -p SubState -p Result -p NRestarts
sudo journalctl -u portbridge -n 50 --no-pager
```

Expect `ActiveState=active`, `SubState=running`, and no ongoing restart loop. Inspect logs when a service or rule is unhealthy; do not disable HTTPS, erase ownership/recovery records or open the management allowlist to work around a failure. Redact tokens and operational details before sharing logs. For nftables-path inspection, use `sudo nft list table inet portbridge`. WebGUI combines cumulative Go/nft observations into an approximate total and displays their real-time rates separately; API and Prometheus preserve separate sources. See [monitoring boundaries](docs/MONITORING.en-US.md).

## Upgrade and uninstall

Before an upgrade, securely back up `/etc/portbridge/` and `/etc/portbridge-tls/`, and plan a maintenance window. Download and verify the target release, then run **that release's installer**. It preserves existing configuration and rules while enforcing HTTPS, but stops/restarts the service; upgrades are not promised to be interruption-free. Never replace your live configuration with an example file.

For uninstalling, use the script from a verified release directory:

```bash
sudo ./scripts/uninstall.sh
```

This keeps configuration. Adding `--purge` also removes configuration and the service account; use it only when those are no longer needed. `/etc/portbridge-tls/` is intentionally retained. The quick start prints its extracted package directory, which is temporary and may later be cleaned by the OS; retain a verified copy for maintenance or download and verify it again.

## Development and documentation

Use **Go 1.27.1** for the documented development and release workflow; the source installer requires this exact toolchain. The module declares Go 1.27.1 as its minimum version, and dependencies are vendored. Source checkouts and GitHub-generated Source code archives do not contain precompiled binaries. From a source checkout, run:

```bash
GOPROXY=off go test ./...
GOPROXY=off go test -race ./...
GOPROXY=off go vet ./...
make dist
```

`make dist` produces unsigned development binaries, **not installable signed Release packages**. Do not bypass the installer's signature checks to install them.

[API reference](docs/API.en-US.md) · [Forwarding limits](docs/forwarding-limits.md) · [UDP design and tuning](docs/udp-dataplane.md) · [Release notes](RELEASE_NOTES.md) · [Contributing](CONTRIBUTING.md)

## Contributing and license

Bug reports, documentation improvements and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md), and follow [SECURITY.md](SECURITY.md) for security reports. If PortBridge is useful to you, a GitHub star helps others discover the project.

Released under the [MIT License](LICENSE).
