# Interactive one-click installation — v2.5.0

English | [简体中文](ONECLICK.zh-CN.md)

Use `scripts/install-oneclick.sh` on Debian/Ubuntu, amd64/arm64. It downloads the latest stable GitHub Release's prebuilt package for the selected language and detected architecture; no Go compiler is needed. Obtain and review this script from a trusted source first. Do not modify files inside a verified, signed release package.

```bash
sudo bash scripts/install-oneclick.sh
```

An interactive terminal is required. Before selection, prompts are English only: `1` selects English, `2` Simplified Chinese. Subsequent prompts use the selected language. The path above refers to a source checkout containing this script; the script can also be copied and run independently with Bash.

For v2.5.0 packages, the selected package sets the initial WebUI language; every package includes both English and Simplified Chinese, switchable from the WebUI language menu without reinstalling. The script selects the latest published stable release, not the local checkout version, and does not publish releases. Check the selected version before confirming; the matching release's documentation describes its UI and capabilities.

## Installation flow

1. Select a language; detect OS and CPU architecture.
2. Prepare dependencies and enter client IP/CIDR allowlist entries separated by commas or spaces. Empty lists, `/0`, multicast, scoped addresses and IPv4-mapped IPv6 are rejected.
3. Enter the HTTPS management port, default `9080`; occupied ports require another choice.
4. Download the latest stable prebuilt package. Verify the pinned Ed25519 signature, archive hash, internal signed manifest and source/script/binary hashes. A publisher key rotation requires a script update, never a verification bypass or dynamic trust in an unknown downloaded key.
5. After confirmation, install with `--no-start` and generate a ten-year self-signed certificate. Before starting the service, persist strict IP allowlisting and disable automatic LAN discovery and plaintext HTTP.
6. Verify stable service state, trusted HTTPS, administrator authentication and effective allowlisting. On success, show the certificate SHA-256, management URLs for usable interface addresses and the administrator token.

Management listens on `0.0.0.0` and also `::` when IPv6 is available, restricted by the strict allowlist; loopback recovery remains allowed. This differs from the original installer's loopback-only default. The management allowlist is not an ACL for forwarding ports. The script does not modify host/cloud firewalls or NAT, and listed addresses are not public-IP discovery results. IPv6 URLs use brackets; loopback, link-local, tentative and deprecated addresses are omitted from the displayed management URLs.

Browsers do not automatically trust self-signed certificates. Independently verify the fingerprint before establishing trust. Later, configure valid certificate paths in management settings and restart; recheck certificate SANs after interface/IP changes. Do not record or publish terminal output containing the administrator token.

## Existing installations and failure handling

This script is for fresh installation only. Existing configuration, TLS directories, executable or service cause a refusal to overwrite; upgrades use the README procedure instead. Failures do not trigger destructive rollback and may leave installed files. Inspect the private diagnostic log and service state; do not erase ownership/recovery records to bypass failures.

## Minimal validation

```bash
bash scripts/install-oneclick.sh --check
```

Select language, allowlist and an unused port; the script downloads/verifies the current Release and lists planned URLs, without installing dependencies, changing services/configuration or reading existing administrator tokens. Requires curl, Python 3, OpenSSH ssh-keygen, iproute2, tar/gzip and coreutils already installed. Safe for non-overwriting checks on an existing instance.
