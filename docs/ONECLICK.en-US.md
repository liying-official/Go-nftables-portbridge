# Interactive fresh installation — v2.5.0

[Back to README](../README.md) · [简体中文](ONECLICK.zh-CN.md) · [Pinned release installation](INSTALL.en-US.md)

`scripts/install-oneclick.sh` supports fresh Debian/Ubuntu installations on amd64 and arm64. It selects the latest published stable GitHub Release, not the version of a local checkout. No Go compiler is needed. A normal installation requires root, an interactive terminal and a running systemd host.

## Obtain and inspect the installer

From a trusted source checkout, inspect the script before running it:

```bash
# Run from the repository root. This is an interactive, system-changing install.
sudo bash scripts/install-oneclick.sh
```

To inspect a standalone copy obtained from the repository's current `main` branch:

```bash
set -euo pipefail
umask 077
PB_INSTALLER=$(mktemp)
curl --proto '=https' --tlsv1.2 -fSL \
  https://raw.githubusercontent.com/liying-official/Go-nftables-portbridge/main/scripts/install-oneclick.sh \
  -o "$PB_INSTALLER"
printf 'Inspect the downloaded script before execution: %s\n' "$PB_INSTALLER"
```

Review that file first; then run `sudo bash "$PB_INSTALLER"` in the same shell only after trusting its contents. This bootstrap script is obtained over HTTPS from `main`; its release-payload signature checks do not independently authenticate the bootstrap script itself. Do not edit scripts inside a signed package or bypass a verification failure. Remove the standalone temporary file when no longer needed.

## What changes during installation

The initial English menu selects `1` for English or `2` for Simplified Chinese. The installer checks the platform, prepares dependencies, prompts for a persistent IP/CIDR allowlist and an available HTTPS port (default `9080`), and obtains confirmation before package installation. **Dependency installation can happen before the final confirmation**, so cancellation does not mean the host was unchanged.

Allowlist entries are separated by commas/spaces. Empty lists, `/0`, multicast, scoped addresses and IPv4-mapped IPv6 are rejected. Release verification checks the pinned Ed25519 key, signed outer checksums, archive hash, signed internal manifest, covered source/script hashes and binary identity. It then uses the verified installer with `--no-start`, prepares a unique ten-year self-signed certificate, persists strict allowlisting, disables automatic LAN discovery/plaintext HTTP, and starts the service.

Management binds to `0.0.0.0` and also `::` when IPv6 is enabled, with the strict allowlist enforced; loopback remains available for recovery. This is **not** the manual installer's loopback-only default. The installer does not configure host/cloud firewall rules or discover your public address. The underlying installer changes forwarding sysctls; the application can manage its owned nftables table when applying forwarding rules. Listed URLs use suitable interface addresses, not a public-reachability probe.

The final local checks inspect service stability, a certificate-validated loopback HTTPS connection, administrator authentication and the persisted strict/whitelist configuration. **They do not prove that an allowed external client can connect, that a disallowed external source is blocked, or that a forwarding rule carries traffic.** Verify those separately from appropriate owned clients after installation.

The success screen includes the certificate SHA-256, interface URLs and **the plaintext administrator token**. Do not record or publish that output. Verify the fingerprint before trusting a self-signed certificate. Both localized v2.5.0 packages include the same bilingual Web UI; the package only selects its initial language.

## Existing installations and failures

Existing configuration, TLS directories, the installed executable or service cause the script to refuse overwriting. For upgrades, use [the verified release procedure](INSTALL.en-US.md). Failures do not perform destructive rollback and can leave files, dependencies or service state behind. Inspect the private diagnostic log locally and sanitize it before sharing. Do not erase ownership/recovery records to bypass an error.

## Non-installing validation

```bash
bash scripts/install-oneclick.sh --check
```

This still requires interactive selections and preinstalled curl, Python 3, OpenSSH `ssh-keygen`, iproute2, tar/gzip and coreutils. It uses network access and temporary files, downloads/verifies the current Release and **executes the verified binary with `-version`**. It does not install dependencies, modify installed configuration/services or read the existing administrator token. It is not a zero-execution, offline or end-to-end installation test. An unavailable Release or missing prerequisite is a blocker, not a reason to weaken verification.
