<h1 align="center">PortBridge</h1>

<p align="center">
  <strong>One interface for TCP/UDP port forwarding across IPv4 and IPv6.</strong>
</p>

<p align="center">
  <a href="https://github.com/liying-official/Go-nftables-portbridge/releases"><img src="https://img.shields.io/github/v/release/liying-official/Go-nftables-portbridge" alt="GitHub Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/platform-Linux-informational" alt="Platform: Linux">
  <img src="https://img.shields.io/badge/arch-amd64%20%7C%20arm64-informational" alt="Architecture: amd64 / arm64">
</p>

<p align="center">
  <strong>English</strong> · <a href="README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <a href="docs/INSTALL.en-US.md">Get started</a> ·
  <a href="docs/API.en-US.md">API reference</a> ·
  <a href="docs/INDEX.md">Documentation</a> ·
  <a href="https://github.com/liying-official/Go-nftables-portbridge/releases">Download</a>
</p>

**PortBridge is a self-hosted port-forwarding manager for Linux.** It combines **nftables kernel forwarding** with a **Go TCP/UDP proxy**, offering an English/Chinese Web UI and an authenticated API for port mapping, service forwarding and connections across IPv4/IPv6 networks.

Create rules, adjust settings and inspect runtime state in your browser, without hand-writing nftables commands for everyday rule management.

## Why PortBridge?

| Feature | What it gives you |
| --- | --- |
| **nftables + Go** | nftables for eligible same-family traffic, optional software flowtable acceleration, and a Go proxy for cross-family forwarding. Explicit Go mode is also available per rule. |
| **IPv4 / IPv6 in both directions** | IPv4 → IPv4, IPv6 → IPv6, IPv4 → IPv6 and IPv6 → IPv4, managed from the same interface. |
| **Flexible port mapping** | TCP, UDP or both; single ports and equal-length port ranges covering up to 4096 ports. |
| **Bilingual Web management** | Create, edit, enable, disable and delete rules, manage settings and rotate the administrator token. UI assets ship with the application, with no external CDN dependency. |
| **Status, monitoring and automation** | Inspect runtime state and traffic observations, manage rules through an authenticated API, and integrate authenticated Prometheus metrics with your monitoring stack. |
| **Built-in management controls** | Native HTTPS, administrator tokens, IP/CIDR allowlisting and CSRF checks for API writes. |

## Install

Use a **Linux amd64 / arm64** host with **systemd**, **root/sudo** access and the required networking permissions. Prebuilt release packages **do not require Go**.

| Installation guide | When to use it | Management access |
| --- | --- | --- |
| **[Release installation and upgrades](docs/INSTALL.en-US.md)** | Install the version pinned in the guide, or upgrade an existing deployment. | Loopback-only HTTPS by default, suitable for management through an SSH tunnel. |
| **[Interactive fresh installation](docs/ONECLICK.en-US.md)** | Set up a fresh Debian/Ubuntu host with prompts for language, HTTPS port and management allowlist. | Externally bound HTTPS with a strict IP allowlist. |

Use the prebuilt asset for your architecture from [Releases](https://github.com/liying-official/Go-nftables-portbridge/releases). Follow the guide to **verify signatures before installation**; GitHub's automatically generated **Source code** archives are not installation packages. The guides cover commands, sign-in, certificate setup and uninstalling.

After installation: **add a forwarding rule → inspect its runtime state → verify that the target service is reachable**. Fresh installations contain no forwarding rules.

> This README describes v2.5.0. The interactive installer selects the latest published stable release; use the matching documentation when deploying another version.

## Before you deploy

**The forwarding path depends on the rule and the host.** nftables and software flowtable availability depend on the kernel, networking permissions and existing firewall. An nftables failure does not guarantee automatic Go fallback, and software flowtable is not NIC hardware offload. See [forwarding limits](docs/forwarding-limits.md).

**Protect management and forwarded services separately.** The management allowlist protects the Web UI/API, not forwarding ports. Restrict those ports with your host firewall or cloud security groups. Private targets require explicit authorization; see [security](SECURITY.md) and [configuration examples](docs/CONFIGURATION.md).

## Documentation and feedback

[Configuration examples](docs/CONFIGURATION.md) · [API reference](docs/API.en-US.md) · [Monitoring and statistics](docs/MONITORING.en-US.md) · [Release notes](RELEASE_NOTES.md) · [All documentation](docs/INDEX.md)

Report bugs or suggest improvements through [GitHub Issues](https://github.com/liying-official/Go-nftables-portbridge/issues). Read the [contributing guide](CONTRIBUTING.md) to get involved. Remove tokens, private keys and sensitive deployment details from logs and screenshots before sharing them. Follow [SECURITY.md](SECURITY.md) for suspected vulnerabilities.

## License

PortBridge is distributed under the [MIT License](LICENSE). Bundled dependencies retain their own license notices; see [third-party dependency notes](VENDOR_PATCHES.md).
