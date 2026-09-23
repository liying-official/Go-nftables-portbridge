# PortBridge — v2.5.0

**TCP and UDP port forwarding for Linux, with a bilingual Web UI and an authenticated HTTP API.**

[![Release](https://img.shields.io/github/v/release/liying-official/Go-nftables-portbridge)](https://github.com/liying-official/Go-nftables-portbridge/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Linux](https://img.shields.io/badge/platform-Linux-informational)
![amd64 / arm64](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-informational)

**English** | [简体中文](README.zh-CN.md)

PortBridge combines nftables DNAT/SNAT and optional **software flowtable** acceleration for eligible traffic with a Go TCP/UDP proxy for cross-family and explicitly selected proxy paths. Manage rules, inspect runtime state and rotate the administrator token without leaving the browser.

[Install](docs/INSTALL.en-US.md) · [API reference](docs/API.en-US.md) · [All documentation](docs/INDEX.md) · [Releases](https://github.com/liying-official/Go-nftables-portbridge/releases)

This documentation describes **v2.5.0**. The live release badge and interactive installer may point to a different published version; use the documentation matching the package you deploy.

## Features

| Area | Included in v2.5.0 |
|---|---|
| Forwarding | TCP, UDP or both; single ports and equal-length ranges of up to 4096 ports. |
| Address families | IPv4 → IPv4, IPv6 → IPv6, IPv4 → IPv6 and IPv6 → IPv4. |
| Data-plane choice | Prefer nftables where eligible, or explicitly use the Go proxy. A wildcard rule can use a hybrid plan. |
| Management | English / 简体中文 Tabler interface, rule editing, settings and a Bearer-authenticated API with CSRF protection for writes. UI assets are served locally. See the [English API reference](docs/API.en-US.md). |
| Observability | Runtime state, Go payload counters, separate best-effort nft/conntrack observations and authenticated Prometheus metrics. |
| Deployment | Signed-release installer, native HTTPS and a dedicated hardened systemd service; release packaging targets Linux amd64 and arm64. |

Both localized packages contain the same bilingual interface. The package selects the initial language; the browser stores the language preference in `localStorage` and the administrator token only in per-tab `sessionStorage`.

## Get started

Choose the installation model deliberately:

| Procedure | Management exposure | Use case |
|---|---|---|
| **[Verified v2.5.0 release installation](docs/INSTALL.en-US.md)** | HTTPS on `127.0.0.1` / `::1`, port `9080` by default. | Recommended when managing through an SSH tunnel. |
| **[Interactive fresh installation](docs/ONECLICK.en-US.md)** | HTTPS on `0.0.0.0` and available IPv6 interfaces, protected by a persistent strict IP allowlist. | Debian/Ubuntu; selects the latest published stable release. |

Use a Linux host that permits the required networking operations. The service installer requires systemd and administrative privileges; restricted containers are not equivalent. Prebuilt packages do not require a Go compiler. Verify publisher signatures before executing downloaded package scripts; missing signatures are a reason to stop, not bypass verification.

After the loopback-only installation, open an SSH tunnel from your administrator computer:

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:9080:127.0.0.1:9080 USER@SERVER
```

Replace `USER` and `SERVER` with your SSH account and host. Open **https://127.0.0.1:9080/**, verify the certificate fingerprint and establish trust, then sign in with the token stored on the server at `/etc/portbridge/admin.token`. Keep the token and installation output private. The full [installation guide](docs/INSTALL.en-US.md) covers verification, certificate import, upgrades and uninstalling.

Fresh installations have no forwarding rules. Add an owned target, save a rule, inspect its runtime status and test real TCP/UDP application traffic before relying on it. [Example configurations](docs/CONFIGURATION.md) are templates, not production defaults; the demonstration rule is disabled.

## Understand the forwarding path

| Rule shape | Expected planning behavior |
|---|---|
| Eligible same-family traffic | nftables DNAT/SNAT; optional software flowtable acceleration when the surrounding firewall can be admitted safely. |
| IPv4 ↔ IPv6, explicit loopback or scoped target | Go proxy where required by the planner. |
| `data_plane: "go"` | Explicit Go proxy path. |
| `listen_host: "*"` | IPv4 and IPv6 are planned separately; dedicated loopback handling can produce a hybrid path. |

The configured preference is not proof of the active path. Inspect `/api/status`, including `data_plane`, `go_running`, `kernel_state` and errors. An nftables failure does **not** imply an automatic Go fallback. PortBridge does not add the flowtable `flags offload` option and does not promise NIC hardware offload.

For private targets, enable `allow_private_target` **and** provide a narrow matching `target_cidr_allowlist`. The latter authorizes otherwise restricted targets; it is not a universal allowlist for all public egress. See [forwarding limits](docs/forwarding-limits.md) before combining PortBridge with other firewall or NAT managers.

## Security and operational boundaries

The management allowlist protects the Web UI/API, **not forwarding ports**. Protect those ports separately. Source-only development defaults can use loopback HTTP before TLS preparation; the installed service enforces HTTPS. Direct management exposure needs native TLS, strict direct-peer allowlisting and restrictive host/cloud firewall rules. Forwarded client-IP headers are not trusted.

Go connection/session/rate budgets do not automatically constrain nftables traffic. Go payload counters and nft L3 counters use different accounting boundaries; the UI's combined total is approximate, and hook counters must not be summed. HTTP success and an active service are not end-to-end health checks. Read [security](SECURITY.md) and [monitoring](docs/MONITORING.en-US.md).

## Development

Source checkouts and GitHub-generated Source code archives do not contain precompiled binaries. Use the **Go 1.27.1** toolchain with the supplied vendor tree. From the repository root:

```bash
go version
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test -race ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go vet ./...
```

Some Linux integration tests need additional tools, privileges and isolated namespaces; a skipped test is not a pass. `make dist` creates unsigned development binaries, not publisher-signed installable release packages. See [contributing](CONTRIBUTING.md) and [vendored patches](VENDOR_PATCHES.md).

## Documentation and community

[Installation](docs/INSTALL.en-US.md) · [API](docs/API.en-US.md) · [Monitoring](docs/MONITORING.en-US.md) · [UDP design](docs/udp-dataplane.md) · [Release notes](RELEASE_NOTES.md) · [Publication checklist](docs/PUBLISHING.md)

For ordinary bugs, open a [GitHub issue](https://github.com/liying-official/Go-nftables-portbridge/issues) with a minimal reproduction and sanitized logs. Follow [SECURITY.md](SECURITY.md) for suspected vulnerabilities; never publish tokens, private keys or unredacted deployment details.

## License

PortBridge is distributed under the [MIT License](LICENSE). Bundled dependencies retain their own notices; see [vendored patches and UI notices](VENDOR_PATCHES.md).
