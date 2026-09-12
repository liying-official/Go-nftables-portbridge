# Go-nftables-portbridge v2.4.4

[English](README.md) | [简体中文](README.zh-CN.md)

A Linux TCP/UDP layer-4 port forwarder with a Go control plane and Web UI, nftables/flowtable acceleration for same-family traffic, and a high-performance Go proxy for cross-family traffic.

## Highlights

- TCP, UDP, or TCP + UDP on the same rule and port.
- IPv4 → IPv4, IPv6 → IPv6, IPv4 → IPv6, and IPv6 → IPv4.
- Per-rule data-plane selection: `nftables preferred` or forced `GO`.
- nftables DNAT/SNAT plus flowtable fast path for external same-family traffic.
- Go TCP/UDP proxy for cross-family traffic and loopback fallback.
- Deterministic one-to-one port-range mapping for up to 4096 ports.
- Local-process forwarding through nftables `output`, with safe Go fallback for wildcard loopback traffic.
- Custom DNS servers and 30-second target re-resolution for domain-based rules.
- Web rule management, runtime/data-plane state, Go-proxy traffic/session/drop counters, and 500 ms serialized monitoring refresh. Inspect nftables-path counters with `nft`.
- Atomic JSON configuration, hot rule updates, 256-bit token authentication, CSRF/origin protection, and direct-peer LAN/CIDR ACLs.
- Native TLS and an explicit strict-IP-allowlist mode for direct public management, with early connection filtering and authentication throttling.
- Static Linux amd64 and arm64 binaries and a hardened systemd unit.
- Fully vendored `golang.org/x/net v0.58.0` and `golang.org/x/sys v0.47.0` dependencies for offline builds.

## Architecture

```text
                 ┌───────────────┐
Web UI ─────────►│ Go Controller │
                 └───────┬───────┘
                         │
           ┌─────────────┴─────────────┐
           │                           │
           ▼                           ▼
   same-family forwarding      cross-family forwarding
   IPv4 → IPv4                 IPv4 → IPv6
   IPv6 → IPv6                 IPv6 → IPv4
           │                           │
           ▼                           ▼
  nftables DNAT/SNAT                 Go net
  + flowtable fast path         TCP/UDP proxy
```

For a wildcard listener, the controller plans IPv4 and IPv6 paths separately. If the target only has IPv4 addresses, non-loopback IPv4 traffic uses nftables, IPv6 traffic uses the Go proxy, and loopback traffic gets a dedicated Go fallback. The Web UI reports this as a hybrid data plane.

## Requirements

- Linux with systemd, nftables, iproute2, OpenSSH `ssh-keygen`, GNU shell/file/text/account utilities, and util-linux `runuser`. Flowtable can be disabled when it is not supported.
- Root access for installation.
- Exactly Go 1.27.1 when building from source or producing release binaries.

The supplied release binaries do not require a Go installation.

Compatibility note: this code has been tested successfully on Debian 13 and Ubuntu 26.04. Other compatible Linux distributions can be tested and deployed independently. The installer automatically installs a missing `nft` only when `apt-get` is available; otherwise install nftables yourself first.

## Fresh-install defaults

These are the values produced by the installer when no configuration exists:

| Item | Default in v2.4.4 |
|---|---|
| Management endpoint | HTTPS on TCP `9080`, listening on `127.0.0.1` and `::1` |
| Forwarding rules | Empty (`rules: []`); no forwarding port is opened automatically |
| New-rule Web form | TCP, `nftables preferred`, wildcard `*`; supply the listen port, target host and target port |
| Management ACL | Automatic LAN discovery off, strict mode off, persistent whitelist empty; loopback remains accessible |
| TLS | HTTPS required; minimum TLS `1.2`, optionally `1.3`; generate a ten-year self-signed certificate only when no pair is configured |
| DNS | No custom resolver; use system DNS; domain targets re-resolved every `30` seconds |
| Monitoring | Serialized status polling every `500 ms` |
| Global Go-proxy budgets | `8192` TCP connections, `16384` UDP sessions, `1 GiB` estimated UDP memory |
| nftables | Flowtable enabled; a fresh installation generates a nonzero instance conntrack mark |

`config.example.json` is an example, not the configuration installed by the script. Its enabled sample rule, documentation-only targets, `443–452` port range and custom DNS entries are examples; review or remove them before using that file. `config.public.example.json` is a public-management template. Neither is automatically installed as live configuration.

Management port `9080` is independent of forwarding ports. Only explicitly configured rules open forwarding endpoints. Upgrades retain the existing management port, listeners and rules while enforcing HTTPS.

## Quick install

Place all six v2.4.4 release assets in one directory and complete [Release verification](#release-verification) before executing any package script. Then extract the English archive and install:

```bash
tar -xzf Go-nftables-portbridge-v2.4.4-en-US.tar.gz
cd Go-nftables-portbridge-v2.4.4-en-US
sudo ./scripts/install.sh
```

Before changing the system, the installer requires the bundle signer file to be a single regular non-symlink/non-hardlinked entry that exactly matches the Ed25519 public key and `SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o` fingerprint pinned in the installer, then verifies the signed internal manifest and its source/binary hash bindings. It selects the amd64 or arm64 binary, installs nftables through `apt-get` if it is missing, enables IPv4/IPv6 forwarding, installs the systemd unit, and starts the service. Existing rules, ACLs and administrator tokens are preserved; upgrades provision required HTTPS and turn off legacy plaintext access.

The secure default binds management only to loopback. Open an SSH tunnel:

```bash
ssh -L 9080:127.0.0.1:9080 root@SERVER
```

Then open `https://127.0.0.1:9080/` locally. When a self-signed certificate is generated, verify the installation fingerprint and establish client trust first. HTTPS does not change the default loopback listener or the IP allowlist.

The installer does not print the administrator token by default, so unattended deployment logs do not capture it. It is stored with restricted permissions at:

```bash
sudo cat /etc/portbridge/admin.token
```

If startup reports an inconsistent or missing token file, stop the service before
resetting the token as its service account, then restart. This preserves file
ownership and reloads the new credential into the running process:

```bash
sudo systemctl stop portbridge
sudo -u portbridge /usr/local/bin/portbridge --config=/etc/portbridge/config.json --token-file=/etc/portbridge/admin.token --reset-admin-token
sudo systemctl start portbridge
```

The reset command prints the new secret; use a private terminal. For custom
deployments, use the same configuration/token paths and account as the service.

For an interactive installation, pass `--show-token` only when printing the token to the terminal is acceptable. The supported installer options are:

| Option | Purpose |
|---|---|
| `--allow IP/CIDR[,more]` | Add temporary bootstrap ACL entries; it does not change the Web listen address or bypass TLS |
| `--tls-cert FILE` / `--tls-key FILE` | Import a certificate/key pair into the managed TLS directory |
| `--tls-name DNS-or-IP` | Add a SAN when generating a new self-signed certificate; repeatable |
| `--no-start` | Prepare files, required HTTPS and the administrator token, but leave the service stopped |
| `--show-token` | Print the token after startup; avoid it in captured deployment logs |

When upgrading or recovering a configuration that already has a non-loopback listener, a temporary bootstrap ACL can be supplied:

```bash
sudo ./scripts/install.sh --allow 203.0.113.10/32
```

Multiple IPv4/IPv6 prefixes are accepted as a comma-separated list. `--allow` does not make a fresh loopback-only installation remotely reachable. It is only a recovery/bootstrap permission, not a substitute for TLS or a host firewall, and strict allowlist mode deliberately ignores it.

For a clean source checkout without prebuilt binaries in `dist/`, install exactly Go 1.27.1 and run the same installer. Go must be visible in the installer's fixed PATH (`/usr/local/go/bin` or a standard system binary directory), not only in your personal shell PATH. Builds use vendored dependencies:

```bash
go version  # must report go1.27.1
sudo ./scripts/install.sh
```

## HTTPS certificates and replacement

Installation and upgrades set `web.require_https=true`, disable `allow_insecure_http`, and provision TLS before the service starts (including `--no-start`). The systemd service also requires HTTPS. The settings API cannot clear certificates or re-enable plaintext HTTP.

If no certificate is configured, the installer generates a unique ECDSA P-256 self-signed certificate valid for ten years. SANs include localhost, loopback addresses, the current machine hostname and unicast interface IPs. For an additional management DNS name or externally mapped IP, use `--tls-name admin.example.com` or `--tls-name 203.0.113.10` during the initial generation. Existing valid certificates are preserved on upgrades; invalid, expired or incomplete configured certificates stop installation instead of triggering a silent replacement. IP/name changes require a replacement certificate if the new name is not in its SANs.

Self-signed TLS encrypts traffic but is not automatically trusted by browsers. Verify the SHA-256 fingerprint printed in the server's installation output through a trusted channel, then import the public certificate into your client's trust store. Never distribute the private key or blindly bypass certificate warnings. Installation output and the Web page explicitly identify self-signed certificates; the Web status describes the certificate actually loaded by the process.

To supply a regular certificate/key pair during installation or upgrade:

```bash
sudo ./scripts/install.sh --tls-cert /secure/fullchain.pem --tls-key /secure/privkey.pem
```

The pair must match, be currently valid, use absolute non-symlink paths, and satisfy the key-owner/permission checks. The installer copies explicit imports into a new managed directory under `/etc/portbridge-tls`, without changing the originals. Generated/imported keys are root-owned with read-only access for the service group (`0640`).

Later, put a CA-issued certificate and matching key on the server, ensure the service can read the files and parent directories (for example `root:portbridge 0640` for the key), enter their absolute paths in Web access settings, save, and run `sudo systemctl restart portbridge`. Certificate renewal at the same path also needs a restart. A reverse proxy must use HTTPS to the installed backend and verify the backend certificate/hostname; it still must enforce the real-client allowlist.

## Public management deployment

The installed service uses loopback-only HTTPS, disables automatic LAN discovery, and therefore is not remotely reachable. Do not weaken that default for Internet exposure.

For direct public management, use [config.public.example.json](config.public.example.json) as a reference and apply all of these controls:

1. Restrict TCP/9080 to the exact administrator IPs in the cloud security group and host firewall. The application ACL is defense in depth, not volumetric DoS protection.
2. Use a certificate valid for the management IP/domain and establish client trust. For direct Web replacement, the service must be able to read the key: use `0600` owned by `portbridge`, or `0640 root:portbridge`, and allow traversal of parent directories.
3. Set the absolute `web.tls_cert_file` and `web.tls_key_file` paths, restart the service, and verify HTTPS first.
4. From that HTTPS session, disable `web.auto_lan_acl`, add the direct client address to `web.whitelist`, and enable `web.strict_ip_allowlist`.

The Web UI enforces this two-stage transition: strict mode cannot be enabled from a plaintext HTTP session. A new installation may instead prepare all fields offline while the service is stopped, then start directly in strict HTTPS mode. Replace the documentation-only addresses in the public example before using it. Certificate renewal at the same path still requires `systemctl restart portbridge`.

Strict mode always permits local loopback recovery, but otherwise uses only the persistent whitelist. It ignores automatically detected LANs and `--bootstrap-allow`, rejects `0.0.0.0/0` and `::/0`, and accepts at most 1024 whitelist entries. TLS 1.2 is the minimum by default; set `web.tls_min_version` to `1.3` (and restart) for internet-exposed management. TLS responses include HSTS.

PortBridge never trusts `Forwarded` or `X-Forwarded-For`. If a reverse proxy terminates TLS, bind PortBridge to loopback/private addresses and enforce the real client allowlist at the proxy and firewall. PortBridge sees only the proxy's directly connected address; the native strict mode is intended primarily for direct TLS connections.

## Data-plane selection

Each rule has two choices:

- `nftables preferred` (default): same-family forwarding uses kernel DNAT/SNAT; established external TCP/UDP flows are eligible for the `fastpath` flowtable. Cross-family paths and wildcard loopback fallback use Go.
- `GO`: the whole rule uses the Go TCP/UDP proxy.

The service manages only its own `inet portbridge` nftables table. The table is stamped with `Go-nftables-portbridge:managed:v1:<conntrack-mark>` and rules are scoped to that instance's conntrack mark; PortBridge refuses to replace or delete a same-name foreign table. A fresh configuration receives a cryptographically random nonzero 32-bit mark. If an nftables replacement fails, the controller attempts to remove its owned table to fail closed; if cleanup also fails, runtime status retains a visible error tombstone instead of claiming the stale path stopped. The systemd unit calls the same ownership-aware cleanup path after every stop.

## Protocols and port ranges

`protocol` accepts `tcp`, `udp`, or `both`. A `both` rule starts TCP and UDP forwarding on the same endpoint.

Listen and target ranges must have equal lengths and may contain up to 4096 ports:

```text
Listen: 10000-10099
Target: 20000-20099
```

This maps `10000 → 20000`, `10001 → 20001`, and so on. The nftables path uses a deterministic destination-port map instead of a NAT port pool.

## DNS and DDNS-style target refresh

The Web settings page accepts up to eight custom DNS servers, one per line:

```text
1.1.1.1
8.8.8.8:53
[2606:4700:4700::1111]:53
```

Port `53` is used when omitted. Leaving the list empty uses the system resolver. DNS traffic itself is plaintext unless the selected local/system resolver provides encrypted upstream transport. Domain targets are resolved every 30 seconds. Every resolved address is revalidated on every refresh to prevent DNS rebinding into denied local, private, link-local, multicast, unspecified, carrier-grade NAT, or cloud-metadata destinations. Private targets require both `allow_private_target=true` and an explicit narrow `target_cidr_allowlist`. Address changes atomically update nftables rules and restart only affected Go paths; a temporary DNS failure retains the last valid target.

## Local-process access

- A local process connecting to a non-loopback forwarded address is handled by the nftables `output` chain.
- For wildcard listeners, `127.0.0.1` and `::1` use dedicated Go fallback listeners.
- The service does not enable `route_localnet`.

## Configuration

The live configuration is `/etc/portbridge/config.json`. [config.example.json](config.example.json) demonstrates fields and rules; it is not a dump of fresh-install defaults.

Connection/session/rate/estimated-memory limits below apply to Go proxy paths. They do not automatically rate-limit the nftables/flowtable path; enforce any required kernel-path limits separately with firewall/kernel controls. Management ACLs also do not protect forwarding endpoints.

Important fields:

| Field | Description |
|---|---|
| `web.port` | Web management port; restart required after a change |
| `web.listen_ipv4` / `listen_ipv6` | Web listen addresses |
| `web.auto_lan_acl` | Automatically allow directly attached private/ULA/link-local prefixes |
| `web.strict_ip_allowlist` | Direct-public mode: require native TLS and use only loopback plus the explicit whitelist |
| `web.require_https` | Set by installation; certificates are mandatory and API downgrades are rejected |
| `web.allow_insecure_http` | Legacy development compatibility only; installed services reject enabling it |
| `web.whitelist` | Explicit IP/CIDR management ACL |
| `web.tls_cert_file` / `tls_key_file` | Absolute native-TLS certificate/key paths; restart after a change |
| `web.tls_min_version` | `1.2` (default) or `1.3`; restart after a change |
| `web.dns_servers` | Custom DNS servers; empty means system resolver |
| `resource_limits.*` | Global TCP connection, UDP session, and estimated UDP-memory ceilings |
| `nftables.conntrack_mark` | Nonzero instance mark used to scope all managed NAT/forward rules |
| `nftables.enable_flowtable` | Enable the optional nftables flowtable fast path |
| `rules[].protocol` | `tcp`, `udp`, or `both`; the new-rule Web form selects TCP and enabled by default |
| `rules[].data_plane` | `nftables` or `go` |
| `rules[].listen_port_end` / `target_port_end` | Optional equal-length range ends |
| `rules[].allow_private_target` / `target_cidr_allowlist` | Two-part opt-in for narrowly allowed private targets |
| `rules[].tcp_idle_timeout_seconds` | Close inactive TCP proxies; default `300` seconds |
| `rules[].max_tcp_connections` / `max_tcp_connections_per_source` | Rule and source limits; defaults `2048` / `256` |
| `rules[].max_udp_sessions` / `max_udp_sessions_per_source` | Exact rule-wide and source-IP-wide session limits across every worker, port, family, and Go runner; defaults `4096` / `512` |
| `rules[].udp_new_sessions_per_second_per_source` | Exact rule-wide source-IP session-creation rate shared by every Go path; default `1000`/s |
| `rules[].udp_packets_per_second_per_source` | Exact rule-wide source-IP packet rate shared by every Go path; default `100000`/s |
| `rules[].udp_workers` | Rule-wide worker budget; `0` selects an automatic value |
| `rules[].udp_batch_size` | `ReadBatch`/`WriteBatch` size; default `64` |
| `rules[].udp_packet_buffer_size` | Preallocated packet-buffer size; default `2048` bytes |
| `rules[].udp_listener_buffer_bytes` | Requested listener socket buffer; default `4 MiB` |
| `rules[].udp_session_buffer_bytes` | Requested connected-session socket buffer; default `64 KiB` |

Rule, ACL, and DNS changes are applied without restarting the service. Web listen address, port, TLS path, or TLS minimum-version changes require a restart. Enabling strict mode is immediate and is accepted only through an existing HTTPS session whose direct client address remains whitelisted.

Saving settings without `tls_min_version` (or with an empty value) preserves the
configured TLS policy for older API clients; explicitly send `1.2` to restore the
default. `restart_required` remains true across repeated saves until the running
listener matches the saved configuration after restart, or the change is reverted.

## Performance design

- Linux TCP fast path uses `net.TCPConn.ReadFrom`, allowing the runtime to use `splice`; the fallback uses pooled 64 KiB buffers and preserves half-close behavior.
- UDP workers own their socket, packet slab, batch messages, `netip.AddrPort` flow table, epoll state, time wheel, and counters.
- Linux batch I/O uses `recvmmsg`/`sendmmsg` through `ReadBatch`/`WriteBatch`.
- `SO_REUSEPORT` distributes flows across worker-local sockets. Session lookup remains worker-local; exact source-IP limits use 64 shared rule-level shards, so each inbound packet holds only one short counter/token-bucket lock and never holds it across socket I/O.
- Connected UDP upstream sockets filter the remote peer and avoid per-packet target-address work.
- The hot path avoids per-packet goroutines, channels, JSON, database work, and logging.
- Global and per-rule/source budgets reject excess TCP/UDP state before it can create unbounded file-descriptor or memory growth. UDP listener slabs and connected-session buffers share the global estimated-memory ceiling.

See [docs/udp-dataplane.md](docs/udp-dataplane.md) for the detailed design and tuning notes.

## Service operations

```bash
sudo systemctl status portbridge
sudo journalctl -u portbridge -f
sudo systemctl restart portbridge
sudo nft list table inet portbridge
sudo nft list flowtable inet portbridge fastpath  # only when enable_flowtable=true
```

The public project name is `Go-nftables-portbridge`. The installed binary, service, configuration directory, and nftables table intentionally retain the `portbridge` identifier for upgrade compatibility.

## Security notes

- The management API uses a random 256-bit bearer token, authenticated CSRF bootstrap, same-origin browser checks, and bounded JSON bodies. Repeated failures are throttled per IP and globally; a valid token is never locked out by failed attempts.
- Installed services require HTTPS. Missing certificates are generated per machine, and self-signed certificate status/fingerprints are clearly displayed.
- The browser keeps the token in per-tab `sessionStorage`, not persistent `localStorage`; closing the tab clears it, and logout/authentication loss clears management data from the page. Treat any system with browser extensions or injected scripts as outside the trust boundary.
- ACL decisions use the direct TCP peer address and do not trust `X-Forwarded-For`.
- Strict mode filters disallowed peers before TLS handshakes/HTTP parsing, repeats the ACL check in middleware, and caps accepted management connections. An upstream firewall is still required for Internet exposure.
- The configuration and administrator token are stored with mode `0600`; TLS private keys reject symlinks, unsafe ownership, and broad permissions. The systemd unit disables core dumps, filters dangerous system-call groups, and applies file-descriptor, task, CPU, and memory ceilings.
- Rule targets are fail-closed: DNS answers are revalidated against the same destination policy on every refresh, and private targets need a narrow CIDR opt-in.
- Release installers verify a pinned Ed25519/OpenSSH signature and all listed source/binary hashes before changing system state.
- Default startup logs omit rule names and forwarding endpoints. Debug and error logs can still contain operational network details and must be protected.
- Never commit `/etc/portbridge/config.json`, `/etc/portbridge/admin.token`, logs, database files, or environment files.

See [SECURITY.md](SECURITY.md) for reporting guidance.

## Build and test

Dependencies are committed under `vendor/`, including the documented local batch-address reuse patch, so builds can run offline:

```bash
go version              # must report go1.27.1
GOPROXY=off go test ./...
GOPROXY=off go test -race ./...
GOPROXY=off go vet ./...
make dist
```

v2.4.4 is built with Go 1.27.1 and uses `http.Server.MaxHeaderValueCount` together with byte limits. No public `pprof` endpoint is enabled. `make dist` creates unsigned development binaries, not a signed release: the installer intentionally rejects prebuilt files without the required signatures. Do not treat that output as an installable Release or bypass verification.

## Release verification

The installer automatically verifies the signed internal bundle manifest before
installing a prebuilt binary. To verify the downloaded top-level assets first,
keep all six v2.4.4 assets in one directory, extract either localized archive,
and use its pinned signer file:

```bash
tar -xzf Go-nftables-portbridge-v2.4.4-en-US.tar.gz
SIGNERS=Go-nftables-portbridge-v2.4.4-en-US/packaging/release-signers
EXPECTED_SIGNER='portbridge-release-v2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVc6m1afFOM3gsLO6VXuLyAlHbkvBP83wlMEqArW/0k'
test -f "$SIGNERS" && test ! -L "$SIGNERS" || exit 1
test "$(cat "$SIGNERS")" = "$EXPECTED_SIGNER" || exit 1
test "$(ssh-keygen -lf "$SIGNERS" -E sha256 | awk 'NR == 1 {print $2}')" = \
  'SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o' || exit 1
ssh-keygen -Y verify -f "$SIGNERS" -I portbridge-release-v2 \
  -n portbridge-release -s release-manifest.json.sig < release-manifest.json
ssh-keygen -Y verify -f "$SIGNERS" -I portbridge-release-v2 \
  -n portbridge-release -s Go-nftables-portbridge-v2.4.4-SHA256SUMS.txt.sig \
  < Go-nftables-portbridge-v2.4.4-SHA256SUMS.txt
sha256sum -c Go-nftables-portbridge-v2.4.4-SHA256SUMS.txt
```

Pinned release-key fingerprint: `SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o`. This identifies the release signing key; it is neither a TLS certificate fingerprint nor an archive SHA-256. Actual file digests are in `Go-nftables-portbridge-v2.4.4-SHA256SUMS.txt` and `release-manifest.json`.

The signing identity is `portbridge-release-v2`, with namespace `portbridge-release`. Obtain the expected key/fingerprint from a trusted project source; a bundled public key alone is not a trust anchor. Keep signing private keys and backups offline, outside the source tree and release directory.

Release binaries are written to `dist/` and are intentionally excluded from Git.

## Uninstall

Keep configuration:

```bash
sudo ./scripts/uninstall.sh
```

Remove configuration and the service account too:

```bash
sudo ./scripts/uninstall.sh --purge
```

The separate `/etc/portbridge-tls` directory is intentionally retained so an
uninstall cannot silently destroy certificates or private keys.

## License

[MIT](LICENSE)
