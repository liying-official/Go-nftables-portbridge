# Go-nftables-portbridge v2.4.4

## Highlights

- Required HTTPS for installation/upgrades; automatic ten-year self-signed certificates when none are configured, visible certificate status, and later CA-certificate replacement.
- TLS minimum 1.2 by default, optional 1.3-only; older clients preserve the configured policy, and pending restart notices remain accurate.
- Serialized administrator-token rotation, explicit consistency warnings and documented offline recovery.
- TCP/UDP/both rules, deterministic port ranges, same-family nftables/flowtable and cross-family Go forwarding.
- Batched Go UDP with worker-local sessions and exact shared source budgets; Web monitoring polls serially every 500 ms.
- Go 1.27.1, vendored dependencies, Linux amd64/arm64 static binaries and signed source/binary manifests.

## Install or upgrade

Verify the release signatures/checksums, extract the archive and run `sudo ./scripts/install.sh`. Fresh installs use loopback HTTPS on TCP/9080 and start with no forwarding rules. Upgrades preserve the administrator token, existing listeners and rules while enforcing HTTPS; absent certificates are generated, and invalid configured certificates fail preflight.

See [README.md](README.md) for access, certificate trust/replacement and default settings.

## Release assets

- `Go-nftables-portbridge-v2.4.4-en-US.tar.gz`
- `Go-nftables-portbridge-v2.4.4-zh-CN.tar.gz`
- `Go-nftables-portbridge-v2.4.4-SHA256SUMS.txt`
- `Go-nftables-portbridge-v2.4.4-SHA256SUMS.txt.sig`
- `release-manifest.json`
- `release-manifest.json.sig`

The binary and source files in each localized archive are authenticated by signed manifests. Use the matching checksum/signature files from the same release set.
