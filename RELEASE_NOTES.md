# v2.5.0 release notes

[简体中文](RELEASE_NOTES.zh-CN.md) · [README](README.md) · [Documentation index](docs/INDEX.md)

## Included in this version

v2.5.0 includes a locally served Tabler Core interface, English / Simplified Chinese switching, responsive rule tables/cards, and a Debian/Ubuntu interactive installer that verifies signed release packages. The dashboard displays approximate cumulative traffic while keeping Go and nft real-time rates separate. The management API and Prometheus endpoint require administrator authentication; writes require CSRF handling.

## Deployment notes

The manual verified-release procedure keeps management on loopback. The interactive installer targets fresh installations, selects the latest published stable release and configures available wildcard listeners behind a persistent strict allowlist. Review [installation](docs/INSTALL.en-US.md) and [one-click behavior](docs/ONECLICK.en-US.md) before selecting a procedure.

Flowtables use software acceleration; this implementation does not emit `flags offload` or promise NIC hardware offload. A successful configuration write does not prove forwarding or old-flow retirement. Go budgets do not automatically limit the nftables path. Read [forwarding limits](docs/forwarding-limits.md) and [monitoring boundaries](docs/MONITORING.en-US.md).

## Release integrity and scope

The release workflow produces four localized amd64/arm64 archives and an SBOM. Signed `SHA256SUMS` authenticates release assets; the internal signed manifest authenticates covered package contents. Availability of assets must be checked at deployment time. Local builds and documentation-only revisions are not automatically publisher-signed.

The configuration schema's `version: 2` is distinct from release version `2.5.0`.
