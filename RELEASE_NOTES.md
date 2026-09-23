# v2.5.0

- Introduce a sky-blue Tabler Core interface with locally served Core CSS/JS and Tabler Icons.
- Switch English and Simplified Chinese in one WebUI, with responsive desktop tables, mobile rule cards and navigation.
- Display combined approximate cumulative traffic and separate Go/nft real-time rates; retain authenticated Prometheus metrics.
- Keep rule controls, HTTPS, direct-peer allowlisting, administrator authentication and CSRF protection unchanged.
- Provide a Debian/Ubuntu one-click installer with architecture/language selection and signed-release verification.

Release archives and SBOM are authenticated by signed SHA256SUMS. Each prebuilt package has a signed internal manifest; local rebuilds are not automatically publisher-signed. See [forwarding limits](docs/forwarding-limits.md) before deployment.
