# v2.5.1 release notes

[简体中文](RELEASE_NOTES.zh-CN.md) · [README](README.md) · [Documentation](docs/INDEX.md)

- Add an independent read-only monitoring token, managed in WebGUI, for status, operation results, diagnostics and Prometheus metrics.
- Expose configuration revisions and application-operation states; add rule-set validation, preview, batch replacement and portable rule-template export.
- Add certificate-expiry metrics, validated manual certificate hot reload, and dashboard/alert examples.
- Add optional Go TCP connection checks, backup targets and configurable DNS refresh/cache lifetime. Connection checks are not application health; UDP and nftables do not gain automatic backend failover.
- Add bilingual read-only environment/application diagnostics in WebGUI, API and CLI, explaining permissions, DNS, firewall compatibility, listeners and pending cleanup.
- Preserve Go connections during display-name-only rule changes; reorganize backend contracts and tests, align API error localization, and refresh documentation and Web version labels.
- Slim prebuilt packages to runtime files and selected-language user documentation; omit source, tests and the static demo, retain signatures and licenses, and keep WebGUI bilingual.

HTTPS, management IP ACL, Bearer/CSRF authentication, destination authorization and nftables ownership/retirement checks remain in force. Configuration saved or a forwarding path observed does not prove end-to-end health. Software flowtable statistics remain best effort.
