# v2.4.9

- Bounded rule-scoped selective ACL proof and original-tuple flowtable isolation.
- Fix login/logout/expired-token GUI recovery and display the running HTTPS certificate correctly.
- Localize default GUI, installation prompts and current documentation for English and Simplified Chinese packages; build each GUI into its own binary when producing signed artifacts.
- Accept the actual single-device nft JSON string while retaining exact device-set verification.
- Preserve `-1 + error` batch syscall failures as zero completed messages plus the original error; keep valid UDP sessions on temporary send pressure and count unsent packets without adding retry queues.

Source packages are unsigned, not publisher-signed binaries. See [forwarding limits](docs/forwarding-limits.md) before deployment.
