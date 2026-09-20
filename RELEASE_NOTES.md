# v2.4.9

- Bounded rule-scoped selective ACL proof and original-tuple flowtable isolation.
- Fix login/logout/expired-token GUI recovery and display the running HTTPS certificate correctly.
- Localize default GUI, installation prompts and current documentation for English and Simplified Chinese source packages; source compilation embeds the selected GUI.
- Accept the actual single-device nft JSON string while retaining exact device-set verification.
- Preserve `-1 + error` batch syscall failures as zero completed messages plus the original error; keep valid UDP sessions on temporary send pressure and count unsent packets without adding retry queues.

Published v2.4.9 source archives have Ed25519 detached signatures. They contain no prebuilt binaries; local builds are not automatically publisher-signed. See [forwarding limits](docs/forwarding-limits.md) before deployment.
