# Environment and application diagnostics — v2.5.1

[README](../README.md) · [Documentation](INDEX.md) · [简体中文](DIAGNOSTICS.zh-CN.md)

Open **Environment & application** in WebGUI and select **Refresh read-only snapshot**. The page shows the current process permissions, trusted nft/conntrack availability, configured versus observed data planes, kernel evidence, pending cleanup and the last recorded application operation. A snapshot is collected on entry or manual refresh; it is not a background forwarding probe.

The same explanation is available from a local command:

```bash
sudo /usr/local/bin/portbridge --diagnose
sudo /usr/local/bin/portbridge --diagnose --diagnose-language zh-CN
sudo /usr/local/bin/portbridge --diagnose-json
```

Use `--config` and `--token-file` for a custom installation. The command reads and validates the file without creating configuration, credentials or recovery records. When possible, it retrieves one authenticated `GET /api/diagnostics` from a verified local listener, preserving HTTPS certificate verification and rejecting redirects/proxies. It can use an administrator token or a configured monitoring token stored in the selected file. If service access fails, it reports local command observations with `runtime_observed:false`; command permissions are not evidence of the service's permissions. Missing/unreadable configuration produces an explanatory report without creating files. Exit status `0` means the report was produced, not that forwarding is healthy; invalid command options return `2`.

| Finding | Interpretation and action |
|---|---|
| `permission_denied` | Check the service account and required capabilities, keeping the restricted service policy. |
| `target_resolution_failed` | Review the target domain, configured resolvers, address families and recorded resolution error. Diagnosis performs no fresh DNS query. |
| `target_policy_denied` | Review the intended destination and explicit target CIDR permission. |
| `firewall_compatibility_rejected` | External firewall compatibility or inspection could not be proved. Review the evidence with that firewall's owner. |
| `listener_failed` | Check occupied ports, unavailable local addresses and binding permission. |
| `admission_suspended` | New nftables admission is suspended; existing connections may remain. |
| `cleanup_pending` | Old paths/connections have not been proven fully retired. Preserve valid ownership and recovery evidence. |
| `ownership_unverified` / `kernel_unverified` | Treat kernel state as unknown until attribution and readback are verified. |
| `dependency_missing` | Check the distribution's nftables/conntrack packages and trusted executable permissions. |
| `application_pending` | The saved forwarding parameters differ from the observed rule. Wait for application and refresh; pending cleanup or uncertainty takes precedence. |

Error categories interpret recorded controller evidence, not fresh probes. Unknown errors retain their original evidence with `application_failed`; review that evidence before acting.

`actual_data_plane` describes observed Go listeners and verified kernel state. `kernel-unverified` and `go-and-unverified-kernel` preserve uncertainty instead of declaring an old path absent. nftables-selected rules can legitimately use Go for cross-family, loopback or scoped-address paths; wildcard rules can use both. `running` alone is not a business-health signal and can indicate unresolved old forwarding. The recorded application operation is historical; compare its revision with the current report and inspect current rule evidence.

`GET /api/diagnostics` requires an administrator or read-only monitoring Bearer token and the normal management HTTPS/IP ACL. It needs no CSRF and exposes no token values, credential hashes, private keys or full external firewall rules. Rule names and recorded rule-error evidence may still contain deployment details; review before sharing a report publicly. English and Chinese explanations share one registry and stable finding codes.

Diagnostics never applies rules, starts listeners, resolves targets, installs dependencies, changes sysctls, changes another application's firewall, alters ownership records or forces cleanup. Hidden kernel files in restricted service namespaces are reported as unknown. Kernel presence and Go listeners are control-plane evidence; `business_health` remains `not_checked`. Flowtable traffic collection remains best effort.
