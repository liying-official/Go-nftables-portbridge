# Traffic statistics and Prometheus — v2.5.0

[简体中文](MONITORING.zh-CN.md)

The controller samples traffic once per second. WebGUI refreshes about every 500 ms and displays the latest sample; API requests and Prometheus scrapes do not trigger additional nft/conntrack commands. Sampling is bounded and skips contended control-plane state. A sample older than three seconds is unavailable. The first sample, recovery after a failed sample and detected counter decreases do not produce a rate until a valid delta exists.

## Counter sources and boundaries

- `traffic.go`: Go payload bytes. On Linux, active TCP connections are sampled using TCP_INFO acknowledged bytes without wrapping `io.Copy` or disabling splice; completed copies reconcile to the copy result. UDP counters are published by worker maintenance. Packet fields in this Go series describe UDP only.
- `traffic.nft`: best-effort observed conntrack L3 bytes and packets, attributed by instance mark, family, protocol, original listener tuple, backend tuple, port offset and common zone/connection identity. Original direction is upload and reply direction is download. These counters are not Go payload bytes. WebGUI combines the cumulative values into an approximate display total while keeping real-time rates separate. API and Prometheus sources remain independent; the displayed total is not a uniform payload or billing measurement.
- `traffic.nft_hooks`: actual nftables rule counters grouped by `prerouting`, `output`, `postrouting`, `forward` or `flowtable`. The same packet may visit several hooks. NAT counters generally describe the first packet establishing a mapping; flowtable hits bypass ordinary forwarding hooks. **Do not sum hook counters or use them as complete forwarding throughput.**

Flowtable statistics are collected on a best-effort basis. Its `counter` option can synchronize counters into conntrack, but synchronization is asynchronous. Connections created and destroyed between samples may be missed; hardware offload, accounting availability, rule rebuilds and collection gaps can further limit coverage. Counters are process-local observations, not billing totals or durable history. Sampling never disables acceleration or changes forwarding/firewall decisions.

For conntrack packet/byte accounting, an administrator may enable:

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

This setting adds accounting overhead and normally affects newly created connections. Existing flows without accounting must expire/reconnect before they can contribute counters; do not flush unrelated connections. The collector does not change this setting automatically. Read failures, unverified ownership or missing accounting are reported as unavailable, not zero traffic. During an incomplete conntrack sample, the previous complete baseline is retained and nft rates are withheld; independent hook counters may remain available.

`GET /api/status` includes `rules[].traffic` with `go`, `nft`, `nft_hooks`, `nft_hooks_available`, `nft_hooks_sampled_at`, `nft_best_effort`, `nft_status` and `counter_resets`. Both series contain byte/packet counters, `*_per_second` rates, `sampled_at`, `interval_seconds`, `available` and `rate_ready`. Check both flags before using a rate. Status values are `pending`, `not_applicable`, `sampled`, `accounting_unavailable`, `unavailable` or `stale`. Existing `stats` fields retain their Go-only semantics.

## Prometheus `/metrics`

`GET /metrics` shares the management HTTPS listener, IP allowlist and administrator Bearer authentication. It is not anonymous and does not require CSRF for GET. The response uses Prometheus text format 0.0.4. The token still grants full management API access: protect the credentials file and scraper host. Metrics label rules by ID/protocol, not names or forwarding endpoint addresses.

```yaml
scrape_configs:
  - job_name: portbridge
    scheme: https
    scrape_interval: 5s
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/portbridge.token
    tls_config:
      ca_file: /etc/prometheus/portbridge-ca.pem
      server_name: pb.example
    static_configs:
      - targets: ['pb.example:9080']
```

Replace the example host and certificate paths. Verify self-signed certificate fingerprints before trusting them; do not use `insecure_skip_verify` as a shortcut. Allow the scraper's direct source IP in the management allowlist.

All 15 metric families are listed below. Except for uptime, every metric has `rule_id` and `protocol` labels (`tcp`, `udp` or `both` for configured rules). The additional-label column lists label names, not a literal PromQL selector. `source` is either `go` or `nft`; `direction` is either `up` or `down`; `hook` identifies the observed hook.

| Metric | Type | Additional labels | Meaning |
|---|---|---|---|
| `portbridge_uptime_seconds` | gauge | None; no rule labels | Seconds since the Web Server was created |
| `portbridge_rule_running` | gauge | None | Manager running/risk flag (0/1), not end-to-end health |
| `portbridge_rule_bytes_total` | counter | `source`, `direction` | Cumulative observations; Go payload or nft L3 bytes |
| `portbridge_rule_bytes_per_second` | gauge | `source`, `direction` | Latest observed byte-rate estimate; multiply by eight for bit/s |
| `portbridge_rule_sample_available` | gauge | `source` | Source sample is fresh and available (0/1) |
| `portbridge_rule_rate_ready` | gauge | `source` | A valid recent delta exists (0/1) |
| `portbridge_rule_sample_timestamp_seconds` | gauge | `source` | Last successful sample's Unix time; zero before initialization |
| `portbridge_nft_packets_total` | counter | `direction` | Best-effort conntrack L3 packets |
| `portbridge_nft_hook_bytes_total` | counter | `hook` | Observed hook bytes; hooks must not be summed |
| `portbridge_nft_hook_packets_total` | counter | `hook` | Observed hook packets, not complete forwarding volume |
| `portbridge_nft_hooks_available` | gauge | None | Owned hook sample is fresh and available (0/1) |
| `portbridge_nft_counter_resets_total` | counter | None | Detected decreases in kernel counters |
| `portbridge_go_active_tcp_connections` | gauge | None | Current Go TCP connections |
| `portbridge_go_active_udp_sessions` | gauge | None | Current Go UDP sessions |
| `portbridge_go_udp_drops_total` | counter | None | Application-observed Go UDP drops, not network-wide loss |

Byte-rate series are emitted only when both source validity flags are true. Byte/packet counters can remain present with the last known value or an initial zero even when unavailable; their presence does not prove a successful sample. Hook series appear only for previously observed hooks and also require `portbridge_nft_hooks_available` to assess freshness. Process restart or removal of a rule's runtime state can reset counters; they are not durable totals. The collector does not create alert rules automatically. The full JSON traffic schema is in [API section 11.5](API.en-US.md#115-trafficsnapshot-and-sampling-validity).

An nft example that excludes unavailable/warming-up rate samples:

```promql
portbridge_rule_bytes_per_second{source="nft",direction="up"}
```

These rates are observations, not a guarantee of full flowtable accounting. See the [Linux flowtable counter documentation](https://www.kernel.org/doc/html/latest/networking/nf_flowtable.html#counters) and [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).
