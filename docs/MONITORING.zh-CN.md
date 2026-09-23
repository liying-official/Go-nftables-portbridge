# 流量统计与 Prometheus — v2.5.0

[English](MONITORING.en-US.md)

控制器每秒采样一次，WebGUI 约每 500 ms 显示最新样本；API 请求和 Prometheus 抓取不会额外触发 nft/conntrack 命令。采集有资源和超时限制，控制面繁忙时跳过采样。样本超过三秒即标为不可用；首次采样、失败恢复及计数下降时，须取得有效差值后才显示速率。

## 统计来源与边界

- `traffic.go`：Go 有效载荷字节。Linux 上通过 TCP_INFO 的已确认字节观察活动 TCP 连接，不包装 `io.Copy`，不关闭 splice；连接结束时以复制结果结算。UDP 由 worker 维护阶段发布计数；该 Go 序列中的包数字段仅表示 UDP。
- `traffic.nft`：尽力采集的 conntrack L3 字节和包数。按实例 mark、地址族、协议、原始监听元组、后端元组、端口偏移及 common zone/连接身份归属；原始方向为上行，回复方向为下行。它不等于 Go 有效载荷；WebGUI 将两者累计值合并为近似展示值，实时速率仍分开显示。API 和 Prometheus 保留独立来源，合计展示值不是统一口径的有效载荷或计费数据。
- `traffic.nft_hooks`：实际 nftables 规则计数，按 `prerouting`、`output`、`postrouting`、`forward` 或 `flowtable` 分组。同一报文可能经过多个 hook；NAT counter 通常只计建立映射的首包，flowtable 命中会绕过普通转发 hook。**不能将各 hook 相加，也不能当作完整转发吞吐量。**

flowtable 统计只做尽力采集。其 `counter` 选项可将计数同步到 conntrack，但同步有延迟；两次采样之间建立并销毁的短连接可能遗漏。硬件卸载、accounting 可用性、规则重建及采集间断也会影响覆盖范围。这些计数是进程内的观测累计值，不是计费账本或持久历史。统计采集不会关闭加速，也不改变转发或防火墙决策。

管理员可启用 conntrack 包数/字节 accounting：

```bash
sudo sysctl -w net.netfilter.nf_conntrack_acct=1
```

该设置有额外计数开销，通常影响新建连接。旧连接若没有 accounting，需要自然过期或重新建立后才能贡献计数；不要为此清空无关连接。采集器不会自动修改此设置。读取失败、归属未验证或缺少 accounting 时标为不可用，不伪装成零流量。conntrack 样本不完整时保留上一次完整基线并暂停 nft 速率，独立 hook 计数仍可能可用。

`GET /api/status` 的 `rules[].traffic` 包含 `go`、`nft`、`nft_hooks`、`nft_hooks_available`、`nft_hooks_sampled_at`、`nft_best_effort`、`nft_status` 和 `counter_resets`。两条序列包含字节/包累计值、`*_per_second` 速率、`sampled_at`、`interval_seconds`、`available`、`rate_ready`；使用速率前必须检查这两个有效标志。状态值包括 `pending`、`not_applicable`、`sampled`、`accounting_unavailable`、`unavailable`、`stale`。原有 `stats` 字段仍仅描述 Go 路径。

## Prometheus `/metrics`

`GET /metrics` 共用管理 HTTPS 监听、IP 白名单及管理员 Bearer 认证，不匿名开放，GET 不需要 CSRF。响应采用 Prometheus text 0.0.4 格式。此令牌仍拥有完整管理权限，必须保护凭据文件及抓取主机。指标按规则 ID/协议标记，不输出规则名称或转发端点地址。

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

替换示例主机名和证书路径，自签证书须先核对指纹并建立信任，不要用 `insecure_skip_verify` 绕过校验。将抓取主机的直连来源 IP 加入管理白名单。

主要指标：

- `portbridge_rule_bytes_total{rule_id,protocol,source="go|nft",direction="up|down"}`：按来源分别累计的观测字节。
- `portbridge_rule_bytes_per_second`：最新字节速率估计，预热或不可用时不输出；乘八可转换为 bit/s。
- `portbridge_rule_sample_available`、`portbridge_rule_rate_ready`、`portbridge_rule_sample_timestamp_seconds`：有效性和新鲜度。
- `portbridge_nft_packets_total`、`portbridge_nft_hook_bytes_total`、`portbridge_nft_hook_packets_total`、`portbridge_nft_hooks_available`、`portbridge_nft_counter_resets_total`：内核观测与计数重置诊断。
- `portbridge_go_active_tcp_connections`、`portbridge_go_active_udp_sessions`、`portbridge_go_udp_drops_total`：Go 资源与应用可见丢包。
- `portbridge_rule_running`：管理器运行/风险标志，**不等于端到端业务健康**。

以下 nft 速率序列在样本不可用或预热时不会输出：

```promql
portbridge_rule_bytes_per_second{source="nft",direction="up"}
```

速率表示已观测流量，不保证覆盖全部 flowtable 报文。参考 [Linux flowtable counter 文档](https://www.kernel.org/doc/html/latest/networking/nf_flowtable.html#counters)和 [Prometheus 格式说明](https://prometheus.io/docs/instrumenting/exposition_formats/)。
