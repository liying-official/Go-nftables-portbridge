# v2.5.0 forwarding limits / 转发限制

## English

Selective ACL compatibility is bounded, not arbitrary firewall interpretation. Relevant filter chains may use accept or drop policy, but rules must contain supported literal, side-effect-free predicates followed by accept. Each direction and NAT view must cover the whole configured domain; client addresses and ports are unknown and partial unions are not inferred.

Explicit drop/reject, stateful predicates, counters/logging, jumps, sets/maps, unknown metadata and nonempty external NAT cannot receive a selective acceleration grant. A client whitelist usually cannot cover an unknown client domain. Conservative suspension does not imply the external firewall denies every client.

Grants are scoped to rule identity and original connection tuples, not a whole family or shared backend. Two snapshots and periodic refresh are not atomic with privileged firewall edits and do not reauthorize each cached packet. Invisible iptables-legacy, tc/eBPF rewriting and other NAT engines are outside this proof. Coordinate NAT-only operation explicitly; there is no automatic Go/NAT-only fallback.

Exact connection retirement requires protected same-identity ownership records. Missing ownership never authorizes deletion by a shared mark. Deleting a table does not prove old connections stopped. Startup can withhold forwarding during kernel inventory changes: verify rule health and real traffic, not only systemd ActiveState.

Go UDP uses bounded sessions and buffers. Temporary send pressure counts unsent packets as drops while retaining valid sessions; there is no unbounded retry queue. Capacity and latency depend on deployment. The generated flowtable uses software acceleration: it has `counter` but no `flags offload`, so this release does not request NIC hardware offload. Release archives and SBOM are authenticated by signed SHA256SUMS. Each prebuilt package has a signed internal manifest; local rebuilds are not automatically publisher-signed.

### Operational interpretation

| Signal | What it proves | What it does not prove |
|---|---|---|
| Rule POST/PUT/DELETE success (`201` / `200` / `204`) | Desired rule configuration was persisted and Apply was invoked | End-to-end reachability or completed old-flow retirement |
| systemd `active` | The unit reports an active state | A stable running process or every rule forwarding |
| `active-verified` | Manager has verified corresponding kernel evidence | Application health or NIC hardware offload |
| Strict management ACL | Direct-peer admission to Web/API | Client filtering on forwarding ports |

A private target needs both the opt-in flag and a matching narrow CIDR. That CIDR list does not filter every public destination. Go budgets apply only to Go paths. Deleting a rule requests retirement, but a pending/unknown cleanup state must be examined rather than hidden by deleting records.

[API](API.en-US.md) · [Security](../SECURITY.md) · [Documentation](INDEX.md)

## 简体中文

选择性 ACL 兼容是有界证明，不解释任意防火墙。相关 filter 链可用 accept/drop 默认策略，但规则必须由受支持、无副作用的常量条件加 accept 组成。每个方向及 NAT 视图必须覆盖整个配置域；客户端地址和端口视为未知，不推断局部许可的并集。

显式 drop/reject、状态条件、计数/日志、跳转、集合、未知元数据及非空外部 NAT 不能取得选择性加速许可。来源白名单通常不能覆盖未知客户端域。保守暂停不表示外部防火墙必然拒绝所有客户端。

许可绑定规则身份及原始连接元组，不按整个地址族或共享后端授权。两次快照及周期刷新不与特权防火墙修改构成原子事务，也不逐包重新授权缓存流量。不可见的 iptables-legacy、tc/eBPF 改写及其他 NAT 引擎不在证明范围。须显式协调 NAT-only，不自动回退至 Go/NAT-only。

精确撤销依赖受保护的同身份归属记录。归属缺失不允许按共享 mark 删除连接；删表不等于旧连接停止。启动时库存变化可能暂时阻止转发，应检查规则健康及实际流量，而不只看 systemd ActiveState。

Go UDP 使用有界会话和缓冲。暂时发送压力下，未发送包计入丢弃而保留有效会话，不使用无界重试队列。容量与延迟取决于部署环境。当前生成的 flowtable 使用软件加速，含 `counter`、不含 `flags offload`，本版本不请求网卡硬件卸载。Release 归档及 SBOM 通过已签名 SHA256SUMS 认证，每个预编译包包含内部签名清单；本地重新构建产物不会自动获得发布者签名。


### 运维解释

| 信号 | 能说明什么 | 不能说明什么 |
|---|---|---|
| 规则 POST/PUT/DELETE 成功（`201` / `200` / `204`） | 期望规则配置已保存并调用 Apply | 端到端可达或旧流已完全撤销 |
| systemd `active` | 单元报告活动状态 | 进程稳定运行或所有规则转发正常 |
| `active-verified` | 管理器验证了相应内核证据 | 应用健康或网卡硬件卸载 |
| 严格管理 ACL | Web/API 的直连来源准入 | 转发端口的来源过滤 |

私有目标需要双重授权：开启允许标志，并命中窄范围 CIDR。该 CIDR 列表并不限制每个公网目标。Go 预算仅作用于 Go 路径。删除规则会请求撤销，但 pending/unknown 清理状态必须继续检查，不应通过删除记录掩盖。

[中文 API](API.zh-CN.md) · [安全](../SECURITY.md) · [文档索引](INDEX.md)
