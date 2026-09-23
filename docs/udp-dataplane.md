# Go-nftables-portbridge v2.5.0 — UDP dataplane / UDP 数据面

## English

### Scope and forwarding path

Forced `GO` rules and cross-family/wildcard-loopback fallback use the Go proxy. Eligible same-family rules with `nftables preferred` use DNAT/SNAT and optional flowtable acceleration; a firewall/admission failure does not guarantee automatic Go fallback. Go connection/session/rate/memory limits do not cover kernel forwarding. WebGUI combines Go payload and best-effort nft L3 cumulative observations into an approximate total, while displaying rates separately. API and Prometheus retain separate sources; see [monitoring](MONITORING.en-US.md).

```text
UDP listener → SO_REUSEPORT workers → ReadBatch/recvmmsg
             → worker-local session lookup → connected upstream socket
             → WriteBatch/sendmmsg → destination
```

- Each worker owns its listener, packet slabs, batch messages, flow/session table, epoll instance, timing wheel and statistics. One worker goroutine services its listener and connected upstream sockets; there is no per-session or per-packet goroutine.
- IPv4 and IPv6 use separate sockets. Same-family and cross-family forwarding use the same session model.
- Packet/message/address structures are preallocated and reused. Mixed-session batches are grouped using reusable packet indices; `netip.AddrPort` is the explicit-bind session key; wildcard keys also include local destination and necessary interface scope. Empty datagrams remain budgeted packets.
- The `x/net/internal/socket` patch reuses a pre-populated UDP address and IP backing array; see [vendored patches](../VENDOR_PATCHES.md).
- Session lookup is worker-local. Source accounting uses 64 rule-level shards shared across Go workers, port ranges, address families and fallback runners. A packet holds one short source-budget lock, never across socket I/O or creation.
- Source session/rate reservations are rolled back on creation failure and released on timeout/shutdown. Time-based refill uses monotonic elapsed time. Rate limits are token buckets with bounded bursts, not fixed-window packet counts.
- Expiry uses a 512-slot, one-second worker-local timing wheel. Shared idle-source cleanup is bounded to four shards and 256 entries per shard per incremental sweep; active source records are retained.
- Truncated datagrams exceeding `udp_packet_buffer_size` are dropped and counted; partial payloads are not forwarded. JSON, database work and per-packet logging remain outside the forwarding path.

Wildcard reply control data is owned per session, OOB slabs are reused, and new costs are reserved within unchanged budgets. Global replies follow routing; scoped addresses retain interface identity. See [forwarding limits](forwarding-limits.md).

Batch syscall failures may return `-1` with an error. The worker preserves that error with zero completed packets instead of misclassifying it as malformed counts. EAGAIN/EWOULDBLOCK, ENOBUFS, ENOMEM and EINTR on send do not destroy an otherwise valid session; unsent packets are counted as drops. Invalid counts and fatal descriptor failures are still rejected. This does not guarantee zero loss under overload or add buffering/retry queues.

### Defaults and capacity boundaries

| Setting | v2.5.0 default |
|---|---|
| Automatic rule worker budget | `min(GOMAXPROCS, 16)`; each listener endpoint still needs at least one worker |
| Batch size | `64` messages |
| Packet buffer | `2048` bytes |
| Listener socket buffer request | `4 MiB` |
| Connected session buffer request | `64 KiB` |
| Global UDP session / estimated memory budget | `16384` / `1 GiB` |
| Per-rule / per-source sessions | `4096` / `512` |
| Per-source new-session / packet refill rate | `1000/s` / `100000/s` |
| UDP idle timeout | `60` seconds |

The worker budget is spread across a rule's listening endpoints. When endpoints outnumber the budget, at least one worker per endpoint means the actual total can exceed it. Main payload slabs use approximately `2 × batch size × packet buffer`: `256 KiB` per worker with defaults. This excludes maps, metadata, kernel socket memory and other process overhead.

Use a packet buffer appropriate to the application's largest datagram. Avoid increasing every buffer to 65535 bytes without measuring the memory cost. Linux socket-buffer accounting may be roughly twice the requested value; the application budget is an estimate, not an exact RSS cap.

The installer configures `net.core.rmem_max=16777216`, `net.core.wmem_max=16777216` and `net.core.netdev_max_backlog=65536`, as well as IPv4/IPv6 forwarding. Review the host's actual settings and other services before tuning.

### Performance tuning

Throughput and latency depend on packet size, active flow count, batch size, worker count, CPU placement, kernel and NIC. Compare settings using the expected workload before changing production limits.

Monitor received PPS, payload throughput, per-core CPU, allocations/GC, kernel/application drops and tail latency. Loopback and physical-NIC measurements are not interchangeable; overload latency should be considered separately from low-load latency.

The Web control plane reads snapshots with serialized polling, scheduling the next request about 500 ms after the previous one finishes; it does not perform per-packet work. It does not guarantee line-rate throughput or zero loss.

### Advanced options

The Go dataplane does not implement UDP GRO/GSO enablement or expose a switch for it. Adding it would need ancillary-data handling, segment validation, MTU/PMTU checks and tested fallbacks; GSO chiefly helps compatible segments for one destination, not arbitrary mixed flows. Investigate it only after profiling.

Check NIC RX/TX queues, RSS distribution, IRQ/CPU/NUMA placement and socket/softnet/NIC drop counters first. RPS/XPS and CPU affinity need workload-specific validation; the program does not pin every worker with `LockOSThread` by default.

nftables/flowtable integrates naturally with same-family NAT. Go batch forwarding supports cross-family paths with moderate implementation cost. XDP/eBPF, AF_XDP and DPDK can provide lower-level processing but require substantially more work on state, routing/neighbours, queues, memory and operational isolation; they are alternatives, not enabled components of v2.5.0.

### Version scope and publication

This document describes v2.5.0 implementation and resource models, not measured throughput or a capacity guarantee. Buffer-size arithmetic is not an RSS measurement. Batch availability, socket pressure and scheduler behavior depend on the Linux environment. Go UDP limits do not become nftables limits, and this release's flowtable configuration does not request NIC hardware offload.

When sharing diagnostics, use synthetic endpoints and remove real source addresses, target domains, packet payloads, namespace identifiers and host paths.

[Forwarding limits](forwarding-limits.md) · [API](API.en-US.md) · [Documentation](INDEX.md)

## 简体中文

### 范围与转发路径

强制 `GO` 规则、跨地址族以及通配回环 fallback 使用 Go 代理；符合条件的同族“nftables 优先”规则使用 DNAT/SNAT 及可选 flowtable 加速，防火墙或准入失败不保证自动回退 Go。Go 连接/会话/速率/内存限额不覆盖内核转发。WebGUI 将 Go 有效载荷与 nft L3 累计观测值合并为近似总量，速率分别显示；API 与 Prometheus 保留独立来源，详见[统计说明](MONITORING.zh-CN.md)。

- 每个 worker 拥有监听 socket、packet slab、batch message、会话表、epoll、时间轮和统计。一个 worker goroutine 同时处理入口及 connected 上游 socket，不按会话或数据报创建 goroutine。
- IPv4/IPv6 socket 独立，同族和跨族沿用同一会话模型。
- 预分配并复用报文、消息和地址结构；交错 batch 使用可复用索引聚合，以 `netip.AddrPort` 为明确绑定会话键；通配 key 同时包含本地目的地址与必要 scope。空数据报仍是计数和消耗配额的真实报文。`x/net/internal/socket` 的地址复用补丁见[依赖补丁说明](../VENDOR_PATCHES.md)。
- 会话查找是 worker-local；来源计数由规则级 64 分片在 Go worker、端口段、地址族及 fallback 间共享。每包只持有一个短锁，锁不跨 socket 创建或 I/O。
- 会话创建失败会回滚预留，超时/停止会释放计数；补充令牌使用单调时间差。速率是允许受限突发的令牌桶，不是固定窗口内严格包数。
- 使用 512 槽、1 秒粒度的 worker-local 时间轮；共享空闲来源每次增量清理最多检查 4 个分片、每片 256 项，不删除活跃来源。
- 超出 `udp_packet_buffer_size` 并被截断的报文会丢弃并计数，不转发残缺数据；逐包路径不做 JSON、数据库或日志操作。

通配回复控制数据归会话独立持有，OOB slab 复用，新增开销计入既有预算；全局地址按路由回程，scoped 地址保留接口身份。参见[转发限制](forwarding-limits.md)。

### 默认值与容量边界

批量系统调用失败可能返回 `-1` 和错误；worker 将其保留为零完成量及原错误，不再误判成非法计数。发送时的 EAGAIN/EWOULDBLOCK、ENOBUFS、ENOMEM、EINTR 不销毁仍有效的会话，未发送包计入丢弃；非法计数和致命描述符错误仍然拒绝。这不保证过载零丢包，也不新增缓冲或重试队列。

| 设置 | v2.5.0 默认值 |
|---|---|
| 自动整规则 worker 预算 | `min(GOMAXPROCS, 16)`，每个监听端点仍至少需要 1 个 worker |
| Batch 大小 | `64` |
| Packet buffer | `2048` 字节 |
| 监听 socket buffer 请求 | `4 MiB` |
| Connected 会话 buffer 请求 | `64 KiB` |
| 全局 UDP 会话 / 估算内存预算 | `16384` / `1 GiB` |
| 单规则 / 单来源会话 | `4096` / `512` |
| 单来源新会话 / 报文令牌补充速率 | `1000/s` / `100000/s` |
| UDP 空闲超时 | `60` 秒 |

worker 预算在整条规则的监听端点间分摊；端点数超过预算时，因每个端点至少 1 个 worker，实际总数可能更高。主要 payload slab 约为 `2 × batch大小 × packet buffer`，默认每 worker `256 KiB`；不包含 map、元数据、内核 socket 内存及其他开销。

按实际最大应用数据报选择 buffer，不要未经测量就统一改成 65535 字节。Linux socket buffer 计账可能约为请求值两倍，应用预算是估算值而非精确 RSS 上限。

安装器设置 `net.core.rmem_max=16777216`、`net.core.wmem_max=16777216`、`net.core.netdev_max_backlog=65536` 以及 IPv4/IPv6 forwarding。调整前应核对主机实际设置与其他服务。

### 性能调优

吞吐与延迟取决于报文大小、活跃 flow 数、batch、worker 数、CPU 分布、内核及网卡。修改生产限制前，应使用预期业务负载比较不同设置。

关注接收 PPS、有效载荷吞吐、各核心 CPU、分配/GC、内核及应用丢包和尾部延迟。回环与物理网卡测量不能互相替代；过载与低负载延迟应分别考虑。

Web 串行轮询并读取快照，上一次请求完成后约 500 ms 发起下一次，不参与逐包工作；不保证线速吞吐或零丢包。

### 高阶选项

Go 数据面未实现 UDP GRO/GSO 启用逻辑，也没有对应配置开关。增加这类能力需要 ancillary data 处理、segment 校验、MTU/PMTU 检查和回退验证；GSO 主要适用于同目标的兼容分段，不能直接合并任意多 flow。应先通过 profile 确认收益。

先检查 NIC 队列、RSS、IRQ/CPU/NUMA 分布及 socket/softnet/NIC 丢包；RPS/XPS 和绑核需要业务验证。程序默认不以 `LockOSThread` 固定每个 worker。

nftables/flowtable 适合同族 NAT；Go batch 代理以适中的维护成本支持跨族。XDP/eBPF、AF_XDP 和 DPDK 提供更底层处理能力，但增加状态、路由/邻居、队列、内存及运维隔离成本；它们是可评估的替代方案，不是 v2.5.0 已启用的数据面。


### 版本范围与公开材料

本文说明 v2.5.0 的实现与资源模型，不是实测吞吐或容量保证；缓冲大小计算不等于 RSS 实测。批量能力、套接字压力和调度行为受 Linux 环境影响。Go UDP 的限制不会变成 nftables 的限制，当前 flowtable 配置也不请求网卡硬件卸载。

分享诊断时使用合成端点，删除真实来源地址、目标域名、报文载荷、命名空间标识与机器路径。

[转发边界](forwarding-limits.md) · [中文 API](API.zh-CN.md) · [文档索引](INDEX.md)
