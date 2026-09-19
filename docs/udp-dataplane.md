# Go-nftables-portbridge v2.4.9 — UDP dataplane / UDP 数据面

## English

### Scope and forwarding path

Forced `GO` rules and cross-family/wildcard-loopback fallback use the Go proxy. Same-family rules with `nftables preferred` use DNAT/SNAT and eligible flowtable acceleration. Go connection/session/rate/memory limits and Web proxy counters do not cover kernel forwarding; use nftables, conntrack and firewall controls for that path.

```text
UDP listener → SO_REUSEPORT workers → ReadBatch/recvmmsg
             → worker-local session lookup → connected upstream socket
             → WriteBatch/sendmmsg → destination
```

- Each worker owns its listener, packet slabs, batch messages, flow/session table, epoll instance, timing wheel and statistics. One worker goroutine services its listener and connected upstream sockets; there is no per-session or per-packet goroutine.
- IPv4 and IPv6 use separate sockets. Same-family and cross-family forwarding use the same session model.
- Packet/message/address structures are preallocated and reused. Mixed-session batches are grouped using reusable packet indices; `netip.AddrPort` is the explicit-bind session key; wildcard keys also include local destination and necessary interface scope. Empty datagrams remain budgeted packets.
- The documented local `x/net/internal/socket` patch reuses a pre-populated UDP address and IP backing array; see [vendored patches](../VENDOR_PATCHES.md).
- Session lookup is worker-local. Source accounting uses 64 rule-level shards shared across Go workers, port ranges, address families and fallback runners. A packet holds one short source-budget lock, never across socket I/O or creation.
- Source session/rate reservations are rolled back on creation failure and released on timeout/shutdown. Time-based refill uses monotonic elapsed time. Rate limits are token buckets with bounded bursts, not fixed-window packet counts.
- Expiry uses a 512-slot, one-second worker-local timing wheel. Shared idle-source cleanup is bounded to four shards and 256 entries per shard per incremental sweep; active source records are retained.
- Truncated datagrams exceeding `udp_packet_buffer_size` are dropped and counted; partial payloads are not forwarded. JSON, database work and per-packet logging remain outside the forwarding path.

Wildcard reply control data is owned per session, OOB slabs are reused, and new costs are reserved within unchanged budgets. Global replies follow routing; scoped addresses retain interface identity. See [forwarding limits](forwarding-limits.md).

Batch syscall failures may return `-1` with an error. The worker preserves that error with zero completed packets instead of misclassifying it as malformed counts. EAGAIN/EWOULDBLOCK, ENOBUFS, ENOMEM and EINTR on send do not destroy an otherwise valid session; unsent packets are counted as drops. Invalid counts and fatal descriptor failures are still rejected. This does not guarantee zero loss under overload or add buffering/retry queues.

### Defaults and capacity boundaries

| Setting | v2.4.9 default |
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

### Measuring the current build

Record the exact source revision, Go 1.27.1 build, kernel, NIC, MTU, traffic topology, flow count, batch size, worker count and CPU placement. Test 64/256/512/1400-byte datagrams, batches 32/64/128, and several worker counts.

Report received PPS, payload Gbps, per-core CPU, syscall counts, allocations/GC, kernel/application drops, RTT or explicitly defined one-way latency, p95/p99 latency and scaling efficiency. Separate loopback/namespace results from physical-NIC results and low-load latency from overload latency. Do not present historical benchmarks as current-build production capacity.

The Web control plane polls serially every 500 ms and reads snapshots; it does not perform per-packet work. Current documentation makes no measured line-rate or zero-loss capacity promise.

### Advanced options

UDP GRO/GSO is not enabled by default. It needs ancillary-data handling, segment validation, MTU/PMTU checks and tested fallbacks; GSO chiefly helps compatible segments for one destination, not arbitrary mixed flows. Investigate it only after profiling.

Check NIC RX/TX queues, RSS distribution, IRQ/CPU/NUMA placement and socket/softnet/NIC drop counters first. RPS/XPS and CPU affinity need workload-specific validation; the program does not pin every worker with `LockOSThread` by default.

nftables/flowtable integrates naturally with same-family NAT. Go batch forwarding supports cross-family paths with moderate implementation cost. XDP/eBPF, AF_XDP and DPDK can provide lower-level processing but require substantially more work on state, routing/neighbours, queues, memory and operational isolation; they are alternatives, not enabled components of v2.4.9.

## 简体中文

### 范围与转发路径

强制 `GO` 规则、跨地址族以及通配回环 fallback 使用 Go 代理；同族且选择“nftables 优先”的规则使用 DNAT/SNAT 和符合条件的 flowtable 加速。Go 连接/会话/速率/内存限额及 Web 代理计数不覆盖内核转发，后者应通过 nftables、conntrack 和防火墙管理。

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

| 设置 | v2.4.9 默认值 |
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

### 当前构建的测试方法

记录源码 revision、Go 1.27.1、内核、NIC、MTU、拓扑、flow 数、batch、worker 数和绑核情况。至少测试 64/256/512/1400 字节报文、32/64/128 batch 和多个 worker 数。

报告接收 PPS、有效载荷 Gbps、各核心 CPU、syscall、分配/GC、内核及应用丢包、定义清楚的 RTT/单向延迟、p95/p99 和扩展效率。区分 loopback/namespace 与物理 NIC，区分低负载和过载延迟；历史压测不应表述成当前构建的生产容量。

Web 每 500 ms 串行轮询并读取快照，不参与逐包工作；当前文档不承诺已测线速或无丢包容量。

### 高阶选项

默认不启用 UDP GRO/GSO。它们需要 ancillary data 处理、segment 校验、MTU/PMTU 检查和回退验证；GSO 主要适用于同目标的兼容分段，不能直接合并任意多 flow。应先通过 profile 确认收益。

先检查 NIC 队列、RSS、IRQ/CPU/NUMA 分布及 socket/softnet/NIC 丢包；RPS/XPS 和绑核需要业务验证。程序默认不以 `LockOSThread` 固定每个 worker。

nftables/flowtable 适合同族 NAT；Go batch 代理以适中的维护成本支持跨族。XDP/eBPF、AF_XDP 和 DPDK 提供更底层处理能力，但增加状态、路由/邻居、队列、内存及运维隔离成本；它们是可评估的替代方案，不是 v2.4.9 已启用的数据面。
