# Go-nftables-portbridge v2.4.9 — Contributing / 贡献指南

## English

Keep contributions focused and explain their forwarding, security and compatibility impact. Use Go 1.27.1 to match the official installer and release-toolchain checks. Linux integration testing is needed for nftables, SO_REUSEPORT, epoll, splice and batched UDP.

For code changes, run:

```bash
go version  # go1.27.1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test -race ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go vet ./...
```

Run staticcheck, gosec, govulncheck and the affected shell/deployment checks when relevant. For UDP changes, measure 64/256/512/1400-byte datagrams, PPS, payload Gbps, CPU per core, syscall counts, allocations/GC, drops and p95/p99 latency; compare batch sizes 32/64/128 and multiple worker counts.

Session tables remain worker-local. Exact source budgets intentionally use 64 shared rule-level shards with short locks; do not describe that path as fully lock-free. Avoid adding a global packet-path lock, per-packet goroutines, channels, logging, JSON or database work.

For documentation-only changes, check both languages, defaults and command examples against current code. Preserve binaries and signatures during review. Before publishing documentation inside signed archives, regenerate source manifests, signatures and archive checksums; editing an extracted signed bundle invalidates its integrity checks.

Never commit runtime configurations, tokens, SSH credentials, private keys, logs, packet captures or private environment details. See [README.md](README.md), [SECURITY.md](SECURITY.md) and [UDP design](docs/udp-dataplane.md).

## 简体中文

保持修改聚焦，并说明对转发、安全和兼容性的影响。使用 Go 1.27.1，与正式安装器和发布工具链检查一致。nftables、SO_REUSEPORT、epoll、splice 和批量 UDP 需要 Linux 集成验证。

代码修改应执行上方测试、race 和 vet 命令，并按影响范围运行 staticcheck、gosec、govulncheck 以及 shell/部署检查。UDP 修改至少测试 64/256/512/1400 字节报文，记录 PPS、有效载荷 Gbps、各核心 CPU、syscall、分配/GC、丢包与 p95/p99 延迟，同时比较 32/64/128 batch 和不同 worker 数。

会话表保持 worker-local；精确来源预算有意使用规则级 64 分片短锁，不能描述为完全无锁。避免在逐包路径新增全局锁、每包 goroutine、channel、日志、JSON 或数据库操作。

仅文档修改应核对双语一致性、实际默认值和命令示例。审核期间保持二进制及签名不变；将文档更新进正式签名包前，需要重新生成源码清单、签名及压缩包摘要。直接修改已解压签名包的文档会使完整性校验失败。

不要提交运行配置、令牌、SSH 凭据、私钥、日志、抓包或私有环境信息。参阅[中文 README](README.zh-CN.md)、[安全说明](SECURITY.md)和 [UDP 设计](docs/udp-dataplane.md)。
