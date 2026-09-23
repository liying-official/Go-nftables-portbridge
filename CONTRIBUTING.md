# Go-nftables-portbridge v2.5.0 — Contributing / 贡献指南

## English

Use Go 1.27.1 for source development. The nftables, SO_REUSEPORT, epoll, splice and batched UDP paths use Linux facilities.

For code changes, run:

```bash
go version  # go1.27.1
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test -race ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go vet ./...
```

For bug reports, provide a minimal reproduction and the expected and observed behavior. The [UDP design](docs/udp-dataplane.md) and [forwarding limits](docs/forwarding-limits.md) describe the data planes.

Never commit runtime configurations, tokens, SSH credentials, private keys, logs, packet captures or private environment details. See [README.md](README.md), [SECURITY.md](SECURITY.md) and [UDP design](docs/udp-dataplane.md).

## 简体中文

源码开发使用 Go 1.27.1。nftables、SO_REUSEPORT、epoll、splice 和批量 UDP 路径使用 Linux 系统能力。

可使用上方命令执行测试、race 和 vet。反馈问题时请提供最小复现、预期行为和实际行为。数据面说明见 [UDP 设计](docs/udp-dataplane.md)和[转发边界](docs/forwarding-limits.md)。

不要提交运行配置、令牌、SSH 凭据、私钥、日志、抓包或私有环境信息。参阅[中文 README](README.zh-CN.md)、[安全说明](SECURITY.md)和 [UDP 设计](docs/udp-dataplane.md)。
