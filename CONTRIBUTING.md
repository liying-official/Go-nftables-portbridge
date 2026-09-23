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

### Test results and reproducibility

Report the exact Go version, commands, OS/kernel family and test result. Distinguish passed, skipped, failed and environment-blocked tests; `go test` can succeed with integration tests skipped. Use a disposable host or new namespaces for tests that manipulate nftables, interfaces, routing, mounts or sysctls. Never run topology/cleanup experiments against an unrelated production firewall.

The `scripts/test-clean-go-netns.sh`, `scripts/test-recovery-boot-bind.sh` and `scripts/test-recovery-proc-subset.sh` drivers require a compiled proxy test executable, not the service binary. The boot-bind component test is not a full systemd/ProcSubset integration test. Consult the driver source and prerequisites before execution; do not fake missing tools to turn a skip into a pass.

### Documentation changes

Update English and Chinese together. Preserve API field names, complete-replacement semantics, authentication/CSRF requirements and runtime-vs-desired-state distinctions. Validate shell/Python/JSON/YAML examples and relative links in a complete source checkout.

Use [the publication checklist](docs/PUBLISHING.md) before submitting screenshots, logs or evidence. Generated test credentials and private keys are not suitable evidence attachments. Documentation revisions covered by release manifests must be included before the publisher regenerates and signs a release; do not claim old signatures still authenticate modified files.

## 简体中文

源码开发使用 Go 1.27.1。nftables、SO_REUSEPORT、epoll、splice 和批量 UDP 路径使用 Linux 系统能力。

测试、race 和 vet 命令见本文代码块。反馈问题时请提供最小复现、预期行为和实际行为。数据面说明见 [UDP 设计](docs/udp-dataplane.md)和[转发边界](docs/forwarding-limits.md)。

不要提交运行配置、令牌、SSH 凭据、私钥、日志、抓包或私有环境信息。参阅[中文 README](README.zh-CN.md)、[安全说明](SECURITY.md)和 [UDP 设计](docs/udp-dataplane.md)。

### 测试结果与复现

请记录实际 Go 版本、命令、操作系统/内核类型与结果，区分通过、跳过、失败和环境阻断。`go test` 成功时仍可能有集成测试被跳过。操作 nftables、接口、路由、挂载或 sysctl 的测试应在可丢弃主机或新命名空间运行，不要对无关生产防火墙执行拓扑或清理实验。

`scripts/test-clean-go-netns.sh`、`scripts/test-recovery-boot-bind.sh` 和 `scripts/test-recovery-proc-subset.sh` 需要编译后的 proxy 测试程序，不是服务二进制。boot-bind 组件测试不能替代完整 systemd/ProcSubset 集成。执行前应阅读脚本与前置条件，不要伪造缺失工具把跳过变成通过。

### 文档变更

中英文应同步更新。保留 API 字段名、完整替换语义、认证/CSRF 要求，以及运行态与期望态的区别。在完整源码检出中校验 shell/Python/JSON/YAML 示例与相对链接。

提交截图、日志或证据前使用[发布检查表](docs/PUBLISHING.md)。测试生成的凭据与私钥也不能作为证据附件公开。被发布清单覆盖的文档应在发布者重新生成并签署清单前完成修改，不能声称旧签名继续覆盖改后的文件。
