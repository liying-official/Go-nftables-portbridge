# PortBridge — v2.5.0

**面向 Linux 的 TCP / UDP 端口转发工具，提供中英双语 Web 管理界面和需要认证的 HTTP API。**

[![Release](https://img.shields.io/github/v/release/liying-official/Go-nftables-portbridge)](https://github.com/liying-official/Go-nftables-portbridge/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Linux](https://img.shields.io/badge/platform-Linux-informational)
![amd64 / arm64](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-informational)

[English](README.md) | **简体中文**

PortBridge 将适用于符合条件流量的 nftables DNAT/SNAT、可选的 **software flowtable 软件加速**，与支持跨地址族转发的 Go TCP/UDP 代理结合。通过浏览器即可管理规则、查看运行状态和轮换管理员令牌。

[安装指南](docs/INSTALL.zh-CN.md) · [API 文档](docs/API.zh-CN.md) · [完整文档](docs/INDEX.md) · [发布版本](https://github.com/liying-official/Go-nftables-portbridge/releases)

[体验 WebUI 演示](https://liying-official.github.io/Go-nftables-portbridge/?lang=zh-CN) — 公开演示密码：**`PortBridge`**。数据仅在浏览器内模拟，不连接真实管理 API，也不转发流量；请勿输入真实凭据。详见[演示边界](docs/DEMO.md)。

本文档适用于 **v2.5.0**。动态版本徽章和交互式安装器可能指向其他已发布版本；部署时应使用与所选发布包匹配的文档。

## 主要功能

| 功能 | v2.5.0 提供的能力 |
|---|---|
| 端口转发 | TCP、UDP 或两者同时；单端口及最多 4096 个端口的等长端口段映射。 |
| 地址族 | IPv4 → IPv4、IPv6 → IPv6、IPv4 → IPv6、IPv6 → IPv4。 |
| 数据面选择 | 在符合条件时优先使用 nftables，或明确选择 Go 代理；通配监听可能形成混合路径。 |
| 管理界面 | English / 简体中文 Tabler 界面、规则编辑、设置与 Bearer 认证 API；写操作另需 CSRF 校验，界面资源由本机提供。详见[中文 API 文档](docs/API.zh-CN.md)。 |
| 可观测性 | 运行状态、Go 载荷计数、独立的 nft/conntrack 尽力采样，以及需要认证的 Prometheus 指标。 |
| 部署 | 发布包验签安装、原生 HTTPS、独立账户与加固的 systemd 服务；发布打包目标为 Linux amd64 / arm64。 |

两种语言的发布包都包含同一个双语界面，包语言决定初始显示语言。浏览器用 `localStorage` 保存语言偏好，管理员令牌只放在当前标签页的 `sessionStorage`。

## 快速开始

先选择符合管理方式的安装流程：

| 安装方式 | 管理端口暴露范围 | 适用场景 |
|---|---|---|
| **[固定 v2.5.0 的验签安装](docs/INSTALL.zh-CN.md)** | 默认在 `127.0.0.1` / `::1` 的 `9080` 端口提供 HTTPS。 | 推荐使用 SSH 隧道管理。 |
| **[交互式全新安装](docs/ONECLICK.zh-CN.md)** | 在 `0.0.0.0` 及可用 IPv6 接口提供 HTTPS，由持久化严格 IP 白名单限制访问。 | Debian/Ubuntu；选择最新的已发布稳定版。 |

使用允许相应网络操作的 Linux 主机。服务安装器需要 systemd 和管理员权限，受限容器不能等同于完整主机。预编译包不需要 Go 编译器。执行下载包内脚本前先验证发布者签名；签名缺失应停止，而不是绕过校验。

完成仅回环监听的安装后，在管理电脑上建立 SSH 隧道：

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:9080:127.0.0.1:9080 USER@SERVER
```

将 `USER`、`SERVER` 换成 SSH 账户与服务器地址。打开 **https://127.0.0.1:9080/**，核对证书指纹并建立信任，再用服务器上 `/etc/portbridge/admin.token` 中的令牌登录。不要公开令牌或安装输出。完整[安装指南](docs/INSTALL.zh-CN.md)包含验签、证书导入、升级与卸载流程。

全新安装没有转发规则。添加自有目标，保存规则并查看运行状态，再用真实 TCP/UDP 应用请求确认可用。[示例配置](docs/CONFIGURATION.md)不是生产默认配置，其中的演示规则默认禁用。

## 理解实际转发路径

| 规则类型 | 预期规划行为 |
|---|---|
| 符合条件的同地址族流量 | nftables DNAT/SNAT；周边防火墙满足安全准入时可启用 software flowtable 软件加速。 |
| IPv4 ↔ IPv6、显式回环或带作用域目标 | 根据规划器要求使用 Go 代理。 |
| `data_plane: "go"` | 明确选择 Go 代理。 |
| `listen_host: "*"` | 分别规划 IPv4、IPv6；专用回环处理可能形成混合路径。 |

配置中的偏好不等于已生效的数据面。应检查 `/api/status` 的 `data_plane`、`go_running`、`kernel_state` 和错误。nftables 失败**不保证自动回退到 Go**。当前代码不添加 flowtable 的 `flags offload`，不能据此承诺网卡硬件卸载。

访问私有目标必须同时启用 `allow_private_target` 并填写窄范围、能匹配目标的 `target_cidr_allowlist`。后者用于授权原本受限的目标，不是对所有公网出站目标生效的总白名单。与其他防火墙或 NAT 管理器共存前，请阅读[转发边界](docs/forwarding-limits.md)。

## 安全与运维边界

管理白名单保护 WebUI/API，**不限制转发端口**，转发端口需要单独保护。源码开发配置在准备 TLS 前可以使用回环 HTTP；安装后的服务强制 HTTPS。直接暴露管理端口必须配合原生 TLS、严格的直连来源白名单和主机/云防火墙。应用不信任转发客户端地址头。

Go 的连接、会话与速率预算不会自动限制 nftables 流量。Go 载荷计数与 nft L3 计数口径不同，界面合计仅为近似展示，不能累加各 hook 计数。HTTP 成功和服务 active 都不等于端到端业务健康。详见[安全说明](SECURITY.md)和[监控说明](docs/MONITORING.zh-CN.md)。

## 开发

源码检出和 GitHub 自动生成的 Source code 归档不含预编译二进制。使用 **Go 1.27.1** 和随源码提供的 vendor 依赖，在仓库根目录运行：

```bash
go version
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go test -race ./...
GOTOOLCHAIN=local GOFLAGS=-mod=vendor GOPROXY=off go vet ./...
```

部分 Linux 集成测试需要额外工具、权限和隔离命名空间，跳过不代表通过。`make dist` 生成未签名的开发二进制，不是发布者签名的可安装 Release 包。详见[贡献指南](CONTRIBUTING.md)与[依赖补丁](VENDOR_PATCHES.md)。

## 文档与反馈

[安装](docs/INSTALL.zh-CN.md) · [API](docs/API.zh-CN.md) · [监控](docs/MONITORING.zh-CN.md) · [UDP 设计](docs/udp-dataplane.md) · [版本说明](RELEASE_NOTES.zh-CN.md) · [发布检查表](docs/PUBLISHING.md)

普通问题可通过 [GitHub Issues](https://github.com/liying-official/Go-nftables-portbridge/issues) 提供最小复现与脱敏日志。疑似安全漏洞请遵循[安全报告流程](SECURITY.md)，不要公开令牌、私钥或未经脱敏的部署信息。

## 许可证

PortBridge 使用 [MIT 许可证](LICENSE)。随包依赖保留各自的许可声明，参见[依赖补丁与界面资源许可](VENDOR_PATCHES.md)。
