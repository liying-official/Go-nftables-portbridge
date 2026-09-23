<h1 align="center">PortBridge</h1>

<p align="center">
  <strong>一个界面，管理 TCP / UDP 与 IPv4 / IPv6 端口转发。</strong>
</p>

<p align="center">
  <a href="https://github.com/liying-official/Go-nftables-portbridge/releases"><img src="https://img.shields.io/github/v/release/liying-official/Go-nftables-portbridge" alt="GitHub Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/platform-Linux-informational" alt="Platform: Linux">
  <img src="https://img.shields.io/badge/arch-amd64%20%7C%20arm64-informational" alt="Architecture: amd64 / arm64">
</p>

<p align="center">
  <a href="README.md">English</a> · <strong>简体中文</strong>
</p>

<p align="center">
  <a href="docs/INSTALL.zh-CN.md">开始安装</a> ·
  <a href="docs/API.zh-CN.md">API 文档</a> ·
  <a href="DOCUMENTATION_INDEX.md">完整文档</a> ·
  <a href="https://github.com/liying-official/Go-nftables-portbridge/releases">下载发布版</a>
</p>

**PortBridge 是一个面向 Linux 的自托管端口转发管理工具。** 它将 **nftables 内核转发**与 **Go TCP/UDP 代理**结合，提供中英双语 Web 界面和需要认证的 API，适合端口映射、服务转发以及 IPv4/IPv6 混合网络中的连接需求。

在浏览器中创建规则、调整设置、查看运行状态，无需为日常规则管理反复手写 nftables 命令。

## 为什么选择 PortBridge？

| 特色 | 你可以用它做什么 |
| --- | --- |
| **nftables + Go 双引擎** | 符合条件的同地址族流量使用 nftables，并可启用软件 flowtable 加速；跨地址族转发由 Go 代理处理，也可按规则明确选择 Go。 |
| **IPv4 / IPv6 双向互通** | 支持 IPv4 → IPv4、IPv6 → IPv6、IPv4 → IPv6 和 IPv6 → IPv4，在同一界面中管理不同转发方向。 |
| **灵活的端口映射** | 支持 TCP、UDP 或两者同时转发；支持单端口及最多 4096 个端口的等长端口段映射。 |
| **中英双语 Web 管理** | 创建、编辑、启用、禁用和删除规则，管理设置并轮换管理员令牌；界面资源随程序提供，不依赖外部 CDN。 |
| **状态、监控与自动化** | 查看运行状态和流量观测，通过认证 API 管理规则，使用需要认证的 Prometheus 指标接入监控。 |
| **内置管理防护** | 原生 HTTPS、管理员令牌、IP/CIDR 访问白名单，以及 API 写操作的 CSRF 校验。 |

## 安装

准备一台 **Linux amd64 / arm64** 主机，使用 **systemd** 管理服务，并具备 **root/sudo** 及所需网络权限。使用预编译发布包，**无需安装 Go**。

| 安装入口 | 适用场景 | 管理访问方式 |
| --- | --- | --- |
| **[发布包安装与升级](docs/INSTALL.zh-CN.md)** | 按指南指定版本安装，或升级现有部署。 | 默认仅在本机提供 HTTPS，适合通过 SSH 隧道管理。 |
| **[交互式全新安装](docs/ONECLICK.zh-CN.md)** | 在 Debian/Ubuntu 上交互配置语言、HTTPS 端口和管理白名单；仅用于全新安装。 | 对外监听 HTTPS，并以严格 IP 白名单限制访问。 |

请使用 [Releases](https://github.com/liying-official/Go-nftables-portbridge/releases) 中对应架构的预编译附件，按安装文档**先验签，再安装**；不要将 GitHub 自动生成的 **Source code** 归档当作安装包。完整命令、登录方式、证书配置和卸载步骤见上述指南。

安装完成后，在 Web 界面中 **添加转发规则 → 查看运行状态 → 验证目标服务可访问**。全新安装不预置转发规则。

> 本文介绍 v2.5.0。交互式安装器选择最新已发布稳定版；部署其他版本时，请使用对应版本的文档。

## 使用前了解

**转发路径由规则与运行环境共同决定。** nftables 与软件 flowtable 的可用性取决于内核、网络权限和现有防火墙；nftables 失败不保证自动回退到 Go，软件 flowtable 也不等于网卡硬件卸载。详见[转发边界](docs/forwarding-limits.md)。

**管理访问与业务访问分别控制。** 管理白名单只保护 Web/API，转发端口需通过主机防火墙或云安全组另行限制。转发到私网目标需要显式授权，详见[安全说明](SECURITY.md)与[配置示例](docs/CONFIGURATION.md)。

## 文档与反馈

[配置示例](docs/CONFIGURATION.md) · [API 文档](docs/API.zh-CN.md) · [监控与统计](docs/MONITORING.zh-CN.md) · [版本说明](RELEASE_NOTES.zh-CN.md) · [完整文档](DOCUMENTATION_INDEX.md)

通过 [GitHub Issues](https://github.com/liying-official/Go-nftables-portbridge/issues) 反馈问题或提出建议；参与开发请阅读[贡献指南](CONTRIBUTING.md)。提交日志和截图前请移除令牌、私钥及敏感部署信息。疑似安全漏洞请遵循 [SECURITY.md](SECURITY.md) 中的报告流程。

## 许可证

PortBridge 使用 [MIT 许可证](LICENSE)。随包依赖保留各自的许可声明，参见[第三方依赖说明](VENDOR_PATCHES.md)。
