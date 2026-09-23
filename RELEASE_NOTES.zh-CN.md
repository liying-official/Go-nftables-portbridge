# v2.5.0 版本说明

[English](RELEASE_NOTES.md) · [README](README.zh-CN.md) · [文档索引](docs/INDEX.md)

## 本版本包含的功能

v2.5.0 提供本机托管的 Tabler Core 界面、中英语言切换、响应式规则表格/卡片，以及验证签名发布包的 Debian/Ubuntu 交互式安装器。仪表盘展示近似累计流量，并分别显示 Go 与 nft 实时速率。管理 API 和 Prometheus 端点需要管理员认证，写操作需要 CSRF 校验。

## 部署说明

手动验签安装默认仅开放回环管理监听。交互式安装器面向全新安装，选择最新的已发布稳定版，并在严格持久化白名单后配置可用的通配监听。选择流程前请阅读[安装指南](docs/INSTALL.zh-CN.md)和[一键安装行为](docs/ONECLICK.zh-CN.md)。

当前 flowtable 使用软件加速，代码不生成 `flags offload`，不承诺网卡硬件卸载。配置写入成功不能证明业务转发或旧连接已撤销；Go 预算也不会自动限制 nftables 路径。详见[转发边界](docs/forwarding-limits.md)与[监控边界](docs/MONITORING.zh-CN.md)。

## 发布完整性与说明范围

发布流程生成 amd64/arm64 × 中英双语四个归档和 SBOM。已签名 `SHA256SUMS` 认证发布资产，内部签名清单认证其覆盖的包内容。实际部署时仍需确认远端资产可用。本地构建和仅修改文档的修订不会自动获得发布者签名。

配置结构中的 `version: 2` 与发布版本 `2.5.0` 是不同概念。
