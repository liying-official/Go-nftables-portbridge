# v2.5.0

- 引入天蓝色 Tabler Core 界面，Core CSS/JS 与 Tabler Icons 均在本机加载。
- 同一 WebUI 切换简体中文与 English，适配桌面表格、移动端规则卡片和导航。
- 累计流量合并为近似值，Go/nft 实时速率独立显示，保留受认证保护的 Prometheus 指标。
- 保留全部规则控制、HTTPS、直连来源白名单、管理员认证和 CSRF 防护。
- 提供 Debian/Ubuntu 一键安装脚本，支持架构与语言选择、签名发布包校验。

Release 归档及 SBOM 通过已签名 SHA256SUMS 认证，每个预编译包包含内部签名清单；本地重新构建产物不会自动获得发布者签名。部署前请阅读[转发限制](docs/forwarding-limits.md)。
