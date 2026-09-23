# PortBridge documentation / 文档索引 — v2.5.0

[English README](../README.md) · [中文 README](../README.zh-CN.md)

Documentation for v2.5.0. Use the guides matching the version you install. / 本索引适用于 v2.5.0，安装时应使用与目标版本匹配的文档。

## User documentation / 使用文档

| Topic / 主题 | English | 简体中文 |
|---|---|---|
| Overview / 项目首页 | [README](../README.md) | [README](../README.zh-CN.md) |
| Static WebUI demo / 静态界面演示 | [Demo and boundaries](DEMO.md) | [演示与边界](DEMO.md) |
| Verified installation, operations, upgrades / 验签安装与运维升级 | [Installation](INSTALL.en-US.md) | [安装指南](INSTALL.zh-CN.md) |
| Interactive fresh installer / 交互式全新安装 | [One-click](ONECLICK.en-US.md) | [一键安装](ONECLICK.zh-CN.md) |
| HTTP API and client examples / HTTP API 与客户端示例 | [API](API.en-US.md) | [API](API.zh-CN.md) |
| Statistics and Prometheus / 流量统计与指标 | [Monitoring](MONITORING.en-US.md) | [监控](MONITORING.zh-CN.md) |
| Version scope / 版本说明 | [Release notes](../RELEASE_NOTES.md) | [版本说明](../RELEASE_NOTES.zh-CN.md) |

## Shared bilingual references / 共用双语文档

[Configuration examples / 配置示例](CONFIGURATION.md) explain [the disabled forwarding example](../config.example.json) and [the public-management template](../config.public.example.json). [Forwarding limits / 转发边界](forwarding-limits.md), [UDP implementation / UDP 设计](udp-dataplane.md) and [security / 安全](../SECURITY.md) describe deployment and trust boundaries.

For development and publication, read [contributing / 贡献指南](../CONTRIBUTING.md), [vendored patches / 依赖补丁](../VENDOR_PATCHES.md) and [the publication/privacy checklist / 公开发布检查表](PUBLISHING.md). Keep the [project license](../LICENSE), [UI license notices](../internal/web/static/vendor/LICENSES.txt) and [dependency manifest](../packaging/web-dependencies.json).

## Source references and installation / 源码引用与安装

API implementation references use repository-relative paths and require the corresponding source files. For installation, use the verified prebuilt Release package described in the installation guide; documentation and source-only archives are not substitutes for that package.

API 实现引用采用仓库相对路径，需要对应源码文件。安装时请按安装指南使用经过验证的预编译 Release 包；文档包与纯源码归档不能替代该安装包。
