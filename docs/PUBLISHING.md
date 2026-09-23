# Publication and privacy checklist / 公开发布与隐私检查 — v2.5.0

[English README](../README.md) · [中文 README](../README.zh-CN.md) · [Security / 安全](../SECURITY.md)

## English

Review the **actual files to be published**, including archive members, examples, screenshots, terminal recordings, generated manifests and CI logs. A clean source snapshot does not prove that Git history, releases, caches or deployment backups are clean. Automated matching finds candidates; classification still requires context.

### Keep, replace or remove

| Category | Public-repository treatment |
|---|---|
| Real access credentials | Remove administrator tokens, API keys, Authorization/cookie values, SSH credentials and private keys. Revoke/rotate any credential already exposed; deleting text alone is insufficient. |
| Deployment identity | Replace real management/target IPs, owned domains, hostnames, account names, home directories, instance IDs and network identifiers unless intentionally public and approved. |
| Runtime evidence | Do not publish full configuration/status dumps, private diagnostic logs, packet payloads/captures, TLS directories or token files. Provide minimal sanitized reproductions. |
| Examples | Prefer documentation-reserved IP ranges and `.example` hosts; label them and keep demo rules disabled. Retain loopback/wildcard addresses when required for accurate semantics. |
| Policy constants | Keep accurately described denied-target ranges and protocol defaults; they are not automatically private machine data. |
| Public integrity material | Keep the trusted release **public** key, signing identity/namespace, fingerprint, source/asset hashes and license notices. They are necessary verification/attribution data, not signing secrets. |

Use a clean staging directory and an explicit allowlist of output files. Inspect hidden files and nested archives. Exclude runtime `.token`/`.key` files, private certificate material, `.env` files, core dumps and raw evidence directories. A public certificate is not a private key, but its SANs can identify hosts; use synthetic certificates rather than production certificates in examples.

Before publishing docs, validate bilingual coverage, API examples and relative links in a full checkout. Package scripts and documentation covered by an internal release manifest must be finalized **before** computing hashes and signing. After any covered-file change, regenerate manifests/checksums and obtain a new publisher signature. An unsigned source checksum list or audit report is not a release signature or a security certification.

This checklist is not a statement that a future release has passed these checks. Scan and review each actual publication candidate and its relevant history separately.

## 简体中文

应检查**实际准备公开的文件**，包括归档成员、示例、截图、终端录制、生成清单与 CI 日志。当前源码快照没有发现问题，不代表 Git 历史、Release、缓存或部署备份也安全。自动匹配只能给出候选，仍需结合语境分类。

必须移除管理员令牌、API 密钥、Authorization/Cookie 值、SSH 凭据和各类私钥。已经泄露的凭据需要撤销或轮换，单纯删掉文本不够。真实管理/目标 IP、自有域名、机器名、账户、主目录、实例和网络标识，除明确批准公开者外都应替换。不要公开完整配置/状态响应、私有诊断日志、报文载荷/抓包、TLS 目录或令牌文件。

示例优先使用文档保留地址段与 `.example` 域名，并注明占位、禁用演示规则。准确说明监听行为需要的回环/通配地址可以保留；明确描述安全策略的拒绝目标范围也不应误认成测试机地址。发布**公钥**、签名身份/namespace、指纹、源码/资源哈希和版权许可声明是必要公开信息，不能当作私钥或隐私删除。

使用干净暂存目录和显式文件白名单，检查隐藏文件及嵌套归档。排除运行时 `.token`/`.key`、私有证书材料、`.env`、核心转储与原始证据目录。证书不是私钥，但 SAN 可能暴露主机信息；示例宜使用合成证书，而不是生产证书。

在完整源码目录中检查双语覆盖、API 示例与相对链接。内部发布清单覆盖的脚本与文档必须在计算摘要和签名前定稿；改动任何覆盖文件都需要重新生成清单、校验和并由发布者重新签名。未签名源码摘要清单和审计报告都不是发布签名或安全认证。

本检查表不代表任何未来发布已通过检查。每次都应对实际候选包及相关历史重新扫描、复核。
