# Configuration examples / 配置示例 — v2.5.0

[English README](../README.md) · [中文 README](../README.zh-CN.md) · [Documentation / 文档索引](INDEX.md)

## English

`config.example.json` and `config.public.example.json` illustrate the on-disk schema, not the API settings request. Their `version: 2` is the configuration schema version, not release `2.5.0`. Fresh installation creates its own configuration; it does not automatically import either example.

| File | Purpose | Before use |
|---|---|---|
| [config.example.json](../config.example.json) | Loopback management; disabled IPv6 → IPv4 TCP range using explicit Go mode; system DNS resolver. | Replace the documentation target with an owned service, prepare HTTPS, generate credentials and then intentionally enable a rule. |
| [config.public.example.json](../config.public.example.json) | Native TLS 1.3 and strict management allowlisting, with no rules. | Supply valid local certificate/key files and actual administrator/scraper source addresses; prepare host/cloud firewall rules. |

The examples deliberately contain no usable token or private key. An empty `admin_token_sha256` is not permission for anonymous management; use the program's credential-generation path. The sample conntrack mark is a public default illustration, not a secret or a globally unique ownership identity. Do not clone live instance identity/recovery files or copy the same sample mark into multiple coexisting instances without understanding ownership and collision handling. Prefer initialization through the installer/application.

Documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32`) and `.example` names are illustrative, not routable service dependencies. Loopback and wildcard addresses are kept where they explain actual binding semantics. Explicit restricted-target ranges in the API/security documentation describe policy, not a test machine. `dns_servers: []` uses the system resolver; a documentation DNS address is only a formatting example, not a recommended resolver.

Do not PUT the entire file to `/api/settings`. Read `GET /api/config`, modify its `.web` projection and send the complete projected object. On-disk-only fields such as credentials, global limits and nftables settings are not API settings fields. See [the API reference](API.en-US.md).

## 简体中文

`config.example.json`、`config.public.example.json` 展示磁盘配置结构，不是 API 设置请求体。其中 `version: 2` 表示配置结构版本，不是发布版本 `2.5.0`。全新安装会生成自己的配置，不会自动导入这两个示例。

普通示例使用回环管理监听、系统 DNS 与默认禁用的 IPv6 → IPv4 TCP 端口段 Go 规则。使用前应替换成自有业务端点、准备 HTTPS、生成凭据，再有意识地启用规则。公网管理示例使用 TLS 1.3 和严格白名单，不包含规则；需要填写有效证书/私钥文件与实际管理/抓取来源，并配置主机/云防火墙。

示例不包含可用令牌或私钥。空的 `admin_token_sha256` 不代表匿名管理，应使用程序的凭据生成流程。示例 conntrack mark 是公开默认值示意，不是秘密，也不是全局唯一实例身份。不要克隆运行实例的归属或恢复文件，也不要在不了解归属/冲突处理时让共存实例照抄相同 mark；优先通过安装器或程序初始化。

文档保留地址段和 `.example` 域名仅供说明，不是可路由的服务依赖。回环、通配地址用于解释真实监听语义，API/安全文档中的受限目标网段描述策略，不代表测试机。`dns_servers: []` 使用系统解析器；保留地址段中的 DNS 示例仅说明格式，不是推荐解析器。

不要将整个配置文件 PUT 到 `/api/settings`。应读取 `GET /api/config`，修改 `.web` 投影后完整提交。凭据、全局预算、nftables 参数等磁盘专用字段不是该 API 的设置字段。详见[中文 API](API.zh-CN.md)。


## Recovery-directory trust / 恢复目录信任

Even an explicitly selected Go rule can be withheld when previous kernel forwarding cannot be proven safely retired. The configuration's parent directory and its ancestor components are checked for trusted ownership, symlinks and group/world-writable permissions (a root-owned sticky ancestor is a special allowed case). A configuration placed in an untrusted shared workspace can therefore save successfully through the API while forwarding remains blocked. Use an appropriately protected service directory; do not fix this with `chmod 777`, an assume-clean switch or deletion of recovery records. A CLI-free clean-kernel proof still needs suitable kernel access; Go-only does not mean all networking privilege requirements disappear.

即使明确选择 Go，无法确认旧内核转发安全撤销时也可能暂停新规则。配置父目录及祖先路径会检查可信所有者、符号链接和组/其他用户可写权限；root 所有、带 sticky 位的祖先目录属于特定允许情形。在不可信共享工作目录放置配置，可能出现 API 保存成功但转发仍被阻止。应使用受保护的服务目录，不要通过 `chmod 777`、假定内核为空或删除恢复记录绕过。无 CLI 的空内核证明仍需要适当内核访问权限，纯 Go 并不等于所有网络权限要求都消失。


## Address-reference sources / 地址约定依据

Reserved IPv4 examples follow [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737.html); the IPv6 documentation prefix follows [RFC 3849](https://www.rfc-editor.org/rfc/rfc3849.html); `.example` follows [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606.html). / IPv4、IPv6 和域名示例分别采用上述 RFC 中的文档保留约定。
