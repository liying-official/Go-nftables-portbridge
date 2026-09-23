# Go-nftables-portbridge API 参考 — v2.5.0

**适用版本：v2.5.0**

**语言：** [English](API.en-US.md) | **简体中文**  

> [!IMPORTANT]
> 所有管理 API 都要求管理员 Bearer Token。写操作还要求 `X-PortBridge-CSRF`。正常安装应通过 HTTPS 访问；不要把 HTTP 成功状态单独视为数据面已经生效或旧转发路径已经完全撤销。

本文档描述 Web 管理 HTTP API。它不描述 Go 内部包接口，也不描述被转发业务流量本身的 TCP/UDP 协议。字段名、枚举值和错误语义以 v2.5.0 实现为准。

示例使用文档占位值，不包含真实凭据或部署信息。

## 目录

- [1. 接口范围与速查](#1-接口范围与速查)
- [2. 访问地址、TLS、鉴权与 CSRF](#2-访问地址tls鉴权与-csrf)
- [3. HTTP 与 JSON 通用约定](#3-http-与-json-通用约定)
- [4. 获取 CSRF：GET /api/bootstrap](#4-获取-csrfget-apibootstrap)
- [5. 获取配置：GET /api/config](#5-获取配置get-apiconfig)
- [6. 获取运行状态：GET /api/status](#6-获取运行状态get-apistatus)
- [7. 保存管理设置：PUT /api/settings](#7-保存管理设置put-apisettings)
- [8. 轮换令牌：POST /api/token/rotate](#8-轮换令牌post-apitokenrotate)
- [9. 创建、替换与删除规则](#9-创建替换与删除规则)
- [10. Rule 完整字段与校验规则](#10-rule-完整字段与校验规则)
- [11. Runtime、Stats 与内核状态](#11-runtimestats-与内核状态)
- [12. 错误响应与处理方法](#12-错误响应与处理方法)
- [13. curl 完整接入流程](#13-curl-完整接入流程)
- [14. Python 标准库客户端示例](#14-python-标准库客户端示例)
- [15. 并发、重试与运维边界](#15-并发重试与运维边界)
- [16. 当前 API 不提供的能力](#16-当前-api-不提供的能力)
- [17. Prometheus 指标](#17-prometheus-指标)
- [实现依据与源码链接](#实现依据与源码链接)

---

## 1. 接口范围与速查

当前版本显式注册 **8 个 JSON 管理 API 路由**，统一以 `/api/` 开头；另提供受保护的 `GET /metrics` Prometheus 接口，没有 `/api/v1/` 版本前缀。管理接口与 WebGUI 共用监听地址、端口、TLS 和 IP ACL。[^routes]

| 方法 | 路径 | 作用 | 成功状态 | CSRF | 请求 JSON |
|---|---|---|---:|---|---|
| `GET` | `/api/bootstrap` | 获取进程级 CSRF 值及项目名 | `200` | 不需要 | 无 |
| `GET` | `/api/config` | 获取可公开给管理员的配置投影 | `200` | 不需要 | 无 |
| `GET` | `/api/status` | 获取运行状态、计数器及有效管理 ACL | `200` | 不需要 | 无 |
| `PUT` | `/api/settings` | 保存管理面设置 | `200` | 必须 | `settingsRequest` |
| `POST` | `/api/token/rotate` | 生成并立即启用新管理员令牌 | `200` | 必须 | 无 |
| `POST` | `/api/rules` | 创建一条规则 | `201` | 必须 | `Rule` |
| `PUT` | `/api/rules/{id}` | 完整替换一条已有规则 | `200` | 必须 | `Rule` |
| `DELETE` | `/api/rules/{id}` | 删除持久配置中的一条规则并请求撤销 | `204` | 必须 | 无 |

**所有上述 API 均要求管理员 Bearer Token。** `/api/bootstrap` 不是匿名登录接口。当前没有用户账号、角色、只读令牌或按规则授权，持有有效管理员令牌即可执行这些管理操作。[^auth]

需要读取规则列表时，使用 `/api/config` 的 `rules`，或 `/api/status` 的 `rules[].rule`。当前**没有** `GET /api/rules` 或 `GET /api/rules/{id}`；未注册的读取路径返回 `404`，不要根据 POST 路径自行推导读取接口。[^routes]

### 1.1 四个必须区分的概念

| 概念 | 对应位置 | 含义 |
|---|---|---|
| 管理访问权限 | `web.whitelist`、`/api/status.acl` | 谁能访问 WebGUI/API，不是转发端口的来源 ACL |
| 期望规则配置 | `/api/config.rules[]` | 已持久保存的规则；`enabled` 是管理员期望 |
| 运行状态 | `/api/status.rules[]` | 当前管理器观察到的运行/风险状态，可能包含只存在于运行态的清理记录 |
| 实际业务可达性 | 外部 TCP/UDP 载荷检查 | API 没有提供自动端到端探测结果，HTTP 成功不能替代业务验证 |

规则写入会先保存配置，再调用数据面应用逻辑。该逻辑将运行失败写入状态，但处理器不把这些失败转换成创建/更新接口的失败码。因此 `201`、`200`、`204` **均不能单独证明数据面已按预期生效或旧连接已完全撤销**。[^rule-handlers][^manager]

## 2. 访问地址、TLS、鉴权与 CSRF

### 2.1 Base URL 与默认部署

典型本机管理地址：

```text
https://127.0.0.1:9080
https://[::1]:9080
```

实际地址由 `web.listen_ipv4`、`web.listen_ipv6` 和 `web.port` 决定。源码默认配置的管理端口是 `9080`，监听 `127.0.0.1`、`::1`，不会因为新增管理白名单就自动改为公网监听。[^config-defaults]

**区分源码默认与安装后的服务：** 未执行 HTTPS 准备的原始开发配置可保留回环 HTTP；随包安装流程会准备证书、设置 `web.require_https=true`，提供的 systemd 单元还传入 `--require-https`。正常安装后的服务应使用原生 HTTPS，设置 API 不能关闭这一部署强制策略。[^deployment]

服务器默认最低 TLS 版本为 `1.2`，可通过设置中的 `tls_min_version:"1.3"` 改为最低 TLS 1.3，重启后生效。HTTPS 响应带 `Strict-Transport-Security: max-age=31536000`。[^tls][^headers]

自签名证书需要先经可信渠道核对指纹，再在客户端建立信任；本文示例使用 `--cacert` 或 Python 的可信 CA 文件，不以跳过证书验证作为接入方式。证书主机名/IP 也必须覆盖请求地址。`self_signed:false` 本身不是客户端信任链验证成功的证明。[^tls][^deployment]

### 2.2 管理 IP ACL：先于 Token 生效

ACL 根据 TCP 直接对端地址判断，不读取 `X-Forwarded-For`、`X-Real-IP` 或 `Forwarded` 作为客户端身份。新连接可能在 TLS 握手/HTTP 解析前被关闭；已建立连接上的后续请求还会再次经过 HTTP ACL 检查。因此不被允许时，客户端可能看到连接关闭，而不一定得到 JSON 错误。HTTP 层 ACL 拒绝为纯文本 `403 Forbidden`。[^acl][^listener]

非严格模式的允许集合为回环地址、可选自动探测 LAN、显式白名单与启动参数提供的 bootstrap ACL 的并集。严格模式保留本机回环恢复通道，只额外接受持久白名单，禁用自动 LAN，并忽略 bootstrap ACL。[^acl]

`auto_lan_acl=true` 探测的是本机处于启用状态的接口上直接连接的私有/链路本地前缀，不是无条件开放所有私网地址。管理白名单最多 **1024 个规范化去重后的条目**。严格模式拒绝 `/0`；普通模式默认也拒绝 `/0`，其本地风险开关不通过 API 暴露。[^acl][^config-validation]

### 2.3 管理员令牌

每个请求使用一个 Authorization 头：

```http
Authorization: Bearer <64-character-admin-token>
```

程序生成的令牌来自 32 字节随机数据，以 64 个十六进制字符编码。服务器保存并比对的是令牌字符串的 SHA-256；不要把 `admin_token_sha256` 的哈希值当作令牌发送。[^token-storage]

| 项目 | 当前行为 |
|---|---|
| 认证位置 | 仅从 `Authorization` 请求头提取 |
| Scheme | `Bearer`，Scheme 比较不区分大小写 |
| Token 值 | 提取后的 Token 必须恰好 64 字节并匹配现有哈希，内容区分大小写；头解析使用 `strings.Fields` 分隔首尾及字段间空白，Token 内不能有空白 |
| 重复 Authorization | 拒绝，不能发送多个 Authorization 头 |
| Cookie / URL 查询参数 / Basic | 不提供这些认证方式 |
| 默认本地令牌路径 | `/etc/portbridge/admin.token`，可被启动参数 `--token-file` 改变 |
| 匿名登录/注册 | 不提供 |
| 服务端退出登录 | 不提供；GUI 的退出只是清理浏览器中的令牌状态 |
| 撤销已有 Token | 轮换管理员令牌；随后旧令牌不再通过认证 |

读取初始令牌需要本机管理员对文件的访问权限；没有通过 API 读取当前明文 Token 的接口。轮换成功的响应会返回新 Token，同时更新所配置的本地令牌文件。[^auth][^token-storage][^cli][^gui]

### 2.4 CSRF 获取与生命周期

先调用：

```http
GET /api/bootstrap
Authorization: Bearer <admin-token>
```

再把响应中的 `csrf` 放入所有写操作：

```http
X-PortBridge-CSRF: <csrf-from-bootstrap>
```

CSRF 值在 `Server.New` 中由 24 字节随机数据生成，编码后为 **48 个十六进制字符**。它是该服务器对象/进程的值，不是每个浏览器用户的独立会话令牌。正常进程重启后重新生成，管理员 Token 轮换不会重新生成该值。[^auth][^web-constructor]

CLI、脚本和后端程序同样必须发送 CSRF；不能因为不是浏览器就省略。`DELETE /api/rules/{id}` 和无请求体的 `/api/token/rotate` 也不例外。

### 2.5 浏览器同源校验

写请求按下列顺序经过处理：

```text
管理 ACL → Bearer 认证 → 浏览器同源校验 → CSRF → 请求解析/业务处理
```

当前同源规则如下。[^auth]

| 请求头 | 接受条件 |
|---|---|
| `Sec-Fetch-Site` | 不存在、空值、`same-origin` 或 `none` |
| `Sec-Fetch-Site: same-site` | 拒绝；同站不等于同源 |
| `Sec-Fetch-Site: cross-site` | 拒绝 |
| `Origin` | 可以不发送；发送非空值时，scheme 必须等于服务端实际 TLS/HTTP scheme，host:port 必须与请求 `Host` 相同（host 比较不区分大小写） |
| Origin 其他部分 | 不得包含用户信息、路径（包括尾随 `/`）、查询参数或 fragment；`Origin: null` 不通过 |
| 重复 Origin / Sec-Fetch-Site | 拒绝 |

示例：请求地址是 `https://pb.example:9080/api/rules`，合法 Origin 为 `https://pb.example:9080`，不是 `https://pb.example:9080/`。

标准命令行请求不需要伪造浏览器头，省略 `Origin` 和 `Sec-Fetch-Site` 即可，但 Token、CSRF 仍然必需。当前没有跨域 CORS 授权或预检处理器；不要假定跨站网页能够调用管理 API。[^routes][^auth]

### 2.6 认证失败限流

失败认证使用令牌桶，而非固定时间窗口。[^auth-limiter]

| 维度 | 突发容量 | 补充速率 |
|---|---:|---:|
| 每个直接来源 IP | 10 次失败 | 每 6 秒补充 1 次 |
| 全局 | 100 次失败 | 每秒补充 5 次 |

失败请求通常返回 `401`，超出失败预算返回 `429`。合法 Token 在限流判断之前验证，**不会被这些失败请求锁死**；成功认证清理该来源 IP 的失败桶，不重置全局桶。该限流是认证失败防护，不是成功 API 调用的通用 QPS 配额，也不是转发流量限速。

当前 `401` 带 `WWW-Authenticate: Bearer realm="PortBridge"`；`429` 处理器未设置 `Retry-After`。客户端应降低错误凭据重试频率，不能依赖不存在的重试时间字段。[^auth]

## 3. HTTP 与 JSON 通用约定

### 3.1 请求编码

`PUT /api/settings`、`POST /api/rules`、`PUT /api/rules/{id}` 必须发送：

```http
Content-Type: application/json
```

带参数的 `application/json; charset=utf-8` 可被 MIME 解析接受。请求体上限为 **1,048,576 字节（1 MiB）**。解码器拒绝未知字段、类型不匹配、无效 JSON、以及一个 JSON 值后继续出现另一个值。客户端应始终发送一个对象，而不是数组或 `null`。[^json]

这些解析错误在当前处理器中均返回 **400**，包括不支持的 Content-Type 和超过体积上限；不要写死为通常见到的 `415` 或 `413`。`null` 没有独立的“非对象”检查，会进入 Go 零值与后续业务校验，不是受支持的“清空对象”用法。[^json][^config-validation]

无请求体的 Token 轮换和删除处理器不调用该 JSON 解码器，不要求 Content-Type；也没有为它们定义任何请求体参数。[^rule-handlers]

`DisallowUnknownFields` 不等于完整 JSON schema 校验：当前解码器未单独拒绝重复键，字段匹配也可不区分大小写。客户端应只发送文档中的小写字段名，每个字段出现一次；不要依赖重复键覆盖顺序。

### 3.2 响应编码

JSON 响应使用：

```http
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
```

响应没有统一的 `data` 包装层：创建/更新直接返回 Rule，删除返回空体，设置返回 `{ "ok": true, "restart_required": ... }`，其余见各接口。字段排列顺序不是协议的一部分。[^json]

未知路径、方法不匹配、HTTP ACL 拒绝和传输层错误未必是 JSON。客户端应先检查状态码与 Content-Type，再决定是否 JSON 解码；尤其不能对 `204` 调用 JSON 解码。[^routes][^headers]

### 3.3 字段、时间与集合

| 类型/情形 | 约定 |
|---|---|
| 端口、限制、秒数 | JSON 整数，不是字符串，不支持 `"9080"` 代替 `9080` |
| 布尔值 | JSON `true` / `false`，不是字符串 |
| 时间 | `time.Time` 的 JSON 字符串，RFC3339 风格，可能有小数秒和时区偏移 |
| 未初始化时间 | `started_at`、`not_after` 可能为 `0001-01-01T00:00:00Z`；当前工具链下 `omitempty` 并不会省略这里的零值 time.Time |
| 空集合 | `/api/config` 的规则、白名单、DNS 列表以及 `/api/status` 的 ACL 列表通常返回 `[]` |
| Rule 可省略字段 | `omitempty` 字段在零值/空值时不一定出现，具体见第 10 节 |
| 累计计数器 | JSON 数字，Go 类型为 `uint64`；超大计数在 JavaScript 普通 Number 中存在整数精度边界 |
| 错误码 | 没有机器可读业务错误码、字段错误列表或 request ID 字段 |

请求方应按文档字段发送，响应方则宜容忍未来新增字段。响应缺少可选字段时按该字段明确的零值/默认语义处理，不要把所有缺失数值都解释为“无限制”。[^json][^stats][^tls][^config-clone]

### 3.4 请求时限与连接限制

原生 Web Server 设置：读取 Header 超时 `5s`，读取超时 `15s`，写入超时 `30s`，空闲超时 `60s`，`MaxHeaderBytes=32 KiB`，`MaxHeaderValueCount=128`。每个管理监听器有最多 **256** 个连接的限制包装。超限/超时不保证产生 APIError JSON。[^web-start][^listener]

没有分页、游标、排序、筛选查询参数契约；这些处理器不读取请求 URL 的查询参数。不要依赖自行附加的 `page`、`limit`、`enabled` 参数改变结果。[^read-handlers][^rule-handlers]

## 4. 获取 CSRF：`GET /api/bootstrap`

**鉴权：** Bearer Token。**CSRF：** 不需要。**请求体/查询参数：** 无。[^read-handlers]

请求示例：

```http
GET /api/bootstrap HTTP/1.1
Host: pb.example:9080
Authorization: Bearer <admin-token>
```

成功响应 `200 OK`：

```json
{
  "csrf": "0123456789abcdef0123456789abcdef0123456789abcdef",
  "name": "Go-nftables-portbridge"
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `csrf` | string | 本进程的 CSRF 值；示例为占位值，必须使用实际响应 |
| `name` | string | 固定项目名 `Go-nftables-portbridge` |

此接口不会新建账号，不签发 Bearer Token，不返回应用版本，也不设置认证 Cookie。典型错误为 `401`、`429` 或访问层拒绝。重启后写操作遭遇 CSRF 失败时，应重新调用本接口获取当前值。

## 5. 获取配置：`GET /api/config`

**鉴权：** Bearer Token。**CSRF：** 不需要。成功为 `200 OK`。[^read-handlers]

响应示例（一个已准备原生 HTTPS 的空规则部署；证书指纹、有效期为示例）：

```json
{
  "web": {
    "port": 9080,
    "listen_ipv4": "127.0.0.1",
    "listen_ipv6": "::1",
    "auto_lan_acl": false,
    "strict_ip_allowlist": false,
    "allow_insecure_http": false,
    "whitelist": [],
    "tls_cert_file": "/etc/portbridge-tls/fullchain.pem",
    "tls_key_file": "/etc/portbridge-tls/privkey.pem",
    "tls_min_version": "1.3",
    "dns_servers": []
  },
  "rules": [],
  "https": {
    "required": true,
    "certificate": {
      "enabled": true,
      "self_signed": true,
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "not_after": "2027-09-20T00:00:00Z"
    }
  }
}
```

| 顶层字段 | 类型 | 说明 |
|---|---|---|
| `web` | object | 第 7 节列出的 11 个管理设置字段，值来自保存后的配置 |
| `rules` | Rule[] | 持久配置中的规则列表，保留配置顺序；不包含运行态清理记录 |
| `https` | object | 强制 HTTPS 策略与当前已加载证书信息 |

`https` 结构：

| 字段 | 类型 | 说明 |
|---|---|---|
| `required` | boolean | 配置中的 `web.require_https`，只读暴露，不是 settingsRequest 字段 |
| `certificate.enabled` | boolean | 启动时记录的原生 TLS 证书是否启用 |
| `certificate.self_signed` | boolean | 已加载叶证书是否满足源码中的自签名判定，不代表信任验证结论 |
| `certificate.sha256` | string，可省略 | 已加载叶证书原始 DER 的 SHA-256，64 位小写十六进制，无冒号 |
| `certificate.not_after` | string | 已加载证书过期时间；无 TLS 时可能出现零值时间 |

**保存配置和运行实例是两个时间点。** 更改 TLS 路径但尚未重启时，`web.tls_cert_file`/`tls_key_file` 可显示新路径，而 `https.certificate` 仍描述旧的已加载证书。仅替换同一路径下的文件也不会自动热加载证书。[^tls][^settings]

此响应不是原始 `config.json`：不返回 `version`、`resource_limits`、`nftables`、`admin_token_sha256`、`allow_unsafe_all_address_acl`，也不会返回证书/私钥文件内容。不要把整个响应当作配置文件备份或原样提交给 `/api/settings`。只提取 `.web` 才与当前设置请求模型匹配。[^read-handlers][^config-model]

## 6. 获取运行状态：`GET /api/status`

**鉴权：** Bearer Token。**CSRF：** 不需要。成功为 `200 OK`。[^read-handlers]

空规则状态示例：

```json
{
  "uptime_seconds": 120,
  "rules": [],
  "acl": {
    "auto": ["127.0.0.0/8", "::1/128"],
    "whitelist": [],
    "bootstrap": [],
    "strict": false
  }
}
```

| 字段 | 类型 | 说明 |
|---|---|---|
| `uptime_seconds` | integer/int64 | 自 Web Server 对象创建后的运行秒数，截断为整数；不是操作系统启动时间 |
| `rules` | RuleRuntime[] | 运行态规则，结构详见第 11 节；按规则名、再按 ID 排序 |
| `acl.auto` | string[] | 当前有效自动允许前缀，始终含回环；关闭自动 LAN 不会删除回环 |
| `acl.whitelist` | string[] | 当前生效的持久管理白名单 |
| `acl.bootstrap` | string[] | 当前生效的临时启动白名单；严格模式下为空 |
| `acl.strict` | boolean | 当前 ACL 管理器是否运行在严格模式 |

`rules` 可能包含已从 `/api/config.rules` 删除但撤销未完成的规则，以及 `kernel-pending-...`、`kernel-recovery-unverified...` 等运行态清理记录。这些不是新生成的可编辑配置规则。判断某个 ID 是否可更新/删除，应先在 `/api/config.rules` 中查找。[^manager-runtime][^kernel-state]

状态接口返回 `200` 只表示读取成功。即使有规则启动失败或内核状态未验证，也不改为 `503`。监控程序必须读取 `stats.last_error`、`stats.running`、`go_running` 和 `kernel_state`，而不是仅检查 HTTP 状态。计数口径和健康判断限制见第 11 节。[^manager]

## 7. 保存管理设置：`PUT /api/settings`

**鉴权：** Bearer Token + CSRF；浏览器写操作须通过同源检查。**请求格式：** 一个 JSON 对象，字段直接位于顶层，不能包装在 `web` 中。[^settings]

### 7.1 请求字段

| 字段 | JSON 类型 | 取值/约束 | 生效方式 |
|---|---|---|---|
| `port` | integer | `1–65535`；省略会变成 0 并校验失败 | 重启 |
| `listen_ipv4` | string | IPv4 管理监听地址；空字符串表示该地址不启用 | 重启 |
| `listen_ipv6` | string | IPv6 管理监听地址；空字符串表示该地址不启用 | 重启 |
| `auto_lan_acl` | boolean | 自动允许直接连接的私有/链路本地网段；严格模式必须为 false | 立即刷新 ACL |
| `strict_ip_allowlist` | boolean | 严格管理白名单；要求当前请求已经使用原生 HTTPS | 立即刷新 ACL |
| `allow_insecure_http` | boolean | 历史开发兼容风险确认；`require_https=true` 时不能设为 true | 改变该值计入重启判断 |
| `whitelist` | string[] | IP 或 CIDR，规范化后去重排序，最多 1024 项 | 立即刷新 ACL |
| `tls_cert_file` | string | 服务器上证书文件的绝对路径，与私钥同时配置 | 重启 |
| `tls_key_file` | string | 服务器上私钥文件的绝对路径，与证书同时配置 | 重启 |
| `tls_min_version` | string | `"1.2"` / `"1.3"`；省略或空字符串保留原策略 | 有效策略变化时重启 |
| `dns_servers` | string[] | 最多 8 个去重后的 DNS 服务器；空列表使用系统解析器 | 更新解析器并重新应用期望规则 |

**这是替换式保存，不是 PATCH。** 除 `tls_min_version` 的显式兼容处理外，省略的布尔字段为 false，省略的字符串为空，省略的列表会被规范化为空列表。只提交想改的一个字段可能清空证书路径、管理白名单或关闭安全模式，也可能直接报错。正确方式是读取 `/api/config`，提取 `.web`，修改目标字段，再完整 PUT。[^settings]

### 7.2 请求与响应示例

```json
{
  "port": 9080,
  "listen_ipv4": "127.0.0.1",
  "listen_ipv6": "::1",
  "auto_lan_acl": false,
  "strict_ip_allowlist": false,
  "allow_insecure_http": false,
  "whitelist": ["192.0.2.10/32"],
  "tls_cert_file": "/etc/portbridge-tls/fullchain.pem",
  "tls_key_file": "/etc/portbridge-tls/privkey.pem",
  "tls_min_version": "1.3",
  "dns_servers": ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]
}
```

证书文件必须已存在于**服务器本地**并且服务进程可读；本接口不是证书上传接口。示例中的白名单地址仅用于说明，不代表真实管理端地址。

成功 `200 OK`：

```json
{
  "ok": true,
  "restart_required": true
}
```

`restart_required` 比较的是保存后的配置与运行监听器**启动时**配置，而非与上一次保存的配置比较。重复保存同一个尚未应用的变更仍会返回 true；还原为当前运行值后可以返回 false。严格 ACL、自动 LAN、白名单本身的修改不要求重启。[^settings]

同一路径的证书文件内容变了但路径没变时，该比较不检查文件内容，不能依赖 `restart_required` 发现这种更新。当前 API 也没有独立的“查询待重启状态”或“重启服务”接口。[^settings][^routes]

### 7.3 严格白名单的附加检查

启用/保存 `strict_ip_allowlist=true` 时：

1. 当前请求必须已经是服务端原生 HTTPS；仅发送 `X-Forwarded-Proto: https` 无效。
2. 必须有至少一个持久白名单条目，不能包含 `/0`，且 `auto_lan_acl=false`。
3. 必须配置 TLS 证书和私钥。
4. 当前直接客户端 IP 必须位于提交的新白名单内；回环地址有恢复通道例外，但非空白名单要求仍存在。

这些检查是当前处理器/配置模型的真实行为，不代表任何代理后的最终用户身份识别。[^settings][^config-validation]

### 7.4 白名单与 DNS 格式

管理 `whitelist` 接受单个 IP，并将其转成 `/32` 或 `/128`；CIDR 转为网络前缀、去掉空条目、去重、排序。IPv4-mapped IPv6 **CIDR** 被拒绝，应使用普通 IPv4 CIDR。[^normalize-lists]

DNS 接受 IP 或 IP:port：IPv4 `1.1.1.1` → `1.1.1.1:53`，IPv6 `2606:4700:4700::1111` → `[2606:4700:4700::1111]:53`。IPv6 自定义端口需写 `[IPv6]:port`。端口范围 `1–65535`，服务器地址必须是 IP literal，不接受域名、DoH URL 或 DoT URL。规范化后保留首次出现顺序并去重，最多 8 个。[^normalize-lists]

### 7.5 TLS 文件检查与现有实现边界

保存非空证书/私钥对时会执行本地 TLS 检查，包括普通文件、有效证书密钥匹配、证书当前有效期；Unix 私钥权限只允许属主读写和可选组读，不允许其他用户访问或执行位，并检查属主。自签名证书可通过本地材料检查，但客户端仍须建立信任。[^tls]

当前 Web 监听地址校验只检查 IP literal 等基础约束，**没有严格保证 `listen_ipv4` 一定是 IPv4、`listen_ipv6` 一定是 IPv6**。字段名仍应按预期地址族使用；传反可能保存后在重启绑定时失败。也不要同时提交两个空监听地址：API 校验未专门拒绝这一组合，而配置重新加载时会将两者回填为回环默认值。[^config-validation][^config-defaults]

保存失败通常为 `400`。ACL 刷新失败时尝试回滚配置和 ACL，返回 `500`。DNS/规则应用发生在配置保存与 ACL 刷新之后；数据面失败需从 `/api/status` 判断，不由 `{ "ok": true }` 提供保证。[^settings]

## 8. 轮换令牌：`POST /api/token/rotate`

**鉴权：** 当前有效 Bearer Token + CSRF。**请求体：** 不需要。[^rule-handlers][^token-storage]

```http
POST /api/token/rotate HTTP/1.1
Host: pb.example:9080
Authorization: Bearer <current-admin-token>
X-PortBridge-CSRF: <current-csrf>
```

成功 `200 OK`：

```json
{
  "token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

实际 Token 是新随机值，示例不能使用。此响应包含秘密，不应写入普通访问日志、CI 输出或工单。服务端配置哈希与配置的令牌文件完成更新后返回结果；后续认证立即使用新值，没有新旧 Token 双有效期。已经通过旧 Token 认证的在途请求不会因此被追溯取消。[^auth][^token-storage]

CSRF 在轮换中保持不变，但客户端仍可用新 Token 重新 bootstrap，以统一初始化流程。其他持有旧 Token 的客户端后续请求通常收到 `401`；它们不会从错误中自动获得新 Token。[^auth]

若发生生成、读取旧令牌文件、写文件或持久化错误，返回 `500`。源码有两文件事务及回滚处理，但回滚本身也可能失败，并在错误文本中提示本机恢复步骤；不要将这种错误当作“肯定没有发生任何状态变化”。[^token-storage]

**不得自动重试轮换请求。** 响应丢失时，服务端可能已经成功更换令牌。应先使用已知凭据核验状态，并通过授权的本机令牌文件/恢复流程处理，而不是连续轮换。此提醒是基于当前接口副作用给出的客户端接入策略。

## 9. 创建、替换与删除规则

### 9.1 创建规则：`POST /api/rules`

**鉴权：** Bearer Token + CSRF。**请求体：** Rule 对象，详见第 10 节。[^rule-handlers]

最小实用示例（显式保持禁用，便于先审查再启用）：

```json
{
  "name": "Local TCP service",
  "protocol": "tcp",
  "data_plane": "go",
  "listen_host": "127.0.0.1",
  "listen_port": 18080,
  "target_host": "127.0.0.1",
  "target_port": 8080,
  "enabled": false,
  "allow_private_target": true,
  "target_cidr_allowlist": ["127.0.0.1/32"]
}
```

此例只用于本机自有服务；目标 `127.0.0.1:8080` 必须由操作者准备。`enabled:false` 不建立新的期望转发路径。回环目标也属于受限制目标，必须同时提供 `allow_private_target:true` 与匹配的 CIDR。

成功 `201 Created`，响应为**规范化后的完整 Rule**，没有外层 `rule` 或 `data`：

```json
{
  "id": "0123456789abcdef",
  "name": "Local TCP service",
  "protocol": "tcp",
  "data_plane": "go",
  "listen_host": "127.0.0.1",
  "listen_port": 18080,
  "target_host": "127.0.0.1",
  "target_port": 8080,
  "enabled": false,
  "connect_timeout_seconds": 10,
  "tcp_idle_timeout_seconds": 300,
  "max_tcp_connections": 2048,
  "max_tcp_connections_per_source": 256,
  "udp_idle_timeout_seconds": 60,
  "max_udp_sessions": 4096,
  "max_udp_sessions_per_source": 512,
  "udp_new_sessions_per_second_per_source": 1000,
  "udp_packets_per_second_per_source": 100000,
  "udp_batch_size": 64,
  "udp_packet_buffer_size": 2048,
  "udp_listener_buffer_bytes": 4194304,
  "udp_session_buffer_bytes": 65536,
  "allow_private_target": true,
  "target_cidr_allowlist": ["127.0.0.1/32"]
}
```

服务器生成 8 字节随机 ID，编码为 16 个十六进制字符。即使请求中提供 `id`，创建处理器也会覆盖它；保存返回的实际 ID。当前不设置 `Location` 响应头，也没有幂等键。重复 POST 可能创建新的记录，而不是更新同一条规则。[^rule-handlers][^token-storage]

校验/保存错误返回 `400`；生成随机 ID 失败返回 `500`。创建成功后再读取状态。对于 nftables 或 DNS 等运行问题，创建仍可能是 `201`，而 `stats.last_error` 非空。[^rule-handlers][^manager]

### 9.2 完整替换：`PUT /api/rules/{id}`

`{id}` 是已有规则 ID；不带花括号实际发送。新建 API 生成的 ID 可直接放入路径；对于本地导入的其他合法 ID，客户端应将它作为单个路径段编码。[^rule-handlers][^config-validation]

**本地导入 ID 的点路径例外：** 本版本配置校验允许 ID 为 `.` 或 `..`，但直接请求 `/api/rules/.` 或 `/api/rules/..` 会被 Go 1.27.1 ServeMux 规范化，并可能在进入 API 处理器前重定向。Python 的 `urllib.parse.quote(id, safe="")` 仍保留这些点，因此应把完整点路径段显式编码为 `%2E` 或 `%2E%2E`。第 14 节客户端已处理这一情况；不要开启自动跟随重定向来规避它。正常 API 生成的 16 位十六进制 ID 不受影响。这是 Go ServeMux 的路径规范化边界，不是新的 ID 格式要求。

请求体同 Rule。路径中的 ID 覆盖请求体里的 `id`，不能通过此接口重命名 ID。更新成功为 `200 OK`，返回完整规范化 Rule；ID 不存在返回 `404`，不会隐式创建。[^rule-handlers]

**PUT 不与原规则合并。** 假设原规则 `enabled:true`、`data_plane:"go"`，更新时漏传它们，会得到 `enabled:false`、`data_plane:"nftables"`。同理，漏传自定义超时、连接数或 UDP 参数会回到规范化默认值。应从 `/api/config.rules` 取原对象，修改所需字段后整体提交。[^normalize-rule]

启用/禁用没有专用接口，修改完整 Rule 的 `enabled` 即可。下面是“禁用”的概念流程，**不能只提交这个片段**：

```text
GET /api/config
→ 找到 rules 中 id 相同的完整对象
→ 将对象的 enabled 改为 false
→ PUT /api/rules/{id} 提交整个对象
→ GET /api/status 检查撤销状态
```

配置变更可能停止并重建 Go 监听器；不承诺连接无损迁移。更新后同一个规则 ID 的累计计数一般仍由原 Stats 对象保留，不能把 PUT 当作清零计数器接口。[^manager]

### 9.3 删除：`DELETE /api/rules/{id}`

**鉴权：** Bearer Token + CSRF。无请求体。成功为：

```http
HTTP/1.1 204 No Content
```

无 JSON 响应体。ID 不存在返回 `404`：

```json
{
  "error": "rule \"not-found\" not found"
}
```

删除先更新持久配置，再调用规则应用逻辑。`204` 不代表存活 NAT/conntrack 流已证实清理完毕；撤销未完成时，此 ID 或清理记录可能继续出现在 `/api/status` 中，但不再出现在 `/api/config.rules` 中。再次 DELETE 此 ID 将返回 `404`，不是继续清理操作。[^rule-handlers][^kernel-state]

要处理遗留运行态，应查看 `kernel_state` 和 `stats.last_error`，让管理器在满足环境条件后重新协调，并结合主机日志检查；不要把运行态清理记录复制回配置，或仅凭配置列表中消失就宣告安全撤销完成。[^manager][^kernel-state]

## 10. Rule 完整字段与校验规则

Rule 共 **27 个 JSON 字段**。下列“默认”指 API 创建/替换时经过 `NormalizeRule` 的结果，不代表 WebGUI 表单的默认选项；其中 `protocol` 在 API 中没有默认，`enabled` 省略则为 false。[^config-model][^normalize-rule]

### 10.1 身份、协议与目标

| 字段 | 类型 | 默认/是否必需 | 校验与说明 |
|---|---|---|---|
| `id` | string | 创建时服务器生成；更新取路径值 | 本地配置要求非空、最多 128 字节；API 客户端提供的 body ID 不决定记录 ID |
| `name` | string | 必需 | 去除首尾空白后非空；最多 **80 字节**，不是 80 个中文字符；名称不要求唯一 |
| `protocol` | string | 必需 | 去空白并转小写；仅 `tcp`、`udp`、`both`；空值不会自动变成 tcp |
| `data_plane` | string | `nftables` | 去空白并转小写；仅 `nftables` 或 `go`；不能传运行态的 `go-proxy`/`hybrid` |
| `listen_host` | string | `*` | `*`、IPv4 或 IPv6 literal；不可为多播；空字符串规范化为 `*` |
| `listen_port` | integer | 必需 | `1–65535` |
| `listen_port_end` | integer | `0`（单端口） | `0` 等价于起始端口；否则须在范围内且不小于起始端口 |
| `target_host` | string | 必需 | 去空白后非空，最多 253 字节；IP literal 或供解析器处理的主机名，不是 URL |
| `target_port` | integer | 必需 | `1–65535` |
| `target_port_end` | integer | `0`（单端口） | 与监听区间长度相同，结束值不小于起始值 |
| `enabled` | boolean | `false` | 管理员期望的启用状态，不是运行态反馈 |
| `allow_private_target` | boolean | `false` | 显式允许经过 CIDR 白名单约束的受限目标 |
| `target_cidr_allowlist` | string[] | 空 | 必须使用 CIDR，最多 64 个规范化去重后的条目；不接受裸 IP 或 `/0` |

`listen_host`/`target_host` 会去掉外围方括号，例如 `[::1]` → `::1`；字段本身不应带端口。主机名的外部 DNS 解析不在配置的字面 IP 校验阶段完成，不能把“保存通过”理解为“域名已可达”。[^normalize-rule][^config-validation][^plan]

### 10.2 TCP、UDP 通用及连接预算

下表所有数值为整数。列出的默认字段在 API 请求中省略或为 `0` 时自动填入默认值；**`0` 不是无限制或关闭超时**。负数不会被替换成默认，而是校验失败。[^normalize-rule][^config-validation]

| 字段 | 默认 | 合法范围 | 单位/含义 |
|---|---:|---|---|
| `connect_timeout_seconds` | 10 | `1–300` | 秒；目标解析与 Go 连接建立的相关超时配置 |
| `tcp_idle_timeout_seconds` | 300 | `5–86400` | 秒；Go TCP 空闲连接超时 |
| `max_tcp_connections` | 2048 | `1–resource_limits.max_tcp_connections` | 该规则 Go 路径的并发 TCP 预算 |
| `max_tcp_connections_per_source` | 256 | `1–max_tcp_connections` | 该规则每来源 IP 的 TCP 预算 |
| `udp_idle_timeout_seconds` | 60 | `5–86400` | 秒；Go UDP 会话空闲超时 |
| `max_udp_sessions` | 4096 | `1–10000000` 且不超过全局 UDP 会话上限 | 该规则 Go UDP 会话预算 |
| `max_udp_sessions_per_source` | 512 | `1–max_udp_sessions` | 同规则每来源 IP 的 UDP 会话预算 |
| `udp_new_sessions_per_second_per_source` | 1000 | `1–10000000` | 每来源 IP 的 UDP 新会话补充速率，次/秒 |
| `udp_packets_per_second_per_source` | 100000 | `1–100000000` | 每来源 IP 的入站 UDP 包预算补充速率，包/秒；不是 bit/s |

即使 `protocol:"tcp"`，UDP 数值字段也会被规范化和校验；即使 `protocol:"udp"`，TCP 字段也仍参与校验。若本地全局上限被设置得比默认规则值小，客户端可能需要同时显式下调规则级及每来源限制，不能认为省略总能成功。[^config-validation]

这些预算作用于 Go 路径，不自动约束内核 nftables/flowtable 路径。多端口、多地址族、多 worker 和多个派生 Go runner 共享逻辑规则/来源预算，不应将每个 worker 的额度相加理解为对外承诺。UDP 速率是带突发容量的令牌桶，不是任意 1 秒窗口内绝不超过该数值。[^budgets][^udp-doc]

### 10.3 UDP worker 与缓冲参数

| 字段 | 默认 | 合法范围 | 含义 |
|---|---:|---|---|
| `udp_workers` | 0 | `0–128` | 0 自动，当前自动预算为 `min(GOMAXPROCS,16)`，至少 1 |
| `udp_batch_size` | 64 | `1–256` | 批量读写的消息数 |
| `udp_packet_buffer_size` | 2048 | `512–65535` | 单个预分配数据报缓冲区字节数 |
| `udp_listener_buffer_bytes` | 4194304 | `65536–268435456` | 每监听 socket 申请的缓冲区字节数 |
| `udp_session_buffer_bytes` | 65536 | `65536–16777216` | 每连接态 UDP 上游 socket 申请的缓冲区字节数 |

`udp_workers` 是规则级预算，不是每个端口都无条件启动该数量。拆分到多个监听端点后，每端点至少需要一个 worker；如果端点数多于预算，实际总 worker 数可以超过配置预算。当前状态 API 不返回实际 worker 数。[^plan][^udp-implementation]

超过 `udp_packet_buffer_size` 被截断的数据报会被丢弃并计入应用丢包，不会转发截断后的部分内容。socket 缓冲是申请值，不是保证获得的内核值；状态 API 不返回实际 socket 缓冲大小或内存预算占用。[^udp-implementation][^udp-doc]

v2.5.0 对瞬态 UDP 发送压力保留有效会话，但未发送的包仍计为丢弃；这些参数不提供“过载零丢包”保证，也不创建无限重试队列。[^udp-doc]

### 10.4 端口区间

有效区间长度为：

```text
listen_count = (listen_port_end == 0 ? listen_port : listen_port_end) - listen_port + 1
target_count = (target_port_end == 0 ? target_port : target_port_end) - target_port + 1
```

两者必须相等，每条规则最多 **4096 个端口**。映射保留偏移，不是将所有入站端口汇聚到同一个目标端口。[^config-validation][^runner]

例如：

```json
{
  "name": "Local UDP range",
  "protocol": "udp",
  "data_plane": "go",
  "listen_host": "127.0.0.1",
  "listen_port": 40000,
  "listen_port_end": 40009,
  "target_host": "127.0.0.1",
  "target_port": 50000,
  "target_port_end": 50009,
  "enabled": false,
  "allow_private_target": true,
  "target_cidr_allowlist": ["127.0.0.1/32"]
}
```

对应 `40000→50000`、`40001→50001`，直到 `40009→50009`。

### 10.5 受限制目标与 CIDR 的真实含义

程序对 IP literal 及 DNS 解析结果应用目标地址策略。无效地址、未指定地址、多播及源码认定的非合法单播目标被拒绝。回环、链路本地单播、私有地址，以及显式列出的 `100.64.0.0/10`、`100.100.100.200/32` 属于受限目标。[^target-policy]

允许受限目标必须同时满足：`allow_private_target:true`，以及目标命中 `target_cidr_allowlist`。仅设置其中一项不足。`allow_private_target:true` 却给空列表，在配置校验阶段即失败；IPv4-mapped IPv6 CIDR 也不支持。[^target-policy]

**`target_cidr_allowlist` 不是所有公网目标的通用目的地址限制器。** 当前代码先判断目标是否属于受限类别；非受限有效单播目标直接通过，不要求命中该列表。需要对所有目的地址作强制限制时，不能把这个字段误用为完整的出站防火墙。[^target-policy]

域名解析得到多个地址时，每个有效结果都要通过目标策略；其中出现未获授权的受限地址会使这次解析授权失败，而非静默丢掉该结果继续使用其他结果。规则保存时的字面校验与随后运行时 DNS 校验应分开理解。[^plan]

### 10.6 配置数据面与实际数据面

| `Rule.data_plane` | 当前规划行为 |
|---|---|
| `go` | 强制使用 Go 代理；可处理同地址族或跨地址族路径 |
| `nftables` | 优先对符合条件的同地址族、非回环入口建立 nftables 路径；跨地址族、明确回环、带 zone 的目标等情况由规划逻辑选用 Go 路径 |

`listen_host:"*"` 同时建立 IPv4/IPv6 的期望入口；`0.0.0.0` 只表示 IPv4 通配，`::` 只表示 IPv6 通配。通配入口的 nftables 规划还可增加回环 Go 路径，所以配置是 `nftables`，运行态也可能是 `hybrid`。[^plan]

这里的 Go 路径是规划时根据入口/目标条件选出的路径，**不是 nftables 创建失败后无条件自动降级**。若旧内核路径尚未撤销，重叠 Go 路径可被阻止启动；客户端应查看实际状态。[^manager][^kernel-state]

### 10.7 冲突、数量与返回省略

配置最多 **1024 条规则**，禁用规则也计入总数。所有规则都要通过基础字段校验，但监听冲突只检查双方均启用的组合：协议重叠、监听端口区间重叠、监听地址重叠同时成立时拒绝。`both` 与 TCP/UDP 均有协议交集；`*` 与任意地址重叠，同地址族通配地址与该族具体地址重叠。[^config-validation][^rule-conflicts]

该检查比较配置内规则，不保证主机上其他程序没有占用端口。被其他进程占用可能直到数据面应用阶段才显现，仍需读取状态。[^manager][^runner]

以下字段带 `omitempty`，零值/空值时可在 Rule 响应中省略：

```text
data_plane
listen_port_end
target_port_end
udp_workers
udp_batch_size
udp_packet_buffer_size
udp_listener_buffer_bytes
udp_session_buffer_bytes
allow_private_target
target_cidr_allowlist
```

正常 API 创建/替换后，非空的 `data_plane` 与已填默认的批量/缓冲值一般仍会输出；`udp_workers:0`、范围端点 0、false 的 `allow_private_target` 和空的目标列表通常省略。不要因 `udp_workers` 未出现而判断服务器缺少该功能。运行态清理记录不一定经过正常 Rule 规范化，可能出现端口 0、空目标等不适合再次提交的字段。[^config-model][^kernel-state]

## 11. Runtime、Stats 与内核状态

### 11.1 RuleRuntime

`/api/status.rules[]` 的每个元素结构：[^manager-runtime]

| 字段 | 类型 | 含义 |
|---|---|---|
| `rule` | Rule | 该运行态记录关联的规则对象；可能不是持久配置中的普通规则 |
| `stats` | StatsSnapshot | 运行标志、错误与 Go 路径统计 |
| `traffic` | TrafficSnapshot | 每秒后台采样的 Go、nft 尽力统计、hook counter、每规则实时速率及有效性标志；见[统计说明](MONITORING.zh-CN.md) |
| `data_plane` | string | 运行/风险视角的数据面标签，与 `rule.data_plane` 是不同字段 |
| `go_running` | boolean | 该逻辑规则是否至少存在一个已登记的 Go runner；不是所有派生入口逐一健康证明 |
| `kernel_state` | string | 管理器对内核状态证据的分类，见下表 |

运行态 `data_plane`：

| 值 | 含义 |
|---|---|
| `disabled` | 正常禁用规划 |
| `nftables` | 内核路径，或保守保留的内核风险标识 |
| `go-proxy` | Go 路径 |
| `hybrid` | 混合内核与 Go 路径，或保留内核风险同时仍有 Go runner |
| 空字符串 | 规划尚未给出数据面标签的失败情况，例如目标解析失败后提前退出；应结合 last_error 判断 |

不要把运行态的 `go-proxy`、`hybrid`、`disabled` 直接写入配置 `Rule.data_plane`，后者仅接受 `go` 或 `nftables`。[^plan][^manager]

### 11.2 `kernel_state` 完整枚举

当前 `nftRuleState` 可返回下列 8 个值；顺序为源码检查优先级的概括，不是健康分数。[^kernel-state]

| 值 | 实际含义 | 接入注意 |
|---|---|---|
| `retirement-pending` | 存在该规则的待撤销内核路径 | 不能确认旧转发已撤销 |
| `admission-suspended` | 新 NFT 流量准入暂停 | 已有 NAT 连接可能保留，不等于完全停止 |
| `active-verified` | 对应活动路径存在，整体状态证据已验证且非 unknown | 不是业务目标服务可达证明，也不是硬件 offload 证明 |
| `active-unverified` | 记录有活动路径，但状态证据未完全验证 | 不能当作正常健康 |
| `unknown` | 内核状态未知 | 不能推断没有旧转发 |
| `inactive-verified` | 没有匹配的活动/待撤销/暂停路径，且状态证据已验证 | 与当前观测相关，不是未来持久保证 |
| `unverified` | 未获验证且未落入上述类别 | 需要结合错误与环境判断 |
| `not-reported` | 当前后端没有提供这套状态报告接口 | 不等于 inactive-verified |

### 11.3 StatsSnapshot 全部字段

计数按逻辑规则的 Stats 对象汇总，其中业务计数主要来自 Go 代理实现，不覆盖完整 nftables 数据流。[^stats][^tcp-stats][^udp-implementation]

| 字段 | 类型 | 含义 |
|---|---|---|
| `running` | boolean | 管理器的运行/风险标志；可能因“旧内核转发仍可能存在”而保守保持 true |
| `started_at` | string | 从 `running=false` 转为 true 时记录的时间；未初始化可为零值时间；不是最后一次收到业务包的时间 |
| `last_error` | string，可省略 | 最近设置的管理/路径错误；空时省略；不是结构化错误码 |
| `active_tcp` | integer/int64 | 当前已接收并通过 Go TCP 预算的连接数，包含上游拨号中的连接 |
| `active_udp_sessions` | integer/int64 | 当前 Go UDP 会话数 |
| `total_tcp` | integer/uint64 | 累计通过 Go 连接预算的 TCP 接入数；上游拨号随后失败也可能已计数 |
| `total_udp_sessions` | integer/uint64 | 累计创建的 Go UDP 会话数；不是唯一客户端 IP 数 |
| `tcp_rejected` | integer/uint64 | Go TCP 来源识别/资源预算拒绝数；不是全部网络连接错误 |
| `bytes_up` | integer/uint64 | 客户端 → 目标的 Go 代理有效载荷累计字节 |
| `bytes_down` | integer/uint64 | 目标 → 客户端的 Go 代理有效载荷累计字节 |
| `udp_packets_up` | integer/uint64 | Go 路径成功交付到发送系统调用的上行 UDP 消息数；不证明远端已收到 |
| `udp_packets_down` | integer/uint64 | Go 路径成功交付到发送系统调用的下行 UDP 消息数 |
| `udp_drops` | integer/uint64 | 应用可观察的 UDP 丢弃，例如截断、无效包、预算不足、会话创建失败、未发送批量消息等 |

**统计刷新有时序差异。** TCP 字节数在当前双向复制处理结束后汇总，长连接传输中读取到的字节数可能明显滞后；UDP worker 在维护/清理阶段将本地计数合并到共享 Stats。快照不是所有计数器在同一瞬间的原子事务。不能简单以两次 `bytes_up` 差值作为精确实时链路速率。[^tcp-stats][^udp-implementation][^stats]

这些值不是接口流量总表：纯 nftables 路径有实际流量时，Go 计数器仍可能是 0；hybrid 只反映 Go 部分。`udp_drops` 也不是主机内核、NIC、网络与远端的全部丢包总数。[^udp-doc]

规则 ID 保留时，停止/再次启动通常保留累计计数；完全删除并清理该规则或重启进程后不能指望延续原计数。API 没有计数器重置接口，也不提供永久历史。[^manager][^stats]

`traffic.go` 补充活动 TCP 的实时观测；`stats.bytes_up/bytes_down` 仍保持上述复制结束后汇总的语义。nft 使用 conntrack accounting 尽力采样，hook counter 单列；`available=false` 或 `rate_ready=false` 时不能把速率当作零。详见[统计与 Prometheus](MONITORING.zh-CN.md)。

### 11.4 `running=true` 的风险语义

当运行环境无法证明旧内核路径为空时，保存禁用规则可能出现以下**风险状态响应片段**：

```json
{
  "data_plane": "nftables",
  "go_running": false,
  "kernel_state": "unknown",
  "stats": {
    "running": true,
    "last_error": "previous kernel forwarding may still be active; revocation is incomplete: kernel state is not proven empty: netfilter inventory is nonempty or incomplete"
  }
}
```

这不是数据面健康样例，也不是认定存在实际转发；它说明服务器没有把“未能证明旧内核路径为空”伪装为完全停止。正常运行的源代码同样会为待撤销/暂停状态保留显式风险标记。[^manager][^kernel-state]

接入方可采用以下**建议策略**，它不是服务器提供的额外健康契约：配置希望启用时检查无 `last_error`、运行标签符合预期、预期 Go 路径存在且内核证据不存在未完成风险；随后进行真实业务载荷探测。希望停用/删除时同时核对期望配置和运行态撤销证据，不能只数 `enabled` 或 `running` 的 true/false。

## 12. 错误响应与处理方法

### 12.1 JSON 错误结构

处理器的标准错误只有一个字段：[^json]

```json
{
  "error": "错误说明"
}
```

没有 `code`、`message`、`details`、`errors[]` 或 `request_id`。v2.5.0 中，HTTP 处理器的固定鉴权/CSRF/JSON 错误仍有中文，配置校验等错误为英文。双语 GUI 在选择 English 时翻译已知消息，切换界面语言不改变 API 协议。**API 错误文本并不保证全英文，也没有 Accept-Language 协商。**[^auth][^json][^gui]

### 12.2 常见状态码

| 状态码 | 场景 | 响应形式/注意 |
|---:|---|---|
| `200` | 读取、保存设置、轮换、更新成功 | 各接口自己的 JSON 结构 |
| `201` | 创建配置规则成功 | Rule JSON，不保证运行路径已成功 |
| `204` | 删除持久规则成功并已调用应用逻辑 | 无响应体，不保证撤销已验证完成 |
| `400` | JSON、字段、配置校验失败；某些配置持久化错误 | 通常 APIError；超大请求体和 Content-Type 错误也使用此码 |
| `401` | 无/错误/格式不接受的 Token | APIError，带 WWW-Authenticate |
| `403` | CSRF 或同源拒绝 | APIError；管理 ACL 的 HTTP 拒绝为纯文本 |
| `404` | PUT/DELETE 的 ID 不存在，或不存在的 GET 路径 | 前者 JSON，后者可能纯文本 |
| `405` | 方法未被路由接受，如 POST /api/status | Go ServeMux 的纯文本及 Allow 头，不是 APIError |
| `429` | 错误认证过于频繁 | APIError，无 Retry-After 契约 |
| `500` | Token/ID 生成或轮换错误、ACL 刷新失败等 | APIError，可能含本地错误上下文 |

Go ServeMux 的 GET 路由也匹配 HEAD；根路径 GET 注册还是一个兜底匹配，因此某些 `Allow` 列表可能出现 `GET, HEAD`，并不表示该资源实现了有用的 GET API。按当前路由注册，`OPTIONS /api/settings` 可返回 `405`、`Allow: GET, HEAD, PUT`，不应据此当作支持 CORS。[^routes]

### 12.3 可直接对照的真实错误文本

下表保留当前源代码措辞。动态 ID、地址、操作系统错误部分会改变；客户端应优先依据 HTTP 状态和已知操作上下文处理，不宜把所有完整字符串写死。[^auth][^json][^settings][^config-validation][^target-policy]

| HTTP | `error` 示例/原文 | 检查方向 |
|---:|---|---|
| 401 | `管理员令牌无效` | Token 来源、长度、头格式，是否被轮换 |
| 429 | `认证请求过于频繁，请稍后重试` | 减少错误 Token 重试，不影响合法 Token 认证 |
| 403 | `跨站请求被拒绝` | Origin、实际 TLS scheme、Host:port、Sec-Fetch-Site |
| 403 | `CSRF 校验失败，请刷新页面` | 重新 GET bootstrap；检查服务是否重启 |
| 400 | `Content-Type 必须是 application/json` | 仅三个 JSON 写接口需要正确媒体类型 |
| 400 | `JSON 格式错误: json: unknown field "extra"` | 删除不属于该请求模型的字段 |
| 400 | `请求只能包含一个 JSON 对象` | 检查是否拼接了多个 JSON 值 |
| 400 | `JSON 请求体不能超过 1048576 字节` | 缩小单次请求体，注意不存在批量规则接口 |
| 400 | `web port must be 1-65535` | 设置 PUT 是否遗漏 port |
| 400 | `tls_min_version 仅支持 1.2 或 1.3` | 使用字符串 `"1.2"` 或 `"1.3"` |
| 400 | `请先配置 TLS 并重启服务，再通过 HTTPS 启用严格 IP 白名单` | 当前请求不是原生 HTTPS |
| 400 | `严格 IP 白名单必须包含当前客户端地址` | 保留当前直接来源 IP 或合法回环恢复访问 |
| 400 | `this deployment requires HTTPS: certificate/key cannot be cleared and insecure HTTP cannot be enabled` | 完整保留证书路径，不尝试 API 降级 |
| 400 | `rule "<id>" target: local/private target 127.0.0.1 is denied by default` | 受限目标双重授权是否正确 |
| 400 | `rule "<id>" listen and target port ranges must have the same size` | 两个范围长度一致 |
| 404 | `rule "<id>" not found` | ID 是否来自持久配置，而不是运行态清理记录 |

配置写入的 I/O 失败可能仍以 `400` 返回，因为处理器把 Store.Update 错误统一放入该分支。因此 `400` 不能机械地理解为“服务端一定没有故障”；应阅读具体错误并检查服务器权限、磁盘与配置路径。反之，2xx 也不是数据面成功承诺。[^rule-handlers][^settings]

## 13. curl 完整接入流程

本节是接入示例，不是服务端自带脚本。需要 Bash、支持 `--fail-with-body` 的 curl 和 jq。下面的片段在同一个 Bash 会话中依次执行。先确认服务已准备 HTTPS、访问来源已获 ACL 允许、证书名称匹配；示例不会跳过 TLS 验证。

不要在启用 shell 跟踪（`set -x`）、curl verbose/trace 或会话录制的环境输入真实令牌；配置/状态响应及错误也可能包含运行端点和本机路径，不能直接公开分享。示例显式绕过环境代理，并关闭 shell 跟踪；若确需代理，应先验证其信任边界。

### 13.1 初始化 Token、可信证书与 CSRF

```bash
set +x
set -euo pipefail

PB_BASE='https://127.0.0.1:9080'
PB_CA='/path/to/trusted-ca-or-verified-server-cert.pem'

# 临时文件不写入普通日志；认证头不直接展开到 curl 的进程参数中。
umask 077
PB_WORK=$(mktemp -d)
trap 'rm -rf -- "$PB_WORK"' EXIT

read -rsp '管理员令牌：' PB_TOKEN
printf '\n'
printf 'Authorization: Bearer %s\n' "$PB_TOKEN" > "$PB_WORK/headers"
unset PB_TOKEN

CURL=(curl -q --silent --show-error --fail-with-body
      --connect-timeout 5 --max-time 60 --noproxy '*' --cacert "$PB_CA")

pb_api() {
  local method="$1" path="$2"
  shift 2
  "${CURL[@]}" --header "@$PB_WORK/headers" \
    --request "$method" "$PB_BASE$path" "$@"
}

PB_CSRF=$(pb_api GET /api/bootstrap | jq -er '.csrf')
printf 'X-PortBridge-CSRF: %s\n' "$PB_CSRF" >> "$PB_WORK/headers"

pb_api GET /api/config | jq .
pb_api GET /api/status | jq .
```

使用公有受信任 CA、且已由系统信任的证书时，可按环境改用 curl 系统信任库。不要为了让样例立即成功而把 CA 校验删除后又加 `-k`。示例中 `curl -q` 禁止自动读取 curl 默认配置文件，且未启用重定向跟随，避免配置文件暗中改变请求行为。

### 13.2 创建禁用规则，取得服务端 ID

```bash
cat > "$PB_WORK/create.json" <<'JSON'
{
  "name": "Local TCP service",
  "protocol": "tcp",
  "data_plane": "go",
  "listen_host": "127.0.0.1",
  "listen_port": 18080,
  "target_host": "127.0.0.1",
  "target_port": 8080,
  "enabled": false,
  "allow_private_target": true,
  "target_cidr_allowlist": ["127.0.0.1/32"]
}
JSON

pb_api POST /api/rules \
  --header 'Content-Type: application/json' \
  --data-binary "@$PB_WORK/create.json" > "$PB_WORK/created.json"

PB_RULE_ID=$(jq -er '.id' "$PB_WORK/created.json")
printf 'Created rule ID: %s\n' "$PB_RULE_ID"
jq . "$PB_WORK/created.json"
```

### 13.3 读取完整规则后启用

下面是真实写操作。执行前确认 `127.0.0.1:8080` 是你准备转发的自有目标服务，`127.0.0.1:18080` 不与已有服务冲突。示例通过保存后的完整对象修改 `enabled`，不会丢掉自定义字段。

```bash
pb_api GET /api/config > "$PB_WORK/config-before-enable.json"
jq -e --arg id "$PB_RULE_ID" \
  '.rules[] | select(.id == $id) | .enabled = true' \
  "$PB_WORK/config-before-enable.json" > "$PB_WORK/enable.json"

pb_api PUT "/api/rules/$PB_RULE_ID" \
  --header 'Content-Type: application/json' \
  --data-binary "@$PB_WORK/enable.json" | jq .

pb_api GET /api/status | jq --arg id "$PB_RULE_ID" \
  '.rules[] | select(.rule.id == $id) |
   {id: .rule.id, desired_enabled: .rule.enabled,
    data_plane, go_running, kernel_state, stats}'
```

若响应为 2xx，但 `last_error` 非空或内核证据未验证，先处理状态中指出的环境/路径问题，不能将此步骤记为业务验收通过。

### 13.4 保留完整设置后修改 TLS 最低版本

此片段为独立示例，将已保存的最低 TLS 策略改为 1.3；要求管理客户端支持该策略。它不自动重启服务，也不改变监听或白名单。

```bash
pb_api GET /api/config > "$PB_WORK/config-before-settings.json"
jq '.web | .tls_min_version = "1.3"' \
  "$PB_WORK/config-before-settings.json" > "$PB_WORK/settings.json"

pb_api PUT /api/settings \
  --header 'Content-Type: application/json' \
  --data-binary "@$PB_WORK/settings.json" | jq .
```

需要重启时由本机授权运维流程执行。重启后再次 GET bootstrap 更新 `PB_CSRF` 与临时 Header 文件；不要继续使用旧 CSRF。没有 `/api/restart`。

### 13.5 禁用、删除并核对两种状态

```bash
pb_api GET /api/config > "$PB_WORK/config-before-disable.json"
jq -e --arg id "$PB_RULE_ID" \
  '.rules[] | select(.id == $id) | .enabled = false' \
  "$PB_WORK/config-before-disable.json" > "$PB_WORK/disable.json"

pb_api PUT "/api/rules/$PB_RULE_ID" \
  --header 'Content-Type: application/json' \
  --data-binary "@$PB_WORK/disable.json" | jq .

# 删除成功没有响应体，因此不接 jq。
pb_api DELETE "/api/rules/$PB_RULE_ID"

pb_api GET /api/config | jq --arg id "$PB_RULE_ID" \
  '[.rules[] | select(.id == $id)]'
pb_api GET /api/status | jq .
```

第一个读取用于确认持久记录是否消失；第二个读取用于查看旧路径是否仍有撤销/未知状态，不能相互替代。

### 13.6 单独执行 Token 轮换

该操作会让其他客户端持有的旧 Token 失效。只有明确计划轮换时执行，不应作为普通健康检查的一部分。

```bash
pb_api POST /api/token/rotate > "$PB_WORK/rotation.json"
NEW_TOKEN=$(jq -er '.token' "$PB_WORK/rotation.json")

# 原子替换客户端临时认证头；CSRF 在当前服务进程内保持有效。
{
  printf 'Authorization: Bearer %s\n' "$NEW_TOKEN"
  printf 'X-PortBridge-CSRF: %s\n' "$PB_CSRF"
} > "$PB_WORK/headers.new"
mv -- "$PB_WORK/headers.new" "$PB_WORK/headers"
unset NEW_TOKEN

pb_api GET /api/bootstrap > "$PB_WORK/bootstrap-after-rotation.json"
jq '{name, csrf_received: (.csrf | length == 48)}' \
  "$PB_WORK/bootstrap-after-rotation.json"
```

服务器端所配置的 Token 文件会被更新。临时客户端文件在 shell 退出时删除；需要长期自动化时，应通过自己的受控秘密存储机制持久保存新值，不能把轮换响应公开输出。

## 14. Python 标准库客户端示例

以下是为本文编写的接入示例，不是项目自带 SDK。需要 Python 3.10 或以上，不依赖第三方 HTTP 包。它保留 TLS 验证，禁止自动跟随重定向，默认不读取环境代理，处理非 JSON 错误和 `204`，并且**不自动重试写操作**。客户端同时把响应读取不完整等 `http.client.HTTPException` 转成 `PortBridgeTransportError`，包括读取 HTTP 错误响应体时发生的异常。写请求遇到这种异常仍按“结果未知”处理，不自动重试。

保存为 `portbridge_client.py` 后运行：

```bash
python3 portbridge_client.py \
  --base 'https://127.0.0.1:9080' \
  --ca '/path/to/trusted-ca-or-verified-server-cert.pem'
```

默认交互式读取 Token，不回显。也可使用有权限读取的本地秘密文件：

```bash
python3 portbridge_client.py \
  --base 'https://127.0.0.1:9080' \
  --ca '/path/to/trusted-ca-or-verified-server-cert.pem' \
  --token-file '/secure/path/admin.token'
```

CLI 主入口只读取 bootstrap 和状态，不创建、更新、删除或轮换。对象方法可用于自己的自动化：`get_rule` 和 `set_enabled` 是客户端组合操作，不是新增服务端接口。

```python
#!/usr/bin/env python3
"""Go-nftables-portbridge v2.5.0 client; CLI performs read-only calls."""
from __future__ import annotations

import argparse
import getpass
from http import client as http_client
import json
import math
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib import error, parse, request

class PortBridgeAPIError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(f"HTTP {status}: {message}")

class PortBridgeTransportError(RuntimeError):
    pass

class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward management credentials to a redirect target.

class PortBridgeClient:
    def __init__(self, base_url: str, token: str,
                 ca_file: str | None = None, timeout: float = 60.0) -> None:
        parts = parse.urlsplit(base_url)
        if (parts.scheme != "https" or not parts.hostname or
                parts.username is not None or parts.password is not None or
                parts.path not in ("", "/") or parts.query or parts.fragment):
            raise ValueError("base_url must be an HTTPS origin without credentials or a path")
        token = token.strip()
        if len(token) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in token):
            raise ValueError("This example requires a program-generated 64-character hexadecimal administrator token")
        if timeout <= 0 or not math.isfinite(timeout):
            raise ValueError("timeout must be positive and finite")
        self.base_url = f"https://{parts.netloc}"
        self.token = token
        self.csrf = ""
        self.timeout = timeout
        tls_context = ssl.create_default_context(cafile=ca_file)
        self._opener = request.build_opener(
            request.ProxyHandler({}),  # Explicitly avoid ambient proxy settings.
            request.HTTPSHandler(context=tls_context),
            _NoRedirect(),
        )

    def _request(self, method: str, path: str,
                 body: dict[str, Any] | None = None) -> Any:
        if not path.startswith("/api/") or "?" in path or "#" in path:
            raise ValueError("Use a documented /api/ path without query or fragment")
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        if method != "GET":
            if not self.csrf:
                self.bootstrap()
            headers["X-PortBridge-CSRF"] = self.csrf
        payload = None
        if body is not None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(self.base_url + path, data=payload, headers=headers, method=method)
        # The outer handler also covers failures while reading an HTTPError body.
        try:
            try:
                with self._opener.open(req, timeout=self.timeout) as response:
                    raw = response.read()
                    if response.status == 204:
                        return None
                    if response.headers.get_content_type() != "application/json":
                        raise PortBridgeAPIError(response.status, "Expected a JSON response")
                    try:
                        return json.loads(raw)
                    except (ValueError, UnicodeError) as exc:
                        raise PortBridgeAPIError(response.status, "Malformed JSON response") from exc
            except error.HTTPError as exc:
                with exc:
                    raw = exc.read().decode("utf-8", errors="replace")
                try:
                    decoded = json.loads(raw)
                    message = str(decoded.get("error", raw)) if isinstance(decoded, dict) else raw
                except ValueError:
                    message = raw.strip() or str(exc.reason)
                raise PortBridgeAPIError(exc.code, message) from exc
        except (error.URLError, http_client.HTTPException, TimeoutError, OSError) as exc:
            detail = "Read failed" if method == "GET" else "Write outcome is unknown; inspect state before retrying"
            raise PortBridgeTransportError(f"{detail}: {exc}") from exc

    def bootstrap(self) -> dict[str, Any]:
        data = self._request("GET", "/api/bootstrap")
        if not isinstance(data, dict) or not isinstance(data.get("csrf"), str) or len(data["csrf"]) != 48:
            raise ValueError("Unexpected bootstrap response")
        self.csrf = data["csrf"]
        return data

    def get_config(self) -> dict[str, Any]:
        return self._request("GET", "/api/config")

    def get_status(self) -> dict[str, Any]:
        return self._request("GET", "/api/status")

    def get_rule(self, rule_id: str) -> dict[str, Any]:
        # This is local lookup, not GET /api/rules/{id}.
        for rule in self.get_config()["rules"]:
            if rule["id"] == rule_id:
                return dict(rule)
        raise KeyError(f"Rule is absent from persistent configuration: {rule_id}")

    def create_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/rules", rule)

    @staticmethod
    def _rule_path(rule_id: str) -> str:
        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError("rule_id must be a non-empty string")
        segment = parse.quote(rule_id, safe="")
        # quote(..., safe="") still leaves dots unescaped. Encode complete dot
        # segments so ServeMux does not redirect these locally imported IDs.
        if rule_id in (".", ".."):
            segment = segment.replace(".", "%2E")
        return "/api/rules/" + segment

    def replace_rule(self, rule_id: str, rule: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", self._rule_path(rule_id), rule)

    def set_enabled(self, rule_id: str, enabled: bool) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be bool")
        rule = self.get_rule(rule_id)
        rule["enabled"] = enabled
        return self.replace_rule(rule_id, rule)

    def delete_rule(self, rule_id: str) -> None:
        self._request("DELETE", self._rule_path(rule_id))

    def save_settings(self, complete_web_settings: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", "/api/settings", complete_web_settings)

    def rotate_token(self) -> str:
        # Not retried. The old token stops authenticating after a successful rotation.
        data = self._request("POST", "/api/token/rotate")
        new_token = data.get("token") if isinstance(data, dict) else None
        if (not isinstance(new_token, str) or len(new_token) != 64 or
                any(ch not in "0123456789abcdef" for ch in new_token)):
            raise ValueError("Rotation may have succeeded, but the response token is invalid")
        self.token = new_token
        return new_token

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="HTTPS origin, e.g. https://127.0.0.1:9080")
    parser.add_argument("--ca", help="Trusted CA or verified self-signed certificate PEM")
    parser.add_argument("--token-file", help="Local secret file; otherwise prompt without echo")
    args = parser.parse_args()
    try:
        token = (Path(args.token_file).read_text(encoding="utf-8").strip()
                 if args.token_file else getpass.getpass("Administrator token: "))
        client = PortBridgeClient(args.base, token, args.ca)
        client.bootstrap()
        print(json.dumps(client.get_status(), ensure_ascii=False, indent=2))
        return 0
    except (PortBridgeAPIError, PortBridgeTransportError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
```

修改规则时先取完整对象：

```python
rule = client.get_rule(rule_id)
rule["udp_packet_buffer_size"] = 4096
updated = client.replace_rule(rule_id, rule)
status = client.get_status()
```

保存设置时只传配置投影中的 `.web`：

```python
settings = client.get_config()["web"]
settings["tls_min_version"] = "1.3"
result = client.save_settings(settings)
print("Requires service restart:", result["restart_required"])
```

这些片段假设已有初始化完成的 `client` 及合法 `rule_id`；不是独立可直接执行的脚本。发生 CSRF 403 时先查错误、调用 `client.bootstrap()`，再由操作者决定是否重新提交；客户端没有跨进程令牌同步或多线程写入序列化功能。

## 15. 并发、重试与运维边界

客户端对成功状态但非 JSON/损坏响应报错时，写入同样可能已生效，应先回读核对，不自动重试。Python 示例仅接受程序生成的十六进制 Token，这是客户端约束，不是服务端额外格式校验。

### 15.1 HTTP 写成功之后还需要做什么

创建/更新处理顺序是“解码 → 规范化 → 校验并持久化 → Apply → 返回配置对象”，不是可回滚的“保存 + 所有内核路径成功”整体事务。设置保存也会进一步触发 ACL、DNS 与规则应用。[^rule-handlers][^settings]

建议将自动化流程分成两个结果：**配置提交结果**与**数据面验收结果**。提交完成后重新读取 `/api/config` 和 `/api/status`；对启用操作做目标协议的业务往返检查，对禁用/删除操作确认没有未完成的旧路径撤销记录。这是接入策略，不是本文对具体运行环境的验收结论。

### 15.2 并发修改

Store 内部对更新加锁并原子替换配置文件，避免同一进程中配置写入交错，但 API 没有 ETag、If-Match、revision 或 compare-and-swap 机制。两个客户端分别读取旧 Rule 后各自 PUT，后提交者可能覆盖先提交者的不同字段修改。[^config-store][^routes]

建议对同一实例的规则/设置写操作在客户端侧串行化，提交前读取最新完整对象；它只能降低覆盖风险，不能在没有服务端版本条件的情况下提供严格并发安全。Token 轮换尤其应由单一受控流程执行。

### 15.3 重试与结果未知

| 操作 | 传输失败后的处理建议 |
|---|---|
| GET 读取 | 可在确认地址、TLS、ACL 后有限重试；认证失败不要密集重复 |
| POST 创建规则 | 不自动重试；先读配置比对是否已创建，避免重复记录 |
| PUT 更新规则/设置 | 先回读核对是否已保存；重新提交相同对象也可能再次触发运行逻辑 |
| DELETE | 先看配置与运行态；后续 404 只说明持久 ID 不存在，不能证明内核路径已清除 |
| POST Token 轮换 | 不自动重试；可能已使旧 Token 失效，需要使用已知新值或本机恢复渠道 |
| 明确 CSRF 403 | 新取 bootstrap，核对进程是否重启，再决定是否重做原操作 |

处理器没有把客户端断线和数据面应用组成事务。DNS 规划使用独立超时，多个规则的应用及内核操作可能耗时；读写超时也不能保证此前保存没有发生。[^plan][^web-start][^rule-handlers]

### 15.4 配置刷新与服务重启

主程序每 **30 秒**从内存 Store 取得当前配置，刷新接口 ACL 并调用规则 `Refresh`。这不是每 30 秒重新读取磁盘 `config.json`。直接编辑磁盘配置不会由这条周期逻辑自动热加载，还可能被后续 API 保存覆盖。应通过受控停服/编辑/重启流程处理只能本地设置的字段。[^main-refresh][^config-store]

周期性 DNS 刷新失败时，代码可在主机名未变化且缓存仍符合当前目标授权时保留上一次解析结果；授权失败不能以缓存绕过。规则写入和 DNS 设置更新使用的主动 Apply 不等同于允许使用缓存的周期 Refresh。API 不单独返回已解析目标地址列表、TTL 或缓存命中情况。[^plan]

前端自身采用串行状态请求，完成后约 500 ms 再发下一次。本节建议外部监控按自身需要采用较低且串行的轮询频率，避免上一请求未完成时堆积请求；服务端没有承诺固定的状态延迟或成功请求 QPS。[^gui][^web-start]

### 15.5 原生 TLS 与反向代理边界

当前 ACL 识别直接连接源，Origin 校验使用实际 `r.TLS` 和 `r.Host`，不根据转发头恢复原始 scheme/IP。普通反向代理配置不能被默认视为已兼容：代理自身可能成为 ACL 看到的来源，Host 或上游 TLS 方式变化也可能造成同源拒绝。[^auth][^acl]

本文不提供或声称存在“可信代理 IP 列表”API。需要代理部署时，应单独验证上游原生 TLS、Host 保持、真实客户端访问控制及同源请求，不应靠删除安全头、关闭 TLS 或将 ACL 全部开放来消除报错。

## 16. 当前 API 不提供的能力

下表用于避免按常见 REST 命名习惯构造不存在的接口；依据本版本完整路由注册与请求模型。[^routes][^read-handlers][^config-model]

| 能力 | 当前状态/实际替代方式 |
|---|---|
| `GET /api/rules`、`GET /api/rules/{id}` | 未实现；从 GET config/status 中读取 |
| `PATCH /api/rules/{id}`、字段局部更新 | 未实现；读取完整 Rule 后 PUT |
| `POST /api/login`、`POST /api/logout` | 未实现；直接 Bearer 认证，客户端本地清理 Token |
| 多用户、角色、只读 Token、逐规则授权 | 未实现；单一管理员 Token |
| 批量创建/删除、导入/导出原始配置 | 未实现；一个请求操作一条规则，GET config 不是全量磁盘配置 |
| 设置令牌为客户端指定值、读取当前明文令牌 | 未实现；只能由轮换接口生成新值，或由授权本地管理员处理 |
| 远程重启、停止服务、热加载证书 | 未实现；本机运维操作 |
| API 上传证书/私钥、ACME 签发 | 未实现；设置接口只接受服务器本地文件路径 |
| 日志查询/下载、SSE、WebSocket、事件订阅 | 未实现 |
| 匿名业务 `/healthz` | 未实现；状态 API 和 `/metrics` 均需要管理员认证 |
| 统计历史、流量计数重置、分页/筛选 | 未实现 |
| 查询软件版本、动态 OpenAPI/Swagger 文档 | 本路由表未实现；`/api/bootstrap.name` 不是版本号 |
| 读取/修改全局资源限制、conntrack mark、flowtable 总开关 | 未通过 API 暴露；在本地完整配置中设置 |
| 读取实际解析目标、worker 数、socket 缓冲、全局内存占用 | 未通过当前状态结构暴露 |
| 针对转发端口的来源 ACL、防火墙完整管理 | 不能由管理 Web ACL 代替；当前 API 不提供完整防火墙管理接口 |

### 16.1 只在本地配置中的重要字段

以下列的是配置模型能力，不是额外 API 参数。把它们加入 `PUT /api/settings` 会触发未知字段错误。[^config-model][^config-defaults][^config-validation]

| 本地字段 | 源码默认/范围 | API 可见性 |
|---|---|---|
| `version` | 配置 schema 版本 `2`，不是软件发布版本 2.5.0 | GET config 不返回 |
| `web.admin_token_sha256` | 管理员 Token 字符串的 SHA-256 | 不返回，不能通过 settings 设置 |
| `web.require_https` | 安装流程设为 true，原始 Default 为 false | 只通过 `https.required` 读取；settings 不接受 |
| `web.allow_unsafe_all_address_acl` | 默认 false | 不返回/不可通过 API 修改；严格模式仍拒绝 `/0` |
| `resource_limits.max_tcp_connections` | 默认 8192；范围 `1–1000000` | 不返回/不可通过 API 修改 |
| `resource_limits.max_udp_sessions` | 默认 16384；范围 `1–10000000` | 不返回/不可通过 API 修改 |
| `resource_limits.max_udp_memory_bytes` | 默认 1073741824；范围 `67108864–1099511627776` | 不返回/不可通过 API 修改；是估算预算，不是精确 RSS |
| `nftables.conntrack_mark` | 必须非零；Default 常量为 `0x50420001`，新配置创建流程会生成随机非零实例 mark | 不返回/不可通过 API 修改；不能把默认常量当作所有实例实际值 |
| `nftables.enable_flowtable` | 默认 true | 不返回/不可通过 API 修改；开启不代表已观测硬件卸载 |

---

## 17. Prometheus 指标

`GET /metrics` 共用管理 HTTPS、来源白名单及 Bearer 认证，GET 不要求 CSRF；成功返回 `text/plain; version=0.0.4; charset=utf-8`，不是 JSON。指标不输出规则名、转发端点或令牌，采集缺失时省略实时速率并通过有效性指标告警。配置示例、字段与 flowtable 尽力统计边界见[统计说明](MONITORING.zh-CN.md)。

## 实现依据与源码链接

以下链接按本文位于仓库 `docs/` 目录计算，并指向 v2.5.0 对应实现。引用采用文件级链接，避免行号变化导致错误定位；正文脚注用于区分服务端已有行为与本文明确标记的客户端建议。

[^routes]: [`internal/web/server.go`](../internal/web/server.go)。完整路由注册、根页面与静态资源兜底。
[^web-start]: [`internal/web/server.go`](../internal/web/server.go)。监听地址、原生 TLS、HTTP 时限与 Header 上限。
[^web-constructor]: [`internal/web/server.go`](../internal/web/server.go)。Web Server 初始化时间与随机 CSRF 生成。
[^headers]: [`internal/web/server.go`](../internal/web/server.go)。安全响应头、HTTP 层 ACL 与 JSON 响应头。
[^auth]: [`internal/web/server.go`](../internal/web/server.go)。Bearer 提取、Token 校验、同源检查、CSRF、401/403/429。
[^auth-limiter]: [`internal/web/security.go`](../internal/web/security.go)。失败认证的全局/来源 IP 令牌桶。
[^listener]: [`internal/web/security.go`](../internal/web/security.go)。先于 HTTP/TLS 的 ACL 监听器及连接限制包装。
[^read-handlers]: [`internal/web/server.go`](../internal/web/server.go)。bootstrap、status、config 的实际响应投影。
[^settings]: [`internal/web/server.go`](../internal/web/server.go)。设置请求模型、持久化、ACL/DNS 应用及待重启比较。
[^rule-handlers]: [`internal/web/server.go`](../internal/web/server.go)。Token 轮换与 Rule 创建/替换/删除处理器。
[^json]: [`internal/web/server.go`](../internal/web/server.go)。1 MiB 上限、严格 JSON 解码、APIError 与响应编码。
[^tls]: [`internal/web/security.go`](../internal/web/security.go)、[`internal/web/tls_owner_unix.go`](../internal/web/tls_owner_unix.go)。TLS 材料读取/检查、最低版本、证书状态、Unix 权限和属主检查。
[^config-model]: [`internal/config/config.go`](../internal/config/config.go)。Config、WebConfig、Rule、ResourceLimits、NFTConfig 的字段和 JSON 标签。
[^config-defaults]: [`internal/config/config.go`](../internal/config/config.go)。默认配置、加载回填、新实例 mark 与全局预算默认值。
[^config-store]: [`internal/config/config.go`](../internal/config/config.go)。Store.Get、加锁更新、校验、原子文件替换与失败回退。
[^token-storage]: [`internal/config/config.go`](../internal/config/config.go)。Token 轮换事务、本地文件一致性、Token/ID 生成与哈希。
[^normalize-rule]: [`internal/config/config.go`](../internal/config/config.go)。Rule 字符串规范化、数字默认值、范围端点和 Host 方括号处理。
[^config-validation]: [`internal/config/config.go`](../internal/config/config.go)。Web/TLS/ACL/全局资源/Rule 的校验条件与真实错误文本。
[^normalize-lists]: [`internal/config/config.go`](../internal/config/config.go)。管理白名单、目标 CIDR 与 DNS 服务器规范化及数量限制。
[^target-policy]: [`internal/config/config.go`](../internal/config/config.go)。目标 CIDR 格式、受限制地址集合与授权判定顺序。
[^rule-conflicts]: [`internal/config/config.go`](../internal/config/config.go)。仅启用规则之间的协议、端口和地址重叠检查。
[^config-clone]: [`internal/config/config.go`](../internal/config/config.go)。配置副本中的空集合保留为数组。
[^acl]: [`internal/acl/acl.go`](../internal/acl/acl.go)。有效 ACL 快照、回环恢复、严格模式、自动 LAN 与直接来源判断。
[^manager]: [`internal/proxy/manager.go`](../internal/proxy/manager.go)。设置 DNS、Apply/Refresh、启动/撤销风险、Stats 复用和运行态保留。
[^manager-runtime]: [`internal/proxy/manager.go`](../internal/proxy/manager.go)。RuleRuntime 字段与排序，Go runner 存在性检查。
[^kernel-state]: [`internal/proxy/manager_nft_state.go`](../internal/proxy/manager_nft_state.go)。运行态清理记录、未知状态、内核状态枚举与 Go 路径准入阻止。
[^plan]: [`internal/proxy/plan.go`](../internal/proxy/plan.go)。配置/运行态数据面枚举、IPv4/IPv6 路径规划、DNS 验证/缓存、worker 分配。
[^runner]: [`internal/proxy/manager.go`](../internal/proxy/manager.go)。Go runner 启动、端口偏移映射与绑定错误。
[^stats]: [`internal/proxy/stats.go`](../internal/proxy/stats.go)。StatsSnapshot 全字段、running/started_at 更新与累计计数快照。
[^tcp-stats]: [`internal/proxy/tcp.go`](../internal/proxy/tcp.go)。接入计数、上游拨号与字节数在双向复制结束后汇总。
[^udp-implementation]: [`internal/proxy/udp.go`](../internal/proxy/udp.go)。自动 worker、UDP 包过滤/丢弃/发送计数与维护汇总。
[^budgets]: [`internal/proxy/budget.go`](../internal/proxy/budget.go)。跨 runner/worker/端口/地址族共享来源预算与 UDP 令牌桶。
[^udp-doc]: [`docs/udp-dataplane.md`](udp-dataplane.md) 的 Scope、Defaults and capacity boundaries；[`README.md`](../README.md)。Go 与内核路径计数/预算边界、默认值及批量发送错误语义。
[^gui]: [`internal/web/static/app.js`](../internal/web/static/app.js) 和 [`i18n.js`](../internal/web/static/i18n.js)。API 客户端包装、bootstrap、500 ms 串行状态轮询、完整设置/Rule 提交、语言选择、已知错误翻译与本地退出。
[^cli]: [`cmd/portbridge/main.go`](../cmd/portbridge/main.go)。默认配置/Token 路径与相关启动参数。
[^deployment]: [`README.md`](../README.md)、[`packaging/portbridge.service`](../packaging/portbridge.service)。安装后的原生 HTTPS 强制策略、证书信任及回环恢复说明。
[^main-refresh]: [`cmd/portbridge/main.go`](../cmd/portbridge/main.go)。初始化、每 30 秒读取 Store 快照并刷新 ACL/规则、退出信号。
