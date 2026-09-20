# Go-nftables-portbridge v2.4.9

[English](README.md) | [简体中文](README.zh-CN.md)

Linux TCP/UDP 四层端口转发服务：Go 负责控制面和跨地址族代理，同地址族转发优先使用 nftables DNAT/SNAT 与 flowtable，并提供 Web 管理页面。

> **v2.4.9 源码发布，归档附有 Ed25519 分离签名。包含有界选择性 ACL 证明、原始 tuple 加速隔离、单设备 nft JSON 兼容及正确的非阻塞 UDP 错误处理。发布归档已签名；本地源码构建出的二进制不会自动获得发布者签名。包内不含预编译二进制，签名不代表普遍容量或部署安全保证。请阅读[当前支持边界](docs/forwarding-limits.md)。**

## 主要功能

- 管理 HTTP API：读取配置/运行状态、管理规则及设置、轮换管理员令牌；使用 Bearer 认证，写操作还需 CSRF。详见[中文 API 接口文档](docs/API.zh-CN.md)。
- TCP、UDP，或在同一规则和端口同时转发 TCP + UDP。
- IPv4 → IPv4、IPv6 → IPv6、IPv4 → IPv6、IPv6 → IPv4。
- 每条规则可选择“nftables 优先”或强制“GO”数据面。
- 同地址族外部流量使用 nftables DNAT/SNAT，已建立连接可进入 flowtable 快速路径。
- 跨地址族和通配监听的回环 fallback 使用 Go TCP/UDP 代理。
- 最多 4096 个端口的一一映射，nftables 使用确定性端口 map。
- 本机进程访问非回环转发地址时由 nftables `output` 链处理。
- 自定义 DNS；域名目标每 30 秒重新解析。
- Web 创建、编辑、启停和删除规则，500ms 串行刷新运行状态、数据面以及 Go proxy 的流量/会话/丢包统计；nftables 路径计数请使用 `nft` 查看。
- JSON 配置原子写入，规则热更新，256 位令牌认证、CSRF/同源校验与直连来源 IP/CIDR ACL。
- 公网直连管理支持原生 TLS 与显式严格 IP 白名单，并在 TLS/HTTP 解析前过滤连接及限制认证失败频率。
- 支持构建 Linux amd64/arm64 静态二进制及强化的 systemd 服务；本发布仅分发源码，不含预编译二进制。
- vendoring `golang.org/x/net v0.58.0`、`golang.org/x/sys v0.47.0`，支持离线构建。

## 架构

```text
                 ┌───────────────┐
Web UI ─────────►│ Go Controller │
                 └───────┬───────┘
                         │
           ┌─────────────┴─────────────┐
           │                           │
           ▼                           ▼
       同地址族转发                 跨地址族转发
   IPv4 → IPv4                 IPv4 → IPv6
   IPv6 → IPv6                 IPv6 → IPv4
           │                           │
           ▼                           ▼
  nftables DNAT/SNAT                 Go net
  + flowtable 快速路径           TCP/UDP proxy
```

监听地址为 `*` 时，控制器会分别规划 IPv4、IPv6 路径。例如目标只有 IPv4 地址时，IPv4 非回环入口走 nftables，IPv6 入口走 Go，回环地址使用专用 Go fallback，Web 会显示为“混合”数据面。

## 系统要求

- Linux 环境，具备 systemd、nftables、conntrack、iproute2、OpenSSH `ssh-keygen`、GNU shell/文件/文本/账户工具和 util-linux `runuser`；不支持 flowtable 时可以关闭该选项。
- 安装时需要 root。
- 源码构建与 Release 二进制均要求准确的 Go 1.27.1。

本源码发布不含预编译二进制，需要 Go 1.27.1。

历史兼容性记录：此前版本已在 Debian 13 / Ubuntu 26.04 验证；v2.4.9 未重新验证 Ubuntu。其他兼容 Linux 发行版可自行测试。任一依赖缺失时安装器使用 apt-get 安装 nftables/conntrack，非 APT 系统请先安装两者。

## 全新安装默认值

下表对应没有已有配置时，由安装器创建的实际配置：

| 项目 | v2.4.9 默认值 |
|---|---|
| 管理入口 | TCP `9080` 上的 HTTPS，监听 `127.0.0.1` 和 `::1` |
| 转发规则 | 空列表（`rules: []`），不会自动打开任何转发端口 |
| Web 新建规则表单 | TCP、`nftables 优先`、通配监听 `*`；监听端口、目标主机和目标端口必须自行填写 |
| 管理 ACL | 自动 LAN 识别关闭、严格模式关闭、持久白名单为空；保留回环访问 |
| TLS | 强制 HTTPS；最低 TLS `1.2`，可选 `1.3`；仅在未配置证书对时生成十年自签证书 |
| DNS | 无自定义解析器，使用系统 DNS；域名目标每 `30` 秒重新解析 |
| 监控 | 每 `500 ms` 串行轮询状态 |
| 全局 Go 代理预算 | `8192` 个 TCP 连接、`16384` 个 UDP 会话、`1 GiB` 估算 UDP 内存 |
| nftables | flowtable 开启；全新安装随机生成非零的实例 conntrack mark |

`config.example.json` 是示例，不是安装脚本创建的默认配置。其中启用的示例规则、文档专用目标、`443–452` 端口段和自定义 DNS 均仅供演示，手动使用前应检查或删除。`config.public.example.json` 是公网管理模板。安装器不会自动把二者作为运行配置。

管理端口 `9080` 与转发端口相互独立，只有显式配置的规则才会打开转发入口。升级保留已有管理端口、监听地址及规则，同时强制 HTTPS。

## 隔离源码评估

从 [v2.4.9 Release](https://github.com/liying-official/Go-nftables-portbridge/releases/tag/v2.4.9) 下载对应语言归档、同名 `.sig`、`SHA256SUMS`、`SHA256SUMS.sig` 和 `release-signers`，放在同一目录。解压前应使用经独立可信渠道确认的发布公钥验证分离签名，再核对 SHA256SUMS。签名认证的是发布归档的准确字节；生产部署仍需完成环境适配验证并准备回滚方案。

```bash
ssh-keygen -Y verify -f release-signers -I portbridge-release-v2 -n portbridge-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS
tar -xzf Go-nftables-portbridge-v2.4.9-zh-CN.tar.gz
cd Go-nftables-portbridge-v2.4.9-zh-CN
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOFLAGS=-mod=vendor GOWORK=off GOENV=off
go version  # 必须显示 go1.27.1
go test ./...
go build -trimpath -ldflags="-X main.version=2.4.9" -o build/portbridge ./cmd/portbridge
```

完整特权命名空间矩阵可在隔离评估机运行 `sudo bash scripts/verify-candidate.sh /实际绝对路径/go1.27.1/bin/go`。该脚本新建网络命名空间及私有证据/缓存目录，必需覆盖出现 Skip 时失败，不修改宿主机防火墙。请传入实际工具链路径。

在隔离评估机运行既有干净源码安装分支（`sudo ./scripts/install.zh-CN.sh`），会从固定 PATH 使用 Go 1.27.1 构建、按需安装 nftables/conntrack、开启转发、准备 HTTPS 并启动服务。此操作修改系统；用于生产前应验证目标环境。预编译安装仍强制执行原有固定签名校验。

安全默认值只监听回环地址，请先建立 SSH 隧道：

```bash
ssh -L 9080:127.0.0.1:9080 root@服务器
```

然后在本机打开 `https://127.0.0.1:9080/`。生成自签证书时，先核对安装输出中的指纹并建立客户端信任。HTTPS 不会改变默认回环监听或 IP 白名单。

安装脚本默认不输出管理员令牌，避免无人值守部署日志记录凭据。令牌以受限权限保存，可用以下命令查看：

```bash
sudo cat /etc/portbridge/admin.token
```

如果启动日志报告令牌文件不一致或缺失，先停止服务，再以服务账户重置令牌并重新启动，以保持文件属主正确，并让进程加载新凭据：

```bash
sudo systemctl stop portbridge
sudo -u portbridge /usr/local/bin/portbridge --config=/etc/portbridge/config.json --token-file=/etc/portbridge/admin.token --reset-admin-token
sudo systemctl start portbridge
```

重置命令会输出新密钥，请在私密终端执行。自定义部署必须使用与服务相同的配置路径、令牌路径和运行账户。

交互式安装时，只有在确认终端输出不会被记录的情况下才使用 `--show-token`。安装器支持以下选项：

| 选项 | 用途 |
|---|---|
| `--allow IP/CIDR[,更多]` | 添加临时启动 ACL；不会修改 Web 监听地址，也不会绕过 TLS |
| `--tls-cert FILE` / `--tls-key FILE` | 导入证书和匹配私钥，复制到托管 TLS 目录 |
| `--tls-name DNS或IP` | 为首次生成的自签证书追加 SAN，可重复 |
| `--no-start` | 准备安装文件、强制 HTTPS 和管理员令牌，但保持服务停止 |
| `--show-token` | 启动后输出令牌；不要用于会捕获输出的部署日志 |

升级或恢复已经配置了非回环监听的实例时，可以临时添加启动 ACL：

```bash
sudo ./scripts/install.sh --allow 203.0.113.10/32
```

多个 IPv4/IPv6 网段使用英文逗号分隔。`--allow` 不会让全新的回环监听实例变成远程可访问；它只是启动/恢复用的临时权限，不能替代 TLS 和主机防火墙，严格白名单模式也会主动忽略它。

使用不含 `dist/` 预编译文件的干净源码目录时，先安装准确的 Go 1.27.1，再运行同一安装器。Go 必须位于安装器固定 PATH 可见的位置（如 `/usr/local/go/bin` 或标准系统二进制目录），不能只依赖个人 shell 的 PATH。构建使用 vendored 依赖：

```bash
go version  # 必须显示 go1.27.1
sudo ./scripts/install.sh
```

## HTTPS 证书与后续替换

安装与升级会在服务启动前（包括 `--no-start`）设置 `web.require_https=true`、关闭 `allow_insecure_http` 并准备证书；systemd 服务也强制要求 HTTPS。设置 API 拒绝清空证书或重新开启明文 HTTP。

未配置证书时，安装器自动生成每台机器独立的 ECDSA P-256 自签证书，有效期十年。SAN 包含 localhost、回环地址、当前机器主机名及网卡单播 IP；首次生成时可用 `--tls-name admin.example.com` 或 `--tls-name 203.0.113.10` 追加管理域名或外部映射 IP。升级保留已有有效证书；已配置但过期、缺失或不匹配的证书会中止安装，不会被悄悄替换。若后续 IP/域名变化且新名称不在 SAN 中，需要替换证书。

自签 TLS 能加密传输，但浏览器不会自动信任。请通过可信渠道核对服务器安装输出中的 SHA-256 指纹，再把公开证书导入客户端信任存储；不要分发私钥或盲目绕过证书警告。安装输出与 Web 页面均明确提示自签证书；页面显示的是当前进程实际加载的证书。

安装或升级时提供正式证书与私钥：

```bash
sudo ./scripts/install.sh --tls-cert /secure/fullchain.pem --tls-key /secure/privkey.pem
```

证书和私钥必须匹配、当前有效，使用非符号链接的绝对路径，并符合属主/权限检查。安装器会把显式导入的文件复制到 `/etc/portbridge-tls` 下新建的管理目录，不修改源文件；生成或导入的私钥使用 root 属主及服务组只读权限（`0640`）。

后续替换时，把 CA 签发证书和匹配私钥放到服务器，确保服务账户能读取文件及父目录（私钥例如 `root:portbridge 0640`），在 Web 访问设置填写绝对路径、保存，再运行 `sudo systemctl restart portbridge`。同路径续期也需重启。反向代理到已安装服务也应使用 HTTPS，并验证后端证书/主机名；真实客户端白名单仍需由代理执行。

## 公网管理部署

安装后的服务只在回环地址提供 HTTPS，并关闭自动 LAN 识别，因此远程无法直接访问。不要为了公网暴露而削弱该默认值。

公网直连管理请参考 [config.public.example.json](config.public.example.json)，并同时落实以下控制：

1. 在云安全组与主机防火墙中，只允许管理员的精确来源 IP 访问 TCP/9080。应用 ACL 属于纵深防御，不能代替抗流量型 DoS 的边界过滤。
2. 使用覆盖管理 IP/域名且当前有效的证书，并建立客户端信任。通过 Web 直接替换时，私钥须能被服务读取：可用 `portbridge` 属主的 `0600`，或 `0640 root:portbridge`，父目录也须允许服务账户进入。
3. 先设置绝对路径 `web.tls_cert_file`、`web.tls_key_file`，重启服务并确认 HTTPS 正常。
4. 再从该 HTTPS 会话关闭 `web.auto_lan_acl`，把当前直连客户端地址加入 `web.whitelist`，然后启用 `web.strict_ip_allowlist`。

Web UI 强制采用以上两阶段切换，不能从明文 HTTP 会话直接启用严格模式。全新安装也可以在服务停止时离线准备好全部字段，然后直接以严格 HTTPS 模式启动。使用公网示例前必须替换其中仅供文档示范的地址。证书在同一路径续期后仍需执行 `systemctl restart portbridge`。

严格模式始终保留本机回环恢复通道，除此以外只使用持久白名单；它忽略自动 LAN 和 `--bootstrap-allow`，拒绝 `0.0.0.0/0`、`::/0`，白名单最多 1024 项。TLS 默认最低版本为 1.2；公网直连管理面可把 `web.tls_min_version` 设为 `1.3` 并重启。TLS 响应包含 HSTS。

PortBridge 从不信任 `Forwarded` 或 `X-Forwarded-For`。如果由反向代理终止 TLS，应让 PortBridge 只监听回环/私网地址，并在代理与防火墙按真实客户端执行白名单；PortBridge 只能看到直接连接的代理地址。原生严格模式主要面向直接 TLS 连接。

## 数据面选择

- `nftables 优先`（默认）：同地址族走内核 DNAT/SNAT，外部已建立 TCP/UDP 流可进入 `fastpath` flowtable；跨地址族及通配回环 fallback 自动走 Go。
- `GO`：整条规则强制使用 Go TCP/UDP 代理。

控制器校验自有 `inet portbridge` 的真实表 owner。普通更新保留 flowtable；关闭加速删除对象但保留 NAT。旧路径必须精确撤销 conntrack，不能以删表代表停止转发。失败保留风险状态/墓碑并阻止重叠替换；恢复、防火墙共存及手动 NAT-only 的限制见[转发限制](docs/forwarding-limits.md)。

## 协议与端口段

`protocol` 支持 `tcp`、`udp`、`both`。`both` 会在相同监听端点同时启动 TCP 与 UDP 转发。

监听端口段与目标端口段必须等长，最多 4096 个端口：

```text
监听: 10000-10099
目标: 20000-20099
```

以上配置按 `10000 → 20000`、`10001 → 20001` 依次映射。nftables 数据面使用确定性目标端口 map，而不是 NAT 端口池。

## DNS 与域名更新

Web 设置页面支持最多 8 个自定义 DNS，每行一个：

```text
1.1.1.1
8.8.8.8:53
[2606:4700:4700::1111]:53
```

未写端口时使用 `53`；留空使用系统 DNS。除非所选本地/系统解析器自行提供加密上游，否则 DNS 流量本身仍是明文。域名目标每 30 秒解析一次，每次刷新都会重新校验所有返回地址，阻止 DNS rebinding 指向未授权的本机、私网、链路本地、多播、未指定、运营商级 NAT 或云元数据地址。私网目标必须同时设置 `allow_private_target=true` 与精确的 `target_cidr_allowlist`。地址变化时原子更新 nftables，并只重建受影响的 Go 路径；临时解析失败时保留上一次有效地址。

## 本机进程访问

- 本机进程访问非回环转发地址时由 nftables `output` 链处理。
- 通配监听的 `127.0.0.1`、`::1` 使用专用 Go fallback。
- 程序不会启用安全风险较高的 `route_localnet`。

## 配置

运行配置位于 `/etc/portbridge/config.json`。[config.example.json](config.example.json) 用于演示字段和规则，不等同于全新安装默认值。

下列连接/会话/速率/估算内存限额作用于 Go 代理路径，不会自动限制 nftables/flowtable 内核转发；如需约束内核路径，请另行配置防火墙/内核限流。管理 ACL 也不保护转发入口。

| 字段 | 说明 |
|---|---|
| `web.port` | Web 管理端口；修改后需要重启 |
| `web.listen_ipv4` / `listen_ipv6` | Web IPv4/IPv6 监听地址 |
| `web.auto_lan_acl` | 自动授权直连私网、ULA、链路本地接口网段 |
| `web.strict_ip_allowlist` | 公网直连模式：强制原生 TLS，仅允许回环与显式白名单 |
| `web.require_https` | 安装器设置为 true，强制证书并拒绝 API 降级 |
| `web.allow_insecure_http` | 仅保留开发兼容字段，安装后拒绝启用 |
| `web.whitelist` | 手动 IP/CIDR 白名单 |
| `web.tls_cert_file` / `tls_key_file` | 原生 TLS 证书/私钥绝对路径；修改后需重启 |
| `web.tls_min_version` | TLS 最低版本：`1.2`（默认）或 `1.3`；修改后需重启 |
| `web.dns_servers` | 自定义 DNS；留空使用系统 DNS |
| `resource_limits.*` | 全局 TCP 连接、UDP 会话及估算 UDP 内存上限 |
| `nftables.conntrack_mark` | 非零实例 mark，用于限制全部受管 NAT/forward 规则作用域 |
| `nftables.enable_flowtable` | 是否启用可选 nftables flowtable 快速路径 |
| `rules[].protocol` | `tcp`、`udp` 或 `both`；Web 新建表单默认选中 TCP 与启用 |
| `rules[].data_plane` | `nftables` 或 `go` |
| `rules[].listen_port_end` / `target_port_end` | 可选的等长端口段结束值 |
| `rules[].allow_private_target` / `target_cidr_allowlist` | 私网目标的两段式、窄范围授权 |
| `rules[].tcp_idle_timeout_seconds` | 关闭不活动 TCP proxy；默认 `300` 秒 |
| `rules[].max_tcp_connections` / `max_tcp_connections_per_source` | 单规则/单来源上限；默认 `2048` / `256` |
| `rules[].max_udp_sessions` / `max_udp_sessions_per_source` | 跨全部 worker、端口、地址族和 Go runner 的精确整规则/来源 IP 会话上限；默认 `4096` / `512` |
| `rules[].udp_new_sessions_per_second_per_source` | 全部 Go 路径共享的精确整规则来源 IP 新建会话速率；默认 `1000`/秒 |
| `rules[].udp_packets_per_second_per_source` | 全部 Go 路径共享的精确整规则来源 IP 报文速率；默认 `100000`/秒 |
| `rules[].udp_workers` | 整条规则共享的 worker 预算；`0` 自动选择 |
| `rules[].udp_batch_size` | `ReadBatch`/`WriteBatch` 批大小；默认 `64` |
| `rules[].udp_packet_buffer_size` | 预分配单包缓冲；默认 `2048` 字节 |
| `rules[].udp_listener_buffer_bytes` | 入口 socket 缓冲请求值；默认 `4 MiB` |
| `rules[].udp_session_buffer_bytes` | connected 会话 socket 缓冲请求值；默认 `64 KiB` |

规则、ACL、DNS 修改会立即热应用；Web 监听地址、端口、TLS 路径或 TLS 最低版本修改后需要重启。严格模式启用后立即生效，只允许从现有 HTTPS 会话操作，并要求白名单继续包含当前直连客户端。

为兼容旧 API 客户端，保存设置时省略 `tls_min_version` 或发送空值会保留已有 TLS 策略；恢复默认值需显式发送 `1.2`。重复保存不会清除尚未生效的 `restart_required` 提示；只有重启使监听配置一致，或撤销变更，才会清除此提示。

## 性能设计

- Go TCP 优先使用 `net.TCPConn.ReadFrom`，Linux 可走 `splice`；fallback 使用池化 64 KiB 缓冲并保留半关闭语义。
- UDP worker 独占入口 socket、packet slab、batch Message、`netip.AddrPort` 会话表、epoll、时间轮和统计。
- Linux 通过 `ReadBatch/WriteBatch` 使用 `recvmmsg/sendmmsg`。
- `SO_REUSEPORT` 将 flow 分配到 worker-local socket，会话查表仍是 worker-local；精确来源 IP 限制使用规则级 64 分片，每个入口报文只短暂持有一个计数/token bucket 分片锁，绝不跨 socket I/O 持锁。
- connected UDP 上游 socket 避免逐包处理目标地址并由内核过滤远端。
- hot path 不进行逐包 goroutine、channel、JSON、数据库或日志操作。
- 全局、单规则及单来源预算在资源失控前拒绝多余 TCP/UDP 状态；UDP 监听 slab 和 connected 会话缓冲共同受全局估算内存上限约束。

详细设计与调优建议见 [docs/udp-dataplane.md](docs/udp-dataplane.md)。

## 服务管理

```bash
sudo systemctl status portbridge
sudo journalctl -u portbridge -f
sudo systemctl restart portbridge
sudo nft list table inet portbridge
sudo nft list flowtable inet portbridge fastpath  # 仅 enable_flowtable=true 时
```

公开项目名称是 `Go-nftables-portbridge`。为兼容已有安装，二进制、systemd 服务、配置目录和 nftables 表仍使用 `portbridge` 标识。

## 安全说明

- 管理 API 使用随机 256 位 bearer token、需认证的 CSRF 初始化、浏览器同源校验和有界 JSON 请求体。认证失败按来源及全局限速，有效令牌不会被失败尝试锁死。
- 安装后强制 HTTPS；缺少证书时为每台机器独立生成自签证书，明确展示证书类型和指纹。
- 浏览器只把令牌保存在当前标签页的 `sessionStorage`，不会写入持久 `localStorage`；关闭标签页即清除，退出或认证失效时还会清空页面中的管理数据。安装不可信浏览器扩展或存在脚本注入的终端不在信任边界内。
- ACL 只使用 TCP 直连来源地址，不信任 `X-Forwarded-For`。
- 严格模式在 TLS 握手/HTTP 解析前过滤不允许的来源，HTTP 中间件会再次校验，并限制已接受的管理连接总数；公网仍必须配置上游防火墙。
- 配置和管理员令牌均以 `0600` 权限保存；TLS 私钥拒绝符号链接、不安全属主和过宽权限。systemd 单元禁用 core dump、过滤危险系统调用，并设置文件描述符、任务、CPU 与内存上限。
- 新目标及 DNS 故障时的缓存地址均重新校验当前授权；已有内核连接撤销仍受文档所列转发限制约束。
- 当前 Release 通过 Ed25519 分离签名认证源码归档，并使用干净源码构建路径。独立的预编译安装清单验签机制保持不变，归档签名不能替代该二进制包验证契约。
- 默认启动日志不记录规则名称和转发端点；debug 及错误日志仍可能包含运行网络详情，必须妥善保护。
- 不要提交 `/etc/portbridge/config.json`、`/etc/portbridge/admin.token`、日志、数据库或环境文件。

漏洞报告方式见 [SECURITY.md](SECURITY.md)。

## 构建与测试

依赖已提交到 `vendor/`，包括有记录的 batch 地址复用补丁，可完全离线构建：

```bash
go version              # 必须显示 go1.27.1
GOPROXY=off go test ./...
GOPROXY=off go test -race ./...
GOPROXY=off go vet ./...
make dist
```

v2.4.9 使用 Go 1.27.1 构建，以 `http.Server.MaxHeaderValueCount` 配合字节限制约束请求头；不开放公网 `pprof`。
`make dist` 生成的是未签名开发二进制，不是已签名 Release。安装器会拒绝缺少相应签名的预编译文件；不要把该输出当作可安装 Release，也不要绕过验证。

## 发布归档签名与源码构建

签名对象是 Release 上传的两个 `.tar.gz` 源码归档和 `SHA256SUMS`，各有同名 `.sig` 文件。它们不含预编译二进制，也不是预编译安装器要求的内部 bundle manifest/signature。`go build`、源码安装和 `make dist` 不会自动为新生成的二进制添加发布者签名。

发布公钥指纹为 `SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o`，身份 `portbridge-release-v2`，namespace `portbridge-release`。先通过独立可信的项目副本/渠道核对预期公钥，再使用下载的 `release-signers`；不能只相信与归档一起下载的陌生公钥。公钥指纹不是 TLS 证书指纹或制品 SHA256。

```bash
ssh-keygen -lf release-signers -E sha256
ssh-keygen -Y verify -f release-signers -I portbridge-release-v2 -n portbridge-release -s SHA256SUMS.sig < SHA256SUMS
sha256sum -c SHA256SUMS
# 也可直接验证单个语言归档：
ssh-keygen -Y verify -f release-signers -I portbridge-release-v2 -n portbridge-release -s Go-nftables-portbridge-v2.4.9-zh-CN.tar.gz.sig < Go-nftables-portbridge-v2.4.9-zh-CN.tar.gz
```

`SHA256SUMS` 列出两个语言包；完整检查需同时下载两包。仅下载一包时，可以直接验证该归档的分离签名；不要把另一包缺失的提示当作所选归档已损坏。GitHub 自动生成的 Source code (zip/tar.gz)、Git 检出及后来修改的源码树不属于这些附件签名的覆盖对象。任何归档字节变化都需重新计算摘要并重新签名，不能复用旧签名。

签名证明经信任公钥认证的来源及完整性，不证明构建结果、安全无漏洞或适合所有生产环境。`verify-candidate.sh` 的测试/人工发布审批门禁与归档验签是两套机制；签名不能豁免测试失败，也不会改变该脚本的退出策略。

## 卸载

保留配置：

```bash
sudo ./scripts/uninstall.sh
```

同时删除配置与服务账号：

```bash
sudo ./scripts/uninstall.sh --purge
```

独立的 `/etc/portbridge-tls` 目录会被刻意保留，避免卸载操作静默删除证书或私钥。

## 许可证

[MIT](LICENSE)
