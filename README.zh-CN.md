# Go-nftables-portbridge v2.4.9

[English](README.md) | [简体中文](README.zh-CN.md)

Linux TCP/UDP 四层端口转发服务：Go 负责控制面和跨地址族代理，同地址族转发优先使用 nftables DNAT/SNAT 与 flowtable，并提供 Web 管理页面。

> **v2.4.9 提供中英双语 Linux amd64/arm64 签名预编译包。包含有界选择性 ACL 证明、原始 tuple 加速隔离、单设备 nft JSON 兼容及正确的非阻塞 UDP 错误处理。顶层校验和与包内安装清单均有 Ed25519 签名；预编译安装无需 Go，本地重新构建的二进制不会自动获得发布者签名。签名不代表普遍容量或部署安全保证。请阅读[当前支持边界](docs/forwarding-limits.md)。**

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
- 支持构建 Linux amd64/arm64 静态二进制及强化的 systemd 服务；Release 按架构和语言提供预编译二进制。
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
- 仅自行源码构建时需要准确的 Go 1.27.1；Release 预编译安装不需要 Go。

Release 每包包含一个架构的预编译二进制、对应语言界面、安装脚本和文档，并附源码供检查。

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

## 使用 Release 预编译包首次安装

本节适用于尚未安装 PortBridge 的 Linux 主机；已有实例应先备份配置并安排维护窗口，不应直接作为首次安装处理。需要 Bash、curl、CA 证书、tar/gzip、sha256sum、awk、OpenSSH `ssh-keygen`、systemd 及前述系统依赖。无需安装 Go。root 会话可省略下列命令中的 `sudo`。

### 1. 选择架构并下载中文包

在目标服务器执行。`x86_64` 选择 amd64，`aarch64`/`arm64` 选择 arm64；下面代码会自动选择。可用制品为 `portbridge-v2.4.9-linux-amd64-zh-CN.tar.gz` 和 `portbridge-v2.4.9-linux-arm64-zh-CN.tar.gz`，详见 [v2.4.9 Release](https://github.com/liying-official/Go-nftables-portbridge/releases/tag/v2.4.9)。不要选 GitHub 自动生成的 Source code 归档，它不含预编译二进制。以下步骤在同一个 Bash 会话中依次运行。

```bash
set -euo pipefail
case "$(uname -m)" in
  x86_64) PB_ARCH=amd64 ;;
  aarch64|arm64) PB_ARCH=arm64 ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
PB_LANG='zh-CN'
PB_NAME="portbridge-v2.4.9-linux-${PB_ARCH}-${PB_LANG}"
PB_URL='https://github.com/liying-official/Go-nftables-portbridge/releases/download/v2.4.9'
PB_WORK=$(mktemp -d)
cd "$PB_WORK"
curl -q -fL --proto '=https' --proto-redir '=https' -o "$PB_NAME.tar.gz" "$PB_URL/$PB_NAME.tar.gz"
for PB_FILE in SHA256SUMS SHA256SUMS.sig SBOM; do
  curl -q -fL --proto '=https' --proto-redir '=https' -H 'Cache-Control: no-cache' \
    -o "$PB_FILE" "$PB_URL/$PB_FILE?release=binary-v2.4.9"
done
curl -q -fL --proto '=https' --proto-redir '=https' -o release-signers \
  'https://raw.githubusercontent.com/liying-official/Go-nftables-portbridge/c54d27252e5e76fe76eaf8a3c63f37cab304eb40/packaging/release-signers'
```

下载的 `release-signers` 来自固定源码提交；仍应通过独立可信渠道核对下面的预期指纹。与归档一起取得的公钥本身不是独立信任依据。若同名校验和文件命中旧缓存，请重新获取最新文件；不要跳过验签。

### 2. 验签、校验并安装

先验证 SHA256SUMS 的 Ed25519 分离签名，再从可信清单选择本语言/架构包和 SBOM 的摘要；无需下载其余三个包。任一步失败立即停止。当前 Release 不提供逐归档 `.tar.gz.sig`，也不提供独立的 `release-signers` 附件。

```bash
PB_EXPECTED_FP='SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o'
test "$(ssh-keygen -lf release-signers -E sha256 | awk '{print $2}')" = "$PB_EXPECTED_FP"
ssh-keygen -Y verify -f release-signers -I portbridge-release-v2 -n portbridge-release -s SHA256SUMS.sig < SHA256SUMS
awk -v file="$PB_NAME.tar.gz" '$2 == file || $2 == "SBOM" { print; n++ } END { if (n != 2) exit 1 }' SHA256SUMS > selected-SHA256SUMS
sha256sum -c selected-SHA256SUMS
tar -xzf "$PB_NAME.tar.gz"
cd "$PB_NAME"
test "$(./dist/go-nftables-portbridge-linux-$PB_ARCH -version)" = '2.4.9'
sudo ./scripts/install.sh
```

安装器优先使用包内当前架构的二进制，校验固定公钥、内部签名清单、源码/脚本摘要、二进制摘要及版本后再安装；不会要求 Go 编译器。请勿删除 `dist/` 或绕过验签。安装会创建服务账户、部署 systemd 单元、设置转发并启动服务；缺少 nftables/conntrack 时会使用 apt-get 安装，非 APT 系统请提前准备依赖。

未提供 TLS 证书时，安装器自动生成十年自签证书并强制 HTTPS；如需使用已有证书，将最后一条命令替换为 `sudo ./scripts/install.sh --tls-cert /absolute/path/fullchain.pem --tls-key /absolute/path/privkey.pem`。证书及私钥路径应为服务器上的实际文件；不要把示例配置直接覆盖到正式配置中。

### 3. 确认服务并首次访问

```bash
systemctl is-active portbridge
systemctl show portbridge -p ActiveState -p SubState -p Result -p MainPID -p NRestarts
/usr/local/bin/portbridge -version
sudo journalctl -u portbridge -n 50 --no-pager
```

应确认服务为 `active/running`、版本为 `2.4.9`，且没有反复重启；失败时先检查日志，不要关闭 HTTPS 或放开所有 IP。上述日志可能含运行信息，分享前需脱敏。全新安装规则为空，不会自动开启转发端口；登录后创建规则并验证实际 TCP/UDP 流量。ARM64 制品已做 QEMU 用户态检查，不等同于原生 ARM64 systemd/内核验收。

下面的 SSH 隧道命令在管理员电脑执行，将 `SERVER` 替换为服务器地址。若本机 9080 已被占用，可将隧道的第一个端口改为其他端口，并相应调整浏览器访问地址。

安全默认值只监听回环地址，请先建立 SSH 隧道：

```bash
ssh -L 9080:127.0.0.1:9080 root@SERVER
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
- 当前 Release 通过已签名 SHA256SUMS 认证四个预编译归档和 SBOM；包内签名清单另行绑定二进制及源码/脚本，安装器保留固定信任链校验。
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

## 发布签名与源码构建的区别

当前 Release 包含四个 `portbridge-v2.4.9-linux-{amd64,arm64}-{en-US,zh-CN}.tar.gz`、`SHA256SUMS`、`SHA256SUMS.sig` 和 CycloneDX 1.6 JSON 格式的 `SBOM`。先用固定发布公钥验证 SHA256SUMS 签名，再检查所选归档和 SBOM 的摘要；具体命令见首次安装教程。

每包的 `release-bundle-manifest.json.sig` 认证内部清单，该清单绑定版本、源码修订、Go 工具链、架构和二进制/源码摘要。签名身份为 `portbridge-release-v2`，namespace 为 `portbridge-release`，固定指纹为 `SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o`。

Git 检出、GitHub 自动生成的 Source code 归档和自行运行 `go build`/`make dist` 的产物不会自动获得这些发布签名。签名认证准确制品的来源和完整性，不保证零漏洞或任意生产环境兼容；归档字节变化后必须重新计算摘要并签名。

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
