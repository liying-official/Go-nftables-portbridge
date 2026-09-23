# Go-nftables-portbridge — v2.5.0

[![Release](https://img.shields.io/github/v/release/liying-official/Go-nftables-portbridge)](https://github.com/liying-official/Go-nftables-portbridge/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-informational)
![Architecture: amd64 / arm64](https://img.shields.io/badge/arch-amd64%20%7C%20arm64-informational)

[English](README.md) | [简体中文](README.zh-CN.md)

**面向 Linux 的 TCP/UDP 端口转发工具，通过易用的 WebGUI 或 HTTP API 管理。**

PortBridge 将 nftables/flowtable 加速与 Go 代理结合：符合条件的同地址族流量使用内核转发，IPv4 ↔ IPv6 跨地址族流量使用 Go 代理。支持按规则选择数据面、热更新规则，并在浏览器中查看实际运行状态。

[下载发布版](https://github.com/liying-official/Go-nftables-portbridge/releases/latest) · [中文 API 文档](docs/API.zh-CN.md) · [转发边界](docs/forwarding-limits.md) · [反馈问题](https://github.com/liying-official/Go-nftables-portbridge/issues)

## 主要功能

| 能力 | 说明 |
|---|---|
| WebGUI 与 API | 创建、编辑、启停和删除规则，管理设置，查看运行状态，轮换管理员令牌。 |
| Tabler 双语界面 | 同一界面切换简体中文 / English，采用天蓝色卡片、响应式规则表和移动端导航；Tabler Core 与 Icons 均由本机提供。 |
| TCP / UDP | 支持 TCP、UDP 或两者同时转发；支持单端口及最多 4096 个端口的等长端口段映射。 |
| IPv4 与 IPv6 | 支持 IPv4 → IPv4、IPv6 → IPv6、IPv4 → IPv6、IPv6 → IPv4。 |
| 双数据面 | 优先使用 nftables DNAT/SNAT 和可选 flowtable 加速，也可显式选择 Go TCP/UDP 代理。 |
| DNS 与监控 | 自定义 DNS、30 秒域名刷新、每规则实时速率、Go 统计及 nft/flowtable 尽力采集；支持 [Prometheus `/metrics`](docs/MONITORING.zh-CN.md)。 |
| 安全安装 | 提供中英双语 amd64/arm64 签名预编译包，无需 Go 编译器；使用 HTTPS 管理和独立 systemd 服务账户。 |

登录页、管理页和规则弹窗均提供语言菜单。两种语言发布包包含相同的双语 WebUI，包语言决定初始界面语言、安装提示和文档语言。浏览器只在 localStorage 中记忆语言偏好，管理员令牌仍仅保存在 sessionStorage 中。

**注意边界：**管理白名单不保护转发端口，Go 代理资源预算不会自动作用于 nftables 路径。界面将 Go 有效载荷与 nft L3 累计值合并为近似展示值，实时速率及 API/Prometheus 来源仍分开，flowtable 采样可能延迟或遗漏短连接。Flowtable 是否可用取决于内核及周边防火墙，不能假设不满足条件的规则都会自动回退到 Go。与其他防火墙/NAT 软件共存前，请阅读[转发边界](docs/forwarding-limits.md)。

## 快速开始

如需交互式首次安装，请参阅[一键安装脚本](docs/ONECLICK.zh-CN.md)：自动选择最新稳定版，交互选择语言和持久严格 IP 白名单，并在本机网卡地址开放管理监听。这与下方默认仅回环访问的手动流程不同；已有实例不会被自动覆盖。

请在交互式 **root Bash 终端**执行（非 root 用户先运行 `sudo -i`）：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/liying-official/Go-nftables-portbridge/main/scripts/install-oneclick.sh)
```

此命令下载并执行当前 `main` 分支脚本，仅在信任本仓库时使用；如有需要，请先下载审阅。下载报错或未出现安装提示不代表安装成功。

### 1. 准备服务器

使用运行 **systemd 的 Linux 主机**，CPU 为 **amd64 或 arm64**，并具备 root/sudo 权限。主机必须允许修改 nftables 和网络 sysctl；受限容器不能替代满足这些要求的主机。需要 Bash、tar/gzip、`sha256sum`、`awk`、标准 GNU/账户工具及 `runuser`。

Debian/Ubuntu 可先一次性安装附加依赖。root 用户省略 `sudo`：

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends ca-certificates curl openssh-client nftables conntrack iproute2
```

其他发行版请使用自己的包管理器准备同等依赖。非 APT 系统请提前安装全部依赖，因为安装器在缺少 nftables 或 conntrack 时会调用 `apt-get`。

### 2. 下载、验证并安装

以下代码安装 **v2.5.0 中文预编译发布包**，自动选择 CPU 架构。在服务器上完整复制执行即可，兼容 root 和 sudo 用户，**无需安装 Go**。已有实例请先阅读[升级与卸载](#升级与卸载)。

```bash
bash <<'BASH'
set +x
set -euo pipefail
umask 077
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo '不支持的 CPU 架构' >&2; exit 1 ;;
esac
NAME="portbridge-v2.5.0-linux-${ARCH}-zh-CN"
BASE='https://github.com/liying-official/Go-nftables-portbridge/releases/download/v2.5.0'
WORK=$(mktemp -d)
cd "$WORK"
for FILE in "$NAME.tar.gz" SHA256SUMS SHA256SUMS.sig; do
  curl -q -fL --proto '=https' --proto-redir '=https' \
    -H 'Cache-Control: no-cache' -o "$FILE" "$BASE/$FILE?release=binary-v2.5.0"
done
printf '%s\n' 'portbridge-release-v2 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINVc6m1afFOM3gsLO6VXuLyAlHbkvBP83wlMEqArW/0k' > release-signers
ssh-keygen -Y verify -f release-signers -I portbridge-release-v2 \
  -n portbridge-release -s SHA256SUMS.sig < SHA256SUMS
awk -v file="$NAME.tar.gz" '$2 == file { print; n++ } END { if (n != 1) exit 1 }' \
  SHA256SUMS > selected-SHA256SUMS
sha256sum -c selected-SHA256SUMS
mkdir package
tar -xzf "$NAME.tar.gz" --strip-components=1 -C package
cd package
test -x "dist/go-nftables-portbridge-linux-$ARCH"
if (( EUID == 0 )); then ./scripts/install.sh; else sudo ./scripts/install.sh; fi
test "$(/usr/local/bin/portbridge -version)" = '2.5.0'
systemctl is-active --quiet portbridge
test "$(systemctl show portbridge -p SubState --value)" = running
systemctl show portbridge -p ActiveState -p SubState -p Result -p MainPID -p NRestarts
printf '已安装；发布包解压目录：%s\n' "$PWD"
BASH
```

流程会在**解压或执行归档前**验证校验和清单的签名，核对当前发布包摘要，再调用包内安装器。安装器继续检查固定发布公钥、内部清单、源码/脚本摘要、二进制摘要和版本。任一步失败都会停止，请勿绕过校验。

末尾命令要求版本为 `2.5.0`、服务为 `active/running`，并输出结果、进程 ID 和重启次数。安装器会创建服务账户、配置 HTTPS、安装并启用 systemd 服务、设置转发 sysctl，然后启动 PortBridge。全新安装**不包含任何转发规则**。

#### 发布包与签名信任说明

请选择 [v2.5.0 Release](https://github.com/liying-official/Go-nftables-portbridge/releases/tag/v2.5.0) 中上传的附件，不要选择 GitHub 自动生成的 **Source code** 归档。

| CPU | 英文包 | 简体中文包 |
|---|---|---|
| amd64 / x86_64 | `portbridge-v2.5.0-linux-amd64-en-US.tar.gz` | `portbridge-v2.5.0-linux-amd64-zh-CN.tar.gz` |
| arm64 / aarch64 | `portbridge-v2.5.0-linux-arm64-en-US.tar.gz` | `portbridge-v2.5.0-linux-arm64-zh-CN.tar.gz` |

Release 还提供 `SHA256SUMS`、`SHA256SUMS.sig` 和 `SBOM`。快速安装只下载当前架构/语言包及两个校验文件，不需要其余三个包或 SBOM。此版本没有逐归档 `.tar.gz.sig`，也没有独立的 `release-signers` 附件。

安装代码固定使用发布公钥，而不是信任随归档下载的未知公钥。首次使用前，应通过独立可信渠道核对指纹：

```text
SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o
```

签名身份为 `portbridge-release-v2`，命名空间为 `portbridge-release`。签名只能在可信公钥的前提下证明来源及完整性，并不保证部署没有漏洞。命令有意固定到 `2.5.0`；升级时请使用对应版本的说明与信任材料。

安装前不要修改已验证包内的文件，包括 README；这些文件受内部签名清单保护。修改或重新打包 Release 后，必须重新生成清单、校验和及发布者签名。


### 3. 打开 WebGUI

默认管理入口仅监听 **`127.0.0.1` 和 `::1` 的 HTTPS 9080 端口**，不会直接暴露到公网。在管理员电脑上，将 `USER`、`SERVER` 替换为 SSH 用户和服务器地址，建立并保持隧道：

```bash
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:9080:127.0.0.1:9080 USER@SERVER
```

浏览器打开 **https://127.0.0.1:9080/**。若安装器生成了自签证书，请先核对服务器安装输出中的 SHA-256 指纹，并建立客户端信任，再登录；不要盲目忽略证书警告。

在**服务器**的私密终端读取管理员令牌：

```bash
sudo cat /etc/portbridge/admin.token
```

使用该令牌登录。普通安装不会直接打印令牌，请勿将其放入截图、Issue 或部署日志。若本机 9080 已被占用，修改隧道命令中的第一个 `9080`，并使用对应的本机端口访问浏览器。

## 创建第一条转发规则

在 WebGUI 中添加规则，填写协议、监听地址/端口、目标主机/端口和数据面偏好。保存后先检查**实际运行状态**，再从应被允许访问转发端口的客户端测试流量。

| 转发方向 | 数据面行为 |
|---|---|
| IPv4 → IPv4 / IPv6 → IPv6 | 符合条件时可使用 nftables；选择 `GO` 可显式使用代理。 |
| IPv4 → IPv6 / IPv6 → IPv4 | 使用 Go TCP/UDP 代理。 |
| 通配监听 `*` | 分别规划 IPv4、IPv6，可能采用混合数据面，并为回环流量提供专用 Go 处理。 |

端口段示例：`10000–10009 → 20000–20009`，按端口一一映射；两个范围必须等长，最多 4096 个端口。转发到私网目标时，需要**同时**设置 `allow_private_target=true` 和范围明确的 `target_cidr_allowlist`，不要宽泛地关闭目标检查。

全新安装不会加载 [config.example.json](config.example.json)。其中的规则和目标仅供演示，不是可直接使用的生产默认值。请填写自己的实际端点，并通过主机防火墙/云安全组仅允许必要的转发流量。

**验证数据链路：**systemd 显示 `active` 不代表规则一定能转发。应查看 Web 规则状态，并验证真实 TCP 流量，以及启用 UDP 时的请求/响应流量。仅做 UDP 端口探测不能替代应用层端到端测试；防火墙冲突可能导致规则暂停，但管理服务仍正常运行。

## 配置与 API

| 项目 | 路径 / 行为 |
|---|---|
| 安装后的程序 | `/usr/local/bin/portbridge` |
| 服务 | `portbridge.service` |
| 运行配置 | `/etc/portbridge/config.json` |
| 管理员令牌 | `/etc/portbridge/admin.token` |
| 安装器管理的 TLS 材料 | `/etc/portbridge-tls/` |
| 规则、ACL 和 DNS 修改 | 无需重启服务即可应用。 |
| 管理监听地址、端口或 TLS 修改 | 需要执行 `sudo systemctl restart portbridge`。 |

[中文 API 文档](docs/API.zh-CN.md)包含认证、配置、规则、设置及运行状态接口。管理请求需要 Bearer 认证，写操作还需要处理 CSRF；请按接口文档调用，不要将其当作无需认证的 REST 服务。

没有直接远程管理需求时，建议保留回环监听和 SSH 隧道。公网管理必须配置有效的原生 TLS、显式严格 IP 白名单，以及限制来源的主机防火墙/云安全组。`--allow` 只是临时启动 ACL，**不会**改变默认回环监听。ACL 根据直连 TCP 对端判断，不信任 `X-Forwarded-For`，因此反向代理还须自行限制真实客户端来源。详见 [SECURITY.md](SECURITY.md)及[公网管理示例](config.public.example.json)。

### 使用已有 HTTPS 证书

在已验证的发布包目录中，提供当前有效且匹配的证书/私钥，路径必须是服务器上的绝对路径：

```bash
sudo ./scripts/install.sh --tls-cert /absolute/path/fullchain.pem --tls-key /absolute/path/privkey.pem
```

首次安装时，将这些选项加到第 2 步调用安装器的位置即可，不必先执行默认安装。导入材料会复制到受管理的 TLS 目录，原文件不修改；源路径必须符合安装器的属主、权限和非符号链接检查。升级保留已有有效证书，配置的证书无效时会停止安装。

在发布包目录执行 `./scripts/install.sh --help` 可查看全部选项。`--no-start` 只准备文件和凭据，不启动服务；有意使用该选项时，应跳过快速安装末尾的 `systemctl is-active` 检查。避免在会采集日志的环境中使用 `--show-token`。


## 运维与排查

```bash
systemctl show portbridge -p ActiveState -p SubState -p Result -p NRestarts
sudo journalctl -u portbridge -n 50 --no-pager
```

正常应为 `ActiveState=active`、`SubState=running`，且没有持续重启。服务或规则异常时先检查日志，不要通过关闭 HTTPS、删除归属/恢复记录或放开管理白名单来掩盖问题。分享日志前请删除令牌及敏感运行信息。nftables 路径可使用 `sudo nft list table inet portbridge` 检查；Web 分别显示 Go 计数和内核尽力观测值，详见[统计边界](docs/MONITORING.zh-CN.md)。

## 升级与卸载

升级前请安全备份 `/etc/portbridge/` 和 `/etc/portbridge-tls/`，并安排维护窗口。下载并验证目标版本后，运行**该版本包内的安装器**。安装器会保留已有配置和规则并强制 HTTPS，但会停止/重启服务，不承诺无中断升级。不要用示例文件覆盖运行配置。

卸载时，在已验证的发布包目录执行：

```bash
sudo ./scripts/uninstall.sh
```

此操作保留配置。追加 `--purge` 会同时移除配置和服务账户，仅在确认不再需要时使用；`/etc/portbridge-tls/` 有意保留。快速安装会输出解压目录，但该临时目录可能被系统清理；维护时可使用妥善保留的已验证副本，或重新下载并验证发布包。

## 开发与文档

源码构建要求**准确使用 Go 1.27.1**，依赖已放入 `vendor/`。在源码目录执行：

```bash
GOPROXY=off go test ./...
GOPROXY=off go test -race ./...
GOPROXY=off go vet ./...
make dist
```

`make dist` 生成未签名的开发二进制，**不等于可安装的签名 Release 包**。请勿绕过安装器签名检查来安装此类产物。

[中文 API 文档](docs/API.zh-CN.md) · [转发边界](docs/forwarding-limits.md) · [UDP 设计与调优](docs/udp-dataplane.md) · [更新说明](RELEASE_NOTES.zh-CN.md) · [贡献指南](CONTRIBUTING.md)

## 贡献与许可证

欢迎提交问题、改进文档和发起 Pull Request。参与贡献前请阅读 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题请遵循 [SECURITY.md](SECURITY.md)。项目对你有帮助的话，欢迎点一个 Star，让更多人发现它。

本项目采用 [MIT 许可证](LICENSE)。
