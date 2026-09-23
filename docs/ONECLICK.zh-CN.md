# 交互式全新安装 — v2.5.0

[返回 README](../README.zh-CN.md) · [English](ONECLICK.en-US.md) · [固定版本验签安装](INSTALL.zh-CN.md)

`scripts/install-oneclick.sh` 用于 Debian/Ubuntu、amd64 / arm64 的全新安装，选择 GitHub 最新的已发布稳定版，而不是本地源码检出的版本。无需 Go 编译器。普通安装需要 root、交互式终端与正在运行 systemd 的主机。

## 获取并检查安装脚本

在可信源码检出目录中先检查脚本，再运行：

```bash
# 在仓库根目录执行。这是交互式安装，会修改系统。
sudo bash scripts/install-oneclick.sh
```

也可以先从仓库当前 `main` 分支获取独立副本，用于检查：

```bash
set -euo pipefail
umask 077
PB_INSTALLER=$(mktemp)
curl --proto '=https' --tlsv1.2 -fSL \
  https://raw.githubusercontent.com/liying-official/Go-nftables-portbridge/main/scripts/install-oneclick.sh \
  -o "$PB_INSTALLER"
printf '请先检查下载的脚本，再决定是否执行：%s\n' "$PB_INSTALLER"
```

先阅读该文件并确认可信，再在同一 shell 中执行 `sudo bash "$PB_INSTALLER"`。该引导脚本通过 HTTPS 从 `main` 获取；它对 Release 内容的验签不能反过来独立证明引导脚本本身可信。不要修改签名包内脚本或绕过验签错误。独立临时副本不再需要时可以删除。

## 安装过程中会发生什么

初始英文菜单中，`1` 为 English，`2` 为简体中文。安装器检查平台、准备依赖，要求填写持久化 IP/CIDR 白名单和可用 HTTPS 端口（默认 `9080`），并在安装发布包前要求确认。**依赖安装可能先于最终确认发生**，取消不等于系统完全未改变。

白名单以逗号或空格分隔，拒绝空列表、`/0`、多播、带作用域地址和 IPv4-mapped IPv6。Release 验证包括固定 Ed25519 公钥、外层签名校验清单、归档哈希、内部签名清单、覆盖的源码/脚本哈希及二进制身份。随后调用已验证的安装器 `--no-start`，准备独立的十年期自签证书，保存严格白名单，禁用自动 LAN 识别和明文 HTTP，再启动服务。

管理监听为 `0.0.0.0`，IPv6 启用时还包括 `::`；严格白名单限制访问，同时保留回环恢复通道。这**不同于**手动安装默认的仅回环监听。安装器不会配置主机/云防火墙规则，也不会探测公网地址。底层安装器会调整转发 sysctl；应用在应用转发规则时可能管理自己的 nftables 表。显示的 URL 来自适用的接口地址，不代表已经从公网验证可达。

最后的本机检查包括服务稳定性、验证证书的回环 HTTPS、管理员认证，以及持久化 strict/whitelist 配置。**这些检查不能证明允许的外部客户端可以连入、不允许的外部来源被拒绝，或转发规则确实承载业务流量。** 安装后应从合适的自有客户端分别验证。

成功页面会显示证书 SHA-256、接口 URL 和**明文管理员令牌**，不要录屏或公开输出。信任自签证书前应先核对指纹。v2.5.0 两种语言的发布包都包含双语 WebUI，包语言仅决定初始显示语言。

## 现有安装与失败处理

检测到现有配置、TLS 目录、已安装二进制或服务时，脚本会拒绝覆盖。升级使用[发布包验签流程](INSTALL.zh-CN.md)。失败时不会执行破坏性回滚，可能留下文件、依赖或服务状态。诊断日志仅应在本机私下查看，分享前先脱敏，不要为绕过错误而删除归属或恢复记录。

## 不执行安装的验证模式

```bash
bash scripts/install-oneclick.sh --check
```

仍需交互式选择，并预装 curl、Python 3、OpenSSH `ssh-keygen`、iproute2、tar/gzip 与 coreutils。该模式使用网络与临时文件，下载并验证当前 Release，且**会执行已验证二进制的 `-version`**。它不安装依赖、不改动已安装配置或服务，也不读取已有管理员令牌；但它不是零执行、离线或端到端安装测试。Release 不可用或缺少依赖时应停止，不能降低验签要求。
