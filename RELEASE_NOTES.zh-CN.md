# Go-nftables-portbridge v2.4.4

## 重点更新

- 安装与升级强制 HTTPS；未配置证书时自动生成十年自签证书，展示证书状态，支持后续替换 CA 签发证书。
- TLS 默认最低 1.2，可选仅 1.3；旧客户端保存时保留已有策略，待重启提示准确。
- 串行化管理员令牌轮换，明确提示文件一致性问题，并提供停服恢复流程。
- 支持 TCP/UDP/both、确定性端口段、同族 nftables/flowtable 与跨族 Go 转发。
- Go UDP 批量 I/O、worker-local 会话及精确共享来源预算；Web 每 500 ms 串行轮询。
- Go 1.27.1、vendored 依赖、Linux amd64/arm64 静态二进制与签名源码/二进制清单。

## 安装或升级

先验证签名和校验值，解压后执行 `sudo ./scripts/install.sh`。全新安装为回环地址的 HTTPS/TCP 9080，初始无转发规则。升级保留管理员令牌、已有监听和规则，同时强制 HTTPS；缺少证书配置时生成证书，已配置但无效的证书在预检时报错。

访问方式、证书信任/替换和默认设置见[中文 README](README.zh-CN.md)。

## Release 文件

- `Go-nftables-portbridge-v2.4.4-en-US.tar.gz`
- `Go-nftables-portbridge-v2.4.4-zh-CN.tar.gz`
- `Go-nftables-portbridge-v2.4.4-SHA256SUMS.txt`
- `Go-nftables-portbridge-v2.4.4-SHA256SUMS.txt.sig`
- `release-manifest.json`
- `release-manifest.json.sig`

每个语言包内的二进制和源码由签名清单认证。请使用同一套制品中相匹配的校验文件及签名。
