# Go-nftables-portbridge v2.4.9 — Security policy / 安全说明

## Supported release

v2.4.9 adds bounded per-rule default-drop selective ACL proof, not arbitrary policy interpretation. Explicit effects/unknown nodes remain rejected; original tuple constraints prevent a suspended rule borrowing another rule\'s flow-add entry. Read [current security boundaries](docs/forwarding-limits.md). Two snapshots and periodic coordination are not zero-window/per-packet enforcement. Recovery still requires protected same-identity records; missing trusted ownership never authorizes guessed conntrack deletion. Service/reboot evidence is environment-specific and documented separately; broader policies and long-run capacity still require their own validation.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private vulnerability reporting / Security Advisories and include:

- affected version and architecture;
- management deployment model (LAN, direct TLS, reverse proxy, VPN, or SSH tunnel);
- relevant rule and data-plane choice;
- minimal reproduction steps and expected/observed behavior;
- sanitized logs with tokens, real IPs, domains, and private traffic removed.

Never include administrator tokens, SSH credentials, production configuration, TLS private keys, environment files, or unredacted packet captures.

## Management-plane boundary

Installation and upgrades require HTTPS, including on loopback. If no certificate is configured, a unique ten-year self-signed ECDSA P-256 certificate is generated before the service starts. The installer and systemd service enforce this policy, and the settings API rejects clearing TLS paths or enabling insecure HTTP. Automatic LAN discovery remains disabled by default. Self-signed certificates encrypt traffic but require fingerprint verification and explicit client trust; never equate them with automatically trusted certificates. Existing valid certificates are preserved and invalid supplied material fails preflight. See the bilingual README for certificate import and replacement.

For direct public TLS:

- restrict TCP/9080 to exact management sources at the cloud/security-group and host-firewall layers;
- configure absolute native-TLS certificate/key paths and restart into HTTPS first;
- then, from HTTPS, disable automatic LAN ACL, whitelist the current direct peer, and enable `strict_ip_allowlist`;
- use a narrow `/32` or `/128` where possible and never use documentation example addresses unchanged.

Strict mode requires native TLS, ignores automatic LAN prefixes and `--bootstrap-allow`, rejects all-address `/0` prefixes, and retains loopback access for local recovery. Disallowed direct peers are closed before TLS/HTTP parsing and are checked again by middleware. TLS 1.2 is the minimum by default; internet-exposed management can set `web.tls_min_version` to `1.3` for a TLS 1.3-only policy (restart required). Private-key permissions are limited to owner read/write plus optional group read (normally `0600`, or `0640 root:portbridge`). Certificate renewal requires a service restart.

PortBridge deliberately ignores `Forwarded` and `X-Forwarded-For`. Behind a reverse proxy, it sees only the proxy as the TCP peer; use HTTPS to the backend, verify its certificate/hostname, bind it to loopback/private addresses, and enforce the real-client ACL, TLS, request limits, and anti-DoS controls at the proxy/firewall. Never whitelist an untrusted shared proxy and assume PortBridge can recover the original client IP.

The application has bounded header/body sizes, read/write timeouts, an accepted-connection cap, per-IP/global authentication-failure throttling, authenticated CSRF bootstrap, and browser origin checks. These controls do not absorb volumetric attacks. A host firewall or upstream edge control remains mandatory for Internet exposure.

The management ACL does not restrict forwarding rules. Each configured TCP/UDP listen endpoint has its own exposure and must be protected separately when it is not intended to be public.

## Credentials, files, and logs

The administrator token is 256 bits and grants full management access. The Web UI stores it only in per-tab `sessionStorage`; browser extensions, injected scripts, screen capture, and a compromised administrator workstation remain outside the trust boundary. Rotate the token after suspected exposure.

The installer does not print the token unless `--show-token` is explicitly used. Read `/etc/portbridge/admin.token` locally when needed. Configuration and token files are atomically replaced with mode `0600`; protect backups and deployment output to the same standard. Concurrent rotations are serialized across both files and rollback, but process/power failure between the two writes can still interrupt a rotation. Startup reports a mismatch while continuing to authenticate against the configured hash. Stop the service, run `portbridge --reset-admin-token` as the service account with its actual configuration/token paths, then restart. The bilingual README contains the installed-service recovery commands; resetting files beside a running process does not refresh that process's credential.

TLS private keys must be regular files, not symlinks, and must have an accepted owner and restrictive mode. The installer stores operator-supplied TLS material separately under `/etc/portbridge-tls` and uninstall intentionally retains it.

At `info` level, normal startup messages omit rule names and forwarding endpoints. Debug/error logs can contain client addresses, targets, domains, nftables errors, and rule details. Restrict, rotate, and redact them before sharing.

## Privileged data plane

The service needs `CAP_NET_ADMIN` to manage only the `inet portbridge` table and `CAP_NET_BIND_SERVICE` for privileged ports. The table carries an instance-specific owner comment and all forwarding rules use a nonzero instance conntrack mark. PortBridge refuses to overwrite or remove a same-name table with a missing/mismatched marker. The supplied systemd unit removes other capabilities and applies filesystem, process, device, namespace, syscall, file-descriptor, task, CPU, and memory restrictions.

nftables admission updates and conntrack retirement are separate operations. Exact tuple/mark/common-zone matching, a persistent owned unhooked journal and visible failure states replace the misleading delete-table-is-fail-closed claim. Unknown ownership is never guessed from a shared mark; old flows may remain when both records and process memory are lost. See the forwarding limits before cleanup or deployment.

## Forwarding targets and resource exhaustion

Rule targets are untrusted input. Literal addresses and every DNS refresh result are checked against denied local/private/link-local/multicast/unspecified/CGNAT/cloud-metadata ranges. A private target requires both `allow_private_target=true` and a narrow `target_cidr_allowlist`; `/0` target allowlists are rejected. Custom DNS uses conventional plaintext DNS unless the configured local resolver provides its own encrypted upstream, so protect resolver routing and configuration.

Global TCP connection, UDP session and estimated UDP-memory budgets apply to Go proxy paths together with per-rule and per-source limits. UDP source-session and token-bucket rate limits are shared across the rule's SO_REUSEPORT workers, port ranges, IPv4/IPv6 listeners, wildcard fallback and hybrid Go runners. They do not automatically constrain nftables/flowtable traffic; apply required kernel-path limits separately. Token buckets allow bounded bursts rather than fixed-window per-second guarantees. Monitor rejection/drop counters, socket drops, memory, file descriptors and conntrack use.

The v2.4.9 Release provides source archives and SHA256SUMS with detached Ed25519 signatures, but no prebuilt binaries. Verify them before using the clean-source build path. Local compilation does not automatically sign its output; the separate prebuilt-bundle policy below is not the authentication format of these source archives.

## Release integrity

For separately produced prebuilt bundles (not included in the current v2.4.9 source Release), installation is fail-closed: the installer contains the expected Ed25519 public key and fingerprint, rejects a bundle signer file that is a symlink, non-regular file, hard link, extra line, or different key, and only then uses that key to verify the internal bundle manifest before package installation changes system state. The manifest binds the version, source revision, Go toolchain, architecture, and source/binary hashes. That prebuilt packaging format also signs its own manifests and checksums; it is distinct from the current source-archive detached signatures. The pinned public-key fingerprint is `SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o`; the private key is never shipped in the repository or archives.

The signing identity is `portbridge-release-v2` and the namespace is `portbridge-release`. Verify the expected key/fingerprint from a trusted source before trusting bundled signer data. Keep private-key backups offline and separate from published files.

## 中文说明

v2.4.9 新增逐规则 default-drop 选择性 ACL 有界证明，不解释任意策略；未知及副作用节点继续拒绝，原始 tuple 约束防止被暂停规则借用其他规则的 flow add。参见[当前安全边界](docs/forwarding-limits.md)。两读/周期协调不保证零窗口或逐包授权。恢复仍依赖同身份可信记录，不按共享 mark 猜测删除；服务与重启证据属于特定环境并单独记录；更广策略与长时间容量仍需独立验证。

安装与升级后包括回环监听也强制 HTTPS；未配置证书时在启动前生成每台机器独立、有效期十年的 ECDSA P-256 自签证书。安装器与 systemd 双重执行要求，设置 API 拒绝清空证书或启用明文 HTTP。自签证书提供加密但需要核对指纹并建立客户端信任，不能等同于浏览器自动信任。已有有效证书保留，无效证书在预检时报错；导入和替换流程见双语 README。默认仍关闭自动 LAN 识别，远程可使用 SSH 隧道。公网直连必须同时使用云安全组/主机防火墙、原生 TLS 与严格 IP 白名单：先配置证书并重启确认 HTTPS，再从 HTTPS 关闭自动 LAN、加入当前直连地址并启用严格模式。严格模式忽略自动 LAN 和 `--bootstrap-allow`，拒绝 `/0`，只额外保留回环恢复通道；TLS 默认最低 1.2，公网直连可设置 `web.tls_min_version=1.3`（重启生效），私钥必须是非符号链接的常规文件，通常使用 `0600` 或 `0640 root:portbridge`。

PortBridge 不信任 `Forwarded`、`X-Forwarded-For`。反向代理到后端也使用 HTTPS 并验证证书/主机名，后端只监听回环/私网，并由代理和防火墙根据真实客户端执行 TLS、白名单、限流与抗 DoS；应用看到的直连来源只是代理。管理 ACL 只保护管理页面，不会限制每条转发规则的对外暴露。

管理令牌为 256 位并拥有完整管理权限，Web 仅将其放在当前标签页的 `sessionStorage`。安装脚本默认不输出令牌；需要时在本机读取 `/etc/portbridge/admin.token`，怀疑泄露后立即轮换。debug/error 日志可能包含客户端、目标、域名与规则详情，分享前必须脱敏。

并发轮换会在令牌文件、配置和回滚期间完整串行化，但进程或电源在两次写入之间中断仍可能造成不一致。启动时会明确告警，并继续按配置哈希认证。恢复时先停止服务，再以服务账户和相同配置/令牌路径执行 `--reset-admin-token`，随后重新启动；完整命令见中文 README。对运行中进程单独重置磁盘文件不会刷新其内存凭据。

当前 v2.4.9 Release 的源码归档与 SHA256SUMS 附有 Ed25519 分离签名，不含预编译二进制；本地源码构建产物不会自动获得发布者签名。归档分离签名不替代预编译安装器的内部清单验签。验签步骤见 [README.zh-CN.md](README.zh-CN.md)。

签名身份为 `portbridge-release-v2`，namespace 为 `portbridge-release`。应先从可信来源核对预期公钥/指纹，再信任包内 signer；私钥备份应离线保存并与发布文件分离。

服务只操作真实 owner 验证后的自有表。nft 入口更新与 conntrack 撤销分属不同操作，依据完整 tuple/mark/common zone 定向处理，并用自有无 hook 恢复链及可见错误保存未完成状态。删表不等于撤销；所有权记录与进程内存同时丢失时旧流仍可能活动，不能只按共享 mark 猜测清理。详见转发限制。

转发目标和每次 DNS 刷新都会拒绝未授权的本机/私网/链路本地/多播/未指定/CGNAT/云元数据地址，私网目标必须同时启用 `allow_private_target` 并填写窄范围 `target_cidr_allowlist`。连接、会话、速率和估算内存预算作用于 Go 代理路径；UDP 来源预算在同一逻辑规则的 worker、端口段、地址族、通配 fallback 和 hybrid Go runner 之间共享。速率采用允许受限突发的令牌桶，不是任意固定一秒窗口的严格计数；这些设置不会自动限制 nftables/flowtable 内核转发。预编译安装器固定 Ed25519 公钥和指纹，先拒绝替换、链接或多 key signer，再校验签名清单及源码/二进制。发布公钥指纹为 `SHA256:TGJCcbglVkN6Af8yrWYyifxTv+lDNzfXVnQRKeIMl1o`；私钥从不随包分发。
