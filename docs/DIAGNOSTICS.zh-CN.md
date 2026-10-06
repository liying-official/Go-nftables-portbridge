# 环境诊断与应用状态 — v2.5.0

[README](../README.zh-CN.md) · [文档索引](INDEX.md) · [English](DIAGNOSTICS.en-US.md)

在 WebGUI 打开**环境诊断与应用状态**，点击**刷新只读诊断**。页面显示当前进程权限、可信 nft/conntrack 工具是否可用、配置与观察到的数据面、内核证据、待清理状态和最近记录的应用操作。进入页面或手动刷新时采集快照，不在后台探测转发业务。

也可在本机使用诊断命令：

```bash
sudo /usr/local/bin/portbridge --diagnose --diagnose-language zh-CN
sudo /usr/local/bin/portbridge --diagnose
sudo /usr/local/bin/portbridge --diagnose-json
```

自定义安装可指定 `--config` 和 `--token-file`。命令只读取、校验配置，不创建配置、凭据或恢复记录。条件允许时，向已确认属于本机的管理监听发送一次已认证的 `GET /api/diagnostics`；保留 HTTPS 证书校验，不跟随重定向，不使用代理。所选令牌文件可保存管理员令牌或已配置的监控令牌。无法访问服务时返回本地命令观察，`runtime_observed:false`；命令进程的权限不代表服务的权限。配置缺失或不可读时给出解释，不创建文件。退出码 `0` 只表示已生成诊断报告，不代表转发健康；命令选项错误返回 `2`。

| 诊断代码 | 含义与处理方向 |
|---|---|
| `permission_denied` | 检查服务账户和所需 capability，保留受限服务策略。 |
| `target_resolution_failed` | 核对目标域名、DNS、地址族及记录的解析错误；诊断不会重新查询 DNS。 |
| `target_policy_denied` | 核对实际目标及明确的目标 CIDR 授权。 |
| `firewall_compatibility_rejected` | 未能证明外部防火墙兼容性或完成检查，与相关防火墙维护者核对证据。 |
| `listener_failed` | 检查端口占用、本地地址及绑定权限。 |
| `admission_suspended` | 新的 nftables 接入已暂停，既有连接可能仍存在。 |
| `cleanup_pending` | 尚未证明旧路径或连接已清理完毕，保留有效归属和恢复证据。 |
| `ownership_unverified` / `kernel_unverified` | 归属与内核回读验证完成前，将内核状态视为未知。 |
| `dependency_missing` | 检查发行版 nftables/conntrack 软件包及可信可执行文件权限。 |
| `application_pending` | 已保存的转发参数与观察到的规则不同；等待应用后刷新，待清理或不确定状态优先显示。 |

错误分类解释的是控制器记录的证据，并非重新探测。无法分类的错误保留原始证据，以 `application_failed` 表示；操作前请核对具体证据。

`actual_data_plane` 根据观察到的 Go 监听和已验证内核状态解释实际路径。`kernel-unverified`、`go-and-unverified-kernel` 保留不确定性，不把旧路径伪装成已经消失。选择 nftables 的规则也可能因跨地址族、回环或带 scope 的地址路径而使用 Go，通配监听可同时使用两者。`running` 单独不能证明业务健康，也可能表示尚未排除的旧转发风险。应用操作记录属于历史状态，应对照其配置版本和当前诊断快照，并检查当前规则证据。

`GET /api/diagnostics` 接受管理员或只读监控 Bearer 令牌，沿用管理 HTTPS 和 IP 白名单，无需 CSRF。不输出令牌明文、凭据哈希、私钥或完整外部防火墙规则。规则名称和记录的规则错误证据仍可能包含部署信息，公开分享前应审查。中英解释来自同一份注册表，诊断代码保持稳定。

诊断不应用规则、不启动监听、不解析目标、不安装依赖、不修改 sysctl、不改动其他应用防火墙、不改归属记录、不强制清理。受限服务命名空间内隐藏的内核文件显示为未知。内核规则和 Go 监听属于控制面证据，`business_health` 始终为 `not_checked`；flowtable 流量采集仍为尽力统计。
