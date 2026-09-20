# Go-nftables-portbridge v2.4.9 — Vendored patches / 依赖补丁

## English

v2.4.9 preserves the reviewed vendor bytes, using Go 1.27.1, `golang.org/x/net v0.58.0` and `golang.org/x/sys v0.47.0`. Published source archives and SHA256SUMS have Ed25519 detached signatures; no prebuilt binaries or old prebuilt-bundle signature manifests are included.

The module checksums recorded in `go.sum` are:

```text
golang.org/x/net v0.58.0 h1:ynWG7rqYi4ccpTEuPZ2QGWHktVEM9DMCj9yzDE0Q7To=
golang.org/x/sys v0.47.0 h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=
```

These `h1:` values are Go module checksums, not release-archive SHA-256 values.

The documented local batch-address-reuse patch is in `vendor/golang.org/x/net/internal/socket/mmsghdr_unix.go` and `sys_posix.go`. On Linux, batch reads reuse a pre-populated `net.UDPAddr` and its `net.IP` backing array. Calls without a pre-populated `Message.Addr` retain upstream behavior.

The upstream module checksum does not authenticate local vendor edits. Verify the published archive's detached signature against the independently trusted release key to authenticate its exact contents, including patched vendor files. CANDIDATE_SOURCE_SHA256SUMS is an internal file-integrity list, not an independent publisher signature. Keep dependency version strings and upstream notices intact; they are not project release versions.

## 简体中文

v2.4.9 原样保留已审核的 vendor 字节，使用 Go 1.27.1、`golang.org/x/net v0.58.0` 和 `golang.org/x/sys v0.47.0`。发布源码归档和 SHA256SUMS 已有 Ed25519 分离签名，不含预编译二进制或旧预编译包签名清单。上方摘要与 `go.sum` 一致；`h1:` 是 Go 模块校验值，不是压缩包 SHA-256。

已记录的本地批量地址复用补丁位于 `vendor/golang.org/x/net/internal/socket/mmsghdr_unix.go` 和 `sys_posix.go`：Linux 批量读取会复用调用方预填的 `net.UDPAddr` 及 `net.IP` 底层数组；未预填 `Message.Addr` 的调用保持上游行为。

上游模块摘要不覆盖本地 vendor 改动；应使用经独立可信渠道确认的发布公钥验证归档分离签名，认证包含补丁文件在内的准确归档内容。CANDIDATE_SOURCE_SHA256SUMS 是包内文件完整性清单，不是独立的发布者签名。依赖版本及上游声明应保留原值，它们不是本项目的发布版本号。
