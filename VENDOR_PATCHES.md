# Go-nftables-portbridge v2.4.9 — Vendored patches / 依赖补丁

## English

v2.4.9 preserves the reviewed v2.4.4 vendor bytes, using Go 1.27.1, `golang.org/x/net v0.58.0` and `golang.org/x/sys v0.47.0`. This source candidate has no valid release signature; old signed manifests are not included.

The module checksums recorded in `go.sum` are:

```text
golang.org/x/net v0.58.0 h1:ynWG7rqYi4ccpTEuPZ2QGWHktVEM9DMCj9yzDE0Q7To=
golang.org/x/sys v0.47.0 h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=
```

These `h1:` values are Go module checksums, not release-archive SHA-256 values.

The documented local batch-address-reuse patch is in `vendor/golang.org/x/net/internal/socket/mmsghdr_unix.go` and `sys_posix.go`. On Linux, batch reads reuse a pre-populated `net.UDPAddr` and its `net.IP` backing array. Calls without a pre-populated `Message.Addr` retain upstream behavior.

The upstream module checksum does not authenticate local vendor edits. The signed release's source-tree manifest binds the shipped patched files. Keep dependency version strings and upstream notices intact; they are not project release versions.

## 简体中文

v2.4.9 原样保留已审核 v2.4.4 的 vendor 字节，使用 Go 1.27.1、`golang.org/x/net v0.58.0` 和 `golang.org/x/sys v0.47.0`。本源码候选未签名，不包含旧签名清单。上方摘要与 `go.sum` 一致；`h1:` 是 Go 模块校验值，不是压缩包 SHA-256。

已记录的本地批量地址复用补丁位于 `vendor/golang.org/x/net/internal/socket/mmsghdr_unix.go` 和 `sys_posix.go`：Linux 批量读取会复用调用方预填的 `net.UDPAddr` 及 `net.IP` 底层数组；未预填 `Message.Addr` 的调用保持上游行为。

上游模块摘要不覆盖本地 vendor 改动；发布包的签名源码清单绑定实际分发的补丁文件。依赖版本及上游声明应保留原值，它们不是本项目的发布版本号。
