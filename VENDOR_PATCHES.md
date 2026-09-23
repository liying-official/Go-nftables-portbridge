# Go-nftables-portbridge v2.5.0 — Vendored patches / 依赖补丁

## English

v2.5.0 uses Go 1.27.1, `golang.org/x/net v0.58.0` and `golang.org/x/sys v0.47.0`. Dependencies are vendored for offline builds.

The module checksums recorded in `go.sum` are:

```text
golang.org/x/net v0.58.0 h1:ynWG7rqYi4ccpTEuPZ2QGWHktVEM9DMCj9yzDE0Q7To=
golang.org/x/sys v0.47.0 h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=
```

These `h1:` values are Go module checksums, not release-archive SHA-256 values.

The WebUI embeds Tabler Core 1.5.1 CSS/JS and selected Tabler Icons 3.48.0 SVGs. Core includes Bootstrap 5.3.8 and Popper 2.11.8. No optional Tabler plugins, external fonts or CDN assets are loaded. Package integrity and asset hashes are recorded in [web-dependencies.json](packaging/web-dependencies.json); MIT notices are included in [LICENSES.txt](internal/web/static/vendor/LICENSES.txt).

The batch-address-reuse patch is in `vendor/golang.org/x/net/internal/socket/mmsghdr_unix.go` and `sys_posix.go`. On Linux, batch reads reuse a pre-populated `net.UDPAddr` and its `net.IP` backing array. Calls without a pre-populated `Message.Addr` retain upstream behavior.

Upstream module checksums do not authenticate patched vendor files. Verify the signed SHA256SUMS and the internal release manifest against the trusted release key. The internal manifest binds source-tree.sha256, including the delivered vendor files. CANDIDATE_SOURCE_SHA256SUMS is a source-checkout integrity list, not a publisher signature.

### Verification scope

The versions and checksums above describe v2.5.0. Verifying local asset hashes does not independently verify a registry tarball or a release signature, and it is not a vulnerability scan. Do not run `go mod vendor` over the patched tree without deliberately reapplying and testing the documented patch. Preserve third-party copyright and license notices when publishing.

[Contributing](CONTRIBUTING.md) · [Documentation](docs/INDEX.md)

## 简体中文

v2.5.0 使用 Go 1.27.1、`golang.org/x/net v0.58.0` 和 `golang.org/x/sys v0.47.0`，依赖存放在 vendor 中以支持离线构建。以下摘要与 `go.sum` 一致；`h1:` 是 Go 模块校验值，不是压缩包 SHA-256。

```text
golang.org/x/net v0.58.0 h1:ynWG7rqYi4ccpTEuPZ2QGWHktVEM9DMCj9yzDE0Q7To=
golang.org/x/sys v0.47.0 h1:o7XGOvZQCADBQQ4Y7VNq2dRWQR7JmOUW8Kxx4ZsNgWs=
```

WebUI 内嵌 Tabler Core 1.5.1 CSS/JS 与所需 Tabler Icons 3.48.0 SVG。Core 包含 Bootstrap 5.3.8 和 Popper 2.11.8，不加载可选 Tabler 插件、外部字体或 CDN 资源。包完整性与资源摘要见 [web-dependencies.json](packaging/web-dependencies.json)，MIT 声明见 [LICENSES.txt](internal/web/static/vendor/LICENSES.txt)。

批量地址复用补丁位于 `vendor/golang.org/x/net/internal/socket/mmsghdr_unix.go` 和 `sys_posix.go`：Linux 批量读取会复用调用方预填的 `net.UDPAddr` 及 `net.IP` 底层数组；未预填 `Message.Addr` 的调用保持上游行为。

上游模块摘要不覆盖 vendor 补丁。应使用可信发布公钥验证 SHA256SUMS 及内部签名清单；内部清单通过 source-tree.sha256 绑定实际交付的 vendor 文件。CANDIDATE_SOURCE_SHA256SUMS 是源码检出的完整性清单，不是发布者签名。


### 校验范围

上述版本和摘要描述 v2.5.0。核对本地资源哈希不能替代对注册表归档或发布签名的独立验证，也不是漏洞扫描。不要直接运行 `go mod vendor` 覆盖含补丁的依赖树，除非已经计划重新应用并测试补丁。发布时必须保留第三方版权与许可声明。

[贡献指南](CONTRIBUTING.md) · [文档索引](docs/INDEX.md)
