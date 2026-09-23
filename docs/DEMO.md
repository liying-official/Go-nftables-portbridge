# Static WebUI demo / 静态 WebUI 演示 — v2.5.0

## English

[Open the demo](https://liying-official.github.io/Go-nftables-portbridge/) · [Documentation](INDEX.md)

Use the public, case-sensitive demo password **`PortBridge`**. Switch English / 简体中文 from the language menu. You can explore the dashboard, edit simulated rules and settings, simulate token rotation, or reset the example data.

This is a public static demonstration, not a protected management service. The password is visible in the published JavaScript and does not provide access control. Do not enter real tokens, passwords, certificates, private addresses or deployment details. Rules, counters, certificate metadata and settings are synthetic. Changes live only in page memory and reset on reload; only the public demo login and language preference use demo-specific browser-storage keys.

No backend, real `/api/` or `/metrics` service, DNS lookup, socket forwarding or server configuration is involved. The page dispatches actions directly to an in-memory simulator rather than HTTP; its CSP blocks script-initiated connections. GitHub Pages still receives normal static-page/asset requests. Simulator validation is intentionally limited and is not a substitute for the installed product's validation, security controls or performance tests.

GitHub Pages publishes the `main` branch's `/docs` directory. `index.html` is the entry point and `.nojekyll` enables plain static serving; all Tabler assets are served from the same site. The production WebUI and signed Release are independent of this demo.

To regenerate the mirrored UI after editing production assets, from the repository root:

```bash
python3 scripts/build-pages-demo.py
python3 scripts/build-pages-demo.py --check
node scripts/test-pages-demo.mjs
```

## 简体中文

[打开演示站](https://liying-official.github.io/Go-nftables-portbridge/?lang=zh-CN) · [文档索引](INDEX.md)

公开演示密码为 **`PortBridge`**，区分大小写。可通过语言菜单切换简体中文 / English，体验仪表盘、模拟规则与设置编辑、模拟令牌轮换及数据重置。

这是公开静态演示，不是受保护的管理服务。密码可从公开 JavaScript 中读取，不能提供访问控制。请勿输入真实令牌、密码、证书、私有地址或部署信息。规则、计数、证书资料和设置均为模拟数据；修改只保留在当前页面内存，刷新即重置。只有公开演示登录状态与语言偏好使用演示专用的浏览器存储键。

演示没有后端、真实 `/api/` 或 `/metrics` 服务，不解析域名、不转发流量、不修改服务器配置。操作直接交给内存模拟器，不经过 HTTP，页面 CSP 禁止脚本发起连接；GitHub Pages 仍会接收正常的静态页面及资源请求。模拟器仅进行有限输入检查，不能替代正式产品的校验、安全措施或性能测试。

GitHub Pages 发布 `main` 分支的 `/docs` 目录，以 `index.html` 为入口，通过 `.nojekyll` 提供纯静态内容；Tabler 资源均来自本站。演示与正式 WebUI、已签名 Release 相互独立。修改正式界面资源后，可在仓库根目录执行上方命令重新生成并检查演示副本。
