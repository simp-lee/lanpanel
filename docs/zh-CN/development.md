# 开发和人工测试

本文面向本仓库开发者，说明如何构建、运行测试、启动模拟 UI 后人工打开浏览器检查。普通使用者不需要阅读本文；安装 release 二进制并启动 UI 即可。

普通用户入口见 [中文文档索引](index.md)、[快速开始：部署私有网络](quickstart.md) 和 [快速开始：发布本机 App](app-quickstart.md)。

## 构建

```bash
make build
```

生成根目录二进制：

```bash
./lanpanel --help
```

源码直接运行：

```bash
go run ./cmd/lanpanel --help
```

## 常规测试

```bash
go test ./...
make check
```

`make check` 当前运行 build、`go test ./...`、`go vet ./...` 和 P0 静态审计。完整 P0 发布门禁使用 `make p0-release-gate`。`make lint` 依赖本机安装 `golangci-lint`。

## 文档测试

文档一致性测试在 `internal/assets/docs_test.go`：

```bash
go test -count=1 ./internal/assets
```

中文文档重构时要同步更新这些断言。测试应检查 `README.zh-CN.md` 和 `docs/zh-CN/` 文档集合，而不是要求所有 App、UI、CLI 细节都塞在 README 里。

## Playwright E2E

完整 UI E2E：

```bash
make e2e
```

默认 testserver 监听 `127.0.0.1:18080`。端口冲突时：

```bash
E2E_ADDR=127.0.0.1:18081 make e2e
```

Walkthrough：

```bash
make e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/ui-bootstrap-security.spec.ts
```

特殊测试数据：

```bash
E2E_TESTSERVER_FLAGS=-preseed-configs=false \
  make e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/first-run-config-init-flow.spec.ts

E2E_TESTSERVER_FLAGS=-slow-main-deploy=3s \
  make e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/jobs-history-redaction-recovery.spec.ts
```

Walkthrough 证据写到 `.agents-work/60-verification/browser/walkthroughs/<journey-id>/`。

## 手动启动模拟 UI

开发时人工检查浏览器体验，不要直接跑真实 `sudo lanpanel ui` 去改宿主机。使用 e2e build tag 的模拟 testserver，它只模拟 UI，不会部署 Nginx、systemd 或证书：

```bash
tmp_dir=$(mktemp -d "${HOME}/.lanpanel-ui-manual.XXXXXX")

go run -tags e2e ./internal/ui/testserver \
  -listen 127.0.0.1:18080 \
  -state-dir "$tmp_dir/state" \
  -config "$tmp_dir/lanpanel.yaml" \
  -app-config "$tmp_dir/lanpanel-app.yaml" \
  -browser-auth-dir "$tmp_dir/browser-auth" \
  -token-url-file "$tmp_dir/token-url"
```

testserver 会：

- 写入临时主配置和 App 配置。
- 使用模拟主机流程，不真实部署系统服务。
- 把一次性启动 URL 写入 `-token-url-file` 指定的本地临时文件。
- 默认预置一个中断任务，方便检查恢复展示。
- 默认预置 EdgeOne RealIP reference 测试数据。

读取本地临时文件中的一次性启动 URL 后在浏览器打开：

```bash
startup_url=$(cat "$tmp_dir/token-url")
printf '%s\n' "$startup_url"
```

端口被占用时改成：

```bash
-listen 127.0.0.1:18081
```

如果要测试首次配置空白流程：

```bash
go run -tags e2e ./internal/ui/testserver \
  -listen 127.0.0.1:18080 \
  -state-dir "$tmp_dir/state" \
  -config "$tmp_dir/lanpanel.yaml" \
  -app-config "$tmp_dir/lanpanel-app.yaml" \
  -browser-auth-dir "$tmp_dir/browser-auth" \
  -token-url-file "$tmp_dir/token-url" \
  -preseed-configs=false
```

## 真实 UI 本机验证

需要验证真实 CLI/UI 串联时可以构建后运行：

```bash
make build
sudo ./lanpanel ui --listen 127.0.0.1:18080 --config lanpanel.yaml --app-config lanpanel-apps/example-app.yaml
```

这会使用真实主机部署流程。不要在开发机上随意点击 Deploy，除非你明确准备好让 Lanpanel 修改本机 Nginx、systemd、证书和相关运行文件路径。

## 静态安全检查重点

人工 review UI 或文档时检查：

- 不出现完整启动 token URL 示例。
- 不出现 preauth key、browser password、htpasswd 内容、DNS token、EdgeOne secret、Tailscale auth key。
- UI 必须只监听 loopback IP literal；禁止监听 `0.0.0.0`、公网 IP 或 `::`。
- 不引入 CDN htmx script。
- Browser App 保护反代和静态文件，且不转发入站 `Authorization`。
- GoAccess Auth 与 Browser Auth 分离。
- P0 不声称支持 `private_client`、商业账号、RBAC、OIDC/SSO、公网远程控制面、export manifest 或审计日志写路径。
