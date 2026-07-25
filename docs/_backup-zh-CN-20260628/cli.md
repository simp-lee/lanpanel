# CLI 运维手册

Lanpanel CLI 是 UI 背后的同一套执行入口。第一次使用建议先走 UI；CLI 更适合自动化、无浏览器服务器、可重复排障和 JSON 输出。UI 中的主部署、App 部署、RealIP refresh、status 和 verify 最终都复用这些命令背后的逻辑。

## 总览

普通用户只需要先记住四类命令：

- `lanpanel ui`：启动浏览器面板。
- `lanpanel verify` / `lanpanel app verify`：部署前检查配置。
- `lanpanel deploy` / `lanpanel app deploy`：真正修改服务器。
- `lanpanel status`：查看主部署状态。

```bash
lanpanel --help
```

当前命令：

| 命令 | 作用 |
| --- | --- |
| `lanpanel init` | 生成主配置 |
| `lanpanel verify` | 静态验证主配置和运行模板 |
| `lanpanel deploy` | 部署 Headscale、Nginx、TLS、systemd 和 onboarding 基线 |
| `lanpanel status` | 查看主部署配置 readiness、checkpoint 和上次可恢复失败 |
| `lanpanel ui` | 启动只监听本机地址的 Management UI |
| `lanpanel app init` | 生成 App 示例配置 |
| `lanpanel app verify` | 静态验证 App 配置和运行模板 |
| `lanpanel app deploy` | 部署同机服务或 tailnet upstream |
| `lanpanel app realip refresh` | 刷新 EdgeOne RealIP 配置 |
| `lanpanel app realip diagnostics` | 检查已部署 RealIP 配置 |
| `lanpanel app realip validate-reference` | 验证已部署 RealIP reference JSON |

多数命令支持：

```bash
--config path
--format human|json
```

`--format json` 用于脚本化，不改变执行语义。

## 主配置

创建配置：

```bash
lanpanel init --config lanpanel.yaml
```

非交互写示例：

```bash
lanpanel init --config lanpanel.yaml --example
```

高级引导：

```bash
lanpanel init --advanced --config lanpanel.yaml
```

主配置默认字段：

```yaml
default:
  server_url: "https://hs.example.com"
  base_domain: "tailnet.example.com"
  certificate_email: "ops@example.com"
  acme_challenge: "http-01"
```

约束：

- `server_url` 必须是 HTTPS DNS 域名，只能省略端口或使用 `443`。
- `base_domain` 不能等于 `server_url` 主机名，也不能是它的父域。
- `certificate_email` 必须是普通邮箱地址。
- `acme_challenge` 只能是 `http-01` 或 `dns-01`。

## 主验证和部署

静态验证：

```bash
lanpanel verify --config lanpanel.yaml
```

部署：

```bash
sudo lanpanel deploy --config lanpanel.yaml
```

部署后再验证和查看状态：

```bash
lanpanel verify --config lanpanel.yaml
lanpanel status --config lanpanel.yaml
```

`verify` 不读取宿主机 systemd 状态、证书文件、Nginx 运行状态、Headscale 进程状态或客户端在线状态。真实运行态还要执行：

```bash
sudo systemctl status headscale.service nginx.service --no-pager --full
sudo nginx -t
curl -I https://hs.example.com
```

`deploy` 会写 checkpoint 到配置旁边的 `.lanpanel/` 目录。失败后按输出修复，再重复同一条 deploy 命令。

## 启动 UI

```bash
sudo lanpanel ui --listen 127.0.0.1:18080
```

可选参数：

```bash
sudo lanpanel ui \
  --listen 127.0.0.1:18080 \
  --state-dir /var/lib/lanpanel/ui-state \
  --config lanpanel.yaml \
  --app-config lanpanel-apps/example-app.yaml \
  --token-ttl 10m
```

`--app-config` 不是启动 UI 的必需参数；省略时默认使用 `lanpanel-app.yaml`。只有需要指定当前 UI 管理的 App 配置文件时才传这个参数。

UI 只接受 loopback IP literal，也就是 `127.0.0.1` 或 `[::1]` 这类本机 IP 地址形式。不要让 UI 监听公网。

## App CLI

生成 App 配置：

```bash
lanpanel app init --config lanpanel-apps/example-app.yaml
```

验证：

```bash
lanpanel app verify --config lanpanel-apps/example-app.yaml
```

部署：

```bash
sudo lanpanel app deploy --config lanpanel-apps/example-app.yaml
```

EdgeOne 相关会修改源站入口的操作需要确认：

```bash
sudo lanpanel app deploy \
  --config lanpanel-apps/example-app.yaml \
  --confirmation origin-protection-manual
```

`lanpanel app init` 没有 `--example`；它本身就是写出可编辑示例配置。示例源是 `deploy/config/lanpanel-app.yaml.example`。

## RealIP CLI

刷新：

```bash
sudo lanpanel app realip refresh \
  --config lanpanel-apps/example-app.yaml \
  --profile edgeone-prod \
  --confirmation origin-protection-manual
```

诊断：

```bash
sudo lanpanel app realip diagnostics \
  --config lanpanel-apps/example-app.yaml \
  --profile edgeone-prod
```

验证 reference 文件：

```bash
lanpanel app realip validate-reference \
  --profile edgeone-prod \
  --app example-app \
  --path /var/lib/lanpanel/realip/edgeone-prod/references/example-app.json
```

RealIP refresh 和 diagnostics 需要 root，因为它们读取或修改 `/var/lib/lanpanel/realip`、Nginx include、systemd timer/service 等运行文件。

## 确认 token

当前 CLI 使用 repeatable `--confirmation`。EdgeOne origin protection 相关会修改主机入口的操作需要：

```bash
--confirmation origin-protection-manual
```

含义是操作者已经理解并处理了源站边界：云安全组、主机防火墙或等价访问控制必须只允许 EdgeOne OriginACL current+next CIDR 访问源站 `80/443`。

## JSON 输出

示例：

```bash
lanpanel verify --config lanpanel.yaml --format json
lanpanel app verify --config lanpanel-apps/example-app.yaml --format json
sudo lanpanel app realip diagnostics --config lanpanel-apps/example-app.yaml --profile edgeone-prod --format json
```

JSON 输出会保留 status、summary、fields、next_steps 等结构。不要把密钥放进配置或环境输出；Lanpanel 会尽力阻止敏感值进入任务结果，但操作者仍应避免在命令行参数中传 secret。

## 常见排障顺序

主部署：

```bash
lanpanel verify --config lanpanel.yaml
lanpanel status --config lanpanel.yaml
sudo systemctl status headscale.service nginx.service --no-pager --full
sudo nginx -t
curl -I https://hs.example.com
```

App：

```bash
lanpanel app verify --config lanpanel-apps/example-app.yaml
sudo nginx -t
curl -I https://app.example.com
systemctl status <app-name>.service --no-pager --full
```

GoAccess：

```bash
systemctl status <app-name>-goaccess.service --no-pager --full
journalctl -u <app-name>-goaccess.service -e
tail -f <canonical-access-log>
tail -f <error-log>
```

Tailscale upstream：

```bash
tailscale status
tailscale netcheck
curl -I http://<app.upstream>
```

EdgeOne RealIP：

```bash
sudo lanpanel app realip diagnostics --config lanpanel-apps/example-app.yaml --profile edgeone-prod
sudo nginx -t
```

失败时优先保留完整命令输出，包括 summary、details、next steps、retry command 和 modified paths。
