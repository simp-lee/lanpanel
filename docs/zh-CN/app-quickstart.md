# 快速开始：发布本机 App

这篇文档带你把一个同机 HTTP/WebSocket 服务发布到公网 HTTPS。这个路径不要求先部署 Headscale 私有网络。

如果业务服务在 tailnet 里的另一台机器上，先读 [App 配置参考](app.md) 的 `upstream` 模式。

## 你会完成什么

完成后应该得到：

- 一个业务域名，例如 `app.example.com`。
- Nginx 公网 HTTPS 入口。
- 业务服务只监听 `127.0.0.1:18001` 这类 loopback 地址。
- 可选 Browser Auth。
- 一个由 UI 保存、可重复执行的 App 配置文件。

使用 UI 时不需要手写 YAML。UI 会根据表单内容保存 `lanpanel-app.yaml` 或 `--app-config` 指定的文件；你只需要在页面里填写字段、点击 `Save`、`Verify`、`Deploy`。YAML 示例只在 [App 配置参考](app.md) 中作为 CLI、排障和审计参考。

## 准备

| 需要 | 示例 | 说明 |
| --- | --- | --- |
| 服务器 | Debian/Ubuntu | 能使用 root 或 sudo |
| 业务域名 | `app.example.com` | 已解析到这台服务器 |
| 业务服务 | `127.0.0.1:18001` | 不直接暴露公网 |
| 证书邮箱 | `ops@example.com` | ACME 注册邮箱 |
| 端口 | `80/tcp`、`443/tcp` | 云安全组和主机防火墙放行 |

`listen` 模式需要填写 Runtime service。Lanpanel 会根据 `Service exec start` 生成并管理 App 的 systemd service；第一个 token 必须是可执行文件绝对路径。

## 第 1 步：启动 UI

在服务器上运行：

```bash
sudo lanpanel ui --listen 127.0.0.1:18080 --app-config lanpanel-apps/example-app.yaml
```

`--app-config` 不是必需参数。省略时 UI 使用默认 App 配置路径 `lanpanel-app.yaml`；在 `Resources` 页面点击 `Create Example App Config` 会把示例配置写到这个路径。只有想把当前 UI 操作绑定到指定文件时才需要传入。

如果浏览器不在服务器本机，先在自己的电脑上建立 SSH 端口转发：

```bash
# Linux / macOS / Windows OpenSSH
ssh -L 18080:127.0.0.1:18080 user@server
```

Windows PuTTY 用户在 `Connection -> SSH -> Tunnels` 添加 local tunnel：`Source port` 填 `18080`，`Destination` 填 `127.0.0.1:18080`，连接服务器后保持会话打开。更多隧道说明见 [UI 面板手册](ui.md#启动方式)。

然后打开 `lanpanel ui` 输出里的 `Open once` URL。

## 第 2 步：创建 App 配置

打开 `Resources`。

没有配置时点击 `Create Example App Config`，UI 会在当前 App config path 生成配置文件。

你通常不需要打开这个文件手工编辑。推荐一个 App 一个配置文件，并统一放在 `lanpanel-apps/` 目录，方便以后备份、迁移和用 CLI 复现：

```text
lanpanel-apps/example-app.yaml
lanpanel-apps/admin.yaml
lanpanel-apps/tailapp.yaml
```

配置文件名不是部署身份；真正的部署身份来自 `app.name`。重命名配置文件不会重命名 systemd unit、Nginx 站点或证书目录。

## 第 3 步：填写 Resource

最小 `listen` App 需要：

| 字段 | 示例 | 说明 |
| --- | --- | --- |
| `App name` | `example-app` | 用于 systemd unit、Nginx 站点和运行路径 |
| `Domains` | `app.example.com` | 已解析到当前服务器 |
| `Certificate email` | `ops@example.com` | ACME 注册邮箱 |
| `ACME challenge` | `http-01` | 新手优先使用 HTTP-01 |
| `Target mode` | `listen` | 业务服务在同一台服务器 |
| `Listen` | `127.0.0.1:18001` | App 只监听本机地址 |

只部署同机 `listen` App 时可以没有主 `lanpanel.yaml`；保持 `upstream: ""` 且不要启用 `tailscale.enabled_for_listen`，Lanpanel 只管理本机 App、Nginx、证书和 systemd，不会要求你先部署 Headscale 私有网络。

## 第 4 步：选择访问模式

新手建议先二选一：

| 模式 | 适合 | 注意 |
| --- | --- | --- |
| `browser` | 管理后台、内部工具 | Nginx App gateway 层启用 Basic Auth |
| `public` | 明确要公开访问的站点 | 需要确认公网访问风险 |

`access_mode: "browser"` 会在代理到业务服务前清除入站 `Authorization` header。需要业务层 `Authorization` 的 App 应走显式 `public` 风险路径，或等待后续 upstream auth 设计。

Browser Auth 与 GoAccess dashboard Auth 是两套凭据，不能复用。

## 第 5 步：填写 Runtime service

`listen` 模式必须在 `Runtime service` 中填写：

| 字段 | 示例 | 说明 |
| --- | --- | --- |
| `Service exec start` | `/opt/example-app/example-app --listen 127.0.0.1:18001` | 第一个 token 必须是可执行文件绝对路径 |
| `Working directory` | `/opt/example-app` | 业务进程工作目录 |
| `Service env file` | 留空或 `/etc/example-app/app.env` | 如设置，必须是 root-owned、root-only 的绝对路径文件 |

要求：

- `service.exec_start` 第一个 token 是已存在、可执行的绝对路径。
- 业务服务监听地址和 `app.listen` 一致。
- `service.env_file` 只在 `listen` 模式使用；如设置，必须是 root-owned、root-only 的绝对路径文件。

## 第 6 步：Preview 和 Verify

点击 `Preview Exposure`，确认公网只通过 Nginx `80/tcp` 和 `443/tcp` 进入，不开放 `18001` 这类 App 端口。

点击 `Verify`。

成功标准：

- `Jobs` 中对应 Job 状态为成功。
- human/json 输出状态为 `static-passed`。
- 没有要求先修复的域名、证书、模板、service 或端口错误。
- exposure plan 不是 `fail` 或 `unknown`；否则 verify 会先失败，不渲染公网 runtime path。

`lanpanel app verify` 只是静态配置、暴露面阻断项和模板检查，不读取已部署宿主机运行状态。

## 第 7 步：Deploy

点击 `Deploy`。

成功后在服务器上检查：

```bash
sudo nginx -t
curl -I https://app.example.com
systemctl status <app-name>.service --no-pager --full
journalctl -u <app-name>.service -e
```

如果服务没有启动，优先检查 `Service exec start`、`Working directory`、业务端口和 `journalctl` 输出。

## 常见下一步

- 需要真实访问日志看板：读 [App 配置参考](app.md) 的 GoAccess。
- 需要通过 EdgeOne 回源并还原真实客户端 IP：读 [App 配置参考](app.md) 的 EdgeOne RealIP。
- 后端服务在 tailnet 其它节点：读 [App 配置参考](app.md) 的 `upstream` 模式。
- 部署失败或返回 502：读 [常见问题和排障](troubleshooting.md)。
