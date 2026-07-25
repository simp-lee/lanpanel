# UI 面板手册

Lanpanel Management UI 是当前推荐的人机操作入口。它只在服务器本机地址监听，通过一次性启动 URL 登录，然后在浏览器里完成配置、验证、部署和查看任务。UI 不使用 CDN，内置 `htmx.min.js`。

如果你是第一次使用，先按目标阅读：

- 部署私有网络：[快速开始：部署私有网络](quickstart.md)。
- 只发布本机 App：[快速开始：发布本机 App](app-quickstart.md)。

本文是 UI 页面和操作边界手册，用来解释每个页面做什么、哪些操作需要 root、Jobs 中能看到什么。

## 启动方式

在服务器上启动：

```bash
sudo lanpanel ui --listen 127.0.0.1:18080
```

常用参数：

| 参数 | 作用 |
| --- | --- |
| `--listen` | loopback IP literal 和端口，默认 `127.0.0.1:18080` |
| `--state-dir` | UI job/event/resource state 目录，默认 `/var/lib/lanpanel/ui-state` |
| `--config` | 主配置路径，默认 `lanpanel.yaml` |
| `--app-config` | 当前 UI 操作的 App 配置路径，默认 `lanpanel-app.yaml` |
| `--token-ttl` | 启动 token 有效期，默认 `10m`，最大 `30m` |

`--app-config` 可以省略。UI 不要求启动前先准备 App 配置文件；默认会使用 `lanpanel-app.yaml`，缺失时在 `Resources` 页面显示 `Create Example App Config`，点击后由 UI 写出示例配置。需要把 UI 当前操作绑定到其它文件时，再显式指定 `--app-config`。

## UI 和配置文件

UI 是配置文件的编辑器和部署入口。普通用户不需要手写 `lanpanel.yaml` 或 `lanpanel-app.yaml`：

- `Settings` 保存主配置到 `--config` 指定路径，默认 `lanpanel.yaml`。
- `Resources` 保存 App 配置到 `--app-config` 指定路径，默认 `lanpanel-app.yaml`。
- `Create Example Main Config` 和 `Create Example App Config` 会先写出可编辑示例。
- `Save` 会把表单内容写回配置文件。
- `Verify` 和 `Deploy` 会读取同一个配置文件并复用 CLI 的验证和部署逻辑。

文档中的 YAML 示例主要用于 CLI、排障、备份迁移和审计。使用 UI 时，按页面字段填写即可。

有些字段是外部文件路径，UI 会保存路径但不会凭空生成业务密钥文件，例如 DNS-01 env file、Tailscale auth key file、EdgeOne env file、业务自己的 `service.env_file` 和 GoAccess htpasswd。Browser Auth 可以通过 UI 的专用面板创建或轮换。GoAccess dashboard 使用独立 htpasswd；先在服务器上手工准备合法文件，再把路径填入 App 配置。

第一次使用只需要记住三步：

1. 在服务器上运行 `sudo lanpanel ui --listen 127.0.0.1:18080`。
2. 在自己电脑上建立 SSH 端口转发。
3. 打开命令输出里的 `Open once` URL。

如果浏览器在自己的电脑上，先按本机系统建立 SSH 端口转发：

```bash
# Linux / macOS / Windows OpenSSH
ssh -L 18080:127.0.0.1:18080 user@server
```

Windows 没有 OpenSSH 或习惯使用 PuTTY 时，在 PuTTY 的 `Connection -> SSH -> Tunnels` 中添加：

| 字段 | 值 |
| --- | --- |
| Source port | `18080` |
| Destination | `127.0.0.1:18080` |
| 类型 | `Local` |

添加后连接服务器并保持 PuTTY 会话打开。

然后打开 `lanpanel ui` 输出里的 `Open once` URL。启动 token 只能使用一次，过期或已使用后需要重启 UI 生成新的 URL。

UI 只接受 loopback IP literal，例如 `127.0.0.1:18080` 或 `[::1]:18080`。不要使用 `0.0.0.0`、公网 IP、`::` 或 `localhost`。

## 权限和 state

建议生产操作使用 `sudo lanpanel ui`。默认 state 目录 `/var/lib/lanpanel/ui-state` 适合 root 启动的 UI，会检查目录所有权、权限和 symlink 安全。

非 root 也可以用独立 `--state-dir` 打开 UI，但只适合查看页面、Exposure Preview、主/App Verify 和主 Status 这类不改系统的检查。以下会写配置、上传依赖、修改运行文件或生成凭据，必须用 root：

- 主配置保存、主部署。
- 依赖上传。
- App 初始化、App 配置保存、App 部署。
- RealIP refresh；RealIP diagnostics 读取部署目录，也应按 CLI 输出要求用 root。
- Headscale preauth handoff。
- Browser Auth create / rotate / delete。
- GoAccess dashboard 只在 UI 保存和检查外部 htpasswd 路径；UI 不创建或轮换 GoAccess htpasswd。只有 Browser Auth 提供 UI create / rotate / delete。

## 页面地图

| 页面 | 用途 |
| --- | --- |
| `Overview` | 控制中心、主配置摘要、主机健康摘要、资源暴露摘要、最近任务 |
| `Settings` | 主 `lanpanel.yaml` 表单、创建示例配置、Verify、Deploy |
| `Resources` | App 配置表单、Exposure Preview、App Verify/Deploy、Browser Auth、GoAccess、RealIP 操作 |
| `Diagnostics` | 运行诊断与主机健康检查汇总 |
| `Services` | 托管服务相关诊断和主 status refresh |
| `Certificates / Nginx` | 证书、Nginx、运行文件路径和相关检查 |
| `Host Health` | 只读 OS、CPU、内存、磁盘、网络地址、端口监听、证书事实 |
| `Headscale Onboarding` | 默认 `lanpanel` 用户 readiness 和一次性 preauth key 交接 |
| `Jobs` | 任务历史、events、modified paths、retry commands、一次性 secret 交接 |
| `Exit / Migration` | 迁移边界、应保留的本地路径、不会导出的内容 |

## 主网络部署

首次部署 Headscale 私有网络：

1. 打开 `Settings`。
2. 如果没有主配置，点击 `Create Example Main Config`。
3. 至少填写 `Server URL`、`Base domain`、`Certificate email` 和 ACME challenge。
4. 需要 DNS-01、离线包、代理、平台架构、公网 IP 覆盖时再展开高级字段。
5. 点击 `Save`。
6. 点击 `Verify`。
7. 确认 DNS、端口、证书前置条件后点击 `Deploy`。
8. 在 `Jobs` 查看部署结果、修改路径和失败时的 retry command。

UI 的 Verify 与 CLI `lanpanel verify` 一样，是静态配置和运行模板检查；它不替代宿主机上的 `systemctl`、`nginx -t`、`curl` 和真实客户端连通性验证。

## 离线依赖上传

如果服务器不能直接访问 GitHub release，可以在 UI 上传固定版本依赖：

- `Settings` 页面 `Dependency Uploads` 提供 `Upload lego archive` 和 `Upload Headscale deb`。
- `Resources` 页面 `Dependency Uploads` 提供 App-only 部署使用的 `Upload lego archive`。
- 上传文件名必须等于 UI 显示的 `Expected archive` 或 `Expected package`，并匹配当前配置里的平台架构。
- UI 会按 Lanpanel 内置的固定版本和 SHA-256 校验文件，通过后存入 `/var/cache/lanpanel/dependencies/...`，并把对应配置改为 `offline` 文件源。

这个入口只用于提供官方 lego archive 或 Headscale `.deb`。不要上传改名文件、其它版本文件或自建包；校验不匹配会直接失败并保留原配置。

## 发布 App

发布业务服务的入口在 `Resources`：

1. 如果没有 App 配置，点击 `Create Example App Config`。
2. 确认或修改 `App config path`，然后在 `Resource` 填 `App name`、域名、证书邮箱、`listen` 或 `upstream`。
3. 在 `Access` 选择 `browser` 或 `public`。
4. 在 `Origin protection` 选择 `none` 或 `edgeone`。
5. 需要 systemd service、GoAccess、DNS-01、Tailscale 时填写对应折叠区。
6. 点击 `Preview Exposure` 看暴露面计划。
7. 点击 `Verify` 或 `Deploy`。

`Deploy` 和 `RealIP Refresh` 会复用 CLI 的部署逻辑。只有暴露面计划返回 `configured_manual` 并提示缺少 `origin-protection-manual` 时，才按页面提示勾选确认，表示你已经处理源站安全组、防火墙或等价边界，只允许 EdgeOne OriginACL current+next CIDR 访问源站 `80/443`。`configured_pass` 不需要人工确认。

使用 UI 发布 App 时，不需要先手写最小 listen/upstream YAML；那些示例是 UI 保存结果的等价结构。App 的详细配置见 [App 配置参考](app.md)。

## Browser Auth

`Resources` 页面包含 Browser Auth Credentials：

- `Create`：在 `/etc/lanpanel/browser-auth` 下创建托管 htpasswd。
- `Rotate`：轮换指定托管 htpasswd 中的用户密码。
- `Delete`：删除托管 htpasswd，但只有 UI 能证明没有 active 或 staged browser App 引用它时才会执行。

创建或轮换后，明文密码只在当前浏览器会话的一次性交接区展示。关闭页面或过期后无法恢复明文，只能再次轮换。配置文件和任务历史只保存 `credential_id`、`htpasswd_path`、`username`、`password_fingerprint`。

## GoAccess Dashboard Auth

GoAccess dashboard Auth 与 Browser Auth 是两套凭据。先手工创建合法外部 htpasswd，再把路径填入 `Nginx and observability` 的 `GoAccess auth file`。如果路径位于 `/etc/<app-name>` 下，校验只接受直接文件 `/etc/<app-name>/goaccess.htpasswd`，不接受嵌套子目录。不要把 `/etc/lanpanel/browser-auth` 下的 Browser Auth 托管文件复用于 GoAccess。

## Headscale Onboarding

主部署成功后，打开 `Headscale Onboarding`：

1. 确认默认 `lanpanel` onboarding 用户 readiness。
2. 填写用户和 TTL，默认 `lanpanel`、`24h`。
3. 创建一次性 preauth key。
4. 在 `Jobs` 当前浏览器会话的一次性交接区复制 key 给客户端。

preauth key 不写入任务历史、诊断输出、工作流输出或保存结果。每台客户端都应创建新的短期 key，不要复用。

## Jobs 和一次性 secret

UI 中所有变更都作为 Job 执行。Job 就是一次操作任务，记录包含：

- kind、status、actor。
- checkpoint 或 `not_applicable`。
- 配置 snapshot ref。
- modified paths。
- retry command。
- 脱敏后的结果字段和 events。

一次性 secret 只在创建该 Job 的当前浏览器会话中展示，且有单独过期时间。Jobs/history 不应包含 preauth key、browser password、DNS token、EdgeOne secret、Tailscale auth key 或 htpasswd 内容。

## Host Health 和 Diagnostics

Host Health 是只读事实页。它读取本机 OS、CPU、内存、磁盘、网络地址、端口监听、证书过期时间和有限诊断，不提供任意 shell、包管理器、systemd 编辑器、Nginx 编辑器或网络设置修改入口。

Diagnostics、Services、Certificates / Nginx 页面展示的是结构化运行证据：配置、已生成文件、checkpoint、服务路径、证书路径、GoAccess、RealIP、主机健康检查等。它们用于判断下一步操作，不是备份或恢复依据。

## Exit / Migration 边界

当前 UI 不生成机器可读导出清单，也不做一键恢复。迁移时至少保留或记录：

- 主配置 `lanpanel.yaml`。
- App 配置。
- UI state 目录。
- `/etc/lanpanel`、`/var/lib/lanpanel`、Headscale SQLite、证书和续期状态。
- `/etc/lanpanel/browser-auth` 下仍被引用的托管凭据。
- DNS-01、EdgeOne、Tailscale 等密钥文件路径。

preauth key 和 browser password 明文不能从历史记录恢复，需要重新创建。
