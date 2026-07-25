# 安全边界

Lanpanel 的默认设计是单机、可审计、显式确认。它不是公网远程控制面，不提供多账号 RBAC、OIDC/SSO、商业面板或自动云防火墙管理。

## Management UI

- Management UI 只监听 loopback，通过 SSH 端口转发使用。
- 允许 `127.0.0.1` 或 `[::1]` 这类 loopback IP literal。
- 不要监听 `0.0.0.0`、公网 IP、`::` 或 `localhost`。
- 启动 URL 只能使用一次，过期或已使用后需要重启 UI 生成新的 URL。
- UI 不使用 CDN，内置 `htmx.min.js`。

生产操作建议使用：

```bash
sudo lanpanel ui --listen 127.0.0.1:18080
```

## Secret 和凭据

不要把以下内容写入配置正文、任务历史、诊断输出、文档示例或 issue：

- DNS token。
- EdgeOne secret。
- Tailscale auth key。
- Headscale preauth key。
- browser password。
- htpasswd 内容。

DNS-01、EdgeOne、Tailscale 等密钥文件必须 root-owned、root-only，并通过 `_FILE` 或显式路径引用。

preauth key 和 browser password 明文只在一次性交接窗口展示，之后不能从历史记录恢复，需要重新创建或轮换。

## 网络边界

- 公网只应该看到 Nginx `80/tcp`、`443/tcp` 与 Headscale STUN `3478/udp`。
- Headscale control、metrics、gRPC 都只监听 loopback 本机地址。
- Management UI 只通过 SSH tunnel 访问。
- App 业务端口不要直接暴露公网；公网只进 Nginx `80/443`。
- `upstream` 只适合发布 HTTP/WebSocket 服务，不用于 PostgreSQL、MySQL、Redis 等数据库或中间件端口公网发布。

## App 访问模式

`public` App 表示业务直接对公网用户开放。这不是安全默认值，只适合你明确接受公网访问风险的 App。

`browser` App 会在 Nginx App gateway 层启用 Basic Auth，并在代理到业务服务前清除入站 `Authorization` header。Browser Auth 与 GoAccess dashboard Auth 是两套凭据，不能复用。

`private_client` 是 P0 保留访问模式，当前不能激活，UI 不提供写入入口。

## EdgeOne RealIP

EdgeOne origin protection 的暴露面计划返回 `configured_pass` 时不需要人工确认；返回 `configured_manual` 并提示缺少确认时，需要显式提交 `origin-protection-manual`。这个确认的含义是操作者已经理解并处理源站边界：

- 云安全组、主机防火墙或等价访问控制必须只允许 EdgeOne OriginACL current+next CIDR 访问源站 `80/443`。
- Lanpanel 会读取 EdgeOne OriginACL 并渲染 App site scoped realip 配置。
- Lanpanel 不调用 `ConfirmOriginACLUpdate`。
- Lanpanel 不修改 EdgeOne 站点、DNS 或证书配置。

如果 EdgeOne RealIP 使用独立腾讯云凭据，建议只授予目标 EdgeOne zone 的 `DescribeOriginACL` 权限；如果与 DNS-01 共用凭据，则需要同时具备 DNSPod 记录管理权限和目标 EdgeOne zone 的 `DescribeOriginACL` 权限。

## 生成文件

不要手改 Lanpanel 生成的 Nginx、systemd、TLS、RealIP 或 Headscale 运行文件。修改配置后重新运行 UI Job 或 CLI deploy。

迁移时至少保留或记录：

- 主配置 `lanpanel.yaml`。
- App 配置。
- UI state 目录。
- `/etc/lanpanel`、`/var/lib/lanpanel`、Headscale SQLite、证书和续期状态。
- `/etc/lanpanel/browser-auth` 下仍被引用的托管凭据。
- DNS-01、EdgeOne、Tailscale 等密钥文件路径。

当前 UI 不生成机器可读导出清单，也不做一键恢复。
