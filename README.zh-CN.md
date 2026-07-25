# Lanpanel

[English](README.md) | 简体中文

Lanpanel 是一个面向单台 Debian/Ubuntu 服务器的私有网络和应用发布工具，不是 VPN 客户端。它可以部署 Headscale、Nginx、HTTPS 证书续期和 systemd 服务，也可以只把同机 Go Web 服务或 tailnet 内 HTTP/WebSocket 服务发布到公网 HTTPS。

当前推荐入口是 Management UI：在服务器上启动 UI，通过 SSH 端口转发在自己电脑浏览器里打开面板，然后完成配置、验证、部署、App 发布、Browser Auth、GoAccess 配置、EdgeOne RealIP、客户端接入密钥生成和任务查看。CLI 保留完整能力，适合自动化、无浏览器环境和排障。

## 先选你的目标

| 我想做什么 | 先读 |
| --- | --- |
| 从零部署私有 Tailscale/Headscale 网络 | [快速开始：部署私有网络](docs/zh-CN/quickstart.md) |
| 只把同机 Web 服务发布到 HTTPS | [快速开始：发布本机 App](docs/zh-CN/app-quickstart.md) |
| 安装、升级或源码构建 Lanpanel | [安装和升级](docs/zh-CN/install.md) |
| 看不懂 Headscale、tailnet、ACME 等词 | [核心概念](docs/zh-CN/concepts.md) |
| UI 打不开、证书失败、App 502、客户端连不上 | [常见问题和排障](docs/zh-CN/troubleshooting.md) |
| 查完整中文目录 | [中文文档索引](docs/zh-CN/index.md) |

第一次使用建议先走 UI，不要先读 CLI 参考。命令行自动化需要时再看 [CLI 运维手册](docs/zh-CN/cli.md)。

## 适用范围

适合：

- 自建私有 Tailscale/Headscale 网络，并由 Lanpanel 管理 Headscale、Nginx、证书和 systemd。
- 把同机 Go Web 服务发布到 HTTPS。
- 把 tailnet 内固定 HTTP/WebSocket upstream 发布到 HTTPS。
- 给 App 增加 Browser Basic Auth、GoAccess 实时访问日志看板，或腾讯云 EdgeOne 真实客户端 IP 还原。
- 通过本机 UI 或 CLI 做小团队、单机、可审计的运维。

不适合：

- 多机高可用、Kubernetes、Terraform、Ansible。
- 公网远程控制面、OIDC/SSO、RBAC、多账号商业面板。
- 通用反向代理框架、Tailscale 客户端替代品、数据库端口发布器。
- 自动管理云防火墙、自动确认 EdgeOne 回源 IP 更新、完整备份/恢复系统。

当前基线：

| 范围 | 基线 |
| --- | --- |
| 服务器系统 | Debian、Ubuntu，或具备 apt/dpkg/systemd 的 Debian 系发行版 |
| Headscale | v0.29.1，只监听 loopback 本机地址，由 Nginx 对外代理 |
| TLS 自动化 | HTTP-01 或 DNS-01，使用 Lanpanel 管理的固定 lego v5.2.2 |
| 中继 | Headscale 内置 DERP/STUN，`3478/udp` 用于 STUN，不接入官方 DERP 列表 |
| 客户端 | Windows、macOS、Debian/Ubuntu Linux |
| 客户端基线 | Tailscale-compatible client >= v1.80.0 |

## 安装

先打开 [Releases](https://github.com/simp-lee/lanpanel/releases)，选择一个真实稳定 tag，然后替换下面的 `vX.Y.Z`。不要原样复制占位版本。

```bash
VERSION=vX.Y.Z
curl -fsSL "https://raw.githubusercontent.com/simp-lee/lanpanel/${VERSION}/scripts/install.sh" | sh -s -- "${VERSION}"
lanpanel --version
lanpanel --help
```

安装脚本会从同一个 release tag 下载二进制和 `checksums.txt`，校验 SHA-256 后默认安装到 `/usr/local/bin/lanpanel`。更多安装、升级、卸载和源码构建说明见 [安装和升级](docs/zh-CN/install.md)。

## 最短 UI 流程

在服务器上启动 UI：

```bash
sudo lanpanel ui --listen 127.0.0.1:18080
```

如果浏览器不在服务器本机，在自己的电脑上建立 SSH 端口转发：

```bash
ssh -L 18080:127.0.0.1:18080 user@server
```

然后打开 `lanpanel ui` 输出里的 `Open once` URL。启动 token 只能使用一次，过期或已使用后需要重启 UI 生成新的 URL。

UI 只允许 loopback IP literal，也就是 `127.0.0.1` 或 `[::1]` 这类本机 IP 地址形式；不要监听 `0.0.0.0`、公网 IP、`::` 或 `localhost`。

使用 UI 时，普通用户不需要手写 `lanpanel.yaml` 或 `lanpanel-app.yaml`。UI 会把你在表单中填写的内容保存到配置文件，再复用同一套 verify/deploy 逻辑执行部署。文档里的 YAML 示例主要给 CLI、排障、备份迁移和审计使用。

部署私有网络：

1. `Settings`：创建或编辑主配置。
2. `Settings`：运行 Verify。
3. `Settings`：运行 Deploy。
4. `Headscale Onboarding`：创建一次性 preauth key。
5. `Jobs`：查看每次操作的状态、修改路径、重试命令和脱敏输出。

发布业务 App：

1. `Resources`：创建或编辑 App 配置。
2. `Resources`：预览暴露面计划。
3. `Resources`：运行 Verify 或 Deploy。
4. 如使用 `browser` 访问模式，在 `Resources` 创建或轮换托管 Browser Auth 凭据。
5. 如启用 GoAccess，看板使用独立 htpasswd；先在服务器上准备合法外部文件，再在 `Resources` 的 GoAccess auth file 填入路径。不要复用 Browser Auth 凭据。
6. 如使用 EdgeOne RealIP，执行 Deploy 或 RealIP Refresh 前先维护源站安全组/防火墙边界；只有暴露面计划提示缺少 `origin-protection-manual` 时才提交确认。

## 一图看懂

```text
公网用户 / Tailscale 客户端
        |
        | 80/tcp, 443/tcp, 3478/udp
        v
+---------------- Debian/Ubuntu 服务器 ----------------+
| Nginx: 公网 HTTPS 入口                                |
| Headscale: 私有网络控制面，只在本机地址监听             |
| 内置 DERP/STUN: 直连失败时兜底                         |
| App listen: 同机服务只监听 127.0.0.1:port              |
| App upstream: 通过本机 Tailscale client 访问 tailnet    |
+------------------------------------------------------+
        |
        | tailnet 内 HTTP/WebSocket
        v
私有网络内的 Grafana / Uptime Kuma / 内部管理后台
```

普通用户只需要先记住：

- 客户端通过 Headscale 登录私有网络，设备之间优先 WireGuard 直连，失败才通过 DERP 兜底。
- 公网用户访问业务域名时只进入 Nginx。
- 本机 App 只监听本机地址。
- `upstream` 只适合 HTTP/WebSocket 服务，不用于 PostgreSQL、MySQL、Redis 等数据库或中间件端口公网发布。

更多术语解释见 [核心概念](docs/zh-CN/concepts.md)。

## 安全底线

- Management UI 只监听 loopback，通过 SSH 端口转发使用；不要暴露公网。
- 不把 DNS token、EdgeOne secret、Tailscale auth key、preauth key、browser password 或 htpasswd 内容写入配置、任务历史或文档示例。
- DNS-01、EdgeOne、Tailscale 等密钥文件必须 root-owned、root-only，并通过 `_FILE` 或显式路径引用。
- App 业务端口不要直接暴露公网；公网只进 Nginx `80/443`。
- `public` App 需要显式设置 `public_risk_confirmed`；EdgeOne origin protection 只有在暴露面计划返回 `configured_manual` 并提示缺少确认时，Deploy/RealIP Refresh 才需要提交 `origin-protection-manual`。
- 生成的 Nginx、systemd、TLS 和 RealIP 运行文件不要手改；修改配置后重新运行 UI Job 或 CLI deploy。

完整边界见 [安全边界](docs/zh-CN/security.md)。

## 中文文档

用户文档：

- [中文文档索引](docs/zh-CN/index.md)
- [安装和升级](docs/zh-CN/install.md)
- [快速开始：部署私有网络](docs/zh-CN/quickstart.md)
- [快速开始：发布本机 App](docs/zh-CN/app-quickstart.md)
- [核心概念](docs/zh-CN/concepts.md)
- [UI 面板手册](docs/zh-CN/ui.md)
- [App 配置参考](docs/zh-CN/app.md)
- [CLI 运维手册](docs/zh-CN/cli.md)
- [服务器和客户端运维](docs/zh-CN/operations.md)
- [常见问题和排障](docs/zh-CN/troubleshooting.md)
- [安全边界](docs/zh-CN/security.md)

开发者文档：

- [开发和人工测试](docs/zh-CN/development.md)
