# 快速开始：部署私有网络

这篇文档带你完成第一个主 Headscale 私有网络：启动 UI、创建主配置、Verify、Deploy、生成一次性 preauth key，并让客户端加入网络。

如果你只是想发布同机 Web App，可以跳过本文，直接读 [快速开始：发布本机 App](app-quickstart.md)。

## 你会完成什么

完成后应该得到：

- 一个自建 Headscale 登录地址，例如 `https://hs.example.com`。
- 一张由 Lanpanel 管理并自动续期的 HTTPS 证书。
- 云服务器上的 Nginx、Headscale、内置 DERP/STUN 和 systemd 服务。
- 至少一台 Tailscale-compatible client 接入成功。
- 用两台不同网络里的客户端验证 `tailscale ping` 和 `tailscale netcheck`。

## 准备

| 需要 | 示例 | 从哪里获得 |
| --- | --- | --- |
| 服务器 | Debian 12 或 Ubuntu 22.04/24.04 | 云厂商 |
| 管理权限 | root 或 sudo | 服务器账号 |
| 登录域名 | `hs.example.com` | DNS 控制台 |
| MagicDNS 后缀 | `tailnet.example.com` | 你控制的域名 |
| 证书邮箱 | `ops@example.com` | ACME 注册邮箱 |
| 客户端 | Tailscale client >= v1.80.0 | Tailscale 官方下载页 |

主部署需要放行：

| 端口 | 用途 |
| --- | --- |
| `80/tcp` | HTTP-01、HTTP redirect、Nginx app entry |
| `443/tcp` | HTTPS control、DERP WebSocket、App HTTPS |
| `3478/udp` | Headscale 内置 STUN |

中国大陆公网部署前先确认 ICP/接入规则、云入口策略、包下载可达性、代理配置和 HTTP-01 是否可用。公网 `80/tcp` 不可靠时，后续改用 DNS-01。

## 第 1 步：安装 Lanpanel

按 [安装和升级](install.md) 安装 release 二进制，然后确认：

```bash
lanpanel --version
lanpanel --help
```

看到 `lanpanel` 版本和帮助输出，说明命令已经可用。

## 第 2 步：确认 DNS 和端口

确认 `hs.example.com` 已经解析到这台服务器的公网 IP，并且云安全组或主机防火墙已经放行 `80/tcp`、`443/tcp`、`3478/udp`。

如果你不确定当前服务器公网 IP，先在云厂商控制台确认；不要把 CDN/WAF 后面的地址当成 HTTP-01 直连源站。

## 第 3 步：启动 UI

在服务器上运行：

```bash
sudo lanpanel ui --listen 127.0.0.1:18080 --config lanpanel.yaml
```

命令会打印 UI 监听地址、一次性打开 URL、SSH 端口转发示例和启动 token 有效期。

如果浏览器不在服务器本机，在自己的电脑上建立 SSH 端口转发：

```bash
# Linux / macOS / Windows OpenSSH
ssh -L 18080:127.0.0.1:18080 user@server
```

Windows PuTTY 用户在 `Connection -> SSH -> Tunnels` 添加 local tunnel：`Source port` 填 `18080`，`Destination` 填 `127.0.0.1:18080`，连接服务器后保持会话打开。更多隧道说明见 [UI 面板手册](ui.md#启动方式)。

然后打开服务器命令输出里的 `Open once` URL。启动 token 只能使用一次，过期或已使用后需要重启 UI 生成新的 URL。

UI 只允许 loopback IP literal，例如 `127.0.0.1` 或 `[::1]`。不要监听 `0.0.0.0`、公网 IP、`::` 或 `localhost`。

## 第 4 步：创建主配置

在 UI 中打开 `Settings`。

没有主配置时点击 `Create Example Main Config`，然后至少填写：

| 字段 | 示例 | 说明 |
| --- | --- | --- |
| `Server URL` | `https://hs.example.com` | 客户端登录地址 |
| `Base domain` | `tailnet.example.com` | MagicDNS 后缀，不能等于 Headscale 主机名，也不能是其父域 |
| `Certificate email` | `ops@example.com` | ACME 注册邮箱 |
| `ACME challenge` | `http-01` | 新手优先用 HTTP-01 |

先不要急着改高级选项。DNS-01、离线包、代理、平台架构和公网 IP 覆盖只在你的环境确实需要时再展开。

点击 `Save` 保存配置。

使用 UI 时不需要手写 `lanpanel.yaml`。UI 会把 `Settings` 页面里的表单内容保存到 `--config` 指定的文件，后续 Verify 和 Deploy 读取同一个文件。

## 第 5 步：Verify

在 `Settings` 点击 `Verify`。

成功标准：

- `Jobs` 中对应 Job 状态为成功。
- human/json 输出状态为 `passed`。
- 没有要求先修复的配置、DNS、端口或模板错误。

`verify` 是静态配置和运行模板检查；它不读取宿主机 systemd 状态、证书文件、Nginx 运行状态、Headscale 进程状态或客户端在线状态。

## 第 6 步：Deploy

确认 DNS 和端口没有问题后，在 `Settings` 点击 `Deploy`。

Deploy 会检查配置、系统家族、主机能力、权限、DNS、端口、包来源、ACME 前置条件和服务冲突；随后安装依赖、lego、Headscale，渲染运行文件，申请证书，启用服务，准备默认客户端接入用户，并执行静态验证。

成功标准：

```bash
sudo systemctl status headscale.service nginx.service --no-pager --full
sudo nginx -t
curl -I https://hs.example.com
lanpanel status --config lanpanel.yaml
```

期望看到：

- `headscale.service` 和 `nginx.service` 正常运行。
- `nginx -t` 通过。
- `curl -I https://hs.example.com` 返回 HTTPS 响应。
- `lanpanel status` 显示 readiness、checkpoint 和 minimum client version。

失败时不要手改生成的 Nginx、systemd、TLS hook 或 Headscale 运行文件。先看 `Jobs` 里的失败命令、详细结果、retry command 和 modified paths，修正配置或宿主机条件后重试同一个 Deploy。

## 第 7 步：创建一次性 preauth key

主部署成功后，打开 `Headscale Onboarding`：

1. 确认默认 `lanpanel` onboarding 用户 readiness。
2. 填写用户和 TTL，默认 `lanpanel`、`24h`。
3. 创建一次性 preauth key。
4. 在 `Jobs` 当前浏览器会话的一次性交接区复制 key 给客户端。

preauth key 不写入任务历史、诊断输出、工作流输出或保存结果。每台客户端都应创建新的短期 key，不要复用。

## 第 8 步：接入客户端

Windows 管理员 PowerShell：

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" version
& "$env:ProgramFiles\Tailscale\tailscale.exe" up --login-server https://hs.example.com --auth-key "<一次性 preauth key>" --accept-dns=true --hostname=laptop
& "$env:ProgramFiles\Tailscale\tailscale.exe" status
```

macOS 或 Debian/Ubuntu Linux：

```bash
tailscale version
sudo tailscale up \
  --login-server https://hs.example.com \
  --auth-key "<一次性 preauth key>" \
  --accept-dns=true

tailscale set --hostname=<name>
tailscale status
```

全平台详细步骤见 [服务器和客户端运维](operations.md)。

## 第 9 步：验证私有网络

至少用两台不同网络里的客户端验证，例如家庭宽带加手机热点。

统一验证目标：

```bash
tailscale status
tailscale ping peer-name.tailnet.example.com
tailscale netcheck
```

成功标准：

- 客户端使用的是自建 `server_url`，不是 Tailscale.com 默认控制面。
- `tailscale status` 显示节点在线。
- `--accept-dns=true` 或平台 UI 等价设置已启用。
- MagicDNS 名称可解析。
- `tailscale ping` 能访问另一台节点。
- `tailscale netcheck` 能看到直连或 DERP 兜底路径。

内置 DERP 不提供 `/generate_204`。不要只因为 captive portal 探测异常就判定部署失败。

## 下一步

- 想发布一个 Web App：读 [快速开始：发布本机 App](app-quickstart.md)。
- 想理解运行拓扑：读 [服务器和客户端运维](operations.md)。
- 失败了：读 [常见问题和排障](troubleshooting.md)。
