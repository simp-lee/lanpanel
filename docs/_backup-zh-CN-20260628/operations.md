# 服务器和客户端运维

本文覆盖主 Headscale 私有网络部署、服务器运行验证、客户端接入和安全边界。发布业务 App 的细节见 [发布业务服务 App](app.md)。

如果你只是想发布同机业务 App，可以先跳过本文的 Headscale 和客户端接入部分，只看 App 文档。本文主要用于部署私有网络、排障服务器和接入 Windows/macOS/Linux 客户端。

新手部署前先确认三件事：

- 域名已经解析到这台服务器。
- 云安全组或防火墙已经放行需要的端口。
- 能用 root 或 sudo 运行 Lanpanel。

## 服务器准备

目标服务器要求：

- Debian、Ubuntu，或具备 `apt` / `dpkg` / systemd 的 Debian 系发行版。
- root 或可用 sudo。
- 可下载 Headscale `.deb`、固定版本 lego archive、Tailscale 包和 GoAccess 包；不可直连时准备镜像、离线包或代理。
- 公网 DNS 指向服务器。

主 Headscale 部署需要放行：

| 端口 | 用途 |
| --- | --- |
| `80/tcp` | HTTP-01、HTTP redirect、Nginx app entry |
| `443/tcp` | HTTPS control、DERP WebSocket、App HTTPS |
| `3478/udp` | Headscale 内置 STUN |

只发布本机 App、不部署 Headscale 时通常只需要 `80/tcp` 和 `443/tcp`。

中国大陆公网部署前要确认 ICP/接入规则、云入口策略、包下载可达性、代理配置和 HTTP-01 是否可用。必要时改用 DNS-01、镜像、离线包或代理。

## 主配置

最小主配置：

```yaml
api_version: lanpanel/v1alpha1

default:
  server_url: "https://hs.example.com"
  base_domain: "tailnet.example.com"
  certificate_email: "ops@example.com"
  acme_challenge: "http-01"
```

字段：

| 字段 | 说明 |
| --- | --- |
| `server_url` | 客户端 `tailscale up --login-server` 使用的 HTTPS 地址 |
| `base_domain` | 私有 MagicDNS 后缀，不能等于 Headscale 主机名，也不能是其父域 |
| `certificate_email` | ACME 注册邮箱 |
| `acme_challenge` | `http-01` 或 `dns-01` |

高级字段只在需要 Headscale mirror/offline、lego offline、DNS-01、代理、包探测超时、metrics port、平台架构或公网 IP 覆盖时使用。

## ACME

公网 `80/tcp` 可达时使用 HTTP-01：

```yaml
default:
  acme_challenge: "http-01"
```

公网 80 不可靠或组织策略要求 DNS 验证时使用 DNS-01：

```yaml
default:
  acme_challenge: "dns-01"

advanced:
  dns01:
    provider: "tencentcloud"
    env_file: "/etc/lanpanel/dns01/tencentcloud.env"
```

新手优先使用 HTTP-01。只有公网 80 不可达、被接入层拦截，或组织策略要求 DNS 验证时，再配置 DNS-01。

支持的 lego provider code：

- `cloudflare`
- `route53`
- `digitalocean`
- `gcloud`
- `tencentcloud`

`google` 可作为 `gcloud` 别名。

不要把 DNS API 值写进 `lanpanel.yaml`，也不要把原始 token/key 直接写进 `env_file`。Cloudflare、DigitalOcean、Tencent Cloud 应使用 root-owned、root-only 的 env file，并通过 provider 支持的 `_FILE` 变量引用 root-owned、root-only 密钥文件。

腾讯云 DNSPod 示例：

```bash
sudo install -d -o root -g root -m 0700 /etc/lanpanel/dns01
sudo install -o root -g root -m 0600 /dev/null /etc/lanpanel/dns01/tencentcloud-secret-id
sudo install -o root -g root -m 0600 /dev/null /etc/lanpanel/dns01/tencentcloud-secret-key
printf '%s' '<腾讯云 SecretId>' | sudo tee /etc/lanpanel/dns01/tencentcloud-secret-id >/dev/null
printf '%s' '<腾讯云 SecretKey>' | sudo tee /etc/lanpanel/dns01/tencentcloud-secret-key >/dev/null

sudo install -o root -g root -m 0600 /dev/null /etc/lanpanel/dns01/tencentcloud.env
sudo tee /etc/lanpanel/dns01/tencentcloud.env >/dev/null <<'EOF'
TENCENTCLOUD_SECRET_ID_FILE=/etc/lanpanel/dns01/tencentcloud-secret-id
TENCENTCLOUD_SECRET_KEY_FILE=/etc/lanpanel/dns01/tencentcloud-secret-key
TENCENTCLOUD_PROPAGATION_TIMEOUT=900
TENCENTCLOUD_POLLING_INTERVAL=10
TENCENTCLOUD_TTL=600
TENCENTCLOUD_HTTP_TIMEOUT=60
LEGO_DNS_RESOLVERS=119.29.29.29:53
LEGO_DNS_TIMEOUT=30
LEGO_DNS_PROPAGATION_DISABLE_ANS=true
EOF
```

Route53 和 gcloud 可以使用宿主机凭据链，或在 env file 中只放 provider 设置与凭据文件路径。

## UI 部署路径

```bash
sudo lanpanel ui --listen 127.0.0.1:18080 --config lanpanel.yaml
```

通过 SSH tunnel 打开 UI 后：

1. `Settings` 创建或编辑主配置。
2. `Settings` 运行 Verify。
3. `Settings` 运行 Deploy。
4. `Jobs` 查看结果。
5. `Headscale Onboarding` 创建一次性 preauth key。

UI 详细说明见 [UI 面板手册](ui.md)。

## CLI 部署路径

```bash
lanpanel init --config lanpanel.yaml
lanpanel verify --config lanpanel.yaml
sudo lanpanel deploy --config lanpanel.yaml
lanpanel verify --config lanpanel.yaml
lanpanel status --config lanpanel.yaml
```

部署会检查配置、系统家族、主机能力、权限、DNS、端口、包来源、ACME 前置条件和服务冲突；随后安装依赖、lego、Headscale，渲染运行文件，申请证书，启用服务，准备默认客户端接入用户，并执行静态验证。

deploy 不创建或打印可复用 preauth key。请通过 UI 的 Headscale Onboarding 创建短期一次性 handoff。

## 运行拓扑

主部署拓扑如下。公网只应该看到 Nginx 的 `80/tcp`、`443/tcp` 和 Headscale STUN 的 `3478/udp`；Headscale 控制面、metrics、gRPC 和管理 socket 都留在服务器本机边界内。

```text
Internet / ACME CA / Tailscale clients
  |                         \
  | 443/tcp control + DERP   \ 3478/udp STUN
  | 80/tcp HTTP-01            \
  v                            v
+------------------------------------------------+
| Debian/Ubuntu server                           |
|                                                |
| Nginx                                          |
|   - serves HTTP-01 from acme-challenges        |
|   - terminates TLS with fullchain.pem          |
|   - proxies control traffic to 127.0.0.1:8080  |
|   - proxies DERP WebSocket with HTTP/1.1       |
|                                                |
| Headscale                                      |
|   - control plane on 127.0.0.1:8080            |
|   - metrics on 127.0.0.1:<metrics_port>        |
|   - gRPC on 127.0.0.1:50443                    |
|   - local admin over unix socket               |
|   - embedded DERP behind Nginx HTTPS           |
|   - STUN on 0.0.0.0:3478/udp                   |
|                                                |
| lanpanel-managed lego                           |
|   - issues and renews certificates             |
|   - reloads Nginx after certificate install    |
+------------------------------------------------+
```

客户端之间优先走直连 WireGuard；直连失败时，经 Nginx 代理的内置 DERP 通过 `443/tcp` 兜底。

期望：

- Headscale control、metrics、gRPC 都只监听 loopback 本机地址。
- Nginx 从 `/var/lib/lanpanel/acme-challenges` 处理 HTTP-01。
- Nginx 使用 `/etc/lanpanel/tls/<server>/fullchain.pem` 和 `/etc/lanpanel/tls/<server>/privkey.pem`。
- Nginx 有 HTTP/HTTPS `default_server` catch-all，拒绝不匹配 Host/SNI 的流量。
- Headscale `derp.urls` 为空，使用内置 DERP/STUN。
- Management UI 只通过 SSH tunnel 访问。

部署后检查：

```bash
sudo systemctl status headscale.service nginx.service --no-pager --full
sudo nginx -t
curl -I https://hs.example.com
```

## 服务端排障

失败时先看 Lanpanel 输出的失败命令、详细结果和重试命令。不要直接手改生成的 Nginx、systemd、TLS hook 或 Headscale 运行文件；修正配置或宿主机条件后重新运行对应命令。

新手排障顺序：先看 UI 的 `Jobs`，再运行 `lanpanel verify`，最后看 `systemctl`、`nginx -t` 和日志。

配置类问题先检查：

- `default.server_url` 是否是公网 HTTPS URL，并且 DNS 指向目标服务器。
- `default.base_domain` 是否没有等于 Headscale 主机名，也不是 Headscale 主机名的父域。
- `default.certificate_email` 是否是有效邮箱。
- `default.acme_challenge` 是否与实际网络条件匹配。

预检失败常见原因：

- 公网 DNS 还未解析到目标服务器，或解析结果被 CDN / WAF / 云接入层改写。
- `80/tcp`、`443/tcp` 或 `3478/udp` 没有在云安全组、主机防火墙或上游网络放行。
- 机器上已有 Nginx 站点占用相同 `server_name`。不同 `server_name` 可以共存；默认站点冲突要按 Lanpanel 输出处理。
- HTTP-01 被强制跳转、代理缓存或上游负载均衡拦截；这种环境应改用 DNS-01。

软件包和 lego：

- direct 模式会下载固定的 Headscale v0.29.1 `.deb` 并校验 SHA-256。
- mirror 模式需要可访问 URL 和明确的 SHA-256。
- offline 模式需要本地 `.deb` 文件和明确的 SHA-256。
- lego offline 模式要求 `advanced.lego_source.file_path` 指向匹配 `advanced.platform.arch` 的固定版本 lego v5.2.2 archive。
- Management UI 的 `Dependency Uploads` 可以上传固定版本 lego archive 或 Headscale `.deb`，校验文件名、架构和内置 SHA-256 后自动切换到 offline 文件源。
- 已由 lego v4 创建的证书数据会在签发或续期前自动迁移。迁移失败时，按错误里的 lego data path 检查权限或异常文件，然后重新运行 deploy。

运行状态检查重点：

- Headscale 应监听 `127.0.0.1:8080`。
- metrics 默认监听 `127.0.0.1:<advanced.headscale.metrics_port>`，默认端口是 `19090`。
- gRPC 应监听 `127.0.0.1:50443`。
- STUN 应监听 `3478/udp`。
- Nginx `nginx -t` 必须通过，且 Headscale 的 DERP WebSocket upgrade 由 Nginx 代理。

常用命令：

```bash
lanpanel verify --config lanpanel.yaml
lanpanel status --config lanpanel.yaml
sudo nginx -t
sudo systemctl status headscale.service nginx.service --no-pager --full
sudo journalctl -u headscale.service -e
sudo ss -lntup
```

如果失败影响的是 App 发布，而不是主 Headscale 部署，优先检查：

- `service.exec_start` 第一个 token 是否是已存在、可执行的绝对路径。
- `listen` App 是否真的监听配置里的 loopback 本机地址。
- `upstream` App 是否能从云服务器访问固定 HTTP/WebSocket upstream。
- `systemctl status <app-name>.service --no-pager --full`。
- Nginx App site、证书路径和静态 alias 目标是否由 `lanpanel app deploy` 重新生成。

## 客户端接入

每个客户端用户需要：

- `server_url`，例如 `https://hs.example.com`。
- 一个通过 UI Headscale Onboarding 创建的一次性 preauth key。
- `base_domain` 对应的 MagicDNS 后缀，例如 `tailnet.example.com`。
- Tailscale-compatible client >= `v1.80.0`。

每台客户端都创建新的短期 preauth key。不要复用 key。

统一验证目标：

- 已加入自建 login server。
- `tailscale status` 显示在线。
- 接受托管 DNS：`--accept-dns=true` 或平台 UI 等价设置。
- MagicDNS 可解析。
- 能 `tailscale ping` 另一台节点。
- `tailscale netcheck` 能看到直连或 DERP 兜底路径。

至少用两台不同网络里的客户端验证，例如家庭宽带加手机热点。

## Windows

从 <https://tailscale.com/download/windows> 或 Microsoft Store 安装 Tailscale client >= `v1.80.0`。首次使用自定义 login server 时，打开管理员 PowerShell：

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" version
& "$env:ProgramFiles\Tailscale\tailscale.exe" up --login-server https://hs.example.com --auth-key "<一次性 preauth key>" --accept-dns=true --hostname=laptop
& "$env:ProgramFiles\Tailscale\tailscale.exe" status
& "$env:ProgramFiles\Tailscale\tailscale.exe" ping peer-name.tailnet.example.com
& "$env:ProgramFiles\Tailscale\tailscale.exe" netcheck
```

也可以用 Tailscale GUI 的自定义 login server 流程，但仍需使用 Lanpanel UI 生成的一次性 preauth key。

日常断开和重新连接：

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" down
& "$env:ProgramFiles\Tailscale\tailscale.exe" up --login-server https://hs.example.com --accept-dns=true
```

## macOS

从 <https://tailscale.com/download/mac> 安装 Tailscale client >= `v1.80.0`。默认推荐 standalone package，也支持 Mac App Store 版本。

图形界面路径适用于已经登录过至少一个其它 tailnet 的客户端：点击菜单栏 Tailscale 图标，打开 Settings，进入 Accounts，选择左下角下拉箭头，填入 `server_url` 并添加账号。全新客户端直接使用 CLI：

```bash
sudo tailscale up \
  --login-server https://hs.example.com \
  --auth-key "<一次性 preauth key>" \
  --accept-dns=true

tailscale set --hostname=<name>
tailscale status
tailscale ping peer-name.tailnet.example.com
tailscale netcheck
```

日常断开和重新连接：

```bash
sudo tailscale down
sudo tailscale up --login-server https://hs.example.com --accept-dns=true
```

## Debian/Ubuntu Linux

安装 Tailscale client >= `v1.80.0`：

```bash
curl -fsSL https://tailscale.com/install.sh | sh
tailscale version
systemctl status tailscaled --no-pager --full
sudo tailscale up \
  --login-server https://hs.example.com \
  --auth-key "<一次性 preauth key>" \
  --accept-dns=true

tailscale set --hostname=<name>
tailscale status
tailscale ping peer-name.tailnet.example.com
tailscale netcheck
```

如果环境不允许 `curl | sh`，按 Tailscale 官方 Debian/Ubuntu 手动步骤安装，或使用运维提供的包文件。

日常断开和重新连接：

```bash
sudo tailscale down
sudo tailscale up --login-server https://hs.example.com --accept-dns=true
```

## DERP 和 netcheck

内置 DERP 不提供 `/generate_204`。不要只因为 captive portal 探测异常就判定部署失败。优先验证：

- 登录是否成功。
- `tailscale status`。
- MagicDNS。
- `tailscale ping`。
- `tailscale netcheck`。
- 可选 `tailscale debug derp-map`，应只看到自建 DERP region。

UDP 直连可用时应优先走 WireGuard 直连。UDP 被阻断时，只要互通正常，走 TCP/443 DERP 兜底是可接受的。

## 客户端排障

- preauth key 过期、已使用或绑定条件不匹配时，回到 UI Headscale Onboarding 为该客户端重新创建一个短期一次性 key。
- 确认客户端版本满足 Tailscale-compatible client >= `v1.80.0`。
- 确认客户端使用的是自建 `server_url`，不是 Tailscale.com 默认控制面。
- DNS 问题先看是否启用 `--accept-dns=true` 或平台 UI 等价设置，再验证 MagicDNS 后缀。
- Windows 常见问题是防火墙或终端安全软件阻断虚拟网卡。
- macOS 常见问题是未批准 VPN 提示，或 captive portal / 受限 Wi-Fi 影响登录。
- Linux 常见问题是 `tailscaled` 没有运行，或 `/dev/net/tun` 不存在。
- 自建内置 DERP 没有 `/generate_204`，不要把 captive portal 探测异常当成唯一失败依据。

## 安全边界

- Management UI 不暴露公网。
- Headscale 管理默认通过本机 unix socket，不开放远程 gRPC/API-key。
- DNS-01、EdgeOne、Tailscale auth key 和其它 secret 不写入配置正文、模板输出、job history 或文档示例。
- 业务 App 私有端口只监听 loopback 本机地址，或只作为 tailnet 固定 upstream 使用，不直接开放公网。
- 不手改 Lanpanel 生成的 Nginx、systemd、TLS、RealIP 运行文件。
- `public` App 与 EdgeOne origin protection 都需要显式人工确认。

## 排障信息收集

主部署失败时收集：

- 完整 `lanpanel deploy` 输出。
- `lanpanel verify --config lanpanel.yaml` 输出。
- `lanpanel status --config lanpanel.yaml` 输出。
- 修改过的 `default` 字段。
- Headscale source 模式、ACME 模式、DNS provider。
- `sudo nginx -t` 输出。
- `systemctl status headscale.service nginx.service --no-pager --full`。

客户端问题收集：

- 客户端 OS 和 Tailscale client 版本。
- `tailscale status`。
- `tailscale netcheck`。
- 失败的 `tailscale ping` 目标。
- 是否接受 DNS。
- 是否用了一次性 key，key 是否过期。
