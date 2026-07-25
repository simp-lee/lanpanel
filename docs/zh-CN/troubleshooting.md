# 常见问题和排障

失败时先看 Lanpanel 输出的失败命令、详细结果、next steps、retry command 和 modified paths。不要直接手改生成的 Nginx、systemd、TLS、RealIP 或 Headscale 运行文件；修正配置或宿主机条件后重新运行对应 UI Job 或 CLI deploy。

## 先看哪里

| 场景 | 首选入口 | 命令或页面 |
| --- | --- | --- |
| UI 操作失败 | `Jobs` | 查看 status、events、retry command、modified paths |
| 主部署失败 | `Settings` / CLI | `lanpanel verify --config lanpanel.yaml` |
| 主服务异常 | 服务器 | `sudo systemctl status headscale.service nginx.service --no-pager --full` |
| Nginx 异常 | 服务器 | `sudo nginx -t` |
| App 部署失败 | `Resources` / CLI | `lanpanel app verify --config lanpanel-apps/example-app.yaml` |
| 客户端连不上 | 客户端 | `tailscale status`、`tailscale netcheck`、`tailscale ping` |
| EdgeOne RealIP | 服务器 | `sudo lanpanel app realip diagnostics --config lanpanel-apps/example-app.yaml --profile edgeone-prod` |

## 常见现象

| 现象 | 常见原因 | 下一步 |
| --- | --- | --- |
| 打不开 Management UI | SSH tunnel 没建立、token 过期、URL 已用过一次 | 重启 `sudo lanpanel ui --listen 127.0.0.1:18080`，重新建立 `ssh -L`，打开新的 `Open once` URL |
| UI 拒绝监听地址 | 使用了 `0.0.0.0`、公网 IP、`::` 或 `localhost` | 改成 `127.0.0.1:18080` 或 `[::1]:18080` |
| Verify 报 DNS 错误 | 域名未解析到服务器、被 CDN/WAF/云接入层改写 | 修正 A/AAAA 记录；HTTP-01 环境不要让验证流量被中间层截断 |
| Deploy 证书失败 | `80/tcp` 不通、HTTP-01 被强制跳转或缓存拦截 | 放行 `80/tcp`，或改用 DNS-01 |
| Deploy 报端口冲突 | 机器上已有服务占用 `80/443/3478` 或 App 端口 | 按输出定位进程；修正冲突后重试 deploy |
| `curl -I https://hs.example.com` 失败 | DNS、证书、Nginx 或 Headscale 上游异常 | 看 `sudo nginx -t`、`systemctl status` 和 Job details |
| App 返回 502 | 业务服务没运行、没监听 `app.listen`、`exec_start` 错 | 检查 `systemctl status <app-name>.service` 和 `journalctl -u <app-name>.service -e` |
| App 域名打开的是别的站点 | Nginx `server_name` 冲突或 DNS 指错 | 检查 App 域名解析、Nginx site 和 Lanpanel modified paths |
| Browser Auth 密码找不到 | 明文密码只在一次性交接窗口展示 | 重新在 UI 里 rotate 托管凭据 |
| GoAccess 页面打不开 | htpasswd、locale、access log 或 service 异常 | 检查 `<app-name>-goaccess.service`、`locale -a` 和 canonical access log |
| `upstream` App 访问失败 | 云服务器上的 Tailscale client 不能访问固定 upstream | 在云服务器运行 `tailscale status` 和 `curl -I http://<app.upstream>` |
| 客户端登录失败 | preauth key 过期、已使用或绑定条件不匹配 | 回到 UI `Headscale Onboarding` 为该客户端重新创建短期一次性 key |
| MagicDNS 不通 | 客户端没有接受 DNS | 使用 `--accept-dns=true` 或平台 UI 等价设置 |
| `tailscale netcheck` 有 captive portal 异常 | 自建内置 DERP 没有 `/generate_204` | 不要只凭这个判断失败；继续验证登录、status、ping 和实际互通 |
| EdgeOne 直连被拒绝 | 源站边界或 OriginACL current+next CIDR 未对齐 | 运行 RealIP diagnostics，按输出维护云安全组、主机防火墙或等价边界 |

## 主部署排障顺序

```bash
lanpanel verify --config lanpanel.yaml
lanpanel status --config lanpanel.yaml
sudo nginx -t
sudo systemctl status headscale.service nginx.service --no-pager --full
sudo journalctl -u headscale.service -e
sudo ss -lntup
```

重点检查：

- `default.server_url` 是否是公网 HTTPS URL，并且 DNS 指向目标服务器。
- `default.base_domain` 是否没有等于 Headscale 主机名，也不是 Headscale 主机名的父域。
- `default.certificate_email` 是否是有效邮箱。
- `default.acme_challenge` 是否与实际网络条件匹配。
- Headscale 是否监听 `127.0.0.1:8080`。
- metrics 是否监听 `127.0.0.1:<advanced.headscale.metrics_port>`，默认端口是 `19090`。
- gRPC 是否监听 `127.0.0.1:50443`。
- STUN 是否监听 `3478/udp`。

## App 排障顺序

```bash
lanpanel app verify --config lanpanel-apps/example-app.yaml
sudo nginx -t
curl -I https://app.example.com
systemctl status <app-name>.service --no-pager --full
journalctl -u <app-name>.service -e
```

重点检查：

- `app.domains` 都解析到当前云服务器，且不要复用主 Headscale `server_url` 主机名。
- 公网只通过 Nginx 开放 `80/tcp` 和 `443/tcp`，不开放 `18001` 这类 App 端口。
- `service.exec_start` 第一个 token 是否是已存在、可执行的绝对路径。
- `listen` App 是否真的监听配置里的 loopback 本机地址。
- `upstream` App 是否能从云服务器访问固定 HTTP/WebSocket upstream。

## 客户端排障顺序

```bash
tailscale version
tailscale status
tailscale ping peer-name.tailnet.example.com
tailscale netcheck
```

重点检查：

- 客户端版本满足 Tailscale-compatible client >= v1.80.0。
- 客户端使用的是自建 `server_url`，不是 Tailscale.com 默认控制面。
- 该客户端使用的是新创建的短期一次性 preauth key。
- DNS 问题先看是否启用 `--accept-dns=true` 或平台 UI 等价设置。
- Windows 常见问题是防火墙或终端安全软件阻断虚拟网卡。
- macOS 常见问题是未批准 VPN 提示，或 captive portal / 受限 Wi-Fi 影响登录。
- Linux 常见问题是 `tailscaled` 没有运行，或 `/dev/net/tun` 不存在。

## 收集信息

主部署失败时收集：

- 完整 `lanpanel deploy` 输出。
- `lanpanel verify --config lanpanel.yaml` 输出。
- `lanpanel status --config lanpanel.yaml` 输出。
- 修改过的 `default` 字段。
- Headscale source 模式、ACME 模式、DNS provider。
- `sudo nginx -t` 输出。
- `systemctl status headscale.service nginx.service --no-pager --full`。

App 问题收集：

- 完整 `lanpanel app deploy` 输出。
- `lanpanel app verify --config lanpanel-apps/example-app.yaml` 输出。
- App 配置中 `app`、`access`、`service`、`tailscale`、`nginx` 的非敏感字段。
- `sudo nginx -t` 输出。
- `systemctl status <app-name>.service --no-pager --full`。

客户端问题收集：

- 客户端 OS 和 Tailscale client 版本。
- `tailscale status`。
- `tailscale netcheck`。
- 失败的 `tailscale ping` 目标。
- 是否接受 DNS。
- 是否用了一次性 key，key 是否过期。

不要提交 DNS token、EdgeOne secret、Tailscale auth key、preauth key、browser password 或 htpasswd 内容。

