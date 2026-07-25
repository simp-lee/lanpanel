# 核心概念

这篇文档用普通语言解释 Lanpanel 文档里反复出现的词。第一次阅读时不需要记住所有细节，只要知道它们分别负责什么。

## Lanpanel

Lanpanel 是一个面向单台 Debian/Ubuntu 服务器的私有网络和应用发布工具，不是 VPN 客户端。它可以部署 Headscale、Nginx、HTTPS 证书续期和 systemd 服务，也可以只把同机 Go Web 服务或 tailnet 内 HTTP/WebSocket 服务发布到公网 HTTPS。

## Headscale

Headscale 是自建的 Tailscale 控制面。客户端用它登录你的私有网络，而不是登录 Tailscale.com 默认控制面。

Lanpanel 主部署会让 Headscale 控制面、metrics、gRPC 和管理 socket 留在服务器本机边界内；公网只应该看到 Nginx 的 `80/tcp`、`443/tcp` 和 Headscale STUN 的 `3478/udp`。

## Tailscale client

Tailscale client 是安装在 Windows、macOS、Linux 等设备上的客户端程序。Lanpanel 要求 Tailscale-compatible client >= v1.80.0。

客户端加入自建网络时要使用：

```bash
tailscale up --login-server https://hs.example.com --auth-key "<一次性 preauth key>" --accept-dns=true
```

## tailnet

tailnet 指你的私有网络。加入同一个自建 Headscale 的设备可以通过私有地址互相访问。客户端之间优先 WireGuard 直连，直连失败时通过 DERP 兜底。

## server_url

`server_url` 是客户端登录 Headscale 的 HTTPS 地址，例如 `https://hs.example.com`。

要求：

- 必须是 HTTPS DNS 域名。
- 只能省略端口或使用 `443`。
- DNS 应指向部署 Lanpanel 的服务器。

## base_domain 和 MagicDNS

`base_domain` 是私有网络里的 MagicDNS 后缀，例如 `tailnet.example.com`。客户端开启 `--accept-dns=true` 后，可以用类似 `peer-name.tailnet.example.com` 的名字访问其它节点。

`base_domain` 不能等于 `server_url` 主机名，也不能是它的父域。

## preauth key

preauth key 是客户端加入私有网络的一次性入网钥匙。Lanpanel 通过 UI 的 `Headscale Onboarding` 创建短期一次性 key。

每台客户端都应创建新的短期 key。不要复用。明文 key 只在当前浏览器会话的一次性交接区展示，不写入任务历史、诊断输出、工作流输出或保存结果。

## Nginx gateway

Nginx 是公网 HTTPS 入口。Lanpanel 生成 Nginx 配置，把公网 `80/tcp` 和 `443/tcp` 的请求转发给 Headscale 或 App。

业务 App 私有端口不要直接暴露公网；公网只进 Nginx `80/443`。

## ACME、HTTP-01 和 DNS-01

ACME 是自动申请 HTTPS 证书的协议。Lanpanel 使用固定 lego v5.2.2 管理证书。

| 方式 | 适合 | 新手建议 |
| --- | --- | --- |
| HTTP-01 | 公网 `80/tcp` 可以直连服务器 | 优先使用 |
| DNS-01 | 公网 80 不可靠、被接入层拦截，或组织策略要求 DNS 验证 | 需要 DNS provider 凭据 |

DNS-01、EdgeOne、Tailscale 等密钥文件必须 root-owned、root-only，并通过 `_FILE` 或显式路径引用。

## listen App

`listen` 表示业务服务就在这台服务器上，例如监听 `127.0.0.1:18001`。公网用户访问业务域名时只进入 Nginx，Nginx 再反代到本机 App。

只部署同机 `listen` App 时可以没有主 `lanpanel.yaml`。

## upstream App

`upstream` 表示业务服务在 tailnet 里的另一台机器上，例如 `100.64.10.20:18001`。公网仍然只进入云服务器 Nginx，云服务器通过本机 Tailscale client 访问这个固定 HTTP/WebSocket upstream。

`upstream` 只适合 HTTP/WebSocket 服务，不用于 PostgreSQL、MySQL、Redis 等数据库或中间件端口公网发布。需要访问数据库时，让客户端加入私有网络后直接连接 tailnet 地址。

## Browser Auth

`access_mode: "browser"` 会在 App gateway 层启用 Basic Auth，也就是先让浏览器访问者输入用户名和密码。Browser Auth 与 GoAccess dashboard Auth 是两套凭据，不能复用。

Browser Auth 会在代理到业务服务前清除入站 `Authorization` header。

## GoAccess

GoAccess 是可选的访问日志看板。启用后 Lanpanel 会生成 GoAccess service、实时 HTML 报表、WebSocket 反代、状态持久化和必要的 logrotate。看板使用独立 Basic Auth，不是免密公网 dashboard。

## EdgeOne RealIP

EdgeOne RealIP 用于通过腾讯云 EdgeOne 回源时还原真实客户端 IP。Lanpanel 会读取 EdgeOne OriginACL，渲染 App site scoped `set_real_ip_from` 与真实 IP header 设置，并拒绝非可信直连。

云安全组、主机防火墙或等价边界仍需要操作者手动保持 current+next CIDR 对齐。Lanpanel 不调用 `ConfirmOriginACLUpdate`，不修改 EdgeOne 站点、DNS 或证书配置。

