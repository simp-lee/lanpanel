# LanPanel

[English](https://github.com/simp-lee/lanpanel/blob/main/README.md) | [简体中文](https://github.com/simp-lee/lanpanel/blob/main/README.zh-CN.md)

LanPanel 是一个面向个人和相互信任小团队的自托管 Linux 主机管理工具。它通过浏览器管理应用进程、网络入口和可选的可信网络；不会上传、构建或修改你的应用代码。

> **当前状态：Preview。** 适合试用和验证，不代表正式版、高可用或完整生产资格。

## 是否适合你

| 你的目标 | 是否适合 |
| --- | --- |
| 在一台 Linux 主机上通过浏览器管理应用和网络入口 | 适合 |
| 使用官方 Tailscale 客户端加入私有可信网络 | 适合，LanPanel 可以管理可选的 Headscale 控制面；LanPanel 本身不是 VPN 客户端 |
| 在一台主机上配置 Headscale、Nginx、证书和服务生命周期 | 适合，这是可信网络场景的主要用途 |
| 把本机 HTTP/WebSocket 应用发布为 HTTPS | 适合，使用 `local_http` |
| 把可信网络内固定节点的 HTTP/WebSocket 服务发布到公网 | 适合，使用 `tailnet_http` 和已验证的 Tailscale 连接器 |
| 只发布本机应用，不创建 Headscale 网络 | 适合，使用不依赖 Headscale 或 Tailscale 的 `local_http` |
| 直接获得服务器终端、文件管理器、通用管理 CLI 或通用 VPN 客户端 | 不适合，日常管理只通过 Management UI |
| 多机高可用、容器/Kubernetes、数据库托管、OIDC/RBAC 或公网 TCP/UDP 转发 | 不适合，当前版本不包含这些能力 |

## 快速开始

### 1. 准备主机

目前支持 Debian 或 Ubuntu Linux 的 amd64（x86_64）主机，并要求：

- 使用 `systemd`、cgroup v2 和 `apt/dpkg`；
- 具备 root 或可用的 `sudo` 权限；
- APT 镜像启用签名校验，软件包状态正常；
- 有足够的磁盘空间和可用端口。

安装器会在修改主机前检查系统、软件包、端口、文件系统和 Nginx 配置。其他发行版、ARM64 和未通过检查的主机不受支持；未知的未来 Debian/Ubuntu 版本只有在全部检查通过后才会继续。

安装不要求提前执行 ACME 或 DNS 操作。只有在之后发布域名 HTTPS 应用时，才需要准备域名、DNS 和对应的 80/443 网络访问条件。

根据计划使用的能力准备额外条件：

| 场景 | 额外准备 |
| --- | --- |
| 只使用管理界面，或只管理不发布域名的本机应用 | 初次安装不需要 Headscale 或公网 DNS |
| 发布域名 HTTPS 应用 | 准备解析到入口的公网域名，并确保 80/443 可达；ACME 联系方式稍后在 UI 中设置 |
| 使用 Headscale 可信网络 | 准备公网控制域名、可达的 80/443，以及用于 STUN 的 `3478/udp`；客户端使用官方 Tailscale 客户端加入 |
| 发布 tailnet 应用 | 准备已验证的本机 Tailscale 连接器，以及可信网络内固定的 HTTP/WebSocket upstream |

### 2. 安装

从 [GitHub Releases](https://github.com/simp-lee/lanpanel/releases) 下载并解压与主机匹配的 Preview 包，在包目录执行：

```sh
sudo ./lanpanel install
```

这是唯一公开的安装入口。不要自行传入 bundle 路径、摘要、软件包计划、依赖路径或 ACME 联系方式。安装器会自动发现发布材料并校验清单、签名、完整校验和、固定第三方依赖及主机条件；校验失败时不会继续修改主机。

也可以使用官方发布页提供的版本固定 Bootstrap。把 `<tag>` 换成实际的 Preview 标签，不要使用 `latest`：

```sh
curl -fL https://github.com/simp-lee/lanpanel/releases/download/<tag>/lanpanel-bootstrap.sh \
  -o /tmp/lanpanel-bootstrap.sh &&
sudo /tmp/lanpanel-bootstrap.sh install
```

Bootstrap 会在受保护的临时目录中验证发布包 SHA-256，然后调用同一个 `install` 流程；不会把下载内容直接交给 Shell，也没有第三方下载源回退。系统软件包使用主机自己的、启用签名校验的 APT 镜像，请不要关闭仓库签名检查或使用 `--allow-unauthenticated`。

### 3. 打开管理界面

安装器会显示本次安装专用的 `127/8` 地址和高位端口，并创建管理员令牌：有 TTY 时显示一次；无 TTY 时只显示受 root 保护的令牌文件路径，请按提示保存。

Management UI 只监听本机回环地址，不会直接暴露到公网。远程管理时，使用 SSH 隧道连接安装器显示的**准确地址和端口**，不能用 `localhost` 替代：

```sh
ssh -N -L 8080:<安装器显示的地址>:<安装器显示的端口> <用户>@<主机>
```

然后在本机浏览器打开 `http://127.0.0.1:8080`。日常应用管理没有 CLI、终端、Shell 或文件管理器；UI 进程不以 root 运行，需要特权的操作会经过受保护的 typed helper。

## 日常使用

- **应用**：`local_http` 管理本机受限的非 root HTTP/WebSocket 进程；`tailnet_http` 访问经 Tailscale 路由验证的固定远端节点。LanPanel 不负责上传、构建、安装或编辑应用代码。
- **发布**：`domain_https` 使用 80/443 提供 HTTPS；仅用于测试的 `temporary_ip_http` 使用公网明文 HTTP 和高位端口，不会自动过期。
- **访问控制**：支持匿名（`public`）、由应用处理认证（`application_managed`）和 Basic 认证（`basic`）。Basic 可使用一次性托管密码或外部 `htpasswd`，并可配置 CIDR 限制。
- **静态内容与日志**：支持指定外部静态目录；可选 GoAccess，但它使用独立的访问凭据，不提供原始日志浏览器。
- **可信网络**：Headscale 可选，最多管理一个包含 MagicDNS 和内置 DERP/STUN 的可信网络域；可管理用户、一次性预授权密钥和设备。客户端仍使用 Windows、macOS 或 Debian/Ubuntu Linux 上的官方 Tailscale 客户端；Tailscale 连接器最多管理一个实例。

`publish` 是唯一会正常开放或替换应用入口的操作。保存配置、启动进程、连接器登录、重启和后台协调都不会自动开放入口。`unpublish` 和 `close-all` 会持久关闭入口；但关闭发布、设备过期或撤销预授权密钥，都不保证立即终止已经建立的网络连接。

域名 HTTPS 使用 HTTP-01，或使用 Cloudflare、Route53、DigitalOcean、Google Cloud、Tencent Cloud 的 DNS-01。使用 DNS-01 时，在 Management UI 的 provider 字段中填写准确的代码：`cloudflare`、`route53`、`digitalocean`、`gcloud` 或 `tencentcloud`。ACME 联系方式在登录后的 Management UI 中设置，首次申请证书前会再次校验；安装阶段不会要求输入，也不会把它写进命令行或日志。

## 运行拓扑

LanPanel 是管理层，不是 Tailscale 客户端。下面的图示说明了流量的基本路径：

### Management UI

```text
你的浏览器
    | SSH 隧道连接安装器显示的准确地址和端口
    v
Management UI（仅回环监听，非 root）
    | 受保护的 typed helper
    v
LanPanel 管理的服务和状态
```

### 本机应用

```text
公网用户
    | HTTP/HTTPS :80/:443
    v
Nginx（TLS、Host/SNI 和访问控制）
    | 受保护的本机目标
    v
这台主机上的非 root 应用进程
```

应用端口不会直接暴露到公网。`domain_https` 是正常的 HTTPS 发布方式；`temporary_ip_http` 仅用于测试，使用高位端口和明文 HTTP。

### Tailnet 应用与 Headscale

```text
公网用户 -- HTTP/HTTPS :80/:443 --> Nginx -- 本机应用或 Tailscale 连接器 --> 固定对端

Tailscale 客户端 -- HTTPS :443 --> Nginx --> Headscale 控制面
Tailscale 客户端 -- HTTPS :443 --> Nginx --> 内置 DERP（对端无法直连时）
Tailscale 客户端 -- UDP :3478 ---------------------------> Headscale STUN
```

Headscale 和 Tailscale 连接器都是可选的。没有它们时，本机应用仍可通过 Nginx 发布；启用后，客户端使用官方 Tailscale 客户端，连接器只访问经过验证的固定 upstream。

## 加入可信网络（可选）

本节仅适用于启用了 Headscale 的场景。LanPanel 不是 VPN 客户端；客户端使用 `1.74.0` 或更新版本的官方 Tailscale 客户端。

平台差异是有意保留的：Windows 使用安装后的 PowerShell 可执行文件，macOS 可以使用菜单栏应用或其自带 CLI，Debian/Ubuntu 使用 `tailscaled` 系统服务，特权命令通过 `sudo` 执行。

在客户端加入前，先在 Management UI 中完成以下两步：

1. 使用控制域名和 MagicDNS 命名空间初始化 Headscale identity。初始化后，这些 identity 不能修改或删除。
2. 部署 Headscale control ingress：选择 HTTP-01 或 DNS-01，填写 ACME directory URL 和联系方式，确认 ACME 条款；选择 DNS-01 时还要填写 DNS provider profile 和 zone。等待该操作成功完成。

对每台客户端执行以下步骤：

1. 在 Management UI 中创建用户和一次性预授权密钥。密钥只显示一次；请为每台设备单独创建短期密钥。
2. 按客户端平台安装官方 Tailscale 客户端。
3. 将下面命令中的 `hs.example.com` 和 `<preauth-key>` 换成实际值，然后使用控制域名加入并启用托管 DNS。

#### Windows PowerShell

从 <https://tailscale.com/download/windows> 安装 `1.74.0` 或更新版本的 Tailscale。较新的 Windows 系统也可以使用 WinGet；自定义 login-server 命令请在管理员 PowerShell 中执行：

```powershell
winget install --id Tailscale.Tailscale --exact
```

然后执行：

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" version
& "$env:ProgramFiles\Tailscale\tailscale.exe" up --login-server https://hs.example.com --auth-key "<preauth-key>" --accept-dns=true --hostname=laptop
& "$env:ProgramFiles\Tailscale\tailscale.exe" status
& "$env:ProgramFiles\Tailscale\tailscale.exe" ping peer-name.tailnet.example.com
& "$env:ProgramFiles\Tailscale\tailscale.exe" netcheck
```

以后离开网络或重新连接时执行：

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" down
& "$env:ProgramFiles\Tailscale\tailscale.exe" up --login-server https://hs.example.com --accept-dns=true
```

#### macOS

从 <https://tailscale.com/download/mac> 安装 `1.74.0` 或更新版本的 Tailscale。通常选择 standalone app，它可以在 **Settings → CLI integration** 中加入 `tailscale` 命令。下面的命令使用 Mac App Store 版本自带的 CLI：

```sh
TAILSCALE="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
"$TAILSCALE" version
"$TAILSCALE" up --login-server https://hs.example.com --auth-key "<preauth-key>" --accept-dns=true --hostname=laptop
"$TAILSCALE" set --hostname="laptop"
"$TAILSCALE" status
"$TAILSCALE" ping peer-name.tailnet.example.com
"$TAILSCALE" netcheck
```

以后离开网络或重新连接时执行（下面代码块可以单独复制）：

```sh
TAILSCALE="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
"$TAILSCALE" down
"$TAILSCALE" up --login-server https://hs.example.com --accept-dns=true
```

也可以直接在 Tailscale 菜单栏应用中完成同样的登录。standalone app 启用 CLI integration 后，可把 `"$TAILSCALE"` 替换成 `tailscale`。

#### Debian/Ubuntu Linux

从官方 Linux 软件源安装 `1.74.0` 或更新版本的 Tailscale，并检查 `tailscaled` 系统服务：

```bash
curl -fsSL https://tailscale.com/install.sh | sh
tailscale version
systemctl status tailscaled --no-pager --full
sudo tailscale up --login-server https://hs.example.com --auth-key "<preauth-key>" --accept-dns=true --hostname=laptop
sudo tailscale set --hostname="laptop"
tailscale status
tailscale ping peer-name.tailnet.example.com
tailscale netcheck
```

以后离开网络或重新连接时执行：

```bash
sudo tailscale down
sudo tailscale up --login-server https://hs.example.com --accept-dns=true
```

4. 在 Management UI 中确认设备已经出现，然后使用 `tailscale status`、`tailscale ping <对端>` 和 `tailscale netcheck` 验证连通性。

Headscale 控制域名通过 Nginx 提供 HTTPS；对端无法直连时，内置 DERP 会通过 HTTPS 路径转发，STUN 使用 `3478/udp`。设备过期或撤销密钥不保证立即终止已经建立的连接。

如果要发布 `tailnet_http` 应用，控制面准备好后，在 Management UI 中配置本机连接器：将 binding 设置为 Headscale 控制 URL，使用单独的一次性预授权密钥登录，然后执行连接器验证。固定可信网络 upstream 发布前，连接器必须先验证通过。

## 卸载与数据迁出

已完成安装后，唯一公开的卸载入口是：

```sh
sudo lanpanel uninstall
```

卸载前会显示将删除的 LanPanel 管理范围，并要求交互式输入 `UNINSTALL LANPANEL`。卸载只删除能够确认归 LanPanel 所有的文件、服务、账号和状态，不删除 APT/dpkg 软件包，也不删除外部应用的可执行文件、工作目录、静态目录、环境文件、`htpasswd` 或日志源。

需要迁出产品配置时，可使用无密钥的配置导出；这不等同于产品级备份。不支持产品级备份/恢复、恢复切换或跨主机迁移。手工复制主机或 VM 快照也不会自动成为受支持且可恢复的备份。

## Preview 限制

- 仅支持全新安装；不支持原地升级、同版本重装、依赖维护、更新器、回滚、状态迁移或跨主机迁移。
- 不提供 Repair、主机修复、孤儿状态接管或自动规范化。
- 不提供 EdgeOne 集成、公网 TCP/UDP 发布、SSH/RDP/VNC、容器、Kubernetes、数据库、应用模板、远程 API、OIDC 或 RBAC。
- 不提供连接器断开、注销、重置、重新加入或重新绑定自动化；连接器不匹配必须在 LanPanel 外解决。
- 未提供独立远端权威时，Tailnet HTTP/WebSocket 仅按“未经过实时测试”处理。
- Preview 不声称 hardened GA、完整审计、实时资格验证或完整可复现发布保证。
- 撤销密钥不会使已注册设备过期。
- 证书、远端路由或入口激活不确定时，系统会优先关闭入口而不是盲目重试；失效关闭 Nginx 可能同时中断 Headscale 控制入口。

## 开发者

开发、测试和 Preview 发布流程见[开发文档](https://github.com/simp-lee/lanpanel/blob/main/docs/DEVELOPING.md)。

## 许可证

LanPanel 使用 MIT License，详见 `LICENSE`。
