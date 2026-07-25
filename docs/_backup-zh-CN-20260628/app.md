# 发布业务服务 App

Lanpanel App 发布流程用来把业务 HTTP/WebSocket 服务发布到公网 HTTPS。它既可以通过 UI 操作，也可以用 CLI 自动化；两条路径使用同一份 `lanpanel-app.yaml`、同一套验证和部署逻辑。

新手先记住一句话：业务服务如果就在这台服务器上，选 `listen`；业务服务如果在 tailnet 里的另一台机器上，选 `upstream`。不确定时先从 `listen` 开始。

## 选择入口

优先使用 UI：

- 第一次发布 App。
- 需要人工编辑配置、预览暴露面、处理 Browser Auth、查看 Jobs。
- 想在浏览器里完成 App deploy、RealIP refresh、GoAccess 配置检查。
- 需要一次性展示托管 browser password。

优先使用 CLI：

- CI/CD 或脚本化部署。
- 无浏览器环境。
- 想拿 `--format json` 给上层系统解析。
- 需要在 SSH session 中精确复现失败命令。

## 两种发布模式

| 模式 | 适用场景 | 准备内容 |
| --- | --- | --- |
| `listen` | 业务 Go 服务运行在同一台云服务器上 | 业务二进制已安装，`service.exec_start` 第一个 token 是绝对可执行路径，服务监听 loopback |
| `upstream` | 业务服务在 tailnet 其它节点，例如 `100.64.10.20:18001` | 云服务器上的 Tailscale client 能访问固定 HTTP/WebSocket upstream |

`listen` 和 `upstream` 必须二选一。`upstream` 自动要求 Tailscale client；`listen` 只有在业务服务主动访问 tailnet 时才设置 `tailscale.enabled_for_listen: true`。

App 端口不要开放公网。公网入口是 Nginx 的 `80/tcp` 和 `443/tcp`。

只部署同机 `listen` App 时可以没有主 `lanpanel.yaml`；保持 `upstream: ""` 且不要启用 `tailscale.enabled_for_listen`，Lanpanel 只管理本机 App、Nginx、证书和 systemd，不会要求你先部署 Headscale 私有网络。

配置文件名不是部署身份；真正的部署身份来自 `app.name`。重命名配置文件不会重命名 systemd unit、Nginx 站点或证书目录。

推荐一个 App 一个配置文件，并统一放在 `lanpanel-apps/` 目录：

```text
lanpanel.yaml
lanpanel-apps/abc.yaml
lanpanel-apps/admin.yaml
lanpanel-apps/tailapp.yaml
```

多个域名写在同一个 `app.domains` 列表中。它们会进入同一个 Nginx `server_name`、同一张证书 SAN，以及 Host/SNI allowlist。当前版本不会自动做 `abc.com` 和 `www.abc.com` 之间的 canonical redirect；它们默认服务同一个 App。

`upstream` 只适合 HTTP/WebSocket 服务，不用于 PostgreSQL、MySQL、Redis 等数据库或中间件端口公网发布；需要访问时，让客户端加入私有网络后直接连接 tailnet 地址，例如 `PostgreSQL: 100.64.10.40:5432`、`MySQL: 100.64.10.50:3306`、`Redis: 100.64.10.60:6379`。

## App 运行拓扑

`listen` 模式用于业务服务就在这台服务器上的场景。App 自己只监听 loopback 本机地址，公网只进入 Nginx。

```text
Internet
  |
  | app domain: 80/tcp, 443/tcp
  v
+------------------------------------------------+
| Debian/Ubuntu server                           |
|                                                |
| Nginx app site                                 |
|   - app certificate and Host/SNI allowlist     |
|   - optional Browser Auth and CIDR allowlist   |
|   - optional static alias locations            |
|   - proxies / to 127.0.0.1:18001               |
|                                                |
| Optional GoAccess dashboard                    |
|   - reads the canonical Nginx access log       |
|   - serves report.html through Nginx           |
|   - live updates over loopback WebSocket       |
|   - optional managed logrotate                 |
|                                                |
| example-app.service                            |
|   - runs ExecStart from service.exec_start     |
|   - runs as the app.name system user/group     |
|   - listens on loopback only                   |
+------------------------------------------------+
```

只部署同机 Go 服务时，上图就是完整拓扑：不需要先部署 Headscale，也不需要 Tailscale client。

`upstream` 模式用于后端服务在 tailnet 另一台机器上的场景。公网仍然只进入这台云服务器的 Nginx，但 Nginx 通过本机 Tailscale client 访问固定 `100.64.x.y:port` upstream。

```text
Internet
  |
  | app domain: 80/tcp, 443/tcp
  v
+------------------------------------------------+
| Debian/Ubuntu server                           |
|                                                |
| Nginx app site                                 |
|   - app certificate and Host/SNI allowlist     |
|   - optional Browser Auth and CIDR allowlist   |
|   - proxies / to fixed tailnet upstream        |
|                                                |
| Tailscale client on this server                |
|   - logged in to the expected login server     |
|   - reaches fixed 100.64.x.y:port upstream     |
+------------------------------------------------+
  |
  | tailnet HTTP/WebSocket
  v
100.64.x.y:port on another tailnet node
```

## UI 路径

这是新手推荐路径。

1. 启动 UI：

   ```bash
   sudo lanpanel ui --listen 127.0.0.1:18080
   ```

   `--app-config` 不是必需参数。省略时 UI 使用默认 App 配置路径 `lanpanel-app.yaml`；在 `Resources` 页面点击 `Create Example App Config` 会把示例配置写到这个路径。只有想把当前 UI 操作绑定到指定文件时才需要传入，例如：

   ```bash
   sudo lanpanel ui --listen 127.0.0.1:18080 --app-config lanpanel-apps/example-app.yaml
   ```

2. 打开 `Resources`。
3. 没有配置时点击 `Create Example App Config`，UI 会在当前 App config path 生成配置文件。
4. 编辑 `Resource`：
   - `App name`
   - `Domains`
   - `Certificate email`
   - `ACME challenge`
   - `Target mode`
   - `Listen` 或 `Tailnet upstream`
5. 编辑 `Access`：
   - `browser` 或 `public`
   - public 风险确认
   - CIDR allowlist
   - Browser Auth 外部文件或托管 metadata
6. 需要 EdgeOne 时编辑 `Origin protection` 和 RealIP profile。
7. 需要 GoAccess 时编辑 `Nginx and observability`。
8. 点击 `Preview Exposure`。
9. 点击 `Verify`。
10. 点击 `Deploy`。EdgeOne 相关会修改源站入口的操作需要勾选 `origin-protection-manual`。

UI Deploy 会写入任务历史。失败时优先看 `Jobs` 中的 retry command 和详细结果。

## CLI 路径

创建示例配置：

```bash
lanpanel app init --config lanpanel-apps/example-app.yaml
```

编辑后验证：

```bash
lanpanel app verify --config lanpanel-apps/example-app.yaml
```

验证通过时 human/json 输出状态为 `static-passed`。这只是静态配置和模板检查，不读取已部署宿主机运行状态。

部署：

```bash
sudo lanpanel app deploy --config lanpanel-apps/example-app.yaml
```

EdgeOne origin protection 或 RealIP 相关会修改源站入口的操作需要显式确认：

```bash
sudo lanpanel app deploy \
  --config lanpanel-apps/example-app.yaml \
  --confirmation origin-protection-manual
```

需要机器可读输出时：

```bash
lanpanel app verify --config lanpanel-apps/example-app.yaml --format json
```

App 流程没有 `lanpanel app status`。主 `lanpanel status` 只读取主部署 checkpoint、activation history 和上次可恢复失败。

## 最小 listen 配置

```yaml
api_version: lanpanel/app/v1alpha2

app:
  name: "example-app"
  domains:
    - "abc.com"
    - "www.abc.com"
  certificate_email: "ops@example.com"
  acme_challenge: "http-01"
  listen: "127.0.0.1:18001"
  upstream: ""

service:
  exec_start: "/opt/example-app/example-app --listen 127.0.0.1:18001"
  working_directory: "/opt/example-app"
  env_file: ""

access:
  access_mode: "public"
  public_risk_confirmed: true
  browser_auth:
    auth_basic_user_file: ""
    managed: {}
  cidr_allowlist: []
  origin_protection:
    mode: "none"
    edgeone_profile: ""
    direct_origin_risk_confirmed: true

tailscale:
  enabled_for_listen: false
```

`service.env_file` 只在 `listen` 模式使用；它必须是 root-owned、root-only 的绝对路径文件。

## 最小 upstream 配置

```yaml
api_version: lanpanel/app/v1alpha2

app:
  name: "tailapp"
  domains:
    - "tailapp.example.com"
  certificate_email: "ops@example.com"
  acme_challenge: "http-01"
  listen: ""
  upstream: "100.64.10.20:18001"

service:
  exec_start: ""
  working_directory: ""
  env_file: ""

access:
  access_mode: "public"
  public_risk_confirmed: true
  browser_auth:
    auth_basic_user_file: ""
    managed: {}
  cidr_allowlist: []
  origin_protection:
    mode: "none"
    edgeone_profile: ""
    direct_origin_risk_confirmed: true

tailscale:
  login_server: "https://hs.example.com"
  auth_key_file: "/etc/lanpanel/tailscale/app-auth-key"
```

如果 `tailscale.login_server` 为空，Lanpanel 会从 `tailscale.lanpanel_config` 读取 `default.server_url`；如果 `tailscale.lanpanel_config` 也为空，默认读取当前工作目录下的 `./lanpanel.yaml`。主配置不在当前目录时要显式设置。

自动登录 Tailscale 时会附加 `--accept-dns=false --accept-routes=false --shields-up`。如果当前机器已登录到无法证明匹配的 login server，deploy 会失败，不会自动 logout、清状态或重入网。

## 访问模式

### public

`access_mode: "public"` 表示 App 直接对公网用户开放。配置必须显式设置：

```yaml
access:
  access_mode: "public"
  public_risk_confirmed: true
  origin_protection:
    mode: "none"
    direct_origin_risk_confirmed: true
```

这不是安全默认值，只适合你明确接受公网访问风险的 App。

### browser

`access_mode: "browser"` 表示 Nginx App gateway 层启用 Basic Auth，也就是先让浏览器访问者输入用户名和密码。Browser Auth 会保护反代和静态文件 location，请求通过后才到业务 App。

只能选择一种凭据来源：

| 来源 | 配置 | 说明 |
| --- | --- | --- |
| 外部 htpasswd | `access.browser_auth.auth_basic_user_file` | 你自己创建和维护，必须是 app gateway 凭据 |
| Lanpanel 托管 | `access.browser_auth.managed` | 用 UI 创建或轮换，文件在 `/etc/lanpanel/browser-auth` |

Browser Auth 与 GoAccess dashboard Auth 是分开的。不要复用 `nginx.goaccess.auth_basic_user_file`。

`browser` 模式会清除上游 `Authorization` header。需要业务层 `Authorization` 的 App 应走显式 `public` 风险路径，或等后续 upstream auth 设计。

使用 Lanpanel 托管凭据时，明文密码只在一次性交接窗口展示；配置和任务历史只保存 metadata 与 `password_fingerprint`。

## Nginx 和静态文件

以下是进阶配置。第一次只发布普通 HTTP App 时，可以先跳过本节和后面的 GoAccess、EdgeOne RealIP。

默认 `nginx.http2: false`，首次部署不会要求现代 HTTP/2 指令支持。只有改成 `true` 时才会渲染 `http2 on;`；目标 Nginx 必须至少 `1.25.1` 且包含 `http_v2` 模块。

常用字段：

| 字段 | 说明 |
| --- | --- |
| `nginx.client_max_body_size` | 默认 `20m` |
| `proxy.read_timeout` | 默认 `600s`，适合长连接/SSE 时调整 |
| `proxy.send_timeout` | 默认 `600s` |
| `proxy.buffering` / `proxy.request_buffering` | 流式响应或上传转发时使用 |
| `nginx.static_locations` | 在反代前暴露静态文件或目录 |

静态 location 支持 `default_type`、`expires`、`cache_control`、`try_files`、`gzip_static` 和 `access_log`。`expires` 会影响 `Cache-Control` 响应头；建议同一 location 只设置 `expires` 或 `cache_control` 之一。如果两者都设置，Lanpanel 会同时渲染两个指令。

Lanpanel 不复制静态文件，静态内容应由业务发布流程放到 release 路径。

## GoAccess 看板

`nginx.goaccess` 默认关闭。启用后会生成：

- GoAccess 配置。
- `<app-name>-goaccess.service`。
- `/var/lib/<app-name>/goaccess/report.html`。
- `persist true` 和 `restore true`。
- GoAccess `db-path` `/var/lib/<app-name>/goaccess/db`。
- loopback WebSocket 反代。
- `nginx.goaccess.websocket_path` 对应的实时更新通道。
- 使用托管 access log 时的 `logrotate`。

示例：

```yaml
nginx:
  access_log: ""
  error_log: "/var/log/nginx/example-app.error.log"
  goaccess:
    enabled: true
    language: "zh-CN"
    log_format: "enhanced"
    auth_basic_user_file: "/etc/example-app/goaccess.htpasswd"
    auth_cidr_allowlist: []
    websocket_listen: ""
```

Management UI 不创建或轮换 GoAccess htpasswd。启用 GoAccess 前先准备 htpasswd 文件，再把路径写入 `nginx.goaccess.auth_basic_user_file`。它必须：

- 已存在、普通非空、非 symlink。
- 至少包含一行 `user:hash`，user 和 hash 都不能包含空白字符。
- 文件不能被 group/others 写入，也不能被其他本机用户访问。
- 父目录 root-owned，不能被 group/others 写入，且 Nginx 运行用户能进入。

Debian/Ubuntu 示例：

```bash
sudo apt update
sudo apt install -y apache2-utils
sudo install -d -o root -g root -m 0755 /etc/example-app
sudo htpasswd -c -m /etc/example-app/goaccess.htpasswd goaccess
sudo chown root:www-data /etc/example-app/goaccess.htpasswd
sudo chmod 0640 /etc/example-app/goaccess.htpasswd
```

首次创建才用 `-c`；后续新增或修改用户不要带 `-c`。

`auth_cidr_allowlist` 不是免密白名单。非空时 Nginx 同时要求来源 IP 匹配 allowlist 且 Basic Auth 通过。

GoAccess 看板只以 primary domain 为准；secondary domain 上的 dashboard 请求会重定向到 `https://<primary-domain><nginx.goaccess.path>`，WebSocket 请求返回 `421`。

GoAccess 还要求系统 locale 可用。`language: "en"` 使用 `C.UTF-8`；`language: "zh-CN"` 使用 `zh_CN.UTF-8` 显示 GoAccess UI，并保持原始 raw 日志字段语义。deploy 会检查 `locale -a`，缺失时应先生成对应 UTF-8 locale。`enhanced` log format 还包含 request serving time。

Debian/Ubuntu 上生成中文 locale：

```bash
sudo apt install -y locales
sudo sed -i 's/^# *zh_CN.UTF-8 UTF-8/zh_CN.UTF-8 UTF-8/' /etc/locale.gen
sudo locale-gen zh_CN.UTF-8
locale -a | grep -Ei '^(C|C\.utf8|zh_CN\.utf8|zh_CN\.UTF-8)$'
```

登录 shell 自身的 locale 也要有效。例如 `env` 显示 `LANG=en_US.UTF-8` 时，`locale -a` 必须包含 `en_US.utf8`；否则生成它，或用 `sudo update-locale LANG=C.UTF-8` 把主机默认值改成 `C.UTF-8`。Lanpanel 会用 `LANG=C LC_ALL=C` 运行 GoAccess 的 `--version`、`--help` 和兼容性探测，避免依赖操作者 SSH 会话的 locale。

## Access log 规则

`nginx.access_log` 决定 App 的 canonical access log 来源，也是 GoAccess 启用时最重要的日志边界字段。
`nginx.error_log` 只用于 Nginx 错误排查，GoAccess 不解析它；它不能等于 canonical access log 或 htpasswd 文件，也不能放在 Lanpanel 管理的 App/GoAccess 运行路径下。

| 配置 | 行为 |
| --- | --- |
| `nginx.access_log: ""` 且 GoAccess 关闭 | 继承 Nginx 全局日志，Lanpanel 不处理 |
| `nginx.access_log: ""` 且 GoAccess 开启 | 使用 `/var/log/lanpanel/apps/<app-name>/access.log`，Lanpanel 管理 logrotate |
| 显式其它 access log 且 GoAccess 关闭 | 只渲染到 Nginx，不创建、不轮转 |
| 显式其它 access log 且 GoAccess 开启 | 作为外部 canonical access log，必须预先存在并满足安全要求 |

外部 `access_log` 安全要求：启用 GoAccess 时，Lanpanel deploy 会先创建或确认 GoAccess runtime identity（运行身份），再做 access log 最终可读性检查。

外部 access log 不要放在 `/home`、`/root`、`/run/user`、`/tmp`、`/var/tmp`、`/var/log/nginx`、其它 App 的 `/var/log/lanpanel/apps/` 或当前 App 生成目录下。`ProtectHome=true`、`PrivateTmp=true` 和发行版 logrotate 会让这些路径不可靠或边界不清。

## EdgeOne RealIP

EdgeOne RealIP 只作用于引用该 profile 的 App：

```yaml
app:
  acme_challenge: "dns-01"

access:
  origin_protection:
    mode: "edgeone"
    edgeone_profile: "edgeone-prod"
    direct_origin_risk_confirmed: false

realip:
  profiles:
    edgeone-prod:
      enabled: true
      provider: "edgeone"
      refresh_interval: "72h"
      edgeone:
        zone_id: "zone-xxxxxxxx"
        env_file: "/etc/lanpanel/realip/edgeone-prod.env"
```

EdgeOne env file 必须 root-owned、root-only，并用 `_FILE` 变量引用密钥：

```bash
TENCENTCLOUD_SECRET_ID_FILE=/etc/lanpanel/realip/edgeone-prod-secret-id
TENCENTCLOUD_SECRET_KEY_FILE=/etc/lanpanel/realip/edgeone-prod-secret-key
# 腾讯云临时凭据可选：
TENCENTCLOUD_SESSION_TOKEN_FILE=/etc/lanpanel/realip/edgeone-prod-session-token
```

如果 HTTPS 证书的 DNS-01 已经使用腾讯云凭据，可以让 EdgeOne RealIP 共用同一组 SecretId/SecretKey 文件；不要直接共用含有 lego DNS 调参的 `dns01.env_file` 本身。单独创建 RealIP env file，只引用同一组密钥文件：

```bash
sudo install -d -o root -g root -m 0700 /etc/lanpanel/realip
sudo install -o root -g root -m 0600 /dev/null /etc/lanpanel/realip/edgeone-prod.env
sudo tee /etc/lanpanel/realip/edgeone-prod.env >/dev/null <<'EOF'
TENCENTCLOUD_SECRET_ID_FILE=/etc/lanpanel/dns01/tencentcloud-secret-id
TENCENTCLOUD_SECRET_KEY_FILE=/etc/lanpanel/dns01/tencentcloud-secret-key
EOF
```

独立 EdgeOne 凭据示例：

```bash
sudo install -d -o root -g root -m 0700 /etc/lanpanel/realip
sudo install -o root -g root -m 0600 /dev/null /etc/lanpanel/realip/edgeone-prod-secret-id
sudo install -o root -g root -m 0600 /dev/null /etc/lanpanel/realip/edgeone-prod-secret-key
printf '%s' '<腾讯云 SecretId>' | sudo tee /etc/lanpanel/realip/edgeone-prod-secret-id >/dev/null
printf '%s' '<腾讯云 SecretKey>' | sudo tee /etc/lanpanel/realip/edgeone-prod-secret-key >/dev/null

sudo install -o root -g root -m 0600 /dev/null /etc/lanpanel/realip/edgeone-prod.env
sudo tee /etc/lanpanel/realip/edgeone-prod.env >/dev/null <<'EOF'
TENCENTCLOUD_SECRET_ID_FILE=/etc/lanpanel/realip/edgeone-prod-secret-id
TENCENTCLOUD_SECRET_KEY_FILE=/etc/lanpanel/realip/edgeone-prod-secret-key
EOF
```

当前实现调用腾讯云中国区 EdgeOne API endpoint `teo.tencentcloudapi.com`。需要 `teo.intl.tencentcloudapi.com` 的国际站账号暂不支持。

首次部署：

```bash
lanpanel app verify --config lanpanel-apps/example-app.yaml
sudo lanpanel app deploy \
  --config lanpanel-apps/example-app.yaml \
  --confirmation origin-protection-manual
```

刷新与诊断：

```bash
sudo lanpanel app realip refresh \
  --config lanpanel-apps/example-app.yaml \
  --profile edgeone-prod \
  --confirmation origin-protection-manual

sudo lanpanel app realip diagnostics \
  --config lanpanel-apps/example-app.yaml \
  --profile edgeone-prod
```

Lanpanel 会把 current+next OriginACL CIDR 渲染进 App Nginx realip include。你仍然必须手动维护云安全组、主机防火墙或等价边界，只允许这些 CIDR 访问源站 `80/443`。Lanpanel 不调用 `ConfirmOriginACLUpdate`，不修改 EdgeOne 站点、DNS 或证书配置。

如果 EdgeOne RealIP 使用独立腾讯云凭据，建议只授予目标 EdgeOne zone 的 `DescribeOriginACL` 权限；如果与 DNS-01 共用凭据，则需要同时具备 DNSPod 记录管理权限和目标 EdgeOne zone 的 `DescribeOriginACL` 权限。

当前版本不支持非 EdgeOne provider、manual CIDRs、`trust_all`、自定义真实 IP header、把 `X-Forwarded-For` 作为 realip 输入、Headscale realip 或全局 Nginx realip。客户端 IP header 固定为 `EO-Connecting-IP`。

启用后，Lanpanel 只在目标 App site 渲染 `set_real_ip_from` / `real_ip_header`，把上游 `X-Real-IP` 和 `X-Forwarded-For` 重建为 canonical `$remote_addr`，`X-Forwarded-Proto` 保持源站 Nginx `$scheme` 语义，并清空入站 `Forwarded`、`X-Original-Forwarded-For`、`X-Client-IP`、`EO-Connecting-IP`、`EO-Client-IP` 等 forwarded/client-IP header。非可信直连请求会被生成的 App site 拒绝，并以 `untrusted_source_ip` 写入拒绝日志。

刷新 timer 默认 `72h`，且 `refresh_interval` 最小为 `1h`。请订阅 EdgeOne OriginACL/回源 IP 变更通知，并用 `lanpanel app realip refresh` 或 diagnostics 输出跟踪已部署 current+next CIDR。EdgeOne 返回 `NextOriginACL` 时，Lanpanel 会把 current+next CIDR 都同步进 Nginx 信任列表；操作者仍必须在 Lanpanel 之外完成云安全组、防火墙或 EdgeOne 回源 IP 确认。

## 部署前检查清单

- `app.domains` 都解析到当前云服务器，且不要复用主 Headscale `server_url` 主机名。
- 使用 EdgeOne RealIP profile 时，公网 DNS 可以解析到 EdgeOne；deploy 会检查 DNS-01 凭据和 EdgeOne OriginACL 覆盖，而不是要求 A/AAAA 直连源站。
- 公网只通过 Nginx 开放 `80/tcp` 和 `443/tcp`，不开放 `18001` 这类 App 端口。
- 同机也运行主 Headscale 时，`3478/udp` 留给 STUN，`app.listen` 和 `nginx.goaccess.websocket_listen` 不要复用 Headscale metrics 端口。
- `listen` 模式业务二进制已经安装，且 `service.exec_start` 的第一个 token 是可执行文件绝对路径。
- 如设置 `service.env_file`，它必须指向 root-owned、root-only 文件。
- 如启用 `nginx.goaccess.enabled`，先准备 htpasswd；显式外部 `nginx.access_log` 必须已存在并满足外部日志安全要求。
- `nginx.static_locations` 的 alias 指向已经随 App release 发布的文件或目录。
- `upstream` 模式后端是固定 `100.64.x.y:port`，并且从云服务器可以访问。
- DNS-01 的 `dns01.env_file` 和 Tailscale 的 `tailscale.auth_key_file` 都是 root-owned、root-only 文件。

## 部署后验证

通用检查：

```bash
sudo nginx -t
curl -I https://app.example.com
```

`listen` 模式：

```bash
systemctl status <app-name>.service --no-pager --full
journalctl -u <app-name>.service -e
```

`upstream` 模式：

```bash
tailscale status
curl -I http://<app.upstream>
```

GoAccess：

```bash
systemctl status <app-name>-goaccess.service --no-pager --full
journalctl -u <app-name>-goaccess.service -e
curl -I https://app.example.com/_lanpanel/apps/<app-name>/goaccess
tail -f <canonical-access-log>
tail -f <error-log>
```

`<canonical-access-log>` 使用 `nginx.access_log`；如果为空且 GoAccess 启用，则是 `/var/log/lanpanel/apps/<app-name>/access.log`。`<error-log>` 使用 `nginx.error_log`；如果为空，查看 Nginx 默认 error log。

RealIP：

```bash
sudo lanpanel app realip diagnostics --config lanpanel-apps/example-app.yaml --profile edgeone-prod
```
