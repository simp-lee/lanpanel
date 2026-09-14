# LanPanel 社区版

LanPanel 是面向个人和相互信任小团队的 MIT License、自托管 Linux 主机管理产品。一个 Linux amd64 executable 以固定 installer、Management UI、helper、guard、timer、relay 和数据面 role 运行。

## 管理边界

仅 loopback 监听的 Management UI 是唯一受支持的日常管理入口。LanPanel 不提供管理 CLI、JSON CLI、YAML workflow、shell、terminal 或文件管理器。远程管理时，使用 SSH tunnel 连接 installer 显示的 installation-specific exact `127/8` IPv4 与 high port；不得用 `localhost` 替代。

安装生成 CSPRNG admin token。连接 TTY 时可以显示一次；无 TTY 时只报告 root-protected source path。登录使用带 CSRF、exact Origin/Host 的短期 selector/proof session。token rotation 会使现有 session 失效。secret 不进入 URL、argv、unit、Plan、job、audit、diagnostics、后续 WebSocket event 或业务消息、或 release asset。短期 session proof 由 login 返回并用于 authenticated HTTP header；在 WebSocket traffic 中只在首帧认证中传输，绝不进入后续 event 或业务消息。

UI 进程是 non-root。root mutation 只能经过 peer-authenticated typed Unix-socket helper。关闭或重启 UI 不会停止已提交的 Headscale、managed process、GoAccess、certificate timer 或 App ingress。

## 平台与安装

Preview release 支持使用 systemd 和 apt/dpkg 的 Debian 或 Ubuntu Linux amd64 主机。release profile 选择发行版家族和包版本范围，不再把某个具体发行版版本作为唯一兼容性依据；未知的未来 Debian/Ubuntu 版本只有在所有能力和真实功能检查通过后才会继续安装。LanPanel 仅提供 Preview：安装执行基础主机检查、签名仓库校验、包版本范围校验和事务清理；不声称 hardened GA 或 live qualification。

首版只支持 clean install。从解压后的官方 release artifact 执行唯一公开 Preview 路径：

```text
sudo ./lanpanel install
```

程序从自身所在目录发现 artifact，并在任何主机 mutation 前校验 canonical manifest、受信任的 detached Ed25519 签名、完整 checksum inventory、固定第三方资产、package template、source archive、LICENSE 和 Known Limitations。artifact 内部文件只是发布实现细节；用户不提供 bundle path、digest、package Plan、dependency path 或 ACME contact。若不想手工处理 bundle，可直接复制发布页提供的版本固定命令：

```sh
curl -fL https://github.com/simp-lee/lanpanel/releases/download/<tag>/lanpanel-bootstrap.sh \
  -o /tmp/lanpanel-bootstrap.sh &&
sudo /tmp/lanpanel-bootstrap.sh install
```

发布的 `lanpanel-bootstrap.sh` 会下载固定 artifact，在受保护临时目录中校验内置 digest，退出时清理临时文件，然后调用同一个 `install` 命令。它由 `scripts/generate-preview-bootstrap.sh` 生成；发布页提供实际的版本固定 GitHub Release URL。它不使用 pipe-to-shell，也不提供在线 fallback。

installer 会在任何 mutation 前，依据 checksum-bound release asset 构造绑定当前 host 的 package Plan 和 fresh bootstrap preflight。service bootstrap 前，installer 验证 canonical `release.json`、`SHA256SUMS`、binary/source-tree digest、dependency manifest、signed repository/key metadata、包版本范围和实际安装版本，以及 arch、systemd PID 1、cgroup v2、apt/dpkg 健康、时钟、磁盘、path、listener 和生成的 Nginx 配置。package 安装是 noninteractive 的，会 mask 可能 autostart 的 unit，并拒绝 ambient hook/proxy。

系统包使用主机自己的已认证 APT 配置与 profile 版本范围要求；LanPanel 不限制用户选择 Debian/Ubuntu 镜像。Lego、Tailscale 和 Headscale 都由 release authority 绑定的资产交付；不执行第三方 installer script，也不提供 offline source 或 download fallback。

## Headscale 与 connector

Headscale 是可选能力。没有任何 Headscale evidence 时，本机 App-only publication 仍可工作。启用后，LanPanel 管理一个 trusted-mesh Headscale trust domain：SQLite、MagicDNS、embedded DERP/STUN、private admin endpoint，以及独立 exact-host HTTPS control ingress。

Headscale lifecycle 刻意保持精简：

- user：仅 create/list；
- pre-auth key：仅 create/list/revoke；新 key 为 one-use、untagged，默认一小时、最长 24 小时，并且只显示一次；
- device：仅 list/expire；
- Headscale control certificate 可通过 `headscale_certificate_reissue` reissue：仅在进入 30 天 renewal window 或 expiry 已收缩 control ingress 后运行；要求 fresh、10 分钟的 Plan 与明确的 `reissue` confirmation，保持 control identity 不变。expiry recovery 只接受匹配的本地持久化 control/certificate authority，并在证书验证及原子激活后才恢复 control ingress；失败时保持 closed/fenced，不 adopt foreign 或 ambiguous state。

Key revoke 不会 expire 已注册 device。Device expire 不保证终止既有 TCP/UDP flow。

LanPanel 管理一个本机 Tailscale connector，ControlURL set-once。verify 检查 pinned client、running/logged-in 状态、exact ControlURL、本机 tailnet IP、peer，以及经过 `tailscale0` 的 kernel route。assisted login 直接接收当前 authenticated request 的一次性 auth key，写 owner-only job file，只调用 `--auth-key=file:<exact-path>`，并在 terminal/cancel/startup 删除。没有 key inventory、external key adoption、discard、disconnect、自动 logout/reset/rejoin、rebind 或 multi-connector action。mismatch 必须在 LanPanel 外处理后再次 verify。

## App 与 managed process

每个 App 有 immutable resource ID，target 仅为：

- `local_http`：per-resource non-root confined managed process，通过 protected Unix socket、release-owned relay 或 PID1-owned socket activation 访问；
- `tailnet_http`：一个固定非本机 peer IP:port，并 fresh 证明 route 经 Tailscale。

LanPanel 不上传、构建、安装或编辑 application code/runtime/config。executable、arguments、working directory、environment-file reference 与 write path 都是 typed 的；禁止 shell parsing 和 opaque `ExecStart`。已 publish 的本机 App 必须先显式 unpublish 才能 stop process。Unpublish 不保证终止既有 flow。

## Publication

`publish` 是唯一正常开放或替换 App ingress 的动作。save、process start、connector login、Headscale deploy、restart、timer 和 reconciliation 都不会隐式 publish。每个 resource 初始为 sticky-unpublished。

Publication mode：

- `domain_https`：80/443、exact TLS SNI/HTTP Host、TLS 1.2/1.3、HTTP/1.1、HTTP/2，以及可选 WebSocket；
- test-only `temporary_ip_http`：一个 publicly routable IPv4 与 high port、exact Host、仅 public HTTP/1.1。

Temporary HTTP 是公网明文，并且不会自动过期。

Access mode 为 `public|application_managed|basic`。Basic 可使用一次性 Managed Basic password 或 verified external htpasswd，并可配置 CIDR allowlist。static root 是 external、root-owned、read-only、no-follow tree，只开放显式 route。可选 GoAccess 使用 isolated identity、protected endpoint 与独立 external Basic credential，不提供 raw access-log browser。

每个入口先移除 untrusted identity header，再只根据实际 socket peer 重建 `X-Real-IP`、`X-Forwarded-For`、`X-Forwarded-Host` 和 `X-Forwarded-Proto`。首版不信任 CDN identity header。

clean installer 会原子生成唯一的 installation-managed P-256 ACME account key。Contact 只能在 authenticated Management UI 中设置或修改，并在首次 ACME request 前再次校验；不会进入命令行、日志或 release artifact。ACME 支持 HTTP-01 和 DNS-01；DNS provider exact 闭集为 `cloudflare|route53|digitalocean|gcloud|tencentcloud`。DNS credential 保持在 protected file/profile。禁止 provider、CA 和 source fallback。release notes 会区分真实 live-tested provider 与 deterministic fixture coverage。

## 关闭、恢复、删除与导出

`unpublish` 持久关闭一个 App；`close-all` 持久关闭全部 LanPanel-owned App ingress，正常情况下保留健康 Headscale control ingress。sticky closure 跨 restart/reboot 保留。certificate expiry 或 uncertain activation 会收缩 ingress，而不是重试 remote work。

关闭会验证 owned disk graph、Nginx reload、prior-worker drain 和 release-owned runtime rejection。无法证明 selective closure 时，LanPanel 持久化 stop fence 并 stop Nginx。Fail-closed stop Nginx 可能同时中断 Headscale control ingress。

Startup reconciliation 只可完成 exact existing local journal 或收缩 ingress；不会重试 ACME/provider、登录 connector、adopt orphan、启动 explicitly stopped process 或恢复 App ingress。未解决的 orphan/unknown state 保持 closed。受支持的后续动作是 diagnostics、无 secret configuration export 和 clean-host rebuild，而不是 Repair。

Plan-bound resource delete 要求 fresh unpublished closure；本机 App 还要求 cgroup/listener 已停止。只删除 exact LanPanel-managed inventory。external executable、working directory、static root、environment file、htpasswd 和 log source 永不删除。

## 首版明确限制

- 不支持原地 upgrade、same-version reinstall、dependency maintenance、updater、rollback engine 或 state/schema migration。
- 不支持产品级 backup/restore、restore cutover 或跨主机 migration。手工 host copy 或 VM snapshot 不自动构成受支持、可恢复的 backup。
- 不提供 Repair、fix-host、orphan adoption 或 normalization action。
- 首版无 EdgeOne integration。
- 不声明 ARM64 GA；不提供公网 TCP/UDP、SSH/RDP/VNC、容器、Kubernetes、数据库、application template、remote API、OIDC 或 RBAC。

主机管理员可以在产品外读取自己的配置、SQLite 和数据。Configuration export 是产品支持的数据迁出能力。

## 发行

release 包含一个 Linux amd64 binary、source tag/archive、LICENSE、按发行版家族区分的 dependency manifest 和 package template、`SHA256SUMS` 以及 canonical `release.json`。用户安装说明见 [docs/INSTALLING.md](docs/INSTALLING.md)；开发和发布流程见 [docs/DEVELOPING.md](docs/DEVELOPING.md) 与 [docs/RELEASING.md](docs/RELEASING.md)。Preview 不发布 SBOM/OSV 或 live qualification 证据。
