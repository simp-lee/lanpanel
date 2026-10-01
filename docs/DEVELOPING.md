# LanPanel

## 开发与发布文档

本文面向贡献者、开发者和 Preview 发布维护者。普通用户只需阅读根目录的 [README.md](../README.md)。

## 开发环境

- 使用 `go.mod` 声明的 Go 版本；
- `golangci-lint` 必须为 `2.11.3`；
- 本地发布还需要 `curl`、`jq`、`sha256sum`、GNU `tar`、`gzip`；
- GitHub 发布还需要已登录的 `gh` CLI。

常用命令：

```sh
make build                 # 构建 lanpanel
make test                  # 单元测试
make vet                   # go vet
make lint                  # golangci-lint
make race                  # race 测试
make check                 # 完整质量门禁
```

`make check` 会依次执行测试、`vet`、Lint 和 race 测试。提交代码前应至少运行一次；CI 使用相同的 Preview 质量门禁。`make tidy` 只在确实需要调整依赖时使用。

### 浏览器 fixture 门禁

结构化应用向导的可重复浏览器验证使用单独的 fixture 门禁。首次运行先安装 Node 依赖和 Playwright Chromium：

```sh
npm ci
npx playwright install chromium
make playwright-fixture-gate
```

`make playwright-fixture-gate` 的唯一测试入口是 `LANPANEL_PLAYWRIGHT_FIXTURE=1 npm run test:auth`。Playwright spec 会启动一个 Go fixture，等待本机 readiness；启动超时、Go fixture 退出、测试失败或 browser failure 都以非零状态传播，`afterAll` 会清理 fixture。fixture 使用内存 typed resource/status/probe/Job 和副作用计数，不连接真实持久化、Nginx、应用进程、ACME、DNS、Tailscale 或远程命令；因此它验证 UI/helper/application 合同，不替代真实主机或外部服务资格验证。CI 先运行 `make preview-local-gate`，再执行 `npm ci`、固定 Chromium 安装和同一个 `make playwright-fixture-gate`，不会启动第二个 fixture。

### 真实主机和外部依赖验收（人工，非 CI）

要验证主机和外部依赖，必须使用 Debian/Ubuntu amd64 的可销毁云主机或 VM；这项验收不应加入确定性 CI 门禁。先做快照，只使用测试域名和测试凭据。记录安装器输出的 Management 地址和端口，并通过 SSH 隧道连接这个准确地址。

1. 安装前后保存 `systemctl --failed`、`systemctl status lanpanel-helper lanpanel-ui lanpanel-nginx lanpanel-recovery --no-pager --full`、`systemctl is-enabled lanpanel-helper lanpanel-ui lanpanel-nginx lanpanel-timer.timer`、`ss -ltnup` 和 `journalctl -u 'lanpanel-*' --since -5min`。确认 `/run/lanpanel/helper.sock` 是 root 所有、仅 helper client group 可读写、权限为 `0660` 的 Unix socket；确认 UI 和应用进程不是 root。
2. 在 UI 创建由临时 HTTP/WebSocket 测试程序提供服务的 `local_http`。保存后重启，确认 resource、停止/未发布状态、Job 历史和配置仍在；再验证编辑、启动、readiness/status、停止、发布、HTTPS 请求、撤销发布和删除。检查进程 UID/cgroup、监听端口、Nginx 配置检查/重载，并确认删除 resource 不会删除外部可执行文件或工作目录。
3. 验证预期的 helper rejection，例如对 `tailnet_http` 请求启动进程。浏览器 Network 响应和 UI 状态必须包含 HTTP 409、typed `error_code` 和 `job_id`；打开该 Job，确认终态失败及修复指引。`service_unavailable` 不能作为替代结果。
4. 执行成功和失败的创建、编辑、发布、撤销发布、删除、进程、Token 轮换、Headscale、Connector 操作，并制造一次取消。以 root 用 `jq` 检查 `/var/lib/lanpanel-management-audit/events.json`，确认每个请求有正确的 `operation`、target、非敏感 actor、UTC 时间、`succeeded`/`failed`/`cancelled` 结果和适用的 typed error code；重启后文件仍是合法 JSON，且不含 token、密码、auth key、私钥或 credential 内容。
5. 使用测试域名和 ACME staging 账户分别验证 HTTP-01 和支持的 DNS-01 provider：DNS 解析、challenge 创建/清理、证书签发、Nginx 重载、续期 timer 以及 HTTPS/SNI/Host 行为。首次验证不要使用生产凭据。
6. 准备第二台测试节点，安装支持版本的 Tailscale 客户端，验证 Headscale 初始化、控制入口、用户/密钥/设备生命周期、客户端加入、`tailscale status`、`tailscale ping` 和 `tailscale netcheck`。绑定并登录 Connector，完成验证后发布固定 `tailnet_http` endpoint，测试 connector、route、target、HTTP 和 WebSocket 的失败/恢复场景；确认没有远端进程控制或远程 Shell/命令执行。
7. 在安装完成、local 发布完成、Headscale/Connector 配置完成等关键边界重启，重复状态和公网探测，并保存带 release/host 标识的 systemd、网络、DNS、证书、Tailscale、Job 和审计输出。真实主机结果才是资格证据；Playwright fixture 通过本身不能证明这些边界。

不要提交下载的第三方二进制、`dist/` 输出、发布包、Bootstrap、GitHub Token 或签名私钥。下载的依赖只应放在被忽略的 `dist/dependencies/` 中。

## 目录约定

- `cmd/lanpanel/`：公开二进制入口及内部角色分发；
- `cmd/lanpanel-release/`：构建和校验发布工件；
- `internal/`：安装器、UI、应用、网络、证书、进程和发布校验等实现；
- `scripts/`：依赖物化、发布打包、Bootstrap 生成和 GitHub 发布适配器；
- `release-inputs/`：经过审查并纳入版本控制的发布输入；
- `.github/workflows/`：CI 和 Preview 发布工作流。

根目录 `README.md` 是普通用户文档，同时也是发布清单中的限制说明资产；不要再创建或恢复单独的限制说明文件。

日常应用管理的产品边界是 Management UI，不要为应用管理重新增加 CLI、Shell、任意 `ExecStart` 或未类型化的配置入口。特权操作应继续经过现有的 typed helper；不要复制第二套安装、恢复或卸载流程。

## 依赖和 Host Capability Contract

第三方依赖为 GoAccess、Lego、Tailscale 和 Headscale。GoAccess 在 release 构建阶段从固定的官方源码版本编译为静态 amd64 二进制，不使用主机 APT 中的 GoAccess。`release-inputs/dependency-inputs.v2.json` 是经过审查的版本锁定文件；`dist/dependencies/` 是下载和解包目录，必须保持为空后再执行相关命令。

只有明确要升级依赖时，才查询上游最新稳定版本：

```sh
make resolve-preview-dependencies \
  PREVIEW_DEPENDENCY_DIR="$PWD/dist/dependencies"
```

审查生成的 `dependency-inputs.json` 后，将确认的结果更新到 `release-inputs/dependency-inputs.v2.json`。普通代码发布不要执行这一步。使用已审查的锁定结果时：

```sh
make materialize-preview-dependencies \
  PREVIEW_DEPENDENCY_LOCK="$PWD/release-inputs/dependency-inputs.v2.json" \
  PREVIEW_DEPENDENCY_DIR="$PWD/dist/dependencies"
```

`materialize` 只下载锁定的 URL，构建固定版本的 GoAccess，并验证所有输入和输出的大小及 SHA-256；它不查询 `latest`。`make release-preview` 会自动执行同样的物化步骤。

Host Capability Contract 不是 Debian/Ubuntu 版本白名单；它只记录 LanPanel 真正依赖的接口：Linux amd64、systemd、APT/dpkg、Nginx 最低版本，以及 unified cgroup v2、`cgroup.kill` 和 systemd delegation。发行包对每个支持的架构只应包含一个通用的 `linux-amd64-apt-dpkg-systemd` 契约，不应为 Ubuntu 22.04、Ubuntu 24.04、Debian 12、Debian 13 等分别添加 profile；profile 选择也不得按发行版名称或版本号分支。运行时兼容性不得按发行版版本硬编码。profile capture 生成的是签名 APT 计划的参考 authority：带版本范围的发行版仓库包由目标主机的签名 APT 候选版本解析，并按范围检查，而不是要求候选版本等于参考主机版本。发布前应从任一满足能力契约且仓库健康的参考主机采集 profile，不能手工替换 authority；随后用代表性的不同主机验证能力契约，不需要把每个发行版版本的 profile 放进发行包。显式复用外部 Nginx 时，安装器会把 Nginx 从事务中移除，只按能力版本范围校验已安装的软件包。

先运行只读检查：

```sh
make check-preview-profile-host PREVIEW_PROFILE_TARGET=capability-host
```

然后在已完成依赖物化的参考环境中采集：

```sh
make capture-preview-profile \
  PREVIEW_PROFILE_ID=linux-amd64-apt-dpkg-systemd \
  PREVIEW_PROFILE_OUTPUT_DIR=release-inputs/profiles/linux-amd64-apt-dpkg-systemd \
  PREVIEW_DEPENDENCY_INPUTS=dist/dependencies/dependency-inputs.json
```

采集只读取 APT 候选 Nginx 版本，生成 Host Capability Contract、APT 包模板和依赖基线。发布时 APT/dpkg 仍使用目标主机自身的签名仓库；安装器会在真实目标主机上主动探测 systemd delegation、动态 cgroup v2 mountpoint、`cgroup.kill`、APT/dpkg 状态和 Nginx 最低版本。生成结果必须人工审查后再提交。

## 本地构建 Preview 发布包

发布构建必须从干净 worktree 的精确 Git tag 开始。常规流程分为：

1. **resolve**：有意查询上游最新依赖并更新锁定文件；
2. **materialize**：只按锁定文件下载和校验依赖；
3. **build**：构建 Linux amd64 二进制、源代码归档、Host Capability Contract 相关文件和依赖清单；
4. **verify/package**：校验完整发布目录并制作外层归档及 Bootstrap；
5. **publish**（可选）：上传后重新下载并校验公开文件。

完整本地流程使用 `make release-preview`。它不会查询 `latest`，但需要以下输入：已审查的发布清单模板、Profile 输入目录、签名私钥路径，以及各阶段的输出目录。例如：

```sh
make release-preview \
  PREVIEW_TAG=v1.2.3-preview \
  PREVIEW_SOURCE_DIR="$PWD" \
  PREVIEW_DEPENDENCY_DIR="$PWD/dist/dependencies" \
  PREVIEW_MANIFEST_TEMPLATE="$MANIFEST_TEMPLATE" \
  PREVIEW_PROFILE_INPUT_DIR="$PROFILE_INPUT_DIR" \
  PREVIEW_SIGNING_KEY="$SIGNING_KEY" \
  PREVIEW_ARTIFACT_DIR="$PWD/dist/release" \
  PREVIEW_DOWNLOAD_BASE_URL="https://github.com/simp-lee/lanpanel/releases/download/v1.2.3-preview" \
  PREVIEW_OUTPUT_DIR="$PWD/dist/releases"
```

`MANIFEST_TEMPLATE`、`PROFILE_INPUT_DIR` 和 `SIGNING_KEY` 必须先指向真实的、经过审查的输入；签名私钥应放在仓库外并限制权限。也可以使用 `make build-preview-artifact` 和 `make package-preview-release` 分步执行。只有已经准备好并通过校验的发布目录才能执行打包。

发布工件至少包含：

- `lanpanel` 和对应版本的源代码归档；
- `release.json`、其 detached Ed25519 签名、`lanpanel.sig` 二进制签名和 `SHA256SUMS`；
- `LICENSE`、Host Capability Contract 的软件包模板/依赖清单/依赖基线；
- 经过版本、来源、大小和 SHA-256 绑定的 Lego、Tailscale、Headscale 资产。

发布构建会校验清单中的路径、文件大小、摘要、源代码树和第三方归档成员。`SHA256SUMS` 不包含 `release.json`、自身和 detached 签名；外层 `lanpanel-<tag>-linux-amd64.tar.gz` 的 SHA-256 单独写入 Bootstrap。任何缺失、篡改、额外文件、非 canonical 清单或脏 worktree 都必须失败。

## GitHub 发布

本地打包完成后，使用 GitHub 适配器发布：

```sh
make publish-preview-github \
  PREVIEW_TAG=v1.2.3-preview \
  PREVIEW_OUTPUT_DIR="$PWD/dist/releases"
```

适配器要求 `gh` 已认证，且不会覆盖已有 tag。它会创建草稿 Release、校验上传后的字节、正式发布，然后从公开 HTTPS 地址重新下载归档和 Bootstrap，确认 URL、外层归档摘要和 Bootstrap 中的固定摘要一致。上传失败或发布后复验失败都不能视为发布成功。

`.github/workflows/release-preview.yml` 使用同一套 `make release-preview` 和 GitHub 适配器；CI 的发布密钥只能来自受保护的 Secret。发布页面应使用实际的版本固定 Bootstrap 地址，不得改成 `latest` 或未绑定摘要的下载地址。

## 变更检查清单

提交前确认：

- `make check` 通过；
- 用户可见行为仍以 loopback UI 和唯一的 `install`/`uninstall` 生命周期入口为准；
- 未引入隐式发布、自动重试远端操作、来源回退、原地升级、回滚或孤儿状态接管；
- 新增的发布输入已审查，依赖 URL、版本、大小和 SHA-256 完全一致；
- 没有把凭据、密钥、下载二进制或 `dist/` 输出提交到仓库。
