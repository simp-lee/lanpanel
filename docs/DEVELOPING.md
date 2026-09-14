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

## 依赖和主机 Profile

第三方依赖为 Lego、Tailscale 和 Headscale。`release-inputs/dependency-inputs.v1.json` 是经过审查的版本锁定文件；`dist/dependencies/` 是下载和解包目录，必须保持为空后再执行相关命令。

只有明确要升级依赖时，才查询上游最新稳定版本：

```sh
make resolve-preview-dependencies \
  PREVIEW_DEPENDENCY_DIR="$PWD/dist/dependencies"
```

审查生成的 `dependency-inputs.json` 后，将确认的结果更新到 `release-inputs/dependency-inputs.v1.json`。普通代码发布不要执行这一步。使用已审查的锁定结果时：

```sh
make materialize-preview-dependencies \
  PREVIEW_DEPENDENCY_LOCK="$PWD/release-inputs/dependency-inputs.v1.json" \
  PREVIEW_DEPENDENCY_DIR="$PWD/dist/dependencies"
```

`materialize` 只下载锁定的 URL 并验证大小和 SHA-256，不查询 `latest`。`make release-preview` 会自动执行同样的物化步骤。

每个支持的发行版家族都要在干净的 Debian 或 Ubuntu amd64 主机上采集 Profile。先运行只读检查：

```sh
make check-preview-profile-host PREVIEW_PROFILE_TARGET=debian
```

然后在已完成依赖物化的环境中采集：

```sh
make capture-preview-profile \
  PREVIEW_PROFILE_ID=debian-amd64 \
  PREVIEW_PROFILE_OUTPUT_DIR=release-inputs/profiles/debian-amd64 \
  PREVIEW_DEPENDENCY_INPUTS=dist/dependencies/dependency-inputs.json
```

Ubuntu 主机使用 `PREVIEW_PROFILE_TARGET=ubuntu` 和 `PREVIEW_PROFILE_ID=ubuntu-amd64`。检查和采集会验证发行版、amd64、systemd、cgroup v2、APT/dpkg 以及必要软件包；采集命令只写入 Profile、软件包模板和依赖基线，不绑定某个 APT 镜像。生成结果必须人工审查后再提交。

## 本地构建 Preview 发布包

发布构建必须从干净 worktree 的精确 Git tag 开始。常规流程分为：

1. **resolve**：有意查询上游最新依赖并更新锁定文件；
2. **materialize**：只按锁定文件下载和校验依赖；
3. **build**：构建 Linux amd64 二进制、源代码归档、Profile 相关文件和依赖清单；
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
- `release.json`、其 detached Ed25519 签名和 `SHA256SUMS`；
- `LICENSE`、各 Profile 的软件包模板/依赖清单/依赖基线；
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
