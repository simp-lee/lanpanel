# 安装和升级

本文只讲如何把 `lanpanel` 命令安装到服务器上。第一次使用建议安装 release 二进制；只有开发或本地验证时才从源码构建。

## 支持环境

| 项目 | 要求 |
| --- | --- |
| 系统 | Debian、Ubuntu，或具备 `apt` / `dpkg` / systemd 的 Debian 系发行版 |
| CPU 架构 | `amd64` 或 `arm64` |
| 权限 | 可使用 root 或 sudo |
| 网络 | 能访问 GitHub Releases；不能直连时后续可在 UI 上传固定离线依赖 |

安装 `lanpanel` 命令本身只下载 Lanpanel release asset 和 `checksums.txt`。后续部署时，主 Headscale 流程需要可安装基础 apt 依赖、Headscale `.deb` 和固定 lego v5.2.2 archive；App 的 `upstream` 或 tailnet 访问场景需要 Tailscale 包；启用 GoAccess 时才需要 GoAccess 包，使用 Lanpanel 管理 access log 时还需要 logrotate。

## 推荐安装方式

先打开 [Releases](https://github.com/simp-lee/lanpanel/releases)，选择一个真实稳定 tag，例如 `v0.1.0`。不要原样复制 `vX.Y.Z`。

```bash
VERSION=vX.Y.Z
curl -fsSL "https://raw.githubusercontent.com/simp-lee/lanpanel/${VERSION}/scripts/install.sh" | sh -s -- "${VERSION}"
lanpanel --version
lanpanel --help
```

安装脚本会：

- 按当前机器架构选择 `lanpanel_linux_amd64` 或 `lanpanel_linux_arm64`。
- 从同一个 release tag 下载二进制和 `checksums.txt`。
- 用 `sha256sum -c` 校验 asset。
- 默认安装到 `/usr/local/bin/lanpanel`。
- 安装后执行 `lanpanel --help` 确认命令可运行。

如果当前用户不能写 `/usr/local/bin`，脚本会使用 sudo 安装；没有 sudo 时会直接失败并显示原因。

## 指定安装目录

默认安装目录是 `/usr/local/bin`。如果你要安装到其它目录：

```bash
VERSION=vX.Y.Z
curl -fsSL "https://raw.githubusercontent.com/simp-lee/lanpanel/${VERSION}/scripts/install.sh" |
  LANPANEL_INSTALL_DIR="$HOME/.local/bin" sh -s -- "${VERSION}"
```

确认目标目录已经在 `PATH` 中：

```bash
command -v lanpanel
lanpanel --version
```

## 从源码构建

源码 checkout 中：

```bash
make build
./lanpanel --version
./lanpanel --help
```

源码构建适合开发、测试或临时验证。生产服务器建议使用 release 二进制，便于复现版本和 checksum。

## 升级

升级就是安装新的 release tag。先读对应 release notes，再执行：

```bash
VERSION=vX.Y.Z
curl -fsSL "https://raw.githubusercontent.com/simp-lee/lanpanel/${VERSION}/scripts/install.sh" | sh -s -- "${VERSION}"
lanpanel --version
```

升级 `lanpanel` 二进制不会自动执行部署。升级后需要按你的场景重新运行：

```bash
lanpanel verify --config lanpanel.yaml
sudo lanpanel deploy --config lanpanel.yaml
```

或 App：

```bash
lanpanel app verify --config lanpanel-apps/example-app.yaml
sudo lanpanel app deploy --config lanpanel-apps/example-app.yaml
```

## 卸载命令

如果只卸载 `lanpanel` 命令：

```bash
sudo rm -f /usr/local/bin/lanpanel
```

这不会删除已经生成的 Nginx、systemd、TLS、Headscale、UI state、App 配置或 `/var/lib/lanpanel` 等运行文件。迁移或清理生产环境前先阅读 [安全边界](security.md) 和 [服务器和客户端运维](operations.md)，不要手工删除仍被服务引用的文件。

## 安装后下一步

- 要部署私有网络：读 [快速开始：部署私有网络](quickstart.md)。
- 只发布本机 Web App：读 [快速开始：发布本机 App](app-quickstart.md)。
- 想先理解术语：读 [核心概念](concepts.md)。
