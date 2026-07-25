# 中文文档

Lanpanel 中文文档按“先跑通，再深入”的顺序组织。第一次使用不要从命令参考开始读，先选下面最接近你目标的路径。

## 我应该读哪篇

| 目标 | 先读 | 说明 |
| --- | --- | --- |
| 自建一个私有 Tailscale/Headscale 网络 | [快速开始：部署私有网络](quickstart.md) | 从服务器准备到客户端接入的完整闭环 |
| 只把同机 Web 服务发布到 HTTPS | [快速开始：发布本机 App](app-quickstart.md) | 不要求先部署 Headscale |
| 还没安装 Lanpanel | [安装和升级](install.md) | release 二进制、源码构建、升级和卸载 |
| 看不懂 Headscale、tailnet、ACME 等词 | [核心概念](concepts.md) | 用普通语言解释常见术语 |
| UI 怎么启动和使用 | [UI 面板手册](ui.md) | 页面地图、Jobs、一次性密钥和权限边界 |
| App 配置字段和高级能力 | [App 配置参考](app.md) | listen、upstream、Browser Auth、GoAccess、EdgeOne RealIP |
| 命令行自动化 | [CLI 运维手册](cli.md) | init、verify、deploy、status、app、realip、version |
| 服务器、客户端和主网络运维 | [服务器和客户端运维](operations.md) | DNS/ACME、运行拓扑、客户端接入和运行检查 |
| 部署失败或客户端连不上 | [常见问题和排障](troubleshooting.md) | 按现象定位下一步 |
| 安全边界和密钥处理 | [安全边界](security.md) | UI、secret、端口、生成文件和 EdgeOne 风险 |

## 推荐阅读顺序

主私有网络：

1. [安装和升级](install.md)
2. [快速开始：部署私有网络](quickstart.md)
3. [常见问题和排障](troubleshooting.md)
4. [服务器和客户端运维](operations.md)

只发布本机 App：

1. [安装和升级](install.md)
2. [快速开始：发布本机 App](app-quickstart.md)
3. [App 配置参考](app.md)
4. [常见问题和排障](troubleshooting.md)

自动化和脚本：

1. [CLI 运维手册](cli.md)
2. [App 配置参考](app.md)
3. [服务器和客户端运维](operations.md)

开发者文档：

- [开发和人工测试](development.md)
