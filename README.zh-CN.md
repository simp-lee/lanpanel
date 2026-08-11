# LanPanel

LanPanel 是一个采用 MIT License 的社区版本机管理应用，用于 Headscale 与已发布应用。

发行架构只使用一个 binary，并以闭集、独立监督的进程角色运行。Management UI 是唯一受支持的管理接口。数据面服务和 timer 角色独立受监督，因此关闭或重启 UI 不会停止既有 ingress、Headscale、connector、managed process、分析或证书续期。

项目正在按 GA 安全与 qualification contract 重建。每个 operational role 只有在完整 typed handler 与发行 qualification 就绪后才会开放。产品不提供受支持的命令行、JSON 或 YAML 管理接口。

许可证见 [LICENSE](LICENSE)。
