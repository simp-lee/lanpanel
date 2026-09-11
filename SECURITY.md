# Security Policy / 安全策略

## Supported versions / 支持版本

LanPanel Preview is not supported for production use. Community security handling is best effort; LanPanel does not promise a response or remediation SLA.

LanPanel Preview 不用于生产环境。社区安全处理采用 best-effort，不承诺响应或修复 SLA。

## Private reporting / 私密报告

Do not open a public issue for a suspected vulnerability or include credentials, admin tokens, auth keys, private keys, host addresses, or private Preview installation inputs in a report.

Please report privately through GitHub Security Advisories for this repository. If private advisories are unavailable, contact the repository owner through the private contact channel shown on the repository profile and request an encrypted reporting channel before sending details.

请勿为疑似漏洞创建公开 issue，也不要在报告中包含 credential、admin token、auth key、private key、host address 或 private Preview installation input。

请优先通过本仓库 GitHub Security Advisories 私密报告。如该功能不可用，请通过仓库 profile 展示的私密联系方式联系维护者，并在发送细节前请求加密报告通道。

## What to include / 报告内容

- affected exact version or commit and binary digest；
- reproducible impact and prerequisites；
- whether ingress, authentication, helper privilege, secret handling, path safety, or release identity is affected；
- minimal redacted reproduction；
- suggested mitigation, if known.

请提供受影响的 exact version/commit 与 binary digest、可复现影响和前置条件、涉及的安全边界、最小脱敏复现，以及已知 mitigation。

## Handling / 处理方式

Maintainers will attempt to acknowledge, reproduce, assess, fix, and publish an appropriate notice on a best-effort basis. Reports may be declined when they require unsupported upgrades, Repair, backup/restore, EdgeOne, external CDN behavior, or other explicitly excluded first-release capabilities, unless they demonstrate a vulnerability in shipped code.

维护者会 best-effort 地确认、复现、评估、修复并发布适当说明。若报告仅依赖首版明确排除的 upgrade、Repair、backup/restore、EdgeOne、外部 CDN 行为或其他未交付能力，且未证明 shipped code 漏洞，可能不予受理。
