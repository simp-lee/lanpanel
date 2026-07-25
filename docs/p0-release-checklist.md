# P0 Release Checklist

Release candidate inventory:

- Main deployment: Headscale v0.29.1, loopback Headscale control/metrics/gRPC,
  Nginx HTTPS ingress, HTTP-01 or DNS-01 certificate issuance, lego renewal
  hook, managed systemd units, default `lanpanel` onboarding user, and static
  post-deploy verification.
- App deployment: same-host `listen` mode and tailnet/upstream HTTP/WebSocket
  proxying, public or browser access modes, static locations, certificate
  issuance/renewal, managed app systemd units, and optional GoAccess dashboard.
- Browser Auth: UI-managed htpasswd create, rotate, fail-closed delete, one-time
  password handoff, and explicit separation from GoAccess htpasswd files.
- RealIP: EdgeOne OriginACL read, current+next CIDR rendering, app-scoped Nginx
  realip include, refresh timer/service, diagnostics, and manual origin
  protection confirmation.
- Management UI: loopback-only listener, one-time startup token, local assets,
  CSRF protection, jobs/history, host health, diagnostics, services,
  certificates/Nginx, Headscale onboarding handoff, and exit/migration page.
- Release baseline: Debian/Ubuntu family host with systemd, Nginx, root or
  sudo, Tailscale-compatible clients >= v1.80.0, public DNS for main/app
  domains, and either reachable pinned release artifacts or offline uploads.
- Existing baseline retained: CLI `init`, `verify`, `deploy`, `status`, app
  commands, static verification, checkpoint status, and generated example
  configs remain available for non-UI and automation use.
- Deferred P1 scope: private-client app access, commercial/multi-tenant
  controls, RBAC, account/OIDC/SSO, public remote UI/control plane, export
  manifest, audit-log writer, Kubernetes/Terraform/Ansible workflows, HA, and
  automatic cloud firewall/EdgeOne confirmation.
- Known limits: no live provider mutation for EdgeOne, no automatic backup or
  restore, no generated migration manifest, no official DERP fallback, no
  public Management UI, no GoAccess htpasswd create/rotate, and no browser
  app upstream `Authorization` forwarding in `browser` mode.
- Schema and config contract: `deploy/config/lanpanel.yaml.example`,
  `deploy/config/lanpanel-app.yaml.example`, `internal/config/types.go`,
  `internal/appconfig/types.go`, `docs/zh-CN/app.md`, `docs/zh-CN/cli.md`,
  and `docs/zh-CN/ui.md` must describe the same supported fields and limits.

User docs and examples required for RC:

- Health and diagnostics: `docs/zh-CN/ui.md#host-health-和-diagnostics`,
  `docs/zh-CN/operations.md`, `docs/zh-CN/troubleshooting.md`.
- Exposure preview and public risk: `docs/zh-CN/ui.md#发布-app`,
  `docs/zh-CN/app.md`, `docs/zh-CN/security.md`.
- Checkpoint recovery: `docs/zh-CN/cli.md`, `docs/zh-CN/troubleshooting.md`,
  and UI Jobs history walkthrough evidence.
- Certificates and Nginx: `docs/zh-CN/app.md`, `docs/zh-CN/operations.md`,
  and `docs/zh-CN/troubleshooting.md`.
- EdgeOne RealIP: `docs/zh-CN/app.md#edgeone-realip`,
  `docs/zh-CN/ui.md#发布-app`, and RealIP walkthrough evidence.
- GoAccess: `docs/zh-CN/app.md#goaccess-dashboard-auth`,
  `docs/zh-CN/ui.md#goaccess-dashboard-auth`, and RealIP/GoAccess walkthrough
  evidence.
- Job history and redaction: `docs/zh-CN/ui.md#jobs-和一次性-secret` and
  jobs history walkthrough evidence.
- Headscale onboarding: `docs/zh-CN/ui.md#headscale-onboarding`,
  `docs/zh-CN/quickstart.md`, and onboarding walkthrough evidence.
- SSH tunnel access: `docs/zh-CN/ui.md#启动方式`,
  `docs/zh-CN/quickstart.md#第-3-步启动-ui`, and
  `docs/zh-CN/app-quickstart.md#第-1-步启动-ui` must cover Linux/macOS,
  Windows OpenSSH, and PuTTY.

Local gates:

- `make p0-release-gate` runs the full local P0 release gate.
- `make check` runs build, `go test ./...`, `go vet ./...`, and the P0
  static audit.
- `make e2e`
- `make e2e-walkthrough-all`
- `E2E_ADDR=127.0.0.1:18081 make e2e` when the default loopback
  test port is busy.

Static audits:

- No full startup token URL in logs, jobs, events, diagnostics, or docs.
- No preauth key, browser password, htpasswd content, DNS token, EdgeOne secret,
  or Tailscale auth key in stored workflow/job results.
- No Management UI listen suggestion using `0.0.0.0`, public IPs, or `::`.
- No CDN htmx script reference in product pages.
- Browser apps protect proxy and static locations with Basic Auth and do not
  forward inbound `Authorization`.
- Managed browser auth delete fails closed unless every active or staged app
  reference can be proven absent; otherwise manual removal is documented.
- GoAccess auth remains separate from browser app auth.
- P1-only `private_client`, commercial, RBAC, account/OIDC/SSO, public remote
  control, public Management UI, export manifest, and audit-log write paths are
  not exposed in P0 UI.
- Exposure summary and resource cards stay derived, read-only interpretation
  from config, staged files, checkpoints, diagnostics, and runtime checks; they
  are not deploy or restore truth.

Live host gate:

- Debian/Ubuntu systemd host with real Nginx, ACME staging or controlled DNS-01,
  Headscale, Tailscale-compatible client, GoAccess, and EdgeOne OriginACL
  profile.
- Verify main deploy, app deploy, RealIP refresh/rollback, browser Basic Auth,
  public risk confirmation, checkpoint recovery, UI tunnel access, job
  interrupted recovery, and Headscale preauth handoff.

Manual UI gate:

- Token exchange redirects to `/`.
- Cookie is HttpOnly and SameSite.
- CSRF blocks mutating requests without token.
- Host Health is read-only and offers only controlled links.
- Jobs/history never reveal one-time secrets.
- Exit/Migration documents local config and state paths, non-exported secrets,
  no export manifest, and recovery limits.
