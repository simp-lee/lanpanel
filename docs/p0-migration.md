# P0 Exit And Migration Boundary

P0 keeps migration information local and human-readable. It does not generate a
machine-readable export manifest, one-click backup, or automatic restore plan.

Keep or recreate:

- Main config: `lanpanel.yaml`.
- App configs: each `lanpanel-app.yaml`.
- Runtime state: `/var/lib/lanpanel`, `/etc/lanpanel`, Headscale SQLite, and
  app-specific state under `/var/lib/<app-name>` where applicable.
- Certificates and renewal state under the LanPanel-managed lego paths.
- Browser auth credentials under `/etc/lanpanel/browser-auth/`; plaintext
  passwords are not recoverable after the one-time display window.
- DNS provider, EdgeOne, Tailscale auth key, and other secret files referenced
  by config paths; these are not copied into job history.

P0 exposure summary is a derived view from config, staged files, checkpoint,
RealIP/GoAccess state, and diagnostics. It helps humans understand current
browser/public exposure but is not a restore source of truth.

Before uninstalling, record:

- Config paths and state paths.
- Active resources and their access mode.
- Explicit `public` and direct-origin risk confirmations.
- RealIP profile names and OriginACL provider env files.
- GoAccess dashboard boundaries and app access log locations.
- Recent failed jobs and retry commands.

P1 may add an export manifest and richer migration workbench. P0 deliberately
does not.
