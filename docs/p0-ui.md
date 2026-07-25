# P0 Management UI

`sudo lanpanel ui` starts a loopback-only Management UI for SSH tunnel access.
It prints a short-lived startup URL, exchanges that token for an HttpOnly
SameSite session cookie, then redirects to a token-free URL. The default state
directory is intended for sudo-owned UI sessions and must be owned by the
process running `lanpanel ui`; a non-root process must use a separate explicit
`--state-dir` that it owns. P0 mutating jobs such as config save, deploy, RealIP
refresh, browser auth create/rotate/delete, and Headscale preauth handoff are
root-gated and fail with an explicit sudo requirement when the UI is not running
as root. The UI serves vendored
`htmx.min.js` from the same binary and does not use a CDN or frontend build
pipeline.

Browser auth delete is fail-closed in P0. The UI refuses automated deletion
when it cannot prove the managed credential is unreferenced by every active or
staged browser app; after checking all app configs, remove the htpasswd file
manually if the credential is no longer used.

By default, UI job/event state is kept in the LanPanel-managed local state
directory `/var/lib/lanpanel/ui-state`; `--state-dir` may point to another
explicit directory, and the store refuses unsafe ownership, mode, symlink paths,
or owner mismatches instead of starting in a degraded in-memory mode.

SSH tunnel examples:

- On the server: `sudo lanpanel ui --listen 127.0.0.1:18080`
- Linux/macOS: `ssh -L 18080:127.0.0.1:18080 user@server`
- Windows OpenSSH: `ssh -L 18080:127.0.0.1:18080 user@server`
- PuTTY: add local source port `18080` and destination `127.0.0.1:18080`.

P0 pages:

- Overview: build version in the shell, main config summary, compact host health,
  derived exposure summary, and recent jobs.
- Settings: structured main config fields and Verify/Deploy job entry points.
- Resources: app access mode `browser|public`, browser Basic Auth, CIDR
  allowlist, origin protection `none|edgeone`, GoAccess, and exposure preview.
- Host Health: read-only OS, CPU, memory, disk, network-address, port-listener,
  certificate-expiry facts, diagnostics checks, and allowed/forbidden action
  boundaries. Checks cover DNS, ports, apt/dpkg/systemd, Nginx config,
  certificates, and public port prechecks.
- Diagnostics, Services, and Certificates/Nginx: typed main/app runtime evidence,
  staged Headscale/Nginx/TLS paths, app service/timer paths, GoAccess and RealIP
  runtime paths when configured, and host-health diagnostics with manual and
  unknown states kept distinct from pass.
- Jobs: local job/event history with checkpoint refs or `not_applicable`,
  modified paths, retry commands, and redacted summaries.
- Headscale onboarding: default user `lanpanel`; preauth keys are one-time
  handoff secrets and are not stored in history.

Boundaries:

- No public Management UI listen address.
- No arbitrary shell, generic package manager, arbitrary systemd, arbitrary
  Nginx editor, disk cleanup, network settings editor, or remote control plane.
- `public` apps require explicit risk confirmation.
- `browser` apps require app gateway Basic Auth and clear upstream
  `Authorization`.
