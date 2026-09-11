# LanPanel Community Edition

LanPanel is an MIT-licensed, self-hosted Linux host manager for individuals and mutually trusted small teams. One Linux amd64 executable provides fixed installer, Management UI, helper, guard, timer, relay, and data-plane roles.

## Management boundary

The loopback-only Management UI is the only supported day-to-day management interface. LanPanel has no management CLI, JSON CLI, YAML workflow, shell, terminal, or file manager. To administer remotely, use an SSH tunnel to the installation-specific exact `127/8` IPv4 address and high port shown by the installer; do not substitute `localhost`.

Installation creates a CSPRNG admin token. An attached TTY may display it once. Non-TTY installation reports only its root-protected source path. Login creates short-lived selector/proof sessions with CSRF and exact Origin/Host checks. Token rotation invalidates existing sessions. Secrets are never placed in URLs, argv, units, plans, jobs, audit, diagnostics, subsequent WebSocket events or business messages, or release assets. The short-lived session proof is returned by login and used in authenticated HTTP headers; within WebSocket traffic, it is sent only in the authentication first frame and never in later event or business messages.

The UI process is non-root. Root mutations cross a peer-authenticated, typed Unix-socket helper boundary. Closing or restarting the UI does not stop committed Headscale, managed processes, GoAccess, certificate timers, or application ingress.

## Platform and installation

The code targets Debian and Ubuntu Linux amd64 with systemd and apt/dpkg. LanPanel is Preview-only: installation performs basic host checks, signed repository validation, exact package-version checks, and transaction cleanup. It is not a hardened GA or live-qualified release.

Only clean installation is supported. From an extracted official release artifact, run the sole public Preview path:

```text
sudo ./lanpanel install
```

The artifact directory is discovered from the running binary. Its canonical manifest, detached Ed25519 signature, complete checksum inventory, fixed dependency assets, package template, source archive, LICENSE, NOTICE, and Known Limitations are verified before host mutation. The artifact's internal files are release implementation details; users do not provide a bundle path, digest, package Plan, dependency path, or ACME contact. A release-specific bootstrap command is published with each fixed artifact version and digest; it verifies the same material in a protected temporary directory and then invokes this command, never pipe-to-shell or an online fallback.

The installer constructs the host-bound package Plan and fresh bootstrap preflight from the checksum-bound release assets before any mutation. Before service bootstrap, it verifies the canonical `release.json`, `SHA256SUMS`, binary and source-tree digests, dependency manifest, signed repository/key metadata, exact package set and versions, host architecture, systemd, apt/dpkg health, clock, disk, paths, and listeners. Package installation is noninteractive, masks possible autostart units, and rejects ambient hooks and proxies.

System packages use only the release-authority-bound signed `OfficialDistro` repository and exact package set. Lego, Tailscale, and Headscale are delivered as release-authority-bound assets; no third-party installer script, mirror, offline source, proxy, or download fallback is used.

## Headscale and connector

Headscale is optional. App-only local publication works without any Headscale evidence. When enabled, LanPanel manages one trusted-mesh Headscale trust domain with SQLite, MagicDNS, embedded DERP/STUN, a private admin endpoint, and an independent exact-host HTTPS control ingress.

Headscale lifecycle is intentionally small:

- users: create and list only;
- pre-auth keys: create, list, and revoke only; new keys are one-use, untagged, default one hour, maximum 24 hours, and displayed once;
- devices: list and expire only;
- the Headscale control certificate can be reissued through `headscale_certificate_reissue` when renewal is due within the 30-day window or after expiry contraction. Reissue requires a fresh 10-minute Plan and explicit `reissue` confirmation, and preserves the control identity. After expiry contraction, recovery accepts only the matching persisted local control/certificate authority and reactivates control ingress after validated atomic activation; failures leave it closed/fenced, and foreign or ambiguous state is not adopted.

Key revoke does not expire a registered device. Device expire does not guarantee termination of an existing TCP or UDP flow.

LanPanel manages one local Tailscale connector with a set-once HTTPS ControlURL. Verification checks the pinned client, running/logged-in state, exact ControlURL, local tailnet IPs, peers, and a kernel route through `tailscale0`. Assisted login accepts a one-time auth key from the current authenticated request, writes an owner-only job file, invokes only `--auth-key=file:<exact-path>`, and deletes the file at terminal/cancel/startup. There is no key inventory, external key adoption, discard, disconnect, automatic logout/reset/rejoin, rebind, or multi-connector action. A mismatch must be resolved outside LanPanel and verified again.

## Applications and managed processes

Each App has an immutable resource ID and either:

- `local_http`: a confined, per-resource non-root managed process reached through a protected Unix socket, release-owned relay, or PID1-owned socket activation; or
- `tailnet_http`: one fixed non-local peer IP and port whose route is freshly proved to use Tailscale.

LanPanel does not upload, build, install, or edit application code/runtime/config. Executable, arguments, working directory, environment-file reference, and write paths are typed. Shell parsing and opaque `ExecStart` are forbidden. A published local App must be explicitly unpublished before process stop. Unpublish does not guarantee termination of an existing flow.

## Publication

`publish` is the only normal action that opens or replaces App ingress. Saving configuration, process start, connector login, Headscale deploy, restart, timer, and reconciliation never publish implicitly. Every resource starts sticky-unpublished.

Supported publication modes are:

- `domain_https` on ports 80/443, exact TLS SNI and HTTP Host, TLS 1.2/1.3, HTTP/1.1, HTTP/2, and optional WebSocket;
- test-only `temporary_ip_http` on one publicly routable IPv4 and high port, exact Host, public HTTP/1.1 only.

Temporary HTTP is public plaintext and does not expire automatically.

Access modes are `public`, `application_managed`, and `basic`. Basic may use a one-time Managed Basic password or a verified external htpasswd and may add a CIDR allowlist. Static roots are external, root-owned, read-only, no-follow trees with explicit routes. Optional GoAccess uses an isolated identity, protected endpoint, independent external Basic credential, and no raw-log browser.

Every ingress removes untrusted identity headers before rebuilding only `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` from the actual socket peer. The first release does not trust CDN identity headers.

The clean installer generates one installation-managed P-256 ACME account key atomically. Contact is configured or changed only in the authenticated Management UI and is validated again immediately before the first ACME request; it is never a command-line, log, or release-artifact input. ACME supports HTTP-01 and DNS-01 with exactly `cloudflare`, `route53`, `digitalocean`, `gcloud`, and `tencentcloud`. DNS credentials remain in protected files/profiles. Provider, CA, and source fallback are forbidden. Release notes distinguish real live-tested providers from deterministic fixture coverage.

## Closing, recovery, deletion, and export

`unpublish` durably closes one App; `close-all` durably closes all LanPanel-owned App ingress while normally preserving healthy Headscale control ingress. Sticky closure survives restart and reboot. Certificate expiry and uncertain activation contract ingress rather than retry remote work.

Closure verifies the owned disk graph, Nginx reload, prior-worker drain, and release-owned runtime rejection. If selective closure cannot be proved, LanPanel persists a stop fence and stops Nginx. Fail-closed Nginx stop may also interrupt Headscale control ingress.

Startup reconciliation may only finalize an exact existing local journal or contract ingress. It never retries ACME/provider work, logs in a connector, adopts an orphan, starts an explicitly stopped process, or reopens App ingress. Unresolved orphan/unknown state remains closed. Supported next steps are diagnostics, secret-free configuration export, and clean-host rebuild—not repair.

Plan-bound resource deletion requires fresh unpublished closure and, for local Apps, a stopped cgroup/listener. It removes only exact LanPanel-managed inventory. External executable, working directory, static root, environment file, htpasswd, and log source are never deleted.

## Explicit first-release limitations

- No in-place upgrade, same-version reinstall, dependency maintenance, updater, rollback engine, or state/schema migration.
- No supported product backup/restore, restore cutover, or cross-host migration. A manual host copy or VM snapshot is not automatically a supported recoverable backup.
- No Repair, fix-host, orphan adoption, or normalization action.
- No EdgeOne integration.
- No ARM64 GA claim, public TCP/UDP publication, SSH/RDP/VNC, containers, Kubernetes, databases, application templates, remote API, OIDC, or RBAC.

Host administrators may read their own configuration, SQLite, and data outside LanPanel. Configuration export is the supported product data-exit capability.

## Security and release

See [SECURITY.md](SECURITY.md). A release includes one Linux amd64 binary, source tag/archive, LICENSE, NOTICE, dependency manifest, public `package-template.json`, `SHA256SUMS`, and a canonical `release.json`. Preview does not publish SBOM/OSV or live-qualification evidence.
