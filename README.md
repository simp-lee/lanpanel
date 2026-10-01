# LanPanel

[English](https://github.com/simp-lee/lanpanel/blob/main/README.md) | [简体中文](https://github.com/simp-lee/lanpanel/blob/main/README.zh-CN.md)

LanPanel is a self-hosted Linux host manager for individuals and mutually trusted small teams. It uses a browser to manage application processes, network ingress, and an optional trusted network. It does not upload, build, or modify your application code.

> **Current status: Preview.** This release is intended for evaluation and testing. It is not a claim of production readiness, high availability, or complete qualification.

## Is LanPanel right for you?

| Your goal | Fit |
| --- | --- |
| Manage applications and network ingress on one Linux host through a browser | Yes |
| Use official Tailscale clients to join a private trusted network | Yes; LanPanel can manage the optional Headscale control plane. LanPanel itself is not a VPN client |
| Configure Headscale, Nginx, certificates, and service lifecycle on one host | Yes; this is the main trusted-network use case |
| Publish a same-host HTTP/WebSocket application over HTTPS | Yes, with `local_http` |
| Publish an HTTP/WebSocket service on a fixed trusted-network node | Yes, with `tailnet_http` and a verified Tailscale connector |
| Publish only a local application without creating a Headscale network | Yes; use `local_http` without Headscale or Tailscale |
| Get a server terminal, file manager, general-purpose management CLI, or a generic VPN client | No; day-to-day management uses the Management UI |
| Build multi-host HA, container/Kubernetes hosting, database hosting, OIDC/RBAC, or public TCP/UDP forwarding | No; these are outside the current scope |

## Quick start

### 1. Prepare the host

The current release supports Linux amd64 (x86_64) hosts that satisfy the signed Host Capability Contract:

- `systemd` as PID 1, complete unified cgroup v2 with `cgroup.kill`, and effective systemd delegation;
- `apt/dpkg` with a healthy package database and a signed APT candidate for Nginx (minimum `1.18.0`);
- root or usable `sudo` access;
- an APT mirror with signature verification enabled and a healthy package state;
- enough disk space and available ports.

Before changing the host, the installer checks the capability contract, packages, ports, filesystem, and Nginx ownership/configuration. The distribution name and release number are not compatibility allowlists. Other architectures, hosts without the required capabilities, and hosts that fail these checks are unsupported.

Installation does not require ACME or DNS operations in advance. You only need a domain, DNS, and the relevant 80/443 network access when you later publish a domain-based HTTPS application.

Choose the additional preparation for the feature you plan to use:

| Scenario | Additional preparation |
| --- | --- |
| Management UI or local app without domain publication | No Headscale or public DNS is required for the initial installation |
| Domain-based HTTPS application | A public domain resolving to the ingress and reachable 80/443; configure the ACME contact later in the UI |
| Headscale trusted network | A public control domain, reachable 80/443, and `3478/udp` for STUN; clients join with the official Tailscale client |
| Tailnet application | A verified local Tailscale connector and a fixed HTTP/WebSocket upstream on the trusted network |

### 2. Install

Download the Preview package for the host from [GitHub Releases](https://github.com/simp-lee/lanpanel/releases), extract it, and run this command from the package directory:

```sh
sudo ./lanpanel install
```

This is the only public installation entry point. Do not provide a bundle path, digest, package plan, dependency path, or ACME contact. The installer discovers the release materials and verifies the manifest, signature, complete checksums, fixed third-party dependencies, and host conditions before mutation; verification failure stops the installation.

You can also use the version-pinned Bootstrap published on the official release page. Replace `<tag>` with an actual Preview tag; do not use `latest`:

```sh
curl -fL https://github.com/simp-lee/lanpanel/releases/download/<tag>/lanpanel-bootstrap.sh \
  -o /tmp/lanpanel-bootstrap.sh &&
sudo /tmp/lanpanel-bootstrap.sh install
```

Bootstrap verifies the release archive's SHA-256 in a protected temporary directory and then invokes the same `install` flow. It does not pipe downloaded content to a shell and has no third-party download fallback. System packages still come from the host's own APT mirror with signature verification enabled; do not disable repository signature checks or use `--allow-unauthenticated`.

### Nginx package ownership and bundled GoAccess

- On a fresh installation, if a compatible host Nginx is already installed, the interactive installer asks whether to reuse it. The package remains host-owned; LanPanel preserves it, stops and masks `nginx.service`, and runs its own closed ingress configuration through the packaged Nginx binary.
- If the existing Nginx version is outside the signed capability range, or has an unsafe systemd override, installation stops without package mutation. Remove or repair it and rerun the installer.
- If an exact LanPanel installation already owns Nginx, an interrupted transaction resumes only from its durable journal. Replaying the same signed release is idempotent; uninstall never removes the host-owned Nginx package.
- GoAccess is carried in the signed release as a fixed amd64 binary at `/usr/lib/lanpanel/dependencies/goaccess`. The installer never installs, upgrades, or removes a system GoAccess package and never uses `/usr/bin/goaccess`.

The signed Host Capability Contract is not an Ubuntu/Debian version allowlist. A release carries one generic `linux-amd64-apt-dpkg-systemd` contract per supported architecture, not a separate profile for every distro release. The profile capture is a reference authority for the signed APT plan; for distro-repository packages with version bounds, the target host's own signed APT candidate is installed and checked against those bounds. Do not add distro-version branches or package profiles to the release just because the host is Ubuntu 24.04, Debian 12, or Debian 13. Test representative capability-qualified hosts instead. An explicit external-Nginx choice removes Nginx from the transaction and validates the host package by the signed Nginx capability range.

### 3. Open the Management UI

The installer prints an installation-specific `127/8` address and high port, and creates an administrator token. With a TTY, the token is shown once; without a TTY, only the path to a root-protected token file is shown. Save it as instructed.

The Management UI listens only on the local loopback interface and is not directly exposed to the public internet. For remote administration, use an SSH tunnel to the **exact address and port** printed by the installer; do not replace it with `localhost`:

```sh
ssh -N -L 8080:<address shown by the installer>:<port shown by the installer> <user>@<host>
```

Then open `http://127.0.0.1:8080` in a browser on your computer. There is no CLI, terminal, shell, or file manager for day-to-day application management. The UI runs as a non-root process; privileged operations cross a protected typed helper boundary.

## Daily use

- **Applications:** `local_http` manages a confined non-root HTTP/WebSocket process on this host; `tailnet_http` reaches a fixed remote node over a verified Tailscale route. LanPanel does not upload, build, install, or edit application code.
- **Ingress:** `domain_https` provides HTTPS on ports 80/443; test-only `temporary_ip_http` uses public plaintext HTTP on a high port and does not expire automatically.
- **Access control:** supports anonymous (`public`), application-managed (`application_managed`), and Basic (`basic`) access. Basic can use a one-time managed password or an external `htpasswd` file, with an optional CIDR restriction.
- **Static content and logs:** supports external static directories and optional GoAccess. GoAccess uses its own access credentials and does not provide a raw-log browser.
- **Trusted network:** Headscale is optional and manages at most one trusted network domain with MagicDNS and embedded DERP/STUN. It can manage users, one-time pre-authentication keys, and devices. Clients remain official Tailscale clients for Windows, macOS, and Debian/Ubuntu Linux; LanPanel manages at most one Tailscale connector.

`publish` is the only normal operation that opens or replaces application ingress. Saving configuration, starting a process, logging in to the connector, restarting, and background reconciliation do not publish implicitly. `unpublish` and `close-all` persistently close ingress; closing an ingress, expiring a device, or revoking a pre-authentication key does not guarantee immediate termination of already-established connections.

Domain HTTPS uses HTTP-01 or DNS-01 with Cloudflare, Route53, DigitalOcean, Google Cloud, or Tencent Cloud. For DNS-01, enter the exact provider code `cloudflare`, `route53`, `digitalocean`, `gcloud`, or `tencentcloud` in the Management UI. Set the ACME contact in the authenticated Management UI; it is checked again before the first certificate request and is not requested during installation or written to command-line arguments or logs.

The Management UI does not provide remote process control for `tailnet_http`: it stores a fixed peer/source/port and observes connector, route, and target evidence before publication. It does not deploy files, run a remote shell, or promise to terminate an existing remote service. Unpublish, device expiry, and pre-authentication-key revocation prevent new normal-path use where applicable, but existing TCP/WebSocket connections may persist; LanPanel does not promise immediate termination.

For repeatable browser checks, the repository provides a fixture-only gate. From a checkout, prepare Node dependencies and the pinned Chromium browser, then run `make playwright-fixture-gate` (`npm ci`, followed by `npx playwright install chromium`). The fixture uses in-memory typed resources, status, probes, Jobs, and side-effect counters; it does not qualify real persistence, Nginx, processes, DNS, ACME, Tailscale, or remote commands.

## Runtime topology

LanPanel is the management layer, not a Tailscale client. The following diagrams show where traffic goes:

### Management UI

```text
Your browser
    | SSH tunnel to the exact installer address and port
    v
Management UI (loopback only, non-root)
    | protected typed helper
    v
LanPanel-managed services and state
```

### Same-host application

```text
Public user
    | HTTP/HTTPS :80/:443
    v
Nginx (TLS, Host/SNI and access control)
    | protected local target
    v
Non-root application process on this host
```

The application port is not public. `domain_https` is the normal production-style path; `temporary_ip_http` is a test-only plaintext path on a high port.

### Tailnet application and Headscale

```text
Public user -- HTTP/HTTPS :80/:443 --> Nginx -- local app or Tailscale connector --> fixed peer

Tailscale clients -- HTTPS :443 --> Nginx --> Headscale control plane
Tailscale clients -- HTTPS :443 --> Nginx --> embedded DERP (when direct peer paths fail)
Tailscale clients -- UDP :3478 ---------------------------> Headscale STUN
```

Headscale and the Tailscale connector are optional. Without them, a local application can still be published through Nginx. With them, clients use the official Tailscale client and the connector reaches only the verified fixed upstream.

## Join the trusted network (optional)

This section applies only when Headscale is enabled. LanPanel is not a VPN client; clients use the official Tailscale client version `1.74.0` or newer.

The platform differences are intentional: Windows uses the installed PowerShell executable, macOS can use the menu-bar app or its bundled CLI, and Debian/Ubuntu uses the `tailscaled` system service with privileged commands run through `sudo`.

Before clients join, complete these two steps in the Management UI:

1. Initialize the Headscale identity with a control domain and a MagicDNS namespace. These identities cannot be changed or removed after initialization.
2. Deploy the Headscale control ingress. Choose HTTP-01 or DNS-01, enter the ACME directory URL and contact, accept the ACME terms, and provide the DNS provider profile and zone when DNS-01 is selected. Wait for this operation to complete successfully.

For each client:

1. Create a user and a one-time pre-authentication key in the Management UI. The key is shown only once; create a separate short-lived key for each device.
2. Install the official Tailscale client for your platform.
3. Replace `hs.example.com` and `<preauth-key>` in one of the platform examples below, then join the control domain with managed DNS enabled.

#### Windows PowerShell

Install Tailscale `1.74.0` or newer from <https://tailscale.com/download/windows>. On a recent Windows system, you can install it with WinGet. Run the custom login-server commands from an Administrator PowerShell:

```powershell
winget install --id Tailscale.Tailscale --exact
```

Then run:

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" version
& "$env:ProgramFiles\Tailscale\tailscale.exe" up --login-server https://hs.example.com --auth-key "<preauth-key>" --accept-dns=true --hostname=laptop
& "$env:ProgramFiles\Tailscale\tailscale.exe" status
& "$env:ProgramFiles\Tailscale\tailscale.exe" ping peer-name.tailnet.example.com
& "$env:ProgramFiles\Tailscale\tailscale.exe" netcheck
```

To leave the network or reconnect later:

```powershell
& "$env:ProgramFiles\Tailscale\tailscale.exe" down
& "$env:ProgramFiles\Tailscale\tailscale.exe" up --login-server https://hs.example.com --accept-dns=true
```

#### macOS

Install Tailscale `1.74.0` or newer from <https://tailscale.com/download/mac>. The standalone app is the usual choice and can add the `tailscale` command through **Settings → CLI integration**. For the Mac App Store app, the following block uses its bundled CLI directly:

```sh
TAILSCALE="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
"$TAILSCALE" version
"$TAILSCALE" up --login-server https://hs.example.com --auth-key "<preauth-key>" --accept-dns=true --hostname=laptop
"$TAILSCALE" set --hostname="laptop"
"$TAILSCALE" status
"$TAILSCALE" ping peer-name.tailnet.example.com
"$TAILSCALE" netcheck
```

To leave the network or reconnect later (this block is standalone):

```sh
TAILSCALE="/Applications/Tailscale.app/Contents/MacOS/Tailscale"
"$TAILSCALE" down
"$TAILSCALE" up --login-server https://hs.example.com --accept-dns=true
```

You can also complete the same login from the Tailscale menu-bar application. If CLI integration is enabled for the standalone app, replace `"$TAILSCALE"` with `tailscale`.

#### Debian/Ubuntu Linux

Install Tailscale `1.74.0` or newer from the official Linux package source and check the `tailscaled` system service:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
tailscale version
systemctl status tailscaled --no-pager --full
sudo tailscale up --login-server https://hs.example.com --auth-key "<preauth-key>" --accept-dns=true --hostname=laptop
sudo tailscale set --hostname="laptop"
tailscale status
tailscale ping peer-name.tailnet.example.com
tailscale netcheck
```

To leave the network or reconnect later:

```bash
sudo tailscale down
sudo tailscale up --login-server https://hs.example.com --accept-dns=true
```

4. Verify that the device appears in the Management UI, then use `tailscale status`, `tailscale ping <peer>`, and `tailscale netcheck` to verify connectivity.

The Headscale control domain uses HTTPS through Nginx; embedded DERP uses the HTTPS path when direct peer connectivity is unavailable, and STUN uses `3478/udp`. Expiring a device or revoking a key does not guarantee that existing connections end immediately.

For a `tailnet_http` application, configure the host connector in the Management UI after the control plane is ready: set its binding to the Headscale control URL, log in with a separate one-time pre-authentication key, and run connector verification. The connector must be verified before a fixed trusted-network upstream can be published.

## Uninstall and data export

After a committed installation, the only public uninstall entry point is:

```sh
sudo lanpanel uninstall
```

Before uninstalling, LanPanel shows the managed scope and requires the exact interactive confirmation `UNINSTALL LANPANEL`. It removes only files, services, accounts, and state that can be verified as LanPanel-owned. It does not remove APT/dpkg packages or external application executables, working directories, static directories, environment files, `htpasswd` files, or log sources.

Use the secret-free configuration export when you need to take product configuration out of the host. It is not a product backup. A manual host copy or VM snapshot is not automatically a supported and recoverable backup.

## Preview limitations

- Clean installation only for a new host; no in-place release upgrade, dependency updater, rollback engine, or state/schema migration. Replaying the same signed release after a committed installation is idempotent; package ownership rules above still apply.
- No supported product backup/restore, restore cutover, or cross-host migration. A manual host copy or VM snapshot is not automatically a supported recoverable backup.
- No generic Repair, host repair, orphan adoption, or automatic normalization.
- No EdgeOne integration in Preview.
- No connector disconnect, logout, reset, rejoin, or rebind automation. Connector mismatches must be resolved outside LanPanel.
- Without an independent remote authority, Tailnet HTTP/WebSocket is reported as not live tested.
- Key revoke does not expire a registered device.
- Unpublish, device expiry, and pre-authentication key revocation do not guarantee termination of existing flows.
- Temporary public HTTP is plaintext and does not expire automatically.
- Preview does not claim hardened GA, complete audit coverage, live qualification, or complete reproducible-release guarantees.
- Fail-closed Nginx stop can interrupt Headscale control ingress.

## Developers

See the [developer guide](https://github.com/simp-lee/lanpanel/blob/main/docs/DEVELOPING.md) for development, testing, and Preview release workflows.

## License

LanPanel is released under the MIT License; see `LICENSE`.
