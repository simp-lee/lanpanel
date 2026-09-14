# Installing LanPanel Preview

This is the user-facing installation guide. Release construction and publishing are documented in [RELEASING.md](RELEASING.md).

## Supported systems

The Preview release supports Debian or Ubuntu Linux amd64 hosts. The installer does not use a fixed distribution release as its compatibility proof. It admits a host family first, then requires the package ranges, runtime capabilities, filesystem checks, port checks, and generated Nginx configuration to pass before mutation.

Other distributions, derivatives, and architectures are rejected before host mutation. Unknown future Debian or Ubuntu releases may enter preflight and continue only when every required capability and functional check passes.

## Install from a downloaded release

Extract the official release archive, enter its directory, and run:

```sh
sudo ./lanpanel install
```

Do not add bundle paths, release digests, package plans, dependency paths, or ACME contact arguments. The binary discovers its release directory and verifies the canonical manifest, complete checksums, selected Debian/Ubuntu family profile, package version requirements, and bundled third-party assets before mutation. System packages are installed from the host's configured authenticated APT mirror; LanPanel does not require a particular mirror.

## Install using the GitHub bootstrap

Use the exact tag URL shown on the official GitHub Release page. Replace `<tag>` with a published release tag; do not use `latest`:

```sh
curl -fL https://github.com/simp-lee/lanpanel/releases/download/<tag>/lanpanel-bootstrap.sh \
  -o /tmp/lanpanel-bootstrap.sh &&
sudo /tmp/lanpanel-bootstrap.sh install
```

The bootstrap downloads one fixed release archive, verifies its embedded SHA-256 digest before extraction, and invokes the same `./lanpanel install` flow. It does not pipe downloaded data to a shell and does not fall back to third-party download sites.

## After installation

The installer prints the installation-specific loopback Management UI address and high port. For remote administration, use an SSH tunnel to that exact `127/8` address and port. The installer creates an admin token; display and storage behavior depends on whether an attached TTY is available.

ACME contact is configured later in the authenticated Management UI. It is not an installation command-line argument.

## Uninstall

The supported uninstall entry point is:

```sh
sudo lanpanel uninstall
```

Uninstall requires an interactive confirmation of exactly `UNINSTALL LANPANEL`. It removes only verified LanPanel-owned state and does not automatically remove shared APT packages or user application files.

APT must remain authenticated; do not disable repository signature checks or use `--allow-unauthenticated`. The selected mirror must provide packages within the required version ranges. LanPanel is not responsible for the trust or availability of a user-managed mirror.

## Preview boundaries

Preview provides basic installation integrity, signed repository checks, package range checks, and runtime capability probes, bundled dependency verification, and transaction cleanup. It does not claim hardened GA status, complete audit coverage, live qualification, in-place upgrade, rollback, migration, backup/restore, or ARM64 support.
