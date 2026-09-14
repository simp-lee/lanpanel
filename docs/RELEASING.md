# Preview release workflow

The Preview platform contract is Debian or Ubuntu amd64 with systemd, cgroup v2, APT/dpkg, required package ranges, writable managed paths, available disk space, no required-port conflicts, and successful runtime probes. The release verifier rejects other distribution families or architectures. A release number is recorded for diagnostics and profile capture, but is not the compatibility gate; unknown future Debian or Ubuntu releases enter preflight and continue only when all checks pass. Before capturing OS inputs, run `make check-preview-profile-host PREVIEW_PROFILE_TARGET=debian` or `ubuntu`; this is a read-only capability check. The host may use any authenticated mirror that supplies the required packages.

This document is for release maintainers. `scripts/generate-preview-bootstrap.sh` is a release-time generator; it is not the bootstrap script that users download, and it does not build or upload a release artifact.

Resolve the latest stable third-party assets only when intentionally changing dependency versions:

```sh
make resolve-preview-dependencies PREVIEW_DEPENDENCY_DIR="$PWD/dist/dependencies"
```

The resolver verifies upstream checksums and writes `dependency-inputs.json`; review and commit the lock snapshot in `release-inputs/dependency-inputs.v1.json`. For an ordinary code release, materialize the committed lock without querying `latest`:

```sh
make materialize-preview-dependencies \
  PREVIEW_DEPENDENCY_LOCK="$PWD/release-inputs/dependency-inputs.v1.json" \
  PREVIEW_DEPENDENCY_DIR="$PWD/dist/dependencies"
```

`make release-preview` performs this deterministic materialization automatically before building the artifact. The GitHub release workflow calls `make release-preview`, so CI does not require a separate manual materialization step. `resolve` is the only dependency step intended to be manual: it intentionally discovers upstream updates and changes the reviewed lock. Build the complete release directory and package it as the outer release archive. The repository provides `scripts/package-preview-release.sh` and the corresponding Make target to automate this step. The archive must contain the official artifact directory (`lanpanel`, `release.json`, checksums, and all manifest-declared assets). This outer archive is distinct from the source archive listed inside `release.json`.

For a prepared artifact directory, run:

```sh
make package-preview-release \
  PREVIEW_VERSION=v1.2.3-preview \
  PREVIEW_ARTIFACT_DIR=dist/release \
  PREVIEW_DOWNLOAD_BASE_URL=https://github.com/simp-lee/lanpanel/releases/download/v1.2.3-preview \
  PREVIEW_OUTPUT_DIR=dist/releases
```

The command creates the deterministic outer archive, calculates its SHA-256 digest, and generates `lanpanel-bootstrap.sh`. It does not upload files or materialize dependencies; use `make release-preview` for the complete automated build path. The output can then be published by the release provider's CI action.

After the dependency lock is resolved, the shared artifact builder can assemble and locally verify the complete release directory. It requires a clean worktree whose `HEAD` is exactly the requested release tag; this prevents an untagged or dirty binary/source archive from entering a release:

```sh
go run ./cmd/lanpanel-release \
  --tag v1.2.3-preview \
  --source . \
  --dependency-inputs dist/dependencies/dependency-inputs.json \
  --manifest-template release-inputs/release-manifest.template.json \
  --package-template release-inputs/package-template.json \
  --dependency-baseline release-inputs/dependency-baseline.json \
  --signing-key "$LANPANEL_RELEASE_SIGNING_KEY" \
  --output dist/release
```

The read-only capture command records the host's package version floors and profile facts after the host has been qualified:

```sh
make check-preview-profile-host PREVIEW_PROFILE_TARGET=debian
make capture-preview-profile \
  PREVIEW_PROFILE_ID=debian-amd64 \
  PREVIEW_PROFILE_OUTPUT_DIR=release-inputs/profiles/debian-amd64 \
  PREVIEW_DEPENDENCY_INPUTS=dist/dependencies/dependency-inputs.json
```

Run the same command with `PREVIEW_PROFILE_TARGET=ubuntu` and `PREVIEW_PROFILE_ID=ubuntu-amd64` on an Ubuntu host. It writes `os-profile.json`, `package-template-<profile-id>.json`, and `dependency-baseline-<profile-id>.json` without mutating the host. The capture records package version requirements; APT source selection remains the user's responsibility.

The manifest template contains one entry per supported OS profile. Each entry carries its own package template, dependency manifest, and dependency baseline identity. The package and baseline inputs are supplied as `package-template-<profile-id>.json` and `dependency-baseline-<profile-id>.json` in `--profile-input-dir`. The inputs must be reviewed for the selected Debian or Ubuntu target before publication. Dependency manifests are generated from the locked dependency inputs unless an explicit reviewed template is supplied. The assembled directory can be checked independently with `scripts/verify-preview-release.sh dist/release`; packaging invokes this check and rejects undeclared or missing files before creating the outer bundle.

Release manifests are authenticated with the installer-trusted Ed25519 key. Keep the private key outside the repository (the GitHub workflow reads the `LANPANEL_RELEASE_PRIVATE_KEY_B64` secret) and provide it to the builder as `--signing-key`; never commit or print it.

The underlying generator can also be called directly when only the bootstrap needs to be regenerated:

```sh
scripts/generate-preview-bootstrap.sh \
  v1.2.3-preview \
  https://github.com/simp-lee/lanpanel/releases/download/v1.2.3-preview/lanpanel-v1.2.3-preview-linux-amd64.tar.gz \
  <64-lowercase-hex-sha256> > lanpanel-bootstrap.sh
chmod 755 lanpanel-bootstrap.sh
```

The outer archive contains `release.json.sig` with the artifact. Publish the archive and `lanpanel-bootstrap.sh` at the URLs shown to users; direct installation verifies the signature against the embedded public trust anchor. With the default GitHub provider, run:

```sh
make publish-preview-github \
  PREVIEW_TAG=v1.2.3-preview \
  PREVIEW_OUTPUT_DIR=dist/releases
```
 The script embeds the release URL and archive digest, downloads the archive, verifies it before extraction, and invokes the artifact's `install` command. The artifact's canonical manifest, complete checksum inventory, and dependency authorities are then verified by the LanPanel binary.

The packaging script validates the artifact directory contains the executable and required authority files, rejects symlinks and special files, and produces stable archive metadata. The generator validates the fixed preview version format, HTTPS artifact URL, and SHA-256 format. `scripts/publish-preview-github.sh` is the GitHub adapter: it creates a draft release, verifies uploaded bytes, publishes it, and then verifies the public URLs. It never overwrites an existing release. The local and CI orchestrator should invoke the same signing, packaging, and local-verification logic and then call this adapter when GitHub publishing is requested.
