# LanPanel development and release inputs

This document is for contributors and release maintainers. End users should read [INSTALLING.md](INSTALLING.md).

## Normal development

Run the quality gate before committing:

```sh
make check
```

Do not commit downloaded binaries, `dist/` output, release bundles, bootstrap files, GitHub tokens, or signing keys. Third-party binaries are fetched into the ignored `dist/dependencies` directory only during release resolution.

## Profile capture

Each supported distribution family has a package/profile contract; release numbers are recorded as capture facts, not compatibility gates. On a clean host using a working authenticated APT configuration, first run:

```sh
make check-preview-profile-host PREVIEW_PROFILE_TARGET=debian
```

Then resolve the third-party lock and capture the host:

```sh
make resolve-preview-dependencies PREVIEW_DEPENDENCY_DIR="$PWD/dist/dependencies"
make capture-preview-profile \
  PREVIEW_PROFILE_ID=debian-amd64 \
  PREVIEW_PROFILE_OUTPUT_DIR=release-inputs/profiles/debian-amd64 \
  PREVIEW_DEPENDENCY_INPUTS=dist/dependencies/dependency-inputs.json
```

Use `ubuntu-amd64` for Ubuntu captures. The capture command is read-only: it reads APT candidates from the host's configured mirror and writes canonical OS/package version requirements and the strict third-party dependency baseline. It does not capture or bind a particular APT URI, keyring, or repository snapshot.

Qualify at least one clean host for each distribution family, and repeat on additional releases before declaring them tested. Review the generated files before committing them as release inputs. Ordinary Go code changes reuse these inputs; recapture only when the supported OS or package requirements change.

## Building a release locally

The shared local/CI orchestrator performs these phases:

1. `resolve`: intentionally query upstream latest stable releases and update the reviewed lock. This is a manual, deliberate upgrade operation.
2. `materialize`: download only the exact URLs/digests in the reviewed lock. `make release-preview` runs this automatically; it never queries `latest`.
3. `package/local-verify`: build Linux amd64, create the source archive, generate family manifests and checksums, and verify the complete inventory.
4. `upload` (optional): publish the outer bundle and bootstrap through the provider adapter.
5. `post-upload-verify`: re-download public assets and verify their bytes and bootstrap binding.

For local step-by-step work, `make materialize-preview-dependencies` must be run before `make build-preview-artifact` or `make package-preview-release`. The one-command release path is `make release-preview`; the GitHub Actions workflow uses that same path, so CI performs materialization automatically.

For a multi-profile release, the manifest template contains one profile entry per supported target. Each entry names its package template, dependency manifest, and dependency baseline. The same LanPanel binary and third-party runtime assets may be shared.

The release builder requires a clean worktree and an exact Git tag. It writes only to ignored output directories. `SHA256SUMS` excludes itself and `release.json`; the bootstrap binds the final outer archive with its SHA-256 digest.

## GitHub publishing

To refresh third-party versions, run `make resolve-preview-dependencies` and review the lock diff. For an ordinary code release, do not run materialization separately when using `make release-preview`; it is already included. If testing the steps separately, use `make materialize-preview-dependencies PREVIEW_DEPENDENCY_DIR=dist/dependencies`; this is deterministic and does not query upstream release metadata.

The GitHub adapter is optional and is not part of local artifact construction:

```sh
make publish-preview-github \
  PREVIEW_TAG=v1.2.3-preview \
  PREVIEW_OUTPUT_DIR=dist/releases
```

It uses `gh`, creates a draft release, verifies uploaded assets, publishes the release, then verifies the public HTTPS URLs. It refuses to overwrite an existing tag. Authentication must come from local `gh` credentials or protected CI permissions.

## Input and output locations

- `release-inputs/`: reviewed, versioned authority inputs only.
- `dist/dependencies/`: ignored downloaded third-party archives and extracted executables.
- `dist/release/`: ignored assembled artifact directory.
- `dist/releases/`: ignored deterministic outer bundle and generated bootstrap.
- `.github/workflows/release-preview.yml`: CI entry point using the same Make orchestrator.
