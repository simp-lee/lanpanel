# Preview release inputs

This directory contains versioned release authority inputs, not downloaded third-party binaries. The release platform contract is Debian or Ubuntu amd64; release numbers are capture facts and are not the compatibility gate. Unknown future releases are admitted to preflight and must pass all capability and functional checks.

`dependency-inputs.v1.json` is the reviewed dependency lock for the current resolve result. The archive and executable files named by that lock are produced by `scripts/resolve-preview-dependencies.sh` in a separate, ignored build directory.

The family inputs are generated and reviewed from a clean Debian or Ubuntu amd64 environment. Run `make capture-preview-profile` after qualifying the host; it emits the family profile, package template, and dependency baseline for that family:

- `release-manifest.template.json`
- `dependency-manifest.template.json` (optional; generated from the dependency lock when omitted)
- `package-template-<profile-id>.json`
- `dependency-baseline-<profile-id>.json`

They contain the captured OS identity for diagnostics, systemd/Nginx compatibility floors, package version ranges, and the managed-confinement profile for the selected distribution family. The release no longer binds a particular APT mirror; users may use their own authenticated APT sources. The release builder validates the profile and strict third-party asset bindings.
