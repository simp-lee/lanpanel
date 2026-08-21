# GA Qualification Tooling

This tooling is for release operators; it does not add a LanPanel management CLI.

## Local deterministic gate

Run the single noninteractive gate from the repository root:

```bash
TMPDIR=/var/tmp/lanpanel-ga make ga-local-gate
```

It runs build, Go test/race/vet/lint, contract and privileged-boundary audits, pinned Chromium Playwright, vulnerability scanning, release tooling, documentation, and final-asset self-tests. A failed run does not qualify a candidate.

## Protected input

`lanpanel-qualification` accepts only an absolute, owner-only, regular file. Credential fields contain references such as `file:`, `agent:`, or `vault:`; secret values must not be put in the input, repository, plan, or cleanup report.

The protected input binds:

- exact candidate binary and source archive;
- clean tracked source root;
- immutable target profile, side-effect plan, install manifest, dependency authority, and dependency assets;
- authorized SSH host key and machine identity, ACME directory/contact/Terms approval, DNS scope, external vantage, and optional tailnet peer; cleanup policy is fixed per journey step in source and the immutable side-effect plan;
- mutable cleanup report path and owner-only final qualification-summary output path.

The immutable authority files must be owner-read-only. The protected input and mutable files must be owner-only. Parent directories for cleanup reports must be owner-only.

Before any live mutation, use:

```bash
make ga-live-qualification-preflight \
  QUALIFICATION_INPUT=/absolute/protected/qualification-input.json
```

The preflight verifies candidate, host, plan, target, dependency, Git-index/worktree, and source-archive bindings. It does not perform a live mutation.

## Ordered runner and cleanup

`internal/qualification.Runner` fixes the thirteen-step journey in source. It observes and matches every planned prior state before the first mutation, never retries a remote mutation implicitly, cleans executed mutations in reverse order, and persists a monotonic cleanup report after each terminal cleanup.

Once the trusted adapter is connected, the final command atomically writes the canonical qualification summary bound to the verified report; provider status is derived from the protected DNS provider and cannot be caller-selected.

A `delete_exact` item must end as `cleaned`. An authorized retained item may end as `retained`. The report binds the protected-input digest and gains `journey_succeeded` only after every fixed step succeeds and exact cleanup completes. Missing, rewritten, ambiguous, residual, or cleanup-only reports block readiness.

The repository currently has no trusted live-executor attestation adapter, so final readiness deliberately fails closed and cannot generate a releasable summary. After that adapter is implemented and the authorized live executor has completed the fixed journey and cleanup, verify the same bytes with:

```bash
make ga-final-release-readiness-check \
  QUALIFICATION_INPUT=/absolute/protected/qualification-input.json
```

Release publication remains disabled until an authorized live executor is connected, the full journey passes on one clean supported host, and this final check succeeds.
