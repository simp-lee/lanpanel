# GA Qualification Tooling

This tooling is for release operators. It does not add a supported LanPanel management CLI. The installed binary exposes only fixed, unsupported qualification-agent and fixture roles used by the protected harness.

## Local deterministic gate

From a clean exact commit:

```bash
TMPDIR=/var/tmp/lanpanel-ga make ga-local-gate
```

The gate runs build, Go test/race/vet/lint, contract and privileged-boundary audits, pinned Chromium Playwright, vulnerability scans, release tooling, documentation, and final-asset self-tests. A failed run does not qualify a candidate.

## Protected references

Never put a password, token, auth key, private key, host address, or credential value in the repository, side-effect plan, cleanup report, release assets, or an issue/chat message.

Supported SSH credential references are:

- `file:/absolute/owner-only/unencrypted-ed25519-key`; or
- `agent:/absolute/owner-only/socket#sha256:<exact-public-key-digest>`.

The harness does not read ambient `SSH_AUTH_SOCK`, proxy variables, cloud credentials, `known_hosts`, or SSH configuration. `vault:` references remain fail-closed until a concrete resolver exists. SSH requires the exact root `IPv4:port`, a pinned raw SHA-256 host-key digest, and the independently recorded `host_<32-hex>` machine fingerprint. Root passwords and `StrictHostKeyChecking=no` are forbidden.

The first live DNS adapter is Cloudflare. Its reference is `file:/absolute/owner-only/token`; the token file contains only the token and no newline. Scope it to the authorized disposable zone with the minimum Zone Read/DNS Edit permissions. Other providers retain deterministic coverage and are reported `not_live_tested`.

A direct external-vantage reference is an owner-read-only canonical JSON file:

```json
{"schema_version":"lanpanel.qualification.direct-vantage.v1","expected_source_ipv4":"198.51.100.10"}
```

Use the actual independently verified public source address, not this documentation address. It must differ from the target host. Public probes connect directly from the harness host, disable proxies and redirects, pin the target IP/Host/SNI, verify the public trust chain, and prove header sanitization from the echoed source IP.

## Generate immutable artifacts

Create an owner-only generation input outside the repository. Its schema is `lanpanel.qualification.generation-input.v1` and includes:

- exact release tag, clean commit OID, source root, and new output directory;
- live-observed `release.OSProfile` and exact distro package transaction template;
- canonical dependency authority and every exact dependency asset;
- clean-host bootstrap inventory digest;
- pinned SSH authority, ACME directory/contact/Terms approval, DNS authority, and external vantage reference;
- one fixed journey specification (`lanpanel.qualification.journey-spec.v2`) containing the public IPv4, temporary port, App/alias/Headscale/MagicDNS/DNS-01 domains, authoritative zone, and optional tailnet domain.

The package template contains repository/package/source/time bounds but leaves run/manifest/preflight identity to the harness. At mutation time the candidate agent performs a fresh read-only package preflight; the harness binds that result, the immutable profile, manifest, plan, candidate, closure, and host into the installer authority.

The generator requires exact Go 1.26.6, builds one `linux/amd64` candidate with networking disabled for module resolution, generates the canonical source archive, verifies all dependency bytes, and atomically creates a private artifact directory:

```bash
make ga-generate-qualification-artifacts \
  QUALIFICATION_GENERATION_INPUT=/absolute/protected/generation-input.json
```

The generated `side-effect-plan.json`, profile, journey specification, install manifest, package-template digest binding, dependency authority/assets, SBOM, candidate, and source archive are owner-read-only. `qualification-input.json` binds their exact paths and digests. The cleanup report, executor attestation, summary, and live state do not exist yet.

Before mutation, inspect the complete immutable `side-effect-plan.json`. It explicitly lists all thirteen fixed steps, human-readable scope/prior/action/selector, exact digests, and fixed `delete_exact|retain_authorized` policy. Do not authorize the run if any host, IP, domain, provider, record, package, or retained object is unexpected.

## Read-only live preflight

```bash
make ga-live-qualification-preflight \
  QUALIFICATION_INPUT=/absolute/protected/run/qualification-input.json
```

Preflight requires a clean exact source revision, verifies candidate/source/dependency/profile/plan/manifest bindings, connects with the pinned SSH host key, reads machine identity and platform through SFTP/fixed read-only commands, and recomputes the clean bootstrap inventory. It performs no product mutation.

## Run and cleanup

After explicit human authorization:

```bash
make ga-run-live-journey \
  QUALIFICATION_INPUT=/absolute/protected/run/qualification-input.json
```

The trusted executor:

1. uploads the exact candidate and assets to one run-scoped root-owned staging directory;
2. performs fresh package preflight and qualification-mode clean installation;
3. exercises real Management login/session/WebSocket and restart;
4. runs the fixed local HTTP/WebSocket fixture, temporary HTTP, domain HTTPS, public/application-managed/Basic, CIDR, static, and GoAccess cases;
5. completes App and Headscale HTTP-01 issuance and public trust probes;
6. exercises Headscale user/key/device and one `--auth-key=file:` connector login;
7. runs tailnet HTTP/WebSocket only when an independent peer authority is supplied;
8. performs real Cloudflare DNS-01 issuance and exact TXT cleanup;
9. exercises diagnostics/export/jobs, deletion, sticky close, secret sentinel, and an observed reboot;
10. cleans run-owned resources/records/files, verifies retained installation/Headscale authority, and writes final inventory evidence.

The runner observes each prior state immediately before mutation. Every attempt, passed/failed/unknown result, evidence digest, and cleanup identity is persisted monotonically. Cleanup has fixed deadlines and runs in reverse order. A resumed nonterminal run is cleanup-only: remote mutations are never replayed and the run can never become successful. Re-image the host before a new run.

The clean installation, Headscale identity/entities, connector binding/device, final retained inventory, and Headscale DNS record are explicitly retained. Other journey objects must be exactly cleaned. Ambiguous DNS, staging, fixture, process, listener, credential, or secret residue blocks the candidate.

## Final readiness and release bundle

Only a report with all thirteen steps `passed`, exact cleanup policy satisfied, `execution_failed:false`, and a matching immutable `lanpanel-trusted-live-executor-v1` attestation can become successful:

```bash
make ga-final-release-readiness-check \
  QUALIFICATION_INPUT=/absolute/protected/run/qualification-input.json
```

This writes the canonical qualification summary once. Provider and tailnet claims are derived from executor results, not caller-selected summary fields.

Prepare an owner-read-only canonical security report matching `lanpanel.release.security-report.v2`, including distro package, Go binary, and SBOM scanner/feed identities. It must bind the exact `candidate_digest`, `sbom_digest`, `dependency_manifest_digest`, and `target_profile_digest`, and must be no more than seven days old when the bundle is finalized. Then create an owner-only `lanpanel.release.finalize-input.v1` containing the qualification input, security report, exact tag/commit, and a new output directory:

```bash
make ga-finalize-release \
  RELEASE_FINALIZE_INPUT=/absolute/protected/release-finalize-input.json
```

Finalization reuses the exact qualified candidate/source/dependency/SBOM bytes and the limitations from the qualified source archive, creates one `SHA256SUMS` and one canonical `release.json`, runs the complete offline release/security/qualification verifier, and atomically commits a read-only bundle. It does not rebuild the candidate.

Release publication remains fail-closed until one authorized real journey succeeds and the resulting exact bundle is independently reviewed. Do not enable or push the release workflow merely because deterministic tests pass.
