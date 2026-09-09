# GA Qualification Tooling

This tooling is for release operators. It does not add a supported LanPanel management CLI. The installed binary exposes only fixed, unsupported qualification-agent and fixture roles used by the protected harness.

## Local deterministic gate

From a clean exact commit:

```bash
TMPDIR=/var/tmp/lanpanel-ga make ga-local-gate
```

The gate runs build, Go test/race/vet/lint, contract and privileged-boundary audits, pinned Chromium Playwright, online source vulnerability checks, release tooling, documentation, and final-asset self-tests. A failed run does not qualify a candidate. These source checks are developer feedback only; they do not replace the fixed-feed exact-candidate release scan below.

The ordinary local gate may run as a non-root developer and therefore is not evidence for real ownership/identity transitions. Fourteen protected-source, certificate-pointer/deletion, bpffs-confinement, installation-authority, and Nginx-worker traversal tests are mandatory in both test and race modes. The `Mandatory isolated root identity tests` CI job runs them on a fresh GitHub-hosted Linux VM and fails on any skip or missing pass. To reproduce it, use only an authorized disposable Linux host with bpffs mounted at `/sys/fs/bpf` and no existing `/sys/fs/bpf/lanpanel` or `/var/lib/lanpanel/certificates`:

```bash
sudo --preserve-env=PATH make ga-root-required-tests
```

Never run this target on an installed or shared host. A non-root run, an isolation-precondition failure, or a skip is not passing evidence.

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

The generated `side-effect-plan.json`, profile, journey specification, install manifest, package-template digest binding, dependency authority/assets, SBOM, candidate, and source archive are owner-read-only. `qualification-input.json` binds their exact paths and digests and fixes the future `security-report.json` path. The cleanup report, executor attestation, qualification summary, security report, and live state do not exist yet.

Before mutation, inspect the complete immutable `side-effect-plan.json`. It explicitly lists all thirteen fixed steps, concrete observed-state predicates, provider/object scope, exact selectors, every effect in each compound mutation, exact digests, and fixed `delete_exact|retain_authorized` policy. Runtime-assigned IDs use named result references (for example, the local resource ID); a later step may use a reference only after the executor freshly resolves it to one exact remote object matching the frozen selector. Do not authorize the run if any host, IP, domain, provider, record, package, effect, cleanup disposition, or retained object is unexpected.

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

The runner observes each prior state immediately before mutation. It reconstructs scope, mutation, and selector authority from protected inputs and constructs prior-state comparison bytes from fresh SSH/SFTP, Management inventory, Headscale inventory, and DNS-provider observations; it never returns plan text as an observation. Any digest mismatch stops before submission. Every attempt, passed/failed/unknown result, bounded canonical observation payload, evidence digest, and cleanup identity is persisted monotonically in the protected cleanup report. The payloads are directly readable JSON: they include the exact candidate/profile and freshly observed install/final package tuple, public HTTPS URL/status/TLS version/certificate fingerprint/SAN/expiry, ACME method and directory, DNS provider/challenge owner/TXT absence, before/after boot IDs, and final retained/absent inventory. They contain digests rather than response bodies or credentials. Cleanup has fixed deadlines and runs in reverse order. A resumed nonterminal run is cleanup-only: remote mutations are never replayed and the run can never become successful. Re-image the host before a new run.

The clean installation, Headscale identity/entities, connector binding/device, exact Headscale certificate pointer and bundle, final retained inventory, and Headscale DNS record are explicitly retained. Every App HTTP-01/DNS-01 certificate ID, generation, and bundle identity is recorded in protected run state. Cleanup removes those exact active pointers and bundles only after their resources are unpublished and deleted; final host inventory requires the retained Headscale pointer and bundle to be the complete certificate inventory. Other journey objects must be exactly cleaned. Ambiguous DNS, staging, fixture, process, listener, certificate, credential, or secret residue blocks the candidate. A successful terminal cleanup report and executor attestation are sealed owner-read-only; final readiness rejects a writable report, unreadable observation, changed observation digest, package tuple drift, missing public-trust certificate metadata, changed retained-certificate identity, unchanged boot ID, or incomplete provider/authoritative TXT cleanup.

## Final readiness and release bundle

Only a sealed report with all thirteen steps `passed`, exact cleanup policy satisfied, `execution_failed:false`, reviewable observations matching the selected host/profile/candidate, and a matching immutable `lanpanel-trusted-live-executor-v1` attestation can become successful:

```bash
make ga-final-release-readiness-check \
  QUALIFICATION_INPUT=/absolute/protected/run/qualification-input.json
```

This writes the canonical public qualification summary once. It contains only the same-binary/source/profile identity and qualification status needed by the release contract; the readable cleanup report, executor attestation, immutable plan, and protected inputs remain private harness artifacts and are not linked from the summary. Give those protected artifacts to the authorized independent reviewer through the approved out-of-repository channel; a summary alone is not live-run evidence. Provider and tailnet claims are derived from executor results, not caller-selected summary fields.

Prepare fixed local feed snapshots outside the repository for the Go vulnerability database, the complete SBOM OSV database, and the qualified distro's OSV-compatible advisory database. The Go path is a `vuln.go.dev`-format tree (including `index/db.json`); each OSV path is the cache root above `osv-scanner/<ecosystem>/all.zip`. The complete-SBOM root must include every ecosystem represented in the SBOM (`Go` and the qualified distro), while the distro root must include the named Debian or Ubuntu advisory export. Seal every feed directory owner-only and read-only; it may contain only regular files and directories. Record its canonical closure digest with:

```bash
go run ./cmd/lanpanel-qualification database-digest /absolute/protected/feed-directory
```

Create an owner-only `lanpanel.qualification.security-scan-input.v1`. It contains the generated `qualification-input.json`; absolute paths and SHA-256 byte digests for regular, executable, non-group/world-writable copies of the exact `govulncheck` 1.1.4 and `osv-scanner` 2.0.3 executables; and `name`, absolute `path`, canonical directory `digest`, and UTC `captured_at` for each of the three fixed databases. Each feed capture and the resulting report are valid for at most seven days. No scanner may update a feed during this step.

The same input also requires `repository_snapshot`: absolute `keyring` and `in_release` file paths, plus `indexes`, an array of `{ "release_path": "main/binary-amd64/Packages", "path": "/absolute/protected/Packages" }` locators. These files must be owned by the harness user and sealed mode `0400`. Supply the **exact qualified repository snapshot**, not today's repository or the scanning host's installed-package data. Index files contain uncompressed Packages bytes; an existing APT LZ4 index can be exported with `/usr/lib/apt/apt-helper cat-file /path/to/index.lz4 > /absolute/protected/Packages` before sealing. The scanner verifies the keyring/InRelease digests and signature, signed index checksums, cutoff, and every binary name/version/architecture/SHA-256/size against the already-bound package template. Source names and versions come only from those signed stanzas, including Debian's `Source` field defaults; missing or conflicting mappings fail.

Each fixed distro archive may contain multiple releases. The harness derives a temporary cache by keeping only `affected` entries for the profile's exact release (Debian numeric release; Ubuntu numeric release with optional `Pro`/`LTS` labels). It rejects release-less/ambiguous entries and archives with no selected-release evidence. This filtering is applied separately to both scan feeds, without changing either sealed snapshot.

Run the release scan independently when reviewing the candidate:

```bash
make ga-release-vulnerability-scan \
  SECURITY_SCAN_INPUT=/absolute/protected/security-scan-input.json
```

The command verifies scanner bytes and versions and runs `govulncheck` in binary/symbol mode against the exact qualified candidate with the fixed local Go database. For OSV, it derives a private SPDX document from the qualified public SBOM: Go/native identities remain unchanged; distro binaries map to their signed source names/versions, with shared sources deduplicated. It scans that complete derived document and its distro-only subset offline against the respective release-scoped feeds. The public SBOM, its binary package tuples/checksums, and the report's original SBOM digest remain unchanged. Scanner output must enumerate the entire expected derived package closure; an omitted package, changed candidate/SBOM/feed, online resolution, malformed output, or unresolved high/critical finding fails closed. The command directly writes and seals canonical `security-report.json` (`lanpanel.release.security-report.v3`) at the path already bound by `qualification-input.json`; it records exact artifact bindings, scanner executable digests, feed names/digests/capture times, scan UTC, and findings.

Then create an owner-only `lanpanel.release.finalize-input.v2` containing the qualification input, the exact security-scan input path, exact tag/commit, and a new output directory. The mandatory final target re-executes that bound fixed-feed scan before finalization and reads the generated report directly:

```bash
make ga-finalize-release \
  RELEASE_FINALIZE_INPUT=/absolute/protected/release-finalize-input.json
```

Finalization requires the report to bind the exact `candidate_digest`, `sbom_digest`, `dependency_manifest_digest`, and `target_profile_digest` and to be no more than seven days old. It directly re-runs the terminal cleanup and executor-attestation readiness checks, then reuses the exact qualified candidate/source/dependency/SBOM bytes and the limitations from the qualified source archive, creates one `SHA256SUMS` and one canonical `release.json`, runs the complete offline release/security/qualification verifier, and atomically commits a read-only bundle. Detailed scanner output, cleanup, and attestation artifacts are not published. It does not rebuild the candidate.

Release publication remains fail-closed until one authorized real journey succeeds, the protected report/attestation/plan are independently reviewed, and every asset listed by the finalizer is present in the resulting exact bundle and verifies against its single `release.json` and `SHA256SUMS`. Do not enable or push the release workflow merely because deterministic tests pass; no repository fixture or generated example is acceptable live evidence.
