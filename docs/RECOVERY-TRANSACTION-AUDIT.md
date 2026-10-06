# Recovery transaction audit

This is the checkpoint-level audit for the installation and Management HTTPS
transactions. A process stop is treated as a crash at the last durable
checkpoint; recovery may only finish or contract the identity recorded there.
It must never infer a new certificate, pointer, graph entry, package set, or
Safety generation.

## Bootstrap and resume

| Checkpoint | Durable authority before the next side effect | Recovery result |
| --- | --- | --- |
| `prepared` journal | Signed release identity, host observation, management authority, preflight and package input digests | Re-validate the exact release, paths, host preflight, package input, and owned residue; no installed authority is exposed. |
| `nginx_masked` | The package transaction identity and masked-service boundary | Reconcile the exact package journal or fail closed; foreign package transactions and residue are rejected. |
| `packages_committed` | Completed package journal bound to the plan and release | Reuse only the exact cleaned package journal, then continue the recorded bundle transaction. |
| `bundle_committed` | Installation bundle and ACME account-key fingerprint | Re-verify the bundle, key fingerprint, release identity, and ownership before account/store work. |
| `accounts_submitted` / `accounts_verified` | Exact installation account set and submission result | Verify the recorded accounts; partial or foreign account state stops recovery. |
| `stores_initialized` / `assets_installed` | Normal, Safety, ownership, systemd, helper, Nginx, and dependency asset identities | Verify every recorded path and digest; retry only the missing exact side effect. |
| `committed` | Final commit digest, artifact inventory, ownership inventory, startup authority | Re-read and verify all three authorities before activation. |
| `activated` | Startup authority and activated journal bound to the same commit | Idempotently replay the same release only. A different signed release, binary, profile, dependency, or host identity is rejected. |

The public resume path re-verifies the current signed bundle and rebinds its
asset paths to the recorded journal. Empty-vs-absent serialized slices are
normalization differences, not authority changes; immutable release fields
remain exact matches.

## Management HTTPS issuance and renewal

The transaction is ordered as follows:

1. persist typed pending configuration and its exact ACME binding;
2. persist the operation intent, child identity, and certificate journal;
3. commit the Safety challenge authority;
4. install and audit the exact HTTP-01/DNS-01 challenge graph;
5. complete the child and prove the issued bundle identity;
6. persist the active certificate journal **before** pointer activation;
7. activate the candidate pointer and verify the candidate bundle;
8. commit normal configuration as `active` with the same certificate identity;
9. install and audit the exact Management Nginx entry;
10. commit independent Safety active-certificate and entry authority;
11. reload or start Nginx, then verify the served certificate fingerprint;
12. terminalize the journal and complete the Job.

| Crash boundary | Durable state on restart | Recovery decision |
| --- | --- | --- |
| Before the challenge Safety commit | Pending configuration only | No challenge is trusted; the next issue attempt may begin after normal preflight. |
| After challenge commit, before child completion | Exact pending challenge and graph | Prove the same Host, token, key-authorization digest, generation, webroot, and marker snapshot; remove/contract only that challenge. DNS cleanup requires a fresh owner-lock and TXT preflight. |
| After child completion, before activation journal | Exact child result and challenge authority | Reject a missing or changed child/bundle; no pointer mutation is inferred. |
| After activation journal, before pointer activation | Candidate bundle and pointer identity are journaled | Activate only the journaled candidate. A mismatch is a fail-closed recovery error. |
| After pointer activation, before normal configuration | Candidate pointer and bundle exist; normal config is pending | Finish the exact pending candidate activation, or contract it for first issuance. Renewal never silently replaces the prior bundle. |
| After normal `active` configuration, before Safety commit | Normal graph authority names the candidate | Rebuild the exact entry and commit Safety only if the challenge, pointer, bundle, generation, and binding all match. |
| After Safety commit, before graph/reload | Independent Safety says whether ingress is allowed | Install/audit the exact graph, then reload/start only through the guarded authority. |
| After graph mutation, before reload | Disk graph is exact but runtime may be stale | Guarded reload/start re-audits graph, Safety, normal configuration, ownership, certificate pointer, Host/SNI, and expiry. |
| After reload/start, before served-certificate probe | Runtime is serving an unproven candidate | The served fingerprint probe is mandatory. Failure stops Nginx and leaves recovery authority durable. |
| After served probe, before terminal journal | Runtime and all durable identities agree | Retry only journal terminalization and Job completion; no certificate or pointer change is needed. |

Renewal uses the same candidate journal with a prior generation/pointer. If a
renewal stops before activation, recovery restores the prior pointer and
removes only the journaled inactive candidate. If candidate normal configuration
is already committed, recovery follows the activation path instead of rolling
back a candidate that is already the exact active authority.

## Expiry and contraction

Certificate expiry is an independent Safety deadline. At or after its deadline,
contraction first establishes the stop fence, verifies the independent
certificate authority, removes the exact Management graph entry, commits the
closed normal/Safety state, and only then performs cleanup. Concurrent expiry
workers cannot mutate the Management graph without winning the stop fence.
An interrupted Nginx contraction is recovered from its journal and candidate
manifest; a terminal contraction receipt must be acknowledged before any
unrelated graph mutation.

## Local executable coverage

The local Linux suite now exercises guarded reload/start success and failure
checkpoints, exact served-certificate fingerprint probing, persisted expiry
intent replay after restart, reserved-intent rejection, candidate identity
binding, and independent Safety marker snapshots. `make nginx-https-integration`
uses a temporary extracted Nginx package, while `make pebble-dns01` uses pinned
Pebble/challtestsrv/Lego tooling; both clean their temporary roots and
processes. These checks do not replace public ACME staging/provider or
installed-host validation.

## Final conclusion

The safe terminal states are limited to:

- exact active pointer + active normal configuration + active Safety + audited
  graph + served-certificate proof; or
- exact closed/contracted state with no trusted Management graph.

Any missing, conflicting, stale, or unproven checkpoint remains closed and is
reported for recovery rather than repaired by inference. The real-Nginx test
(`TestManagementHTTPSRenderedGraphServesThroughRealNginx`) validates TLS
certificate serving plus Host/SNI rejection and Management proxy headers when
Nginx is available; it uses only temporary configuration, certificates, ports,
and upstreams.
