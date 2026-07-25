# LanPanel Management UI E2E

These Playwright specs are release-gate tooling for the local Management UI.
They are not part of the product runtime and are not required by `go test ./...`
or `make check`.

Run the full local P0 release gate:

```bash
make p0-release-gate
```

Run only the compact Management UI smoke gate:

```bash
make e2e
```

The Makefile starts `internal/ui/testserver` on `127.0.0.1:18080`, writes
temporary main/app configs, UI state, and a managed browser-auth root, captures
the one-time startup URL for Playwright, runs the specs, and then stops the
server. Use `E2E_ADDR` when that port is already busy:

```bash
E2E_ADDR=127.0.0.1:18081 make e2e
```

Walkthroughs are part of the release gate. The all-walkthrough target runs one
journey per testserver instance so each spec gets a fresh startup token and
isolated temp state, including the special fixtures required by individual
journeys:

```bash
make e2e-walkthrough-all
```

Run a single journey while developing:

```bash
make e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/ui-bootstrap-security.spec.ts
```

Journeys with special fixtures:

```bash
E2E_TESTSERVER_FLAGS=-preseed-configs=false \
  make e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/first-run-config-init-flow.spec.ts

E2E_TESTSERVER_FLAGS=-slow-main-deploy=3s \
  make e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/jobs-history-redaction-recovery.spec.ts
```

Each walkthrough writes durable evidence under
`.agents-work/60-verification/browser/walkthroughs/<journey-id>/`.

The specs cover the P0 browser gate basics: startup-token session exchange,
local embedded htmx, no CDN script, htmx fragment submission, CSRF rejection,
resource-first configuration saves, access-mode validation failures, exposure
decision tables, one-time Headscale preauth handoff, job polling/history,
RealIP, GoAccess, service, certificate/Nginx, read-only host health, and
migration boundary pages. Browser installation is managed by a pinned Playwright
version outside the LanPanel release binary; override `E2E_PLAYWRIGHT_VERSION`
only when intentionally updating the gate.
