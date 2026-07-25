#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

release_surface=(
  README.md
  README.zh-CN.md
  Makefile
  .github
  deploy
  docs
  e2e
  scripts
)

fail() {
  printf 'p0-static-audit: %s\n' "$*" >&2
  exit 1
}

require_match() {
  local description="$1"
  shift
  if ! rg -q "$@"; then
    fail "missing required check: ${description}"
  fi
}

reject_match() {
  local description="$1"
  shift
  local output
  local status
  set +e
  output=$(rg -n "$@" 2>&1)
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf '%s\n' "$output" >&2
    fail "forbidden match: ${description}"
  fi
  if [ "$status" -ne 1 ]; then
    printf '%s\n' "$output" >&2
    fail "rg failed while checking: ${description}"
  fi
}

reject_release_match() {
  local description="$1"
  shift
  reject_match "$description" --glob '!scripts/p0-static-audit.sh' "$@" "${release_surface[@]}"
}

reject_backup_files() {
  local output
  output=$(
    find . \
      \( -path ./.git -o -path ./node_modules -o -path ./dist -o -path ./coverage \) -prune \
      -o -type f \
      \( -name '*.bak' -o -name '*.orig' -o -name '*.rej' -o -name '*~' \) \
      -print
  )
  if [ -n "$output" ]; then
    printf '%s\n' "$output" >&2
    fail "forbidden backup or rejected patch file"
  fi
}

reject_backup_files

require_match "local htmx asset reference" '<script src="/static/vendor/htmx/htmx\.min\.js"></script>' internal/ui/server.go
reject_match "remote htmx script in UI product code" --glob '*.go' --glob '!**/*_test.go' '<script[^>]+src="https?://|https?://(cdn\.jsdelivr|unpkg|jsdelivr|cdn)[^[:space:]]*htmx' internal/ui

require_match "loopback listen validation" 'func ValidateLoopbackAddr' internal/ui/server.go
require_match "Management UI startup security note" 'Security: loopback-only management UI; use SSH local forwarding; do not expose this port; startup token is one-time and expires\.' internal/cli/ui.go scripts/e2e-production-ui-smoke.sh
require_match "non-loopback E2E release gate" 'rejects non-loopback listen addresses before serving' e2e/specs/management-ui.spec.ts
require_match "production UI smoke in P0 release gate" 'p0-release-gate:.*e2e-production-ui-smoke' Makefile
require_match "production UI smoke starts real CLI" '"\$binary" ui' scripts/e2e-production-ui-smoke.sh
require_match "release workflow installs htpasswd dependency" 'apache2-utils' .github/workflows/release.yml
reject_release_match "public Management UI listen suggestion" 'lanpanel ui[^\n]*(--listen|-listen)[ =]*(0\.0\.0\.0|\[::\]|::|203\.|198\.51\.100\.|192\.0\.2\.)'
reject_release_match "weakened Management UI loopback-only wording" '不建议 UI 监听|not recommended[^[:cntrl:]]*(Management UI|UI)[^[:cntrl:]]*(listen|bind)'
reject_release_match "full startup token URL in release surface" '/login\?token=[A-Za-z0-9%_.~-]+'
reject_release_match "raw Headscale or Tailscale auth key in release surface" '(hskey-auth|tskey-auth|authkey-)[A-Za-z0-9_.~-]{8,}'
reject_release_match "machine key in release surface" 'mkey:[A-Za-z0-9_.~-]{8,}'
reject_release_match "HTTP Basic credential in release surface" 'Authorization:[[:space:]]*Basic[[:space:]]+[A-Za-z0-9+/=]{12,}'
reject_release_match "Bearer credential in release surface" 'Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{12,}'
reject_release_match "Cookie credential in release surface" 'Cookie:[[:space:]]*[^[:space:];=]+=[^[:space:];]{8,}'
reject_release_match "bcrypt htpasswd hash in release surface" '\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}'
reject_release_match "URL userinfo credential in release surface" '[A-Za-z][A-Za-z0-9+.-]*://[^[:space:]/:@]+:[^[:space:]@]+@'
reject_release_match "direct cloud or auth secret assignment in release surface" '(TENCENTCLOUD_SECRET_ID|TENCENTCLOUD_SECRET_KEY|TENCENTCLOUD_SESSION_TOKEN|CF_DNS_API_TOKEN|CLOUDFLARE_DNS_API_TOKEN|DO_AUTH_TOKEN|DIGITALOCEAN_ACCESS_TOKEN|TAILSCALE_AUTH_KEY|EDGEONE_SECRET|BROWSER_PASSWORD)[[:space:]]*='
reject_match "full startup token URL in product output paths" --glob '*.go' --glob '!**/*_test.go' '/login\?token=[A-Za-z0-9%_.~-]+' internal/cli internal/domain internal/output internal/uistate internal/workflow
reject_match "e2e testserver startup token URL stdout" 'fmt\.[A-Za-z]+\([^)]*startupURL|fmt\.[A-Za-z]+\([^)]*StartupURL\(' internal/ui/testserver
require_match "Playwright trace disabled for startup-token gate" "trace: 'off'" e2e/playwright.config.ts
reject_match "Playwright trace retention with startup-token gate" "trace: '(retain-on-failure|on|on-first-retry)'" e2e/playwright.config.ts

reject_match "P1 private_client UI write path" --glob '!**/*_test.go' --glob '!testserver/**' 'private_client' internal/ui
reject_match "commercial identity UI write path" --glob '!**/*_test.go' --glob '!testserver/**' 'OIDC|SSO|RBAC|commercial|account' internal/ui

require_match "browser auth proxy/static gate in Nginx template" 'auth_basic "Lanpanel Browser";' deploy/templates/app/nginx.conf.tmpl
require_match "browser mode clears upstream Authorization header" 'proxy_set_header Authorization "";' deploy/templates/app/nginx.conf.tmpl
require_match "browser auth delete active reference test" 'TestBrowserAuthDeleteRejectsActiveNginxReference' internal/ui/server_test.go
require_match "browser auth delete staged reference test" 'TestBrowserAuthDeleteRejectsStagedNginxReference' internal/ui/server_test.go

reject_match "implicit app deploy Headscale preauth creation" 'CreatePreAuthKey|NewOnboardingPlan|NewOnboarding|preauthkeys create' internal/cli/app.go
require_match "app deploy explicit auth material failure" 'app deploy does not create Headscale preauth keys' internal/cli/app.go internal/cli/root_test.go
require_match "explicit preauth handoff workflow" 'func RunPreAuthKeyCreate' internal/workflow/operations.go
require_match "one-time preauth/browser secret carrier" 'OneTimeSecret' internal/workflow/operations.go

require_match "job record secret rejection" 'job record must not contain secrets' internal/uistate/store.go
require_match "workflow result secret marker rejection" 'workflow result contains secret marker' internal/workflow/operations.go
require_match "central sensitive redaction covers auth key markers" 'tskey-auth|hskey-auth' internal/sensitive/sensitive.go
require_match "stored text redaction uses central sensitive redactor" 'sensitive\.RedactText' internal/uistate/store.go

require_match "P0 no export manifest page copy" 'No machine-readable export manifest' internal/ui/server_test.go docs/p0-migration.md
reject_match "unsupported diagnostic enum constants outside P0 schema" --glob '!scripts/p0-static-audit.sh' 'DiagnosticScope(Host|Job)|DiagnosticEvidence(StagedFile|Unavailable|NotApplicable)|DiagnosticResponsible(Admin|Provider|Host|None)' internal scripts
reject_match "legacy preflight diagnostics formatter output contract" --glob '!scripts/p0-static-audit.sh' 'DiagnosticsFormatter|NewDiagnosticsFormatter|WritePreflight|WriteReport\(.*preflight\.Report|diagnosticsEnvelope' internal scripts

printf 'p0-static-audit: passed\n'
