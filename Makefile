.DEFAULT_GOAL := check

.PHONY: build test vet lint check tidy ga-playwright-action-boundary ga-contract-audit ga-cli-absence-audit ga-legacy-closure-audit ga-release-disabled-audit ga-helper-boundary-audit ga-release-identity-selftest ga-forbidden-utility-audit ga-preflight-contraction-integration ga-bootstrap-integration ga-nginx-contraction-integration ga-playwright-auth ga-target-readiness-integration ga-managed-process-integration ga-certificate-lifecycle-integration ga-domain-publication-integration

# S2 HEAD-derived disposition: tests inherit their package disposition; every
# legacy template/tree is deleted, while the named packages remain for their
# owning in-place GA rewrite.
GA_FOUNDATION_PACKAGES := ./cmd/lanpanel ./internal/application ./internal/archive ./internal/bootstrap ./internal/child ./internal/closure ./internal/confinement ./internal/contraction ./internal/dependencies ./internal/domain ./internal/download ./internal/filetxn ./internal/helper ./internal/helperaudit ./internal/helperproto ./internal/identity ./internal/jobs ./internal/locks ./internal/nginx ./internal/nginxguard ./internal/operations ./internal/ownership ./internal/packages ./internal/persist ./internal/plans ./internal/preflight ./internal/process ./internal/relay ./internal/release ./internal/reservations ./internal/roles ./internal/safety ./internal/secrets ./internal/session ./internal/sources ./internal/target ./internal/ui
GA_REWRITE_PACKAGES := ./internal/acme ./internal/activation ./internal/basic ./internal/certificates ./internal/challenge ./internal/htpasswdref ./internal/publication ./internal/renewal ./internal/static ./internal/realip ./internal/realip/edgeone ./internal/realiprender ./internal/resource
GA_DELETE_TREES := deploy deploy_embed.go internal/appassets internal/appconfig internal/appguard internal/apphost internal/apppreflight internal/apprender internal/appverify internal/assets internal/browserauth internal/components internal/config internal/exposure internal/host internal/hosthealth internal/hostworkflow internal/maindeploy internal/realipassets internal/render internal/sensitive internal/state internal/uistate internal/verify internal/workflow

GO ?= go
PKGS ?= ./...
GOLANGCI_LINT ?= golangci-lint
BINARY ?= lanpanel

build:
	$(GO) build -o $(BINARY) ./cmd/lanpanel

test:
	$(GO) test $(PKGS)

vet:
	$(GO) vet $(PKGS)

lint:
	$(GOLANGCI_LINT) run $(PKGS)

tidy:
	$(GO) mod tidy

ga-contract-audit:
	@test ! -d internal/qualification/cases
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'OperationRepair|RepairWriter|RoleRepair|RoleGlobalCloseRepair|repair_writer|global_close_repair|"(repair|fix_host|fix-host)"' internal cmd; then echo 'generic repair authority remains' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'ClauseID|clause_id|RowsForScope|ga-test-cases|per[_-]clause' internal cmd; then echo 'per-clause runner remains' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-cli-absence-audit:
	$(GO) test -count=1 ./cmd/lanpanel ./internal/roles
	@test ! -d internal/cli && test ! -d internal/output && test ! -d internal/prompt
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; $(GO) run ./cmd/lanpanel --help >"$$tmp"; ! grep -Eiq 'deploy|status|verify|init|app|--config|--format|json|yaml|generic|alias|migration' "$$tmp"
	@! git grep -I -Eq '(^|[[:space:]`])lanpanel[[:space:]]+(deploy|status|verify|init|app|ui)([[:space:]`]|$$)' -- README.md README.zh-CN.md docs cmd '*.go'
	@set -eu; if grep -R -n -Ei --include='*.go' --exclude='*_test.go' 'v1alpha|alpha migration' internal cmd; then echo 'alpha production schema remains' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi
	@! git grep -I -Eiq 'internal/(cli|output|prompt)' -- '*.go' '*.md' '*.yml' '*.yaml'

ga-legacy-closure-audit:
	@set -eu; for path in $(GA_DELETE_TREES); do test ! -e "$$path" || { echo "legacy path remains: $$path" >&2; exit 1; }; done
	@set -eu; actual=$$($(GO) list ./... | sed 's#^lanpanel/#./#' | sort); expected=$$(printf '%s\n' $(GA_FOUNDATION_PACKAGES) $(GA_REWRITE_PACKAGES) | sort); test "$$actual" = "$$expected" || { printf 'package disposition mismatch\nactual:\n%s\nexpected:\n%s\n' "$$actual" "$$expected" >&2; exit 1; }
	@set -eu; for path in internal/acme/doc.go internal/preflight/doc.go internal/realip/doc.go internal/realip/edgeone/doc.go internal/realiprender/doc.go internal/resource/doc.go; do grep -Fq 'GA rewrite owner:' "$$path"; done
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'ShellCommand|ActorSourceCLI|v1alpha|lanpanel\.instance\.v1|LoadOrCreateInstance|ResourceTypePrivate|AmbientCredentialsSupported|normalizeProviderAlias|ValidateDNSProviderEnvironment|SupportedDNSProviderEnvFileVars' internal cmd; then echo 'legacy schema or management shim remains' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi
	@test -z "$$(find internal cmd \( -name '*.tmpl' -o -name '*.sh' \) -type f -print)"

ga-release-disabled-audit:
	@grep -Fq 'workflow_dispatch:' .github/workflows/release.yml
	@grep -Fq 'Release publication remains disabled until the S31 final asset gate is implemented.' .github/workflows/release.yml
	@set -eu; if grep -n -E 'tags:|contents:[[:space:]]*write|arm64|gh release|attest-build-provenance|dist/' .github/workflows/release.yml; then echo 'release publication path remains enabled' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-helper-boundary-audit:
	$(GO) test -count=1 ./internal/helperaudit
	@grep -Fq 'SO_PEERCRED' internal/helper/server_linux.go
	@grep -Fq 'PR_SET_NO_NEW_PRIVS' internal/child/executor_linux.go
	@grep -Fq 'PR_CAPBSET_DROP' internal/child/executor_linux.go
	@grep -Fq 'runtime.LockOSThread' internal/child/executor_linux.go
	@grep -Fq 'setExactCapabilities' internal/child/executor_linux.go
	@grep -Fq 'validOperationTarget' internal/helperproto/types.go
	@set -eu; found=$$(grep -R -n -E --include='*.go' --exclude='*_test.go' --exclude-dir='helperaudit' '"os/exec"|exec\.Command(Context)?\(|exec\.LookPath\(|unix\.Exec\(|syscall\.Exec\(|os\.StartProcess\(' internal cmd || true); expected=$$(printf '%s\n' internal/child/executor_linux.go internal/process/managed_exec_linux.go); test -z "$$found" || test "$$(printf '%s\n' "$$found" | cut -d: -f1 | sort -u)" = "$$expected" || { printf 'external process call escaped fixed executor boundary:\n%s\n' "$$found" >&2; exit 1; }
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' --exclude-dir='helperaudit' '"([^" ]*/)?(sh|bash|dash)"|"([^" ]*/)?(sudo|doas|pkexec|su)"' internal cmd; then echo 'shell or sudo-like executable remains in production' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi
	@set -eu; if grep -n -E 'Command|Arguments|Argv|Unit|Path' internal/helperproto/types.go; then echo 'generic command, unit, argv, or path entered helper request schema' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-release-identity-selftest:
	$(GO) test -count=1 ./internal/release ./internal/dependencies
	@set -eu; if grep -R -n -Ei --include='*.go' --exclude='*_test.go' 'ed25519|signature|signing[_-]token|key[_-]id' internal/release internal/dependencies; then echo 'signing ceremony entered checksum-only release identity' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-preflight-contraction-integration:
	$(GO) test -count=1 ./internal/preflight ./internal/operations
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'sudo|doas|pkexec|su |exec\.Command|os\.StartProcess' internal/preflight; then echo 'preflight gained mutation or privilege fallback' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi
	@grep -Fq 'RequireExpansionPlanEvidence' internal/operations/operations.go
	@grep -Fq 'RequireContractionPlanEvidence' internal/operations/operations.go

ga-nginx-contraction-integration:
	$(GO) test -count=1 ./internal/nginx ./internal/nginxguard ./internal/contraction ./internal/closure ./internal/preflight ./internal/safety ./internal/ownership
	@grep -Fq 'worker_shutdown_timeout 10s' internal/nginx/graph.go
	@grep -Fq 'default_server' internal/nginx/graph.go
	@grep -Fq 'ProfileNginxStart' internal/nginxguard/role_linux.go
	@grep -Fq 'PersistStopFence' internal/contraction/engine.go
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'exec\.Command|os\.StartProcess|sudo|doas|pkexec' internal/nginx internal/nginxguard internal/contraction internal/closure; then echo 'Nginx contraction escaped fixed child authority' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-playwright-action-boundary:
	$(GO) test -count=1 ./internal/application ./internal/secrets ./internal/ui
	@grep -Fq 'action_unavailable' internal/application/catalog.go
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' '((Operation|Action|Handler|Route)(Shell|Terminal|FileBrowser|Generic(Unit|Path|Package))|"(shell|terminal|file_browser|generic_(unit|path|package))")' internal/application internal/ui; then echo 'generic action escaped typed boundary' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-playwright-auth:
	$(GO) test -count=1 ./internal/ui ./internal/session ./internal/bootstrap
	LANPANEL_CHROMIUM_PATH="$${LANPANEL_CHROMIUM_PATH:-$${HOME}/.cache/ms-playwright/chromium-1181/chrome-linux/chrome}" npm run test:auth
	@grep -Fq 'Content-Security-Policy' internal/ui/server.go
	@grep -Fq 'Cache-Control' internal/ui/server.go
	@grep -Fq 'WebSocketSubprotocol' internal/ui/server.go
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'serviceWorker|unsafe-inline|unsafe-eval|Request\.Cookie\(|FormValue\(' internal/ui; then echo 'Management browser boundary is unsafe' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-bootstrap-integration:
	$(GO) test -count=1 ./internal/bootstrap ./internal/identity ./internal/preflight ./internal/roles ./cmd/lanpanel
	@grep -Fq 'ListenStream=' internal/bootstrap/assets_linux.go
	@grep -Fq 'FileDescriptorName=lanpanel-management' internal/bootstrap/assets_linux.go
	@grep -Fq 'RequireCommitted' cmd/lanpanel/main.go
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'math/rand|localhost|0\.0\.0\.0|:8080|sudo|doas|pkexec' internal/bootstrap internal/identity; then echo 'bootstrap gained fallback randomness, authority, or privilege path' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi


ga-forbidden-utility-audit:
	$(GO) test -count=1 ./internal/sources ./internal/download ./internal/archive ./internal/packages ./internal/filetxn ./internal/child
	@grep -Fq 'PackageTransactionHandler' internal/helper/role_linux.go
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'exec\.Command(Context)?\([^\n]*(curl|wget|sha256sum|tar|unzip|openssl|install|cp|mv|rm|ln|chmod|chown)' internal cmd; then echo 'forbidden download, archive, hash, TLS, or file utility remains' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' '"/[^"[:space:]]*/(curl|wget|sha256sum|tar|unzip|openssl|install|cp|mv|rm|ln|chmod|chown)"' internal cmd; then echo 'forbidden fixed child utility entered production profile' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-target-readiness-integration:
	$(GO) test -count=1 ./internal/target ./internal/resource
	@grep -Fq 'CheckRedirect' internal/target/readiness.go
	@grep -Fq 'Sec-WebSocket-Accept' internal/target/readiness.go

ga-temporary-publication-integration:
	$(GO) test -count=1 ./internal/publication ./internal/activation ./internal/preflight ./internal/target ./internal/nginx ./internal/application

ga-certificate-lifecycle-integration:
	$(GO) test -count=1 ./internal/acme ./internal/challenge ./internal/certificates ./internal/renewal ./internal/operations ./internal/nginx ./internal/application ./internal/helper
	@grep -Fq 'ProfileLego' internal/child/profiles_linux.go
	@grep -Fq 'CertificateRenewHandler' internal/helper/role_linux.go
	@grep -Fq 'ObserveExclusiveCurrentCgroup' internal/helper/role_linux.go
	@! grep -Fq 'RoleCertificateStage' internal/identity/accounts_linux.go
	@! grep -Fq 'unix.Mount' internal/acme/staging_linux.go
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'tls-alpn-01|exec\.Command|os\.StartProcess|openssl' internal/acme internal/challenge internal/certificates internal/renewal; then echo 'certificate lifecycle escaped closed ACME authority' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-domain-publication-integration:
	$(GO) test -count=1 ./internal/basic ./internal/htpasswdref ./internal/static ./internal/publication ./internal/nginx ./internal/activation ./internal/application ./internal/helper ./internal/target
	@grep -Fq 'PrepareDomain' internal/publication/prepare.go
	@grep -Fq 'ManagedBasicGenerateHandler' internal/helper/role_linux.go
	@grep -Fq 'disable_symlinks on' internal/nginx/graph.go
	@grep -Fq 'proxy_set_header Authorization " + authorization' internal/nginx/graph.go
	@grep -Fq 'MaximumInputBytes: 72' internal/child/profiles_linux.go
	@set -eu; if grep -R -n -E --include='*.go' --exclude='*_test.go' 'auth_basic_user_file[[:space:]]+\$|alias[[:space:]]+\$|htpasswd.*-b' internal/basic internal/htpasswdref internal/static internal/nginx; then echo 'domain publication escaped typed auth/static authority' >&2; exit 1; else rc=$$?; test $$rc -eq 1 || exit $$rc; fi

ga-managed-process-integration:
	$(GO) test -count=1 ./internal/process ./internal/relay ./internal/confinement ./internal/identity ./internal/application ./internal/helper
	@grep -Fq 'KillMode=control-group' internal/process/units_linux.go
	@grep -Fq 'SocketBindDeny=any' internal/confinement/policy_linux.go
	@grep -Fq 'PR_SET_NO_NEW_PRIVS' internal/process/managed_exec_linux.go

check: build test vet ga-contract-audit ga-cli-absence-audit ga-legacy-closure-audit ga-release-disabled-audit ga-helper-boundary-audit ga-release-identity-selftest ga-preflight-contraction-integration ga-bootstrap-integration ga-nginx-contraction-integration ga-target-readiness-integration ga-temporary-publication-integration ga-managed-process-integration ga-certificate-lifecycle-integration ga-domain-publication-integration ga-playwright-auth ga-playwright-action-boundary ga-forbidden-utility-audit
