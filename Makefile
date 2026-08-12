.DEFAULT_GOAL := check

.PHONY: build test vet lint check tidy ga-contract-audit ga-cli-absence-audit ga-legacy-closure-audit ga-release-disabled-audit ga-helper-boundary-audit ga-release-identity-selftest ga-forbidden-utility-audit ga-preflight-contraction-integration ga-bootstrap-integration

# S2 HEAD-derived disposition: tests inherit their package disposition; every
# legacy template/tree is deleted, while the named packages remain for their
# owning in-place GA rewrite.
GA_FOUNDATION_PACKAGES := ./cmd/lanpanel ./internal/archive ./internal/bootstrap ./internal/child ./internal/dependencies ./internal/domain ./internal/download ./internal/filetxn ./internal/helper ./internal/helperaudit ./internal/helperproto ./internal/identity ./internal/jobs ./internal/locks ./internal/operations ./internal/ownership ./internal/packages ./internal/persist ./internal/plans ./internal/preflight ./internal/release ./internal/reservations ./internal/roles ./internal/safety ./internal/sources
GA_REWRITE_PACKAGES := ./internal/acme ./internal/realip ./internal/realip/edgeone ./internal/realiprender ./internal/resource
GA_DELETE_TREES := deploy deploy_embed.go internal/appassets internal/appconfig internal/appguard internal/apphost internal/apppreflight internal/apprender internal/appverify internal/assets internal/browserauth internal/components internal/config internal/exposure internal/host internal/hosthealth internal/hostworkflow internal/maindeploy internal/realipassets internal/render internal/sensitive internal/state internal/ui internal/uistate internal/verify internal/workflow

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
	@set -eu; found=$$(grep -R -n -E --include='*.go' --exclude='*_test.go' --exclude-dir='helperaudit' '"os/exec"|exec\.Command(Context)?\(|exec\.LookPath\(|unix\.Exec\(|syscall\.Exec\(|os\.StartProcess\(' internal cmd || true); test -z "$$found" || test "$$(printf '%s\n' "$$found" | cut -d: -f1 | sort -u)" = 'internal/child/executor_linux.go' || { printf 'external process call escaped child boundary:\n%s\n' "$$found" >&2; exit 1; }
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

check: build test vet ga-contract-audit ga-cli-absence-audit ga-legacy-closure-audit ga-release-disabled-audit ga-helper-boundary-audit ga-release-identity-selftest ga-preflight-contraction-integration ga-bootstrap-integration ga-forbidden-utility-audit
