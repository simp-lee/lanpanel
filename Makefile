.DEFAULT_GOAL := check

.PHONY: build test vet lint check tidy ga-contract-audit ga-cli-absence-audit

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
	@! git grep -I -Eq '(^|[[:space:]`])lanpanel[[:space:]]+(deploy|status|verify|init|app|ui)([[:space:]`]|$$)' -- README.md README.zh-CN.md docs cmd deploy '*.go'
	@! git grep -I -Eiq 'v1alpha|alpha migration' -- deploy
	@! git grep -I -Eiq 'internal/(cli|output|prompt)' -- '*.go' '*.md' '*.yml' '*.yaml'

check: build test vet ga-contract-audit ga-cli-absence-audit
