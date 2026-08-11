.DEFAULT_GOAL := check

.PHONY: build test vet lint check tidy ga-test-cases ga-test-cases-selftest ga-cli-absence-audit

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

ga-test-cases:
	@test -n "$(SCOPE)" || { echo "SCOPE must name one exact implementing step" >&2; exit 2; }
	$(GO) run ./internal/qualification/cases/cmd/ga-test-cases -scope "$(SCOPE)" -go "$(GO)" -- $(PKGS)

ga-test-cases-selftest:
	$(GO) test -count=1 ./internal/qualification/cases
	$(GO) run ./internal/qualification/cases/cmd/ga-test-cases -scope S1 -go "$(GO)" -- ./internal/domain ./internal/reservations ./internal/qualification/cases >/dev/null

ga-cli-absence-audit:
	$(GO) test -count=1 ./cmd/lanpanel ./internal/roles
	@test ! -d internal/cli && test ! -d internal/output && test ! -d internal/prompt
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; $(GO) run ./cmd/lanpanel --help >"$$tmp"; ! grep -Eiq 'deploy|status|verify|init|app|--config|--format|json|yaml|generic|alias|migration' "$$tmp"
	@! git grep -I -Eq '(^|[[:space:]`])lanpanel[[:space:]]+(deploy|status|verify|init|app|ui)([[:space:]`]|$$)' -- README.md README.zh-CN.md docs cmd deploy '*.go'
	@! git grep -I -Eiq 'v1alpha|alpha migration' -- deploy
	@! git grep -I -Eiq 'internal/(cli|output|prompt)' -- '*.go' '*.md' '*.yml' '*.yaml'

check: build test vet ga-cli-absence-audit
