.DEFAULT_GOAL := preview-local-gate

.PHONY: build test vet lint race preview-local-gate check tidy docs-build

GO ?= go
BINARY ?= lanpanel
PKGS ?= ./...
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_VERSION := 2.11.3

build:
	$(GO) build -o $(BINARY) ./cmd/lanpanel

test:
	$(GO) test -count=1 $(PKGS)

vet:
	$(GO) vet $(PKGS)

lint:
	@command -v $(GOLANGCI_LINT) >/dev/null || { echo 'pinned golangci-lint is required' >&2; exit 1; }
	@set -eu; $(GOLANGCI_LINT) version 2>&1 | grep -Eq '^golangci-lint has version $(GOLANGCI_LINT_VERSION)([[:space:]]|$$)'; $(GOLANGCI_LINT) run $(PKGS)

race:
	$(GO) test -race -count=1 $(PKGS)

preview-local-gate: test vet lint race

check: preview-local-gate

tidy:
	$(GO) mod tidy

docs-build:
	@test -f README.md && test -f README.zh-CN.md && test -f docs/README.md
	@grep -Fq 'sudo ./lanpanel install' README.md README.zh-CN.md docs/README.md
	@grep -Fq 'sudo lanpanel uninstall' docs/README.md
	@! grep -Eq 'lanpanel installer --bundle-dir|--release-digest|--acme-account-contact' README.md README.zh-CN.md docs/README.md
	@! grep -Eq 'source_kind|mirror_url|offline_path|proxy_url' docs/README.md
