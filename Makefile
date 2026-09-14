.DEFAULT_GOAL := preview-local-gate

.PHONY: build test vet lint race preview-local-gate check tidy docs-build check-preview-profile-host capture-preview-profile resolve-preview-dependencies materialize-preview-dependencies build-preview-artifact package-preview-release publish-preview-github release-preview

GO ?= go
BINARY ?= lanpanel
PKGS ?= ./...
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_VERSION := 2.11.3
PREVIEW_PROFILE_TARGET ?= debian
PREVIEW_DEPENDENCY_LOCK ?= release-inputs/dependency-inputs.v1.json

export PREVIEW_DEPENDENCY_LOCK PREVIEW_PROFILE_TARGET PREVIEW_PROFILE_ID PREVIEW_PROFILE_OUTPUT_DIR PREVIEW_TAG PREVIEW_SOURCE_DIR PREVIEW_DEPENDENCY_INPUTS PREVIEW_DEPENDENCY_DIR PREVIEW_MANIFEST_TEMPLATE PREVIEW_DEPENDENCY_TEMPLATE PREVIEW_PACKAGE_TEMPLATE PREVIEW_BASELINE PREVIEW_PROFILE_INPUT_DIR PREVIEW_SIGNING_KEY PREVIEW_ARTIFACT_DIR PREVIEW_DOWNLOAD_BASE_URL PREVIEW_OUTPUT_DIR PREVIEW_VERSION

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

check-preview-profile-host:
	@scripts/check-preview-profile-host.sh "$${PREVIEW_PROFILE_TARGET}"

capture-preview-profile:
	@test -n "$${PREVIEW_PROFILE_ID}" && test -n "$${PREVIEW_PROFILE_OUTPUT_DIR}" && test -n "$${PREVIEW_DEPENDENCY_INPUTS}" || { echo 'PREVIEW_PROFILE_ID, PREVIEW_PROFILE_OUTPUT_DIR, and PREVIEW_DEPENDENCY_INPUTS are required' >&2; exit 2; }
	@$(GO) run ./cmd/lanpanel-profile-capture --output "$${PREVIEW_PROFILE_OUTPUT_DIR}" --profile-id "$${PREVIEW_PROFILE_ID}" --dependency-inputs "$${PREVIEW_DEPENDENCY_INPUTS}"

resolve-preview-dependencies:
	@test -n "$${PREVIEW_DEPENDENCY_DIR}" || { echo 'PREVIEW_DEPENDENCY_DIR is required' >&2; exit 2; }
	@scripts/resolve-preview-dependencies.sh "$${PREVIEW_DEPENDENCY_DIR}"

materialize-preview-dependencies:
	@test -n "$${PREVIEW_DEPENDENCY_LOCK}" && test -n "$${PREVIEW_DEPENDENCY_DIR}" || { echo 'PREVIEW_DEPENDENCY_LOCK and PREVIEW_DEPENDENCY_DIR are required' >&2; exit 2; }
	@scripts/materialize-preview-dependencies.sh "$${PREVIEW_DEPENDENCY_LOCK}" "$${PREVIEW_DEPENDENCY_DIR}"

build-preview-artifact:
	@test -n "$${PREVIEW_TAG}" && test -n "$${PREVIEW_SOURCE_DIR}" && test -n "$${PREVIEW_DEPENDENCY_INPUTS}" && test -n "$${PREVIEW_MANIFEST_TEMPLATE}" && test -n "$${PREVIEW_SIGNING_KEY}" && test -n "$${PREVIEW_ARTIFACT_DIR}" && { test -n "$${PREVIEW_PROFILE_INPUT_DIR}" || { test -n "$${PREVIEW_PACKAGE_TEMPLATE}" && test -n "$${PREVIEW_BASELINE}"; }; } || { echo 'release build variables, PREVIEW_SIGNING_KEY, and either PREVIEW_PROFILE_INPUT_DIR or single-profile inputs are required' >&2; exit 2; }
	@$(GO) run ./cmd/lanpanel-release --tag "$${PREVIEW_TAG}" --source "$${PREVIEW_SOURCE_DIR}" --dependency-inputs "$${PREVIEW_DEPENDENCY_INPUTS}" --manifest-template "$${PREVIEW_MANIFEST_TEMPLATE}" --dependency-template "$${PREVIEW_DEPENDENCY_TEMPLATE}" --package-template "$${PREVIEW_PACKAGE_TEMPLATE}" --dependency-baseline "$${PREVIEW_BASELINE}" --profile-input-dir "$${PREVIEW_PROFILE_INPUT_DIR}" --signing-key "$${PREVIEW_SIGNING_KEY}" --output "$${PREVIEW_ARTIFACT_DIR}"

release-preview:
	@test -n "$${PREVIEW_TAG}" && test -n "$${PREVIEW_SOURCE_DIR}" && test -n "$${PREVIEW_DEPENDENCY_DIR}" && test -n "$${PREVIEW_MANIFEST_TEMPLATE}" && test -n "$${PREVIEW_SIGNING_KEY}" && test -n "$${PREVIEW_ARTIFACT_DIR}" && test -n "$${PREVIEW_DOWNLOAD_BASE_URL}" && test -n "$${PREVIEW_OUTPUT_DIR}" && { test -n "$${PREVIEW_PROFILE_INPUT_DIR}" || { test -n "$${PREVIEW_PACKAGE_TEMPLATE}" && test -n "$${PREVIEW_BASELINE}"; }; } || { echo 'release-preview variables, PREVIEW_SIGNING_KEY, and either PREVIEW_PROFILE_INPUT_DIR or single-profile inputs are required' >&2; exit 2; }
	@scripts/materialize-preview-dependencies.sh "$${PREVIEW_DEPENDENCY_LOCK}" "$${PREVIEW_DEPENDENCY_DIR}"
	@$(GO) run ./cmd/lanpanel-release --tag "$${PREVIEW_TAG}" --source "$${PREVIEW_SOURCE_DIR}" --dependency-inputs "$${PREVIEW_DEPENDENCY_DIR}/dependency-inputs.json" --manifest-template "$${PREVIEW_MANIFEST_TEMPLATE}" --dependency-template "$${PREVIEW_DEPENDENCY_TEMPLATE}" --package-template "$${PREVIEW_PACKAGE_TEMPLATE}" --dependency-baseline "$${PREVIEW_BASELINE}" --profile-input-dir "$${PREVIEW_PROFILE_INPUT_DIR}" --signing-key "$${PREVIEW_SIGNING_KEY}" --output "$${PREVIEW_ARTIFACT_DIR}"
	@scripts/package-preview-release.sh "$${PREVIEW_TAG}" "$${PREVIEW_ARTIFACT_DIR}" "$${PREVIEW_DOWNLOAD_BASE_URL}" "$${PREVIEW_OUTPUT_DIR}"

publish-preview-github:
	@test -n "$${PREVIEW_TAG}" && test -n "$${PREVIEW_OUTPUT_DIR}" || { echo 'PREVIEW_TAG and PREVIEW_OUTPUT_DIR are required' >&2; exit 2; }
	@scripts/publish-preview-github.sh "$${PREVIEW_TAG}" "$${PREVIEW_OUTPUT_DIR}"

package-preview-release:
	@test -n "$${PREVIEW_VERSION}" && test -n "$${PREVIEW_ARTIFACT_DIR}" && test -n "$${PREVIEW_DOWNLOAD_BASE_URL}" && test -n "$${PREVIEW_OUTPUT_DIR}" || { echo 'PREVIEW_VERSION, PREVIEW_ARTIFACT_DIR, PREVIEW_DOWNLOAD_BASE_URL, and PREVIEW_OUTPUT_DIR are required' >&2; exit 2; }
	@scripts/package-preview-release.sh "$${PREVIEW_VERSION}" "$${PREVIEW_ARTIFACT_DIR}" "$${PREVIEW_DOWNLOAD_BASE_URL}" "$${PREVIEW_OUTPUT_DIR}"

docs-build:
	@test -f README.md && test -f README.zh-CN.md && test -f docs/README.md && test -f docs/INSTALLING.md && test -f docs/DEVELOPING.md && test -f docs/RELEASING.md && test -f release-inputs/preview-target-debian.json && test -f release-inputs/preview-target-ubuntu.json && test -x scripts/check-preview-profile-host.sh && test -x scripts/generate-preview-bootstrap.sh && test -x scripts/resolve-preview-dependencies.sh && test -x scripts/materialize-preview-dependencies.sh && test -x scripts/verify-preview-release.sh && test -x scripts/package-preview-release.sh && test -x scripts/publish-preview-github.sh
	@grep -Fq 'sudo ./lanpanel install' README.md README.zh-CN.md docs/README.md
	@grep -Fq 'sudo lanpanel uninstall' docs/README.md
	@grep -Fq 'scripts/generate-preview-bootstrap.sh' README.md README.zh-CN.md docs/README.md
	@grep -Fq 'package-preview-release' docs/RELEASING.md Makefile
	@grep -Fq 'INSTALLING.md' docs/README.md README.md
	@grep -Fq 'DEVELOPING.md' docs/README.md README.md
	@grep -Fq 'resolve-preview-dependencies' docs/RELEASING.md Makefile
	@grep -Fq 'materialize-preview-dependencies' docs/DEVELOPING.md Makefile
	@grep -Fq 'check-preview-profile-host' docs/RELEASING.md Makefile
	@grep -Fq 'capture-preview-profile' docs/RELEASING.md Makefile
	@grep -Fq 'IsSupportedPreviewTarget' internal/release/identity.go
	@grep -Fq 'PREVIEW_PROFILE_TARGET=ubuntu' docs/RELEASING.md
	@grep -Fq 'publish-preview-github' docs/RELEASING.md Makefile
	@grep -Fq '"family":"debian"' release-inputs/preview-target-debian.json
	@grep -Fq '"family":"ubuntu"' release-inputs/preview-target-ubuntu.json
	@grep -Fq '"architecture":"amd64"' release-inputs/preview-target-debian.json
	@grep -Fq 'verify-preview-release' Makefile scripts/package-preview-release.sh
	@grep -Fq 'lanpanel-bootstrap.sh' README.md README.zh-CN.md docs/README.md
	@! grep -Eq 'curl[^\n]*\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash)' README.md README.zh-CN.md docs/README.md
	@! grep -Eq 'lanpanel installer --bundle-dir|--release-digest|--acme-account-contact' README.md README.zh-CN.md docs/README.md
	@! grep -Eq 'source_kind|mirror_url|offline_path|proxy_url' docs/README.md
