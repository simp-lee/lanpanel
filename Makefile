.DEFAULT_GOAL := check

.PHONY: build test vet lint check tidy p0-static-audit e2e-production-ui-smoke e2e e2e-walkthrough e2e-walkthrough-all p0-release-gate

GO ?= go
PKGS ?= ./...
GOLANGCI_LINT ?= golangci-lint
BINARY ?= lanpanel
E2E_NODE_DIR ?= /tmp/lanpanel-e2e-node
E2E_ADDR ?= 127.0.0.1:18080
E2E_PLAYWRIGHT_VERSION ?= 1.61.0
E2E_SPEC ?=
E2E_TESTSERVER_FLAGS ?=

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

check: build test vet p0-static-audit

p0-release-gate: check e2e-production-ui-smoke e2e e2e-walkthrough-all

p0-static-audit:
	scripts/p0-static-audit.sh

e2e-production-ui-smoke: build
	LANPANEL_BINARY=./$(BINARY) E2E_ADDR=$(E2E_ADDR) scripts/e2e-production-ui-smoke.sh

e2e:
	mkdir -p $(E2E_NODE_DIR)
	npm --prefix $(E2E_NODE_DIR) install --no-save @playwright/test@$(E2E_PLAYWRIGHT_VERSION)
	NODE_PATH=$(E2E_NODE_DIR)/node_modules $(E2E_NODE_DIR)/node_modules/.bin/playwright install chromium
	tmp_dir=$$(mktemp -d "$${HOME}/.lanpanel-e2e.XXXXXX"); \
	server_pid=; \
	node_modules_link=; \
	if test -L e2e/node_modules && ! test -e e2e/node_modules; then rm -f e2e/node_modules; fi; \
	if ! test -e e2e/node_modules; then ln -s "$(E2E_NODE_DIR)/node_modules" e2e/node_modules; node_modules_link=e2e/node_modules; fi; \
	trap 'test -z "$$server_pid" || kill $$server_pid >/dev/null 2>&1 || true; test -z "$$node_modules_link" || rm -f "$$node_modules_link"; rm -rf $$tmp_dir' EXIT INT TERM; \
	token_file=$$tmp_dir/token-url; \
	browser_auth_dir=$$tmp_dir/browser-auth; \
	$(GO) build -tags e2e -o $$tmp_dir/ui-testserver ./internal/ui/testserver; \
	$$tmp_dir/ui-testserver -listen $(E2E_ADDR) -state-dir $$tmp_dir/state -config $$tmp_dir/lanpanel.yaml -app-config $$tmp_dir/lanpanel-app.yaml -browser-auth-dir $$browser_auth_dir -token-url-file $$token_file >$$tmp_dir/server.log 2>&1 & \
	server_pid=$$!; \
	for i in $$(seq 1 100); do test -s $$token_file && break; sleep 0.1; done; \
	test -s $$token_file || { cat $$tmp_dir/server.log; exit 1; }; \
	LANPANEL_UI_URL=http://$(E2E_ADDR) LANPANEL_UI_TOKEN_URL=$$(cat $$token_file) LANPANEL_BROWSER_AUTH_DIR=$$browser_auth_dir NODE_PATH=$(E2E_NODE_DIR)/node_modules $(E2E_NODE_DIR)/node_modules/.bin/playwright test -c e2e/playwright.config.ts e2e/specs/management-ui.spec.ts

e2e-walkthrough:
	test -n "$(E2E_SPEC)" || { echo "E2E_SPEC is required, for example E2E_SPEC=e2e/specs/walkthrough/ui-bootstrap-security.spec.ts"; exit 2; }
	mkdir -p $(E2E_NODE_DIR)
	npm --prefix $(E2E_NODE_DIR) install --no-save @playwright/test@$(E2E_PLAYWRIGHT_VERSION)
	NODE_PATH=$(E2E_NODE_DIR)/node_modules $(E2E_NODE_DIR)/node_modules/.bin/playwright install chromium
	tmp_dir=$$(mktemp -d "$${HOME}/.lanpanel-e2e.XXXXXX"); \
	server_pid=; \
	node_modules_link=; \
	if test -L e2e/node_modules && ! test -e e2e/node_modules; then rm -f e2e/node_modules; fi; \
	if ! test -e e2e/node_modules; then ln -s "$(E2E_NODE_DIR)/node_modules" e2e/node_modules; node_modules_link=e2e/node_modules; fi; \
	trap 'test -z "$$server_pid" || kill $$server_pid >/dev/null 2>&1 || true; test -z "$$node_modules_link" || rm -f "$$node_modules_link"; rm -rf $$tmp_dir' EXIT INT TERM; \
	token_file=$$tmp_dir/token-url; \
	browser_auth_dir=$$tmp_dir/browser-auth; \
	$(GO) build -tags e2e -o $$tmp_dir/ui-testserver ./internal/ui/testserver; \
	$$tmp_dir/ui-testserver -listen $(E2E_ADDR) -state-dir $$tmp_dir/state -config $$tmp_dir/lanpanel.yaml -app-config $$tmp_dir/lanpanel-app.yaml -browser-auth-dir $$browser_auth_dir -token-url-file $$token_file $(E2E_TESTSERVER_FLAGS) >$$tmp_dir/server.log 2>&1 & \
	server_pid=$$!; \
	for i in $$(seq 1 100); do test -s $$token_file && break; sleep 0.1; done; \
	test -s $$token_file || { cat $$tmp_dir/server.log; exit 1; }; \
	LANPANEL_UI_URL=http://$(E2E_ADDR) LANPANEL_UI_TOKEN_URL=$$(cat $$token_file) LANPANEL_BROWSER_AUTH_DIR=$$browser_auth_dir NODE_PATH=$(E2E_NODE_DIR)/node_modules $(E2E_NODE_DIR)/node_modules/.bin/playwright test -c e2e/playwright.config.ts $(E2E_SPEC)

e2e-walkthrough-all:
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/ui-bootstrap-security.spec.ts E2E_TESTSERVER_FLAGS=
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/first-run-config-init-flow.spec.ts E2E_TESTSERVER_FLAGS=-preseed-configs=false
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/main-config-job-flow.spec.ts E2E_TESTSERVER_FLAGS=
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/public-resource-exposure-flow.spec.ts E2E_TESTSERVER_FLAGS=
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/browser-auth-resource-flow.spec.ts E2E_TESTSERVER_FLAGS=
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/realip-goaccess-flow.spec.ts E2E_TESTSERVER_FLAGS=
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/headscale-onboarding-handoff.spec.ts E2E_TESTSERVER_FLAGS=
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/jobs-history-redaction-recovery.spec.ts E2E_TESTSERVER_FLAGS=-slow-main-deploy=3s
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/overview-runtime-readonly.spec.ts E2E_TESTSERVER_FLAGS=
	$(MAKE) e2e-walkthrough E2E_SPEC=e2e/specs/walkthrough/migration-boundary-flow.spec.ts E2E_TESTSERVER_FLAGS=
