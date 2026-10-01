GO ?= go
GO_VERSION := $(shell $(GO) list -m -f '{{.GoVersion}}')
TOOL_BIN ?= $(CURDIR)/.tools/bin
GOLANGCI_LINT_VERSION ?= v2.14.0
GOVULNCHECK_VERSION ?= v1.8.0
PYTHON ?= python3
VENV ?= .venv-docs

.PHONY: build test test-race db-test fmt-check mod-check vet tools lint vuln docs-verify verify

## build: compile every package
build:
	$(GO) build ./...

## test: short unit suite
test:
	$(GO) test -short ./... -count=1

## test-race: short unit suite under the race detector
test-race:
	$(GO) test -short -race ./... -count=1

## db-test: full suite including PostgreSQL integration (needs LAYERLEAK_TEST_DATABASE_URL)
db-test:
	$(GO) test ./... -count=1

## fmt-check: whitespace and gofmt
fmt-check:
	git diff --check
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then echo "gofmt found unformatted files:"; echo "$$unformatted"; exit 1; fi

## mod-check: module integrity
mod-check:
	$(GO) mod verify
	$(GO) mod tidy -diff

vet:
	$(GO) vet ./...

## tools: install the pinned lint and vulnerability tools, built with the go.mod toolchain
tools:
	mkdir -p $(TOOL_BIN)
	GOTOOLCHAIN=go$(GO_VERSION) GOBIN=$(TOOL_BIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	GOTOOLCHAIN=go$(GO_VERSION) GOBIN=$(TOOL_BIN) $(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

lint: tools
	$(TOOL_BIN)/golangci-lint run ./...

vuln: tools
	$(TOOL_BIN)/govulncheck ./...

## docs-verify: OpenAPI, documentation, SARIF, JSON Schema, release-script and compose validation
docs-verify:
	test -x $(VENV)/bin/python || $(PYTHON) -m venv $(VENV)
	$(VENV)/bin/python -m pip install --quiet --require-hashes -r requirements-docs.txt
	$(VENV)/bin/python -m unittest scripts/test_validate_docs.py
	$(VENV)/bin/python scripts/validate_docs.py
	$(VENV)/bin/python scripts/validate_sarif.py internal/sarif/testdata/*.sarif.json
	$(VENV)/bin/python -m unittest scripts/tests/test_validate_schemas.py
	$(VENV)/bin/python scripts/validate_schemas.py
	$(PYTHON) -m unittest discover -s scripts/tests
	LAYERLEAK_DB_PASSWORD=make-verify docker compose -f docker-compose.yml config --quiet
	LAYERLEAK_DB_PASSWORD=make-verify docker compose -f docker-compose.yml --profile tools config --quiet

## verify: everything CI runs without a database or a container runtime
verify: fmt-check mod-check vet lint test test-race vuln docs-verify
