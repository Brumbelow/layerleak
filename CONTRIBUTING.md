# Contributing to layerleak

Layerleak scans adversarial container content. Contributions should preserve
correctness, redaction, bounded resource use, OCI integrity, and predictable
operation before adding convenience.

## Before you start

- Use Go 1.27.1 or newer.
- Read [README.md](./README.md), [SECURITY.md](./SECURITY.md) and
  [AGENTS.md](./AGENTS.md) (the short rule sheet for contributors and AI
  coding agents; [CLAUDE.md](./CLAUDE.md) carries the same text for Claude
  Code). The [docs/](./docs/README.md) tree holds the architecture note, the
  threat model and the operations guides.
- Check existing issues and pull requests before duplicating work.
- Keep changes focused and match existing package boundaries and test style.
Do not include live credentials, private registry URLs, customer data, or
unredacted scan output in issues, fixtures, tests, screenshots, or logs.

## Local setup

```bash
go mod download
go build -o layerleak .
go test -short ./...
go run . scan alpine:latest --progress plain
```

The module root is the public CLI (`go run .`). Administrative binaries live
under `cmd/api`, `cmd/migrate`, `cmd/purge`, and `cmd/healthcheck`; there is no
separate `cmd/scanner`.

To run PostgreSQL integration tests:

```bash
export LAYERLEAK_TEST_DATABASE_URL='postgres://layerleak:password@127.0.0.1:5432/layerleak_test?sslmode=disable'
go test ./... -count=1
```

Integration tests may reset the configured database. Never point
`LAYERLEAK_TEST_DATABASE_URL` at a database containing useful data.

To run the browser demo tests with Node.js 22 or newer:

```bash
npm ci --prefix scripts/tests
npm exec --prefix scripts/tests -- playwright install chromium
npm test --prefix scripts/tests
```

Playwright is a development dependency for testing the real browser DOM. The
tests intercept every page request and use local synthetic fixtures; they do
not contact a registry or backend. To use an existing Chromium or Chrome
installation, set `DEMO_BROWSER_PATH` to its executable path when running
`npm test --prefix scripts/tests` instead of installing the bundled browser.

## Required verification

Run the checks that match `.github/workflows/verify.yml` (called by
`test.yml` on every push and pull request). `make verify` runs everything
that needs neither a database nor a container runtime and installs the pinned
golangci-lint and govulncheck under `.tools/`; `make db-test` runs the
PostgreSQL suite.

```bash
git diff --check
test -z "$(gofmt -l .)"
go mod verify
go mod tidy -diff
go vet ./...
golangci-lint run ./...              # make lint (pinned v2.14.0)
go test -short ./... -count=1        # CI adds -shuffle=on
go test -short -race ./... -count=1
govulncheck ./...                    # make vuln (pinned v1.8.0)
go test ./... -count=1               # with LAYERLEAK_TEST_DATABASE_URL (make db-test)
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install --require-hashes -r requirements-docs.txt
.venv-docs/bin/python -m unittest scripts/test_validate_docs.py
.venv-docs/bin/python scripts/validate_docs.py
.venv-docs/bin/python scripts/validate_sarif.py internal/sarif/testdata/*.sarif.json
.venv-docs/bin/python -m unittest scripts/tests/test_validate_schemas.py
.venv-docs/bin/python scripts/validate_schemas.py
python3 -m unittest discover -s scripts/tests -v
npm ci --prefix scripts/tests && npm test --prefix scripts/tests
LAYERLEAK_DB_PASSWORD=test docker compose config --quiet
LAYERLEAK_DB_PASSWORD=test docker compose --profile tools config --quiet
```

`validate_docs.py` checks the OpenAPI document and its documented examples,
every local documentation link, the configuration variable tables and the
synthetic demo data; `validate_sarif.py` checks the SARIF golden
fixtures against the OASIS 2.1.0 schema; `validate_schemas.py` checks the CLI
golden fixtures and the documented API responses against the published JSON
Schemas. `scripts/tests` holds the Python unit tests for the release
preflight, container-platform and schema validators and the Playwright demo
test.

Install smoke:

```bash
install_bin="$(mktemp -d)"
GOBIN="${install_bin}" go install .
"${install_bin}/layerleak" --help
"${install_bin}/layerleak" scan --help
"${install_bin}/layerleak" --version
```

When Docker and Buildx are available, build both supported image platforms:

```bash
docker buildx build --platform linux/amd64 --load -t layerleak:test .
docker buildx build --platform linux/arm64 --load -t layerleak:test-arm64 .
```

CI also asserts the module path is `github.com/brumbelow/layerleak/v3` and
that the Dockerfile `golang:` builder matches the `go.mod` toolchain,
cross-compiles and vets for darwin/arm64, darwin/amd64, windows/amd64 and
linux/arm64, runs every `Fuzz*` target briefly, applies the real PostgreSQL
migrations twice, checks the native purge confirmation guard, builds both
image architectures under emulation and smokes migration, API readiness and
the API error envelopes against them, runs `govulncheck`, gates linked
dependency licenses and uploads the inventory, runs dependency review on pull
requests (`test.yml`), and runs CodeQL from its own workflow.

## Coding expectations

- Prefer explicit errors and narrow interfaces.
- Preserve immutable digests and source provenance across every layer.
- Treat registry responses, redirects, compressed streams, tar metadata, and
  API bodies as hostile input.
- Bound reads before allocation or decompression.
- Check cancellation in long loops and before persistence.
- Keep output deterministic; sort map-derived data before serialization.
- Keep logs and errors free of tokens, credentials, raw secrets, and raw auth
  endpoints.
- Use table-driven tests when they make boundary cases clearer.
- Do not weaken limits or private-network protections without an explicit
  security review.

High-value regression areas include:

- reference, platform, and digest validation;
- manifest-list and attestation-manifest selection;
- digest mismatch and decompression failure handling;
- whiteouts, path traversal, links, and deleted-layer recovery;
- detector precedence, normalization, suppression, and redaction;
- complete/partial/failed coverage accounting and exit codes;
- redirect and registry/auth destination policy, including proxies and
  credential scoping;
- migration drift, dirty state, legacy adoption, and concurrency;
- API request limits, request IDs, concurrency, timeouts, readiness, bearer
  tokens and cursors;
- raw-secret purge scope and confirmation.

Prefer deterministic HTTP fixtures and in-memory OCI documents over live
registry tests.

## API and result compatibility

The Go module major is independent of the HTTP API path (`/api/v1`), the
result and record schema versions, and the database schema version; bump those
only when their own contracts change.

The CLI JSON result carries `result_schema_version` (currently `2`) and the
local scan record `record_schema_version` (also `2`). Both shapes are published
as JSON Schemas (draft 2020-12) at `web/docs/schemas/result-v2.schema.json`
and `web/docs/schemas/scan-record-v2.schema.json`, and pinned by golden
fixtures under `internal/cli/testdata/`, `internal/sarif/testdata/` and
`internal/api/testdata/`. Additive fields are preferred. Removing or renaming
fields, changing exit codes, changing API paths, or changing defaults requires
an intentional compatibility decision, a CHANGELOG entry and an UPGRADING
note.

When the result, record, SARIF or API response shape changes intentionally,
regenerate the fixtures after reviewing the diff, and update the JSON Schema
when a field was added or removed:

```bash
go test ./internal/cli -run TestGoldenResultAndScanRecordFixtures -update
go test ./internal/sarif -update
LAYERLEAK_UPDATE_CONTRACT_FIXTURES=1 go test ./internal/api -run TestDocumented
go test ./internal/cli -run TestDetectorsDocMatchesCatalog -update-docs
```

A new detector identifier needs a one-line description in
`internal/detectors/descriptions.go` (a test keeps the descriptions and the
catalog one to one) and a regenerated `docs/detectors.md` with the last
command above.

When API behavior changes, update together:

- handler and integration tests;
- [README.md](./README.md);
- [`web/docs/openapi.yaml`](./web/docs/openapi.yaml);
- [`web/docs/index.html`](./web/docs/index.html);
- [docs/api-operations.md](./docs/api-operations.md) when operations change;
- [CHANGELOG.md](./CHANGELOG.md).

API errors must retain a stable machine-readable code and a request ID. API and
persistence responses must never expose stored raw values.

## Database changes

- Add paired `NNNN_name.up.sql` and `NNNN_name.down.sql` files.
- Never edit a migration after it has shipped. The ledger checksums make drift
  a hard error at startup, and `TestShippedMigrationChecksumsAreFrozen`
  (`internal/storage/migration_checksums_test.go`) pins the SHA-256 of every
  shipped file, so an accidental edit fails CI. Add a new numbered pair and
  record its digests in that test instead.
- Prefer additive schema changes and explicit indexes/constraints.
- Update `CurrentSchemaVersion`, the expected-schema contract in
  `internal/storage/migrate.go`, migration tests, Compose smoke coverage, and
  readiness expectations in the same change.
- Verify migration from an empty database and from the last supported schema,
  then run the migration command twice; `layerleak-migrate-up --status` must
  exit `0` afterwards.
- Keep destructive data maintenance behind a dedicated, confirmation-gated
  command.

## Dependencies and workflows

Explain why a new dependency is necessary. Run `go mod tidy -diff` and update
[THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) when dependency licensing
changes.

All GitHub Actions references are pinned to full commit SHAs with a readable
version comment. Container bases and service images are pinned to multi-platform
manifest digests. Dependabot proposes reviewed updates; do not replace immutable
pins with moving tags.

Workflow changes affect the release trust boundary. Keep permissions job-local,
avoid privileged pull-request triggers, and preserve the order: verify, stage,
scan, attest/sign, smoke, protected approval, tag, promote, release.

## Versioning

The canonical install path is:

```text
go install github.com/brumbelow/layerleak/v3@latest
```

The module path carries the `/v3` major suffix, so releases are `v3.x.y` tags
whose `go.mod` declares `github.com/brumbelow/layerleak/v3`; `go list -m` is
asserted in CI. The root path `github.com/brumbelow/layerleak` is frozen at
v1.0.0 and the historical v2.x GitHub/container tags are not Go module
releases. Release source tags are prepared offline exactly as described in
[RELEASING.md](./RELEASING.md); do not push them manually. The protected
workflow alone pushes the prepared, immutable v3 tag after all release gates
pass.

## Documentation and pull requests

Update user documentation whenever flags, environment variables, defaults,
result fields, endpoints, migrations, container behavior, or operational risks
change. Keep examples safe to paste and use placeholders instead of secrets.

Pull requests should explain:

- the user or operator problem;
- the smallest behavior change that solves it;
- security and compatibility impact;
- tests run, including any checks that could not run locally;
- documentation, migration, or deployment follow-up.
