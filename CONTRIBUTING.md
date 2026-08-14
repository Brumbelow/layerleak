# Contributing to layerleak

Layerleak scans adversarial container content. Contributions should preserve
correctness, redaction, bounded resource use, OCI integrity, and predictable
operation before adding convenience.

## Before you start

- Use Go 1.25.13 or newer.
- Read [README.md](./README.md) and [SECURITY.md](./SECURITY.md).
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

The module root is the public CLI. `go run ./cmd/scanner` remains a development
entrypoint. Administrative binaries live under `cmd/api`, `cmd/migrate`,
`cmd/purge`, and `cmd/healthcheck`.

To run PostgreSQL integration tests:

```bash
export LAYERLEAK_TEST_DATABASE_URL='postgres://layerleak:password@127.0.0.1:5432/layerleak_test?sslmode=disable'
go test ./... -count=1
```

Integration tests may reset the configured database. Never point
`LAYERLEAK_TEST_DATABASE_URL` at a database containing useful data.

## Required verification

Run the checks that match `.github/workflows/verify.yml`:

```bash
git diff --check
test -z "$(gofmt -l .)"
go mod verify
go mod tidy -diff
go vet ./...
go test -short ./... -count=1
go test -short -race ./... -count=1
go test ./... -count=1 # with LAYERLEAK_TEST_DATABASE_URL
LAYERLEAK_DB_PASSWORD=test docker compose config --quiet
LAYERLEAK_DB_PASSWORD=test docker compose --profile tools config --quiet
```

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

CI also runs real PostgreSQL migration/idempotence checks, the native purge
confirmation guard, both image architectures under emulation, API readiness,
`govulncheck`, a linked-dependency license gate and inventory, dependency
review, CodeQL, and image configuration validation.

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
- redirect and registry/auth destination policy;
- migration drift, dirty state, legacy adoption, and concurrency;
- API request limits, request IDs, concurrency, timeouts, and readiness;
- raw-secret purge scope and confirmation.

Prefer deterministic HTTP fixtures and in-memory OCI documents over live
registry tests.

## API and result compatibility

The CLI JSON result has an explicit `result_schema_version`. Additive fields are
preferred. Removing or renaming fields, changing exit codes, changing API paths,
or changing defaults requires an intentional compatibility decision and release
note.

When API behavior changes, update together:

- handler and integration tests;
- [README.md](./README.md);
- [`web/docs/openapi.yaml`](./web/docs/openapi.yaml);
- [`web/docs/index.html`](./web/docs/index.html);
- [CHANGELOG.md](./CHANGELOG.md).

API errors must retain a stable machine-readable code and a request ID. API and
persistence responses must never expose stored raw values.

## Database changes

- Add paired `NNNN_name.up.sql` and `NNNN_name.down.sql` files.
- Never edit a migration after it has shipped; checksums make drift a hard
  error.
- Prefer additive schema changes and explicit indexes/constraints.
- Update `CurrentSchemaVersion`, migration tests, Compose smoke coverage, and
  readiness expectations in the same change.
- Verify migration from an empty database and from the last supported schema,
  then run the migration command twice.
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
go install github.com/brumbelow/layerleak@latest
```

The module path has no major suffix, so releases must remain on v1. Historical
v2.x GitHub/container tags are not valid v2 Go module releases. Do not create or
push release tags manually. Maintainers use the protected workflow described in
[RELEASING.md](./RELEASING.md), which creates an immutable v1 tag only after all
release gates pass.

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
