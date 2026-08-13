# layerleak

[![CI](https://github.com/brumbelow/layerleak/actions/workflows/test.yml/badge.svg)](https://github.com/brumbelow/layerleak/actions/workflows/test.yml)
[![CodeQL](https://github.com/brumbelow/layerleak/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/brumbelow/layerleak/actions/workflows/codeql-analysis.yml)
[![Go](https://img.shields.io/badge/Go-1.25.13%2B-00ADD8?logo=go)](https://go.dev/)

Layerleak is a read-only OCI image secret scanner. It resolves public image
references without a Docker daemon, verifies downloaded content against OCI
digests, reconstructs layer state, inspects deleted artifacts and image
metadata, and returns redacted, provenance-rich findings.

It supports Docker Hub, GHCR, Quay, GCR, MCR, Amazon ECR Public, and other
OCI-compatible registries. Results can be saved as JSON and persisted in
PostgreSQL for the bundled API.

- [Documentation](https://brumbelow.github.io/layerleak/docs/)
- [OpenAPI specification](https://brumbelow.github.io/layerleak/docs/openapi.yaml)
- [Changelog](./CHANGELOG.md)
- [Security policy](./SECURITY.md)
- [Contributing](./CONTRIBUTING.md)

## Security model

Layerleak scans untrusted image content, so its defaults are intentionally
bounded and fail closed:

- image, manifest, config, tag response, file, layer, retained-state, and
  finding limits prevent unbounded work;
- manifest, config, and layer bodies are checked against their advertised OCI
  digests before use;
- redirects are capped and revalidated;
- private, loopback, link-local, and otherwise non-public registry and auth
  destinations are blocked unless their exact host is explicitly allowed;
- findings, API responses, scan history, and logs are redacted by default;
- incomplete coverage is reported as `partial` or `failed`, never as a clean
  scan.

Layerleak does not verify whether a detected credential is live. The API has no
built-in authentication or authorization; expose it only on a trusted network
or behind an authenticated gateway.

## Install the CLI

Layerleak requires Go 1.25.13 or newer.

```bash
go install github.com/brumbelow/layerleak@latest
layerleak --version
layerleak --help
```

The module root is the canonical install target. Pin a stable or release
candidate explicitly when reproducibility matters:

```bash
go install github.com/brumbelow/layerleak@v1.0.0
go install github.com/brumbelow/layerleak@v1.1.0-rc.1
```

Go deliberately excludes prereleases from `@latest` while a stable version is
available. Local checkout builds report `dev`; module-installed binaries report
the resolved module version through `layerleak --version`.

Build from source:

```bash
git clone https://github.com/brumbelow/layerleak.git
cd layerleak
go build -o layerleak .
./layerleak --help
```

## Scan images

A bare repository scans its `latest` tag. Use an explicit tag or digest for an
immutable target:

```bash
layerleak scan ubuntu
layerleak scan library/nginx:1.29 --format json
layerleak scan alpine@sha256:<digest>
layerleak scan ghcr.io/homebrew/core/hello:latest
layerleak scan quay.io/prometheus/busybox:latest
layerleak scan gcr.io/distroless/static:nonroot
layerleak scan public.ecr.aws/docker/library/alpine:3.20
layerleak scan mcr.microsoft.com/hello-world:latest
```

Choose one platform from a multi-platform index:

```bash
layerleak scan alpine:latest --platform linux/arm64
```

Scanning every public tag is explicit because it can perform substantial work:

```bash
layerleak scan mongo --all-tags
layerleak scan mongo --all-tags \
  --tag-page-size 100 \
  --max-repository-tags 500 \
  --max-repository-targets 200
```

Useful scan flags:

| Flag | Meaning |
| --- | --- |
| `--format summary|json` | Human summary or stable JSON result. |
| `--platform os/arch[/variant]` | Restrict a multi-platform image. |
| `--all-tags` | Enumerate every public tag for a bare repository. |
| `--allow-partial` | Accept usable incomplete coverage while preserving `status`, coverage, and diagnostics. |
| `--progress auto|tty|plain|off` | Select interactive, log-safe, or disabled progress output. |
| `--tag-page-size` | Override the tag-list page size for `--all-tags`. |
| `--max-repository-tags` | Override the tag enumeration bound for `--all-tags`; `0` disables it. |
| `--max-repository-targets` | Override the distinct target bound for `--all-tags`; `0` disables it. |

Exit codes are stable for automation:

| Code | Meaning |
| --- | --- |
| `0` | Complete scan with no actionable findings, or an accepted usable partial scan with none. |
| `1` | Invalid input, operational failure, persistence failure, cancellation, or unaccepted incomplete coverage. |
| `2` | One or more actionable findings. |

Every result has a top-level `status` (`completed`, `partial`, or `failed`), a
coverage object, per-target and per-platform status, and diagnostics. Likely
test, fixture, example, and demo placeholders are retained separately as
suppressed findings and do not drive exit code `2`.

## Results and secret handling

Each scan writes JSON under `LAYERLEAK_FINDINGS_DIR`. If it is unset, the CLI
uses `findings/` beside the nearest `go.mod`, then falls back to the current
directory.

Finding records include:

- detector, confidence, disposition, and suppression reason;
- redacted value and redacted context;
- manifest, platform, file, layer, line, and source-location provenance;
- whether the occurrence survives in the final filesystem;
- deduplicated occurrence counts.

Raw values and raw context snippets are omitted unless
`LAYERLEAK_PERSIST_RAW_SECRETS=1`. That setting increases breach impact and
should normally remain disabled. API responses and the `scan_runs` snapshot
remain redacted even when raw storage is enabled. Turning the setting back off
prevents new raw writes but does not erase historical raw material; use the
confirmation-gated purge command below for that explicit operation.

## Configuration

The process reads environment variables; it does not load `.env` itself. Copy
the complete, versioned example when running from a checkout, then export its
values before starting Layerleak:

```bash
cp .env.example .env
set -a
. ./.env
set +a
```

Durations use Go syntax such as `30s`, `10m`, or `1h`. Positive resource bounds
fail the scan instead of silently truncating it. A value of `0` disables a
`MAX_*` bound unless the description says otherwise.

### Core and registry

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAYERLEAK_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `LAYERLEAK_FINDINGS_DIR` | auto | Saved result directory. |
| `LAYERLEAK_PERSIST_RAW_SECRETS` | `0` | Unsafe opt-in for raw values and snippets. |
| `LAYERLEAK_HTTP_TIMEOUT` | `30s` | Manifest, config, tag, and auth request deadline. |
| `LAYERLEAK_BLOB_TIMEOUT` | `10m` | Layer blob transfer deadline. |
| `LAYERLEAK_SCAN_TIMEOUT` | `30m` | End-to-end CLI scan deadline. |
| `LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS` | `2` | Attempts including the first request. |
| `LAYERLEAK_REGISTRY_MAX_REDIRECTS` | `3` | Redirect cap; each destination is revalidated. |
| `LAYERLEAK_MAX_AUTH_RESPONSE_BYTES` | `1048576` | Maximum registry token response size. |
| `LAYERLEAK_ALLOWED_PRIVATE_REGISTRY_HOSTS` | empty | Comma-separated exact private registry `host[:port]` allowlist. |
| `LAYERLEAK_ALLOWED_PRIVATE_AUTH_HOSTS` | empty | Comma-separated exact private auth `host[:port]` allowlist. |
| `LAYERLEAK_REGISTRY_BASE_URL` | empty | Advanced registry endpoint override. |
| `LAYERLEAK_REGISTRY_AUTH_URL` | empty | Advanced auth endpoint override. |

Private destination allowlists are an explicit trust decision. Entries accept
an exact DNS hostname or IPv4 address, optionally with a port, or bracketed
IPv6 with a port. Schemes, paths, credentials, wildcards, malformed hostnames,
invalid ports, and unbracketed IPv6 are rejected. Allow only infrastructure you
control.

### Resource bounds

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAYERLEAK_MAX_FILE_BYTES` | `1048576` | Maximum decompressed bytes buffered for one file; must be positive. |
| `LAYERLEAK_MAX_LAYER_BYTES` | `536870912` | Maximum decompressed stream bytes for one layer. |
| `LAYERLEAK_MAX_LAYER_ENTRIES` | `50000` | Maximum tar entries for one layer. |
| `LAYERLEAK_MAX_IMAGE_LAYERS` | `512` | Maximum layers selected for one image. |
| `LAYERLEAK_MAX_IMAGE_MANIFESTS` | `64` | Maximum platform manifests selected from one image index. |
| `LAYERLEAK_MAX_IMAGE_LAYER_BYTES` | `4294967296` | Aggregate advertised compressed and expanded layer bytes. |
| `LAYERLEAK_MAX_IMAGE_ARTIFACTS` | `250000` | Aggregate layer artifact count. |
| `LAYERLEAK_MAX_RETAINED_BYTES` | `1073741824` | Bytes retained while reconstructing final state. |
| `LAYERLEAK_MAX_MANIFEST_BYTES` | `8388608` | Maximum manifest response size. |
| `LAYERLEAK_MAX_CONFIG_BYTES` | `8388608` | Maximum image config response size. |
| `LAYERLEAK_MAX_TAG_RESPONSE_BYTES` | `8388608` | Maximum tag-list response page size. |
| `LAYERLEAK_MAX_FINDINGS_PER_SCAN` | `10000` | Maximum findings retained for one scan. |
| `LAYERLEAK_MAX_RAW_FINDING_BYTES` | `67108864` | Maximum raw value and context bytes retained when raw-secret persistence is enabled; exceeding it makes coverage partial. |
| `LAYERLEAK_TAG_PAGE_SIZE` | `100` | Registry tag-list page size. |
| `LAYERLEAK_MAX_REPOSITORY_TAGS` | `1000` | Maximum tags enumerated by `--all-tags`. |
| `LAYERLEAK_MAX_REPOSITORY_TARGETS` | `250` | Maximum distinct targets scanned by `--all-tags`. |

### API and PostgreSQL

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAYERLEAK_API_ADDR` | `127.0.0.1:8080` | API listen address; image default is `0.0.0.0:8080`. |
| `LAYERLEAK_API_MAX_REQUEST_BYTES` | `16384` | Maximum JSON request body. |
| `LAYERLEAK_API_SCAN_TIMEOUT` | `30m` | Deadline for an API scan. |
| `LAYERLEAK_API_MAX_CONCURRENT_SCANS` | `1` | In-process scan concurrency. |
| `LAYERLEAK_API_READ_HEADER_TIMEOUT` | `5s` | HTTP header deadline. |
| `LAYERLEAK_API_READ_TIMEOUT` | `15s` | HTTP request read deadline. |
| `LAYERLEAK_API_RESPONSE_WRITE_TIMEOUT` | `30s` | Non-scan response write deadline. |
| `LAYERLEAK_API_IDLE_TIMEOUT` | `60s` | Keep-alive idle timeout. |
| `LAYERLEAK_API_SHUTDOWN_TIMEOUT` | `30s` | Graceful shutdown deadline. |
| `LAYERLEAK_API_READINESS_TIMEOUT` | `2s` | Database readiness query deadline. |
| `LAYERLEAK_DATABASE_URL` | empty | PostgreSQL connection URL. |
| `LAYERLEAK_DATABASE_MAX_OPEN_CONNS` | `10` | Open connection cap. |
| `LAYERLEAK_DATABASE_MAX_IDLE_CONNS` | `5` | Idle connection cap. |
| `LAYERLEAK_DATABASE_CONN_MAX_LIFETIME` | `30m` | Connection lifetime. |
| `LAYERLEAK_DATABASE_CONN_MAX_IDLE_TIME` | `5m` | Idle connection lifetime. |
| `LAYERLEAK_DATABASE_QUERY_TIMEOUT` | `10s` | Read and readiness query deadline. |
| `LAYERLEAK_DATABASE_WRITE_TIMEOUT` | `2m` | Transactional persistence deadline. |
| `LAYERLEAK_MIGRATIONS_DIR` | `/app/migrations` | Migration directory used by the migration command. |

## PostgreSQL and migrations

The API and persistent CLI mode require PostgreSQL 16.13 or newer. Migrations
are explicit and must complete before the API becomes ready.

From a checkout:

```bash
export LAYERLEAK_DATABASE_URL='postgres://layerleak:password@localhost:5432/layerleak?sslmode=disable'
export LAYERLEAK_MIGRATIONS_DIR="$PWD/migrations"
go run ./cmd/migrate
go run ./cmd/migrate
```

The second run is intentionally a no-op. The migration command uses an advisory
lock, a checksummed migration ledger, and one transaction per migration. It can
adopt a complete legacy 0001-0003 schema and refuses drift, gaps, dirty state,
or a partial legacy schema.

The container bundles the same native command:

```bash
docker run --rm \
  -e LAYERLEAK_DATABASE_URL="$LAYERLEAK_DATABASE_URL" \
  --entrypoint /usr/local/bin/layerleak-migrate-up \
  ghcr.io/brumbelow/layerleak:latest
```

To irreversibly remove opt-in raw material while retaining redacted findings,
fingerprints, occurrences, and history:

First set `LAYERLEAK_PERSIST_RAW_SECRETS=0` for every API or CLI database
writer and restart or stop those processes. Any writer that remains opted in
can store raw material again after the purge completes.

```bash
docker run --rm \
  -e LAYERLEAK_DATABASE_URL="$LAYERLEAK_DATABASE_URL" \
  --entrypoint /usr/local/bin/layerleak-purge-raw-secrets \
  ghcr.io/brumbelow/layerleak:latest \
  --confirm
```

The purge command requires `--confirm`, serializes concurrent purge attempts,
and clears only `findings.value` and `finding_occurrences.raw_snippet`.

## HTTP API

Run the API from a migrated checkout:

```bash
export LAYERLEAK_DATABASE_URL='postgres://layerleak:password@localhost:5432/layerleak?sslmode=disable'
go run ./cmd/api
```

Health endpoints:

| Endpoint | Meaning |
| --- | --- |
| `GET /health` | Process liveness; does not query PostgreSQL. |
| `GET /livez` | Kubernetes-style process liveness alias. |
| `GET /readyz` | Readiness; requires a database ping and exact schema version `0004`. |

API endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/scans` | Run a synchronous scan and persist its redacted result. |
| `GET /api/v1/scans/{id}` | Read one persisted scan. |
| `GET /api/v1/repositories` | List persisted repositories. |
| `GET /api/v1/repositories/{repository}/scans` | List repository scan history. |
| `GET /api/v1/repositories/{repository}/findings` | List deduplicated findings. |
| `GET /api/v1/findings/{id}` | Read one finding and its occurrences. |

Start a single-image scan:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -d '{"reference":"alpine:3.20","platform":"linux/amd64"}' \
  http://127.0.0.1:8080/api/v1/scans
```

A bare reference means `latest`. Set `"all_tags": true` to request an explicit
repository sweep:

```json
{
  "reference": "library/alpine",
  "all_tags": true
}
```

List endpoints accept `limit` and `offset`; `limit` defaults to 50 and is capped
at 200. Repository scan and finding endpoints accept `registry` (default
`docker.io`). The finding list accepts
`disposition=actionable|suppressed|all` and defaults to actionable.

Every response includes `X-Request-ID`. Error bodies use this shape:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "human-readable description",
    "request_id": "request correlation id"
  }
}
```

Unknown request fields and extra JSON values are rejected. Request size,
concurrency, database work, and scan duration are bounded by configuration. See
the versioned [OpenAPI 3.1 specification](./web/docs/openapi.yaml) for request,
response, pagination, and error schemas.

## Container and Compose deployment

The published API image supports `linux/amd64` and `linux/arm64`. It is a
shell-free, non-root image containing only CA roots, four static Layerleak
binaries, and migrations. The image healthcheck probes `/readyz` with a hard
two-second deadline.

```bash
docker pull ghcr.io/brumbelow/layerleak:latest
docker run --rm \
  -p 8080:8080 \
  -e LAYERLEAK_DATABASE_URL='postgres://<user>:<password>@<host>:5432/layerleak?sslmode=disable' \
  --read-only --tmpfs /tmp:mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges \
  ghcr.io/brumbelow/layerleak:latest
```

For Compose, copy the example and replace the required password:

```bash
cp .env.example .env
# Edit LAYERLEAK_DB_PASSWORD in .env.
docker compose config
docker compose --profile tools run --rm migrate
docker compose up -d api
docker compose ps
curl --fail http://127.0.0.1:8080/readyz
```

The Compose services use a digest-pinned PostgreSQL 16.13 image, wait for
PostgreSQL health, run the API read-only with all capabilities dropped, and use
the native readiness probe. The host port binds to `127.0.0.1` by default; set
`LAYERLEAK_API_HOST` only when an authenticated network edge is ready. The
migration stays explicit. Purge raw material only after reviewing the command:

```bash
docker compose --profile tools run --rm purge-raw-secrets --confirm
```

If a database password contains reserved URL characters, percent-encode it for
the connection URL or choose a URL-safe generated password.

## Verify a release

Releases publish one signed multi-platform image digest. RC tags never move
`latest`; a stable tag and `latest` point to the exact accepted RC digest.

```bash
version=v1.1.0-rc.1
image=ghcr.io/brumbelow/layerleak
source_sha='<source-sha-from-release-manifest>'
docker buildx imagetools inspect "${image}:${version}"

digest=$(docker buildx imagetools inspect "${image}:${version}" \
  --format '{{json .Manifest.Digest}}' | tr -d '"')

cosign verify \
  --certificate-identity 'https://github.com/Brumbelow/layerleak/.github/workflows/container-release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${image}@${digest}"

gh attestation verify "oci://${image}@${digest}" \
  --repo Brumbelow/layerleak \
  --bundle-from-oci \
  --signer-workflow Brumbelow/layerleak/.github/workflows/container-release.yml \
  --source-ref refs/heads/main \
  --source-digest "${source_sha}" \
  --deny-self-hosted-runners

gh release verify "${version}" --repo Brumbelow/layerleak
```

Each GitHub release includes checksums, per-platform SPDX SBOMs, SLSA
provenance, vulnerability reports, attestation bundles, and a
`release-manifest.json` that binds the source commit to the image index and
platform digests.

## Version history

The canonical module path is `github.com/brumbelow/layerleak`, so installable
releases stay on v1. The v1.1.0 line is preceded by one or more v1.1.0 release
candidates.

Historical GitHub/container tags v2.0.0-v2.5.0 did not use the required `/v2`
Go module path. They are preserved for history but are not valid v2 module
releases and are not selected by `go install ...@latest`. The v1.1 line
contains and supersedes that work; its version number is not a source downgrade.
A future true v2 requires a deliberate module-path and API migration.

See [CHANGELOG.md](./CHANGELOG.md) for release-line details and
[RELEASING.md](./RELEASING.md) for the protected release procedure.

## License and notices

Layerleak is released under the [MIT License](./LICENSE). Third-party components
retain their own licenses; see [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).

## Support the project

If Layerleak saves you time, you can support ongoing maintenance through
[Ko-fi](https://ko-fi.com/brumbelow).
