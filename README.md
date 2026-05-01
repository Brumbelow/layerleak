# layerleak the OCI Image Secret Scanner

Check [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines.

- OCI image secret scanner that works against any public OCI-compliant registry (Docker Hub, GHCR, Quay, GCR, MCR, Amazon ECR Public, self-hosted). It analyzes image layers, config metadata, and image history, then stores deduplicated findings by manifest digest.
- Traditional secret scanners often treat a container image as a flat blob or depend on a local Docker daemon. This project is designed around OCI image internals

## Docs Page
- https://brumbelow.github.io/layerleak/docs

The published site is built from `web/` on `main` by `.github/workflows/pages.yml`. The docs source and the simulated browser demo both live under that directory.

## Current Capabilities:

- Public images from any OCI-compliant registry (Docker Hub, GHCR, Quay, GCR, MCR, Amazon ECR Public, self-hosted)
- Read-only scanning
- No secret verification
- No Docker daemon dependency required
- Manifest-aware and layer-aware scanning
- Scans final filesystem and deleted-layer artifacts
- Scans image config metadata, env vars, labels, and history
- Deduplicates findings by secret fingerprint and collapses repeated identical context snippets per manifest

## Install

Prerequisites:

- Go 1.25.7+

Install with Go:

```bash
go install github.com/brumbelow/layerleak@latest
layerleak --help
```

The canonical install target is the module root.
To pin a release explicitly:

```bash
go install github.com/brumbelow/layerleak@v1.0.0
```

Replace `v1.0.0` with the published `v1.x.y` tag you want.
Make sure your `GOBIN` or `GOPATH/bin` directory is on `PATH`.

Build from source:

```bash
git clone https://github.com/brumbelow/layerleak.git
cd layerleak
go build -o layerleak .
./layerleak --help
```

Run the API with a container image:

```bash
docker pull ghcr.io/brumbelow/layerleak:latest
docker run --rm \
  -p 8080:8080 \
  -e LAYERLEAK_DATABASE_URL='postgres://<user>:<password>@<host>:5432/layerleak?sslmode=disable' \
  ghcr.io/brumbelow/layerleak:latest
```

The container image runs the API by default and sets `LAYERLEAK_API_ADDR=0.0.0.0:8080`.

Optional environment configuration:

```bash
cp .env.example .env
```

Result and database configuration:

```bash
export LAYERLEAK_FINDINGS_DIR=findings
export LAYERLEAK_API_ADDR=127.0.0.1:8080
export LAYERLEAK_PERSIST_RAW_SECRETS=0
export LAYERLEAK_TAG_PAGE_SIZE=100
export LAYERLEAK_HTTP_TIMEOUT=30s
export LAYERLEAK_MAX_FILE_BYTES=1048576
export LAYERLEAK_MAX_LAYER_BYTES=536870912
export LAYERLEAK_MAX_LAYER_ENTRIES=50000
export LAYERLEAK_MAX_MANIFEST_BYTES=0
export LAYERLEAK_MAX_CONFIG_BYTES=0
export LAYERLEAK_MAX_TAG_RESPONSE_BYTES=8388608
export LAYERLEAK_MAX_REPOSITORY_TAGS=0
export LAYERLEAK_MAX_REPOSITORY_TARGETS=0
export LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS=2
export LAYERLEAK_DATABASE_URL=postgres://postgres:postgres@localhost:5432/layerleak?sslmode=disable
```

If `LAYERLEAK_FINDINGS_DIR` is not set, layerleak writes JSON findings files to `findings/` under the repo root.
Saved findings files contain only detections and are redacted by default.
Set `LAYERLEAK_PERSIST_RAW_SECRETS=1` only if you explicitly want raw finding values and raw context snippets written to disk and Postgres.
`LAYERLEAK_TAG_PAGE_SIZE` controls registry tag-list pagination for repository-wide scans.
`LAYERLEAK_MAX_LAYER_BYTES` defaults to `536870912` (512 MiB) of decompressed layer stream data per layer, and `LAYERLEAK_MAX_LAYER_ENTRIES` defaults to `50000` tar entries per layer.
`LAYERLEAK_MAX_TAG_RESPONSE_BYTES` defaults to `8388608` (8 MiB) per registry tag-list response page.
`LAYERLEAK_REGISTRY_BASE_URL` and `LAYERLEAK_REGISTRY_AUTH_URL` are optional overrides. Leave them unset for normal use — layerleak derives the registry base URL from each image reference and discovers the auth realm from the registry's `WWW-Authenticate` challenge. Set them only to force scans through a proxy or alternate endpoint.
`LAYERLEAK_MAX_LAYER_BYTES`, `LAYERLEAK_MAX_LAYER_ENTRIES`, `LAYERLEAK_MAX_MANIFEST_BYTES`, `LAYERLEAK_MAX_CONFIG_BYTES`, `LAYERLEAK_MAX_TAG_RESPONSE_BYTES`, `LAYERLEAK_MAX_REPOSITORY_TAGS`, and `LAYERLEAK_MAX_REPOSITORY_TARGETS` are disabled when set to `0`.
If enabled, those limits fail the scan with a clear error instead of silently truncating work.
`LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS` controls registry request retries and defaults to `2`.
`LAYERLEAK_HTTP_TIMEOUT` is the per-request timeout applied to the HTTP client used for every registry call (manifest fetches, blob downloads, tag list pages, auth token requests). Accepts any Go duration value (`30s`, `2m`, `1h`); defaults to `30s`.
`LAYERLEAK_MAX_FILE_BYTES` is the maximum decompressed bytes layerleak buffers per file inside a layer; files larger than this are classified as oversize and skipped. Defaults to `1048576` (1 MiB) and must be greater than zero.
`LAYERLEAK_API_ADDR` controls the bind address for the API server and defaults to `127.0.0.1:8080` in local binaries.
The container image overrides this to `0.0.0.0:8080`.
If `LAYERLEAK_DATABASE_URL` is set, the scanner also writes the scan to Postgres and fails the command if Postgres is unavailable or the save does not succeed.

Result behavior:

- Actionable findings remain in `findings` and drive the non-zero scan exit status.
- Likely test/example/demo placeholders are emitted separately as suppressed example findings and do not count toward `total_findings`.
- Finding records include `disposition`, `disposition_reason`, and `line_number` to make triage and false-positive review easier.
- If a configured operational limit is exceeded, layerleak still writes and renders the partial results produced before the failure, then exits with status `1` because the scan is incomplete.

## Postgres persistence

Layerleak ships versioned SQL migrations under `migrations/`.
Migrations are manual on purpose. The scanner does not auto-create or auto-upgrade the schema.
Layerleak requires PostgreSQL server `>= 16.13` for DB-backed API and scanner persistence.

Apply the migrations with `psql` in order:

```bash
psql "$LAYERLEAK_DATABASE_URL" -f migrations/0001_initial.up.sql
psql "$LAYERLEAK_DATABASE_URL" -f migrations/0002_finding_occurrence_metadata.up.sql
psql "$LAYERLEAK_DATABASE_URL" -f migrations/0003_scan_runs.up.sql
```

Or apply migrations using the container helper command:

```bash
docker run --rm \
  -e LAYERLEAK_DATABASE_URL="$LAYERLEAK_DATABASE_URL" \
  ghcr.io/brumbelow/layerleak:latest \
  layerleak-migrate-up
```

`layerleak-migrate-up` is safe to rerun when migrations are already applied.
If it detects a partial migration state, it exits non-zero and asks for manual intervention.
The helper also enforces server version `>= 16.13` and validates that the bundled `postgresql-client-16`
uses Ubuntu PGDG `24.04` packaging (`.pgdg24.04+`) at version `>= 16.13-1.pgdg24.04+1`.

Rollback the migrations in reverse order:

```bash
psql "$LAYERLEAK_DATABASE_URL" -f migrations/0003_scan_runs.down.sql
psql "$LAYERLEAK_DATABASE_URL" -f migrations/0002_finding_occurrence_metadata.down.sql
psql "$LAYERLEAK_DATABASE_URL" -f migrations/0001_initial.down.sql
```

Operational defaults:

- Migrations are expected to remain additive.
- The schema keeps current deduplicated state with `first_seen_at` and `last_seen_at`, and also stores append-only scan history in `scan_runs`.
- Tag mappings are refreshed for tags touched by the current scan.
- Findings are deduplicated canonically by `(manifest_digest, fingerprint)`, and repeated identical context snippets are collapsed before persistence.
- Scan history stores a redacted snapshot of the public result JSON, not raw values or raw snippets.

Secret-safety note:

- Postgres persistence stores redacted previews by default.
- If `LAYERLEAK_PERSIST_RAW_SECRETS=1`, Postgres also stores raw finding values and raw snippets.
- The `scan_runs.result_json` snapshot stays redacted.
- Use a dedicated database or schema for layerleak.
- For the safest purge path, drop the dedicated database or schema instead of trying to surgically delete individual rows.

## How to start

Show the CLI help:

```bash
layerleak --help
layerleak scan --help
```
![help_output](https://github.com/user-attachments/assets/dbd87faa-d3bb-4bfa-941a-643e6bbd48f6)


Run a scan against a public OCI image on any supported registry:

```bash
./layerleak scan ubuntu
./layerleak scan library/nginx:latest --format json
./layerleak scan alpine:latest --platform linux/amd64
./layerleak scan mongo
./layerleak scan ghcr.io/homebrew/core/hello:latest
./layerleak scan quay.io/prometheus/busybox:latest
./layerleak scan gcr.io/distroless/static:nonroot
./layerleak scan public.ecr.aws/docker/library/alpine:3.20
./layerleak scan mcr.microsoft.com/hello-world:latest
```
![cli pic](https://github.com/user-attachments/assets/9c24960e-4085-451d-a206-b92331d604ef)


Every scan writes a JSON findings file to the findings output directory.
If `LAYERLEAK_FINDINGS_DIR` is not set, the default output directory is `findings/` under the repo root.

Those saved findings files contain finding records with `redacted_value`, redacted `context_snippet`, exact source location, disposition metadata, and line number for each finding.
If `LAYERLEAK_PERSIST_RAW_SECRETS=1`, the saved findings files also include raw `value` and `raw_context_snippet`.
If Postgres persistence is enabled, raw `findings.value` and `finding_occurrences.raw_snippet` stay empty unless `LAYERLEAK_PERSIST_RAW_SECRETS=1`.
For multi-arch images, layerleak skips attestation and provenance manifests such as `application/vnd.in-toto+json` instead of counting them as failed platform scans.
If you pass a bare repository name such as `mongo`, layerleak enumerates all public tags in that repository, resolves each tag to a digest, groups duplicate digests, and scans the distinct targets. If you want a single image only, pass an explicit tag or digest such as `mongo:latest` or `mongo@sha256:...`.

Command syntax:

```text
layerleak [command]
layerleak scan <image-ref> [flags]
```

## HTTP API

Layerleak also ships a minimal JSON API under `cmd/api`.
The API is Postgres-backed and requires `LAYERLEAK_DATABASE_URL`; it does not serve from the findings files on disk.

Start it with:

```bash
go run ./cmd/api
```

Or run the API container:

```bash
docker run --rm \
  -p 8080:8080 \
  -e LAYERLEAK_DATABASE_URL='postgres://<user>:<password>@<host>:5432/layerleak?sslmode=disable' \
  ghcr.io/brumbelow/layerleak:latest
```

Current endpoints:

- `POST /api/v1/scans`
- `GET /api/v1/scans/{id}`
- `GET /api/v1/repositories`
- `GET /api/v1/repositories/{repository}/scans`
- `GET /api/v1/repositories/{repository}/findings`
- `GET /api/v1/findings/{id}`

`POST /api/v1/scans` stays synchronous and now returns `scan_run_id` whenever Postgres persistence is enabled.
API scan responses reuse the same redacted result schema as the CLI JSON output.
`GET /api/v1/scans/{id}` returns the persisted run metadata plus the stored redacted result snapshot.
Repository and finding endpoints also stay redacted: they return `redacted_value` and redacted `context_snippet`, never raw secret values or raw snippets from Postgres.

`GET /api/v1/repositories/{repository}/scans` and `GET /api/v1/repositories/{repository}/findings` accept an optional `registry` query parameter (for example `?registry=ghcr.io`). When omitted, the registry defaults to `docker.io` for backward compatibility. Use this to fetch scans of repositories on GHCR, Quay, GCR, MCR, Amazon ECR Public, or any self-hosted registry.

The API does not include authentication.
For org deployments, keep it on a private network and front it with your own authn/authz gateway or reverse proxy policy.

## Docker Compose deployment (Dockge / Komodo)

This repo ships a Compose stack in `docker-compose.yml` with `db`, `migrate`, and `api` services.
The `db` service baseline is pinned to `postgres:16.13-alpine`.
If you use a different Postgres image, keep the server version at `16.13` or newer.

Set deployment variables (export in shell or place in a `.env` file next to `docker-compose.yml`):

```bash
export LAYERLEAK_IMAGE=ghcr.io/brumbelow/layerleak:latest
export LAYERLEAK_DB_NAME=layerleak
export LAYERLEAK_DB_USER=layerleak
export LAYERLEAK_DB_PASSWORD=replace-me
export LAYERLEAK_API_PORT=8080
```

Run migrations once before starting the API:

```bash
docker compose --profile manual run --rm migrate
```

Start the API service:

```bash
docker compose up -d api
```

In Dockge or Komodo, import the same Compose file and run the `migrate` service once before enabling the long-running `api` service.

## Support this project

<details open>
<summary><strong>☕ Enjoying this project? Click here to support it</strong></summary>

<br>

If this repo saved you time or helped you out, you can support future updates here:

 **[Buy me a coffee](https://ko-fi.com/brumbelow)**

Thank you :) it genuinely helps keep the project maintained.

</details>
