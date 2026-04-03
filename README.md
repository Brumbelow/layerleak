# layerleak the Docker Hub Secret Scanner

Check [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines.

- Docker Hub / OCI image secret scanner that analyzes image layers, config metadata, and image history, then stores deduplicated findings by manifest digest.
- Traditional secret scanners often treat a container image as a flat blob or depend on a local Docker daemon. This project is designed around OCI image internals

## Pages
- https://brumbelow.github.io/layerleak/docs

## Current Capabilities:

- Public Docker Hub images only
- Read-only scanning
- No secret verification
- No Docker daemon dependency required
- Manifest-aware and layer-aware scanning
- Scans final filesystem and deleted-layer artifacts
- Scans image config metadata, env vars, labels, and history
- Deduplicates findings by secret fingerprint and collapses repeated identical context snippets per manifest

## To Install

Prerequisites:

- Go 1.24+

Build from source:

```bash
git clone https://github.com/brumbelow/layerleak.git
cd layerleak
go build -o layerleak .
./layerleak --help
```
Optional environment configuration:

```bash
cp .env.example .env
```

Result and database configuration:

```bash
export LAYERLEAK_FINDINGS_DIR=findings
export LAYERLEAK_API_ADDR=127.0.0.1:8080
export LAYERLEAK_TAG_PAGE_SIZE=100
export LAYERLEAK_MAX_LAYER_BYTES=536870912
export LAYERLEAK_MAX_LAYER_ENTRIES=50000
export LAYERLEAK_MAX_MANIFEST_BYTES=0
export LAYERLEAK_MAX_CONFIG_BYTES=0
export LAYERLEAK_MAX_REPOSITORY_TAGS=0
export LAYERLEAK_MAX_REPOSITORY_TARGETS=0
export LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS=2
export LAYERLEAK_DATABASE_URL=postgres://postgres:postgres@localhost:5432/layerleak?sslmode=disable
```

If `LAYERLEAK_FINDINGS_DIR` is not set, layerleak writes JSON findings files to `findings/` under the repo root.
Saved findings files contain only detections, including unredacted finding values and unredacted context snippets.
`LAYERLEAK_TAG_PAGE_SIZE` controls Docker Hub tag-list pagination for repository-wide scans.
`LAYERLEAK_MAX_LAYER_BYTES` defaults to `536870912` (512 MiB) of decompressed layer stream data per layer, and `LAYERLEAK_MAX_LAYER_ENTRIES` defaults to `50000` tar entries per layer.
`LAYERLEAK_MAX_LAYER_BYTES`, `LAYERLEAK_MAX_LAYER_ENTRIES`, `LAYERLEAK_MAX_MANIFEST_BYTES`, `LAYERLEAK_MAX_CONFIG_BYTES`, `LAYERLEAK_MAX_REPOSITORY_TAGS`, and `LAYERLEAK_MAX_REPOSITORY_TARGETS` are disabled when set to `0`.
If enabled, those limits fail the scan with a clear error instead of silently truncating work.
`LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS` controls registry request retries and defaults to `2`.
`LAYERLEAK_API_ADDR` controls the bind address for the API server and defaults to `127.0.0.1:8080`.
If `LAYERLEAK_DATABASE_URL` is set, the scanner also writes the scan to Postgres and fails the command if Postgres is unavailable or the save does not succeed.

Result behavior:

- Actionable findings remain in `findings` and drive the non-zero scan exit status.
- Likely test/example/demo placeholders are emitted separately as suppressed example findings and do not count toward `total_findings`.
- Finding records include `disposition`, `disposition_reason`, and `line_number` to make triage and false-positive review easier.
- If a configured operational limit is exceeded, layerleak still writes and renders the partial results produced before the failure, then exits with status `1` because the scan is incomplete.

## Postgres persistence

Layerleak ships versioned SQL migrations under `migrations/`.
Migrations are manual on purpose. The scanner does not auto-create or auto-upgrade the schema.

Apply the migrations with `psql` in order:

```bash
psql "$LAYERLEAK_DATABASE_URL" -f migrations/0001_initial.up.sql
psql "$LAYERLEAK_DATABASE_URL" -f migrations/0002_finding_occurrence_metadata.up.sql
psql "$LAYERLEAK_DATABASE_URL" -f migrations/0003_scan_runs.up.sql
```

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

- Postgres persistence stores raw finding values and raw snippets, not only redacted previews.
- The `scan_runs.result_json` snapshot stays redacted.
- Use a dedicated database or schema for layerleak.
- For the safest purge path, drop the dedicated database or schema instead of trying to surgically delete individual rows.

## How to start

Show the CLI help:

```bash
./layerleak --help
./layerleak scan --help
```
![help_output](https://github.com/user-attachments/assets/dbd87faa-d3bb-4bfa-941a-643e6bbd48f6)


Run a scan against a public Docker Hub image:

```bash
./layerleak scan ubuntu
./layerleak scan library/nginx:latest --format json
./layerleak scan alpine:latest --platform linux/amd64
./layerleak scan mongo
```
![cli pic](https://github.com/user-attachments/assets/9c24960e-4085-451d-a206-b92331d604ef)


Every scan writes a JSON findings file to the findings output directory.
If `LAYERLEAK_FINDINGS_DIR` is not set, the default output directory is `findings/` under the repo root.

Those saved findings files contain only finding records, including the exact match value, exact source location, unredacted snippet, disposition metadata, and line number for each finding.
If Postgres persistence is enabled, the same raw finding material is stored in the `findings` and `finding_occurrences` tables.
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

## Support this project

<details open>
<summary><strong>☕ Enjoying this project? Click here to support it</strong></summary>

<br>

If this repo saved you time or helped you out, you can support future updates here:

 **[Buy me a coffee](https://ko-fi.com/brumbelow)**

Thank you :) it genuinely helps keep the project maintained.

</details>
