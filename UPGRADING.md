# Upgrading to Layerleak 3.0.0

> **Draft for 3.0.0.** The CLI contract items below (schema version 2, output
> files, exit codes, `--fail-on`, SARIF, detector renames) describe the planned
> 3.0.0 behaviour and are verified against the code in the documentation pass
> before the first release candidate.

3.0.0 is the first release on the Go module path
`github.com/brumbelow/layerleak/v3`. The root module path
`github.com/brumbelow/layerleak` is frozen at `v1.0.0` forever, and the
`v2.0.0`–`v2.5.0` GitHub and container tags were never valid Go modules. Pick
the track that matches what you run today. The CHANGELOG lists every change;
this guide only covers what you must do differently.

## What 3.0.0 does and does not break

Unchanged:

- The HTTP API stays at `/api/v1`. Existing response fields keep their names
  and types; 3.0.0 only adds fields and error codes.
- The PostgreSQL schema stays at migration `0004`. No new migration ships.
- The binary is still called `layerleak`, and `layerleak scan <reference>` with
  the default summary output behaves the same for a clean image.
- Fingerprints are still `sha256` of the raw secret value, unsalted and
  identical across installs.

Changed:

- Module path `/v3`; install with `go install github.com/brumbelow/layerleak/v3@latest`.
- `result_schema_version` and `record_schema_version` are `2` (see the field
  list below). JSON Schemas are published under `web/docs/schemas/`.
- Exit code `3` means the scan finished but coverage was incomplete and
  `--allow-partial` was not given; `--fail-on` chooses which confidence levels
  cause exit code `2`.
- One scan-record file per scan under `./findings` (or `--output-dir`); the
  legacy findings array file and all raw local output are gone.
- Redacted values show a fixed-length mask: short values are fully masked and
  longer values reveal only a prefix.
- Environment and label findings now cover the value only, so their
  fingerprints change once; file findings are unaffected.
- Some detector identifiers were renamed for consistency, and identifier-only
  detectors no longer claim high confidence.
- Multi-platform images scan only `linux` manifests by default; other
  platforms are skipped with a diagnostic instead of failing the scan.
- `LAYERLEAK_LOG_LEVEL` accepts exactly `debug`, `info`, `warn`, `error`.
- Go API: `registry.NewClient` returns `(*Client, error)`.

## Track 1: v1.0.0 CLI users

1. Install the new module path. The binary name does not change:

   ```bash
   go install github.com/brumbelow/layerleak/v3@latest
   layerleak version
   ```

   Remove any old binary built from `github.com/brumbelow/layerleak@v1.0.0`
   that is earlier on your `PATH`.

2. Replace the two-file output expectations. 3.0.0 writes one scan record per
   scan (`record_schema_version: 2`) under `./findings` relative to the
   working directory, or wherever `--output-dir` / `LAYERLEAK_FINDINGS_DIR`
   points; `--output <file>` writes the JSON result to a chosen path and
   `--no-artifacts` writes nothing locally. The nearest-`go.mod` directory
   heuristic is gone, and an existing directory is never `chmod`ed.

3. Re-baseline suppressions keyed on fingerprints of environment-variable or
   label findings: they now fingerprint the value alone, matching the same
   secret found in a file.

4. Update scripts that parse exit codes:

   | Code | Meaning |
   | --- | --- |
   | `0` | Clean, complete scan |
   | `1` | Invalid input, operational failure, persistence failure, or cancellation |
   | `2` | Actionable findings at or above `--fail-on` (default `low`) |
   | `3` | Incomplete coverage not accepted with `--allow-partial` |

5. Update scripts that parse `detector_name`: see the rename table in the
   CHANGELOG. Redacted values are shorter and no longer reveal the length.

6. New since v1.0.0 that you may want: `--all-tags` repository sweeps,
   `--format sarif` for code scanning, `--platform linux` OS-only selection,
   `layerleak version`, proxy support through `HTTPS_PROXY`.

## Track 2: v2.x container and PostgreSQL installs

1. Back up the database.

2. Pull `ghcr.io/brumbelow/layerleak:v3.0.0` and run its migration command
   against the existing database before starting the API:

   ```bash
   docker run --rm -e LAYERLEAK_DATABASE_URL="$LAYERLEAK_DATABASE_URL" \
     --entrypoint /usr/local/bin/layerleak-migrate-up ghcr.io/brumbelow/layerleak:v3.0.0
   ```

   The command adopts a complete legacy `0001`–`0003` schema, applies `0004`
   once, is idempotent, and now bounds its lock waits
   (`LAYERLEAK_MIGRATION_LOCK_TIMEOUT`, `LAYERLEAK_MIGRATION_TIMEOUT`). Stop
   API replicas and long transactions first on a populated database. The API
   refuses to start until the schema is exactly `0004`.

3. Compose users: `.env.example` now ships `LAYERLEAK_DB_PASSWORD` empty and
   Compose refuses to start until it is set. The password reaches the
   containers as `PGPASSWORD`, the `api` service waits for the `migrate`
   service, and a 35 second `stop_grace_period` protects in-flight scans. Run
   `docker compose up -d` instead of running `migrate` by hand.

4. Review raw-secret persistence. `LAYERLEAK_PERSIST_RAW_SECRETS` is still
   off by default. If an earlier install stored raw values, the API logs a
   warning at startup; remove them with
   `layerleak-purge-raw-secrets --confirm` after disabling the setting on
   every writer.

5. Operational changes to expect: a scan that completes after its client
   disconnected is now persisted; on SIGTERM the API answers `503 not_ready`
   from `/readyz` and refuses new scans with `503 server_shutting_down` for
   `LAYERLEAK_API_PRESTOP_DELAY` (default `0s`), then cancels in-flight scans
   and exits 0 within `LAYERLEAK_API_SHUTDOWN_TIMEOUT`; one structured access
   record is logged per request; `GET /health` includes `version`; registry
   `404`s map to `404 image_not_found` instead of `502`; `/readyz` caches its
   result for `LAYERLEAK_API_READINESS_CACHE_TTL` (default `5s`).

## Track 3: API consumers

`/api/v1` paths, request bodies and existing response fields are unchanged.
Additions you may start reading:

- `result_schema_version: 2` results carry `scanned_at`, `scanner`
  (`name`, `version`) and typed `tag_results[].status`
  (`resolved`, `scanned`, `partial`, `failed`, `skipped`); integer counters are
  always present instead of omitted when zero.
- New error codes: `image_not_found` (404), `registry_rate_limited` (503 with
  `Retry-After`), `registry_unauthorized` (502), `server_shutting_down` (503),
  `not_ready` (503). See the README status table and `web/docs/openapi.yaml`.
- Two tightenings affect only malformed clients: the `{repository}` path
  segment is percent-decoded once (`library%252Fapp` is no longer read as
  `library/app`) and must match the OCI repository-name grammar (400
  otherwise); `/api/v1/repositories/scans` and `/api/v1/repositories/findings`
  are 404. `408 scan_canceled` now means only that the client went away;
  registry timeouts are `502 scan_failed`. `504 scan_timeout` is returned only
  when the API's own scan deadline expired.
- List responses echo the normalised `registry` filter.
- Redacted values and context snippets are shorter and never reveal a secret
  that appears twice in a window.

Nothing in 3.0.0 requires an API consumer change; a client that validated
`result_schema_version == 1` must accept `2`.
