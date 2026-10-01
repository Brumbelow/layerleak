# Upgrading to Layerleak 3.0.0

3.0.0 is the first release on the Go module path
`github.com/brumbelow/layerleak/v3`. The root module path
`github.com/brumbelow/layerleak` is frozen at `v1.0.0` forever, and the
`v2.0.0`–`v2.5.0` GitHub and container tags were never valid Go modules. Pick
the track that matches what you run today. [CHANGELOG.md](./CHANGELOG.md)
lists every change; this guide only covers what you must do differently.

## What 3.0.0 does and does not break

Unchanged:

- The HTTP API stays at `/api/v1`. Existing paths, request bodies, response
  fields and error codes keep their names and types; 3.0.0 only adds fields,
  error codes and two opt-in features (bearer tokens and a metrics listener).
  Scans remain synchronous.
- The PostgreSQL schema stays at migration `0004`. No new migration ships.
- The binary is still called `layerleak`, and `layerleak scan <reference>`
  with the default summary output exits `0` for a clean image as before.
- Fingerprints are still `sha256` of the raw secret value, unsalted and
  identical across installs; the `detector_name` field keeps its name.

Changed:

- Module path `/v3`; install with
  `go install github.com/brumbelow/layerleak/v3@v3.0.0`.
- `result_schema_version` and `record_schema_version` are `2`. JSON Schemas
  are published at `web/docs/schemas/result-v2.schema.json` and
  `web/docs/schemas/scan-record-v2.schema.json`; the field diff is below.
- Exit code `3` means the scan finished with usable but incomplete coverage
  and `--allow-partial` was not given (it exited `1` before); `--fail-on`
  chooses which confidence levels cause exit code `2`.
- One scan-record file per scan under `./findings` (or `--output-dir`,
  `LAYERLEAK_FINDINGS_DIR`); the legacy findings-array file, the nearest
  `go.mod` directory heuristic and all raw local output are gone, and a
  pre-existing directory is never `chmod`-ed.
- Redacted values have a fixed-length mask that no longer reveals the length
  or the tail of the secret.
- Environment and label findings cover the value alone, so their
  fingerprints change once; file findings are unaffected.
- Eight detector identifiers were renamed, and identifier-only detectors no
  longer claim high confidence.
- Multi-platform images scan only the `linux` manifests (and entries with no
  OS) by default; other operating systems and non-image index entries are
  reported as `platform_skipped` / `manifest_skipped` diagnostics instead of
  failing the scan. A selected manifest whose layers cannot be scanned is
  `manifest_unsupported` (partial, acceptable with `--allow-partial`).
- `LAYERLEAK_LOG_LEVEL` accepts exactly `debug`, `info`, `warn`, `error`.
- Go API: `registry.NewClient` returns `(*Client, error)`.

## Track 1: v1.0.0 CLI users

1. Install from the new module path. The binary name does not change:

   ```bash
   go install github.com/brumbelow/layerleak/v3@v3.0.0
   layerleak version
   ```

   `layerleak version` prints the version, commit, build time, Go version
   and platform (`--format json` for the same as JSON); `layerleak --version`
   still prints the first line. Remove any binary built from
   `github.com/brumbelow/layerleak@v1.0.0` that is earlier on your `PATH`.

2. Replace the two-file output expectations. v1 wrote a findings array under
   `findings/` (with raw `value` and `raw_context_snippet` fields when
   `LAYERLEAK_PERSIST_RAW_SECRETS=1`, and a cap on low-confidence entries)
   plus a companion record under `findings/scans/`, looked for the nearest
   `go.mod` to place them and ran `chmod 0700` on the directory every time.
   3.0.0 writes exactly one record per scan:

   | | v1.0.0 | 3.0.0 |
   | --- | --- | --- |
   | Files | findings array plus `findings/scans/` record | one `<dir>/<utc-timestamp>-<reference-token>-<random>.json` |
   | Directory | nearest `go.mod` directory, `chmod 0700` on every run | `--output-dir`, else `LAYERLEAK_FINDINGS_DIR` (relative to the working directory), else `./findings`; created `0700` when missing, never `chmod`-ed when present, a symbolic link in its place is refused |
   | Record version | 1 | `record_schema_version: 2` |
   | Record content | findings with optional raw fields | `created_at`, `result` (the `--format json` result), `findings[]` (every finding, actionable first, with `source_location`), `persistence` (`disabled`, `saved` with `scan_run_id`, or `failed` with `storage_unavailable`) |
   | Raw values | optional, locally | never; raw persistence is PostgreSQL-only |
   | File mode | directory `0700` | record `0600`, never overwrites an existing file |

   Consumers of the old array read `findings[]` from the record instead.
   New flags: `--output <file>` (`-` for stdout) writes the formatted result
   to a file created `0600`, `--output-dir <dir>` chooses the record
   directory, `--no-artifacts` writes no record and `--no-db` ignores
   `LAYERLEAK_DATABASE_URL` for one run. The record path is printed on
   stderr as `Scan record: "<path>"`.

3. Update scripts that parse exit codes:

   | Code | Meaning |
   | --- | --- |
   | `0` | Clean, complete scan (or an accepted `--allow-partial` scan with no blocking findings) |
   | `1` | Invalid input, operational failure (registry, network, authentication), persistence failure, or cancellation (SIGINT, SIGTERM, `LAYERLEAK_SCAN_TIMEOUT`) |
   | `2` | Actionable findings at or above `--fail-on` (default `low`); findings take precedence over `3` |
   | `3` | Usable but incomplete coverage not accepted with `--allow-partial` (was `1`) |

   `--fail-on low|medium|high|none` sets the lowest confidence of an
   actionable finding that produces exit code `2`; `none` reports only.
   Suppressed findings never affect the exit code. Scripts that retried on
   `1` should treat `3` as "investigate coverage".

4. Add `--all-tags` to repository sweeps. A bare repository (`layerleak scan
   mongo`) now scans `latest`; `layerleak scan mongo --all-tags` enumerates
   every public tag, and `--all-tags` with a tag or digest is rejected.

5. Update scripts that parse `detector_name`:

   | v1.0.0 identifier | 3.0.0 identifier |
   | --- | --- |
   | `digitalocean_pat` | `digitalocean_personal_access_token` |
   | `stripe_key` | `stripe_api_key` |
   | `gitlab_token` | `gitlab_personal_access_token` |
   | `jwt` | `json_web_token` |
   | `hashicorp_vault_token` | `vault_token` |
   | `docker_config_identitytoken` | `docker_config_identity_token` |
   | `npmrc_auth` | `npmrc_basic_auth` |
   | `planetscale_token` | `planetscale_service_token` |

   `twilio_account_sid` and `sentry_dsn` now report `medium` confidence,
   so a `--fail-on high` pipeline no longer fails on them.

6. Re-baseline suppressions keyed on the fingerprints of environment-variable
   or label findings. They used to cover `KEY=value`; they now cover the
   value alone, so their `fingerprint`, `match_start`, `match_end` and
   `redacted_value` equal those of the same secret found in a file, and the
   two no longer produce separate findings. This change happens once; file
   findings keep their fingerprints.

7. Update anything that parsed `redacted_value`. v1 showed the first three
   and last two characters around a mask whose length matched the secret.
   3.0.0 masks values shorter than 12 characters completely (`********`) and
   otherwise shows the first three characters followed by a fixed
   eight-character mask (`ghp********`); multi-line values stay
   `[REDACTED MULTILINE]`. Context snippets redact every copy of a matched
   secret inside the window, not only the first.

8. `--format json` now prints the result for failed scans too (exit code
   stays `1`, and the scan record is written), so automation can read
   `status: failed` and the diagnostics. It printed nothing before.

9. Accept the `sensitive_file_*` family: a sensitive file that cannot be read
   as text (binary or over `LAYERLEAK_MAX_FILE_BYTES`) is reported by path
   with an empty `redacted_value`, an empty `context_snippet`, `line_number`
   `0`, `match_start` = `match_end` = `0` and a fingerprint of
   `sha256(layer digest + "\n" + path)`. Parsers that required a non-empty
   value or a positive span must accept them.

10. New since v1.0.0 that you may want: `--format sarif` for code scanning,
    `--platform linux` OS-only selection, `--username`/`--password-stdin`
    and `LAYERLEAK_REGISTRY_USERNAME`/`LAYERLEAK_REGISTRY_PASSWORD` for
    private registries, `LAYERLEAK_DOCKER_CONFIG` for a Docker `config.json`,
    and proxy support through `HTTPS_PROXY`/`NO_PROXY`.

## Track 2: v2.x container and PostgreSQL installs

1. Back up the database.

2. Pull `ghcr.io/brumbelow/layerleak:v3.0.0`, stop the API replicas and run
   the migration command against the existing database before starting the
   new API:

   ```bash
   docker run --rm -e LAYERLEAK_DATABASE_URL="$LAYERLEAK_DATABASE_URL" \
     --entrypoint /usr/local/bin/layerleak-migrate-up ghcr.io/brumbelow/layerleak:v3.0.0 --status
   docker run --rm -e LAYERLEAK_DATABASE_URL="$LAYERLEAK_DATABASE_URL" \
     --entrypoint /usr/local/bin/layerleak-migrate-up ghcr.io/brumbelow/layerleak:v3.0.0
   ```

   `--status` prints the ledger against the shipped files without changing
   anything and exits `0` when current, `2` when migrations are pending and
   `1` on error; `--dry-run` lists what would be applied. The apply run
   adopts a legacy `0001`–`0003` schema that has no ledger (the rows are
   recorded without re-running the files), applies `0004` once, and is
   idempotent. Lock waits are bounded per transaction by
   `LAYERLEAK_MIGRATION_LOCK_TIMEOUT` (default `15s`, three attempts) and
   the whole run by `LAYERLEAK_MIGRATION_TIMEOUT` (default `30m`, `0`
   disables), so end long transactions first on a populated database. The
   API refuses to start, and `/readyz` answers `503 not_ready`, until the
   schema is exactly `0004` (`layerleak-migrate-up --status` exits `0`).

3. Compose users: `.env.example` ships `LAYERLEAK_DB_PASSWORD` empty and
   Compose refuses to start until it is set. The password reaches the
   containers as `PGPASSWORD` rather than inside the connection URL, the
   `api` service waits for the `migrate` service to complete, and a 35 second
   `stop_grace_period` (`LAYERLEAK_API_STOP_GRACE_PERIOD`) protects in-flight
   scans. Run `docker compose up -d` instead of running `migrate` by hand;
   `migrate` is no longer in the `tools` profile. `LAYERLEAK_DATABASE_URL`
   also accepts unix-socket URLs and libpq keyword strings, and `PGPASSWORD`
   or `PGPASSFILE` can carry the password outside Compose too.

4. Review raw-secret persistence. `LAYERLEAK_PERSIST_RAW_SECRETS` is still off
   by default and the CLI no longer writes raw values locally at all. If an
   earlier install stored raw values in PostgreSQL, the API logs a warning at
   startup. Check and remove them from the image's purge binary:

   ```bash
   layerleak-purge-raw-secrets --dry-run
   layerleak-purge-raw-secrets --confirm
   ```

   `--dry-run` only counts. Before `--confirm`, disable the setting on every
   writer and restart those processes: the purge clears rows in id-range
   batches (`--batch-size`, bounded by `LAYERLEAK_PURGE_TIMEOUT`, default
   `30m`), keeps committed batches when a later one fails, and recounts
   afterwards, exiting non-zero if a still-opted-in writer left residue.

5. Operational changes to expect: a scan that completes after its client
   disconnected is still persisted; on SIGTERM the API answers `503 not_ready`
   from `/readyz` and refuses new scans with `503 server_shutting_down` for
   `LAYERLEAK_API_PRESTOP_DELAY` (default `0s`), then cancels in-flight scans
   and exits `0` within `LAYERLEAK_API_SHUTDOWN_TIMEOUT` (default `30s`);
   one structured access record is logged per request; `GET /health`,
   `/livez` and `/readyz` include `version`; `/readyz` caches its result for
   `LAYERLEAK_API_READINESS_CACHE_TTL` (default `5s`); the API warns at
   startup when it listens on a non-loopback address without bearer tokens.
   Optional extras: `LAYERLEAK_API_BEARER_TOKENS` (or `_FILE`) and
   `LAYERLEAK_API_METRICS_ADDR`; see [docs/api-operations.md](./docs/api-operations.md).
   The container image no longer sets `LAYERLEAK_FINDINGS_DIR` (the API never
   wrote local findings).

## Track 3: API consumers

`/api/v1` paths, request bodies and existing response fields are unchanged.
Additions you may start reading:

- `result_schema_version: 2` results. Stored results produced by an earlier
  version are returned unchanged by `GET /api/v1/scans/{id}`, so branch on the
  version:

  | Field | v1 | v2 |
  | --- | --- | --- |
  | `result_schema_version` | `1` | `2` |
  | `scanned_at` | absent | RFC 3339 UTC scan start time, always present |
  | `scanner` | absent | `{ "name": "layerleak", "version": "<build version>" }`, always present |
  | `tags_enumerated`, `tags_resolved`, `tags_failed` | omitted when `0` | always present |
  | `suppressed_findings_count`, `suppressed_unique_fingerprints` | omitted when `0` | always present |
  | `tag_results[].status` | free string: `resolved`, `scanned`, `failed` | enum `resolved`, `scanned`, `partial`, `failed`, `skipped`, shared by both scan modes |
  | `platform` on findings and platform results | `{}` when empty | omitted when empty |
  | `findings[].redacted_value` | prefix, variable mask, suffix | fixed-length mask (see Track 1) |
  | `findings[].disposition_reason` | five reasons | adds `default_credentials` |
  | `findings[].detector_name` | old identifiers | renamed identifiers (see Track 1); `sensitive_file_*` findings carry empty value and snippet |

  Everything else (`status`, counters, `targets`, `coverage`, `diagnostics`,
  `findings` fields) keeps its name and type.
- New `POST /api/v1/scans` error codes: `404 image_not_found`,
  `503 registry_rate_limited` (with `Retry-After: 60`),
  `502 registry_unauthorized`, and `503 server_shutting_down` while the
  server drains. `GET /readyz` answers `503 not_ready`. `401 unauthorized`
  (with `WWW-Authenticate: Bearer realm="layerleak"`) appears only when the
  operator enables bearer tokens; send `Authorization: Bearer <token>` on
  every `/api/` request then. See the README status table and
  `web/docs/openapi.yaml`.
- Additive response fields: `limit_kind` and `limit` on
  `scan_limit_exceeded` errors; `registry` (the normalised filter) on
  repository scan and finding lists; `version` on `/health`, `/livez` and
  `/readyz`; and `next_cursor` on the three list endpoints. Pass it back as
  `cursor` to continue strictly after the last row; `limit` and `offset`
  keep working, but a cursor combined with a non-zero `offset`, a malformed
  cursor or one from another endpoint is `400 invalid_request`.
- Status classification is stricter: `408 scan_canceled` now means only that
  the client closed the connection, `504 scan_timeout` only that
  `LAYERLEAK_API_SCAN_TIMEOUT` expired, and a timeout or cancellation inside
  a registry request is `502 scan_failed`. `422 scan_limit_exceeded` carries
  a fixed message naming the limit kind and value.
- Two tightenings affect only malformed clients: the `{repository}` path
  segment is decoded once (`library%2Fapp` is `library/app`, but
  `library%252Fapp` is no longer read as `library/app`) and must match the
  OCI repository-name grammar (400 otherwise); `?registry=` must be
  `host[:port]` (400 otherwise); paths with repeated slashes or dot segments
  are a JSON 404 instead of a redirect.
- Redacted values and context snippets are shorter and never reveal a secret
  that appears twice in a window.

Nothing in 3.0.0 requires an API consumer change; a client that validated
`result_schema_version == 1` must accept `2`.
