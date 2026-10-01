# Upgrading to Layerleak 3.0.0

3.0.0 is the first release on the Go module path
`github.com/brumbelow/layerleak/v3`. The root module path
`github.com/brumbelow/layerleak` is frozen at `v1.0.0` forever, and the
`v2.0.0`–`v2.5.0` GitHub and container tags were never valid Go modules. Pick
the track that matches what you run today. [CHANGELOG.md](./CHANGELOG.md)
lists every change since `v2.5.0`; this guide only covers what you must do
differently. Where v1.0.0 and the v2.x tags behave differently, both are
stated; behaviour that existed only in unreleased builds of `main` between
`v2.5.0` and 3.0.0 is called out as such.

## What 3.0.0 does and does not break

Unchanged:

- The HTTP API stays at `/api/v1`. Existing paths, request bodies and
  response fields keep their names and types; 3.0.0 adds fields, the `/livez`
  and `/readyz` endpoints, error codes and two opt-in features (bearer tokens
  and a metrics listener). Scans remain synchronous. The one wire change a
  v2.x client can notice is the status and code of a failed
  `POST /api/v1/scans`, which was always `500` before (see Track 3).
- The PostgreSQL schema is exactly migration `0004`. A v2.x database
  (`0001`–`0003`) needs that one migration and nothing beyond it ships.
- The binary is still called `layerleak`, and `layerleak scan <reference>`
  with the default summary output exits `0` for a clean image as before.
- Fingerprints are still `sha256` of the raw secret value, unsalted and
  identical across installs; the `detector_name` field keeps its name.

Changed:

- Module path `/v3`; install with
  `go install github.com/brumbelow/layerleak/v3@v3.0.0`.
- `result_schema_version` and `record_schema_version` are `2`. JSON Schemas
  are published at `web/docs/schemas/result-v2.schema.json` and
  `web/docs/schemas/scan-record-v2.schema.json`; the field diff is below. No
  tagged release wrote either field before.
- Exit code `3` means the scan finished with usable but incomplete coverage
  and `--allow-partial` was not given (such scans exited `1` before);
  `--fail-on` chooses which confidence levels cause exit code `2`.
- One scan-record file per scan under `./findings` (or `--output-dir`,
  `LAYERLEAK_FINDINGS_DIR`); the findings-array file, the nearest `go.mod`
  directory heuristic and all raw local output are gone. A pre-existing
  directory is never `chmod`-ed and a symbolic link in its place is refused.
- Redacted values have a fixed-length mask that no longer reveals the length
  or the tail of the secret, and multi-line values no longer reveal their
  first line.
- Environment and label findings cover the value alone, so the fingerprints
  of those produced by the generic keyword and assignment detectors change
  once; file findings and vendor-pattern findings are unaffected.
- Seven shipped detector identifiers were renamed, and identifier-only
  detectors no longer claim high confidence.
- Multi-platform images scan only the `linux` manifests (and entries with no
  OS) by default; other operating systems and non-image index entries are
  reported as `platform_skipped` / `manifest_skipped` diagnostics instead of
  failing the scan. A selected manifest whose layers cannot be scanned is
  `manifest_unsupported` (partial, acceptable with `--allow-partial`).
- `LAYERLEAK_LOG_LEVEL` accepts exactly `debug`, `info`, `warn`, `error`; the
  `slog` offset forms such as `INFO+2` that v2.x accepted are rejected.
- Go API: `registry.NewClient` returns `(*Client, error)`.

## Track 1: pre-3.0.0 CLI users (v1.0.0 and source builds of the v2.x tags)

`go install github.com/brumbelow/layerleak@latest` resolves to `v1.0.0`,
because the v2.x tags carry a `go.mod` without a `/v2` suffix. A
binary you installed is therefore v1.0.0 unless you built it yourself from a
v2.x checkout with `go build`.

1. Install from the new module path. The binary name does not change:

   ```bash
   go install github.com/brumbelow/layerleak/v3@v3.0.0
   layerleak version
   ```

   `layerleak version` is new: it prints the version, commit, build time, Go
   version and platform (`--format json` for the same as JSON). The
   `layerleak --version` flag, added in v2.5.0, stays available as an alias;
   v1.0.0 had no version flag at all. Remove any binary built from
   `github.com/brumbelow/layerleak@v1.0.0` that is earlier on your `PATH`.

2. Treat an existing `findings/` directory as sensitive, then replace the
   output expectations. Every pre-3.0.0 build wrote one findings-array file
   per scan into `findings/` under the nearest directory containing a
   `go.mod` (falling back to the working directory) and capped low-confidence
   entries at three per file-and-fingerprint group. v1.0.0 wrote the raw
   secret and the raw context snippet into every entry, in a directory
   created `0755` and files created with the process umask (normally `0644`):
   a v1.0.0 `findings/` directory contains raw secrets in world-readable
   files, so delete it or move it somewhere protected before you upgrade.
   v2.0.0 switched to a `0700` directory, `0600` files and redacted fields,
   and wrote raw values only when `LAYERLEAK_PERSIST_RAW_SECRETS=1` was set.
   No tagged release wrote a scan record, a `findings/scans/` directory or a
   `record_schema_version`, and none `chmod`-ed an existing directory; the
   `findings/scans/` companion record existed only in unreleased builds.
   3.0.0 writes exactly one record per scan:

   | | v1.0.0 | v2.0.0–v2.5.0 | 3.0.0 |
   | --- | --- | --- | --- |
   | Files | one findings array `<dir>/<utc-timestamp>-<token>.json` per scan | same | one record `<dir>/<utc-timestamp>-<reference-token>-<random>.json` per scan |
   | Directory | `findings/` under the nearest `go.mod` directory, else the working directory; created `0755` | same location; created `0700` | `--output-dir`, else `LAYERLEAK_FINDINGS_DIR` (relative to the working directory), else `./findings`; created `0700` when missing, never `chmod`-ed when present, a symbolic link in its place is refused |
   | File mode | umask default (normally `0644`), truncates an existing file | `0600`, truncates an existing file | `0600`, never overwrites an existing file |
   | Raw values | `value` and `context_snippet` are the raw secret and raw snippet, always | `redacted_value` and a redacted `context_snippet`; raw `value` and `raw_context_snippet` only with `LAYERLEAK_PERSIST_RAW_SECRETS=1` | never; raw persistence is PostgreSQL-only |
   | Low-confidence entries | capped at three per group, with `occurrence_count` and `suppressed_occurrence_count` | same | every finding is listed |
   | Record | none | none | `record_schema_version: 2` with `created_at`, `result` (the `--format json` result), `findings[]` (every finding, actionable first, with `source_location`) and `persistence` (`disabled`, `saved` with `scan_run_id`, or `failed` with `storage_unavailable`) |

   Consumers of the old array read `findings[]` from the record instead.
   New flags: `--output <file>` (`-` for stdout) writes the formatted result
   to a file created `0600`, `--output-dir <dir>` chooses the record
   directory, `--no-artifacts` writes no record and `--no-db` ignores
   `LAYERLEAK_DATABASE_URL` for one run. The record path is printed on
   stderr as `Scan record: "<path>"`.

3. Update scripts that parse exit codes. Every pre-3.0.0 build used `0`,
   `1` and `2`, and exited `1` whenever a limit cut a scan short, even when
   it had found secrets:

   | Code | Meaning |
   | --- | --- |
   | `0` | Clean, complete scan (or an accepted `--allow-partial` scan with no blocking findings) |
   | `1` | Invalid input, operational failure (registry, network, authentication), persistence failure, or cancellation (SIGINT, SIGTERM, `LAYERLEAK_SCAN_TIMEOUT`) |
   | `2` | Actionable findings at or above `--fail-on` (default `low`); findings take precedence over `3` |
   | `3` | Usable but incomplete coverage not accepted with `--allow-partial` (was `1`) |

   `--fail-on low|medium|high|none` is new and sets the lowest confidence of
   an actionable finding that produces exit code `2`; `none` reports only.
   Suppressed findings never affect the exit code. Scripts that retried on
   `1` should treat `3` as "investigate coverage".

4. Add `--all-tags` to repository sweeps. Every pre-3.0.0 build scanned
   every tag when given a bare repository (`layerleak scan mongo`); 3.0.0
   scans `latest` instead, `layerleak scan mongo --all-tags` enumerates every
   public tag, and `--all-tags` with a tag or digest is rejected.

5. Update scripts that parse `detector_name`. The table lists the release
   that first emitted each old identifier; an eighth rename,
   `planetscale_token` to `planetscale_service_token`, affects only unreleased
   builds:

   | Old identifier | Emitted since | 3.0.0 identifier |
   | --- | --- | --- |
   | `stripe_key` | v1.0.0 | `stripe_api_key` |
   | `gitlab_token` | v1.0.0 | `gitlab_personal_access_token` |
   | `jwt` | v1.0.0 | `json_web_token` |
   | `docker_config_identitytoken` | v1.0.0 | `docker_config_identity_token` |
   | `npmrc_auth` | v1.0.0 | `npmrc_basic_auth` |
   | `digitalocean_pat` | v2.5.0 | `digitalocean_personal_access_token` |
   | `hashicorp_vault_token` | v2.5.0 | `vault_token` |

   `twilio_account_sid` (added in v2.5.0 at `high`) now reports `medium`
   confidence, so it no longer produces exit code `2` under `--fail-on high`;
   `sentry_dsn` is new in 3.0.0 and also reports `medium`.

6. Re-baseline suppressions keyed on the fingerprints of environment-variable
   or label findings. Every pre-3.0.0 build let the generic detectors
   (`keyword_entropy` and the assigned-value rules) match an unquoted
   `KEY=value` entry as one token, because `=` was part of their candidate
   character class, so such a finding was fingerprinted over `KEY=value` and
   never matched the same secret found in a file. 3.0.0 fingerprints the
   value alone, so `fingerprint`, `match_start`, `match_end` and
   `redacted_value` equal those of the file finding and the two no longer
   produce separate findings. This change happens once. File findings keep
   their fingerprints, and so do environment or label findings from
   vendor-pattern detectors (a `glpat-` or `sk_live_` token in an `ENV`
   line), which already matched the token alone.

7. Update anything that parsed `redacted_value`. Every pre-3.0.0 build showed
   the first three and last two characters around a mask five shorter than
   the secret (values of six characters or fewer were masked completely), and
   rendered a multi-line value as its first line followed by
   `...redacted...`, which exposed that line. 3.0.0 masks values shorter than
   12 characters completely (`********`), otherwise shows the first three
   characters followed by a fixed eight-character mask (`ghp********`), and
   renders every multi-line value as `[REDACTED MULTILINE]`. Context snippets
   redact every copy of a matched secret inside the window, not only the
   first.

8. `--format json` now prints the result for failed scans too (exit code
   stays `1`, and the scan record is written), so automation can read
   `status: failed` and the diagnostics. Every pre-3.0.0 build returned the
   error before printing anything.

9. Accept the `sensitive_file_*` family, new in 3.0.0: a sensitive file that
   cannot be read as text (binary or over `LAYERLEAK_MAX_FILE_BYTES`) is
   reported by path with an empty `redacted_value`, an empty
   `context_snippet`, `line_number` `0`, `match_start` = `match_end` = `0`
   and a fingerprint of `sha256(layer digest + "\n" + path)`. Parsers that
   required a non-empty value or a positive span must accept them.

10. New since v2.5.0 that you may want: `--format sarif` for code scanning,
    `--platform linux` OS-only selection, `--username`/`--password-stdin`
    and `LAYERLEAK_REGISTRY_USERNAME`/`LAYERLEAK_REGISTRY_PASSWORD` for
    private registries, `LAYERLEAK_DOCKER_CONFIG` for a Docker `config.json`,
    and proxy support through `HTTPS_PROXY`/`NO_PROXY`.

## Track 2: v2.x container and PostgreSQL installs

1. Back up the database.

2. Pull `ghcr.io/brumbelow/layerleak:v3.0.0`, stop the API replicas and run
   the migration command against the existing database before starting the
   new API. v2.x shipped migrations `0001`–`0003` and told you to apply them
   with `psql` or the image's `layerleak-migrate-up` shell script; 3.0.0
   replaces the script with a Go binary of the same name that keeps a
   migration ledger and adds `0004`:

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
   Compose refuses to start until it is set (v2.x defaulted it to
   `layerleak`). The password reaches the containers as `PGPASSWORD` rather
   than inside the connection URL, the `api` service waits for the `migrate`
   service to complete, and a 35 second `stop_grace_period`
   (`LAYERLEAK_API_STOP_GRACE_PERIOD`) protects in-flight scans. Run
   `docker compose up -d` instead of running `migrate` by hand; `migrate` is
   no longer behind the `manual` profile. `LAYERLEAK_DATABASE_URL` also
   accepts unix-socket URLs and libpq keyword strings, and `PGPASSWORD` or
   `PGPASSFILE` can carry the password outside Compose too.

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
   one structured access record is logged per request; `GET /livez` and
   `GET /readyz` are new beside `GET /health`, all three include `version`,
   and `/readyz` caches its result for `LAYERLEAK_API_READINESS_CACHE_TTL`
   (default `5s`); the API warns at startup when it listens on a non-loopback
   address without bearer tokens. Optional extras:
   `LAYERLEAK_API_BEARER_TOKENS` (or `_FILE`) and `LAYERLEAK_API_METRICS_ADDR`;
   see [docs/api-operations.md](./docs/api-operations.md).

## Track 3: API consumers

`/api/v1` paths, request bodies and existing response fields are unchanged.
Additions you may start reading:

- `result_schema_version: 2` results. Results stored by a v2.x API carry no
  `result_schema_version` field at all (`1` was written only by unreleased
  builds), and `GET /api/v1/scans/{id}` never upgrades a stored result: it
  keeps its original shape and version, and only its `error`,
  `error_message` and diagnostic `message` strings are replaced by fixed
  neutral text on read. Branch on the field being `2`:

  | Field | v2.x (no version field) | v2 |
  | --- | --- | --- |
  | `result_schema_version` | absent | `2` |
  | `scanned_at` | absent | RFC 3339 UTC scan start time, always present |
  | `scanner` | absent | `{ "name": "layerleak", "version": "<build version>", "detector_set_version": "sha256:<hex>" }`, always present |
  | `duration_ms` | absent | wall-clock milliseconds from `scanned_at` to completion, always present |
  | `coverage.files_transcoded_utf16`, `coverage.nested_archives_expanded`, `coverage.nested_entries_scanned` | absent | always present |
  | `tags_enumerated`, `tags_resolved`, `tags_failed` | omitted when `0` | always present |
  | `suppressed_findings_count`, `suppressed_unique_fingerprints` | omitted when `0` | always present |
  | `tag_results[].status` | free string: `resolved`, `scanned`, `failed` | enum `resolved`, `scanned`, `partial`, `failed`, `skipped`, shared by both scan modes |
  | `platform` on findings and platform results | `{}` when empty | omitted when empty |
  | `findings[].redacted_value` | prefix, variable mask, suffix | fixed-length mask (see Track 1) |
  | `findings[].disposition_reason` | five reasons | adds `default_credentials` |
  | `findings[].detector_name` | old identifiers | renamed identifiers (see Track 1); `sensitive_file_*` findings carry empty value and snippet |
  | `findings[].file_path` | layer path | layer path, or `outer/path!inner/path` for a file inside an archive stored in a layer |

  Everything else (`status`, counters, `targets`, `coverage`, `diagnostics`,
  `findings` fields) keeps its name and type.
- Failed scans are classified. A v2.x API answered every failed
  `POST /api/v1/scans` with `500` and the code `scan_failed` or
  `storage_failed` plus the raw error text. 3.0.0 answers `404
  image_not_found`, `408 scan_canceled` (the client closed the connection),
  `422 scan_incomplete` and `422 scan_limit_exceeded` (the error object adds
  `limit_kind` and `limit`), `429 scan_capacity_exceeded` (`Retry-After: 5`),
  `502 scan_failed` (transport errors, registry 5xx and a timeout or
  cancellation inside a registry request), `502 registry_unauthorized`,
  `503 storage_unavailable` (replaces `storage_failed`), `503
  registry_rate_limited` (`Retry-After: 60`), `503 server_shutting_down`
  while the server drains and `504 scan_timeout` when
  `LAYERLEAK_API_SCAN_TIMEOUT` expires, each with a fixed message instead of
  the raw error. Malformed requests gain `405 method_not_allowed` (a JSON
  envelope with an `Allow` header where v2.x returned the router's plain-text
  405), `413 request_too_large` and `415 unsupported_media_type` (v2.x had
  no body-size or media-type check).
  `GET /readyz` answers `503 not_ready`. `401 unauthorized` (with
  `WWW-Authenticate: Bearer realm="layerleak"`) appears only when the
  operator enables bearer tokens; send `Authorization: Bearer <token>` on
  every `/api/` request then. See the README status table and
  `web/docs/openapi.yaml`.
- Additive response fields: `registry` (the normalised filter) on
  repository scan and finding lists; `version` on `/health`, `/livez` and
  `/readyz`; and `next_cursor` on the three list endpoints. Pass it back as
  `cursor` to continue strictly after the last row; `limit` and `offset`
  keep working, but a cursor combined with a non-zero `offset`, a malformed
  cursor or one from another endpoint is `400 invalid_request`.
- Two tightenings affect only malformed clients: the `{repository}` path
  segment is decoded once (`library%2Fapp` is `library/app`, but
  `library%252Fapp` is no longer read as `library/app`) and must match the
  OCI repository-name grammar (400 otherwise); `?registry=` must be
  `host[:port]` (400 otherwise); paths with repeated slashes or dot segments
  are a JSON 404 instead of a redirect.
- Redacted values and context snippets are shorter and never reveal a secret
  that appears twice in a window.
- `POST /api/v1/scans` stays registry-only: a local image source
  (`oci:`, `oci-archive:`, `docker-archive:`) in `reference` is
  `400 invalid_request`. The CLI's `baselined` disposition never reaches the
  database, so API results keep the scanner's `actionable` and `example`
  dispositions.

Nothing in 3.0.0 requires an API consumer change beyond handling the new
failure statuses; a client that validated `result_schema_version == 1` must
accept `2`.
