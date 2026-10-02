# API operations

How to run `layerleak-api` in production and what to expect from it. The
contract itself is `web/docs/openapi.yaml`; the README "HTTP API" section has
the full status-code table. This note covers the operational behaviour around
it. The `LAYERLEAK_API_*`, database, registry and scan-limit variables below
are read by `internal/config` when the API starts and rejected with an error
naming the variable (never its value) when malformed. The remaining five are
read elsewhere: `layerleak-migrate-up` reads `LAYERLEAK_MIGRATION_TIMEOUT`,
`LAYERLEAK_MIGRATION_LOCK_TIMEOUT` and `LAYERLEAK_MIGRATIONS_DIR`,
`layerleak-purge-raw-secrets` reads `LAYERLEAK_PURGE_TIMEOUT`, and
`LAYERLEAK_API_STOP_GRACE_PERIOD` is read by Compose alone.

## Process model

- One process, one API listener (`LAYERLEAK_API_ADDR`, `host:port`;
  `127.0.0.1:8080` by default, `0.0.0.0:8080` in the image). Scans run
  synchronously inside `POST /api/v1/scans`, bounded by
  `LAYERLEAK_API_SCAN_TIMEOUT` (default `30m`) and gated by
  `LAYERLEAK_API_MAX_CONCURRENT_SCANS` (default `1`; excess requests get
  `429 scan_capacity_exceeded` with `Retry-After: 5`). There is no job queue
  or asynchronous mode.
- PostgreSQL is required (`LAYERLEAK_DATABASE_URL`; the password may travel
  as `PGPASSWORD`). The process refuses to start unless the schema is exactly
  `0004`; run `layerleak-migrate-up` first. Readiness re-runs the database
  ping and schema check and caches the answer for
  `LAYERLEAK_API_READINESS_CACHE_TTL` (default `5s`; `0` disables the
  cache), each check bounded by `LAYERLEAK_API_READINESS_TIMEOUT` (default
  `2s`). Concurrent probes share one check.
- There is no authorization, TLS termination, tenant isolation or
  cross-replica rate limiting built in. Put the API on a private network
  behind your own edge. The optional bearer-token check below is defence in
  depth, not a substitute.

## Bearer tokens

Authentication is off by default. Set `LAYERLEAK_API_BEARER_TOKENS` (comma
separated) or `LAYERLEAK_API_BEARER_TOKENS_FILE` (one token per line, at most
64 KiB), never both, to require `Authorization: Bearer <token>` on every path
under `/api/`. Each token must be at least 32 printable ASCII characters
without spaces; duplicates are collapsed. Tokens are hashed with SHA-256 at
load and only the digests stay in memory; every request is compared against
every digest in constant time. A missing, malformed or unknown token answers
`401 unauthorized` with the usual error envelope and
`WWW-Authenticate: Bearer realm="layerleak"` (plus `error="invalid_token"`
when a token was presented). The reason (`missing_token`,
`malformed_authorization`, `unknown_token`) is logged at info level with the
request id; the accepted token is identified at debug level by the first eight
hex characters of its digest. `/health`, `/livez` and `/readyz` never require
a token. When tokens are not configured and the listener is not loopback, one
warning is logged at startup.

## Metrics listener

`LAYERLEAK_API_METRICS_ADDR` (unset by default; it must differ from the API
address) adds a second listener that serves `GET /metrics` in the Prometheus
text exposition format with the same read, idle and write timeouts as the API
and the same drain. It is unauthenticated, so bind it to a private interface.
The families are:

| Family | Type | Labels |
| --- | --- | --- |
| `layerleak_build_info` | gauge (always `1`) | `version` |
| `layerleak_process_start_time_seconds` | gauge | |
| `layerleak_api_requests_total` | counter | `route` (mux pattern or `none`), `status_class` (`2xx`...) |
| `layerleak_api_request_duration_seconds` | histogram, fixed buckets from 5 ms to 30 min | `route` |
| `layerleak_scans_total` | counter | `outcome` (`completed`, `partial`, `failed`) |
| `layerleak_scan_errors_total` | counter | `code` (the `POST /api/v1/scans` error code) |
| `layerleak_scans_in_flight` | gauge | |

Label values are fixed strings chosen by the server; no path, repository,
reference, request body or secret ever becomes a label, and the page is
rendered in memory so a slow scraper cannot block request handling.

## Probes

| Path | Meaning |
| --- | --- |
| `GET /livez` | The process is up. `200 {"status":"ok","version":...}` while the server runs. |
| `GET /readyz` | Database reachable and schema exactly `0004`. `200 {"status":"ready",...}`; `503 not_ready` on any failure and for the whole drain window. |
| `GET /health` | Same handler and body as `/livez`. |

All three return JSON with a `version` field equal to the build version, so a
rollout can confirm which image answers. The image `HEALTHCHECK` runs
`layerleak-healthcheck`, which probes `/readyz` with a two-second deadline.

## Shutdown sequence

On SIGTERM or SIGINT:

1. `/readyz` starts answering `503 not_ready` and new scan requests are refused
   with `503 server_shutting_down`. In-flight requests continue. This lasts
   `LAYERLEAK_API_PRESTOP_DELAY` (default `0s`); set it to a few seconds so
   load balancers deregister the instance before step 2.
2. In-flight request contexts are cancelled; a scan interrupted this way
   answers `503 server_shutting_down`.
3. `http.Server.Shutdown` waits up to `LAYERLEAK_API_SHUTDOWN_TIMEOUT` (default
   `30s`) for handlers to finish; the metrics listener is closed after it.
   The process exits `0` after a clean drain and `1` (with one JSON error
   record) when the shutdown or serve returned an error.

Whatever runs the container must allow more than the sum of the two delays:
Compose ships `stop_grace_period: ${LAYERLEAK_API_STOP_GRACE_PERIOD:-35s}`;
use `docker stop -t 35` or a Kubernetes `terminationGracePeriodSeconds` above
the sum. A scan that completes after its client disconnected, or just as the
drain starts, is still persisted under `LAYERLEAK_DATABASE_WRITE_TIMEOUT`
(default `2m`), so a slow database can hold shutdown past the timeout.

## Logging

Logs are written to stderr at `LAYERLEAK_LOG_LEVEL` (one of `debug`, `info`,
`warn` or `error`, case-insensitive) as JSON lines by default;
`LAYERLEAK_LOG_FORMAT=text` switches both the API and the CLI to `key=value`
records. One `api request` record is written per request,
probes included, with `method`, `route` (the mux pattern, never the path),
`status`, `bytes`, `duration_ms`, `request_id` and `remote_addr`; set `warn`
if the probe noise matters. A failed scan adds an `api scan failed` record
with `error_type`, `error_code`, `status` and `request_id`; a failed read adds
`api storage request failed` with `operation` and `error_type`. Panics log
`panic_type` and the goroutine `stack`, never the panic value. net/http's own
errors and the fatal startup error go through the same logger. Secrets,
reference strings, paths, request bodies and query strings never appear in
logs.

Each response carries `X-Request-ID` (client-supplied when it is at most 128
characters of `A-Z a-z 0-9 - _ .`, otherwise generated); quote it when
reporting a problem.

## Error codes

Every error body is `{"error": {"code", "message", "request_id"}}` with a
fixed neutral message. The complete list of codes the API emits:

| Code | Status | Where | Usually means |
| --- | --- | --- | --- |
| `invalid_request` | 400 | every endpoint | Malformed body, reference, platform, pagination, cursor, `registry` or `disposition` value, or a `{repository}` segment outside the OCI grammar. |
| `unauthorized` | 401 | every `/api/` path with tokens enabled | Missing, malformed or unknown bearer token. |
| `not_found` | 404 | reads, unknown or non-canonical paths | No such scan or finding id; unknown route; repeated slashes or dot segments. |
| `image_not_found` | 404 | `POST /api/v1/scans` | The registry answered 404 for the repository, tag or manifest. |
| `method_not_allowed` | 405 | every endpoint | `Allow` names the accepted method. |
| `scan_canceled` | 408 | `POST /api/v1/scans` | The client closed the connection before the scan finished. |
| `request_too_large` | 413 | `POST /api/v1/scans` | Body over `LAYERLEAK_API_MAX_REQUEST_BYTES` (default 16 KiB). |
| `unsupported_media_type` | 415 | `POST /api/v1/scans` | `Content-Type` is not `application/json`. |
| `scan_incomplete` | 422 | `POST /api/v1/scans` | Coverage was partial; the body carries the partial result and diagnostics. |
| `scan_limit_exceeded` | 422 | `POST /api/v1/scans` | A configured bound stopped the scan; `limit_kind` and `limit` say which. |
| `scan_capacity_exceeded` | 429 | `POST /api/v1/scans` | `LAYERLEAK_API_MAX_CONCURRENT_SCANS` scans already running; `Retry-After: 5`. |
| `internal_error` | 500 | every endpoint | A panic, an unencodable result or a stored result that no longer parses. Alert on it. |
| `scan_failed` | 502 | `POST /api/v1/scans` | Registry or network failure during the scan, including a timeout or cancellation inside a registry request. |
| `registry_unauthorized` | 502 | `POST /api/v1/scans` | The registry or its token endpoint refused anonymous or configured credentials (401/403). |
| `storage_unavailable` | 503 | reads and `POST /api/v1/scans` | Database query failed, or the scan finished but could not be persisted; the scan body still carries the result. |
| `registry_rate_limited` | 503 | `POST /api/v1/scans` | The registry or its token endpoint answered 429 after bounded retries; `Retry-After: 60`. |
| `server_shutting_down` | 503 | `POST /api/v1/scans` while draining, and any request the drain cancelled | Retry against another instance. |
| `not_ready` | 503 | `GET /readyz` | Database unreachable, schema not `0004`, or draining. |
| `scan_timeout` | 504 | `POST /api/v1/scans` | `LAYERLEAK_API_SCAN_TIMEOUT` expired; raise it or scan fewer platforms. |

Worth alerting on: `storage_unavailable`, `internal_error`, a sustained
`scan_timeout` or `registry_rate_limited` rate, and `not_ready` outside a
deployment.

## Pagination

The three list endpoints accept `limit` (default 50, clamped to 200) and
`offset`, and every list response carries `next_cursor`: an opaque keyset
position when the page was full, `""` when the listing is exhausted. Passing
it back as `cursor` continues strictly after the last row at constant cost; a
cursor is bound to one endpoint and cannot be combined with a non-zero
`offset` (both are `400 invalid_request`). Cursors are at most 512 characters
and reveal nothing about their structure when rejected.

## Raw-secret persistence

`LAYERLEAK_PERSIST_RAW_SECRETS` is off by default and the API never returns
raw values even when it is on. At startup (when the setting is off) the
process counts stored raw material under the database query timeout and logs
a warning if any exists. Inspect and remove it with the image's purge binary:

```bash
layerleak-purge-raw-secrets --dry-run
layerleak-purge-raw-secrets --confirm [--batch-size N]
```

`--dry-run` needs no `--confirm` and changes nothing. The purge clears rows in
id-range batches (default `--batch-size 5000`), holding
the exclusive lock per batch, prints running totals to stderr, is bounded by
`LAYERLEAK_PURGE_TIMEOUT` (default `30m`, `0` disables), keeps committed
batches when a later one fails, and recounts afterwards: it exits `1` if a
writer still opted in left residue. Disable the setting on every API and CLI
instance and restart them before running it.

## Migrations

`layerleak-migrate-up` (`LAYERLEAK_DATABASE_URL`; `LAYERLEAK_MIGRATIONS_DIR`
defaults to `/app/migrations`) applies the checksummed migrations under an
advisory lock, one transaction each, adopting a legacy `0001`–`0003` schema
that has no ledger. Flags:

| Flag | Effect | Exit |
| --- | --- | --- |
| (none) | Apply pending migrations; idempotent. | `0` applied or already current, `1` error |
| `--status` | Print the ledger against the shipped files without changing anything. | `0` current, `2` pending or adoptable, `1` error |
| `--dry-run` | List what an apply run would adopt and apply. | `0`, `1` error |
| `--version` | Print the build version. | `0` |

`LAYERLEAK_MIGRATION_TIMEOUT` (default `30m`, `0` disables) bounds the whole
run and `LAYERLEAK_MIGRATION_LOCK_TIMEOUT` (default `15s`) bounds each
transaction's lock wait, retried three times, so an idle-in-transaction reader
cannot queue the migration indefinitely. Progress is printed to stderr. The
flags are mutually exclusive and `-h` exits `0`.

## Compose reference

`docker-compose.yml` runs `db`, `migrate` (to completion, before `api`), `api`
and the `purge-raw-secrets` tool (`--profile tools`). The database password
reaches the containers as `PGPASSWORD` from `LAYERLEAK_DB_PASSWORD`, which
must be set; `sslmode=disable` is acceptable only on the Compose-internal
network. For any remote database use `sslmode=verify-full` with the CA
mounted.
