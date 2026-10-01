# API operations

How to run `layerleak-api` in production and what to expect from it. The
contract itself is `web/docs/openapi.yaml`; the README "HTTP API" section has
the status-code table. This note covers the operational behaviour around it.

## Process model

- One process, one listener (`LAYERLEAK_API_ADDR`, `0.0.0.0:8080` in the
  image). Scans run synchronously inside `POST /api/v1/scans`, bounded by
  `LAYERLEAK_API_SCAN_TIMEOUT` (default 30m) and gated by
  `LAYERLEAK_API_MAX_CONCURRENT_SCANS` (default 1; excess requests get
  `429 scan_capacity_exceeded` with `Retry-After: 5`).
- PostgreSQL is required. The process refuses to start unless the schema is
  exactly the expected version; run `layerleak-migrate-up` first. Readiness
  re-checks the database and schema and caches the answer for
  `LAYERLEAK_API_READINESS_CACHE_TTL` (default 5s).
- There is no authentication, TLS termination, tenant isolation or
  cross-replica rate limiting built in. Put the API on a private network behind
  your own edge. Bearer tokens can be switched on for `/api/v1` with
  `LAYERLEAK_API_BEARER_TOKENS` once that feature lands in this release (see the
  README table); health probes stay unauthenticated.

## Probes

| Path | Meaning |
| --- | --- |
| `GET /livez` | The process is up. Always `200` while the server runs. |
| `GET /readyz` | Database reachable and schema current. `503 not_ready` on any failure and for the whole drain window. |
| `GET /health` | Alias of liveness carrying `status` and `version`. |

All three return JSON with a `version` field equal to the build version, so a
rollout can confirm which image answers.

## Shutdown sequence

On SIGTERM or SIGINT:

1. `/readyz` starts answering `503 not_ready` and new scan requests are refused
   with `503 server_shutting_down`. In-flight requests continue. This lasts
   `LAYERLEAK_API_PRESTOP_DELAY` (default `0s`); set it to a few seconds so
   load balancers deregister the instance before step 2.
2. In-flight scans are cancelled and answer `503 server_shutting_down`.
3. `http.Server.Shutdown` waits up to `LAYERLEAK_API_SHUTDOWN_TIMEOUT` (default
   30s) for connections to close, then the process exits 0.

Whatever runs the container must allow more than the sum of the two delays:
Compose ships `stop_grace_period: 35s`; use `docker stop -t 35` or a Kubernetes
`terminationGracePeriodSeconds` above 30. A scan that completes just as the
drain starts is still persisted under `LAYERLEAK_DATABASE_WRITE_TIMEOUT`, so a
slow database can hold shutdown past the timeout; the process then exits 1 and
logs the shutdown error.

## Logging

Logs are JSON lines on stderr at `LAYERLEAK_LOG_LEVEL` (`debug`, `info`,
`warn`, `error`). One `api request` record is written per request with
`method`, `route` (the pattern, never the path), `status`, `bytes`,
`duration_ms`, `request_id` and `remote_addr`; readiness probes are included,
so set `warn` if the probe noise matters. Failures add `error_type`, `code` and
`status`. Panics log the panic type and goroutine stack, never the value.
net/http's own errors go through the same JSON logger. Secrets, reference
strings, request bodies and query strings never appear in logs.

Each response carries `X-Request-ID` (client-supplied when valid, otherwise
generated); quote it when reporting a problem.

## Error classes worth alerting on

| Code | Status | Usually means |
| --- | --- | --- |
| `storage_unavailable` | 503 | Database down or schema wrong; the body still carries the scan result when one exists. |
| `scan_timeout` | 504 | The API's own scan deadline expired; raise `LAYERLEAK_API_SCAN_TIMEOUT` or scan fewer platforms. |
| `scan_failed` | 502 | Registry or network failure during the scan, including registry-side timeouts. |
| `image_not_found` | 404 | The registry answered 404 for the repository, tag or manifest. |
| `registry_rate_limited` | 503 | The registry or its token endpoint answered 429 after bounded retries; honour `Retry-After`. |
| `registry_unauthorized` | 502 | The registry refused anonymous or configured credentials. |
| `scan_incomplete` | 422 | Coverage was partial; the body carries the partial result and diagnostics. |
| `scan_limit_exceeded` | 422 | A configured bound stopped the scan; `limit_kind` and `limit` say which. |

## Raw-secret persistence

`LAYERLEAK_PERSIST_RAW_SECRETS` is off by default and the API never returns
raw values even when it is on. At startup the process counts stored raw
material and logs a warning if any exists; remove it with
`layerleak-purge-raw-secrets --confirm` after disabling the setting on every
writer.

## Compose reference

`docker-compose.yml` runs `db`, `migrate` (to completion, before `api`), `api`
and the `purge-raw-secrets` tool. The database password reaches the containers
as `PGPASSWORD`; `sslmode=disable` is acceptable only on the Compose-internal
network. For any remote database use `sslmode=verify-full` with the CA mounted.
