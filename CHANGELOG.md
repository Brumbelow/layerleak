# Changelog

Notable user-visible changes are recorded here. Layerleak follows semantic
versioning on the canonical `github.com/brumbelow/layerleak/v3` module line.

## [Unreleased]

## [v3.0.0]

### Module path and major version

- The Go module path is now `github.com/brumbelow/layerleak/v3`; install with
  `go install github.com/brumbelow/layerleak/v3@latest`. The binary is still
  named `layerleak`.
- The root import path `github.com/brumbelow/layerleak` is frozen at v1.0.0 and
  the historical v2.0.0-v2.5.0 tags are not Go modules; see the historical
  version note below.
- The HTTP API path prefix (`/api/v1`) and the database schema version (`0004`)
  do not change with the module major.

### Added

- Explicit `--all-tags` repository sweeps; bare repositories now resolve
  `latest` like other container tooling.
- `--allow-partial` with machine-visible complete/partial/failed coverage,
  per-target status, diagnostics, and stable failure semantics.
- `--progress auto|tty|plain|off` for interactive and CI-friendly output.
- OCI sha256/sha512 integrity verification for manifests, image configs, and
  layer bodies.
- Scan-wide bounds for layer count, advertised layer bytes, retained state,
  artifacts, findings, request bodies, redirects, auth bodies, and total scan
  duration.
- Exact private registry and auth host allowlists; non-public network
  destinations remain blocked by default.
- API request IDs, body limits, scan concurrency, bounded server/database
  operations, graceful shutdown, `/livez`, and schema-aware `/readyz`.
- API `all_tags` request option matching CLI repository-sweep semantics.
- Native migration, raw-secret purge, and container healthcheck binaries.
- Checksummed, advisory-locked migration ledger with legacy 0001-0003 adoption
  and schema version 0004 hardening.
- Protected multi-platform release automation for linux/amd64 and linux/arm64,
  including full source gates, PostgreSQL/container smoke, Grype policy, SPDX
  SBOMs, SLSA provenance, GitHub attestations, and keyless Cosign signatures.
- Versioned OpenAPI 3.1 specification, release manifest, third-party notices,
  and release verification documentation.
- A versioned, always-redacted scan record per scan containing the public
  result, the findings with their source locations, creation time and the
  PostgreSQL persistence outcome.
- Pinned CI validation for OpenAPI 3.1, real handler response fixtures,
  documented response examples, local documentation links, and synthetic demo
  structure.
- `layerleak version` prints the version, commit (with a modified marker),
  build time, Go version, and platform, or the same as JSON with
  `--format json`; `--version` stays an alias for the first line.
- Registry HTTP failures are typed (`registry.StatusError` with helpers such as
  `IsNotFound`, `IsRateLimited`, `IsUnauthorized`) and transport failures are
  `registry.RequestError`, so callers can tell a missing image from an outage.
- Every registry and token request sends `User-Agent: layerleak/<version>`.
- `LAYERLEAK_DATABASE_URL` accepts unix-socket URLs
  (`postgres:///db?host=/var/run/postgresql`) and libpq keyword strings in
  addition to `postgres://` URLs; the password may be supplied through
  `PGPASSWORD` or `PGPASSFILE`.
- `layerleak-migrate-up` reads `LAYERLEAK_MIGRATION_TIMEOUT` (default `30m`,
  `0` disables) and `LAYERLEAK_MIGRATION_LOCK_TIMEOUT` (default `15s`), bounds
  its advisory-lock waits with three attempts, and prints progress to stderr.
- A golden-checksum test freezes the shipped `migrations/*.sql` files and
  `.gitattributes` forces LF checkouts, so an accidental edit fails CI instead
  of breaking every API startup against existing databases.
- Windows consoles are switched into virtual-terminal mode for the dynamic
  progress display, with a plain-text fallback when the console refuses.
- Booleans accept `yes`/`no`/`on`/`off` as well as `1`/`true`/`0`/`false`.
- `--platform` accepts `os`, `os/arch` and `os/arch/variant`; omitted parts
  match anything and variants are normalised like containerd
  (`linux/arm64/v8` equals `linux/arm64`, `linux/arm` equals `linux/arm/v7`).
- New diagnostic codes: `platform_skipped`, `manifest_skipped`,
  `manifest_unsupported`, `platform_not_found`, `layer_trailing_data` and
  `raw_retention_truncated`.
- Fuzz targets for layer replay (`FuzzApplyLayer`) and image-config parsing
  (`FuzzImageConfig`) plus table-driven replay fixtures (GNU sparse and
  contiguous files, root entries, PAX globals, device nodes, hardlink rules,
  trailing data, repeated digests, deep paths).
- API error codes for typed registry outcomes: `404 image_not_found`,
  `503 registry_rate_limited` (with `Retry-After: 60`) and
  `502 registry_unauthorized`; `503 server_shutting_down` while draining.
- API responses gain additive fields: `limit_kind` and `limit` on
  `scan_limit_exceeded` errors, `registry` on repository list responses, and
  `version` on `/health`, `/livez` and `/readyz`.
- One structured access-log record per API request (method, route pattern,
  status, bytes, duration, request id, remote address; never the path, query
  or body), and JSON logging for net/http's own errors and the fatal startup
  error.
- `LAYERLEAK_API_PRESTOP_DELAY` (default `0s`) and
  `LAYERLEAK_API_READINESS_CACHE_TTL` (default `5s`) for graceful drain and
  readiness caching.
- Private-registry authentication. `LAYERLEAK_REGISTRY_USERNAME` and
  `LAYERLEAK_REGISTRY_PASSWORD` supply a credential for the registry pinned by
  `LAYERLEAK_REGISTRY_BASE_URL`; `LAYERLEAK_DOCKER_CONFIG` names a Docker
  `config.json` whose `auths` entries (base64 `auth` or `username`/`password`,
  Docker Hub aliases resolved) are consulted per registry host; the CLI takes
  per-scan credentials with `--username` and `--password-stdin`. Credential
  helpers (`credsStore`/`credHelpers`) and identity tokens are reported as
  unsupported, and there is no implicit `~/.docker/config.json` lookup.
- On a 401 with a Bearer challenge the token request carries the credential as
  HTTP Basic; a Basic-only challenge is answered on the registry request.
  Tokens are cached per registry host, challenge and credential identity with
  their advertised lifetime (60s default, 24h cap, 10s safety margin) and
  refreshed on 401; anonymous and authenticated tokens never share an entry.
- Opt-in API bearer-token authentication: `LAYERLEAK_API_BEARER_TOKENS`
  (comma-separated, at least 32 printable ASCII characters each) or
  `LAYERLEAK_API_BEARER_TOKENS_FILE` (one per line) require
  `Authorization: Bearer <token>` on every `/api/` request; a missing or
  unknown token answers `401 unauthorized` with `WWW-Authenticate`. Health
  probes stay open, tokens are held only as SHA-256 digests and compared in
  constant time, and the API warns at startup when it listens on a
  non-loopback address without tokens.
- Prometheus metrics on a separate `LAYERLEAK_API_METRICS_ADDR` listener
  (`/metrics`, text exposition, no new dependency): requests by route and
  status class, request duration histogram, scans by outcome and error code,
  in-flight scans, process start time and build info. Labels never carry
  paths, references or secrets.
- Keyset pagination: the three list endpoints return an additive
  `next_cursor` and accept it as `cursor` to continue strictly after the last
  row; `limit` and `offset` keep working.
- `layerleak-purge-raw-secrets --dry-run` and `--batch-size`; the purge now
  clears rows in id-range batches holding the exclusive lock per batch, prints
  running totals, is bounded by `LAYERLEAK_PURGE_TIMEOUT` (default `30m`),
  keeps committed batches when a later one fails, and recounts afterwards so a
  writer still opted in cannot hide residue behind a successful exit.
- `layerleak-migrate-up --status` (exit 0 current, 2 pending, 1 error),
  `--dry-run` and `--version`; `-h` exits 0 in both admin binaries.
- `--format sarif` writes a SARIF 2.1.0 log: one run per scan,
  `tool.driver.version` from the build, every default-catalog detector listed
  under `rules`, `level` from confidence, suppressed findings as
  `suppressions`, image, manifest, platform and layer properties and a
  `layerleak/fingerprint/v1` partial fingerprint; `--output` works with it and
  the README shows the `upload-sarif` recipe.
- `--fail-on low|medium|high|none` selects the lowest confidence that produces
  exit code 2 (default `low` keeps the previous behaviour; `none` reports
  only), and exit code 3 reports usable but incomplete coverage that
  `--allow-partial` did not accept.
- Scan flags `--output <file>` (`-` for stdout), `--output-dir <dir>`,
  `--no-artifacts` and `--no-db`.
- The default summary output lists the actionable findings (detector,
  confidence, location, redacted value, platform), capped at 50 with
  "and N more".
- Published JSON Schemas (draft 2020-12) for the CLI result and the scan
  record at `web/docs/schemas/result-v2.schema.json` and
  `web/docs/schemas/scan-record-v2.schema.json`, golden fixtures under
  `internal/cli/testdata/`, and `scripts/validate_schemas.py`, which CI runs
  against the fixtures and every documented API response.
- Detector coverage for connection URLs with embedded passwords
  (`connection_url_credentials`: `postgres://`, `mysql://`, `mongodb(+srv)://`,
  `redis://`, `amqp://`, `cloudinary://` and friends); registry and
  package-manager credentials (Docker Hub `dckr_pat_`/`dckr_oat_` tokens,
  base64 `.dockerconfigjson` blobs, `registrytoken`, Artifactory, RubyGems,
  NuGet, crates.io, Maven `settings.xml`, `.pgpass`, `.my.cnf`, `.npmrc`
  `_password`, Composer and Bundler credentials); `Authorization: Basic` and
  `Bearer`, `X-Api-Key` and `PRIVATE-TOKEN` headers; and refreshed vendor
  prefixes for Slack, GitLab (nine token families), OpenAI, Notion, SonarQube,
  Grafana, Sentry, New Relic, PlanetScale, CircleCI, Twilio and Datadog.
- Detector coverage for kubeconfig files and cloud CLI caches (client key
  data, passwords, quoted tokens, base64 PEM keys in Kubernetes Secrets, gcloud
  refresh tokens, Azure CLI and AWS SSO token caches), cloud-provider formats
  (Google OAuth client secrets, Azure AD client secrets, storage SAS
  signatures, Service Bus shared access keys, Azure DevOps PATs, AWS STS
  session tokens, Alibaba access keys, Fly.io macaroons, Terraform Cloud
  tokens), operating-system and framework secrets (`/etc/shadow`, `.htpasswd`
  and modular-crypt password hashes, Laravel `APP_KEY`, Django/Flask
  `SECRET_KEY`, Rails master keys and `secret_key_base`, WordPress salts, PHP
  `define()` credentials, XML password elements and attributes) and long-tail
  SaaS tokens (Atlassian, Mailgun, Facebook, Supabase, Algolia, Duffel,
  Flutterwave, Twitch, Dropbox, Asana, Bitbucket, Kafka SASL JAAS). The
  default catalog now lists 161 identifiers.
- Path-only findings: a sensitive file that cannot be read as text (binary or
  over `LAYERLEAK_MAX_FILE_BYTES`) is reported by path under the
  `sensitive_file_*` family (private keys, keystores, password databases,
  credential stores, GPG keyrings) with an empty `redacted_value` and
  `context_snippet`, zero offsets and a fingerprint of
  `sha256(layer digest + "\n" + path)`; readable files never receive one.
- `detectors.Set.Catalog()` lists every identifier a finding can carry (the
  structured readers' sub-identifiers included) and backs the SARIF rule list;
  a corpus test asserts that every emitted identifier is in the catalog.
- `FuzzDetectorSetScan`, `BenchmarkDefaultSetScan*` and the
  `internal/scanner/testdata/corpus` fixtures (real positives and discarded
  placeholders, vendor shapes stored base64-encoded) drive the detector tests.

### Changed

- Safety limits now default to bounded production values instead of being
  disabled for manifests, configs, repository sweeps, and related aggregate
  work.
- Partial or failed coverage can no longer look like a successful clean scan.
- Registry reference parsing, platform selection, redirects, and detector
  precedence are stricter and deterministic.
- Finding provenance is secret-redacted and size-bounded before it reaches
  terminal, JSON, or database output.
- The embedded detector fallback is replaced by a native high-confidence rule
  set with explicit coverage for common self-identifying provider tokens.
- PostgreSQL connections use configurable pool and query/write deadlines and
  require the exact current schema for API readiness.
- The API image is shell-free, runs as numeric UID/GID 10001, supports a
  read-only root filesystem, and contains native administration tools instead
  of a package-manager-installed PostgreSQL client.
- Compose requires an explicit database password, pins PostgreSQL by
  multi-platform digest, exposes readiness, and drops all API capabilities.
- GitHub Actions and container bases are immutable-pinned, and prepared source
  tags are pushed only after staged artifacts pass verification.
- Scan and database-save failures retain separate outcomes. Available redacted
  results are still published locally after a database failure, and progress
  rendering cannot prevent persistence or result publication.
- API storage failures use neutral wording while retaining the result's actual
  completed, partial, or failed status and existing machine-readable error.
- Multi-platform container builds now compile each binary for the requested
  target architecture and verify the image metadata and ELF architecture
  before runtime smoke tests.
- The registry client works behind `HTTPS_PROXY`: proxied requests keep the
  registry hostname as the `CONNECT` target, skip local DNS pinning (the proxy
  is the egress control), and honour `NO_PROXY`; https-only and the allowlists
  still apply.
- One long-lived hardened transport per client with keep-alive; destination
  pinning lives in the dialer, which tries every validated address (IPv6/IPv4
  fallback). DNS is resolved once per request instead of twice.
- Repository tag sweeps parse RFC 8288 `Link` headers (several relations,
  unquoted `rel`, any parameter order, multiple headers); a header that cannot
  be parsed makes the sweep partial instead of silently truncating it.
- Retries back off exponentially with jitter (capped at 5s) or honour
  `Retry-After` (capped at 30s); only `GET`/`HEAD` are retried, on 408/429/5xx
  and transient transport failures. `LAYERLEAK_HTTP_TIMEOUT` applies per
  attempt and also bounds dial, TLS handshake, and the response headers of
  blob requests.
- `WWW-Authenticate` parsing honours quoted commas and escaped quotes, reads
  every header, and picks the first Bearer challenge even when Basic is listed
  first; `registry-1.docker.io/<name>`, `index.docker.io/<name>` and
  mixed-case `DOCKER.IO/<name>` keep the `library/` prefix.
- Findings and occurrences are written as multi-row batched upserts:
  persisting 10,000 findings dropped from 18.4s to 1.0s on loopback. Stored
  results are unchanged.
- Each migration transaction sets `lock_timeout` and retries a lock timeout
  instead of queuing indefinitely behind an idle-in-transaction reader; schema
  checks resolve every object in `current_schema()`.
- `storage.PostgresConfig` keeps up to five idle connections by default
  (capped at `MaxOpenConns`) instead of none when unset.
- A scan that completes after its client disconnected or after the scan
  deadline is still persisted under its own write deadline; only scans
  interrupted mid-flight are discarded.
- Configuration is validated at load: `LAYERLEAK_API_ADDR` must be
  `host:port`, `LAYERLEAK_REGISTRY_BASE_URL`/`AUTH_URL` must be absolute
  http(s) URLs, and `LAYERLEAK_LOG_LEVEL` accepts exactly `debug`, `info`,
  `warn`, `error`. The unused `Config.MigrationsDir` is gone.
- Compose: the `api` service waits for the `migrate` service, so a fresh
  volume becomes ready with one `docker compose up -d`; the database password
  reaches the containers as `PGPASSWORD` rather than inside three URLs; a 35s
  `stop_grace_period` lets the shutdown drain finish.
- Dockerfile: the floating `# syntax=docker/dockerfile:1.7` frontend is
  gone (the digest-pinned BuildKit supplies its own), builds pass
  `-buildvcs=false` explicitly, and `.dockerignore` is an allowlist.
- Release tooling pins move to Grype 0.119.0, cosign 3.1.3, Buildx 0.37.2,
  BuildKit 0.33.1 and GitHub CLI 2.102.0; the image scan job runs the
  checksum-pinned Grype directly instead of a third-party action.
- Multi-platform selection and layer handling: see the detector, layer and
  scanner entries added by the 3.0.0 fix waves below.
- Default platform policy: without `--platform` only `linux` manifests of a
  multi-platform index are scanned; other operating systems are reported as
  `platform_skipped` and attestation, in-toto, nested-index and other
  non-image entries as `manifest_skipped` instead of failing the scan.
  `layerleak scan golang:latest` now completes where it exited 1.
- A selected manifest whose layers are foreign or non-distributable (Windows
  base layers) is reported as `manifest_unsupported`: that platform fails, the
  remaining platforms run, the scan is partial and `--allow-partial` can
  accept it. Genuine digest, size and media-type mismatches stay fail-closed.
- `--platform` is enforced for single-manifest images: a selector that does
  not match the image config fails with `platform_not_found` instead of
  silently scanning another platform.
- Document validation accepts Docker foreign and OCI non-distributable layer
  media types and non-image index entries; digest, size and platform syntax
  are still validated for every entry.
- The root manifest digest and size are verified before any JSON is parsed; a
  malformed body under a digest reference fails with
  `descriptor_digest_mismatch` rather than `invalid_manifest_document`.
- Old-GNU sparse (`S`) and GNU contiguous (`7`) tar entries are scanned as
  regular files; a `./` or `.` root directory entry is no longer counted as an
  unsafe entry; PAX global headers are skipped; hardlinks to symlinks or other
  non-file entries are not counted as files or binary exclusions.
- `LAYERLEAK_MAX_RAW_FINDING_BYTES` no longer stops detection: once spent,
  remaining findings are recorded without raw values, coverage stays complete
  and one `raw_retention_truncated` diagnostic replaces
  `max_raw_finding_bytes_exceeded`, which is no longer emitted.
- A findings budget already exhausted when a scan starts yields a partial
  result with `max_findings_exceeded` instead of "all selected manifests
  failed"; budget diagnostics appear exactly once.
- Platform strings for os-only platforms render as `linux` rather than
  `linux/`.
- `POST /api/v1/scans` classifies failures by the API's own contexts:
  `504 scan_timeout` only when `LAYERLEAK_API_SCAN_TIMEOUT` expired,
  `408 scan_canceled` only when the client closed the connection, and a
  timeout or cancellation inside a registry request is `502 scan_failed`.
- `422 scan_limit_exceeded` carries a fixed message naming the limit kind and
  value instead of the raw error chain.
- Graceful shutdown: on SIGTERM the API answers `503 not_ready` from
  `/readyz`, refuses new scans with `503 server_shutting_down` for the
  pre-stop delay while in-flight requests continue, then cancels in-flight
  scans and shuts down within `LAYERLEAK_API_SHUTDOWN_TIMEOUT`, exiting 0.
- Paths with repeated slashes or dot segments answer a JSON 404; the API never
  emits an HTML redirect. Panics are logged with type and stack (never the
  value) and `http.ErrAbortHandler` propagates.
- `?registry=` is validated as `host[:port]` (400 otherwise) and normalised
  like storage. `/readyz` reuses its result for the cache TTL and serialises
  concurrent probes; the startup raw-secret inventory runs under the database
  query timeout.
- OpenAPI documents every `ScanSummary` field and enum with closed schemas,
  `TagResult.status`, the sanitised error and diagnostic strings, 405 with
  `Allow` on every operation, the unknown-route 404 and the always-present
  `Cache-Control` and `X-Content-Type-Options` headers; the README lists
  every API status code.
- `result_schema_version` is 2. Results carry `scanned_at` (RFC 3339 UTC, the
  scan start time) and `scanner {name, version}`; the integer counters
  (`tags_enumerated`, `tags_resolved`, `tags_failed`,
  `suppressed_findings_count`, `suppressed_unique_fingerprints`) are always
  present; an empty `platform` is omitted instead of serialised as `{}`; and
  `tag_results[].status` is a typed enum shared by both scan modes
  (`resolved`, `scanned`, `partial`, `failed`, `skipped`), updated after each
  target finishes.
- A repository sweep that stops early (findings budget, limit, integrity
  error, cancellation) records every unscanned target as failed with a "not
  scanned" reason and marks its tags `skipped`, so `target_count` always
  equals completed + partial + failed; reference-mode results report
  `tags_enumerated`/`tags_resolved` as 0 and list the requested tag in
  `tag_results` whenever it resolved.
- Progress output counts partial targets, reports resolved tags once, keeps
  per-manifest scanner events in the scanning phase and emits one
  `target_done` per target.
- `--format json` prints the result for failed scans too (exit code still 1)
  and the scan record is written for them; CLI stdout JSON and the local
  record keep real, control-character-sanitised error and diagnostic messages
  with raw values redacted instead of the constant "scan step failed". Storage
  and the HTTP API keep the fully redacted result.
- Exactly one local artifact per scan,
  `<dir>/<utc-timestamp>-<reference-token>-<random>.json` with
  `record_schema_version` 2 (public result, findings with `source_location`,
  persistence outcome). The record directory is `--output-dir`, else
  `LAYERLEAK_FINDINGS_DIR` (relative values resolve against the working
  directory), else `./findings` under the working directory; the nearest
  `go.mod` heuristic is gone.
- Exit codes: 0 clean; 1 operational, input or persistence failure and
  cancellation; 2 actionable findings at or above `--fail-on`; 3 usable but
  incomplete coverage not accepted by `--allow-partial` (findings take
  precedence). Unaccepted partial coverage exited 1 before.
- The unaccepted-partial message tells the operator to re-run with
  `--allow-partial`; a scan-timeout error is printed once and names
  `LAYERLEAK_SCAN_TIMEOUT` and its value only when that deadline expired, while
  a blob or request deadline keeps its own text and hints at
  `LAYERLEAK_BLOB_TIMEOUT`/`LAYERLEAK_HTTP_TIMEOUT`; a signal cancellation
  names the signal.
- The first SIGINT/SIGTERM cancels the run with an "interrupt received,
  finishing... press again to force exit" note and restores default signal
  handling, so a second signal terminates the process (SIGINT still exits 1).
- Debug logging goes to the command's stderr; in `--progress auto` the dynamic
  renderer falls back to plain lines when `LAYERLEAK_LOG_LEVEL=debug`,
  `TERM=dumb` or `CI=true`.
- `redacted_value` masks values shorter than 12 characters completely and
  shows the first three characters followed by a fixed eight-character mask
  otherwise; the suffix and the length are no longer disclosed.
- Environment-variable and label findings cover the value alone, so their
  `fingerprint`, `match_start`, `match_end` and `redacted_value` equal those of
  the same secret found in a file and the two no longer produce separate
  findings. These fingerprints change once; see UPGRADING.md.
- Detector identifiers were renamed: `digitalocean_pat` ->
  `digitalocean_personal_access_token`, `stripe_key` -> `stripe_api_key`,
  `gitlab_token` -> `gitlab_personal_access_token`, `jwt` -> `json_web_token`,
  `hashicorp_vault_token` -> `vault_token`, `docker_config_identitytoken` ->
  `docker_config_identity_token`, `npmrc_auth` -> `npmrc_basic_auth`,
  `planetscale_token` -> `planetscale_service_token`.
- Identifier-only detectors (`twilio_account_sid`, `sentry_dsn`) report at
  medium confidence; `password_hash` and `facebook_access_token` are medium by
  shape; `sensitive_file_*` findings are medium (Java keystores low) and are
  never promoted above medium. `assigned_sensitive_value` ranks below the
  specific rules.
- Default-credential pairs on real hosts are reported as suppressed with the
  reason `default_credentials` instead of being discarded.
- Detection fixes: unquoted `KEY=VALUE` and quoted-key assignments
  (`"key": "value"`, `key: "value"`, `key = "value"`) are detectable; the
  entropy floor is alphabet-aware so hex, UUID-shaped and lowercase base64url
  secrets pass while content digests and lock files are skipped; `age` secret
  keys match their real uppercase Bech32 form; `basic_auth_url` handles
  compact JSON and mixed-case schemes; PEM/PGP blocks without an END marker,
  routable GitLab tokens, 76-character `ghr_` tokens, quoted `.npmrc` tokens,
  Databricks and Telegram boundaries, percent-encoded git credentials, quoted
  CRLF AWS profiles and BOM-prefixed INI files are detected; tokens ending in
  `-` match whole; `.netrc` passwords need `machine`/`login` context;
  suppression heuristics weigh placeholder markers and test paths on whole
  words; nested duplicate matches are dropped; `compareFindings` is
  deterministic. The default rule set runs 17-27x faster through a
  required-literal prefilter.
- `keyword_entropy` no longer reports CamelCase word compounds such as
  `RootManageSharedAccessKey`; `xml_password_*` ignore boolean and keyword
  values; `php_define_password` skips constants that describe a credential
  (`*_TTL`, `*_PATH`, `*_FILE`); `twitch_api_token` requires a credential
  word so the public `TWITCH_CLIENT_ID` is not reported.
- OpenAPI: `ScanResult` requires only the fields every
  `result_schema_version` carries and documents `scanned_at`, `scanner` and
  the counters as present from version 2, so stored 2.x results returned by
  `GET /api/v1/scans/{id}` stay valid; `TagResult.status` gains `partial` and
  `skipped`; `disposition_reason` gains `default_credentials`.

### Security

- Raw values remain opt-in; a confirmation-gated command can irreversibly clear
  stored raw values and snippets while preserving redacted history.
- Registry and auth egress policy rejects credentials, unsafe schemes,
  private/reserved destinations, redirect pivots, and malformed host entries.
- Digest mismatch, malformed compression, archive traversal, unsafe link state,
  and resource exhaustion produce explicit incomplete/failure results.
- Raw finding material is omitted from memory by default and has a scan-wide
  byte cap when persistence is explicitly enabled.
- Redirects from https to http are refused even for allowlisted hosts, so a
  bearer token can never be downgraded to cleartext.
- Transport errors no longer echo redirect targets with query strings;
  pre-signed CDN credentials are redacted to scheme, host and path.
- Deprecated site-local (`fec0::/10`) and IPv4-compatible (`::/96`) IPv6
  ranges are classified as non-public.
- A NUL byte or other control character in an image-config key, snippet or
  raw value no longer aborts persistence of the whole scan (which let a hostile
  image evade the audit trail); such characters become U+FFFD consistently in
  API JSON, CLI output and stored rows.
- `.env.example` no longer ships a live `postgres://postgres:postgres` DSN or
  a `change-me` password; both are blank so a forgotten edit fails loudly.
- The GitHub CLI pin moves to 2.102.0 (GHSA-wjmr-j3rp-mh2g,
  GHSA-4mq3-hpgx-9cx8, GHSA-39wj-f2f4-978v).
- The zstd decoder window is capped at a fixed 128 MiB regardless of
  `LAYERLEAK_MAX_LAYER_BYTES`; a ten-byte hostile frame no longer allocates
  513 MiB at the default configuration.
- Cancellation and timeouts are observed while draining sparse-file holes even
  when both byte limits are disabled.
- Bytes after the end of a layer's compressed stream still fail the layer
  closed, now under the dedicated `layer_trailing_data` code.
- Layer replay cost per archive entry no longer grows with path depth,
  closing an algorithmic slowdown that hostile deep-path layers could exploit
  within the default entry limits.
- Registry credentials travel only over https to the host they were looked up
  for; the token realm must still pass the allowlist and private-host checks;
  the `Authorization` header is dropped on any cross-host redirect; the
  configured environment pair is never bound to the registry of a submitted
  reference, so an API caller cannot make the server send the operator's
  credential to a registry or token realm the caller names. Passwords are
  held in `config.Secret` and every credential type redacts itself when
  formatted.
- The CLI never changes the permissions of a pre-existing findings
  directory: it is inspected with `Lstat`, a symbolic link in its place is
  refused, a group- or world-readable directory produces one warning, a
  missing directory is created `0700` and records are written `0600`. No raw
  secret value is ever written locally, even with
  `LAYERLEAK_PERSIST_RAW_SECRETS=1`.
- CLI registry credentials are taken only through `--password-stdin` (no
  `--password` flag), apply to the registry of the scanned reference over
  https only, and never appear in logs, output, records or the database; a
  401/403 exits 1 with "authentication to <registry host> failed".
- `context_snippet` redacts every copy of a matched secret inside the window,
  not only the first one.

### Removed

- `cmd/scanner`, a byte-identical duplicate of the module root CLI; use
  `go run .` for development.
- `scripts/layerleak-migrate-up.sh`, an unreferenced wrapper around
  `go run ./cmd/migrate`.
- The `# syntax=docker/dockerfile:1.7` directive and the image-level
  `LAYERLEAK_FINDINGS_DIR` default.
- The legacy findings-array file under `findings/`, its
  `LAYERLEAK_PERSIST_RAW_SECRETS` raw-value opt-in for local output, the
  low-confidence grouping cap and the nearest-`go.mod` output-directory
  heuristic. Raw secret persistence is database-only.
- The `max_raw_finding_bytes_exceeded` diagnostic (replaced by
  `raw_retention_truncated`).

### Compatibility

- Automation that relied on a bare repository scanning every tag must add
  `--all-tags` or API `"all_tags": true`.
- Detector matches now come from Layerleak's native rule set instead of the
  previously linked fallback; provider coverage and detector identifiers can
  differ for uncommon contextual formats.
- Deployments must apply migration 0004 before `/readyz` returns success.
- Compose deployments must set `LAYERLEAK_DB_PASSWORD`.
- Local output: one record per scan under `./findings` (or `--output-dir`,
  `LAYERLEAK_FINDINGS_DIR`) instead of a findings array plus a companion record
  under `findings/scans/`; the record is `record_schema_version` 2. Consumers
  of the old array must read `findings[]` from the record instead.
- `result_schema_version` 1 -> 2: new `scanned_at` and `scanner` fields,
  counters are no longer omitted when zero, `platform` is omitted when empty,
  `tag_results[].status` adds `partial` and `skipped` and uses `scanned` in
  both modes. Stored version 1 results keep their shape and version when the
  API returns them (they are never upgraded to version 2); only error and
  diagnostic message strings are neutralised on read, as before.
- Exit code 3 is new. Scripts that treated exit 1 as retryable must add 3 as
  "incomplete coverage"; `--fail-on` defaults to `low`, which preserves the
  previous exit 2 behaviour.
- `--format json` now prints a result on failure (exit 1) where it printed
  nothing.
- `redacted_value` has a new shape and the fingerprints of environment and
  label findings changed once; detector identifiers listed under "Changed"
  were renamed. Baselines keyed on these values must be regenerated.
- `sensitive_file_*` findings carry an empty `redacted_value`, an empty
  `context_snippet`, `line_number` 0 and `match_start` = `match_end` = 0;
  consumers that assumed a non-empty value or a positive span must accept
  them.
- Go API users: `registry.NewClient` returns `(*Client, error)` and reports
  configuration errors eagerly (`registry.MustNewClient` panics instead);
  transport failures are `*registry.RequestError` rather than `*url.Error`.
- `LAYERLEAK_LOG_LEVEL` values other than the four names (for example
  `info+2` or `warning`) are rejected at startup.
- `LAYERLEAK_HTTP_TIMEOUT` is a per-attempt deadline; the worst-case wall time
  of a request is attempts x timeout plus backoff.
- The container image no longer sets `LAYERLEAK_FINDINGS_DIR` and Compose no
  longer passes it; the API never wrote local findings.
- Compose users run `docker compose up -d` instead of running `migrate` by
  hand; `migrate` left the `tools` profile.
- Multi-platform images scan only `linux` manifests by default; pass
  `--platform` (for example `--platform windows/amd64`) to attempt another
  operating system.
- `max_raw_finding_bytes_exceeded` is no longer emitted; consumers keying on
  it should read `raw_retention_truncated` (coverage stays complete).
- `--platform` error messages changed wording (`platform selector must be os,
  os/arch or os/arch/variant`).
- The `{repository}` path segment is percent-decoded once (`library%252Fapp`
  is no longer read as `library/app`), must match the OCI repository-name
  grammar (400 otherwise), and `/api/v1/repositories/scans` and
  `/api/v1/repositories/findings` are 404 rather than the history of a
  repository named `scans` or `findings`.
- `408 scan_canceled` now means only that the client went away; registry
  timeouts surface as `502 scan_failed`.

## [v2.5.0] - 2026-05-20

Historical GitHub/container release. Added detectors, suppression signals, and
the version flag. This tag was published without a `/v2` module path and is not
a valid v2 Go module release.

## [v2.1.1] - 2026-05-05

Historical GitHub/container release. Improved error handling, test coverage,
configuration documentation, and finding-directory behavior. Not a valid v2 Go
module release.

## [v2.1.0] - 2026-04-30

Historical GitHub/container release. Added cross-registry repository API
scoping, graceful API/CLI shutdown, the main-branch Pages site, and Go test CI.
Not a valid v2 Go module release.

## [v2.0.0] - 2026-04-24

Historical GitHub/container release. Added API containerization, PostgreSQL
migration helpers, Compose deployment, GHCR publishing, GHCR scan support, and
CI/security workflow improvements. Not a valid v2 Go module release.

## [v1.0.0] - 2026-04-03

First stable, installable release of the root Go module and canonical CLI entry
point.

## Historical version note

Go requires a `/vN` module-path suffix for major versions v2 and newer. The
repository retained the root path while v2.0.0-v2.5.0 tags were created, so Go
correctly excludes those tags from `go install github.com/brumbelow/layerleak@latest`,
which stays at v1.0.0. They remain visible for provenance. No v1.1.0 was ever
published; canonical module releases resume at v3.0.0 on
`github.com/brumbelow/layerleak/v3`, which contains and supersedes that work.

[Unreleased]: https://github.com/Brumbelow/layerleak/compare/v3.0.0...HEAD
[v3.0.0]: https://github.com/Brumbelow/layerleak/compare/v2.5.0...v3.0.0
[v2.5.0]: https://github.com/Brumbelow/layerleak/releases/tag/v2.5.0
[v2.1.1]: https://github.com/Brumbelow/layerleak/releases/tag/v2.1.1
[v2.1.0]: https://github.com/Brumbelow/layerleak/releases/tag/v2.1.0
[v2.0.0]: https://github.com/Brumbelow/layerleak/releases/tag/v2.0.0
[v1.0.0]: https://github.com/Brumbelow/layerleak/releases/tag/v1.0.0
