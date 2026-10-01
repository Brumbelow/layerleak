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
- A versioned, always-redacted companion scan record under `findings/scans/`
  containing image identity, coverage, diagnostics, counts, creation time, and
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

### Removed

- `cmd/scanner`, a byte-identical duplicate of the module root CLI; use
  `go run .` for development.
- `scripts/layerleak-migrate-up.sh`, an unreferenced wrapper around
  `go run ./cmd/migrate`.
- The `# syntax=docker/dockerfile:1.7` directive and the image-level
  `LAYERLEAK_FINDINGS_DIR` default.

### Compatibility

- Automation that relied on a bare repository scanning every tag must add
  `--all-tags` or API `"all_tags": true`.
- Detector matches now come from Layerleak's native rule set instead of the
  previously linked fallback; provider coverage and detector identifiers can
  differ for uncommon contextual formats.
- Deployments must apply migration 0004 before `/readyz` returns success.
- Compose deployments must set `LAYERLEAK_DB_PASSWORD`.
- Existing `findings/*.json` files remain findings arrays. The new object
  record uses the same basename under `findings/scans/`, so non-recursive
  consumers remain compatible.
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
