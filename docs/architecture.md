# Architecture

Layerleak scans OCI images for likely secrets without a container runtime: it
talks to registries over HTTPS, replays image layers in memory with strict
bounds, runs a detector set over the reconstructed files and the image
configuration, and reports redacted findings. This document maps the code to
that pipeline. For the security rationale behind the bounds see
[threat-model.md](threat-model.md) and [SECURITY.md](../SECURITY.md).

## Binaries

| Binary | Source | Purpose |
| --- | --- | --- |
| `layerleak` | `main.go`, `internal/cli` | The CLI. `scan` runs one image or a whole repository (`--all-tags`); `version` prints build details. |
| `layerleak-api` | `cmd/api`, `internal/api` | HTTP API in front of the same scan pipeline, persisting into PostgreSQL. |
| `layerleak-migrate-up` | `cmd/migrate`, `internal/storage` | Applies the checksummed migrations under `migrations/`. |
| `layerleak-purge-raw-secrets` | `cmd/purge` | Removes opt-in raw secret material from an existing database. |
| `layerleak-healthcheck` | `cmd/healthcheck` | Container `HEALTHCHECK` probe for `/readyz`. |

The container image ships the four API-side binaries; the CLI is installed with
`go install github.com/brumbelow/layerleak/v3@latest`.

## Scan pipeline

```text
reference ──► manifest.ParseReference
           ──► registry.Client (token auth, pinned TLS, allowlists, retries)
           ──► scanner.Scan
                 ├─ manifest: parse + validate root document, select platforms
                 ├─ image config: Env / Labels / history → metadata inputs
                 └─ per platform manifest:
                      layers.Replay (tar replay, whiteouts, bounds) → final files
                      detectors.Set.Scan over each scannable file and metadata value
                      findings normalisation (redaction, fingerprints, provenance)
           ──► detectionpolicy (test paths, placeholders, dummy values → dispositions)
           ──► jobs.Result (per target / platform coverage, counts, diagnostics)
           ──► outputs: CLI summary / JSON / SARIF, scan record file,
                        scanservice → storage (PostgreSQL), HTTP API responses
```

### `internal/manifest`

Parses and validates image references, image manifests and image indexes,
verifies descriptor digests and sizes, and selects which platform manifests to
scan. Default selection scans only `linux` manifests and skips attestation,
non-image and non-linux entries with diagnostics; `--platform` accepts
`os`, `os/arch` or `os/arch/variant` with variant normalisation.

### `internal/registry`

A hardened Docker Registry v2 client: token challenge handling, one long-lived
transport with DNS pinning and private-network blocking (configurable
allowlists), proxy support that keeps hostnames intact for the proxy, bounded
redirects that re-validate every hop and refuse https-to-http downgrades,
bounded retries honouring `Retry-After`, per-attempt deadlines, size-bounded
reads, RFC 8288 `Link` pagination for tag lists, and typed status errors so
callers can tell a missing image from an outage.

### `internal/layers`

Replays compressed tar layers in order to reconstruct the final filesystem
state while tracking deletions (whiteouts), hardlinks, symlinks and unsafe
entries. Every dimension is bounded: bytes per layer and per image, entries,
retained bytes, a fixed zstd window, and a per-file size above which files are
skipped with a `files_skipped_oversize` diagnostic. Decompression is streamed
and cancellable.

### `internal/scanner`

Orchestrates one image: fetches and verifies manifests and configs, drives
`layers.Replay`, feeds scannable files and metadata into the detector set,
applies the findings budget (`MAX_FINDINGS_PER_SCAN`, raw retention bytes) and
produces per-platform `PlatformResult`s with `Coverage` counters and
`Diagnostic`s. Coverage is explicit: a scan that could not look at everything
is `partial`, never silently `completed`.

### `internal/detectors` and `internal/detectionpolicy`

`detectors.Default()` is the detector set: structured parsers (AWS shared
credentials, git credentials, INI/npmrc style files), vendor-prefixed token
rules, context-keyed rules, connection URLs with embedded passwords, and a
keyword-entropy fallback with alphabet-aware thresholds. Matches carry a
priority and confidence so overlapping matches collapse deterministically.
`detectionpolicy` then assigns a disposition: `actionable`, or suppressed with
a reason such as `test_path`, `example_path`, `placeholder_marker`,
`reserved_host` or `known_dummy_value`. Suppressed findings are still reported
and counted, never dropped.

### `internal/findings`

Turns detector matches into public findings: the redacted value, the stable
fingerprint (`sha256` of the raw value, unsalted and identical across
installs), a context snippet with every occurrence of the secret removed, and
provenance (file path, layer digest, metadata key, line number). Raw material
is kept only in `DetailedFinding` fields that never serialise.

### `internal/jobs` and `internal/scanservice`

`jobs.Scan` runs one request against one reference or a whole repository,
aggregating targets, tags, counts and diagnostics into `jobs.Result`, the
shape both the CLI and the API emit. `scanservice` wraps it for the API and the
persistent CLI mode: it builds the registry client from `config.Config`, runs
the scan, and persists the completed result through `storage.Store` under a
write deadline that survives a disconnected client.

### `internal/storage`

PostgreSQL persistence (`lib/pq`): scan runs, findings and occurrences with
batched upserts, repository/tag/manifest bookkeeping, read models for the API
list endpoints, control-character sanitisation at the boundary, and the
migration engine (advisory lock, checksummed ledger, one transaction per
migration, bounded lock waits). Shipped migrations are frozen by a checksum
test. The API refuses to start before the schema is current.

### `internal/api`

`net/http` handlers for `POST /api/v1/scans`, scan/finding reads, repository
listings and the health probes, with request bounds, a scan concurrency gate,
neutral error envelopes, security headers, request ids and graceful shutdown.
See `web/docs/openapi.yaml` for the contract.

### `internal/cli`

Cobra commands. `scan` renders a summary, JSON or SARIF, writes a scan-record
file, optionally persists to PostgreSQL, and maps outcomes to exit codes
(`0` clean, `1` operational failure, `2` findings at or above `--fail-on`,
`3` incomplete coverage not accepted by `--allow-partial`).

### Supporting packages

`internal/config` loads and validates every `LAYERLEAK_*` variable;
`internal/limits` carries the typed limit-exceeded errors; `internal/version`
resolves the build version; `internal/sarif` encodes results as SARIF 2.1.0.

## Repository layout

```text
.github/workflows/   CI (verify.yml via test.yml), CodeQL, Codacy, Pages, release
cmd/                 API-side binaries
docs/                plans, history, this architecture note, threat model
internal/            all Go packages (no public Go API is offered)
migrations/          numbered SQL migrations, checksum-frozen once shipped
scripts/             release preflight and tool installer, docs validators
web/                 GitHub Pages site, OpenAPI document, JSON schemas, fixtures
```
