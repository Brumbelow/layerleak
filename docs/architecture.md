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
| `layerleak` | `main.go`, `internal/cli` | The CLI. `scan` runs one image or a whole repository (`--all-tags`); `version` prints build details (`--version` prints its first line). |
| `layerleak-api` | `cmd/api`, `internal/api` | HTTP API in front of the same scan pipeline, persisting into PostgreSQL. |
| `layerleak-migrate-up` | `cmd/migrate`, `internal/storage` | Applies the checksummed migrations under `migrations/`; `--status` and `--dry-run` only report. |
| `layerleak-purge-raw-secrets` | `cmd/purge`, `internal/storage` | Removes opt-in raw secret material from an existing database; `--dry-run` only counts. |
| `layerleak-healthcheck` | `cmd/healthcheck` | Container `HEALTHCHECK` probe for `/readyz`. |

The container image ships the four API-side binaries, CA roots and the
migrations; the CLI is installed with
`go install github.com/brumbelow/layerleak/v3@latest`.

## Scan pipeline

```text
reference ──► manifest.ParseReference
           ──► registry.Client (token auth, credentials, pinned TLS,
           │                    allowlists, proxy, retries)
           ──► scanner.Scan
                 ├─ manifest: parse + validate root document, select platforms
                 ├─ image config: Env / Labels / history → metadata inputs
                 └─ per platform manifest:
                      layers.Replay (tar replay, whiteouts, bounds) → final files
                      detectors.Set.Scan over each scannable file and metadata value
                      findings normalisation (redaction, fingerprints, provenance)
                        └─ detectionpolicy (test paths, placeholders, dummy
                           values → dispositions)
           ──► jobs.Result (per target / platform coverage, counts, diagnostics)
           ──► outputs: CLI summary / JSON / SARIF, scan record file,
                        scanservice → storage (PostgreSQL), HTTP API responses
```

### `internal/manifest`

Parses and validates image references, image manifests and image indexes,
verifies descriptor digests (sha256 or sha512) and sizes, and selects which
platform manifests to scan. Default selection takes every image manifest whose
OS is `linux` or unspecified and reports other operating systems as
`platform_skipped` and attestation, nested-index and other non-image entries
as `manifest_skipped`; `--platform` accepts `os`, `os/arch` or
`os/arch/variant` with containerd-style variant normalisation.

### `internal/registry`

A hardened Docker Registry v2 client: `WWW-Authenticate` challenge handling
with a token cache scoped to host, challenge and credential identity; a
`CredentialSource` chain (a static credential bound to one host, a Docker
`config.json` reader) consulted only after a 401 and only over https; one
long-lived transport with DNS pinning and private-network blocking
(configurable allowlists); proxy support that keeps hostnames intact for the
proxy; bounded redirects that re-validate every hop, refuse https-to-http
downgrades and drop `Authorization` across hosts; bounded retries honouring
`Retry-After`; per-attempt deadlines; size-bounded reads; RFC 8288 `Link`
pagination for tag lists; and typed status errors (`StatusError`,
`RequestError`) so callers can tell a missing image from an outage.

### `internal/layers`

Replays compressed tar layers in order to reconstruct the final filesystem
state while tracking deletions (whiteouts), hardlinks, symlinks and unsafe
entries. Every dimension is bounded: bytes per layer and per image, entries,
retained bytes, a fixed 128 MiB zstd window, and a per-file size above which
files are skipped with a `files_skipped_oversize` diagnostic. Decompression is
streamed and cancellable, and trailing data after a compressed stream fails
the layer (`layer_trailing_data`).

### `internal/scanner`

Orchestrates one image: fetches and verifies manifests and configs, drives
`layers.Replay`, feeds scannable files and metadata into the detector set,
reports unreadable sensitive files by path (`sensitive_file_*`), applies the
findings budget (`LAYERLEAK_MAX_FINDINGS_PER_SCAN`, raw retention bytes) and
produces per-platform `PlatformResult`s with `Coverage` counters and
`Diagnostic`s. Coverage is explicit: a scan that could not look at everything
is `partial`, never silently `completed`.

### `internal/detectors` and `internal/detectionpolicy`

`detectors.Default()` is the detector set: structured parsers (AWS shared
credentials, git credentials, INI/npmrc style files, kubeconfig and cloud CLI
caches), vendor-prefixed token rules, context-keyed rules, connection URLs with
embedded passwords, framework and OS secret formats, and a keyword-entropy
fallback with an alphabet-aware threshold, all behind a required-literal
prefilter. Matches carry a priority and confidence so overlapping matches
collapse deterministically; `Set.Catalog()` lists every identifier a finding
can carry and backs the SARIF rule list. `detectionpolicy` discards a small
set of documentation placeholders outright and otherwise assigns a
disposition: `actionable`, or `example` with a reason (`test_path`,
`example_path`, `placeholder_marker`, `reserved_host`, `known_dummy_value`,
`default_credentials`). Suppressed findings are still reported and counted,
never dropped. See [false-positives.md](false-positives.md).

### `internal/findings`

Turns detector matches into public findings: the redacted value (first three
characters plus a fixed mask, or fully masked under twelve characters), the
stable fingerprint (`sha256` of the raw value, unsalted and identical across
installs), a context snippet with every occurrence of the secret removed,
control-character sanitisation shared with the API and storage, and
provenance (file path, layer digest, metadata key, line number, source
location). Raw material is kept only in `DetailedFinding` fields that never
serialise.

### `internal/jobs` and `internal/scanservice`

`jobs.Scan` runs one request against one reference or a whole repository,
aggregating targets, tags, counts and diagnostics into `jobs.Result`
(`result_schema_version` 2 with `scanned_at` and `scanner`), the shape both
the CLI and the API emit. `scanservice` wraps it for the API and the
persistent CLI mode: it builds the registry client and its credential chain
from `config.Config`, runs the scan, persists the completed result through
`storage.Store` under a write deadline that survives a disconnected client,
and produces the fully redacted `PublicResult`.

### `internal/storage`

PostgreSQL persistence (`lib/pq`): scan runs, findings and occurrences with
batched upserts, repository/tag/manifest bookkeeping, read models and keyset
cursors for the API list endpoints, control-character sanitisation at the
boundary, the batched raw-secret purge, and the migration engine (advisory
lock, checksummed ledger, one transaction per migration, bounded lock waits,
legacy-schema adoption, read-only status). Shipped migrations are frozen by a
checksum test. The API refuses to start before the schema is current.

### `internal/api`

`net/http` handlers for `POST /api/v1/scans`, scan/finding reads, repository
listings and the health probes, with request bounds, a scan concurrency gate,
optional bearer-token authentication, a hand-rolled Prometheus exposition on a
separate listener, neutral error envelopes, security headers, request ids,
one access-log record per request and graceful shutdown with a pre-stop
delay. See `web/docs/openapi.yaml` for the contract and
[api-operations.md](api-operations.md) for operations.

### `internal/cli`

Cobra commands. `scan` renders a summary, JSON or SARIF (`--output` to a
file), writes one scan-record file (`record_schema_version` 2) into a
directory it never `chmod`s, optionally persists to PostgreSQL, takes registry
credentials through `--username`/`--password-stdin`, and maps outcomes to
exit codes (`0` clean, `1` operational failure, `2` findings at or above
`--fail-on`, `3` incomplete coverage not accepted by `--allow-partial`).

### Supporting packages

`internal/config` loads and validates every `LAYERLEAK_*` variable (secrets
in a self-redacting `Secret` type, bearer tokens reduced to digests at load);
`internal/limits` carries the typed limit-exceeded errors; `internal/version`
resolves the build version from `-ldflags` or module build info;
`internal/sarif` encodes results as SARIF 2.1.0.

## Repository layout

```text
.github/workflows/   test.yml (calls verify.yml), CodeQL, Codacy, Pages, container release
cmd/                 API-side binaries (api, migrate, purge, healthcheck)
docs/                this note, threat model, operations guides, plans, reviews, history
internal/            all Go packages (no public Go API is offered)
migrations/          numbered SQL migrations, checksum-frozen once shipped
scripts/             release preflight and tool installer, documentation and schema validators, their tests
web/                 GitHub Pages site, demo, OpenAPI document, JSON schemas
```
