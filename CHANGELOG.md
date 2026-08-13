# Changelog

Notable user-visible changes are recorded here. Layerleak follows semantic
versioning on the canonical `github.com/brumbelow/layerleak` v1 module line.

## [Unreleased]

## [v1.1.0]

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
- GitHub Actions and container bases are immutable-pinned and release tags are
  created only after staged artifacts pass verification.

### Security

- Raw values remain opt-in; a confirmation-gated command can irreversibly clear
  stored raw values and snippets while preserving redacted history.
- Registry and auth egress policy rejects credentials, unsafe schemes,
  private/reserved destinations, redirect pivots, and malformed host entries.
- Digest mismatch, malformed compression, archive traversal, unsafe link state,
  and resource exhaustion produce explicit incomplete/failure results.
- Raw finding material is omitted from memory by default and has a scan-wide
  byte cap when persistence is explicitly enabled.

### Compatibility

- Automation that relied on a bare repository scanning every tag must add
  `--all-tags` or API `"all_tags": true`.
- Detector matches now come from Layerleak's native rule set instead of the
  previously linked fallback; provider coverage and detector identifiers can
  differ for uncommon contextual formats.
- Deployments must apply migration 0004 before `/readyz` returns success.
- Compose deployments must set `LAYERLEAK_DB_PASSWORD`.

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
correctly excludes those tags from `go install github.com/brumbelow/layerleak@latest`.
They remain visible for provenance; v1.1.0 contains and supersedes their work.

[Unreleased]: https://github.com/Brumbelow/layerleak/compare/v1.1.0...HEAD
[v1.1.0]: https://github.com/Brumbelow/layerleak/compare/v1.0.0...v1.1.0
[v2.5.0]: https://github.com/Brumbelow/layerleak/releases/tag/v2.5.0
[v2.1.1]: https://github.com/Brumbelow/layerleak/releases/tag/v2.1.1
[v2.1.0]: https://github.com/Brumbelow/layerleak/releases/tag/v2.1.0
[v2.0.0]: https://github.com/Brumbelow/layerleak/releases/tag/v2.0.0
[v1.0.0]: https://github.com/Brumbelow/layerleak/releases/tag/v1.0.0
