# Layerleak release readiness and reliability plan

Status: preparation implemented and verified on 2026-09-09. Publication pending separate authorization.

Verification record: [release-readiness-2026-09-09.md](../release-readiness-2026-09-09.md).

Reviewed on 2026-09-09 at `e7bb40419961b33d2399355cca4c97ecc4bf8625` on `main`.

## Goal and approach

Prepare the current project for its first canonical v1.1 release, with reliable
result preservation, accurate failure reporting, documented output contracts,
and a reproducible release process. Keep the existing Go CLI, scan service,
PostgreSQL API, and package boundaries. Deliver focused changes that can each
be reviewed independently.

The recommended approach is to fix the concrete reliability gaps before
publishing an RC. Publishing the current tree first would leave those gaps in
the candidate; adding a major input source or service subsystem first would
expand the compatibility and testing work before establishing a released
baseline.

Implementation, committing, and opening a pull request were approved. Merging,
repository-setting changes, and release publication remain separate
authorizations. The release sequence below is planned work, not authorization
to dispatch it.

## Verified baseline

- The repository was cloned to `/home/brumbelow/src/layerleak`. The checkout
  was clean before this plan was added.
- There were no open GitHub issues or pull requests at review time.
- Local Go 1.26.5 passed `go test -short ./... -count=1 -cover`,
  `go test -short -race ./... -count=1`, `go vet ./...`, `go mod verify`,
  `go mod tidy -diff`, formatting, whitespace, and CLI version/help checks.
- GitHub CI on the reviewed commit passed PostgreSQL integration and migration
  checks, Compose validation, amd64/arm64 container smoke, dependency-license
  checks, and reachable Go vulnerability checks. Database and container tests
  were not rerun locally during planning.
- GitHub still identifies historical `v2.5.0` as latest. No `v1.1.0` or
  `v1.1.0-rc.*` tag/release was present.
- The current protected publication workflow has no observed dispatch run.
  Historical container-publication runs do not establish that the current
  release process works end to end.
- Immutable releases, the protected release environment, main rules, and v1
  tag protections are already configured.
- Local `gh 2.46.0` lacks the release-verification and attestation commands
  required by the documented process. This is a confirmed local prerequisite
  gap, not evidence of a GitHub runner failure.

The code observations below come from source review. Their failure cases must
be established with regression tests during implementation before claiming a
fix.

## 1. Preserve results and report scan/save failures accurately

Files: `internal/cli/scan.go`, `internal/scanservice/service.go`,
`internal/api/handler.go`, and their existing tests.

The CLI returns early on a database-save error before writing the local result
or requested JSON output (`internal/cli/scan.go:158`). Progress-write failures
can also prevent persistence through the `BeforeSave` callback. The service
retains a result but replaces the original scan error when saving fails
(`internal/scanservice/service.go:140`). The API describes every save error as
a completed scan (`internal/api/handler.go:723`).

- [x] Add controlled tests for completed, partial, and failed outcomes paired
  with successful and unsuccessful persistence.
- [x] Retain the scan outcome and persistence error separately; preserve the
  existing machine-readable storage error and HTTP status behavior.
- [x] Make progress rendering observational so an unavailable progress stream
  cannot veto database persistence or publication of available results.
- [x] Attempt local publication and requested stdout output for usable results
  after database-save failures. Keep operational-failure exit code `1` and
  existing cancellation behavior.
- [x] Replace inaccurate API completion wording with a neutral storage-error
  message. Keep raw internal error details out of public responses.

Acceptance: a simulated database-save failure preserves available redacted
results and produces exit code `1`; partial coverage remains partial; no scan
ID or persistence success is invented; progress-stream failure does not prevent
saving. Actual result-output failures remain visible. Tests cover combined
scan and save failures as well as the normal path.

## 2. Save a complete redacted scan record

Files: `internal/cli/results.go`, `internal/cli/results_test.go`,
`internal/cli/scan.go`, and shared result-serialization code only where needed.

The existing disk output is a findings array
(`internal/cli/results.go:68`), while the full `jobs.Result` includes status,
coverage, diagnostics, and image identity (`internal/jobs/scan.go:123`). A
saved findings array alone cannot describe scan completeness.

- [x] Keep the existing findings-array file format and location compatible.
- [x] Add a companion scan-record file under
  `${LAYERLEAK_FINDINGS_DIR}/scans/`, using the same generated scan basename.
  The default findings-directory resolution remains unchanged.
- [x] Define a versioned record containing the existing redacted result,
  creation time, and explicit persistence outcome. Include the requested and
  resolved references, coverage, diagnostics, and actionable/suppressed counts.
- [x] Reuse the existing redaction rules and safe file-publication behavior.
  The companion record stays redacted even when raw finding storage is enabled.
- [x] Report artifact paths clearly. If publication of either required artifact
  fails, return an operational error and retain any successfully published
  artifact; do not claim the two files form one atomic transaction.
- [x] Add tests for completed and partial scans with zero findings, error
  sanitization, raw-storage opt-in, file permissions, and concurrent filenames.

Acceptance: a reader can establish coverage and image identity from the saved
record without terminal logs or PostgreSQL. Existing findings-array consumers
remain compatible, and ordinary non-recursive findings-directory globs do not
mix the new object format with the old array format.

## 3. Stabilize repository pagination

Files: `internal/storage/read_postgres.go` and
`internal/storage/storage_integration_test.go`.

Repository listing orders by last-seen time and repository name without a
unique final key (`internal/storage/read_postgres.go:36`). Identical repository
names in different registries can tie.

- [x] Add a stable unique final ordering key without changing API parameters.
- [x] Add a PostgreSQL fixture with equal timestamps and the same repository
  name in different registries; verify successive pages against a fixed dataset.

Acceptance: repeated requests over unchanged data return the same ordering,
with each tied row present exactly once across pages. Concurrent dataset
changes remain subject to the existing offset-pagination semantics.

## 4. Protect the public contract and refresh documentation

Files: `.github/workflows/verify.yml`, `web/docs/openapi.yaml`,
`web/assets/demo-data.json`, `web/docs/index.html`, `web/index.html`,
`README.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, and focused validation fixtures
and scripts under `scripts/` and `web/testdata/`.

The project has extensive functional tests, but Pages currently checks file
existence rather than validating the OpenAPI contract and demonstration data.
The synthetic demo also shows older CLI output and raw database fields that do
not represent the current default configuration.

- [x] Add a pinned OpenAPI 3.1 validation step to reusable verification.
- [x] Validate representative redacted handler responses and documented
  examples for completed, partial, failed, and storage-error outcomes.
- [x] Check local documentation links/assets and demo JSON structure.
- [x] Refresh the synthetic demo to show current coverage/status output,
  redacted default storage, and the new saved-record behavior. Keep synthetic
  labeling explicit.
- [x] Explain the difference between development documentation, currently
  published versions, and planned RC examples. Preserve the intentional v1.1
  changelog/OpenAPI freeze needed for later promotion from the same commit.
- [x] Document the reliability changes, compatibility behavior, new artifacts,
  migration prerequisites, and exact supported install paths together.

Acceptance: CI catches invalid OpenAPI schemas, incompatible representative
responses, broken local assets, and malformed demo data. Install examples make
clear which published version they select. Demonstrations match current
defaults and contain synthetic data only.

## 5. Make the release process ready to execute

Files: `.github/workflows/container-release.yml`, `RELEASING.md`, and a focused
release-preflight script if it improves reuse.

- [x] Select and document a tested release-tool version set. Provide an
  isolated compatible GitHub CLI for local verification without replacing the
  system installation as an incidental change.
- [x] Pin or explicitly provision the required workflow tools. Check required
  commands and fields before staging images or performing publication writes.
- [x] Review source-tag creation and verification against repository rules;
  make the release procedure conform before any workflow dispatch.
- [x] Validate the unchanged RC acceptance interval and stable promotion of
  the exact accepted source commit and multi-platform image digest.
- [x] Prepare a reviewable release-readiness record: intended changes, full
  candidate source SHA when available, tests, tool versions, release notes,
  upgrade instructions, and unresolved release blockers, if any.

Acceptance: prerequisite failure is early and explicit; compatible tools can
perform the documented read-only verification; existing repository protections
remain effective; the candidate has a concrete verification record ready for
publication approval. A passing source check is not described as a successful
release rehearsal.

## Verification and completion gate

Each behavior change receives a focused regression test before its fix and a
review of the resulting diff. Run the normal short and race suites, vet,
formatting, module verification, and CLI smoke checks after the changes. Run
database tests against a disposable PostgreSQL instance and reuse the existing
Compose and both-platform container checks. Run new contract/documentation
checks through the same reusable verification workflow.

The preparation milestone is complete when the changes and documentation are
reviewable, applicable checks pass, a release candidate commit can be selected,
and any remaining publication prerequisite is explicit. Publication is a
separate step with externally visible effects.

## Planned publication sequence

Follow the existing `RELEASING.md` v1 policy. The root module path makes the
canonical v1 line appropriate; historical v2 tags remain preserved.

1. Obtain authorization for the exact candidate source and release dispatch.
2. Publish `v1.1.0-rc.1` through the protected procedure and validate a clean
   install, image digests, attached evidence, migration, and readiness.
3. Verify that RC publication leaves stable `@latest` and the container
   `latest` selection unchanged.
4. Complete at least 72 hours of documented RC acceptance. A code change
   requires another RC, not promotion of a different commit.
5. Obtain stable-publication approval, promote the same source and image digest
   to `v1.1.0`, and verify installation and release metadata after publication.

## Follow-up priorities after the release

1. Downloadable CLI binaries with checksums and provenance. Agree on the
   supported operating systems/architectures before expanding the build matrix.
2. Local OCI-layout/archive input for checking images produced by the owner's
   build pipeline before publication. Treat this as a separately designed
   feature with its own input contract and bounded-resource tests.
3. Broader deterministic benchmarks and bounded parser/property tests for
   cancellation, serialization, and resource behavior. Measure before choosing
   performance changes; preserve existing safety limits.
4. Derive future release-note baselines from the previous canonical stable
   release. The current hard-coded v1.0.0 baseline is appropriate for this first
   v1.1 transition but should not persist into every later patch release.

These follow-ups are prioritized proposals, not part of the initial
implementation approval.

## Evidence

- [Reviewed commit](https://github.com/Brumbelow/layerleak/commit/e7bb40419961b33d2399355cca4c97ecc4bf8625)
- [Passing CI for the reviewed commit](https://github.com/Brumbelow/layerleak/actions/runs/34237800812)
- [Published releases](https://github.com/Brumbelow/layerleak/releases)
- [GitHub CLI release verification](https://cli.github.com/manual/gh_release_verify)
- [Go module major-version rules](https://go.dev/blog/v2-go-modules)
