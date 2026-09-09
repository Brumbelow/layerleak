# Release readiness verification

Verified on 2026-09-09 on local branch `release-readiness`.

The preparation work is implemented and independently reviewed against base
`e7bb40419961b33d2399355cca4c97ecc4bf8625`. This record covers local verification;
the pull request and its hosted checks identify the source to integrate. No
v1.1 release was published as part of this preparation.

## Delivered changes

1. Usable scan results survive database-save failures, including a database
   write deadline while the scan context remains live. Scan cancellation and
   persistence failures remain distinct. Progress-output failures cannot veto
   saving, and actual output failures remain operational errors.
2. Existing findings arrays are preserved. A matching `scans/` companion record
   contains the versioned redacted result, creation time, and explicit
   persistence outcome. Successful artifacts survive failure of the other
   publication, and both full paths are reported after progress finishes.
3. Repository pagination has a unique final ordering key. A real PostgreSQL
   regression test demonstrated duplicate and missing tied rows before the fix
   and stable pages afterward.
4. OpenAPI and static-documentation verification covers actual handler response
   fixtures, documented examples, local links/assets, and the synthetic demo.
   Documentation distinguishes development behavior from published versions.
5. Release tools are provisioned from reviewed, checksum-pinned downloads.
   Early checks enforce the required capabilities. Source-tag handoff and
   protected publication conform to repository requirements, retain exact-object
   retry behavior, and preserve the existing RC acceptance/promotion policy.
6. The ARM container build was corrected after actual runtime testing exposed
   x86-64 binaries inside an image labeled arm64. The Dockerfile now consumes
   BuildKit's target platform arguments and compiles on the build platform.
   CI and release smoke inspect the metadata and all four executable ELF
   headers before running containers.

## Verification results

| Check | Result |
| --- | --- |
| Full Go suite with disposable PostgreSQL 16.13, Go 1.25.13 | Passed |
| Repository-wide short race suite, Go 1.25.13 | Passed |
| Vet, module verification, tidy diff, formatting, whitespace | Passed |
| Local CLI installation, version, root help, and scan help | Passed |
| govulncheck 1.7.0 using Go 1.25.13 | No vulnerabilities found |
| OpenAPI 3.1, handler fixtures, documented examples, site links, demo | Passed |
| Four controlled-negative documentation checks | Passed |
| Hash-locked documentation dependencies installed on Python 3.13 | Passed |
| Fifteen release-preflight and executable-platform tests | Passed |
| All workflows through Actionlint 1.7.12; release installer through ShellCheck | Passed |
| Compose default configuration and tools profile | Passed |
| linux/amd64 and linux/arm64 builds with Go 1.27.1 | Passed |
| Image metadata and all four ELF headers on each architecture | Passed |
| Both-platform functional container smoke | Passed with the host limitation below |
| Real isolated release-tool capability checks | Passed |
| Official GitHub CLI release/asset/attestation verification | Passed |
| Independent final source review | No remaining actionable findings |

The functional container checks used a fresh database for each architecture.
Both applied migrations twice, served `/health`, `/livez`, `/readyz`, and
`/api/v1/repositories`, and ran the bundled healthcheck executable. The amd64
API also refused startup before migration as expected. ARM execution used an
explicit QEMU user-mode helper without changing host architecture registration.

The independent review caught two follow-up issues: storage deadlines were
initially conflated with scan cancellation, and dynamic progress could erase
or truncate artifact paths. Both were fixed with failing-then-passing
regressions and verified in the final review.

No Go runtime dependency changed. Documentation validators are isolated
development dependencies in `requirements-docs.lock`.

## Local runtime limitation

This host's Snap Docker daemon rejects container execution with
`no-new-privileges` during its AppArmor transition, before the application
starts. Kernel audit messages confirmed that failure. Local functional smoke
therefore omitted that one runtime option while retaining the non-root image
user, read-only root filesystem, dropped capabilities, and default
AppArmor/seccomp behavior. Production Compose and CI/release runtime controls
retain `no-new-privileges` unchanged.

The exact restrictive profile must pass on the hosted runner for the candidate
source. Baseline GitHub CI success does not verify these changes, and local
functional smoke does not claim that missing profile check.

## Release-tool environment

The isolated local tool directory is
`/home/brumbelow/.local/share/layerleak/release-tools/2026-09-09`.
Reviewed versions are GitHub CLI 2.100.0, Cosign 3.0.2, Grype 0.99.1, and
Buildx 0.37.0. The release builders select BuildKit 0.33.0 by image digest.
See [RELEASING.md](../RELEASING.md) for reproducible setup and required inputs.

Real capability and verification checks passed with those tools. A local
fixture established valid handoff, exact-object retry, and rejection of
altered/conflicting objects without creating a tag ref. No real release
handoff, workflow dispatch, repository-setting change, or publication occurred.

## Remaining publication steps

1. Integrate the reviewed pull request through the protected branch process,
   then select the full candidate commit SHA.
2. Once the new check exists on a PR, authorize adding
   `Full verification / OpenAPI and static documentation` to the required main
   checks. The current remote list was inspected and does not include it.
   The release's reusable verification already includes this job.
3. Obtain green hosted verification for the exact commit, including the complete
   runtime profile and existing license/security gates.
4. Prepare the version-specific handoff and authorize the protected
   `v1.1.0-rc.1` dispatch. Verify the resulting image digests, release evidence,
   clean installation, and public Go proxy behavior.
5. Complete at least 72 hours of RC acceptance before a separately approved
   `v1.1.0` promotion of the same source and exact image digest. A source change
   requires a subsequent RC.
