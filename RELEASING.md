# Releasing layerleak

Layerleak releases are created by the protected **Release** workflow. Do not
push a release tag first: public Go proxies can observe a tag immediately, and a
bad module version cannot be withdrawn reliably.

## Version policy

The module path is `github.com/brumbelow/layerleak`. Valid release inputs are:

```text
v1.<minor>.<patch>-rc.<positive integer>
v1.<minor>.<patch>
```

Numeric identifiers cannot have leading zeroes. The workflow rejects v2 and v3
tags because those majors require `/v2` or `/v3` in the module path.

- Use a patch release for backward-compatible fixes.
- Use a minor release for additive CLI, API, configuration, result-schema, or
  database behavior.
- Release at least one RC before a stable version.
- Stable must reuse the accepted RC commit and exact multi-platform image
  digest. If code changes after an RC, publish the next RC instead.
- Never move or reuse a version tag.

Historical v2.0.0-v2.5.0 GitHub/container releases are preserved but are not
valid v2 Go module releases. Generate new release notes from v1.0.0, not the
historical GitHub “latest” release. The stable v1.1.0 release will restore the
GitHub latest designation to the canonical module line.

## One-time repository settings

Complete these settings before the first RC:

1. Enable GitHub immutable releases for the repository.
2. Create a `release` environment with required maintainer review. Restrict it
   to `main` and do not allow administrators to bypass approval casually.
3. Keep the default `GITHUB_TOKEN` permissions read-only. The release workflow
   grants required write scopes only to the jobs that publish evidence or the
   release.
4. Protect `main` with pull requests, no force pushes or deletion, and all CI,
   CodeQL, and Codacy checks required.
5. Add a tag ruleset for `v1.*` that blocks updates, deletion, and non-fast-
   forward changes with no bypass. Personal repositories cannot select the
   GitHub Actions integration as a ruleset bypass actor, so leave initial tag
   creation enabled for the protected workflow and do not create tags manually.
6. Enable dependency graph, Dependabot, secret scanning, push protection, code
   scanning, and artifact attestations.
7. Make `ghcr.io/brumbelow/layerleak` public after its initial publication.

The workflow uses only `GITHUB_TOKEN` and GitHub's OIDC token. It does not
require a Cosign private key, registry password, PAT, or custom release secret.
The public-repository GitHub code-scanning workflow can run without a
`CODACY_PROJECT_TOKEN`, but the Codacy coverage job requires that repository
secret to upload Go coverage reports. The analysis job also uses it to retrieve
remote Codacy project settings.
`GITHUB_TOKEN` cannot read repository Administration settings, so enabling
immutable releases remains a required setup step. The workflow checks every
existing candidate/release and verifies `isImmutable` plus the GitHub release
attestation immediately after publication.

## What the workflow enforces

The release workflow accepts a version and full source SHA, then:

1. validates canonical v1 semver, module identity, `main` ancestry, existing
   tags, existing candidate/release immutability, increasing stable versions,
   and RC/stable relationships;
2. runs the reusable full gate: format, module integrity, vet, normal/race
   tests, linked-dependency license policy and inventory, PostgreSQL
   integration, migration idempotence, purge confirmation, Compose validation,
   amd64/arm64 container smoke, and `govulncheck`;
3. builds an RC candidate for linux/amd64 and linux/arm64, or resolves the
   previously accepted RC digest for stable;
4. blocks every Critical image vulnerability and every fixable High finding on
   both platforms using a pinned Grype release;
5. validates per-platform SPDX SBOMs and SLSA v1 provenance;
6. creates source-bound GitHub artifact attestations for an RC, carries those
   exact attestations into stable, then keyless-signs and verifies the image
   index and platform manifests with Cosign;
7. pulls the exact registry digest and repeats migration, database, liveness,
   readiness, and restrictive-runtime smoke on both architectures;
8. pauses at the protected `release` environment;
9. creates the source tag, promotes the already tested digest without replacing
   a conflicting version tag, and publishes an immutable GitHub release with
   checksums and evidence;
10. verifies the Go proxy, image tags, release immutability and attestation,
    signature, and source-bound image attestations after publication.

RC publication never changes the GHCR `latest` tag or Go module `@latest`.
Stable publication points `v1.x.y` and `latest` to the accepted RC digest.

## Prepare v1.1.0-rc.1

1. Merge the intended release changes to `main`.
2. Confirm the **CI**, **CodeQL**, **Codacy Security Scan**, and **Pages**
   workflows are green on the exact commit.
3. Review [CHANGELOG.md](./CHANGELOG.md), [README.md](./README.md), the OpenAPI
   document, migration notes, security policy, and third-party notices. Freeze
   the changes under the final `v1.1.0` changelog heading and use `1.1.0` as the
   OpenAPI version before RC. Do not embed an RC number in files that stable
   must reuse unchanged.
4. From a clean checkout, run:

```bash
git diff --check
test -z "$(gofmt -l .)"
go mod verify
go mod tidy -diff
go vet ./...
go test -short ./... -count=1
go test -short -race ./... -count=1
LAYERLEAK_DB_PASSWORD=release-check docker compose --profile tools config --quiet
```

5. Copy the full `main` commit SHA:

```bash
git rev-parse origin/main
```

6. In **Actions → Release → Run workflow**, select `main` and enter:

```text
version: v1.1.0-rc.1
source_sha: <the full main SHA>
candidate_version: <leave empty>
```

7. Review the workflow summary, Grype reports, image/platform digests,
   attestations, SBOMs, and registry smoke before approving the `release`
   environment.

## RC acceptance

After publication, independently check:

```bash
clean_root="$(mktemp -d)"
GOBIN="${clean_root}/bin" \
GOCACHE="${clean_root}/cache" \
GOMODCACHE="${clean_root}/mod" \
go install github.com/brumbelow/layerleak@v1.1.0-rc.1
"${clean_root}/bin/layerleak" --version
"${clean_root}/bin/layerleak" scan --help

go list -m github.com/brumbelow/layerleak@latest
docker buildx imagetools inspect ghcr.io/brumbelow/layerleak:v1.1.0-rc.1
```

Confirm:

- exact RC installation succeeds while `@latest` remains the previous stable;
- GHCR contains linux/amd64 and linux/arm64 application manifests plus expected
  attestation manifests;
- `latest` did not move;
- migration succeeds twice against a fresh PostgreSQL 16.13 database;
- `/health` and `/livez` stay live, `/readyz` is unavailable before migration,
  and `/readyz` becomes healthy after schema 0004 is installed;
- signatures and GitHub attestations verify against the exact digest and
  `container-release.yml@refs/heads/main` identity and the RC source SHA;
- attached SBOM/provenance/checksum files match `release-manifest.json`.

Soak an RC for at least 72 hours. The stable workflow enforces this interval
from the immutable candidate release's publication timestamp. Treat a
correctness regression, security regression, migration problem, data-loss risk,
false clean scan, signature or attestation failure, or unsupported-platform
failure as release-blocking. Any code or image change requires
`v1.1.0-rc.2`; do not repair or move RC.1.

## Promote v1.1.0

Once an RC is accepted, run the same workflow from `main` with the RC's exact
source SHA:

```text
version: v1.1.0
source_sha: <accepted RC source SHA>
candidate_version: v1.1.0-rc.1
```

The workflow verifies the RC release and asset attestations, publication age,
release manifest, source-bound image attestations, and registry digest; reruns
all source checks and vulnerability scans; and promotes without rebuilding.
Review and approve the protected environment only after confirming the version,
commit, candidate, and digest in the workflow summary.

After stable publication, verify:

- `go install github.com/brumbelow/layerleak@v1.1.0` succeeds;
- `go install github.com/brumbelow/layerleak@latest` installs v1.1.0;
- GHCR `v1.1.0` and `latest` resolve to the accepted RC digest;
- RC tags remain unchanged;
- GitHub marks v1.1.0 as latest and the release is immutable;
- both platforms pass migration/API smoke;
- Pages serves the matching docs and OpenAPI file.

Monitor Actions, code scanning, dependency alerts, package metadata, and issue
reports for at least 24 hours after stable publication.

## Release assets and verification

Every release attaches:

- `release-manifest.json` with version, source SHA, workflow run, index digest,
  and both platform manifest digests;
- per-platform SPDX JSON SBOMs;
- per-platform SLSA v1 provenance;
- image index metadata;
- Critical and fixable-High Grype reports for both platforms;
- the linked Go dependency license inventory;
- GitHub attestation bundles;
- `SHA256SUMS`.

Verify a release digest:

```bash
image=ghcr.io/brumbelow/layerleak
version=v1.1.0
digest='sha256:<digest-from-release-manifest>'
source_sha='<source-sha-from-release-manifest>'

cosign verify \
  --certificate-identity 'https://github.com/Brumbelow/layerleak/.github/workflows/container-release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${image}@${digest}"

gh attestation verify "oci://${image}@${digest}" \
  --repo Brumbelow/layerleak \
  --bundle-from-oci \
  --signer-workflow Brumbelow/layerleak/.github/workflows/container-release.yml \
  --source-ref refs/heads/main \
  --source-digest "${source_sha}" \
  --deny-self-hosted-runners

gh release verify "${version}" --repo Brumbelow/layerleak
sha256sum --check SHA256SUMS
```

## Failure and recovery

- Before the protected publish job, only a run-scoped candidate tag exists. No
  Go version, release version image tag, or GitHub release is public.
- If publication fails after the source tag is created but before the GitHub
  release exists, rerun the failed workflow run from the Actions UI with the
  same inputs. This keeps the execution commit equal to the RC source SHA while
  the release workflow definition still comes from protected `main`.
  Validation permits an existing tag only when it points to that exact commit.
  A version image already promoted by the failed attempt is reused only after
  its workflow identity and source-bound attestation match the requested
  commit. Its digest is recorded and rechecked; the version tag is never
  overwritten.
- Once a complete GitHub release exists, immutable release settings prevent
  repair in place. A post-release-verification retry may revalidate the same
  version and digest; any artifact change requires a new RC or patch version.
- Never delete or move a version tag to hide a failed release. Go proxies and
  downstream caches may retain it indefinitely.
- Run-scoped `candidate-*` image tags may be cleaned up later according to a
  documented package-retention policy, but digest-referenced release evidence
  and all version tags must remain.

Vulnerability exceptions are not encoded in the release workflow. If an
unfixed High finding must be accepted, record the CVE, package, reachability,
rationale, owner, and expiry in a reviewed VEX/exception change before release.
Critical findings are never excepted.
