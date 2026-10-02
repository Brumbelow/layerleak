# Working on layerleak

Guidance for contributors and for AI coding agents. Read README.md and
SECURITY.md first; CONTRIBUTING.md holds the complete rules.

- Run `make verify` before pushing. It mirrors CI: formatting, module
  integrity, vet, golangci-lint, short and race tests, govulncheck, the
  documentation validators, release-script tests and compose validation.
  `make db-test` runs the PostgreSQL integration suite when
  `LAYERLEAK_TEST_DATABASE_URL` points at a disposable database.
- Treat registry responses, redirects, compressed streams, tar metadata and
  API bodies as hostile input. Bound every read before allocating or
  decompressing. Never weaken a limit or the private-network egress policy
  without an explicit security review.
- Never log, print, test-fixture or persist real secrets. Findings are
  redacted by default, and the API and scan history stay redacted even when
  raw persistence is enabled.
- Preserve the public contracts: CLI flags and exit codes, `/api/v1` paths
  and error codes, result and record schema versions, and shipped migration
  checksums. A contract change needs a CHANGELOG entry and the matching
  README, OpenAPI and web documentation edits in the same change.
- Keep output deterministic and tests hermetic: in-memory OCI documents,
  httptest registries and `t.TempDir()`, never live registries.
- Release tags are prepared offline and published only by the protected
  workflow; see RELEASING.md. Do not push tags by hand.
