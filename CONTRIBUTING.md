# Contributing to layerleak

## Purpose

This project is a Docker Hub / OCI image secret scanner.

Contributions should keep the scanner:

- correct
- secret-safe
- layer-aware
- predictable to test and operate

## Before You Start

- Use Go 1.24 or newer.
- Read [README.md](./README.md).
- Ensure you tag any AI assisted commit or PR as such. AI assisted commits not tagged will be rejected.

## Local Setup

Build the CLI:

```bash
go build -o layerleak .
```

Run the test suite:

```bash
go test ./...
```

Run the scanner against a single tag:

```bash
go run . scan redis:latest
```

The explicit scanner entrypoint `go run ./cmd/scanner ...` remains available for development, but the module root is the canonical user-facing CLI entrypoint.

Run the scanner against an entire public repository:

```bash
go run . scan mongo
```

Use an explicit tag or digest when you want to limit scope.

## Versioning And Install Path

- The canonical user install path is `go install github.com/brumbelow/layerleak@latest`.
- The module root must remain the installable CLI entrypoint.
- For the current module path `github.com/brumbelow/layerleak`, publish only `v1.x.y` release tags.
- Do not publish new `v2+` tags from the root module unless the module path first changes to `github.com/brumbelow/layerleak/vN`.
- Before cutting a release tag, verify both `go test ./...` and `GOBIN=/tmp/layerleak-bin go install .` succeed.

## Contribution Rules

- Keep changes small and focused.
- Preserve provenance for findings and scan results.
- Prefer immutable digests internally over mutable tags.
- Do not add private registry support, secret verification, or unrelated platform features unless explicitly requested.
- Do not rewrite unrelated files while implementing a focused change.

## Testing Expectations

Add or update tests for non-trivial changes.

Prioritize tests for:

- tag and digest resolution
- manifest parsing
- multi-arch selection
- whiteout handling
- deleted-layer recovery
- detector accuracy
- false-positive regressions
- finding normalization and redaction
- saved result behavior

Prefer deterministic unit tests with mocked registry responses over live network tests.

## Code Style

- Run `gofmt` on changed Go files.
- Keep package boundaries clear.
- Prefer explicit errors and narrow interfaces.
- Use table-driven tests where they improve clarity.
- Keep logging structured and free of sensitive values.

## Documentation

Update docs when behavior changes:

- `README.md` for user-facing behavior
- `CONTRIBUTING.md` for contributor workflow
- `RELEASING.md` for release/install procedure
- tests when command behavior, result shape, or detector logic changes
