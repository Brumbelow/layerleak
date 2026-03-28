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
go build -o layerleak ./cmd/layerleak
```

Run the test suite:

```bash
go test ./...
```

Run the scanner against a single tag:

```bash
go run ./cmd/layerleak scan redis:latest
```

The legacy entrypoint `go run ./cmd/layerleak ...` is also supported for backward compatibility.

Run the scanner against an entire public repository:

```bash
go run ./cmd/layerleak scan mongo
```

Use an explicit tag or digest when you want to limit scope.

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
- tests when command behavior, result shape, or detector logic changes
