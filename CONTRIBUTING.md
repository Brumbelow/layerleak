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
- Remove any [AGENTS.md](./AGENTS.md) before committing, if you are working through an agent or automation flow.
- Ensure you tag any AI assisted commit or PR as such

## Local Setup

Build the CLI:

```bash
go build -o scanner ./cmd/scanner
```

Run the test suite:

```bash
go test ./...
```

Run the scanner against a single tag:

```bash
go run ./cmd/scanner scan redis:latest
```

Run the scanner against an entire public repository:

```bash
go run ./cmd/scanner scan mongo
```

Use an explicit tag or digest when you want to limit scope.

## Contribution Rules

- Keep changes small and focused.
- Preserve provenance for findings and scan results.
- Prefer immutable digests internally over mutable tags.
- Do not add private registry support, secret verification, or unrelated platform features unless explicitly requested.
- Do not rewrite unrelated files while implementing a focused change.

## Secret-Safe Development

- Never log raw secrets.
- Never commit real secrets to fixtures, tests, screenshots, or documentation.
- Use synthetic tokens, keys, and credentials in tests.
- Treat image metadata, tar entries, file paths, and blobs as hostile input.
- Preserve redaction behavior for CLI output unless a change explicitly targets persisted raw findings.

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

## Pull Requests

A good pull request should:

- explain the problem being solved
- describe the behavior change
- note any security or false-positive tradeoffs
- include test coverage for the change
- mention any follow-up work that remains out of scope
