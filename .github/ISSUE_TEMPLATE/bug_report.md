---
name: Bug report
about: Report reproducible incorrect or unexpected behavior
title: "bug: "
labels: bug
assignees: ""
---

<!--
Do not post live secrets, private registry URLs, credentials, or unredacted
findings. Security issues belong in a private report under the Security tab or
at admin@brumbelow.org.
-->

## Version and environment

- Layerleak version (`layerleak --version`):
- Install method (Go, source, or container digest):
- OS and architecture:
- PostgreSQL version and schema version, if applicable:

## Command or request

Provide the smallest redacted command or HTTP request that reproduces the
problem. Use a public fixture image or synthetic digest when possible.

```text

```

## Expected behavior



## Actual behavior

Include the exit code, top-level result `status`, coverage summary, and API
`X-Request-ID` when available. Redact all secret material.



## Reproduction

1.
2.
3.

## Additional context

Relevant platform, media type, limit overrides, migration path, logs, or a
minimal synthetic fixture. Confirm whether `--allow-partial`, `--all-tags`,
private-host allowlists, or raw-secret persistence were enabled.
