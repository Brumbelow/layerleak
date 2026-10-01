# layerleak

[![CI](https://github.com/brumbelow/layerleak/actions/workflows/test.yml/badge.svg)](https://github.com/brumbelow/layerleak/actions/workflows/test.yml)
[![CodeQL](https://github.com/brumbelow/layerleak/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/brumbelow/layerleak/actions/workflows/codeql-analysis.yml)
[![Go](https://img.shields.io/badge/Go-1.27.1%2B-00ADD8?logo=go)](https://go.dev/)

Layerleak is a read-only OCI image secret scanner. It resolves public image
references without a Docker daemon, verifies downloaded content against OCI
digests, reconstructs layer state, inspects deleted artifacts and image
metadata, and returns redacted, provenance-rich findings.

It supports Docker Hub, GHCR, Quay, GCR, MCR, Amazon ECR Public, and other
OCI-compatible registries. Results can be saved as JSON and persisted in
PostgreSQL for the bundled API.

- [Documentation](https://brumbelow.github.io/layerleak/docs/)
- [OpenAPI specification](https://brumbelow.github.io/layerleak/docs/openapi.yaml)
- [Changelog](./CHANGELOG.md)
- [Security policy](./SECURITY.md)
- [Contributing](./CONTRIBUTING.md)

This development tree documents the 3.0.0 line on the
`github.com/brumbelow/layerleak/v3` module path. The release-candidate command
shown below becomes installable only after that exact tag is published. The
3.0.0 labels in the changelog and OpenAPI document are intentionally frozen so
an accepted release candidate can be promoted from the same source commit.

## Security model

Layerleak scans untrusted image content, so its defaults are intentionally
bounded and fail closed:

- image, manifest, config, tag response, file, layer, retained-state, and
  finding limits prevent unbounded work;
- manifest, config, and layer bodies are checked against their advertised OCI
  digests before use;
- redirects are capped and revalidated;
- private, loopback, link-local, and otherwise non-public registry and auth
  destinations are blocked unless their exact host is explicitly allowed;
- findings, API responses, scan history, and logs are redacted by default;
- incomplete coverage is reported as `partial` or `failed`, never as a clean
  scan.

Layerleak does not verify whether a detected credential is live. The API has no
authorization model: it is open by default, and the opt-in
`LAYERLEAK_API_BEARER_TOKENS` shared-token check is defence in depth for the
`/api/` paths, not access control. Expose it only on a trusted network or
behind an authenticated gateway either way.

## Install the CLI

Layerleak requires Go 1.27.1 or newer.

```bash
go install github.com/brumbelow/layerleak/v3@latest
layerleak --version
layerleak --help
```

The `/v3` module path is the canonical install target; the installed binary is
still named `layerleak`. Pin a stable or release candidate explicitly when
reproducibility matters:

```bash
go install github.com/brumbelow/layerleak/v3@v3.0.0
go install github.com/brumbelow/layerleak/v3@v3.0.0-rc.1
```

`@latest` on the `/v3` path selects the highest published v3 release. Go
excludes prereleases from `@latest` once a stable version exists, so while only
release candidates are published `@latest` resolves to the newest candidate.
The root path `github.com/brumbelow/layerleak` without `/v3` stays at v1.0.0
forever; always include `/v3`. Checkout builds report a VCS-derived development
version, including a dirty-worktree marker, or `dev` without VCS information.
Release-installed binaries report the resolved module version through
`layerleak --version`.

Build from source:

```bash
git clone https://github.com/brumbelow/layerleak.git
cd layerleak
go build -o layerleak .
./layerleak --help
```

The supported distribution paths are the `/v3` module path above for the CLI and
`ghcr.io/brumbelow/layerleak:<published-version>` for the API plus its bundled
migration, purge, and healthcheck commands. The `cmd/*` packages are source
build targets for development, not separately versioned install paths. Before
starting a PostgreSQL-backed API version, run its matching
`layerleak-migrate-up` binary or container entrypoint and wait for migration
success: the API refuses to start unless the installed schema is exactly the
version it expects, and after startup `/readyz` re-checks the database and
schema on every probe so later degradation is reported.

## Platform support

| Component | Platforms | How it is verified |
| --- | --- | --- |
| `layerleak` CLI | Linux, macOS, and Windows on amd64 and arm64 via `go install` | Tests run on linux/amd64 in CI; darwin/arm64, darwin/amd64, windows/amd64, and linux/arm64 are compiled and vetted on every change. |
| API image | `linux/amd64`, `linux/arm64` | Built, smoke-tested, scanned, and signed for both platforms by the release workflow. |

On Windows the dynamic progress display switches the console into
virtual-terminal mode; a console that refuses (older than Windows 10 1511)
falls back to plain progress lines, as does `--progress plain`. Shell
completion for bash, zsh, fish, and PowerShell comes from
`layerleak completion <shell>`.

The CLI reaches registries directly over HTTPS or through `HTTPS_PROXY` (see
[Configuration](#configuration)). The API listens on plain HTTP and expects the
deployment to terminate TLS, authenticate clients, and rate-limit; see
[SECURITY.md](./SECURITY.md#security-boundaries).

## Scan images

A bare repository scans its `latest` tag. Use an explicit tag or digest for an
immutable target:

```bash
layerleak scan ubuntu
layerleak scan library/nginx:1.29 --format json
layerleak scan alpine@sha256:<digest>
layerleak scan ghcr.io/homebrew/core/hello:latest
layerleak scan quay.io/prometheus/busybox:latest
layerleak scan gcr.io/distroless/static:nonroot
layerleak scan public.ecr.aws/docker/library/alpine:3.20
layerleak scan mcr.microsoft.com/hello-world:latest
```

Choose platforms from a multi-platform index. Without `--platform` every
`linux` manifest is scanned and entries for other operating systems are
reported as `platform_skipped` diagnostics instead of being downloaded:

```bash
layerleak scan alpine:latest --platform linux/arm64
layerleak scan golang:latest --platform linux
```

Scanning every public tag is explicit because it can perform substantial work:

```bash
layerleak scan mongo --all-tags
layerleak scan mongo --all-tags \
  --tag-page-size 100 \
  --max-repository-tags 500 \
  --max-repository-targets 200
```

Useful scan flags:

| Flag | Meaning |
| --- | --- |
| `--format summary|json|sarif` | Human summary (counts, per-target table and the first 50 findings), the stable JSON result (`result_schema_version` 2, schema at `web/docs/schemas/result-v2.schema.json`), or a SARIF 2.1.0 log. |
| `--output <file>` | Write the formatted output to a file instead of stdout; `-` is stdout. Created with mode `0600`. |
| `--output-dir <dir>` | Directory for the scan record. Overrides `LAYERLEAK_FINDINGS_DIR`; the default is `./findings` under the working directory. |
| `--no-artifacts` | Do not write a scan record. |
| `--no-db` | Ignore `LAYERLEAK_DATABASE_URL` and run a purely local scan. |
| `--fail-on low|medium|high|none` | Lowest confidence of an actionable finding that produces exit code `2`. `low` (default) is every actionable finding; `none` reports without failing. |
| `--allow-partial` | Accept usable incomplete coverage (exit `0` or `2` instead of `3`) while preserving `status`, coverage, and diagnostics. |
| `--platform os[/arch[/variant]]` | Select platforms from a multi-platform image; omitted parts match anything, so `--platform linux` selects every Linux manifest and `linux/arm64/v8` is equivalent to `linux/arm64`. Defaults to every `linux` manifest. A single-manifest image that does not match fails with `platform_not_found`. |
| `--username <name>` / `--password-stdin` | Authenticate to a private registry for this scan; see "Private registries" below. |
| `--all-tags` | Enumerate every public tag for a bare repository. |
| `--progress auto|tty|plain|off` | Select interactive, log-safe, or disabled progress output. `auto` uses plain lines when `LAYERLEAK_LOG_LEVEL=debug`, `TERM=dumb` or `CI=true`. |
| `--tag-page-size` | Override the tag-list page size for `--all-tags`. |
| `--max-repository-tags` | Override the tag enumeration bound for `--all-tags`; `0` disables it. |
| `--max-repository-targets` | Override the distinct target bound for `--all-tags`; `0` disables it. |

Exit codes are stable for automation:

| Code | Meaning |
| --- | --- |
| `0` | Complete scan with no blocking findings, or an accepted (`--allow-partial`) usable partial scan with none. |
| `1` | Invalid input, operational failure (registry, network, authentication), persistence failure, or cancellation (`LAYERLEAK_SCAN_TIMEOUT`, SIGINT, SIGTERM). |
| `2` | One or more actionable findings at or above `--fail-on`. Findings take precedence over incomplete coverage. |
| `3` | The scan finished with usable but incomplete coverage and `--allow-partial` was not given. |

Scripts that treat any non-zero status as failure keep working; scripts that
retry on `1` should treat `3` as "investigate coverage" rather than retry.
A second SIGINT or SIGTERM after the first terminates the process immediately.

Every result has a top-level `status` (`completed`, `partial`, or `failed`), a
coverage object, per-target, per-platform and per-tag status, and
diagnostics. `--format json` prints the result for failed scans too (exit code
`1`), so automation can read the diagnostics; cancellation is the only silent
path. Likely test, fixture, example, and demo placeholders are retained
separately as suppressed findings and do not drive exit code `2`.

### SARIF

`--format sarif` writes one SARIF 2.1.0 run per scan: every detector in the
default catalog appears under `tool.driver.rules`, each finding is a result
with `level` derived from its confidence, a `partialFingerprints` entry
(`layerleak/fingerprint/v1`, the stable sha256 of the raw value), the image
reference as the `IMAGE` URI base, and suppressed findings carry a
`suppressions` entry. Only redacted values are written. Upload it to GitHub
code scanning from a workflow:

```yaml
- run: layerleak scan ghcr.io/${{ github.repository }}:${{ github.sha }} --format sarif --output layerleak.sarif --fail-on none --no-artifacts
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: layerleak.sarif
```

### Private registries

Pass a per-scan credential with `--username <name> --password-stdin`; the
password or token is read from standard input to EOF and exactly one trailing
newline is removed. Both flags are required together and there is no
`--password` flag (it would land in process listings and shell history):

```bash
printf '%s' "$REGISTRY_TOKEN" | layerleak scan ghcr.io/org/private-app:1.2 --username robot --password-stdin
```

Without the flags, the `LAYERLEAK_REGISTRY_USERNAME`/`LAYERLEAK_REGISTRY_PASSWORD`
pair applies to the registry of the reference on the command line, and a
Docker `config.json` named by `LAYERLEAK_DOCKER_CONFIG` supplies credentials by
registry host (`auths` entries only; credential helpers are not invoked). A
credential is bound to the one registry host it was given for, is only ever
sent over `https` (a plain-`http` private registry is refused), and never
appears in logs, output, scan records or the database. A `401` or `403` from
the registry exits `1` with `authentication to <registry host> failed`.

### Local inputs

Images that have not been pushed yet, or that live on an air-gapped host, are
scanned from the filesystem with a scheme-prefixed reference instead of a
registry name:

| Reference | Source |
| --- | --- |
| `oci:<dir>[:<tag>][@<digest>]` | An OCI image layout directory (`oci-layout`, `index.json`, `blobs/`), as written by `buildx --output type=oci`, `skopeo copy ... oci:`, or `crane pull --format oci`. |
| `oci-archive:<file.tar>[:<tag>][@<digest>]` | The same layout inside a tar archive (`buildx --output type=oci,dest=...`, `skopeo copy ... oci-archive:`). |
| `docker-archive:<file.tar>[:<repo>[:<tag>]][@<digest>]` | A `docker save` archive (`manifest.json`, config and layer tars, optional `repositories`). |

```bash
docker buildx build -o type=oci,dest=app.tar -t app:1.2 .
layerleak scan oci-archive:app.tar:app:1.2
docker save ghcr.io/org/app:1.2 > app-save.tar
layerleak scan docker-archive:app-save.tar:ghcr.io/org/app:1.2 --format sarif
layerleak scan oci:./build/image --all-tags
```

The path is absolute or relative to the working directory. For `oci:` and
`oci-archive:` the tag is the `org.opencontainers.image.ref.name` annotation
of the `index.json` entry and is the text after the last colon (a colon inside
a path component such as `oci:/srv/a:b/c` is part of the path). For
`docker-archive:` the path ends at the first colon and the rest is the image
name `docker save` recorded in `RepoTags`, in any spelling that normalises to
it (`app:1.2`, `library/app:1.2`, `docker.io/library/app:1.2`). A source that
holds one image needs no tag; one that holds several needs a tag or
`@<digest>`, and a missing or ambiguous tag is an exit-`1` error that lists the
available tags. `--all-tags` enumerates the tags the source holds.

Results, scan records and the database treat the local source as the
repository: `repository` is `oci:/srv/images/app`, `requested_reference` is
the reference as given, `resolved_reference` is `oci:/srv/images/app@sha256:…`
and the stored registry is `local`. Platform selection, limits, coverage,
diagnostics and exit codes are identical to registry scans. Every blob is
verified against its descriptor digest and size, archives are indexed once in
memory (never extracted) with bounded entry counts and name lengths, entry
names with `..` or absolute paths make an archive unusable, symbolic and hard
links inside an archive are never followed, and a layout directory is opened so
that no symlink can lead outside it. `--username`/`--password-stdin` and
`LAYERLEAK_REGISTRY_USERNAME`/`LAYERLEAK_REGISTRY_PASSWORD` are refused for a
local source (exit `1`). The HTTP API does not accept local sources: a local
scheme in `POST /api/v1/scans` is `400 invalid_request`.

## Results and secret handling

Every scan that produced a result (completed, partial, or failed) writes
exactly one scan record,
`<dir>/<utc-timestamp>-<reference-token>-<random>.json`, unless
`--no-artifacts` is given. `<dir>` is `--output-dir`, otherwise
`LAYERLEAK_FINDINGS_DIR` (a relative value resolves against the working
directory), otherwise `./findings` under the working directory. The CLI no
longer looks for a surrounding `go.mod`.

The record (`record_schema_version` 2, schema at
`web/docs/schemas/scan-record-v2.schema.json`) contains:

- `result`: the same redacted result as `--format json`, with real,
  control-character-sanitised error and diagnostic messages;
- `findings`: every finding (actionable first, then suppressed) with detector,
  confidence, disposition and suppression reason, redacted value and redacted
  context, manifest, platform, file, layer, line and `source_location`
  provenance, and whether the occurrence survives in the final filesystem;
- `persistence`: `disabled`, `saved` (with `scan_run_id`), or `failed` with the
  neutral `storage_unavailable` code;
- `created_at`.

Directory and file handling is deliberately conservative. A missing directory
is created with mode `0700`; an existing directory is never `chmod`-ed and a
symbolic link in its place is refused, so pointing the CLI at a shared
directory cannot change that directory's permissions. The CLI warns once when
an existing directory is readable by other users. Records are written `0600`,
published without ever overwriting an existing file (falling back from a hard
link to an exclusive create on filesystems without hard links), and the full
path is printed quoted on stderr (`Scan record: "..."`). If the record cannot
be written the scan still prints its result and exits `1`.

Raw secret values and raw context snippets are never written locally: the
record, `--format json` and `--format sarif` are always redacted, and the
local redaction shape reveals at most the first three characters of a value
followed by a fixed-length mask. Raw persistence exists only in PostgreSQL
with `LAYERLEAK_PERSIST_RAW_SECRETS=1`, which increases breach impact and
should normally remain disabled. API responses and the `scan_runs` snapshot
remain redacted even when raw storage is enabled. Turning the setting back off
prevents new raw writes but does not erase historical raw material; use the
confirmation-gated purge command below for that explicit operation.

A database-save failure returns exit code `1`, records the neutral
`storage_unavailable` persistence outcome in the scan record, and still prints
the result. No scan ID is recorded unless persistence succeeded. `--no-db`
skips PostgreSQL entirely for one run.

## Configuration

The process reads environment variables; it does not load `.env` itself. Copy
the complete, versioned example when running from a checkout, then export its
values before starting Layerleak:

```bash
cp .env.example .env
set -a
. ./.env
set +a
```

Durations use Go syntax such as `30s`, `10m`, or `1h`. Resource bounds fail
the scan instead of silently truncating it. Rows marked **must be positive**
reject `0`; every other `MAX_*` bound accepts `0` to disable it. Boolean
variables accept `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off`.

### Core and registry

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAYERLEAK_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` (case-insensitive); any other spelling is rejected. |
| `LAYERLEAK_FINDINGS_DIR` | `./findings` | CLI only. Directory for scan records (one JSON file per scan); relative values resolve against the working directory. `--output-dir` overrides it, `--no-artifacts` skips it. |
| `LAYERLEAK_PERSIST_RAW_SECRETS` | `0` | Boolean. Unsafe opt-in for raw values and snippets. |
| `LAYERLEAK_HTTP_TIMEOUT` | `30s` | Per-attempt deadline for manifest, config, tag, and auth requests and for the response headers of blob requests; also bounds dial and TLS handshake. |
| `LAYERLEAK_BLOB_TIMEOUT` | `10m` | Layer blob transfer deadline. |
| `LAYERLEAK_SCAN_TIMEOUT` | `30m` | End-to-end CLI scan deadline. |
| `LAYERLEAK_REGISTRY_REQUEST_ATTEMPTS` | `2` | Attempts including the first request; retries back off exponentially (jittered, at most 5s) or honour `Retry-After` (at most 30s); must be positive. |
| `LAYERLEAK_REGISTRY_MAX_REDIRECTS` | `3` | Redirect cap; each destination is revalidated; must be positive. |
| `LAYERLEAK_MAX_AUTH_RESPONSE_BYTES` | `1048576` | Maximum registry token response size; must be positive. |
| `LAYERLEAK_ALLOWED_PRIVATE_REGISTRY_HOSTS` | empty | Comma-separated exact private registry `host[:port]` allowlist. |
| `LAYERLEAK_ALLOWED_PRIVATE_AUTH_HOSTS` | empty | Comma-separated exact private auth `host[:port]` allowlist. |
| `LAYERLEAK_REGISTRY_BASE_URL` | empty | Registry endpoint override for a pull-through mirror or alternate registry; validated at startup. Use `HTTPS_PROXY` for forward proxies. |
| `LAYERLEAK_REGISTRY_AUTH_URL` | empty | Token endpoint override matching the registry override; validated at startup. |
| `LAYERLEAK_REGISTRY_USERNAME` | empty | Username for the registry pinned by `LAYERLEAK_REGISTRY_BASE_URL`; requires `LAYERLEAK_REGISTRY_PASSWORD`. Sent only to that host, over https. Without the endpoint pin the pair is not applied: the API never sends it to a registry a caller names, and CLI scans use the per-scan credential flags. |
| `LAYERLEAK_REGISTRY_PASSWORD` | empty | Password or access token paired with `LAYERLEAK_REGISTRY_USERNAME`; never logged, persisted, or sent to any other host. |
| `LAYERLEAK_DOCKER_CONFIG` | empty | Path to a Docker `config.json` whose `auths` entries supply credentials by registry host (`auth` or `username`/`password` fields; Docker Hub aliases resolve). Credential helpers are not invoked. Must be a regular file; blank skips Docker configuration. |

Private destination allowlists are an explicit trust decision. Entries accept
an exact DNS hostname or IPv4 address, optionally with a port, or bracketed
IPv6 with a port. Schemes, paths, credentials, wildcards, malformed hostnames,
invalid ports, and unbracketed IPv6 are rejected. Matching is literal on
`host[:port]`: an entry without a port matches only URLs without an explicit
port, so `localhost` does not cover `localhost:5000` and `registry.internal:443`
does not cover `https://registry.internal/`; list the exact `host:port` the
scanner connects to. Allowlisting a host is also what permits plain `http://`
to it (for example `LAYERLEAK_REGISTRY_BASE_URL=http://registry.internal:5000`
together with `LAYERLEAK_ALLOWED_PRIVATE_REGISTRY_HOSTS=registry.internal:5000`);
every other destination requires TLS 1.2+ with a verifiable certificate. Allow
only infrastructure you control.

Layerleak honours `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY`. When a proxy is
selected for a request, the registry hostname is sent as the `CONNECT` target
and local DNS resolution and IP pinning are skipped, because the proxy is the
egress control; the https-only rule and the private-host allowlists still
apply. Hosts matched by `NO_PROXY` are connected directly with address pinning.

### Resource bounds

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAYERLEAK_MAX_FILE_BYTES` | `1048576` | Maximum decompressed bytes buffered for one file; must be positive. Larger files are not scanned: they are reported with a `files_skipped_oversize` diagnostic and coverage becomes partial. |
| `LAYERLEAK_MAX_LAYER_BYTES` | `536870912` | Maximum decompressed stream bytes for one layer. |
| `LAYERLEAK_MAX_LAYER_ENTRIES` | `50000` | Maximum tar entries for one layer. |
| `LAYERLEAK_MAX_IMAGE_LAYERS` | `512` | Maximum layers selected for one image. |
| `LAYERLEAK_MAX_IMAGE_MANIFESTS` | `64` | Maximum platform manifests selected from one image index. |
| `LAYERLEAK_MAX_IMAGE_LAYER_BYTES` | `4294967296` | Aggregate advertised compressed and expanded layer bytes. |
| `LAYERLEAK_MAX_IMAGE_ARTIFACTS` | `250000` | Aggregate tar entry count across all selected layers, including directories, links, whiteouts, and device nodes. |
| `LAYERLEAK_MAX_RETAINED_BYTES` | `1073741824` | Bytes retained while reconstructing final state. |
| `LAYERLEAK_MAX_MANIFEST_BYTES` | `8388608` | Maximum manifest response size. |
| `LAYERLEAK_MAX_CONFIG_BYTES` | `8388608` | Maximum image config response size. |
| `LAYERLEAK_MAX_TAG_RESPONSE_BYTES` | `8388608` | Maximum tag-list response page size. |
| `LAYERLEAK_MAX_FINDINGS_PER_SCAN` | `10000` | Maximum findings retained for one scan. |
| `LAYERLEAK_MAX_RAW_FINDING_BYTES` | `67108864` | Maximum raw value and context bytes retained when raw-secret persistence is enabled. Once reached, detection continues with raw retention disabled, coverage stays complete, and a `raw_retention_truncated` diagnostic reports how many findings were recorded without raw values. |
| `LAYERLEAK_TAG_PAGE_SIZE` | `100` | Registry tag-list page size; must be positive. |
| `LAYERLEAK_MAX_REPOSITORY_TAGS` | `1000` | Maximum tags enumerated by `--all-tags`. |
| `LAYERLEAK_MAX_REPOSITORY_TARGETS` | `250` | Maximum distinct targets scanned by `--all-tags`. |

### API and PostgreSQL

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAYERLEAK_API_ADDR` | `127.0.0.1:8080` | API listen address as `host:port` (the host may be empty, a hostname, or an IP); validated at startup; image default is `0.0.0.0:8080`. |
| `LAYERLEAK_API_MAX_REQUEST_BYTES` | `16384` | Maximum JSON request body; must be positive. |
| `LAYERLEAK_API_SCAN_TIMEOUT` | `30m` | Deadline for an API scan. |
| `LAYERLEAK_API_MAX_CONCURRENT_SCANS` | `1` | In-process scan concurrency; must be positive. |
| `LAYERLEAK_API_READ_HEADER_TIMEOUT` | `5s` | HTTP header deadline. |
| `LAYERLEAK_API_READ_TIMEOUT` | `15s` | HTTP request read deadline. |
| `LAYERLEAK_API_RESPONSE_WRITE_TIMEOUT` | `30s` | Non-scan response write deadline. |
| `LAYERLEAK_API_IDLE_TIMEOUT` | `60s` | Keep-alive idle timeout. |
| `LAYERLEAK_API_SHUTDOWN_TIMEOUT` | `30s` | How long shutdown waits for in-flight handlers after the drain window; must be positive. |
| `LAYERLEAK_API_PRESTOP_DELAY` | `0s` | Drain window after `SIGTERM`/`SIGINT`: `/readyz` answers 503 `not_ready` and new scans are refused with 503 `server_shutting_down` while in-flight requests keep running; when it elapses, in-flight scans are cancelled with 503 `server_shutting_down`. May be `0s`. Keep `LAYERLEAK_API_STOP_GRACE_PERIOD` above this plus `LAYERLEAK_API_SHUTDOWN_TIMEOUT`. |
| `LAYERLEAK_API_READINESS_TIMEOUT` | `2s` | Database readiness query deadline. |
| `LAYERLEAK_API_READINESS_CACHE_TTL` | `5s` | How long a `/readyz` result (success or failure) is reused before the ping and schema-contract validation run again; concurrent probes share one check. `0s` validates on every probe. |
| `LAYERLEAK_API_BEARER_TOKENS` | empty | Opt-in authentication: comma-separated bearer tokens, each at least 32 printable ASCII characters. When set, every `/api/` request needs `Authorization: Bearer <token>` (401 `unauthorized` otherwise); `/health`, `/livez` and `/readyz` stay open. Tokens are kept only as SHA-256 digests and compared in constant time. Mutually exclusive with `LAYERLEAK_API_BEARER_TOKENS_FILE`. |
| `LAYERLEAK_API_BEARER_TOKENS_FILE` | empty | Path of a file with one bearer token per line (blank lines ignored, at most 64 KiB), read once at startup; the same rules as `LAYERLEAK_API_BEARER_TOKENS` apply. Use it to mount tokens as a secret instead of an environment variable. |
| `LAYERLEAK_API_METRICS_ADDR` | empty | Optional `host:port` for a second listener that serves Prometheus text-format metrics at `GET /metrics` (request counts and durations by route pattern, scan outcomes and error codes, in-flight scans, process start time). Empty disables it; it must differ from `LAYERLEAK_API_ADDR`, because metrics are never served on the API port. Bind it to a private interface: the endpoint is unauthenticated. |
| `LAYERLEAK_DATABASE_URL` | empty | PostgreSQL connection URL. The password may be left out of the URL and supplied through `PGPASSWORD` or `PGPASSFILE`; the driver fills any field the URL omits from the standard `PG*` variables. |
| `LAYERLEAK_DATABASE_MAX_OPEN_CONNS` | `10` | Open connection cap; must be positive. |
| `LAYERLEAK_DATABASE_MAX_IDLE_CONNS` | `5` | Idle connection cap. |
| `LAYERLEAK_DATABASE_CONN_MAX_LIFETIME` | `30m` | Connection lifetime. |
| `LAYERLEAK_DATABASE_CONN_MAX_IDLE_TIME` | `5m` | Idle connection lifetime. |
| `LAYERLEAK_DATABASE_QUERY_TIMEOUT` | `10s` | Read and readiness query deadline. |
| `LAYERLEAK_DATABASE_WRITE_TIMEOUT` | `2m` | Transactional persistence deadline. |

### Compose-only variables

`docker-compose.yml` reads these from `.env`; the Layerleak binaries never see
them directly.

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAYERLEAK_IMAGE` | `ghcr.io/brumbelow/layerleak:latest` | Image used by the `api`, `migrate`, and `purge-raw-secrets` services. |
| `LAYERLEAK_API_HOST` | `127.0.0.1` | Host interface the API port is published on. |
| `LAYERLEAK_API_PORT` | `8080` | Host port published for the API. |
| `LAYERLEAK_DB_NAME` | `layerleak` | Database created by the `db` service. |
| `LAYERLEAK_DB_USER` | `layerleak` | Role created by the `db` service. |
| `LAYERLEAK_DB_PASSWORD` | required | Password for that role. `.env.example` ships it empty and Compose refuses to start until it is set. |
| `LAYERLEAK_API_STOP_GRACE_PERIOD` | `35s` | How long Compose waits for the API to drain before killing it; keep it above `LAYERLEAK_API_SHUTDOWN_TIMEOUT`. |

## PostgreSQL and migrations

The API and persistent CLI mode require PostgreSQL 16.13 or newer. Migrations
are explicit and must complete before the API becomes ready.

From a checkout:

```bash
export LAYERLEAK_DATABASE_URL='postgres://layerleak:password@localhost:5432/layerleak?sslmode=disable'
export LAYERLEAK_MIGRATIONS_DIR="$PWD/migrations"
go run ./cmd/migrate
go run ./cmd/migrate
```

The second run is intentionally a no-op. Without flags the command applies
every pending migration. `--status` prints the ledger (each shipped migration
with its state, applied time and SHA-256, then `current` and `expected`) and
exits 0 when the database is current, 2 when migrations are pending or a legacy
schema is waiting to be adopted, and 1 on any error such as checksum drift;
`--dry-run` lists what a run would adopt and apply, changes nothing, and exits
0; `--version` prints the build version. Neither `--status` nor `--dry-run`
creates the ledger, adopts a legacy schema or takes the migration lock. There
is no `down` command: the shipped `*.down.sql` files are for manual use with
`psql` and bypass the ledger. The migration command reads three variables of
its own:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAYERLEAK_MIGRATIONS_DIR` | `/app/migrations` | Directory holding the shipped `migrations/*.sql`; from a checkout use `$PWD/migrations`. |
| `LAYERLEAK_MIGRATION_TIMEOUT` | `30m` | Overall deadline for one run of the command; `0` disables it. |
| `LAYERLEAK_MIGRATION_LOCK_TIMEOUT` | `15s` | How long each of three attempts waits for the migration advisory lock. |

The migration command uses an advisory lock with bounded waits, a checksummed
migration ledger, and one transaction per migration. It can adopt a complete
legacy 0001-0003 schema and refuses drift, gaps, dirty state, or a partial
legacy schema. On a populated database, stop API replicas and long-running
transactions before applying `0004`, whose data updates hold row locks.

The container bundles the same native command:

```bash
docker run --rm \
  -e LAYERLEAK_DATABASE_URL="$LAYERLEAK_DATABASE_URL" \
  --entrypoint /usr/local/bin/layerleak-migrate-up \
  ghcr.io/brumbelow/layerleak:latest
```

To irreversibly remove opt-in raw material while retaining redacted findings,
fingerprints, occurrences, and history:

First set `LAYERLEAK_PERSIST_RAW_SECRETS=0` for every API or CLI database
writer and restart or stop those processes. Any writer that remains opted in
can store raw material again after the purge completes.

```bash
docker run --rm \
  -e LAYERLEAK_DATABASE_URL="$LAYERLEAK_DATABASE_URL" \
  --entrypoint /usr/local/bin/layerleak-purge-raw-secrets \
  ghcr.io/brumbelow/layerleak:latest \
  --dry-run
docker run --rm \
  -e LAYERLEAK_DATABASE_URL="$LAYERLEAK_DATABASE_URL" \
  --entrypoint /usr/local/bin/layerleak-purge-raw-secrets \
  ghcr.io/brumbelow/layerleak:latest \
  --confirm
```

`--dry-run` prints how many raw finding values and occurrence snippets would
be cleared and changes nothing. A real purge requires `--confirm`, clears only
`findings.value` and `finding_occurrences.raw_snippet`, and works in ascending
id-range batches of `--batch-size` rows (default 5000), one transaction per
batch: each batch holds the exclusive purge lock only for its own transaction,
so concurrent scan writers wait for one batch instead of the whole purge, and
every batch is bounded by `LAYERLEAK_DATABASE_WRITE_TIMEOUT`. Running totals go
to stderr after each batch; the final counts go to stdout. Batches that already
committed stay purged if a later one fails, so a failed or timed-out run can
simply be rerun. The command reads one variable of its own:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAYERLEAK_PURGE_TIMEOUT` | `30m` | Overall deadline for one run of `layerleak-purge-raw-secrets`; `0` disables it. Each batch is separately bounded by `LAYERLEAK_DATABASE_WRITE_TIMEOUT`. |

An `UPDATE` does not remove the old row versions: raw material lingers in dead
tuples until autovacuum (or `VACUUM FULL`) rewrites `findings` and
`finding_occurrences`, and it remains in WAL archives, replicas and backups
taken before the purge until those are rotated or expired.

## HTTP API

Run the API from a migrated checkout:

```bash
export LAYERLEAK_DATABASE_URL='postgres://layerleak:password@localhost:5432/layerleak?sslmode=disable'
go run ./cmd/api
```

Health endpoints:

| Endpoint | Meaning |
| --- | --- |
| `GET /health` | Process liveness and the build `version`; does not query PostgreSQL. |
| `GET /livez` | Kubernetes-style process liveness alias with the same body. |
| `GET /readyz` | Readiness; requires a database ping and exact schema version `0004`. The result is reused for `LAYERLEAK_API_READINESS_CACHE_TTL`, and the endpoint answers 503 `not_ready` while the process drains before shutdown. |

API endpoints:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/scans` | Run a synchronous scan and persist its redacted result. |
| `GET /api/v1/scans/{id}` | Read one persisted scan. |
| `GET /api/v1/repositories` | List persisted repositories. |
| `GET /api/v1/repositories/{repository}/scans` | List repository scan history. |
| `GET /api/v1/repositories/{repository}/findings` | List deduplicated findings. |
| `GET /api/v1/findings/{id}` | Read one finding and its occurrences. |

Start a single-image scan:

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -d '{"reference":"alpine:3.20","platform":"linux/amd64"}' \
  http://127.0.0.1:8080/api/v1/scans
```

A bare reference means `latest`. Set `"all_tags": true` to request an explicit
repository sweep:

```json
{
  "reference": "library/alpine",
  "all_tags": true
}
```

List endpoints accept `limit` and `offset`; `limit` defaults to 50 and values
above 200 are clamped to 200 (the response reports the effective `limit`).
Every list response also returns `next_cursor`: an opaque keyset position for
the following page whenever the page was full, or `""` when the listing is
exhausted. Pass it back as `cursor` to continue from that position; deep pages
then cost the same as the first, unlike `offset`, which re-sorts everything it
skips. A cursor is tied to one endpoint and cannot be combined with a non-zero
`offset`; a foreign, malformed or combined cursor is 400 `invalid_request`.
Repository scan and finding endpoints accept `registry` as `host` or
`host:port` (default `docker.io`; `index.docker.io` and `registry-1.docker.io`
normalise to `docker.io`; anything else is 400) and echo the normalised value
as `registry`. The `{repository}` segment accepts a literal `/` or `%2F`, is
decoded once, and must match the OCI repository-name grammar (lowercase; 400
otherwise). The finding list accepts `disposition=actionable|suppressed|all`
and defaults to actionable.

Authentication is off by default. Setting `LAYERLEAK_API_BEARER_TOKENS` (or
`LAYERLEAK_API_BEARER_TOKENS_FILE`) turns on a shared-token check for every
`/api/` path: requests must send `Authorization: Bearer <token>`, and a missing,
malformed or unknown token answers 401 `unauthorized` with
`WWW-Authenticate: Bearer realm="layerleak"` and the usual error envelope. The
health endpoints never require a token. Tokens are at least 32 characters, are
held in memory only as SHA-256 digests, are compared in constant time, and never
reach the logs (a short digest prefix identifies which token was used at debug
level). The API warns at startup when it listens on a non-loopback address
without tokens. This is defence in depth, not authorization: keep the gateway.

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $LAYERLEAK_API_TOKEN" \
  http://127.0.0.1:8080/api/v1/repositories
```

Every response is JSON and carries `X-Request-ID`, `Cache-Control: no-store`
and `X-Content-Type-Options: nosniff`. A caller-supplied `X-Request-ID` of up
to 128 characters from `A-Z a-z 0-9 - _ .` is echoed; anything else is replaced
by a generated id. Unknown or non-canonical paths (repeated slashes, dot
segments) answer 404 `not_found`; a wrong method answers 405 with `Allow`. The
API never redirects. Error bodies use this shape:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "human-readable description",
    "request_id": "request correlation id"
  }
}
```

Messages are fixed neutral strings; upstream error text, reference strings and
request bodies are never echoed. Status codes and `code` values:

| Status | `code` | Where | Body |
| --- | --- | --- | --- |
| 200 | | every endpoint | the documented response |
| 400 | `invalid_request` | every endpoint | error envelope |
| 401 | `unauthorized` | every `/api/` path when `LAYERLEAK_API_BEARER_TOKENS` is set; `WWW-Authenticate: Bearer realm="layerleak"` | error envelope |
| 404 | `not_found` | reads, unknown paths | error envelope |
| 404 | `image_not_found` | `POST /api/v1/scans` | envelope, plus `result` when available |
| 405 | `method_not_allowed` | every endpoint; `Allow` names the accepted method | error envelope |
| 408 | `scan_canceled` | `POST /api/v1/scans`; the client closed the connection before the scan finished | error envelope |
| 413 | `request_too_large` | `POST /api/v1/scans` | error envelope |
| 415 | `unsupported_media_type` | `POST /api/v1/scans` | error envelope |
| 422 | `scan_incomplete` | `POST /api/v1/scans` | envelope, plus `result` and `scan_run_id` when persisted |
| 422 | `scan_limit_exceeded` | `POST /api/v1/scans`; the error object adds `limit_kind` and `limit` | envelope, plus `result` and `scan_run_id` when persisted |
| 429 | `scan_capacity_exceeded` | `POST /api/v1/scans`; `Retry-After: 5` | error envelope |
| 500 | `internal_error` | every endpoint | error envelope |
| 502 | `scan_failed` | `POST /api/v1/scans`; transport errors, registry 5xx and timeouts inside the scan | envelope, plus `result` when available |
| 502 | `registry_unauthorized` | `POST /api/v1/scans`; the registry or its token endpoint answered 401/403 | envelope, plus `result` when available |
| 503 | `storage_unavailable` | reads: a database query failed; `POST /api/v1/scans`: the scan finished but could not be persisted | reads: envelope; scans: envelope plus `result` |
| 503 | `registry_rate_limited` | `POST /api/v1/scans`; the registry answered 429 after bounded retries; `Retry-After: 60` | envelope, plus `result` when available |
| 503 | `server_shutting_down` | `POST /api/v1/scans` while draining, and any request the drain cancelled | error envelope |
| 503 | `not_ready` | `GET /readyz` | error envelope |
| 504 | `scan_timeout` | `POST /api/v1/scans`; `LAYERLEAK_API_SCAN_TIMEOUT` expired | envelope, plus `result` when available |

`result` is included in a `POST /api/v1/scans` error body whenever the scan
produced a redacted result; `scan_run_id` is included only when that result was
persisted. A 503 `storage_unavailable` on a scan never invents a `scan_run_id`.
Failed and incomplete responses retain their actual `status`, coverage, and
sanitized diagnostics; `error` fields inside `result` are replaced with
`scan step failed` and diagnostic messages with fixed text chosen from the
diagnostic `code`.

Unknown request fields and extra JSON values are rejected. Request size,
concurrency, database work, and scan duration are bounded by configuration. See
the versioned [OpenAPI 3.1 specification](./web/docs/openapi.yaml) for request,
response, pagination, and error schemas.

The API logs one JSON record per request (method, route pattern, status,
bytes, duration, request id, remote address; never the path, query or body).
Setting `LAYERLEAK_API_METRICS_ADDR` adds a separate listener that serves
Prometheus text-format metrics at `GET /metrics`, with the same timeouts and
drain as the API: `layerleak_api_requests_total{route,status_class}`,
`layerleak_api_request_duration_seconds` (fixed buckets from 5 ms to 30 min, by
`route`), `layerleak_scans_total{outcome}`, `layerleak_scan_errors_total{code}`,
`layerleak_scans_in_flight`, `layerleak_process_start_time_seconds` and
`layerleak_build_info{version}`. Label values are mux route patterns, status
classes and error codes only; no path, reference or request body ever becomes
a label. The metrics port is unauthenticated and is never the API port, so
bind it to a private interface.
On `SIGTERM` or `SIGINT` it drains: `/readyz` answers 503 and new scans are
refused for `LAYERLEAK_API_PRESTOP_DELAY` while in-flight requests continue,
then in-flight scans are cancelled with 503 `server_shutting_down` and the
server stops within `LAYERLEAK_API_SHUTDOWN_TIMEOUT`, exiting 0.

## Container and Compose deployment

The published API image supports `linux/amd64` and `linux/arm64`. It is a
shell-free, non-root image containing only CA roots, four static Layerleak
binaries, and migrations. The image healthcheck probes `/readyz` with a hard
two-second deadline.

```bash
docker pull ghcr.io/brumbelow/layerleak:latest
docker run --rm \
  -p 8080:8080 \
  -v /path/to/postgres-ca.pem:/etc/layerleak/postgres-ca.pem:ro \
  -e LAYERLEAK_DATABASE_URL='postgres://<user>:<password>@<host>:5432/layerleak?sslmode=verify-full&sslrootcert=/etc/layerleak/postgres-ca.pem' \
  --read-only --tmpfs /tmp:mode=1777 \
  --cap-drop ALL --security-opt no-new-privileges \
  ghcr.io/brumbelow/layerleak:latest
```

Mount the CA certificate that signed the PostgreSQL server certificate and keep
`sslmode=verify-full` for any database that is not on the same host: it is the
only mode that both encrypts the connection and verifies the server's identity,
which matters for a database that may hold raw secret material. Omitting
`sslmode` is not a safe shortcut, because lib/pq's implicit default `require`
encrypts the connection without verifying the server certificate. Use
`sslmode=disable` only for a database reachable solely over a private network,
as the Compose file does for its `db` service.

For Compose, copy the example and set the required password. The example
ships it empty, and `docker compose` refuses to start until it has a value:

```bash
cp .env.example .env
# Set LAYERLEAK_DB_PASSWORD in .env.
docker compose config
docker compose up -d
docker compose ps
curl --fail http://127.0.0.1:8080/readyz
```

The Compose services use a digest-pinned PostgreSQL 16.15 image, wait for
PostgreSQL health, run the idempotent migration command to completion before
the API starts (a fresh volume becomes ready without a manual step), run the
API read-only with all capabilities dropped, and use the native readiness
probe. The host port binds to `127.0.0.1` by default; set `LAYERLEAK_API_HOST`
only when an authenticated network edge is ready. The Compose connection string
uses `sslmode=disable` only because the `db` container is reachable solely on
the private Compose network; point the API at any other database with
`sslmode=verify-full` as shown above. The `api` service has a 35 second
`stop_grace_period`: whatever runs the container must allow more than
`LAYERLEAK_API_SHUTDOWN_TIMEOUT` (for example `docker stop -t 35` or a
Kubernetes `terminationGracePeriodSeconds` above 30), otherwise an in-flight
scan is killed before it is persisted. Purge raw material only after reviewing
the command:

```bash
docker compose --profile tools run --rm purge-raw-secrets --dry-run
docker compose --profile tools run --rm purge-raw-secrets --confirm
```

Compose hands the database password to the containers as `PGPASSWORD`, so it
may contain any characters. Only a password embedded in a connection URL must
be percent-encoded.

## Verify a release

Releases publish one signed multi-platform image digest. RC tags never move
`latest`; a stable tag and `latest` point to the exact accepted RC digest.

```bash
version=v3.0.0
image=ghcr.io/brumbelow/layerleak
docker buildx imagetools inspect "${image}:${version}"
```

Each GitHub release includes checksums, per-platform SPDX SBOMs, SLSA
provenance, vulnerability reports, attestation bundles, and a
`release-manifest.json` that binds the source commit to the image index and
platform digests. The canonical `cosign verify`, `gh attestation verify`, and
`gh release verify` commands live in
[SECURITY.md](./SECURITY.md#verify-release-integrity); always verify the
digest-addressed image rather than trusting a mutable tag.

## Version history

The canonical module path is `github.com/brumbelow/layerleak/v3`; 3.0.0 is its
first release and is preceded by one or more release candidates.

Two earlier lines exist and are frozen. v1.0.0 is the only release ever
published on the root import path `github.com/brumbelow/layerleak`, so
`go install github.com/brumbelow/layerleak@latest` always resolves to that
build. Historical GitHub/container tags v2.0.0-v2.5.0 were created without the
`/v2` module path Go requires, so they were never installable as Go modules and
are preserved only for history. The 3.0.0 line contains and supersedes that
work.

See [CHANGELOG.md](./CHANGELOG.md) for release-line details and
[RELEASING.md](./RELEASING.md) for the protected release procedure.

## License and notices

Layerleak is released under the [MIT License](./LICENSE). Third-party components
retain their own licenses; see [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md).

## Support the project

If Layerleak saves you time, you can support ongoing maintenance through
[Ko-fi](https://ko-fi.com/brumbelow).
