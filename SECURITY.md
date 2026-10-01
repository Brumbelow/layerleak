# Security policy

Layerleak processes untrusted OCI metadata, compressed layers, tar archives,
registry authentication challenges, redirects, and strings that may be real
credentials. Please report vulnerabilities privately and avoid testing against
systems or data you do not own.

## Supported versions

| Version | Support |
| --- | --- |
| Latest stable 3.0.x release (`github.com/brumbelow/layerleak/v3`) | Security fixes |
| Current announced v3 release candidate | Release-blocking fixes until stable |
| Older v3 releases | Unsupported; upgrade to the latest 3.0.x |
| v1.0.0 on the root import path `github.com/brumbelow/layerleak` | Unsupported. The root path is frozen at v1.0.0 forever; `go install github.com/brumbelow/layerleak@latest` always resolves to it. Migrate to `/v3` ([UPGRADING.md](./UPGRADING.md)). |
| Historical v2.0.0-v2.5.0 GitHub/container tags | Unsupported and never valid Go modules |
| Unreleased `main` | No production support guarantee |

Tags are immutable. Fixes ship as a new patch or release candidate; existing
releases are never patched in place.

## Report a vulnerability

Use GitHub's private vulnerability reporting form when it is available under
the repository **Security** tab. Otherwise email `admin@brumbelow.org`.

Do not open a public issue for a vulnerability that could expose credentials,
bypass egress restrictions, produce a false clean result, corrupt persistence,
or enable denial of service. Do not include live secrets in a report. Revoke or
rotate any credential that may have been exposed before sharing a redacted
reproduction.

Include:

- affected version (`layerleak version`), command, API endpoint, or image
  digest;
- operating system and architecture;
- minimal reproduction using synthetic data;
- expected and observed behavior;
- impact and required attacker access;
- whether raw-secret persistence was enabled;
- relevant request ID, registry media type, manifest digest, or migration
  version;
- suggested mitigation, if known.

Encrypt particularly sensitive details before sending and ask for a suitable
public key if needed.

## Response targets

We aim to:

- acknowledge a new report within 7 days;
- provide an initial severity and next-step assessment within 14 days;
- ship a fix or mitigation within 90 days of acknowledgement.

Critical issues may be handled faster. If a fix depends on upstream work, we
will communicate status and available mitigations. We coordinate disclosure and
credit with the reporter unless anonymity is requested. If 90 days pass without
a fix, mitigation, or meaningful status update, the reporter may disclose.

## Security boundaries

Expected protections include:

- OCI content is verified against advertised sha256 or sha512 digests before
  parsing or scanning; the root manifest digest and size are checked before
  any JSON is parsed;
- archive traversal, unsafe link targets, decompression, resource exhaustion,
  redirects, and private-network egress are treated as hostile-input concerns;
  the zstd decoder window is capped at a fixed 128 MiB regardless of
  `LAYERLEAK_MAX_LAYER_BYTES`, and bytes after the end of a compressed layer
  stream fail the layer closed (`layer_trailing_data`);
- redirects are re-validated hop by hop and never downgrade https to http,
  even to an allowlisted host; the `Authorization` header is dropped on any
  cross-host redirect; deprecated site-local (`fec0::/10`) and
  IPv4-compatible (`::/96`) IPv6 ranges count as non-public;
- when `HTTPS_PROXY` selects a proxy, that proxy becomes the egress control:
  the registry hostname stays in the request so the proxy sees
  `CONNECT host:port`, local DNS pinning is skipped for proxied requests
  (address literals are still classified), and the https-only rule and the
  allowlists still apply; `NO_PROXY` is honoured. This is a documented trust
  boundary;
- private registry and auth destinations require exact explicit allowlisting;
- scan limits fail closed and incomplete coverage is visible in status,
  diagnostics, persistence, and exit behavior (exit code `3`);
- findings are redacted by default; `redacted_value` masks values shorter
  than 12 characters completely and otherwise reveals only the first three
  characters before a fixed-length mask, and context snippets redact every
  copy of a matched secret in the window;
- API responses and scan-history snapshots remain redacted even when raw
  storage is explicitly enabled;
- NUL and other C0 control characters (and DEL) in image-config keys, paths,
  snippets and raw values become U+FFFD consistently in CLI output, API JSON
  and stored rows, so a hostile image cannot abort persistence of a scan by
  embedding one;
- the CLI never writes a raw secret value locally, even with
  `LAYERLEAK_PERSIST_RAW_SECRETS=1`: the scan record, `--format json` and
  `--format sarif` are always redacted. A missing record directory is
  created `0700`; an existing directory is inspected with `Lstat` and never
  `chmod`-ed, a symbolic link in its place is refused, a group- or
  world-readable directory produces one warning, and records are written
  `0600` without ever overwriting an existing file;
- CLI registry credentials are taken only through `--username` with
  `--password-stdin` (no `--password` flag), the configured
  `LAYERLEAK_REGISTRY_USERNAME`/`LAYERLEAK_REGISTRY_PASSWORD` pair or a
  Docker `config.json` named by `LAYERLEAK_DOCKER_CONFIG`; a credential is
  bound to the one registry host it was given for, is sent only over https
  (to the registry and to its token realm, which must itself pass the
  allowlist and private-host checks), and never appears in logs, errors,
  output, scan records or the database;
- API bearer tokens (`LAYERLEAK_API_BEARER_TOKENS` or `_FILE`) are held only
  as SHA-256 digests, compared in constant time against every configured
  digest, and never logged (a short digest prefix identifies the token at
  debug level); health probes stay open;
- the API access log records the method, route pattern, status, size,
  duration, request id and remote address, never the path, query or body;
  panic logs carry the goroutine stack and panic type, never the panic value;
- the metrics listener, when enabled, labels samples only with mux route
  patterns, status classes, error codes and the build version; no path,
  reference, request body or secret ever becomes a label;
- migrations are checksummed, transactional, serialized, and required for
  readiness, and the shipped files are frozen by a golden test;
- the API image runs without a shell, as numeric UID/GID 10001, and supports a
  read-only filesystem;
- release images are scanned on both platforms, carry SBOM/provenance
  attestations, and are keyless-signed after full verification.

The following are deployment responsibilities, not built-in controls:

- The API has no authorization, tenant isolation, TLS termination, or rate
  limiting across replicas, and no authentication unless
  `LAYERLEAK_API_BEARER_TOKENS` is configured (a shared-token check, not
  per-user authorization). Keep it private and front it with appropriate
  controls; the metrics listener, when enabled, is unauthenticated and must
  stay on a private interface. The API warns at startup when it listens on a
  non-loopback address without tokens.
- `LAYERLEAK_PERSIST_RAW_SECRETS=1` stores sensitive material in PostgreSQL.
  Restrict database access, encryption, backups, logs, and retention
  accordingly. Disabling the setting prevents new raw writes but does not
  delete historical values. Before running
  `layerleak-purge-raw-secrets --confirm`, disable the setting on every
  database writer and restart or stop those processes so they cannot
  repopulate the purged fields; the purge recounts afterwards and fails if
  residue remains.
- A private-host allowlist grants the scanner network reachability to that exact
  destination. Keep allowlists minimal and review redirects and DNS controls in
  the deployment environment.
- PostgreSQL connections should use `sslmode=verify-full` with the server CA
  mounted for any database that is not on the same host. Omitting `sslmode`
  is not safe: lib/pq's implicit default `require` encrypts the connection but
  does not verify the server certificate.
- Registry credentials reach only the registry host they were configured for
  (and its token realm), over https. The API process applies the
  `LAYERLEAK_REGISTRY_USERNAME`/`PASSWORD` pair only when
  `LAYERLEAK_REGISTRY_BASE_URL` pins the registry; it is never bound to the
  registry of a reference a caller submits, so a caller cannot make the
  server send the operator's credential to a host or token realm the caller
  names. Docker `config.json` credentials are host-keyed, so in an API
  deployment they let any API caller trigger authenticated scans of the
  operator's private images on those hosts and read the redacted findings;
  keep the API private. Never embed credentials in image references or
  endpoint overrides.

## Verify release integrity

Release notes include a source SHA, image index digest, both platform digests,
SPDX SBOMs, SLSA provenance, vulnerability reports, attestation bundles, and
`SHA256SUMS`. Verify digest-addressed images rather than trusting a mutable
tag:

```bash
image=ghcr.io/brumbelow/layerleak
version=v3.0.0
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

Prebuilt CLI archives (`layerleak_<version>_<os>_<arch>.tar.gz` and
`layerleak_<version>_windows_amd64.zip`) are covered by a `sha256sum` list that
is keyless-signed with Cosign, and by a SLSA v1 build-provenance attestation
whose subjects are the five archives. Verify an archive before running it:

```bash
version=v3.0.0
checksums="layerleak_${version}_checksums.txt"
gh release download "${version}" --repo Brumbelow/layerleak \
  --pattern "layerleak_${version}_*" --pattern release-manifest.json
sha256sum --check --ignore-missing "${checksums}"

cosign verify-blob \
  --bundle "${checksums}.sigstore.json" \
  --certificate-identity 'https://github.com/Brumbelow/layerleak/.github/workflows/container-release.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${checksums}"

gh attestation verify "layerleak_${version}_linux_amd64.tar.gz" \
  --repo Brumbelow/layerleak \
  --signer-workflow Brumbelow/layerleak/.github/workflows/container-release.yml \
  --source-ref refs/heads/main \
  --source-digest "$(jq -r .workflow_sha release-manifest.json)" \
  --deny-self-hosted-runners
```

`--source-digest` takes the manifest's `workflow_sha` (the commit the release
workflow ran at), not `source_sha`: the two differ when a stable release is
promoted from an accepted release candidate. The composite GitHub Action
performs the same three checks before it runs a downloaded binary.

See [RELEASING.md](./RELEASING.md) for the complete release trust model.
