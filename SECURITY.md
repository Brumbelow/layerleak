# Security policy

Layerleak processes untrusted OCI metadata, compressed layers, tar archives,
registry authentication challenges, redirects, and strings that may be real
credentials. Please report vulnerabilities privately and avoid testing against
systems or data you do not own.

## Supported versions

| Version | Support |
| --- | --- |
| Latest stable v1 release | Security fixes |
| Current announced v1 release candidate | Release-blocking fixes until stable |
| Older v1 releases | Unsupported; upgrade to latest |
| Historical v2.0.0-v2.5.0 tags | Unsupported and not valid v2 Go modules |
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

- affected version, command, API endpoint, or image digest;
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
  parsing or scanning;
- archive traversal, unsafe link targets, decompression, resource exhaustion,
  redirects, and private-network egress are treated as hostile-input concerns;
- private registry and auth destinations require exact explicit allowlisting;
- scan limits fail closed and incomplete coverage is visible in status,
  diagnostics, persistence, and exit behavior;
- findings are redacted by default;
- API responses and scan-history snapshots remain redacted even when raw
  storage is explicitly enabled;
- migrations are checksummed, transactional, serialized, and required for
  readiness;
- the API image runs without a shell, as a numeric non-root user, and supports a
  read-only filesystem;
- release images are scanned on both platforms, carry SBOM/provenance
  attestations, and are keyless-signed after full verification.

The following are deployment responsibilities, not built-in controls:

- The API has no authentication, authorization, tenant isolation, TLS
  termination, or rate limiting across replicas. Keep it private and front it
  with appropriate controls.
- `LAYERLEAK_PERSIST_RAW_SECRETS=1` stores sensitive material. Restrict database
  access, encryption, backups, logs, and retention accordingly. Disabling the
  setting prevents new raw writes but does not delete historical values. Before
  running `layerleak-purge-raw-secrets --confirm`, disable the setting on every
  database writer and restart or stop those processes so they cannot repopulate
  the purged fields.
- A private-host allowlist grants the scanner network reachability to that exact
  destination. Keep allowlists minimal and review redirects and DNS controls in
  the deployment environment.
- Registry credentials are not a supported user-facing feature. Do not embed
  credentials in image references or endpoint overrides.

## Verify release integrity

Release notes include a source SHA, image index digest, both platform digests,
SPDX SBOMs, SLSA provenance, vulnerability reports, attestation bundles, and
checksums. Verify digest-addressed images rather than trusting a mutable tag:

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
```

See [RELEASING.md](./RELEASING.md) for the complete release trust model.
