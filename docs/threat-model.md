# Threat model

Layerleak's job is to find secrets in images it does not trust, over networks
it does not control, and to report them without becoming a new place where
those secrets leak. This note records what the scanner defends against, what
it deliberately leaves to the deployment, and where the bounds live in code.
[SECURITY.md](../SECURITY.md) is the reporting policy;
[architecture.md](architecture.md) maps the packages named here.

## Assets

1. **Secrets inside images.** The point of the tool. Raw values stay in memory
   only; everything written, logged, persisted or served is redacted and keyed
   by a `sha256` fingerprint unless an operator explicitly opts in to raw
   persistence in PostgreSQL.
2. **The scanning host.** CPU, memory, disk and network of the machine running
   the CLI or API, and the private network it sits on.
3. **Scan integrity.** A clean result must mean "nothing found in everything we
   looked at", never "we gave up quietly".
4. **The release chain.** Users trust `go install` of the `/v3` module and the
   signed container image.

## Adversaries

- **A hostile image author** who controls manifests, configs and layers, and may
  also control the registry serving them.
- **A hostile or compromised registry** (or a man-in-the-middle for plain
  `http://` endpoints an operator allowed).
- **An API client** on the private network where the API listens.
- **A reader of persisted data**: database backups, logs, local scan records.

Out of scope: a compromised scanning host or Go toolchain, kernel-level
container escapes (no containers are run), and attackers who already hold the
database credentials.

## Untrusted inputs and their bounds

| Input | Hostile shapes | Defence (package) |
| --- | --- | --- |
| Image reference | credentials in references, odd hosts, case tricks | strict grammar, Docker Hub aliases normalised, credentials rejected (`manifest`) |
| Registry responses | redirects to private hosts, https→http downgrade, oversize bodies, slow loris, pre-signed URLs in errors | DNS pinning in one hardened transport, private-range blocking with exact allowlists, re-validated redirects, size caps on every body, per-attempt deadlines, URL redaction in errors (`registry`) |
| Auth challenges and tokens | malformed `WWW-Authenticate`, huge token bodies | RFC 7235 parsing, token response size cap (`registry`) |
| Manifests and indexes | digest/size mismatch, nested indexes, foreign layers, thousands of platforms | digest verified before parse, media types validated, non-linux and non-image entries skipped with diagnostics, manifest count cap (`manifest`, `scanner`) |
| Compressed layers | decompression bombs, zstd window abuse, trailing data, concatenated streams | fixed decoder window, streamed decompression with byte caps per layer and per image, fail-closed on trailing data (`layers`) |
| Tar archives | path traversal, symlink and hardlink games, whiteout abuse, sparse files, PAX headers, device nodes, entry floods | path normalisation, unsafe entries counted and reported, bounded entries and retained bytes, hardlink/symlink target rules (`layers`) |
| File contents | pathological regex inputs, huge files, binary blobs | per-file size cap with skip diagnostic, binary exclusion, prefiltered detectors with fuzz coverage (`scanner`, `detectors`) |
| Image config | NUL and control characters in env/labels, oversize config | control-character sanitisation shared by output and storage, config size cap (`findings`, `storage`) |
| API requests | oversize bodies, wrong content types, path tricks, concurrent scans | body limit, media type check, path cleaning rejection, concurrency gate, neutral error envelopes (`api`) |
| Database rows | hostile strings reaching PostgreSQL | sanitised at the boundary, parameterised statements only (`storage`) |

Every cap is configurable through `LAYERLEAK_*` variables and documented in the
README. Caps that would make the tool useless at `0` reject `0`; the rest treat
`0` as "disabled" and the README says which is which. Exceeding a cap never
truncates silently: the platform or scan becomes `partial` (or `failed`), a
diagnostic names the cap, the CLI exits non-zero unless `--allow-partial` was
given, and the API returns 422 with the partial result attached.

## What a clean result means

`status: completed` with `coverage.complete: true` means every selected
platform manifest was fetched and verified, every layer replayed in full, every
scannable file and metadata value passed through the whole detector set, and no
budget was hit. Anything less is `partial` and says why in `diagnostics`.
Suppressed findings (test paths, placeholders, dummy values) are still reported
with their reason so a reviewer can disagree with the policy.

## What the scanner does not protect

- **Confidentiality of the API.** There is no authentication, authorisation,
  TLS termination or cross-replica rate limiting. Run it on a private network
  behind your own edge.
- **Raw persistence.** `LAYERLEAK_PERSIST_RAW_SECRETS=1` stores the real values
  in PostgreSQL. That database, its backups and its logs then hold secrets;
  protect them accordingly and use the purge command when the need passes.
- **Detector completeness.** Detectors are heuristics. A clean result is a
  statement about the detector set that ran, not proof that no secret exists.
- **Private-host allowlists.** Allowlisting a host grants the scanner the right
  to connect to it, including over plain `http://`. The allowlist is the
  operator's trust decision.
- **Proxies.** When `HTTPS_PROXY` is set the proxy becomes the egress control
  and DNS pinning is skipped for proxied requests; the allowlist and https
  checks still apply.

## Release chain

The release workflow runs from a protected environment, pins every tool by
checksum, scans the image on both platforms, attaches SBOM and provenance
attestations, signs keylessly, and only then publishes. Tags are immutable and
the module is served through the Go module proxy under its `/v3` path.
[RELEASING.md](../RELEASING.md) has the complete trust model and verification
commands.
