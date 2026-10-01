# False positives and suppressions

Layerleak reports every match it finds and lets a policy layer label the ones
that are probably not live secrets. Nothing that reaches the policy is
dropped: a suppressed finding still appears in the result under
`suppressed_findings` with a `disposition` and a `disposition_reason`, is
counted separately (`suppressed_findings_count`,
`suppressed_unique_fingerprints`), and is written to the scan record and the
database so a reviewer can disagree with the policy. The HTTP API lists them
with `?disposition=suppressed` (or `all`).

## Dispositions

| `disposition` | Meaning | Affects exit code |
| --- | --- | --- |
| `actionable` | Looks like a real secret in a real location; listed under `findings` and counted in `total_findings`. | Yes: exit `2` when its confidence is at or above `--fail-on` |
| `example` | Matched, but the location or value marks it as sample, test or placeholder material; listed under `suppressed_findings`. | No |
| `baselined` | An actionable finding whose fingerprint (and detector, when the entry names one) is listed in the caller's `--baseline` file; listed under `suppressed_findings`. | No |

These are the only three values (`internal/findings/findings.go`). In SARIF
output an `example` or `baselined` finding is a result with an accepted
`suppressions` entry; a baselined suppression carries the entry's reason.
`baselined` is applied by the CLI after the scan, so the PostgreSQL row and
the HTTP API keep the scanner's `actionable` disposition for the same finding.

## Reasons

`disposition_reason` is set only on `example` findings. The values and what
triggers them (`internal/detectionpolicy/policy.go`, applied through
`findings.Classify`):

| `disposition_reason` | What triggered it |
| --- | --- |
| `test_path` | A path segment is exactly `test`, `tests`, `__tests__`, `testdata`, `fixtures` or `__mocks__`. Segments are compared whole and case-insensitively, so `/app/config/testimonials.json` is not a test path. |
| `example_path` | The file name contains `.example` or `.sample` (`config.example.yml`, `.env.sample`). |
| `known_dummy_value` | The value (or the userinfo of a URL value) contains `EXAMPLE` or `PLACEHOLDER` in any case, is exactly one of `changeme`, `replace_me`, `replace-me`, `dummy`, `fake`, `your_token_here`, `your_secret_here`, or is a URL whose user is `foobar`. The AWS documentation keys (`AKIAIOSFODNN7EXAMPLE`) land here. |
| `placeholder_marker` | The key, the value or the assignment line (with a trailing `#` or `//` comment removed) contains a placeholder marker such as `placeholder`, `dummy`, `fake`, `changeme`, `change_me`, `replace_me`, `replace this`, `your_token_here`, `your_api_key`, `api_key_here`, `insert_token`, `token_goes_here`, `example token` or `sample token`. |
| `default_credentials` | A URL whose userinfo is a well-known default pair: `admin:admin`, `admin:password`, `admin:admin123`, `root:password`, `root:root`, `root:toor`, `test:test`, `user:user`, `user:password`, `guest:guest`, `postgres:postgres`, `mysql:mysql`, `minioadmin:minioadmin`, `elastic:changeme`, `neo4j:neo4j`, `rabbitmq:rabbitmq`, `redis:redis` or `foo:bar`. Reported as suppressed rather than discarded so default credentials on real hosts stay visible. |
| `reserved_host` | A weak signal (see below): the line or value mentions `example.com`, `example.org`, `example.net`, `localhost`, `127.0.0.1` or `0.0.0.0`. |

The reasons above `reserved_host` are decisive on their own. The remaining
signals are weak and at least two of them must coincide before a finding is
suppressed, with the first matching reason reported:

- a path segment `example`, `examples`, `sample`, `samples`, `demo`, `demos`,
  `doc`, `docs`, `spec`, `specs`, `e2e`, `acceptance`, `stubs`, `mock`,
  `mocks` or `fixture` (`example_path`);
- a file name containing `.template` (`example_path`);
- a placeholder marker in the file path rather than in the value
  (`placeholder_marker`);
- a reserved host in the line or value (`reserved_host`);
- a key containing `example`, `sample` or `demo` (`placeholder_marker`).

So OpenAPI `spec/` directories, envsubst `.template` files and a vendor path
that happens to contain `fake` do not suppress a finding by themselves.

Before classification, the detector layer discards a small set of matches
outright (they never become findings): empty values; values equal to
`foobar`, `foo:bar`, `user@example.com`, `admin@example.com`,
`test@example.com`, `admin:admin`, `admin:password`, `root:password`,
`test:test` or `user:user` (also when base64-encoded or prefixed with
`user=`, `username=` or `credentials=`); and URLs whose host is a reserved
host *and* whose user is a placeholder pair, `foobar`, `user`, `admin` or
`test`. The same pair on a real host is kept as `default_credentials`.

## Confidence and `--fail-on`

Every finding carries `confidence` `low`, `medium` or `high`, and `--fail-on`
picks the lowest confidence of an actionable finding that produces exit code
`2`:

- `--fail-on low` (default) fails on every actionable finding;
- `--fail-on medium` or `high` keeps reporting lower-confidence findings in
  the result without failing the pipeline;
- `--fail-on none` reports only.

Notes on the heuristics:

- `keyword_entropy` starts at `low` confidence and is raised to `medium` when
  one of the file path, the key or the value shape looks sensitive, and to
  `high` when two do. Content digests (`sha256:` and similar prefixes,
  digest/checksum/etag keys) and dependency lock files (`go.sum`,
  `package-lock.json`, `yarn.lock`, `Cargo.lock`, ...) are excluded from
  entropy detection on purpose. Candidates must be at least 20 characters;
  the entropy floor is 3.75 bits per symbol for the generic alphabet and a
  length-scaled hex floor for single-case hex and UUID-shaped values, so
  32- and 40-character hex keys pass while digit-only strings never do.
- `assigned_sensitive_value` (`client_secret=`, `access_token=`, ...) is
  `high` confidence but ranks below the vendor-specific rules, so a value a
  specific detector recognises is reported once under that detector.
- Identifier-only detectors (`twilio_account_sid`, `sentry_dsn`) and
  shape-only ones (`password_hash`, `facebook_access_token`) report `medium`.
- `sensitive_file_*` path-only findings (a private key, keystore or
  credential store that could not be read as text) are `medium` (Java
  keystores `low`) and are never promoted above `medium`.

## Reporting a false positive or negative

Open a [bug report](https://github.com/Brumbelow/layerleak/issues/new?template=bug_report.yml)
with the `detector_name`, the `confidence` and `disposition_reason` you saw, a
synthetic reproduction of the input shape (never the real value; the issue
form repeats this) and the location shape (path segments, key name, source
type). Detector changes ship with corpus fixtures under
`internal/scanner/testdata/corpus` and the detector tests, so regressions are
caught.
