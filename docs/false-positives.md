# False positives and suppressions

> **Draft for 3.0.0.** The CLI contract items below (schema version 2, output
> files, exit codes, `--fail-on`, SARIF, detector renames) describe the planned
> 3.0.0 behaviour and are verified against the code in the documentation pass
> before the first release candidate.

Layerleak reports every match it finds and lets a policy layer label the ones
that are probably not live secrets. Nothing is dropped: a suppressed finding
still appears in the result with a `disposition` and a `disposition_reason`,
is counted separately (`suppressed_findings_count`), and is written to the
scan record and database so a reviewer can disagree with the policy.

## Dispositions

| `disposition` | Meaning | Affects exit code |
| --- | --- | --- |
| `actionable` | Looks like a real secret in a real location. | Yes (exit `2` at or above `--fail-on`) |
| `example` | Matched, but the location or value marks it as sample or test material. | No |

## Reasons

| `disposition_reason` | What triggered it |
| --- | --- |
| `test_path` | The file path has a strong test marker (`/test/`, `/tests/`, `/spec/`, `/e2e/`, `/mock/`, `/stubs/`, `_test.`, `.test.`). |
| `example_path` | The path has an example or fixture marker (`example`, `sample`, `fixture`, `demo`, `.template` is only a weak hint). |
| `placeholder_marker` | The value or its line carries a placeholder marker such as `changeme`, `your-`, `xxx`, `<redacted>`, `TODO`. |
| `reserved_host` | A URL credential points at a documentation or reserved host (`example.com`, `localhost`, link-local or test networks). |
| `known_dummy_value` | A well-known dummy value from vendor documentation (for example the AWS documentation keys). |
| `default_credentials` | A default `user:password` pair such as `admin:admin` or `root:password`; reported as suppressed rather than discarded so default credentials on production hosts stay visible. |

Markers are matched on path segments and whole tokens, not substrings, so a
real secret in `/app/config/testimonials.json` or a vendor path containing
`fake` is not suppressed.

## Tuning

- `--fail-on medium` or `--fail-on high` stops low-confidence entropy hits from
  failing a pipeline while still reporting them.
- `keyword_entropy` and `assigned_sensitive_value` are heuristics and carry
  `low` or `medium` confidence; vendor-prefixed detectors carry `high`.
- Content digests (`sha256:` prefixes, lock files) are excluded from entropy
  detection on purpose.
- A finding you have reviewed and accepted can be tracked by its
  `fingerprint`, which is stable across installs. A baseline file keyed on
  fingerprints is planned for 3.1.

## Reporting a false positive or negative

Open an issue with the detector name, a synthetic reproduction of the input
shape (never the real value), and the location shape. Detector changes ship
with corpus fixtures under `internal/scanner/testdata` so regressions are
caught.
