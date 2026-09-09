# Inherited alert review

This review covers the 149 open inherited code-scanning alerts on PR #137 at
`7d99f93f14f6bd86adfd5f0d4f94e09b5260a0cc`. Every alert has an individual entry
in [the disposition ledger](2026-09-09-inherited-alerts.csv), including its
original location, rationale, and source/test evidence.

| Disposition | Alerts |
| --- | ---: |
| Source fixes included in this PR | 8 |
| Accepted maintenance debt, dismissed as `won't fix` | 138 |
| False positives, dismissed as `false positive` | 3 |
| Total reviewed | 149 |

## Source fixes

- **1002, 1003:** Demo status updates use DOM text nodes and preserve the strong
  label. Fixture text is no longer interpreted as HTML.
- **1004, 1005:** Table and row lookups use Maps built from own JSON entries;
  missing names cannot resolve inherited object properties.
- **1207:** The required-element guard uses an explicit element list and
  `every(Boolean)`, retaining the same admission condition with lower complexity.
- **1214, 1289:** Summary output uses ordered scalar rows and a checked writer
  loop. Literal-output and writer-error tests preserve field order, optional
  rows, sanitization, target tables, spacing, and flushing.
- **1220:** INI value trimming maintains exact byte offsets after removing
  padding, including quoted and Unicode whitespace. Returned values agree with
  `line[start:end]`. The parser now also falls below the complexity threshold.

## Dismissal decisions

The 138 maintenance decisions accept real metrics rather than labeling them
incorrect. Runtime cases retain specific transaction, parser, budget, grammar,
or positional-field contracts. Test cases retain cohesive fixture matrices and
cross-step assertions. Each ledger row explains why that particular structure
is retained. This accepts maintenance debt; it does not establish that a routine
has no possible defects or replace a comprehensive security assessment.

The three false positives are:

- **1001:** The frame index is a private numeric counter initialized at zero and
  incremented internally, with a length check before scheduling the next frame.
  It is not an externally selected object-property name.
- **1345, 1346:** Stylelint reports unknown rule names. Stylelint 16.26.1 produces
  the same errors on a minimal valid stylesheet, confirming tool-configuration
  errors rather than stylesheet violations.

Dismissals are applied to the individual GitHub alerts with concise comments.
The ledger retains the complete rationales beyond the API comment-length limit.
No scanner threshold, whole-engine exclusion, or production limit is relaxed.

## Verification

- Full short Go tests, the short race suite, and vet pass on Go 1.25.13.
- Five real-browser tests exercise literal text, own-property boundaries, replay
  and tabs, load failure, and the checked-in synthetic fixture. Their requests
  are intercepted locally. The browser tests are included in reusable CI.
- Summary and INI regressions pass; the INI span cases failed before the fix.
- Lizard 1.23.0 confirms the fixed routines are below the reported thresholds:
  `renderSummary` is 15 noncomment lines with complexity 5; `parseINIKeyValue`
  has complexity 9; the demo outer function has complexity 3.
- Targeted ESLint checks leave only the individually reviewed numeric frame
  lookup. Narrow test-only annotations cover deliberate literal markup inputs
  and comparisons; production HTML-sink checking remains enabled.
- Documentation validation, script tests, workflow lint, and whitespace checks
  pass. Existing API fixtures remain unchanged.

The ledger records source fixes in the pull request. Those fixes reach the
default branch through the normal merge process; dismissal decisions take
effect independently of merging the code.
