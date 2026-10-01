# Documentation

Reference material that does not fit the README.

| Document | What it covers |
| --- | --- |
| [architecture.md](architecture.md) | Binaries, the scan pipeline, and what every `internal/` package does. |
| [threat-model.md](threat-model.md) | Assets, adversaries, the bounds on every untrusted input, and what is deliberately left to the deployment. |
| [api-operations.md](api-operations.md) | Running `layerleak-api`: probes, shutdown sequence, logging, error classes to alert on. |
| [false-positives.md](false-positives.md) | How dispositions and suppression reasons work and how to tune them. |
| [plans/2026-09-30-v3-release-plan.md](plans/2026-09-30-v3-release-plan.md) | The 3.0.0 release plan: decisions, workstreams, verification and operator steps. |
| [plans/2026-09-30-v3-audit-findings.csv](plans/2026-09-30-v3-audit-findings.csv) | The audit ledger behind that plan, one row per finding. |
| [reviews/](reviews/) | Inherited code-scanning alert reviews. |
| [history/](history/) | Superseded planning records kept for the trail. |

Operator-facing guides live at the repository root: [README.md](../README.md)
(install, scan, configure, deploy), [UPGRADING.md](../UPGRADING.md) (moving
from v1 or v2 to 3.0.0), [SECURITY.md](../SECURITY.md) (reporting and release
verification), [RELEASING.md](../RELEASING.md) (the release procedure) and
[CONTRIBUTING.md](../CONTRIBUTING.md). The HTTP API contract is
`web/docs/openapi.yaml`, published with the documentation site.
