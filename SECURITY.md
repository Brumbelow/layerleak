# Security Policy

Please report security issues responsibly.

- Open a GitHub issue for general security findings and lower-severity issues.
- If you believe the issue is high severity, contact `admin@brumbelow.org` directly.

When reporting, include:

- the affected component or command
- clear reproduction steps
- impact
- any relevant image reference, digest, or file path

Do not publish proof-of-concept details or active secrets before the issue has been reviewed.

## Coordinated disclosure

We aim to acknowledge new reports within 7 days and ship a fix or mitigation within 90 days of acknowledgement. If a report blocks on upstream work (for example, a fix in `github.com/trufflesecurity/trufflehog`), we will keep the reporter updated on progress and credit them in the release notes once the fix lands.

Please give us a reasonable window before public disclosure. If 90 days pass without a fix or status update from us, you are free to disclose.

## Supported versions

Only the latest tagged release on `main` receives security patches. Older `v1.x` tags are not patched in place; upgrade to the latest release to pick up fixes.

| Version    | Supported          |
| ---------- | ------------------ |
| latest tag | yes                |
| older tags | no — please upgrade |
