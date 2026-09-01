# Security Policy

## Reporting a vulnerability

Please report security issues **privately**, not in public issues or pull
requests.

- Preferred: open a private report via GitHub Security Advisories —
  the **Security → Report a vulnerability** button on this repository
  (`https://github.com/jankesec/driftnet2/security/advisories/new`).
- Alternatively, you can reach out directly to `security@jankesec.com`.

Include enough detail to reproduce (affected version/commit, inputs, and impact).
You can expect an initial acknowledgement and, once triaged, coordinated
disclosure of a fix. Please do not disclose publicly until a fix is available.

## Supported versions

Driftnet2 is pre-1.x and moves fast; fixes land on `main` and the latest tagged
release. Please verify an issue against the latest `main` before reporting.

## Authorized-use policy

Driftnet2 captures network traffic and extracts credentials. It is provided for:

- authorized penetration testing and red-team engagements,
- defensive auditing of networks you own or operate, and
- security research and education.

Using it to intercept traffic without explicit authorization is illegal in most
jurisdictions and is **not** a supported use case. When reporting bugs, never
paste real captured credentials or personal data — use synthetic values (see
`examples/`).
