# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through either channel:

- Email **security@getbusbar.com**, or
- GitHub's [private vulnerability reporting](https://github.com/MattJackson/busbarAI/security/advisories/new)
  (the **Security** tab on the repository).

Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

We aim to **acknowledge your report within 48 hours**, work with you on a fix, and
coordinate disclosure timing. Confirmed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/MattJackson/busbarAI/security/advisories),
through which we request and issue **CVE** identifiers. We credit reporters who wish to be
credited once a fix is released.

## Scope

Busbar holds provider credentials centrally and acts as the front door to upstream
LLM providers. The [threat model](THREAT_MODEL.md) documents the trust boundaries,
assets, and the threats we design against (with pointers to each mitigation in code).
Issues of particular interest include:

- Credential leakage (logs, error bodies, `/stats`, responses relayed to clients).
- Authentication bypass on Busbar's own front-door auth (including timing-based).
- SSRF via a config-controlled upstream (`base_url` / `path` / `path_base` / `token_url`).
- AWS SigV4 outbound-signing correctness (signed-vs-sent divergence).
- Admin-plane isolation (reaching the control plane from the data port).
- Request smuggling / routing confusion between pools, models, or providers.
- Denial of service against the gateway or its circuit breaker.
- The circuit breaker mis-attributing a client fault as an upstream fault (or vice
  versa) in a way that drains a pool or leaks state across requests.

## Supported versions

Busbar is at 1.4.0 (stable). Security fixes are applied to the latest `main` and
the most recent tagged release. Pin to a tag for production use, and verify your
download with the recipes at <https://getbusbar.com/security/>.
