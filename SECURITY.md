# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public issues, pull
requests, or discussions.**

Instead, report privately through GitHub's
[private vulnerability reporting](https://github.com/MattJackson/busbarAI/security/advisories/new)
(the **Security** tab on the repository). Please include:

- A description of the issue and its potential impact.
- Steps to reproduce (proof-of-concept if available).
- Affected version / commit.
- Any suggested mitigation.

You can expect an acknowledgement within a few days. We'll work with you on a fix
and coordinate disclosure timing. We'll credit reporters who wish to be credited
once a fix is released.

## Scope

Busbar holds provider credentials centrally and acts as the front door to upstream
LLM providers. Issues of particular interest include:

- Credential leakage (logs, error bodies, `/stats`, responses relayed to clients).
- Authentication bypass on Busbar's own front-door auth.
- Request smuggling / routing confusion between pools, models, or providers.
- Denial of service against the gateway or its circuit breaker.
- The circuit breaker mis-attributing a client fault as an upstream fault (or vice
  versa) in a way that drains a pool or leaks state across requests.

## Supported versions

Busbar is at 1.0.0-rc.2 (release candidate). Security fixes are applied to the
latest `main` and the most recent tagged release. Pin to a tag for production use.
