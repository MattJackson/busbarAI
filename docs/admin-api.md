# Admin API v1: drive Busbar over HTTP

Everything Busbar knows about itself — its topology, its hooks, its auth posture, its live health, its usage — is readable over one authenticated, versioned HTTP surface: `/admin/v1/`. Point `curl`, Terraform, a dashboard, or your own tooling at it and build against a contract that does not move.

**v1 is frozen.** Once shipped, `/admin/v1/*` is additive-only forever: new fields may appear, but no field is ever removed or repurposed, and no error `code` ever changes meaning. A breaking change would be served as `/admin/v2/` alongside v1, never in place. Build against v1 and it keeps working.

---

## Authentication

Every `/admin` request is guarded by the admin token (the same one that has always guarded `/admin/keys`). Present it as either header:

```
x-admin-token: <token>
Authorization: Bearer <token>
```

A missing or wrong token is `401` on every endpoint — no admin read leaks without the credential. The admin token is configured under `governance.admin_token` (see [Configuration](https://getbusbar.com/docs/configuration/)).

## The error envelope

Every `/admin/v1` error is the same shape. Branch on `code` (stable), never on `message` (human-facing, may change):

```json
{ "error": { "code": "not_found", "message": "pool `west` not found" } }
```

| `code` | HTTP | Meaning |
|---|---|---|
| `not_found` | 404 | The named resource does not exist |
| `invalid_request` | 400 | The request is malformed or a parameter is invalid |
| `forbidden` | 403 | The credential lacks the scope for this endpoint |
| `conflict` | 409 | Optimistic-concurrency mismatch (a stale write) |
| `internal` | 500 | An internal failure (details are logged server-side, never returned) |

## Discovery

```
GET /admin/v1/openapi.json
```

Returns the OpenAPI 3.1 schema of the whole surface — generate a client, or point your tooling at it. The document IS the contract: every path it lists resolves, and its error-code enum matches the envelope above exactly (both are test-locked).

---

## What you can read

### Server & topology

| Endpoint | Returns |
|---|---|
| `GET /admin/v1/info` | Busbar version, uptime, the **compiled-in plugin proof** (`auth_modules`, `hook_plugins`, and the always-present `weighted_floor`), and a pool/model/provider count summary |
| `GET /admin/v1/pools` | Every pool with its member models and SWRR weights |
| `GET /admin/v1/pools/{name}` | One pool's **live** per-member status: usable + breaker cooldown, available concurrency, in-flight count, latency EWMA, and success/error tallies |
| `GET /admin/v1/models` | Every model lane and its upstream provider |
| `GET /admin/v1/providers` | Distinct providers and how many lanes route through each |

`GET /admin/v1/info` doubles as the **compliance-by-compilation proof**: `auth_modules`/`hook_plugins` reflect the actual binary. A build compiled with `--no-default-features` reports empty lists — a provable, not merely configured, smaller surface.

### Hooks & plugins

| Endpoint | Returns |
|---|---|
| `GET /admin/v1/hooks` | The hook registry: each hook's kind (tap/gate), transport, access grants (`prompt`/`user`), ordering, and whether it's globally wired |
| `GET /admin/v1/hooks/{name}` | One hook's definition |
| `GET /admin/v1/hooks/{name}/health` | Best-effort transport reachability (a short-timeout socket connect probe; webhooks are probed on demand at request time). Never fires the hook |
| `GET /admin/v1/plugins?type=auth\|hooks` | The plugin catalog for one type: compiled-in plugins (feature-gated, from the binary) and external plugins (registered over socket/webhook) |

No hook definition ever includes a secret — only the operator-configured transport target.

### Auth posture

| Endpoint | Returns |
|---|---|
| `GET /admin/v1/auth` | The ingress auth chain (module names) + the upstream-credential mode (`own`/`passthrough`) + whether the front door is open |
| `GET /admin/v1/admin-auth` | Which modules guard the admin surface itself |

Module names and modes only — never a token.

### Usage & config

| Endpoint | Returns |
|---|---|
| `GET /admin/v1/usage` | Fleet usage aggregation: spend/tokens/requests totals plus a per-key breakdown |
| `GET /admin/v1/config` | The effective running config as one snapshot (auth, pools, models, providers, hooks, global hooks) — for drift detection. Composed from the redacted reads above, so it carries no secret |
| `GET /admin/v1/audit` | The admin audit log — every config mutation with its outcome (`applied`/`rejected`), newest first: who changed what, when. No secrets |
| `POST /admin/v1/config/validate` | **Dry-run** a proposed config (`config.yaml` deploy block + `providers.yaml` defs) through the same resolve + validate Busbar runs at boot, without applying anything. Returns `{ "ok": true }` or `{ "ok": false, "errors": [...] }`. A malformed request body is `invalid_request`; a valid request describing an invalid config is `200` with `ok: false` |

`config/validate` lets CI or your tooling preview a config change safely before rollout.

### Keys

The virtual-key management surface (mint, inspect, adjust, revoke) is served under the versioned prefix:

| Endpoint | Does |
|---|---|
| `GET /admin/v1/keys` | List keys (metadata only — never the secret or hash) |
| `GET /admin/v1/keys/{id}` | One key's metadata |
| `POST /admin/v1/keys` | Mint a key (the secret is returned exactly once, here) |
| `PATCH /admin/v1/keys/{id}` | Adjust budgets, rate limits, allowed pools, enabled |
| `DELETE /admin/v1/keys/{id}` | Revoke |
| `GET /admin/v1/keys/{id}/usage` | Current-window spend/tokens/requests |

> The unversioned `/admin/keys*` routes remain as a deprecated alias for back-compatibility. New tooling should use `/admin/v1/`.

---

## Changing config over the API

Busbar's config plane is live: an authenticated write takes effect immediately, with no restart and without disturbing in-flight requests. Under the hood an apply atomically swaps the running config snapshot — new requests see the new config; requests already in flight finish on the old one; and live reliability state (circuit breakers, latency) is preserved.

### Hooks

| Endpoint | Does |
|---|---|
| `POST /admin/v1/hooks` | Register (or replace) a hook at runtime. Body: `{ "name": "...", "config": { "kind": "gate\|tap", "webhook"\|"socket": "...", ... } }`. A `global: true` hook is live for the next request. Returns `201` with the hook definition. Invalid definitions (missing/both transports, `prompt: rw` on a `tap`) return `400 invalid_request` and change nothing |
| `DELETE /admin/v1/hooks/{name}` | Remove a hook at runtime. `204` on success, `404 not_found` if unregistered |

```bash
# Register a global compression gate — live immediately
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data '{"name":"compress","config":{"kind":"gate","webhook":"http://127.0.0.1:8900/","prompt":"rw","global":true}}' \
  http://localhost:8080/admin/v1/hooks

# Remove it
curl -s -X DELETE -H "x-admin-token: $TOK" http://localhost:8080/admin/v1/hooks/compress
```

## Example

```bash
# What am I running, and which plugins are compiled in?
curl -s -H "x-admin-token: $TOK" http://localhost:8080/admin/v1/info

# Is pool `west` healthy right now?
curl -s -H "x-admin-token: $TOK" http://localhost:8080/admin/v1/pools/west

# Preview a config change without applying it
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data @proposed.json http://localhost:8080/admin/v1/config/validate
```

---

*The admin surface is the read + discovery + observability foundation of the Busbar API. Configuration mutation over the API (apply, rollback, hook registration) builds on this same versioned, frozen contract.*
