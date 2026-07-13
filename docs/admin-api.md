# Admin API v1: drive Busbar over HTTP

Everything Busbar knows about itself — its topology, its hooks, its auth posture, its live health, its usage — is readable over one authenticated, versioned HTTP surface: `/admin/v1/`. Point `curl`, Terraform, a dashboard, or your own tooling at it and build against a contract that does not move.

**v1 is frozen.** Once shipped, `/admin/v1/*` is additive-only forever: new fields may appear, but no field is ever removed or repurposed, and no error `code` ever changes meaning. A breaking change would be served as `/admin/v2/` alongside v1, never in place. Build against v1 and it keeps working.

---

## Authentication & scopes

Every `/admin` request is authenticated by the **`admin_auth:` chain** (default `[admin-tokens]` — the single operator admin token). Present the token as either header:

```
x-admin-token: <token>
Authorization: Bearer <token>
```

A missing or wrong credential is `401` on every endpoint — no admin read leaks without it. The admin token is configured under `governance.admin_token` (see [Configuration](https://getbusbar.com/docs/configuration/)). `admin_auth: []` is the explicit open dev posture; external admin modules (SSO/AD) slot into the same chain at compile time.

**Authorization is a scope ladder** on the authenticated principal — `read-only` ⊂ `hooks-register` ⊂ `full` — checked per endpoint, never derived from the request body:

| Scope | May |
|---|---|
| `read-only` | every `GET` |
| `hooks-register` | reads + hook-definition mutations (`POST`/`PUT`/`DELETE` under `/admin/v1/hooks`) |
| `full` | everything: keys, config rollback, cache — every other mutation |

The operator admin token holds `full`. Group-carrying principals (external modules) get the most permissive `admin_scope` their groups map to in `group_map:`; unmapped groups grant nothing. Insufficient scope is `403 forbidden` naming the scope that would have sufficed.

**Mutation rate limits.** Mutations are budgeted per principal in one-minute windows: config-plane mutations (rollback) at 10/min, everything else at 60/min. Failed attempts count (anti-enumeration). Over-budget is `429 rate_limited`, and the event is audited. Reads are unmetered.

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
| `conflict` | 409 | Optimistic-concurrency mismatch (a stale write), or an immutable property change |
| `rate_limited` | 429 | The principal's per-minute mutation budget is spent |
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
| `GET /admin/v1/info` | Busbar version, uptime, the **compiled-in plugin proof** (`auth_modules`, `hook_plugins`, and the always-present `weighted_floor`), a pool/model/provider count summary, `config_persistence` (whether API changes survive restart), and `config_version` (bumps on each apply — for drift detection) |
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
| `GET /admin/v1/config` | The effective running config as one snapshot (`version`, auth, pools, models, providers, hooks, global hooks) — for drift detection. Composed from the redacted reads above, so it carries no secret |
| `GET /admin/v1/audit` | The admin audit log — every config mutation with its outcome (`applied`/`rejected`), newest first, hash-chained for tamper evidence and **attributed to the acting principal**. No secrets |
| `GET /admin/v1/config/versions` | Config version history, newest first: `version`, timestamp, acting principal, and a one-line summary of the mutation that produced it |
| `GET /admin/v1/config/versions/{v}` | One retained version with its full hook-surface snapshot |
| `GET /admin/v1/config/diff?from=&to=` | A structured diff between two versions: hook names added/removed/changed + the global-wiring delta |
| `POST /admin/v1/config/validate` | **Dry-run** a proposed config (`config.yaml` deploy block + `providers.yaml` defs) through the same resolve + validate Busbar runs at boot, without applying anything. Returns `{ "ok": true }` or `{ "ok": false, "errors": [...] }`. A malformed request body is `invalid_request`; a valid request describing an invalid config is `200` with `ok: false` |

`config/validate` lets CI or your tooling preview a config change safely before rollout.

### Keys

The virtual-key management surface (mint, inspect, adjust, revoke) is served under the versioned prefix:

| Endpoint | Does |
|---|---|
| `GET /admin/v1/keys` | List keys (metadata only — never the secret or hash). Paginate with `?limit=&offset=` over the id-sorted set; `total` counts the filtered set |
| `GET /admin/v1/keys/{id}` | One key's metadata |
| `POST /admin/v1/keys` | Mint a key (the secret is returned exactly once, here) |
| `PATCH /admin/v1/keys/{id}` | Adjust budgets, rate limits, allowed pools, enabled |
| `DELETE /admin/v1/keys/{id}` | Revoke |
| `GET /admin/v1/keys/{id}/usage` | Current-window spend/tokens/requests |
| `POST /admin/v1/keys/{id}/rotate` | Mint a **fresh secret in place**: same id (budgets, rate windows, usage history, and audit attribution carry over), the old secret stops resolving immediately, the new secret is returned exactly once |

Mint (`POST /admin/v1/keys`) accepts an **`Idempotency-Key` header**: a retried request with the same key (~10 min window) returns the first response verbatim instead of double-creating. `GET /admin/v1/keys/{id}` returns an **`ETag`** (also an `etag` body field); `PATCH` accepts **`If-Match`** and rejects a stale tag with `409` before mutating — no lost updates.

> The unversioned `/admin/keys*` routes remain as a deprecated alias for back-compatibility. New tooling should use `/admin/v1/`.

---

## Changing config over the API

Busbar's config plane is live: an authenticated write takes effect immediately, with no restart and without disturbing in-flight requests. Under the hood an apply atomically swaps the running config snapshot — new requests see the new config; requests already in flight finish on the old one; and live reliability state (circuit breakers, latency) is preserved.

**Persistence (optional).** By default, API-applied changes are live but not written to disk — they are lost on restart. Set `BUSBAR_CONFIG_OVERLAY=/path/to/overlay.json` to persist them: Busbar writes API changes to that busbar-owned overlay file and re-applies it at the next boot on top of your hand-written `config.yaml` (which it never touches). Effective config = base `config.yaml` + overlay. A missing or corrupt overlay is ignored at boot (Busbar starts on the base config alone), so a bad overlay can never brick startup.

### Hooks

| Endpoint | Does |
|---|---|
| `POST /admin/v1/hooks` | Register (or replace) a hook at runtime. Body: `{ "name": "...", "config": { "kind": "gate\|tap", "webhook"\|"socket": "...", ... } }`. A `global: true` hook is live for the next request. Returns `201` with the hook definition. Invalid definitions (missing/both transports, `prompt: rw` on a `tap`) return `400 invalid_request` and change nothing |
| `PUT /admin/v1/hooks/{name}` | Replace an existing **overlay** hook definition, live. `404` for an unknown name (PUT replaces; POST creates); `409 conflict` for a base-config-defined hook (edit the file — the API never silently shadows it) or a grant change (`kind`/`prompt`/`user` are immutable; delete and re-register to change them) |
| `DELETE /admin/v1/hooks/{name}` | Remove a hook at runtime. `204` on success, `404 not_found` if unregistered |
| `POST /admin/v1/config/rollback` | Restore a retained version's hook surface. Body: `{ "version": N, "expected_version": M? }`. The target is **re-validated against current reality** before the swap; the result is a NEW version (history is append-only). `404` for a pruned/unknown target; `409` on a stale `expected_version` |
| `POST /admin/v1/config/reload` | **Re-read config.yaml + providers.yaml from disk and apply atomically** — the boot pipeline at runtime, under normal admin auth. Lane-set changes are fully live: surviving models keep their learned health (breakers, latency) **by identity**; new lanes start fresh; an invalid disk config is `400` and changes nothing. The GitOps primitive: push config, call reload, no restart |
| `POST /admin/v1/config/apply` | The body-carried twin of reload: `{ "config": {...}, "providers": {...}, "expected_version": N? }` (validate's exact shape). Same atomicity + health preservation. Applied config is **live until the next reload/restart** returns to disk truth — persist by updating config.yaml |
| `PUT /admin/v1/auth` | **Replace the admin auth chain at runtime.** Body: `{ "admin_auth": [...], "expected_version"? }`. Guarded against self-lockout: the calling request's own credentials are re-evaluated against the NEW chain, and unless they would still hold full scope the change is a `409` that changes nothing. Live until the next reload/restart — persist by updating config.yaml |
| `POST /admin/v1/auth/cache/flush` | **Instant revocation of the credential cache's allow window.** Body `{ "module": "name" }` flushes one auth module's partition; empty body flushes everything. (Invalid credentials are never cached, so the deny path never needs this) |
| `PATCH /admin/v1/hooks/{name}/settings` | Push an opaque settings map to the **running** hook and **commit on ack**: busbar sends the `configure` wire message (5s deadline) and only a version-echoing acknowledgment commits the change (audited, versioned, persisted). A hook that nacks/times out commits nothing (`400`). Socket hooks also receive committed settings as the first message on every (re)connection — a restarted hook never runs blind |
| `GET /admin/v1/hooks/{name}/schema` | The hook's **self-described settings schema** (the `describe` wire message, proxied verbatim; `schema: null` when the hook doesn't answer) |

`POST`/`PUT` hook mutations also accept `expected_version` (the current `config_version` you read) for optimistic concurrency — a stale write is `409 conflict`, never a lost update.

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
