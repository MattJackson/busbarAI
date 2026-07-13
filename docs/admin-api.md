# Admin API v1: drive Busbar over HTTP

Everything Busbar knows about itself — its topology, its hooks, its auth posture, its live health, its keys, its metering — is readable and mutable over one authenticated, versioned HTTP surface: **`/api/v1/admin`**. Point `curl`, Terraform, a dashboard, or your own tooling at it and build against a contract that does not move.

---

## Authentication & scopes

Every `/api/v1/admin` request is authenticated by the **`admin_auth:` chain** (default `[admin-tokens]` — the single operator admin token). Present the credential as either header:

```
x-admin-token: <token>
Authorization: Bearer <token>
```

A missing or wrong credential is `401 unauthorized` — in the same JSON error envelope as every other admin error — on every endpoint. `admin_auth: []` is the explicit open dev posture (anonymous, full authority); external admin modules (SSO/AD) slot into the same chain at compile time. Admin requests deliberately bypass virtual-key governance: the operator credential manages keys, it is not one.

**Authorization is a scope ladder** on the authenticated principal — `read-only` ⊂ `hooks-register` ⊂ `full` — derived from **method + path, never the request body** (a crafted body cannot escalate):

| Scope | May |
|---|---|
| `read-only` | Every `GET` — **plus `POST /config/validate`** (a stateless dry-run: a read in POST clothing, so a read-only CI token can lint configs) |
| `hooks-register` | reads + hook-definition mutations (`POST`/`PUT`/`PATCH`/`DELETE` under `/api/v1/admin/hooks`) |
| `full` | everything else: keys, config apply/reload/rollback, the admin auth chain, cache flush |

The operator admin token holds `full`. Group-carrying principals (external modules) get the most permissive `admin_scope` their groups map to in `group_map:` (capped by the module's `max_admin_scope:`); unmapped groups grant nothing. Insufficient scope is `403 forbidden` naming the scope that would have sufficed. Unknown HTTP methods fail closed to `full`.

One **body-derived refinement**: a `hooks-register` principal may define hooks but not wire them into a security-critical path. Registering, replacing, retuning, or deleting a hook that sees content or identity (`prompt`/`user` above `no`) or sets `global: true` requires `full` — a narrow automation token cannot reach caller content by the back door.

**Mutation rate limits.** Mutations are budgeted per principal in fixed one-minute windows, spent *before* the handler runs — failed attempts count (anti-enumeration):

| Class | Budget | Covers |
|---|---|---|
| config | 10/min | `POST /config/apply`, `/config/reload`, `/config/rollback`, and `PUT /admin-auth` (the blast-radius set) |
| CRUD | 60/min | every other mutation: hooks, keys, cache flush — **and `/config/validate`** (a dry-run never contends with the config budget) |

Over-budget is `429 rate_limited` with a **`Retry-After: 60`** header, and the event is audited. Reads are unmetered.

## The error contract

Every `/api/v1/admin` error — including 401, 404 on an unmatched path, and 405 on a wrong method — is the same shape. Branch on `code` (frozen), never on `message` (human-facing, may change):

```json
{ "error": { "code": "not_found", "message": "pool `west` not found" } }
```

| `code` | HTTP | Meaning |
|---|---|---|
| `not_found` | 404 | The named resource (or path) does not exist |
| `unauthorized` | 401 | No or invalid admin credential |
| `method_not_allowed` | 405 | The path exists, but not with this method |
| `forbidden` | 403 | Authenticated but under-scoped (the message names the sufficient scope) |
| `invalid_request` | 400 | Malformed body, bad parameter, malformed `If-Match`, or a foreign pagination cursor |
| `version_conflict` | 409 | **Retryable**: your `If-Match` is stale — re-read for a fresh ETag and retry |
| `conflict` | 409 | **Terminal**: the request contradicts server state in a way a retry cannot fix (governance disabled, base-defined hook, immutable grant change, in-flight idempotency reservation, lockout guard) |
| `rate_limited` | 429 | The principal's per-minute mutation budget is spent (`Retry-After: 60`) |
| `internal` | 500 | An internal failure (details are logged server-side, never returned) |

The `version_conflict`/`conflict` split is deliberate: a client distinguishes retryable staleness from a terminal state conflict without ever string-matching the message.

## Pagination

Every list endpoint speaks one envelope: `{ "items": [...], "next_cursor": "..." }`. `next_cursor` is present iff more rows remain; round-trip it verbatim into `?cursor=` — it is **opaque** by contract (never parse it). A malformed or foreign cursor is a loud `400 invalid_request`, never a silent skip. `?limit=` bounds the page:

| List | Default limit | Cap |
|---|---|---|
| `GET /keys` | 200 | 1000 |
| `GET /audit` | 200 | 1000 |
| `GET /config/versions` | 100 | 1000 |

The topology reads (`/pools`, `/models`, `/providers`, `/hooks`, `/plugins`) return the same envelope in a single page (`next_cursor: null`).

## Concurrency: ETag + If-Match

Optimistic concurrency is **one mechanism across the whole surface** — the RFC-7232 `If-Match` header; there is no body-level `expected_version` twin:

- **Config plane** (hooks, config, admin-auth): the ETag is the config version, quoted — `ETag: "42"`. It rides on `GET /hooks`, `GET /hooks/{name}`, `GET /config`, `GET /admin-auth`, and on **every successful config-plane mutation response** (including the `204` from a hook DELETE), so a scripted mutation chain never needs a re-read.
- **Keys**: each record's ETag is a 16-hex-char digest of its mutable metadata, returned in the `ETag` header of `GET /keys/{id}`. `PATCH` and `DELETE /keys/{id}` accept it.
- `If-Match: *` matches unconditionally (no guard); an absent header is also unguarded.
- A stale tag is `409 version_conflict` and nothing changes. A **malformed** `If-Match` is `400 invalid_request` — a broken guard never silently passes as "no guard".

Guarded mutations: `POST /hooks`, `PUT|DELETE /hooks/{name}`, `PATCH /hooks/{name}/settings`, `PUT /admin-auth`, `POST /config/apply`, `POST /config/rollback`, `PATCH|DELETE /keys/{id}`. Deliberately unguarded: `validate` (stateless), `reload` (returns to disk truth unconditionally), `cache/flush`, key create/rotate (no versioned resource).

## Discovery

```
GET /api/v1/admin/openapi.json
```

The OpenAPI 3.1 schema of the whole surface — generate a client, or point tooling at it. Every path it lists resolves; its error-code enum matches the envelope above exactly; every operation is annotated with `x-busbar-required-scope` from the same matrix the middleware enforces (all three are test-locked).

---

## What you can read

### Server & topology

| Endpoint | Returns |
|---|---|
| `GET /info` | `version`, `build` (the **compiled-in plugin proof**: `auth_modules`, `hook_plugins`, the always-true `weighted_floor`), `uptime_seconds`, `started_at` (epoch of process start — the boot-epoch marker: `config_version` resets on restart, so a changed `started_at` reads as "new epoch", never "reverted"), `topology` (pool/model/provider counts), `config_persistence` (whether API changes survive restart), `config_version` (monotonic, +1 per apply — drift detection) |
| `GET /pools` | Every pool with its member models and SWRR weights. **`?detail=true`** inlines each member's live status (the same row shape as `/pools/{name}`) — the whole topology-with-health in one call |
| `GET /pools/{name}` | One pool's **live** per-member status: `usable` + `cooldown_remaining_seconds` (breaker), `available_concurrency`, `inflight`, `latency_ms` (EWMA), `ok`/`err` tallies, `dead`, and **`trip_count`** + `last_trip_at` — a monotonic Closed→Open trip counter, so alerting diffs the count instead of trying to catch a breaker episode live |
| `GET /models` | Every model lane and its upstream provider |
| `GET /providers` | Distinct providers and how many lanes route through each |

`GET /info` doubles as the **compliance-by-compilation proof**: `build.auth_modules`/`build.hook_plugins` reflect the actual binary. A build compiled with `--no-default-features` reports empty lists — a provable, not merely configured, smaller surface.

### Hooks & plugins

| Endpoint | Returns |
|---|---|
| `GET /hooks` | The hook registry: each hook's `kind` (tap/gate), transport, access grants (`prompt`/`user`), `priority`, `at` (tap stage), `on_error`, `timeout_ms`, `settings`, and whether it's globally wired |
| `GET /hooks/{name}` | One hook's definition |
| `GET /hooks/{name}/health` | Best-effort transport reachability (a short-timeout socket connect probe; `reachable` is `null` for webhooks/non-unix, with a `detail` note). Never fires the hook |
| `GET /hooks/{name}/schema` | The hook's **self-described settings schema** (the `describe` wire message, proxied verbatim; `{"name", "schema": null}` when the hook doesn't answer) |
| `GET /hooks/{name}/status` | The hook's **observed** state, live-queried over its transport: `{name, desired, reported, drift, metrics, as_of, source}` — the settings it is actually running + their version vs busbar's desired copy, with a **`drift`** verdict (a differing settings version, or a desired key missing/changed in the observed settings; extra self-managed keys are not drift). Self-reported metrics are validated and bounded. `reported`/`drift` are `null` when the hook doesn't answer (fail-open — the desired view still serves) |
| `GET /plugins?type=auth\|hooks` | The plugin catalog for one type (required parameter): compiled-in plugins (feature-gated, from the binary) and external plugins (registered over socket/webhook) |

No hook definition ever includes a secret — only the operator-configured transport target.

### Auth posture

| Endpoint | Returns |
|---|---|
| `GET /auth` | The ingress auth chain (module names) + the upstream-credential mode (`own`/`passthrough`) + whether the front door is open |
| `GET /admin-auth` | `{configured, modules}` — which modules guard the admin surface itself (the same resource `PUT /admin-auth` writes) |

Module names and modes only — never a token.

### Config, versions & audit

| Endpoint | Returns |
|---|---|
| `GET /config` | The effective running config as one redacted snapshot — `version`, auth, pools, models, providers, hooks, `global_hooks` — for drift detection. Carries the config-plane `ETag` |
| `GET /audit` | The admin audit log — every mutation *attempt* with its outcome (`applied`/`rejected`), newest first, attributed to the acting principal. Filters: `?action=hook.register`, `?resource=hook:x` (exact match). Paginated. No secrets |
| `GET /config/versions` | Version history metadata, newest first: `version`, `ts`, `principal`, `summary`. Paginated |
| `GET /config/versions/{v}` | One retained version with its full hook-surface snapshot: `{version, ts, principal, summary, hooks, global_hooks}` — hooks projected through the same wire shape as `/hooks`, so one parser covers both. `404` if pruned or never recorded |
| `GET /config/diff?from=&to=` | A structured diff between two retained versions: `{from, to, hooks: {added, removed, changed}}` + a `global_hooks: {from, to}` delta when the wiring changed. `400` for missing/non-numeric params; `404` names *which* version is missing |

### Metering: `GET /usage`

The fleet FinOps read. Design principle: busbar exposes the **raw inputs of cost**, not just its own number — every row carries the full token split (input / output / cache-read / cache-creation, each of which prices differently), so a consumer with its own negotiated price catalog reconstructs cost independently.

```json
{
  "window": { "start": 1782950400, "end": 1783036800 },
  "as_of": 1782998113,
  "currency": "USD",
  "total": { "tokens_input": 91240, "tokens_output": 30112, "tokens_cache_read": 402000,
             "tokens_cache_creation": 12050, "requests": 512, "spend_micros": 1834200 },
  "by_model": [ { "model": "smart", "provider": "anthropic", "tokens_input": 91240, "...": "..." } ],
  "by_key":   [ { "id": "vk_ab12cd34ef56ab78", "name": "ci", "tokens_input": 91240, "...": "..." } ],
  "by_key_truncated": false
}
```

- **One bucket, always.** A response is exactly one fixed UTC-day metering bucket (`window` is `[start, end)` epoch seconds). `?window=<bucket-start-epoch>` selects a past bucket (default: the current one); a value that isn't a bucket start, or is in the future, is `400`. Billing periods aggregate client-side from day buckets — raw counts are stored, so the math is exact.
- **The ledger rule:** `spend_micros` (micro-USD, integer math) is a **mutable estimate** derived at read time from the operator's *current* configured prices — a price change re-prices history. Never store it as a ledger charge; **bill from the raw token split**.
- `by_key` is capped at the top 1000 rows by spend; `by_key_truncated` says the cap fired, and `others` (present exactly then) carries the summed remainder, so `total == sum(by_key) + others` always holds. `by_model` is never capped. A deleted key's history keeps its `id` (`name` goes `null`).
- `as_of` marks read freshness (counters accumulate live). With governance disabled the aggregations are truthfully empty. Key ids/names only — never a token.

Per-key budget *enforcement* state lives on `GET /keys/{id}/usage`, not here.

---

## Keys

The virtual-key surface at `/api/v1/admin/keys` (requires governance; `full` scope for mutations). Key metadata is `{id, name, allowed_pools, max_budget_cents, budget_period, rpm_limit, tpm_limit, enabled, created_at}` — never the secret or hash.

| Endpoint | Does |
|---|---|
| `POST /keys` | Mint a key — `201`, body is the metadata plus **`secret`, returned exactly once**. `budget_period` ∈ `total`\|`daily`\|`monthly` (default `total`); a negative budget or a zero rate cap is `400` at the door (not a silently dead key). `issue_aws_credential: true` also returns a once-shown `aws_access_key_id` + `aws_secret_access_key` for SigV4 clients |
| `GET /keys` | List metadata, id-sorted. Strict filters — `?enabled=true\|false`, `?prefix=vk_ab` — where an unparseable value is a `400`, never a silently dropped filter. Cursor-paginated |
| `GET /keys/{id}` | One key's metadata + its `ETag` header (16 hex chars) |
| `PATCH /keys/{id}` | Adjust `enabled`, `rpm_limit`, `tpm_limit`, `max_budget_cents`. The caps are three-state: absent = unchanged, `null` = clear to unlimited, value = set (create-parity validated). Honors `If-Match` |
| `DELETE /keys/{id}` | Revoke — **`204 No Content`**; the key stops resolving immediately. Honors `If-Match`; `404` for an unknown id |
| `POST /keys/{id}/rotate` | Mint a **fresh secret in place** — `200`: same id (budgets, rate windows, usage history, audit attribution carry over), the old secret stops resolving immediately, the new secret is shown exactly once. An attached AWS credential is untouched |
| `GET /keys/{id}/usage` | The **enforcement view**: `{id, budget_period, window_start, as_of, spend_cents, tokens, requests, rate_headroom}` — counters against the key's own budget window (labeled, so a consumer can align and reset-detect), plus `rate_headroom`: the fraction `[0,1]` of the tightest RPM/TPM cap left in the current 60s window (`null` = uncapped) — back off *before* tripping a 429 |

**Idempotency.** `POST /keys` and `POST /keys/{id}/rotate` accept an **`Idempotency-Key`** header: a retried request with the same key inside the ~10-minute window returns the first response verbatim — including the once-shown secret — instead of double-minting. The cache is scoped per principal (and per operation + key id for rotate), so no other admin's identical header value can replay your secret. A concurrent request while the first is still in flight is a terminal `409 conflict`.

**Governance off** — one unambiguous rule: `GET /keys` answers `200` with an empty page (the keyspace is truthfully empty), single-resource reads answer `404 not_found` (also truthful), and every write answers `409 conflict` with an actionable message (enable `governance:` in config.yaml).

---

## Changing config over the API

Busbar's config plane is live: an authenticated write takes effect immediately, with no restart and without disturbing in-flight requests. Under the hood an apply atomically swaps the running config snapshot — new requests see the new config; requests already in flight finish on the old one; and surviving lanes keep their learned health (breakers, latency) **by identity**. Config-plane mutations are serialized internally, so concurrent writes can never silently lose one.

**Persistence (optional).** By default, API-applied changes are live but not written to disk. Set `BUSBAR_CONFIG_OVERLAY=/path/to/overlay.json` to persist hook-surface changes: Busbar writes them to that busbar-owned overlay and re-applies it at boot on top of your hand-written `config.yaml` (which it never touches). A missing or corrupt overlay is ignored at boot — a bad overlay can never brick startup. `GET /info` reports `config_persistence` so tooling knows which mode it's in.

### The config plane

| Endpoint | Does |
|---|---|
| `POST /config/validate` | **Dry-run** a proposed config — body `{ "config": {...}, "providers": {...} }` (the `config.yaml` deploy block + `providers.yaml` defs) — through the same resolve + validate Busbar runs at boot, applying nothing. A well-formed request is always `200` with the `{ "ok": bool, "errors": [...] }` verdict (an invalid *config* is `ok: false`, not an HTTP error); only a malformed *body* is `400`. Read-only scope — CI can lint |
| `POST /config/apply` | Apply a full config from the request body (validate's exact shape), atomically: invalid = `400`, nothing changes. Returns `{applied, config_version, note}` + the new ETag. Live until the next reload/restart returns to disk truth — persist by updating config.yaml |
| `POST /config/reload` | **Re-read config.yaml + providers.yaml from disk and apply atomically** — the boot pipeline at runtime, under normal admin auth (no second credential path). Returns `{reloaded, config_version}`. Invalid disk config is `400` and changes nothing; a busbar started without config files is `400`. The GitOps primitive: push config, call reload, no restart, no health amnesia |
| `POST /config/rollback` | Restore a retained version's hook surface. Body `{ "version": N }`; guard with `If-Match`. The target is **re-validated against current reality** before the swap (`400` if it no longer resolves); the result is a **new** version — history is append-only. Returns `{restored_version, config_version}`. `404` for a pruned/unknown target |
| `PUT /admin-auth` | **Replace the admin auth chain at runtime.** Body `{ "admin_auth": ["admin-tokens", ...] }`; unknown module names are `400` (a typo can never silently drop auth). Guarded against self-lockout: the calling request's own credentials are re-evaluated against the *new* chain, and unless they would still hold `full` scope the change is a terminal `409` that changes nothing. Response is the resource (`{configured, modules, applied, config_version, note}`). Live until the next reload/restart |
| `POST /auth/cache/flush` | **Instant revocation of the credential cache's allow window.** Body `{ "module": "name" }` flushes one auth module's partition; an empty body flushes everything. Returns `{flushed}` (entries dropped). The deny path never needs this — rejections are never cached |

### Hooks lifecycle

| Endpoint | Does |
|---|---|
| `POST /hooks` | Register a hook at runtime. Body `{ "name": "...", "config": { "kind": "gate\|tap", "webhook"\|"socket": "...", ... } }`. **`201` when the name is new; `200` when it replaces an existing overlay hook** (honest upsert). A `global: true` hook is live for the next request. Invalid definitions are `400` and change nothing; a base-config-defined name is a terminal `409` (the API never silently shadows file config) |
| `PUT /hooks/{name}` | Replace an existing **overlay** hook, live. `404` for an unknown name (PUT replaces; POST creates); terminal `409` for a base-defined hook or a grant change — `kind`/`prompt`/`user` are immutable (delete and re-register to change them) |
| `DELETE /hooks/{name}` | Remove an overlay hook, live. **`204`** (still carrying the new config ETag); `404` if unregistered; terminal `409` for a base-defined hook. The deletion is tombstoned in the overlay so it survives restart |
| `PATCH /hooks/{name}/settings` | Push an opaque settings map to the **running** hook and **commit on ack**: busbar sends the `configure` wire message (5s deadline) and only a version-echoing acknowledgment commits the change (audited, versioned, persisted). A nack/timeout commits nothing (`400` names the reason); if another mutation landed during the push, the commit is refused with `409` — retry. Socket hooks also receive committed settings as the first message on every (re)connection, so a restarted hook never runs blind |

All hook mutations honor `If-Match` against the config-plane ETag, are audited (including rejections — probing which names exist leaves a trail), recorded in version history, and overlay-persisted.

```bash
# Register a global compression gate — live immediately
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data '{"name":"compress","config":{"kind":"gate","webhook":"http://127.0.0.1:8900/","prompt":"rw","global":true}}' \
  http://localhost:8080/api/v1/admin/hooks

# Is it running what we pushed? (desired vs reported, with a drift verdict)
curl -s -H "x-admin-token: $TOK" http://localhost:8080/api/v1/admin/hooks/compress/status

# Remove it
curl -s -X DELETE -H "x-admin-token: $TOK" http://localhost:8080/api/v1/admin/hooks/compress
```

## Example

```bash
# What am I running, and which plugins are compiled in?
curl -s -H "x-admin-token: $TOK" http://localhost:8080/api/v1/admin/info

# The whole topology with live health, in one call
curl -s -H "x-admin-token: $TOK" 'http://localhost:8080/api/v1/admin/pools?detail=true'

# Preview a config change without applying it
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data @proposed.json http://localhost:8080/api/v1/admin/config/validate

# Guarded apply: read the config ETag, then chain it
ETAG=$(curl -sI -H "x-admin-token: $TOK" http://localhost:8080/api/v1/admin/config | grep -i ^etag | cut -d' ' -f2)
curl -s -X POST -H "x-admin-token: $TOK" -H "If-Match: $ETAG" -H 'content-type: application/json' \
  --data @proposed.json http://localhost:8080/api/v1/admin/config/apply
```

---

## The freeze

**v1 is frozen, additive-only.** New fields may appear in any view; no field is ever removed or repurposed; no error `code` ever changes meaning; the scope matrix and the mount prefix are pinned by tests. A breaking change would ship as `/admin/v2/` alongside v1 — never in place. Build against v1 and it keeps working.
