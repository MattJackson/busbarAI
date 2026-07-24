# Admin API v1: drive Busbar over HTTP

Everything Busbar knows about itself (its topology, its hooks, its auth posture, its live health, its keys, its limit groups, its metering) is readable and mutable over one authenticated, versioned HTTP surface: **`/api/v1/admin`**. Point `curl`, Terraform, a dashboard, or your own tooling at it and build against a contract that does not move.

---

## Authentication & scopes

Every `/api/v1/admin` request is authenticated by the **`admin_auth:` chain** (default `[admin-tokens]`, the single operator admin token). Present the credential as either header:

```
x-admin-token: <token>
Authorization: Bearer <token>
```

A missing or wrong credential is `401 unauthorized` (in the same JSON error envelope as every other admin error) on every endpoint. `admin_auth: []` is the explicit open dev posture (anonymous, full authority); external admin modules (SSO/AD) slot into the same chain at compile time. Admin requests deliberately bypass virtual-key governance: the operator credential manages keys, it is not one.

**Authorization is a scope lattice** — NOT a ladder — on the authenticated principal, derived from **method + path, never the request body** (a crafted body cannot escalate). The scopes form a diamond: `read-only` at the bottom, `full` at the top, and `hooks-register` + `mint` as two **incomparable siblings** in the middle:

| Scope | May | Notes |
|---|---|---|
| `read-only` | Every `GET`, **plus `POST /config/validate`** (a stateless dry-run: a read in POST clothing, so a read-only CI token can lint configs) | Satisfied by any grant |
| `hooks-register` | reads + hook-definition mutations (`POST`/`PUT`/`PATCH`/`DELETE` under `/api/v1/admin/hooks`) | **Sibling of `mint`**: cannot mint keys |
| `mint` | reads + **mint a key** (`POST /keys`, including auto-provisioning the leaf group on first mint) | **Sibling of `hooks-register`**: cannot register hooks. The delegated scope for a customer's self-service portal |
| `full` | everything else: keys (lifecycle), groups, config apply/reload/rollback, the admin auth chain, cache flush, overlay reset | Satisfies every requirement |

`hooks-register` and `mint` are SIBLINGS, not ladder rungs — the authorization check is an explicit lattice (`allows`), NOT `self >= needed`. A `mint` credential cannot register hooks, and a `hooks-register` credential cannot mint keys. A `max_admin_scope: mint` ceiling on a role never widens it into hook authority; both remain safe in either direction.

The operator admin token holds `full`. Role-carrying principals (external modules) get the most permissive `admin_scope` their roles bind to under `auth.role_bindings.<module>` (capped by the module's `max_admin_scope:`); unbound roles grant nothing. Insufficient scope is `403 forbidden` naming the scope that would have sufficed. Unknown HTTP methods fail closed to `full`.

One **body-derived refinement**: a `hooks-register` principal may define hooks but not wire them into a security-critical path. Registering, replacing, retuning, or deleting a hook that sees content or identity (`prompt`/`user` above `no`) or sets `global: true` requires `full`. A narrow automation token cannot reach caller content by the back door.

**Mutation rate limits.** Mutations are budgeted per principal in fixed one-minute windows, spent *before* the handler runs (failed attempts count, anti-enumeration):

| Class | Budget | Covers |
|---|---|---|
| config | 10/min | `POST /config/apply`, `/config/reload`, `/config/rollback`, and `PUT /admin-auth` (the blast-radius set) |
| CRUD | 60/min | every other mutation: hooks, keys, groups, cache flush, **and `/config/validate`** (a dry-run never contends with the config budget) |

Over-budget is `429 rate_limited` with a **`Retry-After: 60`** header, and the event is audited. Reads are unmetered.

## The error contract

Every `/api/v1/admin` error (including 401, 404 on an unmatched path, and 405 on a wrong method) is the same shape. Branch on `code` (frozen), never on `message` (human-facing, may change):

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
| `version_conflict` | 409 | **Retryable**: your `If-Match` is stale, re-read for a fresh ETag and retry |
| `conflict` | 409 | **Terminal**: the request contradicts server state in a way a retry cannot fix (governance disabled, base-defined hook or group, a group another group still parents on, immutable grant change, in-flight idempotency reservation, lockout guard) |
| `rate_limited` | 429 | The principal's per-minute mutation budget is spent (`Retry-After: 60`) |
| `internal` | 500 | An internal failure (details are logged server-side, never returned) |

The `version_conflict`/`conflict` split is deliberate: a client distinguishes retryable staleness from a terminal state conflict without ever string-matching the message.

## Pagination

Every list endpoint speaks one envelope: `{ "items": [...], "next_cursor": "..." }`. `next_cursor` is present iff more rows remain; round-trip it verbatim into `?cursor=`. It is **opaque** by contract (never parse it). A malformed or foreign cursor is a loud `400 invalid_request`, never a silent skip. `?limit=` bounds the page:

| List | Default limit | Cap |
|---|---|---|
| `GET /keys` | 200 | 1000 |
| `GET /audit` | 200 | 1000 |
| `GET /config/versions` | 100 | 1000 |

The topology reads (`/pools`, `/models`, `/providers`, `/hooks`, `/groups`, `/plugins`) return the same envelope in a single page (`next_cursor: null`).

## Concurrency: ETag + If-Match

Optimistic concurrency is **one mechanism across the whole surface**: the RFC-7232 `If-Match` header; there is no body-level `expected_version` twin:

- **Config plane** (hooks, groups, config, admin-auth): the ETag is the config version, quoted: `ETag: "42"`. It rides on `GET /hooks`, `GET /hooks/{name}`, `GET /groups`, `GET /groups/{name}`, `GET /config`, `GET /admin-auth`, and on **every successful config-plane mutation response** (including the `204` from a hook or group DELETE), so a scripted mutation chain never needs a re-read.
- **Keys**: each record's ETag is a 16-hex-char digest of its mutable metadata, returned in the `ETag` header of `GET /keys/{id}`. `PATCH` and `DELETE /keys/{id}` accept it.
- `If-Match: *` matches unconditionally (no guard); an absent header is also unguarded.
- A stale tag is `409 version_conflict` and nothing changes. A **malformed** `If-Match` is `400 invalid_request`. A broken guard never silently passes as "no guard".

Guarded mutations: `POST /hooks`, `PUT|DELETE /hooks/{name}`, `PATCH /hooks/{name}/settings`, `POST /groups`, `PUT|PATCH|DELETE /groups/{name}`, `PUT /admin-auth`, `POST /config/apply`, `POST /config/rollback`, `PATCH|DELETE /keys/{id}`. Deliberately unguarded: `validate` (stateless), `reload` (returns to disk truth unconditionally), `cache/flush`, key create/rotate (no versioned resource).

## Discovery

```
GET /api/v1/admin/openapi.json
```

The OpenAPI 3.1 schema of the whole surface: generate a client, or point tooling at it. Every path it lists resolves; its error-code enum matches the envelope above exactly; every operation is annotated with `x-busbar-required-scope` from the same matrix the middleware enforces (all three are test-locked). Browse it rendered, endpoint by endpoint, in the [API reference](https://getbusbar.com/docs/api/).

### Pinning a released schema

The live endpoint requires a booted, authenticated instance. So that tooling can consume the contract without one, every tagged release **attaches the schema as a release asset**: `busbar-openapi-<tag>.json` on the [GitHub Release](https://github.com/GetBusbar/busbar/releases). CI emits it in-repo from the same `openapi_doc()` the gateway serves (test-locked against drift), and its `info.version` is stamped from the binary's version, so each release's artifact is self-identifying. Downstream tooling can pin a client to an exact version and diff the API surface release-over-release without decompiling or running the gateway.

---

## What you can read

### Server & topology

| Endpoint | Returns |
|---|---|
| `GET /info` | `version`, `build` (the **compiled-in plugin proof**: `auth_modules`, `hook_plugins`, the always-true `weighted_floor`), `uptime_seconds`, `started_at` (epoch of process start, the boot-epoch marker: `config_version` resets on restart, so a changed `started_at` reads as "new epoch", never "reverted"), `topology` (pool/model/provider counts), `config_persistence` (whether API changes survive restart), `config_version` (monotonic, +1 per apply, drift detection) |
| `GET /pools` | Every pool with its member models and SWRR weights. **`?detail=true`** inlines each member's live status (the same row shape as `/pools/{name}`): the whole topology-with-health in one call |
| `GET /pools/{name}` | One pool's **live** per-member status: `usable` + `cooldown_remaining_seconds` (breaker), `available_concurrency`, `inflight`, `latency_ms` (EWMA), `ok`/`err` tallies, `dead`, and **`trip_count`** + `last_trip_at`, a monotonic Closed→Open trip counter, so alerting diffs the count instead of trying to catch a breaker episode live |
| `GET /models` | Every model lane and its upstream provider |
| `GET /providers` | Distinct providers and how many lanes route through each |

`GET /info` doubles as the **compliance-by-compilation proof**: `build.auth_modules`/`build.hook_plugins` reflect the actual binary. A build compiled with `--no-default-features` reports empty lists: a provable, not merely configured, smaller surface.

### Hooks & plugins

| Endpoint | Returns |
|---|---|
| `GET /hooks` | The hook registry: each hook's `kind` (tap/gate), transport, access grants (`prompt`/`user`), `priority`, `at` (tap stage), `on_error`, `timeout_ms`, `settings`, and whether it's globally wired |
| `GET /hooks/{name}` | One hook's definition |
| `GET /hooks/{name}/health` | Best-effort transport reachability (a short-timeout socket connect probe; `reachable` is `null` for webhooks/non-unix, with a `detail` note). Never fires the hook |
| `GET /hooks/{name}/schema` | The hook's **self-described settings schema** (the `describe` wire message, proxied verbatim; `{"name", "schema": null}` when the hook doesn't answer) |
| `GET /hooks/{name}/status` | The hook's **observed** state, live-queried over its transport: `{name, desired, reported, drift, metrics, as_of, source}`, the settings it is actually running + their version vs busbar's desired copy, with a **`drift`** verdict (a differing settings version, or a desired key missing/changed in the observed settings; extra self-managed keys are not drift). Self-reported metrics are validated and bounded. `reported`/`drift` are `null` when the hook doesn't answer (fail-open: the desired view still serves) |
| `GET /plugins?type=auth\|hooks\|store` | The plugin catalog for one type (required parameter). `auth`/`hooks`: compiled-in plugins (feature-gated, from the binary) and installed `kind:hook` plugin tarballs, each with manifest metadata and trust verdict (`trusted` / `unverified` / `rejected`). `store`: the compiled-in `memory` head plus every signed plugin tarball in `plugins.dir`, each with its manifest metadata (`name`, `version`, `publisher`, `interface_version`) and a re-evaluated trust verdict. MANIFEST-ONLY: listing never `dlopen`s anything, so an untrusted plugin's code cannot run from inspection |

No hook definition ever includes a secret, only the operator-configured transport target.

### Auth posture

| Endpoint | Returns |
|---|---|
| `GET /auth` | The ingress auth chain (module names) + the upstream-credential mode (`own`/`passthrough`) + whether the front door is open |
| `GET /admin-auth` | `{configured, modules}`: which modules guard the admin surface itself (the same resource `PUT /admin-auth` writes) |

Module names and modes only, never a token.

### Config, versions & audit

| Endpoint | Returns |
|---|---|
| `GET /config` | The effective running config as one redacted snapshot (`version`, auth, pools, models, providers, hooks, `global_hooks`) for drift detection. Carries the config-plane `ETag` |
| `GET /config/settings` | The current overlay root-section overrides — only the fields the operator has set via API; base `config.yaml` values for the rest. Shape: `{settings: {rate_card?, per_request_fee?, security?, limits?, observability?, advanced?, metrics?, health?, routing?, listen?, admin_listen?, tls?, admin_tls?, admin_insecure?, store?, …}}`. Read-only scope |
| `PUT /config/settings` | Set any subset of the single-value top-level config sections durably. Body: any subset of the root config object (`rate_card`, `per_request_fee`, `security`, `limits`, `observability`, `advanced`, `metrics`, `health`, `routing`, `listen`, `admin_listen`, `tls`, `admin_tls`, `admin_insecure`, `store`, …). Merged into the overlay, re-resolved, and swapped in. Returns `{settings, reload_to_apply}`. **Live (hot-applied, no restart):** `rate_card`, `per_request_fee`, `security`, `limits`, `observability`, `advanced`, `metrics`, `health`, `routing`. **Restart-to-apply (stored durably; takes effect on next restart):** `listen`, `admin_listen`, `tls`, `admin_tls`, `admin_insecure`, `store` — these are bound once at process start; the store is reused across hot reloads. `config.yaml` is never written; persistence is the busbar overlay (atomic temp+rename). Full scope |
| `GET /audit` | The admin audit log: every mutation *attempt* with its outcome (`applied`/`rejected`), newest first, attributed to the acting principal. Filters: `?action=hook.register`, `?resource=hook:x` (exact match). Paginated. No secrets |
| `GET /config/versions` | Version history metadata, newest first: `version`, `ts`, `principal`, `summary`. Paginated |
| `GET /config/versions/{v}` | One retained version with its full hook-surface snapshot: `{version, ts, principal, summary, hooks, global_hooks}`, hooks projected through the same wire shape as `/hooks`, so one parser covers both. `404` if pruned or never recorded |
| `GET /config/diff?from=&to=` | A structured diff between two retained versions: `{from, to, hooks: {added, removed, changed}}` + a `global_hooks: {from, to}` delta when the wiring changed. `400` for missing/non-numeric params; `404` names *which* version is missing |

### Metering: `GET /usage`

The fleet FinOps read. Design principle: busbar exposes the **raw inputs of cost**, not just its own number: every row carries the full token split (input / output / cache-read / cache-creation, each of which prices differently), so a consumer with its own negotiated price catalog reconstructs cost independently.

```json
{
  "window": { "start": 1782950400, "end": 1783036800 },
  "as_of": 1782998113,
  "total": { "tokens_input": 91240, "tokens_output": 30112, "tokens_cache_read": 402000,
             "tokens_cache_creation": 12050, "requests": 512, "spend_micros": 1834200 },
  "by_model": [ { "model": "smart", "provider": "anthropic", "tokens_input": 91240, "...": "..." } ],
  "by_key":   [ { "id": "vk_ab12cd34ef56ab78", "name": "ci", "tokens_input": 91240, "...": "..." } ],
  "by_key_truncated": false
}
```

- **One bucket, always.** A response is exactly one fixed UTC-day metering bucket (`window` is `[start, end)` epoch seconds). `?window=<bucket-start-epoch>` selects a past bucket (default: the current one); a value that isn't a bucket start, or is in the future, is `400`. Billing periods aggregate client-side from day buckets: raw counts are stored, so the math is exact.
- **The ledger rule:** `spend_micros` (MICRO-units of the abstract cost unit, integer math - busbar attaches **no currency**; the unit is whatever the operator priced the top-level `rate_card` in, and denomination/display is the consumer's concern) is a **mutable estimate** derived at read time per model from the *current* rate card plus the flat per-request fee (a rate correction re-prices history on the next read). Never store it as a ledger charge; **bill from the raw token split**. With no `rate_card` configured, the token component derives to 0 and only the flat fee contributes.
- `by_key` is capped at the top 1000 rows by spend; `by_key_truncated` says the cap fired, and `others` (present exactly then) carries the summed remainder, so `total == sum(by_key) + others` always holds. `by_model` is never capped. A deleted key's history keeps its `id` (`name` goes `null`).
- `as_of` marks read freshness (counters accumulate live). With no keys minted the aggregations are truthfully empty. Key ids/names only, never a token.

Per-key budget *enforcement* state lives on `GET /keys/{id}/usage`, not here.

---

## Keys

The virtual-key surface at `/api/v1/admin/keys` (`full` scope for mutations). Key metadata is `{id, name, allowed_pools, group, enabled, created_at, labels}` (`allowed_pools: null` = all pools, `[]` = none), never the secret or hash. Keys are PURE AUTH: every limit lives on the bound group.

| Endpoint | Does |
|---|---|
| `POST /keys` | Mint a key: `201`, body is the metadata plus the **signed token, returned exactly once**. Body: `{name, group?, parent?, allowed_pools?, labels?, expires_in\|expires_at?, issue_aws_credential?}` (default expiry 90d). `group` binds the key into the `groups:` limit chain. **Auto-provision**: when `group` names a leaf that does NOT yet exist and `parent` is an existing group, the leaf is created automatically (limits stamped from the nearest-ancestor `child_default`, inherit-only when none) and the key is bound to it — the first self-mint materializes a `user:<sub>` personal budget bucket live in the enforcement chain. If the group already exists, `parent` must match its actual parent (a `409` otherwise — a mint never re-homes an existing group). `allowed_pools` omitted = all pools, `[]` = none (the intent is stored verbatim); `labels` (`{"team": "growth"}`) are echoed onto the key's metric series, never interpreted by enforcement. `issue_aws_credential: true` also returns a once-shown `aws_access_key_id` + `aws_secret_access_key` for SigV4 clients. Requires **`mint`** scope (or `full`) |
| `GET /keys` | List metadata, id-sorted. Strict filters (`?enabled=true\|false`, `?prefix=vk_ab`, `?group=<name>`) where an unparseable value is a `400`, never a silently dropped filter. `?group=` is an exact bound-group match with **no existence check** against the registry: a key can reference a group the running config no longer has, and listing "keys of `g`" must still find them (that dangling state is exactly what an operator hunts). Cursor-paginated |
| `GET /keys/{id}` | One key's metadata + its `ETag` header (16 hex chars) |
| `PATCH /keys/{id}` | Adjust `enabled` and/or `group`. `group` is three-state: absent = unchanged, `null` = unbind (authed + unlimited), value = rebind to an existing group (mint-parity validated). The 1.4.x cap fields are rejected. Honors `If-Match` |
| `DELETE /keys/{id}` | Revoke: **`204 No Content`**; the key stops resolving immediately. Honors `If-Match`; `404` for an unknown id |
| `POST /keys/{id}/rotate` | Mint a **fresh secret in place**: `200`, same id (budgets, rate windows, usage history, audit attribution carry over), the old secret stops resolving immediately, the new secret is shown exactly once. An attached AWS credential is untouched |
| `GET /keys/{id}/usage` | The **attribution view**: `{id, budget_period: "total", window_start: 0, as_of, group, spend_cents, tokens, requests, rate_headroom}`, the key's all-time attribution counters (its limits, if any, live on the bound group's own windows). `spend_cents` is DERIVED at read time from the key bucket's token ledger x the current `rate_card` plus fee x requests (reprice-on-read; nothing dollar-shaped is stored). `rate_headroom`: the fraction `[0,1]` of the tightest `requests`/`tokens` limit across the group chain left in each limit's own window (`null` = no such limit), back off *before* tripping a 429 |

**Idempotency.** `POST /keys` and `POST /keys/{id}/rotate` accept an **`Idempotency-Key`** header: a retried request with the same key inside the ~10-minute window returns the first response verbatim (including the once-shown secret) instead of double-minting. The cache is scoped per principal (and per operation + key id for rotate), so no other admin's identical header value can replay your secret. A concurrent request while the first is still in flight is a terminal `409 conflict`.

**Anti-sprawl cap.** The optional `limits.max_keys_per_principal` config knob caps how many keys may be bound to one group (a group = one principal in the self-service model; a user leaf can only hold so many keys). An over-cap mint is a terminal `409 conflict`. Absent or `0` = unlimited (the default — today's behavior).

With no store/keys, one unambiguous rule: `GET /keys` answers `200` with an empty page (the keyspace is truthfully empty), single-resource reads answer `404 not_found` (also truthful), and writes answer with an actionable message.

---

## Groups

The `groups:` limit tree — where every limit lives (keys are pure auth) — is fully readable and mutable at runtime under `/api/v1/admin/groups`. Reads are `read-only` scope; every mutation is `full`. The read shape (`GroupView`) is `{name, parent?, enabled, limits, child_default?}`; each limit is projected **explicitly** as `{metric, amount, per?, pool?, on_exhaust?, downgrade_to?}` (`metric` ∈ `requests`|`tokens`|`budget`|`concurrent`; `per` absent only for `concurrent`; `pool` present only on a pool-scoped limit) — the config file's compact `{ budget: 3000, per: month }` form is write-side sugar, a consumer never has to know the metric is the map key. The **write** verbs accept a `GroupCfg` verbatim: paste a `groups:` block from config.yaml.

### Reading the tree

| Endpoint | Returns |
|---|---|
| `GET /groups` | Every group, name-sorted, single page. Carries the config-plane `ETag`, so a client reads then mutates without a second round-trip |
| `GET /groups/{name}` | One group definition (+ config-plane `ETag`); `404` for an unknown name |
| `GET /groups/{name}/usage` | The group's **derived** current-window usage, one row per enforcement bucket — each `(window, pool?)` its limits materialise: `{group, enabled, buckets: [{window, pool?, requests, tokens, spend_cents, requests_cap?, tokens_cap?, budget_cap?, budget_remaining_cents?}], as_of}`. Spend is repriced at read time from the token ledger × the *current* `rate_card` (nothing dollar-shaped is stored). `buckets` is empty for a group with only a `concurrent` limit (or none): there is no windowed ledger to read. The self-service dashboard read: a `user:<sub>` leaf's usage is one person's view |
| `GET /keys?group=<name>` | The keys bound to a group (see the keys table above): a leaf group's keys are one person's keys; a team group's are the team's |

### Mutating the tree

| Endpoint | Does |
|---|---|
| `POST /groups` | Create (or replace) a group at runtime. Body `{ "name": "...", "config": { "parent": ..., "enabled": ..., "limits": [...], "child_default": ... } }` — a config.yaml group block verbatim. **`201` when the name is new; `200` when it replaces an existing overlay group** (honest upsert; re-creating a deleted name clears its tombstone) |
| `PUT /groups/{name}` | Replace an existing **overlay** group, live. `404` for an unknown name (PUT replaces; POST creates) |
| `PATCH /groups/{name}` | **Partial** update: only the fields present change, the rest are preserved — the ergonomic "raise Alice's budget" (send just `limits`) and "freeze this team" (send `enabled: false`) verb. `limits`/`child_default` replace their whole list when present (a list can't be field-merged); to *clear* `parent` or `child_default`, use `PUT` with the full definition. A typo'd field is a `400`, never a silent no-op |
| `DELETE /groups/{name}` | Remove an overlay group, live. **`204`** (still carrying the new config ETag); `404` if unknown; terminal `409` if another group still names it as `parent` (re-parent or remove the children first — a delete never silently orphans them). The name is tombstoned in the overlay so the deletion survives restart |

**Validate-at-the-door.** Every write runs the mutated registry through the *same* `validate_groups` boot uses (parent exists, chain acyclic, pool qualifiers resolve, limit values sane): a bad group — dangling or cyclic parent, a `pool:` naming no pool — is a `400` that changes nothing. On success the enforcement projection is rebuilt atomically and the new limits are live for the next request; the usage **ledger survives the swap**, so past accrual is preserved across a limit change.

**Base groups are file-owned.** A group defined in config.yaml answers every mutation with a terminal `409 conflict`: the API cannot silently shadow operator file config (mirrors hooks). Edit config.yaml and reload instead.

All group mutations honor `If-Match` against the config-plane ETag, are audited (including rejections), recorded in version history, and overlay-persisted (set `BUSBAR_CONFIG_OVERLAY` to survive restart).

```bash
# Raise one group's limits without touching the rest of its definition
curl -s -X PATCH -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data '{"limits":[{"budget":500000,"per":"month"}]}' \
  http://localhost:8081/api/v1/admin/groups/growth

# How is the team tracking against its caps?
curl -s -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/groups/growth/usage
```

---

## Changing config over the API

Busbar's config plane is live: an authenticated write takes effect immediately, with no restart and without disturbing in-flight requests. Under the hood an apply atomically swaps the running config snapshot: new requests see the new config; requests already in flight finish on the old one; and surviving lanes keep their learned health (breakers, latency) **by identity**. Config-plane mutations are serialized internally, so concurrent writes can never silently lose one.

**Persistence (optional).** By default, API-applied changes are live but not written to disk. Set `BUSBAR_CONFIG_OVERLAY=/path/to/overlay.json` to persist hook- and group-surface changes: Busbar writes them to that busbar-owned overlay and re-applies it at boot on top of your hand-written `config.yaml` (which it never touches). A missing or corrupt overlay is ignored at boot: a bad overlay can never brick startup. `GET /info` reports `config_persistence` so tooling knows which mode it's in.

### The config plane

| Endpoint | Does |
|---|---|
| `POST /config/validate` | **Dry-run** a proposed config (body `{ "config": {...}, "providers": {...} }`, the `config.yaml` deploy block + `providers.yaml` defs) through the same resolve + validate Busbar runs at boot, applying nothing. A well-formed request is always `200` with the `{ "ok": bool, "errors": [...] }` verdict (an invalid *config* is `ok: false`, not an HTTP error); only a malformed *body* is `400`. Read-only scope: CI can lint |
| `POST /config/apply` | Apply a full config from the request body (validate's exact shape), atomically: invalid = `400`, nothing changes. Returns `{applied, config_version, note}` + the new ETag. Live until the next reload/restart returns to disk truth; persist by updating config.yaml |
| `POST /config/reload` | **Re-read config.yaml + providers.yaml from disk and apply atomically**, the boot pipeline at runtime, under normal admin auth (no second credential path). Returns `{reloaded, config_version}`. Invalid disk config is `400` and changes nothing; a busbar started without config files is `400`. The GitOps primitive: push config, call reload, no restart, no health amnesia |
| `POST /config/rollback` | Restore a retained version's hook surface. Body `{ "version": N }`; guard with `If-Match`. The target is **re-validated against current reality** before the swap (`400` if it no longer resolves); the result is a **new** version; history is append-only. Returns `{restored_version, config_version}`. `404` for a pruned/unknown target |
| `PUT /admin-auth` | **Replace the admin auth chain at runtime.** Body `{ "admin_auth": ["admin-tokens", ...] }`; unknown module names are `400` (a typo can never silently drop auth). Guarded against self-lockout: the calling request's own credentials are re-evaluated against the *new* chain, and unless they would still hold `full` scope the change is a terminal `409` that changes nothing. Response is the resource (`{configured, modules, applied, config_version, note}`). Live until the next reload/restart |
| `POST /auth/cache/flush` | **Instant revocation of the credential cache's allow window.** Body `{ "module": "name" }` flushes one auth module's partition; an empty body flushes everything. Returns `{flushed}` (entries dropped). The deny path never needs this; rejections are never cached |
| `DELETE /overlay/{section}` | **Revert one overlay section to base `config.yaml` truth** (`section` ∈ `groups` \| `hooks`). Discards ALL overlay mutations for that section — a `groups` reset restores the base limit tree, a `hooks` reset restores base hooks — while leaving the other section's runtime mutations untouched. `full` scope, `If-Match` optimistic concurrency, audited, versioned, and the cleared overlay is persisted (the revert survives restart). A section with no overlay state is an idempotent no-op (`changed: false`, ETag/version unchanged). An unknown section is `400`. An ephemeral busbar with no config files has nothing to revert to and returns `400` |

### Hooks lifecycle

| Endpoint | Does |
|---|---|
| `POST /hooks` | Register a hook at runtime. Body `{ "name": "...", "config": { "kind": "gate\|tap", "module": "webhook\|socket\|<kind:hook plugin name>", "settings": {...}, ... } }`. **`201` when the name is new; `200` when it replaces an existing overlay hook** (honest upsert). A `global: true` hook is live for the next request. Invalid definitions are `400` and change nothing; a base-config-defined name is a terminal `409` (the API never silently shadows file config) |
| `PUT /hooks/{name}` | Replace an existing **overlay** hook, live. `404` for an unknown name (PUT replaces; POST creates); terminal `409` for a base-defined hook or a grant change: `kind`/`prompt`/`user` are immutable (delete and re-register to change them) |
| `DELETE /hooks/{name}` | Remove an overlay hook, live. **`204`** (still carrying the new config ETag); `404` if unregistered; terminal `409` for a base-defined hook. The deletion is tombstoned in the overlay so it survives restart |
| `PATCH /hooks/{name}/settings` | Push an opaque settings map to the **running** hook and **commit on ack**: busbar sends the `configure` wire message (5s deadline) and only a version-echoing acknowledgment commits the change (audited, versioned, persisted). A nack/timeout commits nothing (`400` names the reason); if another mutation landed during the push, the commit is refused with `409`, retry. Socket hooks also receive committed settings as the first message on every (re)connection, so a restarted hook never runs blind |

All hook mutations honor `If-Match` against the config-plane ETag, are audited (including rejections: probing which names exist leaves a trail), recorded in version history, and overlay-persisted.

```bash
# Register a global compression gate — live immediately (using the webhook module)
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data '{"name":"compress","config":{"kind":"gate","module":"webhook","settings":{"url":"https://127.0.0.1:8900/"},"prompt":"rw","global":true}}' \
  http://localhost:8081/api/v1/admin/hooks

# Is it running what we pushed? (desired vs reported, with a drift verdict)
curl -s -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/hooks/compress/status

# Remove it
curl -s -X DELETE -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/hooks/compress
```

## Dynamic plugins: install, list, remove, reload

The admin API can push a signed plugin tarball into `plugins.dir` remotely, the same artifact you
would otherwise copy by hand (see [plugins.md](plugins.md)). Full scope, audited, and it CANNOT
bypass the trust model:

- The upload goes through the SAME gates as a boot-time load: in-memory structural validation
  (tarball shape, manifest completeness, `sha256` binding, `abi_version`), the SAME trust
  evaluation (embedded first-party key / `plugins.trust.publishers` / the explicit `allow_unsigned`
  and `allow_third_party` opt-ins / anti-downgrade floors), and a name/alias conflict check against
  the already-installed loadable set. An untrusted upload is a `409 conflict` naming the exact
  reason and flag; a malformed one is a `400`; nothing is written in either case.
- The endpoint is MANIFEST-ONLY: the uploaded code is never executed during install or listing.
  Loading only ever happens through the boot pipeline (restart / config apply), which re-runs the
  identical three-phase validation. Pushing over the API therefore grants nothing that dropping a
  file in the directory would not; both are inert until the trust gates pass at load.
- Admin-scoped and audited: every attempt (accept AND reject) lands in the hash-chained audit log
  as `plugin.install` / `plugin.remove` with the acting principal.

| Endpoint | Effect |
|---|---|
| `POST /plugins` | Install a signed plugin tarball. Body: `{"file": "<name>.tar.gz", "tarball_b64": "<base64 tarball>"}` (`file` is storage-only; identity comes from the signed manifest inside). `201 Created` with `{file, name, interface_version, trust, version, publisher, note}` |
| `DELETE /plugins/{file}` | Remove a tarball from `plugins.dir` (`204`; `404` if absent). A currently-loaded store keeps running on its loaded handle; removal affects the NEXT load (folder = source of truth) |
| `POST /plugins/reload` | **Live hot swap** (no restart): re-runs the fail-closed plugin pipeline from disk+overlay, rebuilds the registry and `kind: hook` transports, and old libraries drain then unmap. Fail-closed: a bad artifact leaves old plugins serving. Full scope, audited |
| `POST /plugins/rollback` | Explicit, audited, If-Match-guarded rollback. Body: `{"file": "<tarball-filename>"}`. Pins a prior version and lowers the anti-downgrade floor **only for this operator action** — automatic silent downgrade stays refused. Persists the version pin to the overlay. Full scope, audited |

```bash
# Install a signed store plugin tarball (takes effect on the next plugin (re)load)
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  -d "{\"file\": \"busbar-store-redis-1.5.0.tar.gz\",
       \"tarball_b64\": \"$(base64 < busbar-store-redis-1.5.0-x86_64-linux.tar.gz | tr -d '\n')\"}" \
  http://localhost:8081/api/v1/admin/plugins
# -> 201 {"file":"busbar-store-redis-1.5.0.tar.gz","name":"busbar-store-redis",
#         "interface_version":1,"trust":"trusted","version":"1.5.0","publisher":"busbar",
#         "note":"installed durably in the plugins directory; ..."}

# An UNSIGNED tarball against the strict default posture is refused, nothing written:
# -> 409 {"error":{"code":"conflict","message":"plugin rejected by the trust policy: manifest
#         carries no signature; refusing to load an unsigned plugin. Set
#         plugins.trust.allow_unsigned=true to permit unsigned plugins."}}

# Inspect the store-plugin catalog (manifest-only; never executes plugin code)
curl -s -H "x-admin-token: $TOK" 'http://localhost:8081/api/v1/admin/plugins?type=store'

# Remove it
curl -s -X DELETE -H "x-admin-token: $TOK" \
  http://localhost:8081/api/v1/admin/plugins/busbar-store-redis-1.5.0.tar.gz
```

## Example

```bash
# What am I running, and which plugins are compiled in?
curl -s -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/info

# The whole topology with live health, in one call
curl -s -H "x-admin-token: $TOK" 'http://localhost:8081/api/v1/admin/pools?detail=true'

# Preview a config change without applying it
curl -s -X POST -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data @proposed.json http://localhost:8081/api/v1/admin/config/validate

# Guarded apply: read the config ETag, then chain it
ETAG=$(curl -sI -H "x-admin-token: $TOK" http://localhost:8081/api/v1/admin/config | grep -i ^etag | cut -d' ' -f2)
curl -s -X POST -H "x-admin-token: $TOK" -H "If-Match: $ETAG" -H 'content-type: application/json' \
  --data @proposed.json http://localhost:8081/api/v1/admin/config/apply
```

---

## The freeze

**v1 is frozen, additive-only.** New fields may appear in any view; no field is ever removed or repurposed; no error `code` ever changes meaning; the scope matrix and the mount prefix are pinned by tests. A breaking change would ship as `/admin/v2/` alongside v1, never in place. Build against v1 and it keeps working.
