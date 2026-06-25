# Reliability guide

How Busbar routes requests across providers, how the circuit breaker protects you from upstream failures, how in-flight failover works, and how governance/limits keep spending under control. This guide is operator-focused: configuration choices, their tradeoffs, and how to read the signals that tell you what is happening.

Cross-references: [configuration.md](configuration.md) (full field reference) · [operations.md](operations.md) (process config, troubleshooting) · [internals.md](internals.md) (design deep-dive).

---

## Table of contents

- [Concepts: pools, lanes, and cells](#concepts-pools-lanes-and-cells)
- [Weighted pools and SWRR selection](#weighted-pools-and-swrr-selection)
- [Circuit breaker](#circuit-breaker)
  - [What is per-pool vs lane-global](#what-is-per-pool-vs-lane-global)
  - [Disposition pipeline: how failures are classified](#disposition-pipeline-how-failures-are-classified)
  - [Breaker state machine](#breaker-state-machine)
  - [Trip conditions](#trip-conditions)
  - [Cooldown and backoff](#cooldown-and-backoff)
  - [Hard-down vs transient](#hard-down-vs-transient)
  - [Configuration reference](#circuit-breaker-configuration)
- [In-flight failover](#in-flight-failover)
  - [The first-byte boundary](#the-first-byte-boundary)
  - [Failover budget and exclusions](#failover-budget-and-exclusions)
  - [Context-length failover](#context-length-failover)
  - [Session affinity](#session-affinity)
  - [Pool exhaustion](#pool-exhaustion)
- [Active health probing](#active-health-probing)
- [Governance and limits](#governance-and-limits)
  - [Enabling governance](#enabling-governance)
  - [Virtual keys](#virtual-keys)
  - [Admin API](#admin-api)
  - [Enforcement model and precision](#enforcement-model-and-precision)
- [Health, metrics, and observability endpoints](#health-metrics-and-observability-endpoints)
  - [/healthz](#healthz)
  - [/stats](#stats)
  - [/metrics](#metrics)
  - [Metrics to watch](#metrics-to-watch)
- [End-to-end worked example](#end-to-end-worked-example)

---

## Concepts: pools, lanes, and cells

Three terms underpin everything else.

**Lane** — one model on one provider. A lane has a concurrency semaphore (`max_concurrent`), an optional lifetime budget (`max_requests`), and health state. A lane is declared with a `models:` entry and backed by exactly one provider.

**Pool** — a named, weighted set of member lanes. Pools are optional; you can route to a model directly. A request routed to a pool is dispatched to one member at a time, with automatic failover if the chosen member is unhealthy or fails.

**Breaker cell** — the circuit-breaker state (Closed / Open / HalfOpen, failure streak, cooldown, error window) for a specific (pool, lane) pair. A lane that is a member of three pools carries three independent breaker cells. One pool's failures cannot trip the same lane in another pool.

The split matters for operator decisions:

| Concern | Scope | Implication |
|---|---|---|
| Concurrency cap (`max_concurrent`) | Lane-global | Aggregated across every pool the lane belongs to. |
| Lifetime budget (`max_requests`) | Lane-global | A budget-exhausted lane is unusable everywhere. |
| Breaker FSM (Open/Closed/HalfOpen) | Per (pool, lane) | A tripped lane in pool A remains eligible in pool B. |
| SWRR weight tracking | Per pool | Each pool does its own smooth weighted round-robin. |

Direct routes (`POST /<model>/v1/messages`) and the ad-hoc route (`POST /<provider>/<model>/v1/messages`) use a special lane-default breaker cell (pool name `""`), shared only among direct callers and `/stats`. An active health probe that succeeds clears the breaker in **all** cells for that lane simultaneously.

---

## Weighted pools and SWRR selection

```yaml
pools:
  balanced:
    members:
      - target: claude-sonnet
        weight: 8        # ~80% of requests
      - target: gpt-4o
        weight: 2        # ~20% of requests
```

Member selection uses **smooth weighted round-robin (SWRR)** — the same scheme Nginx uses for upstream balancing. Across a sequence of requests each member receives traffic proportional to its weight, with no burst: a weight-8/weight-2 pool sends `claude-sonnet` eight times for every two to `gpt-4o`, spread evenly rather than in blocks.

When a member is tripped or at-capacity, it is dropped from the eligible set and its share is spread proportionally across the remaining healthy members. The SWRR state is maintained per-pool in 64 shards (keyed by pool name), so disjoint pools select independently and in parallel without contention.

Weights must be ≥ 1. A pool with equal-weight members distributes traffic evenly. The pool itself has no weight field — weights are only between members within one pool.

**Multi-protocol pools** — members can span different providers and protocols. Busbar translates through its superset IR on cross-protocol hops (see [internals.md](internals.md)). A warning is logged at startup for heterogeneous pools because the IR models a common superset: same-protocol requests are byte-exact passthrough, but cross-protocol hops drop source-only fields that have no analog on the target (e.g. `logprobs`, `n`). For pools where all members speak the same protocol, there is no translation overhead and no field loss.

---

## Circuit breaker

### What is per-pool vs lane-global

As described above, the breaker FSM — state, streak, cooldown, error window — is stored per (pool, lane) in a `BreakerCell`. A lane can be Open in one pool and Closed in another simultaneously.

What is **not** per-pool: the lane's concurrency semaphore and its lifetime budget. Those govern the shared upstream service and apply across all pools the lane belongs to.

### Disposition pipeline: how failures are classified

Before the breaker records anything, every upstream outcome runs through a two-stage classification pipeline.

**Stage 1 — protocol normalization.** The per-protocol reader extracts a raw error signal: HTTP status, provider JSON error code (if any), and a `Retry-After` value (if the upstream sent one).

**Stage 2 — `classify` → Disposition.** The raw signal is mapped to one of these outcomes, using the lane's configured `error_map` (provider JSON codes → disposition) first, then HTTP-status fallback:

| Disposition | What triggers it | What the breaker does |
|---|---|---|
| `TransientUpstream` | 5xx, 429, 408, 529, network error, timeout | Records a failure; drives trip evaluation. |
| `HardDown` | 401, 403 (auth/billing); JSON codes mapped to `auth` or `billing` | Trips the lane immediately, regardless of window/streak, with a 30-minute sticky cooldown. |
| `ClientFault` | 4xx other than 401/403/408/429 | Relayed verbatim; lane records nothing (the request was bad, not the upstream). |
| `ContextLength` | Provider signals context-length exceeded, on 400/413 only | No lane penalty; request fails over to a larger-context member (see [below](#context-length-failover)). |

One important guard: a `context_length` mapping in `error_map` is **suppressed on any 5xx**, so a provider returning 500 with a body that mentions `context_length` is still classified as `TransientUpstream`. This prevents a misconfigured or adversarial backend from masking an outage as a context-limit.

### Breaker state machine

```
         ┌──── trip condition met ────────────────────────────────────────────────┐
         │                                                                        ▼
       Closed ◀── probe succeeds ── HalfOpen ◀── cooldown expires ──── Open
                                        │
                                        └── probe fails ──▶ Open (escalated cooldown)
```

**Closed** — the lane is healthy and receives traffic. Failures are recorded against the window/streak. A single failure that does not meet the trip condition arms a brief cooldown on the cell (the lane is temporarily deprioritized) but the breaker stays Closed.

**Open** — the lane is tripped and skipped during member selection until its cooldown expires. Requests to this pool during this period are either failed over to another member or handled by the pool's `on_exhausted` policy.

**HalfOpen** — when the cooldown expires, the next selection attempt transitions the cell to HalfOpen via a compare-and-swap. Exactly one request is admitted as the recovery probe (single-flight — no thundering herd). `/healthz`, `/stats`, and SWRR selection reads are side-effect-free: they never consume the probe slot. If the probe succeeds, the lane recovers to Closed (streak and error window cleared). If it fails, the lane returns to Open with an escalated cooldown.

### Trip conditions

Configure per pool with `breaker.trip`:

**`error_rate`** (default) — trips when the fraction of failures in the sliding `window_secs` reaches `threshold`, provided at least `min_requests` outcomes have accrued. Both numerator (errors) and denominator (total) come from the same window, so a burst of successes after a burst of failures can bring the rate below threshold before the window expires.

```yaml
breaker:
  trip:
    mode: error_rate
    window_secs: 30
    threshold: 0.5      # trip at 50% error rate
    min_requests: 5     # never trip on fewer than 5 in-window outcomes
```

**`consecutive`** — trips after `consecutive_n` consecutive failures, regardless of interspersed successes in the wider window. More aggressive; a good choice for a pool whose members are either fully up or fully down (batch APIs, fine-tuned models with narrow failure modes).

```yaml
breaker:
  trip:
    mode: consecutive
    consecutive_n: 3
```

Choose `error_rate` when you want the breaker to absorb a few errors without tripping (normal flakiness tolerance). Choose `consecutive` when a single sustained failure streak indicates the backend is down and you want fast failover with no "maybe it'll recover" window.

### Cooldown and backoff

Cooldown grows exponentially with the consecutive failure streak:

```
cooldown = min(base_cooldown_secs × 2^streak, max_cooldown_secs) ± 10% jitter
```

Jitter is seeded by a hash of the current time, the cell's memory address, and the streak — so simultaneously tripped lanes desynchronize their recovery probes rather than flooding a recovering backend together.

The minimum effective cooldown is 1 second regardless of the computed value.

A server `Retry-After` header is always honored as a **floor**. If the upstream says to wait 90 seconds but your `max_cooldown_secs` is 60, the lane stays Open for 90 seconds. The floor is hard-capped at 24 hours to prevent overflow on malformed headers.

There is no configuration knob to disable `Retry-After` honoring — it is always on.

Default cooldowns (no `breaker:` block, or block present with fields omitted): `base_cooldown_secs: 15`, `max_cooldown_secs: 120`.

### Hard-down vs transient

**Transient** faults (5xx / timeout / rate-limit / overload / network) contribute to the trip window/streak. If the trip condition is met, the lane opens with an exponential cooldown. It will self-recover via the HalfOpen probe.

**Hard-down** faults (auth or billing, either by HTTP status 401/403 or by a matching `error_map` entry) trip the lane immediately — bypassing the window/streak entirely — with a **30-minute sticky cooldown** (`HARD_DOWN_COOLDOWN_SECS = 1800`). The distinction in behavior:

- An `auth` hard-down relays the `401`/`403` to the caller (it was the caller's key, or Busbar's configured key is wrong). The lane is benched in this pool's cell.
- A `billing` hard-down fails the request over to another pool member (or exhausts the pool). The error is not relayed — the caller sees a failover, not a billing error.

A hard-down lane is still recoverable: a successful active health probe (or the organic half-open probe on cooldown expiry) brings it back. It is **not** the same as the permanent `dead` flag, which only a restart clears.

If a lane shows `dead` in `/stats` with `dead_reason: auth`, the provider credential (`api_key_env`) is wrong or expired. Fix the credential and restart. If it shows `dead_reason: billing`, the upstream wallet is empty; fund it and Busbar will recover on the next successful probe.

### Circuit breaker configuration

Full reference — all fields optional, values shown are defaults:

```yaml
pools:
  my-pool:
    members:
      - target: my-model
    breaker:
      base_cooldown_secs: 15    # first cooldown after a trip
      max_cooldown_secs: 120    # ceiling for exponential backoff
      trip:
        mode: error_rate        # or: consecutive
        window_secs: 30         # sliding window for error_rate
        threshold: 0.5          # error fraction to trip (error_rate)
        min_requests: 5         # never trip below this many in-window outcomes
        consecutive_n: 3        # consecutive failures to trip (consecutive mode)
```

Omitting the `breaker:` block entirely is equivalent to specifying all the above defaults. There is no inheritance between pools; each pool's breaker is independent.

---

## In-flight failover

### The first-byte boundary

Failover is bounded by when the upstream starts streaming a response body to the client. Before the first upstream byte reaches the client, any transport or pre-response failure (connect error, timeout waiting for headers, transient upstream response) transparently fails over to another pool member. From the client's perspective, the request is still in flight.

**This pre-first-byte window covers the bulk of real provider failures** — connect errors and timeouts, `429` rate-limit responses, and `5xx` errors returned on the response headers all arrive *before* any body byte, so they fail over transparently. A failure only becomes unrecoverable once the upstream has already streamed a byte to the client and *then* dies mid-generation.

**Why mid-stream failover is impossible — for every gateway, not just Busbar.** A streaming response is a stateful continuation. Once a byte has been sent, you cannot un-send it: the client has already rendered those tokens. A replacement provider cannot *resume* the first provider's half-finished generation either — it would start a brand-new completion from the prompt, so splicing its fresh output onto the partial stream produces duplicated or contradictory text. The only alternatives are to resend the whole response (the client sees tokens twice) or abandon the partial — neither is transparent. This is a property of streaming itself, so no transparent gateway (LiteLLM and OpenRouter included) does mid-stream failover; it is physics, not a missing feature.

**The one real lever — a configurable pre-release buffer (planned, v1.x).** Busbar can hold the first *K* tokens / *T* ms of the upstream stream before releasing any byte to the client; if the provider dies inside that window, nothing has been sent yet, so Busbar can still reroute. The trade-off is up to *T* ms of added TTFT, so it is opt-in per pool and defaults to off (today's pure pre-first-byte behavior). It widens the failover window — it does not claim the impossible mid-stream splice above.

**After the first byte**: failover is impossible (per the reasoning above). The client already holds a partial response body. If the upstream then fails mid-stream:
- For SSE responses (OpenAI, Anthropic, Gemini, Cohere, Responses ingress): Busbar emits an SSE `error` event to the client and closes the connection. The lane records the failure, which may trip its breaker.
- For non-SSE responses: the body stream terminates.

In both cases the client must detect the incomplete response and retry. The breaker will have recorded the failure, so a subsequent retry to the same pool is likely to be routed to a different member.

The practical implication: for workloads where mid-stream failure recovery matters, keep responses short or use non-streaming calls where the full response is buffered before delivery. For long streaming responses, implement client-side retry with session affinity disabled on retry (or send the retry to a different pool).

### Failover budget and exclusions

Each request carries a per-request failover budget: a wall-clock deadline and a hop count cap. Both are configured per pool:

```yaml
pools:
  resilient:
    members:
      - target: primary-model
        weight: 3
      - target: fallback-model
        weight: 1
      - target: last-resort-model
        weight: 1
    failover:
      timeout_secs: 30     # wall-clock budget across all hops; default 120
      max_hops: 3          # max hop count; default 3
      exclusions:
        - last-resort-model    # never selected as primary or failover
```

`exclusions` is a per-pool member blocklist. A model listed in `exclusions` is never selected — not as the initial pick and not as a failover destination. Use it to keep a member in the pool (so it appears in `/stats` and can be targeted directly) without it ever being auto-selected. Each `exclusions` entry must name a member of this pool. A member not in the pool at all is a simpler case; `exclusions` is for members you want visible but never auto-dispatched.

Already-tried lanes are accumulated in an `excluded` set across hops for the lifetime of the request. A lane that succeeded (2xx headers) but whose body then failed before the first byte is refunded its `max_requests` budget spend and is also excluded from further hops on that request.

### Context-length failover

When a request is too large for a member (the provider returns a context-length error), Busbar does not penalize the lane — it was healthy, the request simply did not fit. Instead, it excludes from this request's candidate set any member whose declared `context_max` is ≤ the failed lane's, then retries to a larger (or unknown-context) member.

```yaml
pools:
  long-context:
    members:
      - target: claude-haiku
        context_max: 200000
      - target: gemini-2.5-flash
        context_max: 1048576
```

A member with no `context_max` set is never excluded on context-length grounds — it is always a candidate, and if it also rejects the request as too long, a normal transient/hard-down classification applies.

Context-length failover is suppressed on 5xx responses, even if the body mentions a context-length-related code, to prevent a broken backend from dodging normal breaker penalties.

### Session affinity

Pin a session to one member while it remains healthy:

```yaml
pools:
  smart:
    members:
      - target: claude-sonnet
      - target: gpt-4o
    affinity:
      mode: session
      header_name: x-session-id    # default
```

When a request carries `x-session-id: <value>`, Busbar pins that session to a specific member. If the pinned member is unavailable (tripped, at-capacity, or excluded), affinity is ignored and normal SWRR selection runs — affinity is a preference, not a guarantee. The client receives no signal that the pin was broken.

`session` is the only supported `mode`. `header_name` defaults to `x-session-id`.

### Pool exhaustion

When all candidates are unavailable — tripped, excluded, or at-capacity — the pool is exhausted. The `on_exhausted` action decides what happens:

```yaml
pools:
  primary:
    members:
      - target: fast-model
      - target: fallback-model
    on_exhausted:
      action: fallback_pool:overflow    # try another pool

  overflow:
    members:
      - target: cheap-model
    on_exhausted:
      action: least_bad    # degraded but not a hard error
```

| `action` | Behavior |
|---|---|
| `reject` / `status_503` / `503` | Return `503` with `Retry-After` set to the soonest member's cooldown expiry. (Default when `on_exhausted` is omitted.) |
| `least_bad` | Select the member whose cooldown expires soonest and send the request anyway, even though its breaker is Open. Logs a loud degraded-service warning. |
| `fallback_pool:<name>` | Route to another named pool. Loop-guarded: if the fallback pool itself is exhausted and also falls back, cycles are detected and broken. |

(The parser also accepts the spellings `status503` for reject and `least-bad` / `leastbad` for least-bad.)

A `503` from pool exhaustion sets `Retry-After` so clients and upstream proxies know how long to back off. The `/metrics` counter `busbar_requests_total{outcome="exhausted"}` tracks these. A rising exhausted rate combined with a falling `busbar_upstream_attempts_total` for the pool's lanes indicates breakers are tripping faster than they recover — check `busbar_breaker_trips_total` and `/stats` for individual lane state.

Multi-hop fallback chains — `primary → overflow → emergency` — work as long as they form a DAG (no cycles back to a visited pool). A self-referential or cyclic chain is rejected at config validation; a runtime loop is caught by the loop guard and results in a 503.

---

## Active health probing

By default, Busbar learns a lane is healthy or sick entirely from real traffic outcomes (passive health). Active probing adds a background task that sends periodic probe requests to check lanes independently of organic traffic.

Configure per provider in `config.yaml`:

```yaml
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
    health:
      mode: dead           # or: active, none
      interval_secs: 30    # default
      timeout_secs: 5      # default
```

| `mode` | What it does |
|---|---|
| `none` | No probing. Pure passive health. (Default.) |
| `dead` | Periodically re-probe only tripped or hard-down lanes. Use this to recover a lane promptly after a backend restores, without probing healthy lanes. |
| `active` | Periodically probe every lane, including healthy ones. Trips a lane before organic traffic hits it, if the backend goes silently dark. Sends a tiny billable one-token request per interval. |

Probe behavior:

- A 2xx probe recovers a tripped lane to Closed and clears all per-pool breaker cells for that lane. It bumps the lane's `ok` stat counter exactly once.
- A failed probe records a failure against the per-pool breaker configuration (using the same disposition pipeline as organic traffic). This can trip a healthy-but-sick lane in `active` mode.
- A lane with no configured key is skipped (probing it would only produce 401s and thrash the breaker).
- `interval_secs` and `timeout_secs` floor at 1 second regardless of the configured value.

Choosing a mode: `none` is fine for pools with multiple members — one member going down will be detected on the first organic hit and failed over. Use `dead` when you care about prompt recovery without paying for constant probes. Use `active` when you operate a pool with few members and need pre-emptive trip-out of a dark backend.

---

## Governance and limits

Governance adds per-client virtual keys with allowed-pool ACLs, budget caps, and rate limits. State persists in embedded SQLite. It is optional and disabled by default.

### Enabling governance

```yaml
governance:
  enabled: true
  db_path: /var/lib/busbar/governance.db
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
  price_per_request_cents: 1
  price_per_1k_tokens_cents: 50
```

When `enabled: true`:
- Clients must authenticate with a **virtual key** (`sk-bb-<32hex>`), not with the static `auth.client_tokens`.
- `auth.mode: passthrough` is rejected at startup — governance supersedes passthrough and the combination is unsupported.
- The `/admin/keys` API becomes available, guarded by `admin_token`.
- With no `admin_token` set (or whitespace-only), boot fails: governance can't run with an unguarded admin API.

`price_per_request_cents` and `price_per_1k_tokens_cents` set the deployment-wide pricing used to compute each key's spend. They can be set to `0` if you only want rate limits without budget tracking. Negative prices are clamped to `0`.

### Virtual keys

A virtual key is a credential with these attributes:

| Attribute | Description |
|---|---|
| `name` | Human label. |
| `allowed_pools` | List of pool (or model) names this key may target. Empty = all pools allowed. Violations return `403`. |
| `max_budget_cents` | Spend ceiling for the budget period. Over-budget requests return `429` (or a native `400`-class quota error for Bedrock ingress). |
| `budget_period` | `total` (lifetime), `daily` (resets at UTC midnight), or `monthly` (resets on UTC first-of-month). |
| `rpm_limit` | Requests per 60-second window. Exceeded → `429` with `Retry-After`. |
| `tpm_limit` | Tokens per 60-second window (best-effort; see [below](#enforcement-model-and-precision)). |
| `enabled` | If `false`, the key is revoked: auth fails with the ingress protocol's native `401`/`403`. |

Keys are stored as SHA-256 hashes. The plaintext secret is returned **once**, at mint time. If it is lost, mint a new key and delete the old one.

Keys are carried in the same token positions as regular client tokens: `Authorization: Bearer <key>`, `x-api-key: <key>` (Anthropic SDK), or `x-goog-api-key: <key>` (Gemini SDK). The client SDK need not change; just replace the provider API key with the Busbar virtual key.

### Admin API

All `/admin` routes require the configured admin token, sent as `Authorization: Bearer <admin_token>` or `X-Admin-Token: <admin_token>`. These are not virtual keys, and they are not the vendor SDK carriers (`x-api-key` / `x-goog-api-key`); the admin token is a single static credential set in `governance.admin_token`.

#### Mint a key

```bash
curl -s -X POST http://localhost:8080/admin/keys \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "team-ml",
        "allowed_pools": ["fast", "overflow"],
        "max_budget_cents": 50000,
        "budget_period": "monthly",
        "rpm_limit": 600,
        "tpm_limit": 200000
      }'
```

Response includes `id` (`vk_<16hex>`), `secret` (`sk-bb-<32hex>`, **shown once**), and all attributes. Store the secret immediately.

To also issue an AWS credential pair for Bedrock-SDK clients, add `"issue_aws_credential": true` to the request body. The 201 response then additionally includes `aws_access_key_id` and `aws_secret_access_key` — both shown **once** and never returned by any subsequent read API. Configure your Bedrock SDK with those credentials; Busbar verifies the inbound SigV4 signature and enforces the key's governance controls. See [Bedrock ingress](protocols.md#bedrock).

Create-key field validation: `budget_period` must be `total`, `daily`, or `monthly` (400 otherwise); `max_budget_cents` must be ≥ 0; `rpm_limit` and `tpm_limit` must each be ≥ 1 when set. `allowed_pools` that name no configured pool logs a warning but does not fail.

#### List keys

```bash
curl -s http://localhost:8080/admin/keys \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN"
```

Returns key metadata. Secret hashes are never returned.

#### Check usage

```bash
curl -s "http://localhost:8080/admin/keys/vk_abc123def456.../usage" \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN"
```

Returns `{ "spend_cents": ..., "tokens": ..., "requests": ... }` for the current budget window. `404` if the key does not exist.

#### Update a key

```bash
curl -s -X PATCH "http://localhost:8080/admin/keys/vk_abc123def456..." \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "rpm_limit": 1200, "max_budget_cents": null }'
```

Absent fields are left unchanged. `null` clears a cap to unlimited. Providing a value sets it. Same validation as create. `404` if the key does not exist.

#### Revoke a key

```bash
curl -s -X DELETE "http://localhost:8080/admin/keys/vk_abc123def456..." \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN"
```

Returns `404` if the key does not exist (delete is not idempotent). After deletion, the key's `sk-bb-…` secret is immediately rejected with a native `401`.

### Enforcement model and precision

Understanding where each limit is precise and where it is approximate is important for setting realistic budgets:

**RPM** — precise. The counter is incremented synchronously on admission, before the request is forwarded. A request that would exceed the limit is rejected before any upstream call is made.

**TPM** — best-effort. Token counts are recorded post-response, after the upstream reports them. In-flight concurrent requests do not yet contribute to the window. The first request of each new 60-second window is always admitted regardless of the previous window's total. If multiple large concurrent requests arrive simultaneously at the window boundary, all may be admitted before the TPM limit kicks in.

**Budget** — atomic hard cap. The over-budget check and the spend charge are performed as a single atomic SQLite UPSERT (`charge_within_budget`). Concurrent requests cannot cause an overshoot; if the cap is reached mid-burst, the excess requests are rejected. On a store error during the admission check, behavior is controlled by `governance.budget_on_store_error`: the default `allow` fails open (preserves availability); set `deny` for a hard budget guarantee that rejects on any store error. A definitive over-budget result always rejects regardless of this setting. Budget is a true spending ceiling when `deny` is used, and a reliable guardrail with `allow`.

**`allowed_pools` ACL** — precise and pre-forwarding. A key with `allowed_pools: ["fast"]` trying to target `overflow` or any direct model route not in the list gets `403` before any upstream call.

Rate windows are per-process, in-memory. Running multiple Busbar instances against the same governance database means RPM/TPM windows are per-instance, not shared. For distributed rate limiting, run one instance per governance database or front multiple instances with an upstream rate limiter.

---

## Health, metrics, and observability endpoints

### /healthz

```
GET /healthz
```

No auth required. Returns `200 OK` (body: `ok`) if any lane is usable — meaning at least one lane across all configured pools has a Closed or HalfOpen breaker in any of its cells, and is not permanently dead. Returns `503 Service Unavailable` (body: `no usable lanes`) if every lane is unusable.

Use as a Kubernetes readiness and liveness probe. The check is side-effect-free: it never steals a HalfOpen recovery probe slot.

A `503` from `/healthz` means all lanes are either tripped/cooling, hard-down, budget-exhausted, or permanently dead. Check `/stats` for details.

### /stats

```
GET /stats
Authorization: Bearer <client-token-or-virtual-key>
```

Requires auth (client token or virtual key). Returns a JSON topology snapshot, scoped to the calling key's `allowed_pools`: a key with a non-empty `allowed_pools` list sees only its permitted pools and the lanes reachable through them.

Per-lane fields in the response:

| Field | Meaning |
|---|---|
| `model` | Model name (as declared in `models:`). |
| `provider` | Provider name. |
| `max_concurrent` | Lane's concurrency cap. |
| `inflight` | Currently executing requests. |
| `free_slots` | `max_concurrent - inflight`. |
| `ok` | Lifetime successful upstream responses. |
| `err` | Lifetime recorded upstream failures. |
| `client_fault` | Lifetime 4xx responses attributed to callers (not counted against breaker). |
| `usable` | `true` if the lane is Closed or HalfOpen in any cell. |
| `dead` | `true` if permanently dead (restart to clear). |
| `dead_reason` | `auth`, `billing`, or other hard-down reason. |
| `cooldown_remaining_s` | Worst-case cooldown remaining across all cells (0 if Closed). |
| `streak` | Current consecutive failure streak (worst across cells). |
| `budget` | Remaining `max_requests` lifetime budget (`-1` = unlimited). |

`/stats` is the first tool to reach for when diagnosing a degraded pool. Check `cooldown_remaining_s` (non-zero means a cell is Open and the value shows when it will try to recover), `streak` (growing streak suggests repeated probe failures), and `dead` + `dead_reason` (a hard problem requiring intervention).

### /metrics

```
GET /metrics
Authorization: Bearer <client-token-or-virtual-key>
```

Prometheus text exposition (`text/plain; version=0.0.4`). Goes through the same auth check as other routes — it is treated as an information-disclosure surface (it reveals pool structure, lane names, and failure rates). In `none`/`passthrough` mode the auth check admits unconditionally, so `/metrics` is effectively open under those modes; restrict it at the network layer if that matters for your threat model.

Always enabled; no config needed.

### Metrics to watch

| Metric | Type | Labels | What to watch for |
|---|---|---|---|
| `busbar_requests_total` | counter | `ingress_protocol`, `pool`, `outcome` | `outcome=exhausted` rising → pools running out of healthy members. `outcome=error` → 5xx-class problems reaching the client; `outcome=client_error` → 4xx relayed to callers. |
| `busbar_upstream_attempts_total` | counter | `pool`, `lane` | Real upstream calls, re-counted per failover hop. Ratio to `busbar_requests_total` > 1 indicates failovers are happening. |
| `busbar_upstream_failures_total` | counter | `pool`, `lane`, `disposition` | `disposition` is `transient_upstream`, `hard_down`, or `context_length`. `hard_down` requires intervention (auth/billing problem). |
| `busbar_breaker_trips_total` | counter | `pool`, `lane` | One per Closed→Open trip (reopens don't count). A spike means a backend just went down. |
| `busbar_failovers_total` | counter | `pool`, `reason` | `reason` is `timeout`, `connect`, `transient_upstream`, `hard_down`, or `context_length`. A high rate on one pool indicates a flapping member. |
| `busbar_translations_total` | counter | `from`, `to` | Cross-protocol translation hops. Useful for auditing unexpected protocol conversion. |
| `busbar_request_duration_seconds` | histogram | `ingress_protocol`, `pool` | End-to-end latency including failover hops. |
| `busbar_key_spend_cents` | gauge | `key` | Per-virtual-key spend in cents for the current budget window (scrape-time). Only emitted when governance is enabled. Use for burn-rate alerting. |
| `busbar_key_budget_remaining_cents` | gauge | `key` | Max budget minus current spend for keys with a `max_budget_cents` cap. Only emitted for capped keys. Drive Prometheus budget-burn alerts. |
| `busbar_key_tokens_total` | gauge | `key` | Accumulated tokens consumed by each virtual key in the current budget window. Only emitted when governance is enabled. |
| `busbar_lane_state` | gauge | `pool`, `lane` | Per-(pool, lane-index) circuit-breaker health: `0` = Closed (healthy), `1` = HalfOpen (cooling, probe admitted), `2` = Open (tripped). Side-effect-free at scrape time. |
| `busbar_route_policy_selections_total` | counter | `pool`, `policy` | Requests where a routing policy produced a usable ranked order. Only incremented on a successful `Order` outcome; abstains and on-error fallbacks are not counted. |

The `pool` label is always a configured pool name or the sentinel `unresolved` (for routes that did not resolve to a pool). It is never a raw client-supplied model string, which would create unbounded label cardinality.

An OTLP traces sink (`observability.otlp_endpoint`) and a request-log webhook (`observability.request_log_webhook_url`) are available for deeper observability. Both are validated at startup against SSRF blocklists (no RFC-1918, loopback, or cloud-metadata targets — except OTLP allows plaintext `http://` to loopback for a local collector). See [configuration.md](configuration.md#observability).

---

## End-to-end worked example

The following config creates a production-like setup: a weighted primary pool with fast failover and a cheap overflow, context-length failover between members, session affinity, aggressive tripping with a low streak threshold, and governance-enforced per-team rate limits.

```yaml
listen: "0.0.0.0:8080"

auth:
  mode: token
  client_tokens:
    - "${BUSBAR_CLIENT_TOKEN}"

providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
    health:
      mode: dead
      interval_secs: 30
      timeout_secs: 5
  openai:
    api_key_env: OPENAI_KEY
  gemini:
    api_key_env: GEMINI_KEY

models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    default_max_tokens: 4096

  gpt-4o:
    provider: openai
    max_concurrent: 20

  gemini-flash:
    provider: gemini
    max_concurrent: 30

  claude-haiku:
    provider: anthropic
    max_concurrent: 40

pools:
  primary:
    members:
      - target: claude-sonnet
        weight: 5
        context_max: 200000
      - target: gpt-4o
        weight: 3
      - target: gemini-flash
        weight: 2
        context_max: 1048576
    affinity:
      mode: session
      header_name: x-session-id
    breaker:
      trip:
        mode: consecutive
        consecutive_n: 2       # trip fast — 2 consecutive failures
      base_cooldown_secs: 5
      max_cooldown_secs: 60
    failover:
      timeout_secs: 30
      max_hops: 3
    on_exhausted:
      action: fallback_pool:overflow

  overflow:
    members:
      - target: claude-haiku
        weight: 1
    on_exhausted:
      action: least_bad        # degraded but available; never hard-503

governance:
  enabled: true
  db_path: /var/lib/busbar/governance.db
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
  price_per_request_cents: 0
  price_per_1k_tokens_cents: 10
```

What this achieves:

- **Weighted primary dispatch**: `claude-sonnet` gets 50% of traffic, `gpt-4o` 30%, `gemini-flash` 20%.
- **Fast trip**: two consecutive failures opens a member's breaker in the `primary` pool with a 5-second initial cooldown. Organic traffic triggers failover to the next member within the 30-second deadline.
- **Context-length failover**: if `claude-sonnet` rejects a request as too long (200k context), Busbar excludes `claude-sonnet` and retries to `gemini-flash` (1M context) without penalizing the `claude-sonnet` lane.
- **Session affinity**: callers with `x-session-id` headers stay pinned to the same member while it is healthy.
- **Overflow**: if all primary members are exhausted, traffic spills to `claude-haiku`. If haiku is also exhausted, `least_bad` picks the member with the soonest recovery rather than returning 503.
- **Health probing**: `anthropic` lanes are re-probed on trip (`mode: dead`), so a recovered Anthropic backend is brought back promptly without waiting for organic traffic to probe it.
- **Governance**: each team gets a virtual key with per-pool ACLs and token-based rate limits. Mint keys with `POST /admin/keys`.

To mint a key for a team:

```bash
curl -s -X POST http://localhost:8080/admin/keys \
  -H "Authorization: Bearer $BUSBAR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "team-search",
        "allowed_pools": ["primary", "overflow"],
        "tpm_limit": 500000,
        "rpm_limit": 300,
        "budget_period": "monthly"
      }'
```

The response's `secret` field (`sk-bb-…`) is what the team uses as their API key pointed at busbar. They set it wherever they previously set their Anthropic/OpenAI key. Busbar handles the rest.