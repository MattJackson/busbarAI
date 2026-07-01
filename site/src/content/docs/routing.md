---
title: "Routing Policies"
description: "Swap a pool's selection strategy with one field — weighted, cheapest, fastest, least-busy natively, or your own logic via webhook or Rhai script."
---

Every Busbar pool has a routing policy. The default — weighted smooth round-robin (SWRR) — costs nothing and is the right choice for most pools. When you need a different selection strategy, you swap in a policy with one field: `route:`. Everything else in Busbar — the circuit breaker, failover loop, concurrency semaphore, session affinity — is unchanged. The policy only determines the order in which healthy candidates are tried.

Routing is the first of Busbar's **Hooks** — a programmable request path. At a small number of points in the request lifecycle, an operator-supplied policy inspects the request and returns a decision, via one of three transports (native, webhook, or Rhai script). Routing is hook #1: it decides selection order. The same transport machinery — timeout, fallback, transparency header — carries every hook, so a broken or slow policy never blocks or fails a request.

Cross-references: [Pools](/pools/) (how to define a pool and its members) · [Configuration](/configuration/) (full field reference) · [Reliability & Failover](/reliability/) (breaker, failover, and exhaustion behavior).

---

## Table of contents

- [The model: policy as ranked preference](#the-model-policy-as-ranked-preference)
- [How policies compose with the breaker and failover](#how-policies-compose-with-the-breaker-and-failover)
- [Native policies](#native-policies)
  - [weighted (default)](#weighted-default)
  - [cheapest](#cheapest)
  - [fastest](#fastest)
  - [least_busy](#least_busy)
  - [usage (landing alongside)](#usage)
- [The routing signals](#the-routing-signals)
- [External policies](#external-policies)
  - [webhook](#webhook)
  - [script (Rhai)](#script-rhai)
- [Configuration reference](#configuration-reference)
- [Full examples](#full-examples)
  - [Cost-optimized pool](#cost-optimized-pool)
  - [Latency-sensitive pool](#latency-sensitive-pool)
  - [Tier-based webhook policy](#tier-based-webhook-policy)
  - [Rhai script: route by request size](#rhai-script-route-by-request-size)
- [Observability](#observability)

---

## The model: policy as ranked preference

A routing policy does one thing: given the current request and the set of healthy candidates, it returns an **ordered preference list**. Busbar's existing failover loop walks that list — trying the first candidate, then the second if the first fails, and so on — using the circuit breaker at every step to skip any lane that is tripped, at capacity, or already tried this request.

The design consequence: **a policy ranks; the breaker decides health.** A policy cannot resurrect a tripped lane, and a policy that omits a healthy lane does not strand it — omitted candidates are appended to the end of the preference list, not excluded. A broken policy (timeout, error, empty response) falls back to weighted SWRR rather than failing the request.

Every pool has exactly one `route:` value. `weighted` is both the default and the zero-overhead case: pools without a `route:` field run today's unchanged SWRR code, with no projection built and no policy object constructed. Adding a policy to a pool adds no overhead to pools that do not use one.

---

## How policies compose with the breaker and failover

The sequence for every request routed to a non-weighted pool:

1. **Policy runs once, before the failover loop.** It receives the healthy candidate set (as a projected read-only view) and returns a ranked list of candidate indices.
2. **The failover loop walks the ranked list.** It tries candidates in the policy's preferred order, skipping any that are tripped, at capacity, or already tried (`request_ctx.excluded`).
3. **Candidates not in the ranked list are tried last.** If the policy emits a subset of candidates, the omitted ones are appended after the ranked set in an unspecified order. They are reachable — a policy can never permanently exclude a healthy lane.
4. **On policy failure, SWRR takes over.** A timeout or error causes Busbar to fall back to the pool's `on_error` behavior (default: SWRR), as if no policy were configured. An explicit **abstain** is different: it always falls straight through to SWRR regardless of `on_error` — abstaining is "no opinion," not a failure.

This composition means a policy's job is deliberately narrow. You declare a preference; Busbar's existing reliability machinery handles the rest.

<svg viewBox="0 0 940 150" role="img" aria-label="Request flow: the policy ranks candidates once, then the failover loop walks that order, the breaker filter skips unhealthy or already-tried lanes, and the request is dispatched to the upstream up to the first-byte boundary." style="width:100%;height:auto;max-width:940px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <defs>
    <marker id="rt-arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="940" height="150" fill="#ffffff"/>
  <!-- arrows -->
  <g stroke="#94a3b8" stroke-width="2" marker-end="url(#rt-arw)">
    <line x1="160" y1="78" x2="206" y2="78"/>
    <line x1="350" y1="78" x2="396" y2="78"/>
    <line x1="540" y1="78" x2="586" y2="78"/>
    <line x1="730" y1="78" x2="776" y2="78"/>
  </g>
  <!-- stages -->
  <g>
    <rect x="20"  y="44" width="140" height="68" rx="10" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="90"  y="76" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Request</text>
    <text x="90"  y="94" text-anchor="middle" fill="#64748b" font-size="10.5">the client call</text>
    <rect x="210" y="44" width="140" height="68" rx="10" fill="#f7fee7" stroke="#a3e635" stroke-width="2"/>
    <text x="280" y="76" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Policy</text>
    <text x="280" y="94" text-anchor="middle" fill="#4d7c0f" font-size="10.5">ranks candidates once</text>
    <rect x="400" y="44" width="140" height="68" rx="10" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="470" y="76" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Failover loop</text>
    <text x="470" y="94" text-anchor="middle" fill="#64748b" font-size="10.5">walks the ranked order</text>
    <rect x="590" y="44" width="140" height="68" rx="10" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="660" y="76" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Breaker filter</text>
    <text x="660" y="94" text-anchor="middle" fill="#64748b" font-size="10.5">skips unhealthy / tried</text>
    <rect x="780" y="44" width="140" height="68" rx="10" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="850" y="76" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Dispatch</text>
    <text x="850" y="94" text-anchor="middle" fill="#64748b" font-size="10.5">to first-byte boundary</text>
  </g>
</svg>

---

## Native policies

Native policies are compiled into Busbar and have no runtime dependencies. They are sync, never do I/O, and sort the candidate set by a single live signal. Configure them with `route: native` and a `policy.name`.

### weighted (default)

`policy.name: weighted`

The default selection strategy when no `route:` is set. Uses Nginx-style smooth weighted round-robin (SWRR) across healthy members, proportional to each member's `weight` field. Setting `route: native` and `policy.name: weighted` gives byte-identical behavior to omitting `route:` entirely — it always abstains, letting the inline SWRR path handle selection.

Use `weighted` explicitly only when you want to name the policy in config for documentation clarity. There is no behavioral difference from the absent-`route:` default.

### cheapest

`policy.name: cheapest`

Prefers the member with the lowest operator-declared `cost_per_mtok`. Members without a `cost_per_mtok` value are demoted to the end of the preference list but are still reachable. If no candidate has a declared cost, the policy abstains and SWRR takes over.

Signal: `cost_per_mtok` on the pool member config. You declare the cost; Busbar ranks on it.

```yaml
pools:
  cost-optimized:
    route: native
    policy:
      name: cheapest
    members:
      - target: claude-sonnet
        cost_per_mtok: 3.0
      - target: gpt-4o
        cost_per_mtok: 5.0
      - target: gpt-4o-mini
        cost_per_mtok: 0.15
```

Traffic flows to `gpt-4o-mini` first, then `gpt-4o`, then `claude-sonnet`. If `gpt-4o-mini` is tripped, the breaker skips it and `gpt-4o` becomes the first attempt.

### fastest

`policy.name: fastest`

Prefers the member with the lowest measured round-trip latency, tracked as a rolling EWMA updated after each request. Members with no latency sample yet (new lanes, recently restarted) are demoted but reachable. If no candidate has latency data, the policy abstains.

Signal: rolling EWMA latency in milliseconds, accumulated from organic traffic. No configuration required.

This is a good choice when your members have meaningfully different tail latencies and you want Busbar to track and prefer the faster one automatically over time.

### least_busy

`policy.name: least_busy`

Prefers the member with the most available concurrency headroom — the lane with the most free slots in its semaphore. Unlike `fastest`, `least_busy` always has data (concurrency is always known) and never abstains.

Signal: free concurrency permits on each lane's semaphore at decision time.

Use this when your members have different `max_concurrent` limits or when you want to avoid piling requests onto an already-saturated backend before the breaker trips it.

### usage

`policy.name: usage`

Prefers the member with the most remaining rate-limit headroom (RPM/TPM headroom from the caller key's governance counters). The `rate_headroom` signal is computed in `src/forward.rs` (`rate_headroom_for_token`) and passed to each `Candidate` before the routing decision. Candidates with no headroom signal (`None`, e.g. when governance is disabled or no rate limit is set) are demoted to last but remain reachable. Abstains only when every candidate lacks the signal (no rate limit in play), falling back to SWRR.

---

## The routing signals

Every policy — native and external — sees the same projection of each candidate:

| Signal | Field | Available now | Notes |
|---|---|---|---|
| Per-member cost | `cost_per_mtok` | Yes | Operator-declared in member config. `None` if not set. |
| Per-lane latency | `latency_ms` | Yes | Rolling EWMA in ms, updated per request. `None` until first request. |
| Live concurrency | `available_concurrency` | Yes | Free semaphore slots. Always populated. |
| Budget remaining | `budget_remaining` | Yes | Per-lane `max_requests` remaining. `None` = unlimited. |
| Rate headroom | `rate_headroom` | Yes | Remaining RPM/TPM headroom from governance counters, as a fraction (most headroom first). `None` when governance is disabled or the lane has no rate limit. |

External policies (webhook, script) also receive the request projection. The webhook wire format and the Rhai `req` map share most fields, with the script getting a few extras:

| Signal | Field | Webhook | Script (`req`) | Notes |
|---|---|---|---|---|
| Pool | `pool` | Yes | Yes | Pool name the request is being routed through. |
| Ingress protocol | `ingress_protocol` | Yes | Yes | One of: `anthropic`, `openai`, `gemini`, `bedrock`, `cohere`, `responses`. |
| Requested model | `requested_model` | — | Yes | Model the caller asked for; `()` if absent. Not in webhook payload. |
| Message count | `message_count` | Yes | Yes | Number of messages in the conversation. |
| Has tools | `has_tools` | Yes | Yes | Boolean; `true` when at least one tool is declared. |
| Tool count | `tool_count` | — | Yes | Number of tools declared. Not in webhook payload. |
| Request size | `total_chars` | Yes | Yes | Sum of all text chars across system + messages. v1 size signal — not a token count. Rule of thumb: ~4 chars/token. |
| System size | `system_chars` | — | Yes | System-prompt text chars only. Not in webhook payload. |
| Max tokens | `max_tokens` | Yes | Yes | Caller's requested output token limit; `null`/`()` if unset. |
| Streaming | `stream` | Yes | Yes | Whether the request is a streaming call. |

Token counts are not available pre-dispatch. The upstream response carries token usage, but that comes after a lane is chosen. Use `total_chars` with the rule of thumb (~4 chars/token) for size-based routing decisions in webhook/script policies.

---

## External policies

External policies let you run routing logic outside Busbar — in any language, with access to any data Busbar cannot see. Busbar sends a lightweight request projection to your policy endpoint and receives a ranked candidate list back. The same timeout, fallback, and safety machinery applies as for native policies: a slow or broken external policy never fails a request.

### webhook

`route: webhook`

Busbar POSTs a JSON payload to your operator-supplied sidecar URL before each request's failover loop. The sidecar returns a ranked list of candidate indices. The URL is operator-config-only — never derived from a request header or body.

**Timeout and fallback.** The request is bounded by `policy.timeout_ms` (default 150 ms). On timeout, non-200 response, or malformed JSON, Busbar applies `on_error` (default: `weighted` — fall back to SWRR). A broken sidecar is indistinguishable from no policy. Concurrency is bounded by `policy.timeout_ms` and the HTTP client's connection pool — there is no separate in-flight cap on routing webhook calls.

**URL security.** The sidecar URL allows loopback (`127.0.0.1`, `localhost`) — routing sidecars are commonly co-located processes. RFC-1918, link-local, CGNAT, and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, etc.) are blocked regardless.

**Request payload (Busbar → sidecar):**

```json
{
  "request": {
    "pool": "smart-webhook",
    "ingress_protocol": "anthropic",
    "message_count": 12,
    "has_tools": true,
    "total_chars": 41200,
    "max_tokens": 8192,
    "stream": true
  },
  "candidates": [
    {
      "idx": 0,
      "model": "claude-opus",
      "tier": "large",
      "cost_per_mtok": 15.0,
      "latency_ms": 320.5,
      "available_concurrency": 14,
      "budget_remaining": null,
      "rate_headroom": 0.82
    },
    {
      "idx": 1,
      "model": "claude-sonnet",
      "tier": "small",
      "cost_per_mtok": 3.0,
      "latency_ms": 95.2,
      "available_concurrency": 18,
      "budget_remaining": 5000,
      "rate_headroom": 0.55
    }
  ],
  "context": {
    "pool": "smart-webhook",
    "budget_remaining": null
  }
}
```

Field notes:
- `request.pool` — the pool name the request is being routed through.
- `request.ingress_protocol` — one of `anthropic`, `openai`, `gemini`, `bedrock`, `cohere`, `responses`.
- `request.max_tokens` — `null` if the caller did not set an output-token limit.
- `candidates[*].tier` — `null` if not set on the member config.
- `candidates[*].cost_per_mtok` — `null` if not declared on the member.
- `candidates[*].latency_ms` — `null` until the lane has served at least one request.
- `candidates[*].budget_remaining` — `null` = unlimited (`max_requests: -1`).
- `candidates[*].rate_headroom` — remaining RPM/TPM headroom as a fraction; `null` when governance is disabled or the lane has no rate limit.
- `context.budget_remaining` — always `null` in 1.0: the per-key governance budget is intentionally not fed to the routing seam. Use per-member `budget_remaining` for lane-level capacity.

> The payload contains only the request projection — no prompt text, no message bodies. Busbar never sends request content to any external sink.

**Response payload (sidecar → Busbar):**

Ranked preference — most preferred first:
```json
{ "order": [1, 0] }
```

Or abstain (fall back to `on_error`):
```json
{ "abstain": true }
```

Rules:
- `order` is the only ranking key. Unknown `idx` values are dropped; duplicates are deduplicated preserving first-seen order.
- Omitted candidates are demoted, not excluded — the failover loop can still reach them after the ranked set is exhausted.
- An absent or empty `order` (including a bare `{}`) is treated as abstain.
- `abstain: true` explicitly signals no preference; the `order` field is ignored if present alongside it.
- Any non-2xx response, malformed JSON, or timeout applies `on_error` (same as abstain for the default `on_error: weighted`).

**Transparency.** Every response with a non-default routing policy carries two headers: `x-busbar-route-policy` (the policy name) and `x-busbar-route-target` (the chosen lane model) — for example `x-busbar-route-policy: webhook` and `x-busbar-route-target: claude-sonnet`.

### script (Rhai)

`route: script`

> **Feature-flagged.** The script transport is compiled in behind the `script-policy` cargo feature and is disabled in the default binary. Enable it only if you need in-process scripting and have reviewed the sandbox configuration.

An embedded [Rhai](https://rhai.rs) script, compiled at startup and evaluated per request on a sandboxed thread pool. Rhai is a pure-Rust scripting language with no network or filesystem access by default, bounded by operation count and size limits.

**Script environment.** The script receives three injected variables:

- `req` — a map with the request projection fields:
  - `pool` (string), `ingress_protocol` (string), `requested_model` (string or `()`)
  - `message_count` (int), `tool_count` (int), `has_tools` (bool)
  - `total_chars` (int), `system_chars` (int)
  - `max_tokens` (int or `()` if unset), `stream` (bool)

- `candidates` — an array of maps, one per candidate, each with:
  - `idx` (int), `model` (string), `provider` (string)
  - `weight` (int), `context_max` (int or `()` if unset)
  - `tier` (string or `()` if unset)
  - `cost_per_mtok` (float or `()` if unset), `latency_ms` (float or `()` until first request)
  - `available_concurrency` (int), `budget_remaining` (int or `()` = unlimited)
  - `tags` (array of strings)

- `ctx` — a map with routing context:
  - `pool` (string), `budget_remaining` (always `()` in 1.0 — not fed to the routing seam)

Optional/absent values are `()` (Rhai unit), not `null`. Test with `== ()` or default with `??`.

**Return value.** Return an array of integer candidate `idx` values, most preferred first. Returning `()`, an empty array, or any non-array value is treated as abstain. Unknown or duplicate `idx` values are dropped. An all-unknown array collapses to abstain.

```rhai
// Route large requests to a capable model, smaller ones to a cheaper one.
// ~4 chars/token rule of thumb; 24000 chars ≈ 6k tokens.
let big = req.total_chars > 24000 || (req.max_tokens ?? 0) > 4096;
let preferred = if big {
    candidates.filter(|c| c.tier == "large")
} else {
    candidates.filter(|c| c.tier == "small")
};
preferred.map(|c| c.idx)
```

**Sandbox limits.** The script engine is locked down with:
- Max operations: 250,000 (a runaway `while true {}` terminates at the cap, not hangs)
- Max call/expression depth: 32
- Max string size: 8 KB
- Max array length: 4,096 entries
- Max map entries: 1,024
- No module resolver — `import` statements always fail
- No file, network, or process host functions registered

A script that exceeds any limit errors and the result is coerced via `on_error`. The script evaluates synchronously against a shared pre-compiled AST (compiled once at config load, not per request).

Scripts are operator-config only — never client-supplied.

---

## Configuration reference

### Pool-level fields

| Field | Type | Default | Description |
|---|---|---|---|
| `route` | string | `weighted` | Routing transport: `weighted`, `native`, `webhook`, or `script`. `weighted` (default / absent) runs SWRR with zero added cost. |
| `policy` | object | none | Transport configuration block. Required for `native`, `webhook`, and `script`; inert for `weighted`. |

### `policy` block fields

| Field | Type | Default | Transport | Description |
|---|---|---|---|---|
| `name` | string | none | `native` | Native policy name: `weighted`, `cheapest`, `fastest`, `least_busy`, or `usage`. Required when `route: native`. |
| `url` | string | none | `webhook` | Operator sidecar URL. Loopback allowed; RFC-1918/CGNAT/metadata blocked. Required when `route: webhook`. |
| `timeout_ms` | integer | `150` | `native`, `webhook`, `script` | Hard wall-clock deadline for the policy decision in milliseconds. On timeout, `on_error` applies. (Native policies are synchronous and effectively never hit it.) |
| `on_error` | string | `weighted` | `native`, `webhook`, `script` | Fallback when the policy times out or errors: `weighted` (SWRR), `reject` (503), or `first` (first member in config order). An explicit abstain bypasses this and always falls through to SWRR. |
| `script` | string | none | `script` | Inline Rhai source. Exactly one of `script` or `script_file` is required when `route: script`. |
| `script_file` | string | none | `script` | Path to a Rhai script file. Alternative to inline `script`. |

### Per-member routing metadata fields

Added to each pool member. All optional; inert for pools with `route: weighted`.

| Field | Type | Default | Description |
|---|---|---|---|
| `tier` | string | none | Operator-declared routing tier (e.g. `"primary"`, `"overflow"`, `"large"`, `"small"`). Exposed to webhook and script policies as `tier`. |
| `cost_per_mtok` | float | none | Operator-declared cost in currency units per million tokens. Drives `cheapest` and is exposed to webhook/script. |
| `tags` | list<string> | `[]` | Free-form labels (e.g. `["opus", "large-context"]`). Exposed to webhook and script for tag-based selection. |

### Startup validation

| Rule | Condition |
|---|---|
| `route: native` + no `policy.name` | Startup error |
| `route: native` + unknown `policy.name` | Startup error (must be one of: `weighted`, `cheapest`, `fastest`, `least_busy`, `usage`) |
| `route: webhook` + no `policy.url` | Startup error |
| `route: webhook` + SSRF-blocked URL | Startup error (RFC-1918, CGNAT, link-local, metadata hosts blocked; loopback allowed) |
| `route: script` + neither `policy.script` nor `policy.script_file` | Startup error |
| `route: script` + both `policy.script` and `policy.script_file` | Startup error |
| `route: script` without the `script-policy` feature flag | Startup error |

---

## Full examples

### Cost-optimized pool

Route all traffic to the cheapest healthy member. Useful for background jobs or batch workloads where latency is not the primary concern.

```yaml
pools:
  batch:
    route: native
    policy:
      name: cheapest
    failover:
      timeout_secs: 60
      max_hops: 3
    members:
      - target: gpt-4o-mini
        weight: 1
        cost_per_mtok: 0.15
      - target: claude-sonnet
        weight: 1
        cost_per_mtok: 3.0
      - target: gpt-4o
        weight: 1
        cost_per_mtok: 5.0
```

`gpt-4o-mini` is tried first. If it is tripped, the breaker skips it and `claude-sonnet` becomes the first attempt for this request. The failover loop and breaker are unchanged.

### Latency-sensitive pool

Route to the fastest-responding member, measured over real traffic. New members start with no latency data and are tried last until they accumulate samples.

```yaml
pools:
  realtime:
    route: native
    policy:
      name: fastest
    members:
      - target: claude-sonnet
        weight: 1
      - target: gpt-4o
        weight: 1
      - target: gemini-1.5-flash
        weight: 1
```

### Tier-based webhook policy

Route large requests to a capable model and smaller requests to a cheaper one, using a co-located HTTP sidecar.

```yaml
pools:
  smart:
    route: webhook
    policy:
      url: "http://127.0.0.1:8731/route"
      timeout_ms: 150
      on_error: weighted          # broken sidecar falls back to SWRR, never fails
    failover:
      timeout_secs: 60
      max_hops: 3
    members:
      - target: claude-opus
        weight: 1
        tier: large
        cost_per_mtok: 15.0
        tags: ["opus"]
      - target: claude-sonnet
        weight: 1
        tier: small
        cost_per_mtok: 3.0
        tags: ["sonnet"]
```

Your sidecar receives the request projection (including `total_chars`, `max_tokens`, and each candidate's `tier` and `cost_per_mtok`) and returns `{"order": [0, 1]}` or `{"order": [1, 0]}` depending on request size.

### Rhai script: route by request size

The same tier-based logic as above, without a sidecar, using an inline Rhai script.

```yaml
pools:
  smart-script:
    route: script
    policy:
      on_error: weighted
      script: |
        let big = req.total_chars > 24000 || (req.max_tokens ?? 0) > 4096;
        let preferred = if big {
            candidates.filter(|c| c.tier == "large")
        } else {
            candidates.filter(|c| c.tier == "small")
        };
        preferred.map(|c| c.idx)
    members:
      - target: claude-opus
        tier: large
        tags: ["opus"]
      - target: claude-sonnet
        tier: small
        tags: ["sonnet"]
```

> The `script-policy` cargo feature must be enabled at compile time. The script runs sandboxed: no I/O, no network, operation-count bounded.

---

## Observability

**Response headers.** Every request with a non-default routing policy emits two headers (`src/forward.rs` constants `HDR_ROUTE_POLICY` and `HDR_ROUTE_TARGET`):

- `x-busbar-route-policy: <policy>` — the policy name that made the decision (e.g. `webhook`, `native:cheapest`)
- `x-busbar-route-target: <chosen-lane-model>` — the model of the chosen lane (e.g. `claude-sonnet`, `gpt-4o-mini`)

| Example headers | Meaning |
|---|---|
| `x-busbar-route-policy: webhook` / `x-busbar-route-target: claude-sonnet` | Webhook policy chose `claude-sonnet` |
| `x-busbar-route-policy: native:cheapest` / `x-busbar-route-target: gpt-4o-mini` | Native cheapest policy chose `gpt-4o-mini` |

**Prometheus metrics:**

| Metric | Labels | Description |
|---|---|---|
| `busbar_route_policy_selections_total` | `policy`, `pool` | Count of requests where a non-default routing policy produced a usable ranked order (incremented once per selection). |
