---
title: "Routing"
description: "Swap a pool's selection strategy with one list entry: weighted, cheapest, fastest, least-busy, or usage natively, or your own ordering logic via a compiled socket hook or an HTTP webhook."
---

Every Busbar pool has an ordering strategy. The default (weighted smooth round-robin (SWRR)) costs nothing and is the right choice for most pools. When you need a different selection strategy, you name one in the pool's `hooks:` list — `hooks: [cheapest]` — and everything else in Busbar (the circuit breaker, failover loop, concurrency semaphore, session affinity) is unchanged. The strategy only determines the order in which healthy candidates are tried.

Routing is one verb of Busbar's **[Hooks](/docs/hooks/)** system: a programmable request path. A hook is your own code — a compiled binary on a local Unix domain socket (about 8 microseconds per decision) or an HTTP webhook sidecar in any language — that sees a projection of the request and the live candidate signals and replies with a decision. An ordering hook replies with the `order` arm: a ranked preference list. The same machinery (timeout, `on_error` fallback, transparency headers) carries every hook, so a broken or slow hook never blocks or fails a request. This page covers ordering; the full hook contract — taps, the `restrict` and `rewrite` arms, live settings — lives in the [Hooks guide](/docs/hooks/).

Cross-references: [Pools](/docs/pools/) (how to define a pool and its members) · [Hooks](/docs/hooks/) (the full hook model) · [Configuration](/docs/configuration/) (full field reference) · [Reliability & Failover](/docs/reliability/) (breaker, failover, and exhaustion behavior). Coming from a 1.2.x config (`route:` / `policy:` keys)? See the [1.3 migration guide](/docs/migration-1-3/) — the old keys are hard startup errors that name the fix.

---

## Table of contents

- [The model: ordering as ranked preference](#the-model-ordering-as-ranked-preference)
- [How ordering composes with the breaker and failover](#how-ordering-composes-with-the-breaker-and-failover)
- [Native strategies](#native-strategies)
  - [weighted (default)](#weighted-default)
  - [cheapest](#cheapest)
  - [fastest](#fastest)
  - [least_busy](#least_busy)
  - [usage](#usage)
- [The routing signals](#the-routing-signals)
- [External ordering hooks](#external-ordering-hooks)
  - [The registry](#the-registry)
  - [socket (compiled binary)](#socket-compiled-binary)
  - [webhook](#webhook)
  - [The decision payload](#the-decision-payload)
  - [Access grants: prompt and user](#access-grants-prompt-and-user)
  - [The reply](#the-reply)
- [Fail-safety: on_error](#fail-safety-on_error)
- [A fleet-wide default ordering](#a-fleet-wide-default-ordering)
- [Full examples](#full-examples)
- [Observability](#observability)

---

## The model: ordering as ranked preference

An ordering hook does one thing: given the current request and the set of healthy candidates, it returns an **ordered preference list**. Busbar's existing failover loop walks that list (trying the first candidate, then the second if the first fails, and so on) using the circuit breaker at every step to skip any lane that is tripped, at capacity, or already tried this request.

The design consequence: **a hook ranks; the breaker decides health.** A hook cannot resurrect a tripped lane, and a hook that omits a healthy lane does not strand it; omitted candidates are appended to the end of the preference list, not excluded. A broken hook (timeout, error, empty response) falls back per its `on_error` — for an ordering hook, back to weighted SWRR — rather than failing the request.

A pool names its ordering in one `hooks: [...]` list: at most one strategy (a native name or an external gate that returns `order`) plus any number of other gates. Pools with no `hooks:` list run the zero-overhead case: today's unchanged SWRR code, with no projection built and no hook object constructed. Adding a hook to one pool adds no overhead to pools that do not use one.

---

## How ordering composes with the breaker and failover

The sequence for every request routed through a pool with a non-default ordering:

1. **The ordering hook runs once, before the failover loop.** It receives the healthy candidate set (as a projected read-only view) and returns a ranked list of candidate indices. When several gates apply (the pool's own plus any globals), they fire concurrently and reconcile deterministically — see [Hooks](/docs/hooks/) for the reconcile rules.
2. **The failover loop walks the ranked list.** It tries candidates in the preferred order, skipping any that are tripped, at capacity, or already tried.
3. **Candidates not in the ranked list are tried last.** If the hook emits a subset of candidates, the omitted ones are appended after the ranked set in an unspecified order. They are reachable; a hook can never permanently exclude a healthy lane by omission.
4. **On hook failure, `on_error` takes over.** A timeout or error coerces the decision to the hook's `on_error` (for an ordering hook, `weighted` — as if no hook were configured). An explicit **abstain** is different: it always means "no opinion" and Busbar proceeds as it normally would, regardless of `on_error`; abstaining is not a failure.

This composition means an ordering hook's job is deliberately narrow. You declare a preference; Busbar's existing reliability machinery handles the rest.

<svg viewBox="0 0 940 150" role="img" aria-label="Request flow: the ordering hook ranks candidates once, then the failover loop walks that order, the breaker filter skips unhealthy or already-tried lanes, and the request is dispatched to the upstream up to the first-byte boundary." style="width:100%;height:auto;max-width:940px;font-family:ui-sans-serif,system-ui,sans-serif;">
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
    <text x="280" y="76" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Ordering hook</text>
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

## Native strategies

Native strategies are compiled into Busbar and have no runtime dependencies. They are sync, never do I/O, and sort the candidate set by a single live signal. Name one directly in the pool's `hooks:` list; a pool may name **at most one** strategy.

### weighted (default)

The default selection strategy when a pool names no strategy. Uses Nginx-style smooth weighted round-robin (SWRR) across healthy members, proportional to each member's `weight` field. Writing `hooks: [weighted]` gives byte-identical behavior to omitting it entirely.

Use `weighted` explicitly only when you want to name the strategy in config for documentation clarity. There is no behavioral difference from the default.

### cheapest

Prefers the member with the lowest operator-declared `cost_per_mtok`. Members without a `cost_per_mtok` value are demoted to the end of the preference list but are still reachable. If no candidate has a declared cost, the strategy abstains and SWRR takes over.

Signal: `cost_per_mtok` on the pool member config. You declare the cost; Busbar ranks on it.

```yaml
pools:
  cost-optimized:
    hooks: [cheapest]
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

Prefers the member with the lowest measured round-trip latency, tracked as a rolling EWMA updated after each request. Members with no latency sample yet (new lanes, recently restarted) are demoted but reachable. If no candidate has latency data, the strategy abstains.

Signal: rolling EWMA latency in milliseconds, accumulated from organic traffic. No configuration required.

This is a good choice when your members have meaningfully different tail latencies and you want Busbar to track and prefer the faster one automatically over time.

### least_busy

Prefers the member with the most available concurrency headroom; the lane with the most free slots in its semaphore. Unlike `fastest`, `least_busy` always has data (concurrency is always known) and never abstains.

Signal: free concurrency permits on each lane's semaphore at decision time.

Use this when your members have different `max_concurrent` limits or when you want to avoid piling requests onto an already-saturated backend before the breaker trips it.

### usage

Prefers the member with the most remaining rate-limit headroom (RPM/TPM headroom computed from the caller key's governance rate-limit counters). Candidates with no headroom signal (e.g. when governance is disabled or no rate limit is set) are demoted to last but remain reachable. Abstains only when every candidate lacks the signal (no rate limit in play), falling back to SWRR.

---

## The routing signals

Every ordering decision (native and external) sees the same projection of each candidate:

| Signal | Field | Notes |
|---|---|---|
| Per-member cost | `cost_per_mtok` | Operator-declared in member config. `None` if not set. |
| Per-lane latency | `latency_ms` | Rolling EWMA in ms, updated per request. `None` until first request. |
| Live concurrency | `available_concurrency` | Free semaphore slots. Always populated. |
| Budget remaining | `budget_remaining` | Per-lane `max_requests` remaining. `None` = unlimited. |
| Rate headroom | `rate_headroom` | Remaining RPM/TPM headroom from governance counters, as a fraction (most headroom first). `None` when governance is disabled or the lane has no rate limit. |
| Labels | `tier`, `tags` | Your operator-declared member labels. |

External hooks also receive the request projection: `pool`, `ingress_protocol` (one of `anthropic`, `openai`, `gemini`, `bedrock`, `cohere`, `responses`), `message_count`, `has_tools`, `total_chars`, `max_tokens` (`null` if the caller set no output-token limit), and `stream`.

Token counts are not available pre-dispatch. The upstream response carries token usage, but that comes after a lane is chosen. Use `total_chars` (sum of all text chars across system + messages; not a token count) with the rule of thumb of ~4 chars/token for size-based decisions.

Every signal a native strategy ranks on is on the wire, so an external hook can implement any of them identically — and then go further.

---

## External ordering hooks

External hooks let you run routing logic outside Busbar; in any language, with access to any data Busbar cannot see. Busbar sends a lightweight projection of the request and candidates to your hook and receives a ranked candidate list back. The same timeout, fallback, and safety machinery applies as for native strategies: a slow or broken hook never fails a request.

### The registry

A hook is **defined once**, by name, in a top-level `hooks:` registry, then referenced from any pool's `hooks:` list. An ordering hook is a `kind: gate` (fire-and-wait; a `tap` only observes and can never appear in a pool list). Each hook declares exactly one transport: `socket` or `webhook`.

```yaml
hooks:
  smart-router:
    kind: gate
    socket: /run/busbar/router.sock
    timeout_ms: 1            # the default hard deadline; raise for hooks that do I/O
    on_error: weighted       # a broken ordering hook falls back to the weighted floor

pools:
  smart:
    hooks: [smart-router]
    members:
      - target: claude-opus
        tier: large
        cost_per_mtok: 15.0
      - target: claude-sonnet
        tier: small
        cost_per_mtok: 3.0
```

One list carries both jobs: a pool may name a base strategy *and* gates, e.g. `hooks: [cheapest, smart-router]`. All of a request's gates fire concurrently and reconcile deterministically (any reject wins; restricts intersect; with several orders, the last in the `priority` chain wins). The `priority` field on a hook definition orders that chain; ties keep globals first, then config order. Setting `global: true` on a definition (or listing the name in `global_hooks:`) attaches a hook to every request. Full reconcile rules in [Hooks](/docs/hooks/).

Misconfiguration is a hard startup error, never a silent fallback: a dangling name in a pool list, a tap in a pool list, more than one strategy in one list, a missing/relative `socket` path, or an SSRF-blocked `webhook` URL all fail the boot with a message naming the fix.

### socket (compiled binary)

The fast transport: an operator-run compiled binary (Rust or anything else) listening on a **local Unix domain socket**. Busbar writes one newline-terminated JSON line per decision and reads one line back; the connection is kept alive across decisions.

**Speed.** Measured end to end through Busbar's transport against the example Rust hook running as a separate process: about **8 microseconds median, p99 about 12** (3 candidates). Roughly 20x faster than a co-located HTTP webhook, with the same full process isolation: a crash in your hook is contained, and Busbar falls back per `on_error`.

**Registration.** A hook is a binary that owns a socket path; registration is the registry entry above. You (or your init system) run the binary — Busbar never spawns or supervises it. The connection is lazy (start order does not matter) and Busbar reconnects transparently across hook restarts; a restart costs zero failed decisions.

**Security.** The path is operator config on the local filesystem: no port, no TLS, no SSRF surface — the decision cannot leave the machine. Access control is filesystem permissions on the socket file (e.g. `0600` under a shared service user). Replies are read under a 64 KiB cap and a depth-guarded JSON parse.

**Portability.** Unix-only (macOS/Linux, any architecture). On other platforms a `socket` hook is a startup error pointing at `webhook`.

A complete Rust hook (about a hundred lines, stdlib + serde) ships in the repo under `examples/smart-router/rust-hook/`.

### webhook

The portable transport: Busbar POSTs the same JSON payload to your operator-supplied sidecar URL before each request's failover loop. Any language, any OS; sub-millisecond co-located. The URL is operator-config-only; never derived from a request header or body.

```yaml
hooks:
  smart-router:
    kind: gate
    webhook: "http://127.0.0.1:8787/"
    timeout_ms: 1
    on_error: weighted
```

**URL security.** Loopback (`127.0.0.1`, `localhost`) is allowed; routing sidecars are commonly co-located processes. RFC-1918, link-local, CGNAT, and metadata endpoints (`169.254.169.254`, `metadata.google.internal`, etc.) are blocked regardless, and remote URLs must be `https://`.

**Wire compatibility.** The request and reply schemas are byte-identical to the socket transport's, so a hook graduates from a webhook prototype to a compiled socket binary without changing its logic.

### The decision payload

**Request payload (Busbar → hook):**

```json
{
  "request": {
    "pool": "smart",
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
      "rate_headroom": 0.55,
      "tags": ["sonnet"]
    }
  ]
}
```

Field notes:

- `candidates[*].tier` and `cost_per_mtok`; `null` if not set on the member config.
- `candidates[*].latency_ms`; `null` until the lane has served at least one request.
- `candidates[*].budget_remaining`; `null` = unlimited (`max_requests: -1`).
- `candidates[*].rate_headroom`; `null` when governance is disabled or the lane has no rate limit.
- `candidates[*].tags`; the member's operator-declared free-form `tags` array (team names, regions, compliance labels). Omitted entirely when the member declares none.

> By default the payload contains only this projection: shapes, not content — no prompt text, no message bodies, no caller identity. A routing decision is a shape decision. Two per-hook grants (below) extend it for hooks you trust with more.

### Access grants: prompt and user

The grants live on the hook definition, both default off, and work identically on both transports:

| Grant | Levels | Adds |
|---|---|---|
| `prompt:` | `no` (default) · `ro` · `rw` | `ro` adds the request's content to `request`: a `system` string (flattened system-prompt text; absent when the request has none) and a `messages` array of `{"role": "...", "text": "..."}` (text flattened; images and other binary blocks skipped). The switch for content-screening hooks: PII detection, guardrails, audit. `rw` additionally lets a gate return the `rewrite` reply arm ([Hooks](/docs/hooks/)). |
| `user:` | `no` (default) · `ro` | Adds `request.user`: the governance virtual key's `id` and `name` (when the caller authenticated with one) and the body's end-user field, each absent when unknown. The switch for route-by-who hooks: team lanes, per-user denies. **The caller's secret/token is never in the payload, under any configuration** — the identity projection is built from the resolved key record, not the credential. |

Grants are immutable after registration and enforced both directions: a hook is never sent, and can never return, a field it wasn't granted.

```yaml
hooks:
  guard:
    kind: gate
    socket: /run/busbar/guard.sock
    prompt: ro       # this hook screens content
    user: ro         # ... and routes by caller
    on_error: reject # a security gate fails closed
```

### The reply

Ranked preference; most preferred first:
```json
{ "order": [1, 0] }
```

Or abstain (no opinion; Busbar proceeds as it normally would):
```json
{ "abstain": true }
```

Or **reject** the request outright — no upstream is dispatched and the caller receives a dialect-native error:
```json
{ "reject": { "status": 451, "message": "Request blocked: contains an unredacted SSN." } }
```

Rules:

- `order` is the only ranking key. Unknown `idx` values are dropped; duplicates are deduplicated preserving first-seen order. Omitted candidates are demoted, not excluded. An absent or empty `order` (including a bare `{}`) is treated as abstain.
- `reject` wins over `order` and `abstain` if sent together, and the verb is **fail-closed**: any `reject` value except an explicit `false` (or `null`) is a rejection, even a malformed one — a mis-typed detail degrades to the defaults (403, a generic message), never to "silently route the request". `status` is clamped to 400–499 — a hook cannot mint a success, a redirect, or a 5xx — and picks the dialect error type the SDK sees (401 → authentication, 429 → rate-limit, …); `message` is sanitized. A rejection is a deliberate decision, not a failure: `on_error` does not apply. Combined with `prompt: ro` this is the PII-screen primitive: see content, say no, before it leaves your network.
- A gate has two more arms — `restrict` (pin the candidate set to members carrying given `tags`, persisting across failover) and `rewrite` (replace the request body; requires `prompt: rw`) — documented in [Hooks](/docs/hooks/).
- Any non-2xx response, malformed JSON, or timeout applies `on_error`.

---

## Fail-safety: on_error

The decision is bounded by the hook's `timeout_ms` (default 1 ms — the default says hooks are fast; raise it when your hook does I/O or crosses the network). On timeout, crash, garbage reply, or a dead hook, Busbar coerces the decision to the hook's `on_error`:

| `on_error` | Behavior |
|---|---|
| `nothing` (default) | The failing gate **does not participate**: it drops out of the decision entirely and can never displace another gate's verdict. The right posture for gates whose job is orthogonal to routing. |
| `weighted` | Falls back to the weighted floor — a broken hook is indistinguishable from no hook. Behaviorally identical to `nothing` in the reconcile; the two names exist so a config reads correctly: `weighted` for ordering hooks, `nothing` for everything else. |
| `first` | First member in config order; deterministic. |
| `reject` | Fail closed with a 503 — for security gates, where an unscreened request is worse than none. Set this on every security gate. |
| `<hook-name>` | A **named fallback**: when this hook fails, that hook fires in its place (projected per its own grants). Its own `on_error` chains further; Busbar proves at boot that every chain terminates — an unknown name, a tap, or a cycle is a startup error. A strategy name (`cheapest`, …) is also a valid, infallible fallback. |

Kill an ordering hook mid-traffic and requests keep flowing on the weighted floor. A dropped candidate is demoted, not excluded, so a buggy ranking never strands a healthy model.

---

## A fleet-wide default ordering

`default: true` on an ordering hook makes it the base ordering for every pool that named no strategy of its own — replacing the built-in `weighted` floor. At most one hook may be the default (a second is a boot error naming both); a pool that named its own base keeps its choice, and a pool's own gates layer on top of whatever base it has. No default set means the zero-cost inline `weighted` backstop.

```yaml
hooks:
  fleet-router:
    kind: gate
    socket: /run/busbar/fleet.sock
    default: true      # every pool with no named strategy uses this
```

---

## Full examples

### Cost-optimized pool

Route all traffic to the cheapest healthy member. Useful for background jobs or batch workloads where latency is not the primary concern.

```yaml
pools:
  batch:
    hooks: [cheapest]
    failover:
      timeout_secs: 60
      max_hops: 3
    members:
      - target: gpt-4o-mini
        cost_per_mtok: 0.15
      - target: claude-sonnet
        cost_per_mtok: 3.0
      - target: gpt-4o
        cost_per_mtok: 5.0
```

`gpt-4o-mini` is tried first. If it is tripped, the breaker skips it and `claude-sonnet` becomes the first attempt for this request. The failover loop and breaker are unchanged.

### Latency-sensitive pool

Route to the fastest-responding member, measured over real traffic. New members start with no latency data and are tried last until they accumulate samples.

```yaml
pools:
  realtime:
    hooks: [fastest]
    members:
      - target: claude-sonnet
      - target: gpt-4o
      - target: gemini-1.5-flash
```

### Tier-based external hook

Route large requests to a capable model and smaller requests to a cheaper one, using your own hook. Define it once, name it in the pool.

```yaml
hooks:
  size-router:
    kind: gate
    webhook: "http://127.0.0.1:8731/route"   # or socket: /run/busbar/router.sock
    timeout_ms: 1                # the default; raise for hooks that do I/O
    on_error: weighted           # a broken hook falls back to SWRR, never fails

pools:
  smart:
    hooks: [size-router]
    failover:
      timeout_secs: 60
      max_hops: 3
    members:
      - target: claude-opus
        tier: large
        cost_per_mtok: 15.0
        tags: ["opus"]
      - target: claude-sonnet
        tier: small
        cost_per_mtok: 3.0
        tags: ["sonnet"]
```

Your hook receives the request projection (including `total_chars`, `max_tokens`, and each candidate's `tier` and `cost_per_mtok`) and returns `{"order": [0, 1]}` or `{"order": [1, 0]}` depending on request size (~4 chars/token rule of thumb; 24000 chars ≈ 6k tokens).

> Coming from a 1.2.x embedded Rhai script (`route: script`)? That transport was removed in 1.3; the same logic runs as a small socket hook binary — same ranked-order wire contract, ~100x faster. See the [migration guide](/docs/migration-1-3/).

---

## Observability

**Response headers.** Every request with a non-default ordering emits two headers:

- `x-busbar-route-policy: <hook>`; the hook or strategy that made the decision (e.g. `size-router`, `cheapest`)
- `x-busbar-route-target: <chosen-lane-model>`; the model of the chosen lane (e.g. `claude-sonnet`, `gpt-4o-mini`)

**Prometheus metrics:**

| Metric | Labels | Description |
|---|---|---|
| `busbar_route_policy_selections_total` | `policy`, `pool` | Count of requests where a non-default ordering produced a usable ranked order (incremented once per selection). |
| `busbar_route_policy_rejections_total` | `policy`, `pool`, `status` | Count of requests deliberately rejected by a hook's `reject` verb (no upstream dispatched, 4xx to the caller). |
