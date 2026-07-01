# In-flight failover

When a lane fails, Busbar reroutes the request to another pool member before your client sees a byte, even mid-stream, across protocol families. This page covers the first-byte boundary, the per-request failover budget, context-length failover, session affinity, and what happens when a pool is exhausted.

Cross-references: [Circuit breaker](/circuit-breaker/) (how lanes trip) · [Pools](/pools/) (structure) · [Configuration](/configuration/) (field reference).

## The first-byte boundary

<svg viewBox="0 0 760 210" role="img" aria-label="A timeline split at the first byte reaching the client: before it, Busbar can transparently reroute connect errors, timeouts, 429s, and 5xxs; after it, no failover is possible because the client already holds tokens." style="width:100%;height:auto;max-width:760px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <rect x="0" y="0" width="760" height="210" fill="#ffffff"/>
  <!-- divider marker -->
  <text x="420" y="34" text-anchor="middle" fill="#334155" font-size="12" font-weight="700">first byte reaches client</text>
  <line x1="420" y1="42" x2="420" y2="150" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="4 4"/>
  <!-- green (before) -->
  <rect x="56" y="56" width="360" height="64" rx="12" fill="#f0fdf4" stroke="#16a34a" stroke-width="2"/>
  <text x="236" y="84" text-anchor="middle" fill="#166534" font-size="15" font-weight="700">Failover window</text>
  <text x="236" y="105" text-anchor="middle" fill="#15803d" font-size="10.5">connect · timeout · 429 · 5xx  →  reroute</text>
  <!-- red (after) -->
  <rect x="424" y="56" width="280" height="64" rx="12" fill="#fef2f2" stroke="#dc2626" stroke-width="2"/>
  <text x="564" y="84" text-anchor="middle" fill="#991b1b" font-size="15" font-weight="700">No failover</text>
  <text x="564" y="105" text-anchor="middle" fill="#b91c1c" font-size="10.5">client already holds tokens</text>
  <!-- captions -->
  <text x="236" y="150" text-anchor="middle" fill="#475569" font-size="11">The bulk of real provider failures land here.</text>
  <text x="564" y="150" text-anchor="middle" fill="#475569" font-size="11">Mid-stream death → SSE error; client retries.</text>
  <!-- time axis -->
  <line x1="56" y1="180" x2="700" y2="180" stroke="#cbd5e1" stroke-width="1.5"/>
  <polygon points="700,175 712,180 700,185" fill="#cbd5e1"/>
  <text x="56" y="198" text-anchor="start" fill="#94a3b8" font-size="10.5">request starts</text>
  <text x="712" y="198" text-anchor="end" fill="#94a3b8" font-size="10.5">time →</text>
</svg>

Failover is bounded by when the upstream starts streaming a response body to the client. Before the first upstream byte reaches the client, any transport or pre-response failure (connect error, timeout waiting for headers, transient upstream response) transparently fails over to another pool member. From the client's perspective, the request is still in flight.

**This pre-first-byte window covers the bulk of real provider failures**: connect errors and timeouts, `429` rate-limit responses, and `5xx` errors returned on the response headers all arrive *before* any body byte, so they fail over transparently. A failure only becomes unrecoverable once the upstream has already streamed a byte to the client and *then* dies mid-generation.

**Why mid-stream failover is impossible: for every gateway, not just Busbar.** A streaming response is a stateful continuation. Once a byte has been sent, you cannot un-send it: the client has already rendered those tokens. A replacement provider cannot *resume* the first provider's half-finished generation either, it would start a brand-new completion from the prompt, so splicing its fresh output onto the partial stream produces duplicated or contradictory text. The only alternatives are to resend the whole response (the client sees tokens twice) or abandon the partial, neither is transparent. This is a property of streaming itself, so no transparent gateway (LiteLLM and OpenRouter included) does mid-stream failover; it is physics, not a missing feature.

**The one real lever: a configurable pre-release buffer (planned, v1.x).** Busbar can hold the first *K* tokens / *T* ms of the upstream stream before releasing any byte to the client; if the provider dies inside that window, nothing has been sent yet, so Busbar can still reroute. The trade-off is up to *T* ms of added TTFT, so it is opt-in per pool and defaults to off (today's pure pre-first-byte behavior). It widens the failover window, it does not claim the impossible mid-stream splice above.

**After the first byte**: failover is impossible (per the reasoning above). The client already holds a partial response body. If the upstream then fails mid-stream:
- For SSE responses (OpenAI, Anthropic, Gemini, Cohere, Responses ingress): Busbar emits an SSE `error` event to the client and closes the connection. The lane records the failure, which may trip its breaker.
- For non-SSE responses: the body stream terminates.

In both cases the client must detect the incomplete response and retry. The breaker will have recorded the failure, so a subsequent retry to the same pool is likely to be routed to a different member.

The practical implication: for workloads where mid-stream failure recovery matters, keep responses short or use non-streaming calls where the full response is buffered before delivery. For long streaming responses, implement client-side retry with session affinity disabled on retry (or send the retry to a different pool).

## Failover budget and exclusions

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

`exclusions` is a per-pool member blocklist. A model listed in `exclusions` is never selected: not as the initial pick and not as a failover destination. Use it to keep a member in the pool (so it appears in `/stats` and can be targeted directly) without it ever being auto-selected. Each `exclusions` entry must name a member of this pool. A member not in the pool at all is a simpler case; `exclusions` is for members you want visible but never auto-dispatched.

Already-tried lanes are accumulated in an `excluded` set across hops for the lifetime of the request. A lane that succeeded (2xx headers) but whose body then failed before the first byte is refunded its `max_requests` budget spend and is also excluded from further hops on that request.

## Context-length failover

When a request is too large for a member (the provider returns a context-length error), Busbar does not penalize the lane, it was healthy, the request simply did not fit. Instead, it excludes from this request's candidate set any member whose declared `context_max` is ≤ the failed lane's, then retries to a larger (or unknown-context) member.

```yaml
pools:
  long-context:
    members:
      - target: claude-haiku
        context_max: 200000
      - target: gemini-2.5-flash
        context_max: 1048576
```

A member with no `context_max` set is never excluded on context-length grounds, it is always a candidate, and if it also rejects the request as too long, that rejection is still treated as a context-length failure (no breaker penalty) and the lane is simply excluded for the rest of this request.

Context-length failover is suppressed on 5xx responses, even if the body mentions a context-length-related code, to prevent a broken backend from dodging normal breaker penalties.

## Session affinity

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

When a request carries `x-session-id: <value>`, Busbar pins that session to a specific member. If the pinned member is unavailable (tripped, at-capacity, or excluded), affinity is ignored and normal SWRR selection runs, affinity is a preference, not a guarantee. The client receives no signal that the pin was broken.

`session` is the only supported `mode`. `header_name` defaults to `x-session-id`.

## Pool exhaustion

When all candidates are unavailable, tripped, excluded, or at-capacity, the pool is exhausted. The `on_exhausted` action decides what happens:

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

A `503` from pool exhaustion sets `Retry-After` so clients and upstream proxies know how long to back off. The `/metrics` counter `busbar_requests_total{outcome="exhausted"}` tracks these. A rising exhausted rate combined with a falling `busbar_upstream_attempts_total` for the pool's lanes indicates breakers are tripping faster than they recover, check `busbar_breaker_trips_total` and `/stats` for individual lane state.

Multi-hop fallback chains, `primary → overflow → emergency`, work as long as they form a DAG (no cycles back to a visited pool). A self-referential or cyclic chain is rejected at config validation; a runtime loop is caught by the loop guard and results in a 503.

---
