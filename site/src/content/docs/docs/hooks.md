---
title: "Hooks: your logic on the request path"
description: "Your logic on the request path: the routing policy hook and the request-log hook, what each receives, what you control, and the fail-safe guarantees."
---

Busbar owns the request path. Hooks are the sanctioned attachment points on it: the places where your own code sees what Busbar sees and steers what Busbar does. Every hook follows one design rule, enforced structurally rather than by convention: **a hook can steer and a hook can observe, but a hook can never break the request path.** A slow, crashed, or wrong hook degrades to a safe default; it never blocks, hangs, or fails a request on its own.

Busbar ships two hooks today.

| Hook | Direction | What it does | Deep reference |
|---|---|---|---|
| Routing policy | Busbar asks you | Decide the ORDER in which pool members are tried, per request | [Routing](https://getbusbar.com/docs/routing/) |
| Request log | Busbar tells you | Receive a JSON record of every completed request | [Observability](https://getbusbar.com/docs/observability/) |

---

## The routing policy hook

Set `route: webhook` (an HTTP sidecar in any language) or `route: script` (an in-process, sandboxed [Rhai](https://rhai.rs) script) on a pool, and your logic runs once per request, before the failover loop.

### What you receive

Two things: a projection of the request, and a projection of every candidate lane.

**The request projection** (what kind of work is this?):

| Field | Meaning |
|---|---|
| `pool` | The pool being routed |
| `ingress_protocol` | Which dialect the client spoke (`openai`, `anthropic`, `gemini`, `bedrock`, `cohere`, `responses`) |
| `message_count` | Messages in the conversation |
| `has_tools` | Whether tools are declared (scripts also get `tool_count`) |
| `total_chars` | Text size across system + messages (~4 chars per token as a rule of thumb; token counts do not exist pre-dispatch) |
| `max_tokens` | The caller's requested output cap, if any |
| `stream` | Whether this is a streaming call |

Scripts additionally get `requested_model` and `system_chars`.

**The candidate projection** (what state is each option in?), one entry per healthy pool member:

| Signal | Field | Where it comes from |
|---|---|---|
| Cost | `cost_per_mtok` | Operator-declared on the member |
| Latency | `latency_ms` | Rolling EWMA per lane, updated every request |
| Live load | `available_concurrency` | Free semaphore slots, right now |
| Budget | `budget_remaining` | Per-lane `max_requests` remaining |
| Rate headroom | `rate_headroom` | Remaining RPM/TPM headroom as a fraction, from governance counters |
| Your labels | `tier`, `tags` | Operator-declared routing metadata on the member |

This is the full task/latency/cost/quality picture: the request tells you the task, the candidates carry live latency and load, cost is your declared number, and quality is your judgment encoded in `tier` and `tags` (Busbar gives you the enforcement point; it does not pretend to know which model writes better poetry).

### What you control

You return a **ranked preference list** of candidate indices. That order becomes the failover walk: Busbar tries your first choice, and if it fails before the first byte, your second, and so on. You are choosing the order, not bypassing the machinery — the circuit breaker still gates tripped lanes, concurrency caps still apply, and the failover budget still bounds the request.

You can also return an **abstain**, which means "no opinion, use the default weighted selection."

### What you cannot do

- You cannot mutate the request. Policies rank; they do not rewrite. (Request/response mutation hooks — the shape guardrails, PII steering, and audit need — are the planned next tenant of this same fail-safe machinery. See the [roadmap](https://getbusbar.com/docs/roadmap/).)
- You cannot make Busbar wait. The decision is bounded by `policy.timeout_ms` (default 150 ms), hard.
- You cannot see the message text. The projection carries sizes, counts, and flags, not content — your prompts do not leave the process just to make a routing decision.

### What Busbar guarantees when your hook misbehaves

| Failure | What happens |
|---|---|
| Hook is slow | Cut off at `timeout_ms`, decision coerced to `on_error` |
| Hook errors, returns garbage, or is saturated | Same: `on_error` |
| `on_error: weighted` (default) | Falls back to the standard weighted selection — a broken hook is indistinguishable from no hook |
| `on_error: first` | Config order, deterministic |
| `on_error: reject` | Fail closed with a 503, for pools where an unrouted request is worse than no request |

Boot-time safety: a webhook URL is operator-config-only (never derived from a request) and validated against the SSRF blocklist at startup; scripts run under sandbox limits (see the routing guide). Every routed response can carry `x-busbar-route-policy` / `x-busbar-route-target` headers so you can see which policy made the call.

---

## The request-log hook

Set `observability.request_log_webhook_url` and Busbar fires a fire-and-forget JSON POST for every completed request:

```json
{ "ts": 1760000000, "ingress_protocol": "openai", "pool": "fast", "outcome": "ok", "latency_ms": 412 }
```

Pipe it anywhere: your SIEM, a Lambda, a log store, an S3 writer. Guarantees, same philosophy as above:

- **Never on the request path.** Delivery is async with a 2-second timeout and at most 64 in flight; under pressure it drops rather than queues, and the client response is never delayed by it.
- **SSRF-guarded and `https://` only.** The URL is operator config; RFC-1918, link-local, CGNAT, broadcast, and cloud-metadata targets are rejected at boot.

For metrics and traces (rather than per-request records), Busbar also ships Prometheus `/metrics` and an OTLP trace exporter — those are pull/push telemetry, not hooks, and live in [Observability](https://getbusbar.com/docs/observability/).

---

## Where hooks are going

The routing hook is the first tenant of a general mechanism: bounded, fail-safe operator logic on the request path. The same machinery is built to carry request/response mutation next — guardrails, PII steering, audit — where "your code sees the request" needs more than sizes and counts. Same rules will apply: hard timeouts, safe fallbacks, SSRF-guarded destinations, and no hook ever able to take Busbar down with it.
