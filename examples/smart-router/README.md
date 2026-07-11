# Smart router: task-aware model selection

Pick the best model automatically by task, latency, quality, and cost. It is not a
new product, it is a routing hook: classify each request into a task bucket from
its shape, score every candidate over the live cost / latency / concurrency
signals, sort. Busbar gives you two ways to run it.

## Answer one: the native `smart` policy (ships with busbar)

No sidecar, no code. Classify + score + rank runs in-process, compiled, in about
**0.67 microseconds** per decision (see `bench/`).

```yaml
pools:
  chat:
    route: smart
    members:
      - target: claude-sonnet
        tier: large        # your quality judgment, as data
        cost_per_mtok: 3.0
      - target: gpt-4o-mini
        tier: small
        cost_per_mtok: 0.15
```

You set `tier` and `cost_per_mtok` on each member; the policy does the rest, per
request. A code request (tools present) weights capability and boosts the `large`
tier; a bulk request (single-shot, non-streaming) weights cost. Nothing else to run.

## Answer two: your own webhook, any language (`policy_server.go`)

When you want your own logic, weights you tuned on your own evals, or a rule the
native policy does not have, write a webhook. Busbar POSTs the same request +
candidate projection before each failover loop and reads back `{"order":[idx,...]}`.

```yaml
pools:
  chat:
    route: webhook
    policy:
      url: "http://127.0.0.1:8787/"
      timeout_ms: 150        # hard deadline; on expiry -> on_error
      on_error: weighted     # a broken sidecar is indistinguishable from no policy
    members:
      - target: claude-sonnet
        tier: large
        cost_per_mtok: 3.0
      - target: gpt-4o-mini
        tier: small
        cost_per_mtok: 0.15
```

Run the example sidecar (Go standard library only, no dependencies):

```
go run policy_server.go            # listens on 127.0.0.1:8787
```

### What the sidecar receives (and does not)

- `request`: `pool`, `ingress_protocol`, `message_count`, `has_tools`,
  `total_chars`, `max_tokens`, `stream`.
- `candidates[]`: `idx`, `model`, `tier`, `cost_per_mtok`, `latency_ms`
  (rolling EWMA, `null` until the lane has served), `available_concurrency`,
  `budget_remaining`, `rate_headroom`.

Not in the payload: prompt text or message bodies. Busbar sends no request content
by default, so the policy classifies on shape, not words.

## Fail-safe (both paths)

The decision can never take your traffic down. It is bounded by `policy.timeout_ms`
(default 150 ms), and on any timeout, crash, non-2xx, or malformed reply busbar
coerces the decision to the pool's `on_error` (default `weighted`). The ranking
then feeds the same failover + circuit-breaker loop everything else uses; a dropped
candidate is demoted, not excluded, so a buggy ranking never strands a healthy model.

The wire format is documented in the [routing guide](https://getbusbar.com/docs/routing/).

## Benchmark

How much latency each path adds, and how to reproduce it, is in [`bench/`](bench/).
