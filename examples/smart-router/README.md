# Smart router: task-aware model selection

Pick the best model automatically by task, latency, quality, and cost. It is not a
new product, it is a routing hook: classify each request into a task bucket from
its shape, score every candidate over the live cost / latency / concurrency
signals, sort. Busbar gives the hook two transports — same wire contract, your
choice of speed vs reach.

## The socket hook (`rust-hook/`): a compiled binary, ~8 microseconds

`route: socket` talks to an operator-run binary over a local Unix domain socket.
Measured end to end through busbar's transport against this exact example binary
(separate process, 3 candidates, 50k samples): **~7.9 us median, p99 ~12 us**.

```yaml
pools:
  chat:
    route: socket
    policy:
      socket: /run/busbar/router.sock
      timeout_ms: 1          # the default hard deadline; raise for slow hooks
      on_error: weighted     # a broken hook is indistinguishable from no hook
    members:
      - target: claude-fable
        tier: fable          # best and most expensive ...
        cost_per_mtok: 25.0
      - target: claude-opus
        tier: opus
        cost_per_mtok: 15.0
      - target: claude-sonnet
        tier: sonnet
        cost_per_mtok: 3.0
      - target: claude-haiku
        tier: haiku          # ... down to cheap and fast
        cost_per_mtok: 0.8
```

Run the hook (you own its lifecycle — busbar never spawns it; connection is lazy,
so start order does not matter, and busbar reconnects across hook restarts):

```
cd rust-hook && cargo run --release -- /run/busbar/router.sock
```

Unix-only (macOS/Linux, any architecture). On Windows use the webhook below.

## The webhook (`policy_server.go`): any language, any OS

`route: webhook` POSTs the same projection over HTTP to a sidecar you run —
portable everywhere, written in whatever your team already ships. Sub-millisecond
co-located; plus the network if it is not.

```yaml
pools:
  chat:
    route: webhook
    policy:
      url: "http://127.0.0.1:8787/"
      timeout_ms: 1
      on_error: weighted
    members:
      - target: claude-fable
        tier: fable          # best and most expensive ...
        cost_per_mtok: 25.0
      - target: claude-opus
        tier: opus
        cost_per_mtok: 15.0
      - target: claude-sonnet
        tier: sonnet
        cost_per_mtok: 3.0
      - target: claude-haiku
        tier: haiku          # ... down to cheap and fast
        cost_per_mtok: 0.8
```

```
go run policy_server.go            # listens on 127.0.0.1:8787
```

## One wire contract, two transports

Both transports carry the identical JSON, so a hook graduates from a webhook
prototype to a compiled socket binary without changing its logic:

- `request`: `pool`, `ingress_protocol`, `message_count`, `has_tools`,
  `total_chars`, `max_tokens`, `stream`.
- `candidates[]`: `idx`, `model`, `tier`, `cost_per_mtok`, `latency_ms`
  (rolling EWMA, `null` until the lane has served), `available_concurrency`,
  `budget_remaining`, `rate_headroom`.
- Reply: `{"order":[idx,...]}` most-preferred first, or `{"abstain":true}`.

Not in the payload: prompt text or message bodies. Busbar sends no request
content by default, so the policy classifies on shape, not words.

## Fail-safe (both transports)

The decision can never take your traffic down. It is bounded by
`policy.timeout_ms` (default 1 ms; raise it when your hook does I/O or crosses the network), and on any timeout, crash, malformed reply,
or dead hook busbar coerces the decision to the pool's `on_error` (default
`weighted`). The ranking then feeds the same failover + circuit-breaker loop
everything else uses; a dropped candidate is demoted, not excluded, so a buggy
ranking never strands a healthy model. Kill the hook mid-traffic and requests
keep flowing.

The wire format is documented in the [routing guide](https://getbusbar.com/docs/routing/).

## Benchmark

Numbers and how to reproduce them are in [`bench/`](bench/).
