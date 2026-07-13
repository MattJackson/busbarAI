# Smart router: task-aware model selection

Pick the best model automatically by task, latency, quality, and cost. It is not a
new product, it is a routing hook: classify each request into a task bucket from
its shape, score every candidate over the live cost / latency / concurrency
signals, sort. Busbar gives the hook two transports: same wire contract, your
choice of speed vs reach.

## The socket hook (`rust-hook/`): a compiled binary, ~8 µs

A `socket:` hook talks to an operator-run binary over a local Unix domain socket.
Measured end to end through busbar's transport against this exact example binary
(separate process, 3 candidates, 50k samples): **~7.9 µs median, p99 ~12 µs**.

```yaml
hooks:
  smart-router:
    kind: gate               # it decides (returns `order`); a tap only watches
    socket: /run/busbar/router.sock
    timeout_ms: 1            # the default hard deadline; raise for slow hooks
    on_error: weighted       # a broken ordering hook falls back to the weighted floor

pools:
  my-smart-model:
    hooks: [smart-router]
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

Run the hook (you own its lifecycle: busbar never spawns it; connection is lazy,
so start order does not matter, and busbar reconnects across hook restarts):

```
cd rust-hook && cargo run --release -- /run/busbar/router.sock
```

Unix-only (macOS/Linux, any architecture). On Windows use the webhook below.

## The webhook (`policy_server.go`): any language, any OS

A `webhook:` hook POSTs the same projection over HTTP to a sidecar you run —
portable everywhere, written in whatever your team already ships. Sub-millisecond
co-located; plus the network if it is not.

```yaml
hooks:
  smart-router:
    kind: gate
    webhook: "http://127.0.0.1:8787/"
    timeout_ms: 1
    on_error: weighted

pools:
  my-smart-model:
    hooks: [smart-router]
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
  `budget_remaining`, `rate_headroom`, `tags` (your free-form member labels;
  omitted when the member declares none).
- Reply: `{"order":[idx,...]}` most-preferred first, `{"abstain":true}`, or
  `{"reject":{"status":451,"message":"..."}}` (no upstream dispatched; status
  clamped to 400-499, message sanitized).

Not in the payload by default: prompt text, message bodies, or caller
identity — the policy classifies on shape, not words. Two per-hook grants
(both default `no`) extend it for hooks you trust with more:
`prompt: ro` adds `request.system` + `request.messages` (`{role, text}`;
`rw` additionally unlocks the `rewrite` reply arm), and `user: ro` adds
`request.user` (the governance key's id/name plus the body's end-user field —
never the secret). That is the PII-screen recipe: `prompt: ro` to see,
`reject` to stop.

## Fail-safe (both transports)

The decision can never take your traffic down. It is bounded by
the hook's `timeout_ms` (default 1 ms; raise it when your hook does I/O or
crosses the network), and on any timeout, crash, malformed reply, or dead hook
busbar coerces the decision to the hook's `on_error` (for an ordering hook,
`weighted` — indistinguishable from no hook). The ranking then feeds the same failover + circuit-breaker loop
everything else uses; a dropped candidate is demoted, not excluded, so a buggy
ranking never strands a healthy model. Kill the hook mid-traffic and requests
keep flowing.

The wire format is documented in the [routing guide](https://getbusbar.com/docs/routing/).

## Benchmark

Numbers and how to reproduce them are in [`bench/`](bench/).
