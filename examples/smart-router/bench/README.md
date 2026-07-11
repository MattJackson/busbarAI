# Smart-router benchmark

How much latency does the routing hook add? This measures the **decision cost**,
the work the hook does before busbar's failover loop dispatches the request. It
is not a full LLM round trip: end-to-end latency is your upstream plus this.

## Webhook decision latency

`bench_webhook.py` boots the `policy_server.py` sidecar and times the exact call
busbar's `route: webhook` transport makes per request: serialize a
request-plus-candidates projection, POST it over a **kept-alive** localhost
connection (busbar reuses a connection pool, so a cold-connect number would
overstate steady state), read back the ranked order. Standard library only.

```
python3 bench_webhook.py            # 5000 samples, 3 candidates
python3 bench_webhook.py 20000 8    # samples, candidate count
```

### Result

Measured on an Apple M5 Pro (18 cores), macOS 26.5, Python 3.14, 3 candidates,
5,000 samples, kept-alive localhost:

| metric | value |
|---|---|
| median | ~0.13 ms |
| p95 | ~0.14 ms |
| p99 | ~0.15 ms |

A co-located sidecar adds well under a millisecond before dispatch. A sidecar
across the network costs whatever that hop costs. Either way it is far under the
default `policy.timeout_ms` of 150 ms, after which busbar coerces the decision to
the pool's `on_error` fallback and the request proceeds regardless.

## In-process (Rhai) decision latency

The `route: script` path runs the same logic in-process with no network. Its
benchmark is being finalized against a busbar performance fix and will be
published, version-stamped, alongside that release. The measurement tool is the
`rhai_decide_timing` probe in `src/routing/script.rs` (run with
`--features script-policy ... --ignored`).
