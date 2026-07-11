# Smart-router benchmark

How much latency does the routing decision add? This measures the **decision cost**,
the work the hook does before busbar's failover loop dispatches the request. It is
not a full LLM round trip: end-to-end latency is your upstream plus this.

All numbers below are on an Apple M5 Pro (18 cores), macOS 26.5.

## Native `smart` policy: ~0.67 microseconds

The native policy classifies, scores, and ranks in-process, compiled, with no
network and no interpreter. Measured over 50,000 iterations for a 3-candidate pool:

| metric | value |
|---|---|
| median | ~666 ns (0.67 us) |
| p99 | ~1.0 us |

Reproduce (the probe ships with busbar under the `script-policy` feature, which
pulls in the comparison interpreter):

```
cargo test --features script-policy --bin busbar native_rank_timing -- --nocapture --ignored
```

This is a rounding error on a request: the whole busbar layer adds tens of
microseconds, so a routing decision at two thirds of a microsecond is free in any
way that matters.

## Webhook: sub-millisecond, plus the network

A `route: webhook` sidecar adds a round trip the native policy does not. Co-located
over loopback, the sidecar decision returns in a fraction of a millisecond; a
sidecar across the network costs whatever that hop costs. Either way it is far under
the default `policy.timeout_ms` of 150 ms, after which busbar falls back to the
pool's `on_error` and the request proceeds regardless. To measure your own sidecar,
time a POST of the request+candidate projection to it over a kept-alive connection
(busbar reuses a connection pool, so cold-connect numbers overstate steady state).

## Why native, not a script

For reference: an earlier prototype ran the same logic through an embedded script
interpreter and measured ~108 us per evaluation, over 100x slower than the compiled
native policy. That is why the shipped in-process answer is native, and why the
webhook (out-of-process, any language) is the escape hatch for custom logic rather
than an in-process scripting engine.
