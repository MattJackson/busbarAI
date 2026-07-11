# Smart-router benchmark

How much latency does the routing decision add? This measures the **decision cost**,
the work the hook does before busbar's failover loop dispatches the request. It is
not a full LLM round trip: end-to-end latency is your upstream plus this.

All numbers on an Apple M5 Pro (18 cores), macOS 26.5, release builds, 3 candidates.

## Socket hook (`route: socket`): ~8 µs

Measured through busbar's REAL transport (`SocketPolicy::decide()`: serialize the
projection, Unix-socket round trip, parse, normalize) against the actual
[`rust-hook`](../rust-hook/) example binary running as a separate process,
50,000 samples:

| metric | value |
|---|---|
| median | ~7.9 µs |
| p95 | ~9.7 µs |
| p99 | ~12 µs |

Reproduce with the probe that ships in busbar:

```
cd rust-hook && cargo run --release -- /tmp/bb-probe.sock &
BUSBAR_SOCKET_PROBE_PATH=/tmp/bb-probe.sock \
  cargo test --release --bin busbar socket_decide_timing -- --nocapture --ignored
```

## Webhook (`route: webhook`): ~34 µs co-located

Measured the same way (busbar's `WebhookPolicy::decide()` against a real external
HTTP sidecar over loopback, 20,000 samples): **~34 µs median, p99 ~47 µs**. The
HTTP framing and TCP round trip cost about 4x the socket transport. A sidecar
across the network costs whatever that hop costs. Either way it is far under the default
`policy.timeout_ms` of 1 ms, after which busbar falls back to the pool's
`on_error` and the request proceeds regardless.

## Why the socket hook replaced the script engine

For the record: the deprecated `route: script` (an embedded Rhai interpreter) ran
the same ranking logic in ~180 µs per decision; the interpreter alone accounts
for ~108 µs, which no transport work can remove. A compiled hook over a local
socket is ~20x faster AND runs in its own process, so a crash is contained. That
is why the fast rung of the hook ladder is a compiled binary, not an embedded
script.
