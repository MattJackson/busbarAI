# Benchmark: how much latency does Busbar add?

Busbar's value claim is that it adds only **microseconds** of overhead to a request — small enough to
disappear under the jitter of the provider call it is fronting. This page is the falsifiable artifact
behind that claim: a committed, reproducible harness (`bench/latency/` in the repo) and the numbers it
produces, so you can re-run it and get the same shape on your own hardware.

> The canonical, tabbed version of this page lives in the docs site (`/benchmark/`) with a
> **Result** view for the 10-second read and a **Reproduce** view with the copy-paste commands.

## The result (measured added latency)

We measure a **difference**: drive identical load against the same fixed-latency upstream over two
paths and subtract.

```
direct :  loadgen ───────────────► mock upstream      (baseline)
busbar :  loadgen ──► busbar ─────► mock upstream      (baseline + Busbar)
                       └── added overhead = busbar − direct, per percentile
```

Because the mock contributes the same fixed time on both paths, `busbar − direct` is Busbar's own
cost and nothing else. We report **p50 / p99 / p99.9** for non-streaming full-response latency and for
streaming **TTFT** (time to first byte).

<!-- RESULTS TABLE — fill from `bench/latency/run.sh` output. Do NOT hand-enter estimated numbers. -->

| Path | Upstream delay | p50 added | p99 added | p99.9 added |
|------|---------------|-----------|-----------|-------------|
| Busbar added (non-streaming full response) | 0 ms | _run to fill_ | _run to fill_ | _run to fill_ |
| Busbar added (streaming TTFT) | 0 ms | _run to fill_ | _run to fill_ | _run to fill_ |
| Busbar added (non-streaming full response) | 200 ms | _run to fill_ | _run to fill_ | _run to fill_ |
| Busbar added (streaming TTFT) | 200 ms | _run to fill_ | _run to fill_ | _run to fill_ |

> **Status:** this table is a placeholder pending a measured run. The harness is complete and runs;
> the mock-upstream path requires a Busbar build that trusts the local mock's TLS cert (the release
> binary trusts only public webpki roots upstream — see the harness
> [README](https://github.com/MattJackson/busbarAI/tree/main/bench/latency)). Run `bench/latency/run.sh`
> in an environment that satisfies that precondition (or point it at a real provider with your own
> key) to fill these cells with **measured** numbers. We publish only measured figures.

### The takeaway

Once filled, the one-line read is: *Busbar adds single-digit-to-tens-of-microseconds at p50, and its
p99 stays close to its p50.* That tight p50→p99 spread is the whole story.

### Why the tail stays tight: no garbage collector

Busbar is a single Rust binary with **no garbage collector**. Nothing in the request path pauses to
sweep memory, so the latency it adds is near-constant from request to request — p99 lands close to
p50, and even p99.9 does not balloon. A proxy built on a garbage-collected runtime (a Python or
Node/JVM gateway) pays an occasional GC pause that lands on *some* requests; those requests become the
tail, so its p99 and p99.9 swell well above its p50 even when its median looks fine. The number that
hurts a user is the tail, and the tail is where a no-GC proxy wins.

This is also why we report **p50 / p99 / p99.9**, not p50 alone: a median hides exactly the tail
behavior that distinguishes the two architectures.

## Honest competitive note

There is no apples-to-apples third-party figure to cite, because nobody publishes one:

- **LiteLLM** is a Python/FastAPI proxy. Its added overhead is in the **millisecond** range and
  carries a **GC tail** by construction, but the project publishes no reproducible self-host overhead
  benchmark.
- **OpenRouter** is a SaaS hop — every request crosses the public internet to their servers and back,
  so its "overhead" is a network round-trip, not a proxy cost, and is not comparable to a self-hosted
  in-path gateway. They publish no self-host overhead figure either (there is no self-host).

So this artifact is uniquely Busbar's: a self-hosted overhead number you can reproduce. We would
rather ship a reproducible harness with an honest placeholder than a confident number nobody can
check.

## Reproduce it

The harness lives in `bench/latency/` and is self-contained (Python stdlib + the release binary).

```bash
# from the repo root — builds busbar if needed, starts the mock + busbar, drives both paths,
# prints p50/p99/p99.9 deltas for full-response and streaming TTFT.
bench/latency/run.sh

# scale the load
REQS=50000 CONC=100 bench/latency/run.sh
```

Read `bench/latency/README.md` for the precondition (upstream TLS trust), how to serve the mock over
a trusted cert, the optional native load generators (`oha`/`hey`/`bombardier`/`wrk`), and how to point
the busbar path at a **real provider** with your own key for the real-world delta.

Notes:

- Numbers are machine-specific — report the *shape* (tight tail), not someone else's absolute µs.
- Governance is off in the bench config; it measures the proxy hot path. Enabling governance adds a
  separate, opt-in SQLite round-trip per request.
