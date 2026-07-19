# Busbar throughput & scaling benchmark

The harness and raw data behind the [`/performance`](https://getbusbar.com/performance) headline: **Busbar
scales linearly with cores — ~7,650 req/s per core, ~122,650 req/s on 16 cores at 100% success — while its
own added latency (`Server-Timing: busbar;dur`) stays flat at ~38 µs.** It also runs the *identical* sweep
against Bifrost for the [`/vs/bifrost`](https://getbusbar.com/vs/bifrost) head-to-head.

## The method (one variable at a time, honest)

- **Hardware: one `c7g.8xlarge` (32 vCPU Graviton3).** Graviton has **no hyperthreading**, so 1 vCPU = 1
  physical core — per-core scaling is real, not muddied by shared execution units.
- **The gateway under test is pinned to N cores** (`taskset -c 0..N-1`); the **load generator** gets its own
  cores (16–27) and the **mock upstream** gets its own (28–31). The gateway is never starved, and the mock
  (a fast Go server, ~250k req/s ceiling) is never the bottleneck.
- **Unique request bodies.** `ugen.go` puts a distinct payload in every request. This matters: identical
  bodies let a gateway *cache* and answer without proxying, inflating throughput past what the upstream can
  serve. Unique traffic = every request is real proxy work.
- **Sweep 2 → 16 cores** for both gateways; record req/s at 100% success, plus (for Busbar) `busbar;dur`
  p50/p99 at concurrency 1 and peak RSS.

## Files

| File | Role |
|---|---|
| `ugen.go` | Unique-body load generator (Go). `-url -c <conns> -d <secs> -model -pad <bytes>`. Reports rps / success / p50 / p99. |
| `latency.py` | Concurrency-1 client that reads `Server-Timing: busbar;dur` and reports p50/p90/p99 in µs. |
| `bb_grav.sh` | Busbar sweep: pins Busbar to 2..16 cores, measures throughput + `busbar;dur` + RSS per point. |
| `bf_grav.sh` | Bifrost sweep: identical, via `docker --network host --cpuset-cpus`. |
| `bb_grav.csv` / `bf_grav.csv` | Raw per-core results from the canonical 2026-07-19 run. |

## Results (2026-07-19, c7g.8xlarge, unique traffic, 100% success)

| cores | Busbar req/s | Busbar `busbar;dur` p99 | Bifrost req/s |
|--:|--:|--:|--:|
| 2 | 15,692 | 40 µs | 2,761 |
| 4 | 30,920 | 37 µs | 5,597 |
| 8 | 63,453 | 37 µs | 10,854 |
| 12 | 93,876 | 38 µs | 15,904 |
| 16 | **122,650** | 38 µs | **20,682** |

Busbar is linear at ~7,666 req/s per core; Bifrost is linear at ~1,290 — **~6× the work per core, same
box, same method.** Full method + every gotcha (why `--network host`, why unique bodies, the
`BUSBAR_WORKER_THREADS` default, the mock-ceiling sanity check) is in the internal benchmark runbook.

## Reproduce

Launch a `c7g.8xlarge` (AL2023 arm64). Install `git golang docker python3`, build the Go mock
(`maximhq/bifrost-benchmarking/mocker`), fetch `oha` (arm64) and the released Busbar arm64 binary, build
`ugen`. Then run `bb_grav.sh` and `bf_grav.sh`. Note: pre-1.4 Busbar caps worker threads at `min(cores,4)`
by default — the scripts set `BUSBAR_WORKER_THREADS=N` to unlock full-core scaling (1.4.0 makes that the
default). Tear the box down when done.
