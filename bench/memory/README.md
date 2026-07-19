# Memory under sustained big-payload load

Where [`bench/scaling/`](../scaling/) measures throughput and [`bench/latency/`](../latency/) measures
added latency, this measures **memory** — specifically, what happens to resident memory when a gateway
is held under sustained load with **large** request bodies.

## Why this exists

Bifrost publishes a **3.34 GB** peak-memory figure from its own benchmark. A short, small-payload run
never reproduces it: the pre-allocated pools don't fill, and a one-shot `docker stats` right after boot
reports ~120–150 MB. That 150 MB is a **boot-time snapshot, not a peak** — quoting it next to their own
3.34 GB would be dishonest in the other direction.

So this rig fills the pools the way their big-payload benchmark does: **unique, large request bodies**
(`-psize` bytes) at high concurrency, held for minutes, sampling **peak** resident memory throughout.

## What we measured

c7g.8xlarge (Graviton3), 16-core pin, unique 150 KB request bodies, 1,500 concurrent, mock upstream.
Bifrost v1.6.4 (its documented `initial_pool_size 15000` / `buffer_size 20000`) vs Busbar 1.4.0.
Reproduced **3× in a row** (see `results.md`):

| | Busbar 1.4.0 | Bifrost v1.6.4 |
|---|---|---|
| Behaviour under load | **plateaus** (~1 GB, bounded by in-flight work) | **climbs without bound** |
| After load stops | **falls back toward idle** (jemalloc returns pages) | stays pinned at peak |
| Peak we recorded | ~1 GB | **OOM-killed at a 50 GB container cap** |
| Their own published peak | — | 3.34 GB (this rig blows past it) |

Busbar's memory is the **working set**: `peak concurrency × payload × ~a few copies` (raw bytes → parsed
JSON → outbound). It is bounded — a completed request frees its buffers, so the same 150 KB payload at
concurrency 200 uses only ~140 MB. Busbar 1.4.0 uses jemalloc with a background purge thread, so after a
burst the pages return to the OS and RSS falls back toward idle instead of ratcheting.

Bifrost's memory is its **pools**: they grow as load is held and are not returned, so under sustained
big-payload load resident memory climbs past its own published 3.34 GB — in our runs, straight into an
OOM kill once we let it.

## Run it

Needs Go (mock + load gen), Docker (Bifrost), and a busbar binary.

```sh
# Bifrost — climbs; the 50 GB container cap makes it OOM-KILL safely instead of taking the box down
GATEWAY=bifrost bench/memory/run.sh

# Busbar — bounded plateau, then releases
GATEWAY=busbar BUSBAR_BIN=/path/to/busbar bench/memory/run.sh
```

Knobs (env): `PSIZE` (payload bytes, default 150000), `CONC` (default 1500), `DUR` (seconds),
`CAP_MIB` (watchdog: kills the load if sampled memory crosses this, so an unbounded gateway can't OOM
the box), `CORES` (gateway CPU pin). Files: `mock.go`, `ugen.go` (unique bodies, `-psize` padding),
`bf_config.json` (Bifrost pool config), `bb.providers.yaml` + `bb.config.yaml` (Busbar), `results.md`
(the raw 3× run).

## Safety

An unbounded gateway will OOM the box. `run.sh`'s watchdog kills the load the instant sampled memory
crosses `CAP_MIB`; the Bifrost recipe additionally runs the container under a hard `--memory` cap so the
kernel OOM-kills the container (provably: `docker inspect -f '{{.State.OOMKilled}}'` → `true`) rather
than the host.
