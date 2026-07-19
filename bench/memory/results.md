# Memory benchmark — measured results

Hardware: **c7g.8xlarge** (Graviton3, 32 vCPU), gateway pinned to 16 cores, dedicated load-gen + mock
cores. Unique request bodies (`-psize` padding), mock upstream. Busbar **1.4.0** (jemalloc + background
purge) vs Bifrost **v1.6.4** on its documented pool config (`initial_pool_size 15000` / `buffer_size
20000`). Measured 2026-07-19.

## Headline (150 KB bodies, 1,500 concurrent, sustained)

| | Busbar 1.4.0 | Bifrost v1.6.4 |
|---|---|---|
| Under load | ~1.2 GB plateau (bounded working set) | ~16–19 GB sawtooth (Go GC) |
| After load stops | falls to ~250 MB within ~30 s | holds its pools (does not release) |
| vs its own idle | bounded, releases | ~14× Busbar; ~5× its own published 3.34 GB |

Time-series in `busbar_ts.csv` (0–390 s: 300 s load + 90 s idle) and `bifrost_ts_150k.csv`.

## Payload scaling (Bifrost)

| Payload | Bifrost peak RSS | Note |
|---|---|---|
| 150 KB | ~16–19 GB | sawtooth plateau, retained |
| 400 KB | ~43 GB | GC-capped; `bifrost_ts_400k.csv` |
| 300 KB, higher concurrency | > 45 GB | OOM-killed a 61 GB box (had to reboot) |
| Bifrost's own published | 3.34 GB | our runs sit well above it |

Busbar under the same loads stays a bounded working set (≈ concurrency × payload × a few copies): the same
150 KB payload at concurrency **200** used only ~140 MB. It is not a leak — a completed request frees its
buffers, and jemalloc's background purge returns the pages to the OS after the burst.

## Why the "~150 MB" snapshot is misleading

A short, small-payload run (or a `docker stats` right after boot) shows Bifrost at ~120–150 MB because the
pools haven't filled. That is a boot snapshot, not a peak. Sustained large-payload load is what fills them —
which is exactly the condition behind Bifrost's own published 3.34 GB figure.

## Reproduce

See `README.md`. `GATEWAY=bifrost bench/memory/run.sh` (container capped so it OOM-kills safely) and
`GATEWAY=busbar BUSBAR_BIN=... bench/memory/run.sh`.
