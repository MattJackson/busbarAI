# Busbar soak rig

Where [`bench/latency/`](../latency/) measures how **fast** Busbar is, this measures whether it
**stays** that fast: sustained load through Busbar against the instant mock upstream for
`SOAK_MINUTES`, with three verdicts at the end.

| Verdict | Gate | What it catches |
|---|---|---|
| Zero errors | every batch `errors == 0` | fd/socket/permit leaks surfacing as late-run failures |
| Latency drift | last batch p99 ≤ `DRIFT_FACTOR`× first batch p99 (default 3×) | leaks that show up as steadily-growing tail latency |
| Memory drift | final RSS ≤ first-stable RSS × `RSS_FACTOR` + `RSS_SLACK_MB` (default ×1.25 + 50 MB) | unbounded per-request allocation growth |

## Run

```sh
bench/soak/run.sh                          # 10-minute soak, defaults
SOAK_MINUTES=60 CONC=64 bench/soak/run.sh  # longer + heavier
```

Exit 0 = all verdicts pass; non-zero prints the failing verdict. Raw batch results land in
`results/batches.jsonl`, RSS samples in `results/rss.jsonl`.

## Precondition

Identical to the latency bench: Busbar's release binary only connects to the mock over
publicly-trusted TLS on a non-loopback hostname — see
[`bench/latency/README.md`](../latency/README.md), *"Serving the mock over trusted TLS"*. The
script probes the busbar→mock hop first and aborts with a clear message rather than soaking a
broken path.

## Knobs

| Env | Default | Meaning |
|---|---|---|
| `SOAK_MINUTES` | `10` | total soak duration |
| `BATCH_REQS` | `5000` | requests per loadgen batch |
| `CONC` | `32` | concurrent connections |
| `DRIFT_FACTOR` | `3.0` | p99 last/first ceiling |
| `RSS_FACTOR` / `RSS_SLACK_MB` | `1.25` / `50` | memory ceiling: first-stable × factor + slack |
