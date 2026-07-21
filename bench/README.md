# busbar gateway benchmarks

Head-to-head benchmarks for AI gateways — **busbar** against **LiteLLM (Rust)**, **LiteLLM
(Python)**, **Bifrost**, and whatever else you drop in. Same box, same mock, same load, same cpu
pin, for every gateway. One command runs it; the charts regenerate from raw results; every source
ref is pinned in the open and the built commit is stamped into the output.

No cherry-picked idle snapshots, no "believe us," no numbers you can't regenerate. If a gateway
can't serve the endpoint, the result says `served: false` instead of quietly dropping it.

## Run it — one command, every metric

```sh
BUSBAR_BIN=/path/to/busbar bench/run-all.sh                 # all gateways, all metrics
BUSBAR_BIN=/path/to/busbar bench/run-all.sh busbar litellm-rust   # a subset
```

One run measures **latency, throughput, and memory** for every gateway on the same box, then
regenerates the charts. On a fresh cloud box (builds every gateway, pulls results back, terminates
the box — nothing to set up):

```sh
BUSBAR_REPO=/path/to/busbarAI bench/run-on-ec2.sh          # one-click, Graviton
```

Out comes `results/perf/<gateway>.json`, `results/memory/<gateway>.json`, and the chart PNGs
(`results/added_latency.png`, `results/rps_ceiling.png`, `results/memory_rss.png`).

## What it measures

**`perf/`** — what the system can *do* (the metrics that matter most):

- **added latency (µs)** — p99 the gateway adds over the upstream at concurrency 1
  (gateway p99 − direct-to-mock p99). Microseconds, because at this scale ms hides the story.
- **RPS ceiling** — highest sustained requests/sec with p99 under 1 s and **zero errors** —
  "how much can it carry before it falls over."

**`memory/`** — resident memory across a request's life (matters most at GB scale):

- **idle RSS** — right after the gateway first answers `200`, before any load.
- **peak RSS** — highest RSS under sustained large-payload load.
- **post-load RSS** — 15 s after load stops: does it release, or stay pinned? A gateway that pools
  memory and never returns it looks fine on a boot-time `docker stats` and then eats your node.

## Add a gateway

Drop a directory under [`gateways/`](gateways/) with a `gateway.sh` manifest — four variables, four
functions. The runners are gateway-agnostic; there is nothing else to edit. See
[`gateways/README.md`](gateways/README.md).

## Honesty notes (the receipts)

- **Source refs are config, not defaults buried in a script.** Everything is pinned in
  [`gateways/versions.env`](gateways/versions.env) and overridable; the *actual* version/commit
  built is written into each result's `build` field. "You used an old branch" is answerable by
  pointing at the file and the recorded commit.
- **Each gateway is launched the only way it actually serves the endpoint.** For example,
  LiteLLM-Rust's `/v1/messages` route only serves the `azure_ai` provider *and* only serves at all
  under its `python-config` reader (the lean env config returns `400`) — verified against its own
  source. We launch it that way and record what it costs, rather than quoting an idle number from a
  config that doesn't serve. The reasoning is in
  [`gateways/litellm-rust/gateway.sh`](gateways/litellm-rust/gateway.sh).
- **The mock is deterministic and dumb** — it answers any path with a fixed small body (OpenAI shape,
  or Anthropic shape for `/messages`), so the number is the *gateway's* cost, not the upstream's.
- **The chart colors by measurement, not by name.** Green goes to whichever gateway measured lowest.
  If busbar loses a metric, busbar isn't green on it.

## Why this exists

Gateway vendors publish memory and latency numbers that don't survive a re-run — measured on
undisclosed hardware, from configs that don't serve the endpoint, with the winner hardcoded. This
repo is the opposite: click, run, get the answer, check our work. That's the whole point.
