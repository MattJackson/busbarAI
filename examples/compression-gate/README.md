# Compression gate: rewrite the request body before it ships

A **rewrite gate** — the hook arm that replaces a request's body before dispatch — dressed as the
real [**Headroom**](https://github.com/chopratejas/headroom) context-compression tool ("Compress
tool outputs, logs, files, and RAG chunks before they reach the LLM. 60-95% fewer tokens, same
answers"). The compressor here just collapses whitespace runs (deliberately trivial, so the wire is
the lesson); swap `compress_text` for a real semantic compressor and everything around it stays the
same. The point is that a hook exposes **its own configuration** (via `describe`) and **its own
operational data** (via `status`), exactly the settings + metrics Headroom surfaces on its own
`headroom dashboard`.

## Register it

```yaml
hooks:
  headroom:
    kind: gate
    socket: /run/busbar/compress.sock
    prompt: rw                     # rewrite requires the read-write prompt grant
    global: true                   # fire on every request
    settings: { min_savings_pct: 10 }
```

Run the hook (you own its lifecycle; busbar lazy-connects and reconnects across restarts):

```sh
cd rust-hook && cargo run --release -- /run/busbar/compress.sock
```

## What rides the wire

Because the hook is registered `prompt: rw`, busbar projects the flattened prompt text
(`messages: [{role, text}]`) into each `transform` call; the hook replies with a replacement body in
body form (`{"rewrite": {"messages": [{role, content}]}}`) — or `{}` to abstain when the savings
aren't worth a body swap. The rewrite fires **before routing and before dispatch**, persists across
failover, and token accounting uses the provider-reported usage of the rewritten body: the savings
are real and measured. Per-request messages carry an `op` field: this gate handles `transform`,
writes **nothing** for a tap `notify`, and replies `{}` to any unknown/future `op`.

## Configuration — exposed via `describe.schema`

`describe` returns the self-description **envelope** `{schema, dashboard}`. The `schema` is a JSON
Schema for the hook's knobs, served verbatim at `GET /api/v1/admin/hooks/headroom/schema` and used
to render the config form; a `configure` push applies them (all-or-nothing — one out-of-range value
refuses the whole push with no ack, so busbar keeps the previous settings). The Headroom-style
knobs:

| Setting | Type | Meaning |
|---|---|---|
| `min_savings_pct` | int 0–100 | Rewrite only when the body shrinks by at least this percent; below it, abstain. |
| `target_ratio_pct` | int 0–100 | Target compressed size as a percent of the original (Headroom's compression target). |
| `min_trigger_chars` | int ≥ 0 | Only attempt compression once the request is at least this many characters. |
| `system_aware` | bool | System-prompt-aware compression: be conservative near the system prompt. |
| `price_udollars_per_kchar` | int ≥ 0 | Assumed input price (micro-$ per 1K chars) used to estimate dollars saved. |

## Data — reported via `status.metrics` + a declared dashboard

`status` returns the hook's **observed** settings plus its own operational metrics, surfaced at
`GET /api/v1/admin/hooks/headroom/status` (with a desired-vs-reported drift verdict). `metrics` is
an **array** of Prometheus/OpenMetrics-shaped entries
(`{name, type, value, labels?, quantiles?, estimated?, ci_low?, ci_high?, label?, unit?, viz?,
max?, help?}`). Each entry carries display hints (`label`/`unit`/`viz`/`max`) so a dashboard renders
it without per-plugin code; the matching widget layout is declared in `describe.dashboard`, so
**one** declaration drives both the config form and the dashboard tiles.

**Every counter/gauge is reported PER POOL.** One hook process serves N pools; the hook reads
`request.pool` on each transform, accumulates per pool, and emits one entry per pool via the
`labels: {"pool": ...}` dimension — so a single `status` read returns the whole per-pool breakdown
(the "same hook on 3 pools" picture) and a dashboard drills down by label. The metric set mirrors
Headroom's dashboard:

| Metric | Type | Hint | What it is |
|---|---|---|---|
| `requests_seen_total` | counter | counter | Transform requests observed on the compression path. |
| `requests_compressed_total` | counter | counter | Requests whose savings cleared `min_savings_pct`. |
| `chars_in_total` / `chars_out_total` | counter | counter | Input / output characters on compressed requests (before / after). |
| `chars_saved_total` | counter | counter | Characters removed — Headroom's headline "tokens saved". |
| `compression_ratio` | gauge | gauge `%` max 100 | Percent fewer characters across all compressed requests. |
| `compressed_rate` | gauge | gauge `%` max 100 | Share of seen requests that cleared the threshold. |
| `dollars_saved` | gauge | number `$` | Estimated input cost saved (`estimated: true` + `ci_low`/`ci_high`, mirroring Headroom's holdout-control savings). |
| `compress_latency_us` | histogram | histogram `us` | Per-request compression latency distribution (`quantiles` p50/p95/p99). |

Counters end `_total` and metric names + label keys match `^[a-z][a-z0-9_]{0,63}$`; a `histogram`
carries its distribution in `quantiles` (probability-string keys in `[0,1]`) and an estimate carries
`estimated` + a `ci_low`/`ci_high` interval. busbar validates, bounds (64 entries/reply, 8
labels/entry), and sanitizes every entry, hint, and label value.

## Fail-safe

Everything degrades to the original body: a malformed reply, a timeout, a dead socket — with the
default `on_error: nothing` the gate simply drops out of the decision. A broken compressor never
corrupts (or blocks) a request. `describe` and `status` are fully optional; the socket `configure`
preamble is not — a hook that never acks it has every connection rejected.

Unix-domain sockets are macOS/Linux; on Windows register the same hook as a `webhook:` transport.
