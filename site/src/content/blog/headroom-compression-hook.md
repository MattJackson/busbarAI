---
title: "Headroom: a compression hook that reports its own savings"
description: "Context compression belongs on the request path, not bolted onto your app. Busbar runs it as a rewrite gate: prompt text in, a smaller body out, before routing and before dispatch. And because the hook self-describes its settings and self-reports its metrics, you configure it and read its savings entirely through the frozen Admin API — no second dashboard."
date: 2026-07-15
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

Compression tools like [Headroom](https://github.com/chopratejas/headroom) ("60–95% fewer tokens, same answers") and Microsoft's [LLMLingua](https://llmlingua.com/) prove the point: most of what you send an LLM is padding. Collapse it and you keep the answer, cut the bill. The usual way to run one is a proxy in front of your app with its own dashboard to watch the savings.

Busbar's position is that compression is not a separate box. It is a **rewrite gate** on the request path: Busbar hands your hook the flattened prompt text, your hook hands back a smaller body, and Busbar dispatches the compressed request — **before routing, before dispatch, persisting across failover**, with token accounting on the provider-reported usage of the rewritten body. The savings are real and measured, not estimated off to the side.

And there is no second dashboard, because the hook feeds its own configuration and its own operational data back through Busbar's frozen Admin API. This post shows the wire, then how to **configure it** and **read its metrics** over that API.

The hook is a small standalone Rust binary that speaks the wire below — nothing links against Busbar; it just answers the protocol over a Unix socket.

## The hook, on the wire

Register it like any gate. The `prompt: rw` grant is what lets a gate return the `rewrite` arm — a hook without it never sees message text at all:

```yaml
hooks:
  headroom:
    kind: gate
    socket: /run/busbar/compress.sock
    prompt: rw                     # rewrite requires the read-write prompt grant
    global: true                   # fire on every request
    settings: { min_savings_pct: 10 }
```

On each request Busbar sends the hook a `transform` message carrying the flattened prompt (`messages: [{role, text}]`). The hook compresses each message and replies with a replacement body in body form — or `{}` to abstain when the savings are not worth a body swap:

```jsonc
// Busbar -> hook  (request.pool names the pool this request is routing through)
{"op": "transform", "request": {"pool": "chat", "messages": [{"role": "user", "text": "…lots of whitespace…"}]}}

// hook -> Busbar  (or "{}" to leave the request untouched)
{"rewrite": {"messages": [{"role": "user", "content": "…collapsed…"}]}}
```

It is fail-safe by construction: a malformed reply, a timeout, or a dead socket means "proceed with the original body." A broken compressor never corrupts — or blocks — a request. That is the whole rewrite contract; the [hooks guide](/docs/hooks/) has the rest.

But the interesting part for an operator is not the compression. It is that the same binary answers three **management** messages — `configure`, `describe`, `status` — and those are what turn the hook into something you run from the Admin API.

## Configure it over the Admin API

The hook **self-describes** its settings. Ask Busbar for the schema and it proxies the hook's own `describe` reply verbatim:

```bash
curl -s -H "x-admin-token: $TOK" \
  http://localhost:8080/api/v1/admin/hooks/headroom/schema
```

```jsonc
{
  "name": "headroom",
  "schema": {
    "type": "object",
    "title": "Headroom compression",
    "properties": {
      "min_savings_pct":  {"type":"integer","minimum":0,"maximum":100,"default":10,
        "description":"Rewrite only when the body shrinks by at least this percent; below it, abstain."},
      "target_ratio_pct": {"type":"integer","minimum":0,"maximum":100,"default":60,
        "description":"Target compressed size as a percent of the original."},
      "min_trigger_chars":{"type":"integer","minimum":0,"default":0,
        "description":"Only attempt compression once the request is at least this many characters."},
      "system_aware":     {"type":"boolean","default":true,
        "description":"System-prompt-aware compression: be conservative near the system prompt."},
      "price_udollars_per_kchar": {"type":"integer","minimum":0,"default":50,
        "description":"Assumed input price (micro-$ per 1K chars) used to estimate dollars saved."}
    }
  }
}
```

That schema is the config form — one declaration, rendered by any tooling that reads JSON Schema. To change a knob live, `PATCH` the settings. Busbar sends the hook a `configure` message and **commits only on the hook's version-echoing ack** (5s deadline); a nack or timeout commits nothing and the PATCH returns `400`. Every future request retunes at once:

```bash
# Raise the savings floor to 25% and bill dollars at a higher input price
curl -s -X PATCH -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data '{"min_savings_pct":25,"price_udollars_per_kchar":75}' \
  http://localhost:8080/api/v1/admin/hooks/headroom/settings
```

The apply is all-or-nothing: one out-of-range value refuses the whole push, so a fat-fingered PATCH never leaves the hook half-configured. Socket hooks also receive the committed settings as the first message on every reconnection, so a restarted hook never runs blind.

## Read its savings over the Admin API

Now the part that makes Busbar a control plane and not just a proxy: how do you get the numbers back out? You query `status`. Busbar live-queries the hook over its own transport and returns `{name, desired, reported, drift, metrics, as_of, source}` — its **observed** settings against Busbar's desired copy (with a `drift` verdict), plus its self-reported `metrics`:

```bash
curl -s -H "x-admin-token: $TOK" \
  http://localhost:8080/api/v1/admin/hooks/headroom/status
```

`metrics` is an **array** of Prometheus/OpenMetrics-shaped entries. That shape matters here for one reason: **one hook process serves many pools.** Register `headroom` as a global gate and it fires on your `chat` pool, your `batch` pool, and your `agents` pool — same binary, three pools. A flat name→value map could only report one number per metric; the array lets the hook emit *one entry per pool*, distinguished by a `labels: {"pool": ...}` dimension. So a single `status` read returns the whole per-pool breakdown, and a dashboard drills down by label:

```jsonc
{
  "name": "headroom",
  "desired":  {"min_savings_pct": 25, "price_udollars_per_kchar": 75},
  "reported": {"min_savings_pct": 25, "target_ratio_pct": 60, "min_trigger_chars": 0,
               "system_aware": true, "price_udollars_per_kchar": 75},
  "drift": false,
  "as_of": "2026-07-13T17:04:11Z",
  "source": "socket",
  "metrics": [
    // chars_saved_total, one entry per pool — same name, different labels.pool
    {"name":"chars_saved_total","type":"counter","value":28927142,
     "labels":{"pool":"chat"},  "label":"Tokens saved","viz":"counter"},
    {"name":"chars_saved_total","type":"counter","value":9044310,
     "labels":{"pool":"batch"}, "label":"Tokens saved","viz":"counter"},

    {"name":"compressed_rate","type":"gauge","value":75.7,
     "labels":{"pool":"chat"},"label":"Compressed rate","unit":"%","viz":"gauge","max":100},

    // dollars_saved is an ESTIMATE (priced off an assumed rate / holdout control),
    // so it is marked estimated and bounded by a confidence interval
    {"name":"dollars_saved","type":"gauge","value":1446.35,"estimated":true,
     "ci_low":1229.40,"ci_high":1663.30,
     "labels":{"pool":"chat"},"label":"Proxy $ saved","unit":"$","viz":"number"},

    // compress latency is a DISTRIBUTION, not a mean: value is the sample count,
    // the p50/p95/p99 ride quantiles
    {"name":"compress_latency_us","type":"histogram","value":128401,
     "quantiles":{"0.5":18,"0.95":54,"0.99":91},
     "labels":{"pool":"chat"},"label":"Compress latency","unit":"us","viz":"histogram"}
  ]
}
```

Three entry types earn their keep. A **counter** or **gauge** carries a scalar `value`. A **histogram** reports a distribution — `value` is the observation count and `quantiles` holds p50/p95/p99, so a slow-tail pool shows up where a mean would hide it. And any value the hook *derived* rather than measured — here the dollars saved, priced off an assumed rate the way Headroom estimates savings from a holdout control — carries `estimated: true` with a `ci_low`/`ci_high` interval, so a dashboard renders it as an estimate with error bars, not a hard fact.

Every entry also carries display hints — `label`, `unit`, `viz`, `max` — so a dashboard renders each tile with no per-plugin code, and the hook's `describe` reply declares the matching widget layout, so **one** declaration drives both the config form and the dashboard. Busbar bounds and sanitizes everything (64 entries per reply, 8 labels per entry; a malformed entry is dropped whole, a malformed optional member individually), so a hook granted `prompt: rw` still cannot smuggle prompt content into a metric name, a label key, or a hint.

The metric set mirrors what a real compression tool surfaces to its users:

| Metric | Type | Meaning |
|---|---|---|
| `requests_seen_total` / `requests_compressed_total` | counter | Traffic seen vs. actually compressed. |
| `compressed_rate` | gauge | Share of requests that cleared the savings threshold. |
| `chars_in_total` / `chars_out_total` / `chars_saved_total` | counter | Before / after / removed — Headroom's headline "tokens saved". |
| `compression_ratio` | gauge | Percent fewer characters across all compressed requests. |
| `dollars_saved` | gauge (estimated + CI) | Estimated input cost saved — Headroom's "Proxy $ saved" tile. |
| `compress_latency_us` | histogram (p50/p95/p99) | Per-request compression latency distribution. |

Every one is reported per pool.

Because it is a normal Admin API read, you scrape it however you already do. Since `metrics` is an array, you select by name and label — here, total dollars saved on the `chat` pool:

```bash
curl -s -H "x-admin-token: $TOK" \
  http://localhost:8080/api/v1/admin/hooks/headroom/status \
  | jq '.metrics[]
        | select(.name=="dollars_saved" and .labels.pool=="chat")
        | {value, ci_low, ci_high}'
```

Or poll it on an interval and let your own dashboard accumulate the time series — that is the consumer's job by design; the hook reports point-in-time state, the scraper keeps the history. And `drift` tells you at a glance whether the hook is running what you pushed: a differing settings version, or a desired key missing or changed in the observed settings, flips it to `true` (it is `null` if the hook doesn't answer), so alerting diffs one field instead of comparing maps.

## Why this shape

The recurring theme of Busbar is that policy is yours and the control plane carries the seam and the guarantees. Compression is exactly that: **which** compressor and **how aggressive** is your judgment, so it stays a hook you own. But an operator still needs to configure it and watch it, and forcing a second dashboard for every plug is the wrong answer.

So the hook feeds Busbar three things — its schema, its observed settings, its metrics — over the same frozen Admin API that manages every other resource. Configure it with a `PATCH`, read its savings with a `GET`, alert on `drift`. One control plane, and the plug's own numbers are in it.

The management-message contract is in the [hooks guide](/docs/hooks/), and the endpoints above are in the [Admin API guide](/docs/admin-api/).
