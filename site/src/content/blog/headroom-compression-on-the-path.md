---
title: "Headroom: context compression on the path"
description: "A rewrite gate that compresses an agent's context before it ships. One integration on Busbar's normalized IR covers every protocol and provider. Measured: ~50% fewer input tokens for sub-millisecond overhead."
date: 2026-07-14
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

When I said 1.3's rewrite gate would have a first real user very soon, this is it. **Headroom**
is a context-compression hook for Busbar, and it's the cleanest demonstration I have of why hooks
belong on the normalized request path.

## The problem it solves

Most of what an agent sends the model is boilerplate. Tool-call output, DB rows, file reads, RAG
retrievals: on every turn the model re-reads a pile of noise you're paying for by the token. The
usual fix is to trim it in your application, and then to trim it again differently for the next
provider, because their limits and dialects differ. It's real work, and you do it more than once.

The [Headroom](https://github.com/headroomlabs-ai/headroom) project, by Tejas Chopra, already
solves the hard part: a fast BM25 compressor (no model, no network) that strips that boilerplate
down while keeping what the request actually needs. What was missing was a way to run it in front
of every model you call without wiring it into every app.

## The hook is thin, because Busbar is doing the placement

Busbar 1.3's rewrite gate is exactly that seam. The Headroom hook is a small binary on a Unix
socket; Busbar hands it each request's flattened content, and it hands back a smaller body. That's
the whole integration. Because the gate fires on Busbar's normalized IR, the canonical form every
request takes after translation, that one hook compresses traffic for all six wire protocols and
every provider behind them, with failover and circuit breaking still underneath it. Write it once,
it works everywhere Busbar works.

And it's fail-safe by construction: if the compressor is slow, wrong, or dead, the request
proceeds with its original body untouched. A broken compressor can never corrupt or block a call.

## What it costs, and what it saves

I measured it two ways, both reproducible. First the hook alone, driven directly over its socket
with no Busbar in the loop: a compression call runs about 150 microseconds (µs) on a 2KB history and 720µs on a
16KB one. Then the honest end-to-end test: the same request stream through two identical Busbar
configs that differ only by the hook, with a recording mock upstream so I could confirm the
smaller prompt actually reached the provider.

On an 11KB noisy tool-log history, the hook cut input tokens from **2,832 to 1,422 per request, a
50% reduction**, and the mock confirmed the compressed body is what shipped upstream. It held
across cross-protocol (anthropic in, openai out) and same-protocol paths alike. Measured one
request at a time, the hook adds about **620 microseconds (µs)** to a request — the with-hook minus
without-hook delta, so the benchmark harness's own round-trip floor cancels out and what's left is
the compression plus its socket round trip. That rides on top of Busbar's own overhead, which its
[benchmark](https://getbusbar.com/docs/benchmark/) clocks in the tens of µs. Total added latency:
well under a millisecond. Short conversational chats, where there's nothing worth trimming, pass
through byte-identical — the hook abstained 100% of the time on them.

That trade is decisive, and it's almost free. On a request whose model call takes two seconds,
620µs of compression is 0.03% of the request, and it buys a prompt half the size that bills for
half the input tokens.

And here's the number that matters for anyone deciding *where* to run compression. Headroom ships
as an HTTP proxy today and reports a **52ms median overhead** in production, which they rightly
note is negligible against inference. Run that exact same compression core as a co-located socket
gate on Busbar's path and the added latency is **sub-millisecond**: no separate proxy service, no
network hop between the gateway and the compressor.

| running Headroom as… | added latency | reach |
|---|---|---|
| its own HTTP proxy | 52ms median | the traffic you point at it |
| a gate on Busbar | ~620µs median | all six protocols, with failover underneath |

That's the division of labor I think is right: **Headroom does the compression, Busbar does the
placement.** Same core, same savings, one fewer moving part to run, and it now covers every
protocol and provider Busbar speaks. Build the best compressor; let the gateway be the gateway.

## Try it

Headroom is open source, and the Busbar hook that runs it lives alongside our other example hooks.
Register it as a global gate and it compresses every request your Busbar handles:

```yaml
hooks:
  headroom:
    kind: gate
    socket: /run/busbar/headroom.sock
    prompt: rw           # the rewrite grant
    global: true         # every request
    on_error: nothing    # a broken compressor never touches a request
```

Full credit to Tejas and the [Headroom](https://headroomlabs-ai.github.io/headroom/) project for
the compression core. Busbar just puts it in front of every model you call.

Get Busbar at **[getbusbar.com](https://getbusbar.com)**.
