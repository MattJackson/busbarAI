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

I measured it the way Busbar measures itself: from Busbar's own clock. Busbar reports its internal
processing time — everything it did, minus the upstream round-trip — in a standard
`Server-Timing: busbar;dur` header, and the Headroom gate runs synchronously inside that window, so
that number captures exactly what the hook adds. On an 11KB noisy tool-log history, one request at
a time (`busbar;dur`, µs):

| | p50 | p90 | p99 |
|---|--:|--:|--:|
| Busbar alone | 22 | 25 | 30 |
| Busbar + Headroom | 569 | 601 | 634 |
| **Headroom's added cost** | **547** | 576 | 604 |

Two things I like about that. **Busbar itself is 22 microseconds (µs)** — the gateway isn't where
your latency goes. And **Headroom adds ~550 µs** to compress the history, with a tail that barely
moves: p99 is only about 1.1× p50, because Busbar and the hook are both single Rust binaries with
no garbage collector to pause the path.

A word on what this benchmark is *not*. I wasn't measuring how good Headroom's compression is —
that's their craft, and the [Headroom project](https://headroomlabs-ai.github.io/headroom/) reports
higher ratios than the ~50% I saw here (66–94% on some content types), with more to gain from
tuning the keep-ratio. The mock upstream did confirm the compressed prompt really shipped (2,832 →
1,422 input tokens at the default settings, byte-checked at the provider), so the plumbing is sound.
But the number I care about is the *cost of running that middleware on Busbar* — ~550 µs — because
the pitch isn't "Busbar compresses well," it's "Busbar is the fastest place to put middleware like
Headroom on your request path." And when there's nothing to trim — a short conversational chat —
the hook abstains and the request passes through byte-identical.

That trade is decisive, and it's almost free. On a request whose model call takes two seconds,
550 µs of compression is 0.03% of the request, and it buys a prompt half the size that bills for
half the input tokens.

For scale, Headroom ships as an HTTP proxy today and reports a **52ms median overhead** in
production, which they rightly note is negligible against inference. The same compression core, run
as a gate on Busbar, measures in the hundreds of microseconds on Busbar's clock. Both are small
next to the model call, and I won't pretend to know how their proxy is deployed — the point isn't
a race.

That's the division of labor I think is right: **Headroom does the compression, Busbar does the
placement.** Same core, same savings, and it now covers every protocol and provider Busbar speaks,
with failover and circuit breaking underneath it. Build the best compressor; let the gateway be the
gateway.

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
