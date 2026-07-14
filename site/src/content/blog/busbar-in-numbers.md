---
title: "Busbar, in numbers"
ogImage: "/og/busbar-in-numbers.png"
description: "A fast, lightweight, single-binary AI control plane isn't my roadmap. It's what shipped. Straight answers on memory, latency, throughput, reproducibility, and what you actually deploy."
date: 2026-07-01
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

I build **Busbar**: the reliability and fidelity layer for multi-model AI traffic. Point any SDK at one endpoint. Busbar routes across your providers, translates losslessly between six wire protocols, and keeps serving through provider failures, all as a single static Rust binary you run in your own network.

There's a good conversation happening right now about what an AI control plane should cost you in memory, latency, and operational weight. Here are my answers, measured on the shipped binary rather than a roadmap.

## Why a compiled control plane, and why now?

Because a control plane sits in the hot path of every request, and an interpreted, garbage-collected process pays for that on every call. It pays in startup weight, in memory that climbs with concurrency, and in GC pauses that show up as tail latency exactly when you're busiest. A compiled, no-GC data plane removes all three. The industry agrees, which is why gateways are moving to Rust. I already did it: Busbar shipped as a single Rust binary in v1.0, and it's in production today. There's no migration to wait for.

## How much memory does Busbar use?

About **4.5 MB** resident. It idles there and stays there under load. Thousands of concurrent requests don't move it, because a single static binary with no interpreter and no garbage collector has no runtime heap to grow, and nothing that pauses to sweep it. (Measured on the released v1.1.0 binary, Apple Silicon.)

For reference, a widely-used gateway's own published benchmark reports peak memory around **359 MB** for its Python build and about **32 MB** for its new Rust core. Those are different harnesses on different hardware, so read it as orders of magnitude rather than a stopwatch. The shape is the point: less to carry means less to go wrong at 3am.

## How much latency does Busbar add?

The only honest number is its *added* latency: the microseconds Busbar spends parsing, translating, and serializing, not the network and not the model. Busbar measures exactly that on its own clock and can report it in-band on every response via an opt-in `Server-Timing: busbar;dur=` header:

- **38 µs** (0.038 ms) for a small call
- **84 µs** (0.084 ms) for a full 12k-token cross-protocol translation, Anthropic in and a different protocol out, both directions

And the tail stays tight. p99.9 is only about **1.3 to 1.6 times the median**, because a no-GC request path has no pause to spike it. [Full methodology and per-protocol numbers.](/docs/benchmark/)

## How much throughput?

Saturating two pinned cores, Busbar sustained **19,505 req/s** (about 9,750 per core), and the Tokio runtime scales across cores from there.

## Are these benchmarks reproducible?

Yes. The overhead harness (a mock upstream, Busbar, and a load client that times each request in microseconds) is checked in under `bench/`, and Busbar can report its own added latency in-band on every response via the opt-in `Server-Timing` header. You don't have to trust my number. You can read Busbar's overhead on your own traffic, in production, per request. That's the number that can't be cherry-picked.

## How does Busbar compare?

Lower overhead. An order of magnitude less memory. Mine and a widely-used gateway's, each from its own published benchmark.

- **Overhead:** Busbar adds about **38 µs**. The fastest-moving alternative reports about **50 µs** for its Rust core.
- **Memory:** Busbar peaks around **4.5 MB** resident. That same alternative reports about **32 MB** for its Rust build and about **359 MB** for its Python one. Busbar is **7 to 80 times lighter**.

Fair caveat: these are each side's own numbers on its own hardware, so treat the overhead figures as same-class-or-lower rather than a controlled stopwatch. Memory barely moves with CPU, so that gap is real and architectural, not a hardware artifact.

And both sets of numbers are meant to be reproducible. Mine is: the harness is checked in under `bench/`, and Busbar can report its own added latency in-band on every response (an opt-in header), so you can verify it on your own traffic instead of taking my word for it.

I won't call Busbar "the fastest control plane in existence," because I haven't benchmarked every compiled control plane on one machine. What the numbers on the table say today is clear: lower overhead, far less memory, and it shipped.

## Does it speak my API?

Natively, in both directions. Six wire protocols (OpenAI, OpenAI Responses, Anthropic, Gemini, Amazon Bedrock, Cohere) through a superset intermediate representation. Busbar doesn't flatten everything to one vendor's shape, so native features survive the hop: Anthropic thinking blocks, structured-output schemas, Bedrock tool use. Point a Bedrock SDK at Busbar and reach an Anthropic backend, losslessly, streaming included. This is the one thing a Rust rewrite of an OpenAI-normalized gateway still won't give you.

## And when a provider fails?

Busbar fails over inside the request, before your client sees a byte, even mid-stream, across protocol families. A circuit breaker on every provider connection classifies each failure (provider outage, your bad request, context-length, auth or billing) and treats each differently, instead of retrying into a wall.

## What do you actually deploy?

One file. A single static Rust binary, about **9 MB** on disk, with nothing interpreted and nothing garbage-collected in the request path. Linux and macOS on Intel and ARM, Windows on Intel. Your keys never leave your network. No v2, no migration, nothing to wait for.

## Where to start

Busbar is open source at **[getbusbar.com](https://getbusbar.com)**. If you run multi-provider LLM traffic in production, I'd love to talk. I'm taking on design partners.
