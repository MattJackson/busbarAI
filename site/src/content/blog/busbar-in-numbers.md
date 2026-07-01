---
title: "Busbar, in numbers"
description: "A fast, lightweight, single-binary AI gateway isn't our roadmap — it's what shipped. Straight answers on memory, latency, throughput, reproducibility, and what you actually deploy."
date: 2026-07-01
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

We build **Busbar**: the reliability and fidelity layer for multi-model AI traffic. Point any SDK at one endpoint; Busbar routes across your providers, translates *losslessly* between six wire protocols, and keeps serving through provider failures — as a single static Rust binary you run in your own network.

There's a good conversation happening right now about what an AI gateway should cost you in memory, latency, and operational weight. Here are our answers — measured on the shipped binary, not a roadmap.

## Why a compiled gateway, and why now?

Because a gateway sits in the hot path of every request, and an interpreted, garbage-collected process pays for that on every call: startup weight, memory that climbs with concurrency, and GC pauses that show up as tail latency exactly when you're busiest. A compiled, no-GC data plane removes all three. The industry agrees — it's why gateways are moving to Rust. We just **already did it**: Busbar shipped as a single Rust binary in v1.0, and it's in production today. There's no migration to wait for.

## How much memory does Busbar use?

About **4.5 MB** resident. It idles there and *stays* there under load — thousands of concurrent requests don't move it, because a single static binary with no interpreter and no garbage collector has no runtime heap to grow, and nothing that pauses to sweep it. *(Measured on the released v1.1.0 binary, Apple Silicon.)*

For reference, a widely-used gateway's own published benchmark reports peak memory around **359 MB** for its Python build and about **32 MB** for its new Rust core. Those are different harnesses on different hardware — read it as orders of magnitude, not a stopwatch — but the shape is the point: **less to carry means less to go wrong at 3am.**

## How much latency does Busbar add?

The only honest number is its *added* latency — the microseconds Busbar spends parsing, translating, and serializing, not the network and not the model. Busbar measures exactly that on its own clock and reports it in-band on every response (`Server-Timing: busbar;dur=`):

- **38 µs** (0.038 ms) for a small call
- **84 µs** (0.084 ms) for a full 12k-token *cross-protocol* translation — Anthropic in, a different protocol out, both directions

And the tail stays tight: p99.9 is only **~1.3–1.6× the median**, because a no-GC request path has no pause to spike it. [Full methodology and per-protocol numbers →](/benchmark/)

## How much throughput?

Saturating two pinned cores, Busbar sustained **19,505 req/s** (~9,750 per core), and the Tokio runtime scales across cores from there.

## Are these benchmarks reproducible?

Yes. The overhead harness — a mock upstream, the gateway, and a load client that times each request in microseconds — is checked in under `bench/`, and Busbar reports its own added latency **in-band on every response** via `Server-Timing`. You don't have to trust our number: you can read Busbar's overhead on your *own* traffic, in production, per request. That's the number that can't be cherry-picked.

## Is Busbar the fastest LLM gateway?

It's in the fastest class there is: sub-0.1 ms overhead, no garbage collector, a tail that doesn't blow out. We won't claim a stopwatch win over every compiled gateway — at these numbers, gateway overhead is already a rounding error against model latency. Where Busbar clearly leads is **memory** (single-digit MB, the lightest we've measured shipped) and **fidelity** — which is the part raw speed can't buy.

## Does it speak my API?

Natively, both directions. Six wire protocols — OpenAI, OpenAI Responses, Anthropic, Gemini, Amazon Bedrock, Cohere — through a superset intermediate representation. We do **not** flatten everything to one vendor's shape, so native features survive the hop: Anthropic thinking blocks, Gemini safety settings, Bedrock tool use. Point a Bedrock SDK at Busbar and reach an Anthropic backend, losslessly, including streaming. This is the one thing a Rust rewrite of an OpenAI-normalized gateway still won't give you.

## And when a provider fails?

Busbar fails over *inside the request* — before your client sees a byte, even mid-stream, across protocol families. A circuit breaker on every provider connection classifies each failure — provider outage vs. your bad request vs. context-length vs. auth/billing — and treats each differently, instead of retrying into a wall.

## What do you actually deploy?

One file. A single static Rust binary — **~9 MB** on disk — with no Python sidecar, no interpreter, and no GC in the request path. Linux, macOS, Windows; Intel and ARM. Your keys, your network, your data path. No v2, no migration, nothing to wait for.

## Where to start

Busbar is open source at **[getbusbar.com](https://getbusbar.com)**. If you run multi-provider LLM traffic in production, we'd like to talk — we're taking on design partners.
