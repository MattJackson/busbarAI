---
title: "Why I'm building Busbar"
ogImage: "/og/why-im-building-busbar.png"
description: "As teams go multi-model, the control plane becomes critical infrastructure, and 'flatten everything to OpenAI and retry on failure' isn't enough. Before I write a line of code, here's what I'm setting out to build."
date: 2026-05-01
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

Before I write a line of code, I want the "why" on the record. There's no repo yet, nothing to install, just a conviction about the piece of infrastructure the multi-model era is missing, and a description of what I'm setting out to build.

## The problem

Every serious AI application is becoming multi-model and multi-provider. You want Claude for one thing, GPT for another, a cheap model for classification, and a fallback when your primary is rate-limited. The moment you have more than one provider, something has to sit between your app and all of them. That something is a control plane.

The gateways that exist today mostly do two things. They flatten every provider to OpenAI's shape, and they retry on failure. Both are quietly lossy.

- **Flattening to OpenAI** throws away what makes each provider worth using: Anthropic's thinking blocks, Gemini's safety settings, Bedrock's tool-use envelope. You get portability by giving up capability.
- **Retry-on-failure** is error handling, not failover. The call throws, and then something retries, after your user already felt the stall. And a naive retry can hammer a provider that's already down.

Neither is wrong, exactly. They're just not enough once the control plane is load-bearing infrastructure.

## What I'm building

Busbar is the reliability and fidelity layer for multi-model AI traffic:

- **Lossless translation, both ways.** Speak any of six wire protocols in, any provider out, through a superset intermediate representation, so native features survive the hop instead of being flattened away.
- **Failover inside the request.** Reroute across providers before the client sees a byte, even mid-stream, within a deadline and hop budget. The user never sees the stumble.
- **A circuit breaker that knows whose fault it is.** Classify each failure (provider outage, your bad request, context-length, auth or billing) and treat each differently, instead of retrying into a wall.
- **One static Rust binary.** No Python sidecar, no interpreter, no GC in the request path. Your keys, your network, your data path.

## Why me, why now

Multi-model is going mainstream this year, and the control plane is where the reliability and portability promises get made or broken. I think the right architecture is reliability-first and lossless, not OpenAI-shaped and retry-based, and I'd rather build that from the metal up than bolt it onto an interpreted proxy.

It's day zero. Nothing exists yet, not even a repo. But I'm building this in public, and I'll post every milestone here as it lands. If any of this resonates, if you're running multi-provider LLM traffic and feeling these edges, I'd love to hear from you.
