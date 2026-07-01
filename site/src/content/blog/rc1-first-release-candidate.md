---
title: "Busbar 1.0.0-rc.1, the first release candidate"
description: "From an empty repo to a feature-complete, API-stable release candidate. Six protocols, lossless translation, in-flight failover, and fault-attributed breaking, in one Rust binary."
date: 2026-06-03
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

A few weeks ago this was a manifesto with no code. Today Busbar has its first release candidate, 1.0.0-rc.1: feature-complete and API-stable, in a single Rust binary you can run right now.

Here's what landed.

## Lossless, both ways

Six wire protocols (OpenAI, OpenAI Responses, Anthropic, Gemini, Amazon Bedrock, Cohere) native on both sides, translated through a superset intermediate representation rather than flattened to one vendor's shape. Point a Bedrock SDK at Busbar and reach an Anthropic backend. The native features survive the hop, streaming included.

## Failover inside the request

If a lane fails before your client has seen a byte, Busbar reroutes to the next lane in the pool, even mid-stream, within a configurable deadline and hop budget. Your user sees a slight pause, not an error.

## A breaker that knows whose fault it is

Every provider connection has a circuit breaker that classifies failures. Transient errors cool down and probe. Hard-down failures like auth or billing get a sticky cooldown. Your own 4xx errors never penalize the lane. A context-length overflow fails over to a bigger model. It's reliability engineering, not a retry loop.

## Governance built in

Virtual keys with budgets, RPM and TPM rate limits, and pool-level access control, so you can hand a scoped, capped key to a staging environment or an internal tool without trusting every caller to self-police.

## One binary

No Python sidecar, no interpreter, no GC in the request path. Download it, point your SDK at it, done.

## Why "rc," not "1.0"

It's feature-complete and the contracts are stable, but 1.0 is a promise: frozen APIs under Semantic Versioning, hardened under real load. That's what the release-candidate window is for. Soak, audit, and fix before I make that promise. More milestones to come.

Try it at **[getbusbar.com](https://getbusbar.com)**, and tell me what breaks.
