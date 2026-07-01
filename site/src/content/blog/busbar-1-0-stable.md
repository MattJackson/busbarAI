---
title: "Busbar 1.0 is stable"
description: "The HTTP API, config schema, and six wire-protocol contracts are now frozen under Semantic Versioning, hardened across a multi-round security and correctness audit. It's production-ready."
date: 2026-06-21
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

**Busbar 1.0 is here, and it's stable.** After the release-candidate window of soak, audits, and fixes, I'm ready to make the promise that 1.0 represents.

## What "stable" means

- **Frozen contracts.** The HTTP API, the configuration schema, and the six wire-protocol contracts are stable under Semantic Versioning. No breaking change without a major-version bump. You can build on Busbar and trust the surface won't move under you.
- **Hardened.** 1.0 went through multiple rounds of security and correctness review: SSRF-safe upstreams, constant-time token comparison, parameterized SQL, secret-free logs, request-body caps, and native-protocol error envelopes that leak no internals.
- **Complete where it counts.** Lossless cross-protocol translation across all six protocols (both directions, streaming included), fault-attributed per-lane circuit breaking, in-flight streaming-safe failover, and key-scoped governance for budgets, rate limits, and access control.

## Still one binary

Everything above ships as a single static Rust binary. No Python sidecar, no interpreter, no GC in the request path. Linux, macOS, Windows, on Intel and ARM. Your keys, your network, your data path.

## What's next

1.0 is the foundation, not the finish line. From here the work is depth: more providers, richer routing policy, deeper observability, on top of a surface that no longer moves. The reliability and fidelity guarantees are the part I care most about keeping honest, and they're now locked in.

Get it at **[getbusbar.com](https://getbusbar.com)**. If you're running multi-provider LLM traffic in production, I'd love to talk. I'm taking on design partners.
