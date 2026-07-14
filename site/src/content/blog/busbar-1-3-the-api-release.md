---
title: "Busbar 1.3: your code on the request path"
ogImage: "/og/busbar-1-3-the-api-release.png"
description: "Hooks put your logic on the normalized request path across all six protocols. Auth becomes a pluggable chain you can compile out. And the admin API v1 is frozen: the surface tools get to build on."
date: 2026-07-14
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

**Busbar 1.3 is the API release.** 1.0 froze the data plane: the six wire protocols your apps
speak. 1.3 freezes the two surfaces everything else builds on. **Hooks**, the sanctioned
attachment points for your own code on the request path, and **admin API v1**, the management
contract that will only ever grow.

## Hooks: write it once, it runs on everything

A hook is your own code. A compiled binary on a local Unix socket (~8µs a call) or an HTTPS
sidecar in any language, running on Busbar's normalized IR: the canonical form every request
takes after lossless translation from whatever dialect the caller spoke. That placement is the
whole point. Write a PII screen, a smart router, or a context compressor once and it runs against
all six protocols and every fronted provider, with failover and circuit breaking underneath it.

Two kinds, one rule. A **tap** watches: audit, metering, SIEM. It can never delay a request. A
**gate** decides: reject the request, restrict which pool members may serve it, re-order the
failover walk, or rewrite the body before it ships. Rewrite is the one I'm most excited about;
compression and redaction on the wire, with token accounting on the rewritten body, so the
savings are real and measured. The rule is enforced structurally, not by convention: a hook can
steer, observe, or rewrite, but it can never break the request path. Slow, crashed, or wrong
degrades to a safe default. Every time.

Hooks are also live infrastructure now. Register and remove them at runtime over the admin API;
push settings to a running hook, committed only when the hook acknowledges; read back the schema
the hook describes for itself. And a hook reports its own operational state: `GET
/api/v1/admin/hooks/{name}/status` is the control-plane read — it live-queries the hook and
returns the settings it is actually running against Busbar's desired copy, with a **drift**
verdict, plus the hook's self-reported metrics. A dashboard built on Busbar sees what every plug
is doing, over the same API. No per-plugin dashboards.

## Auth is a chain, and you can compile it out

Authentication is no longer a mode. It's a chain of modules, PAM-style: the first module to
identify the caller admits them, a reject stops everything, and modules that don't recognize the
credential defer down the chain. Today's token auth is now just the first link, and it's
architecturally identical to anything you'd write yourself.

Every built-in lives in its own crate behind a default-on feature. Want to see how tokens work?
Read `auth/tokens/`; it's about 70 lines against the same contract external modules use. Need to
prove your deployment contains no token-auth code at all? Build without it. The module, its
comparison fold, and the allowlist are absent from the binary. **Compliance by compilation**,
checkable from the symbols. Identity maps to authority in config (`group_map:`), never asserted
by a module, and admin principals carry scopes: read-only sees, hooks-register can attach hooks
but can't mint keys, full does everything.

## Admin API v1: frozen, so you can build on it

`/api/v1/admin/*` is now a stable contract, additive-only from here. Pools, keys, usage, hooks,
config: reads for dashboards, mutations with optimistic concurrency, per-principal mutation rate
limits, and a tamper-evident audit log that attributes every attempt, including the denied ones.
The whole surface is discoverable from the binary itself (`openapi.json`), with the required scope
stamped on every operation.

What makes it a contract and not just a pile of endpoints is that every edge is consistent. One
error envelope everywhere, and you branch on a frozen `code`, never on the human message, with a
deliberate split baked into the taxonomy: a retryable `version_conflict` (your `If-Match` is
stale, re-read and retry) versus a terminal `conflict` (server state a retry can't fix), alongside
`unauthorized`, `method_not_allowed`, and the rest. One list envelope, `{items, next_cursor}`,
with opaque cursors. One concurrency mechanism, RFC-7232 `If-Match`/ETag, on every mutable
resource, no body-level twin to keep in sync. And an `Idempotency-Key` on the secret-minting POSTs,
so a retried key mint returns the first response verbatim instead of double-minting. I put the
whole wire through several independent contract-audit rounds and fixed every finding before the
freeze.

Metering is built on the same principle: expose the inputs of cost, not just a number. `GET
/api/v1/admin/usage` reports per-model and per-key consumption as the raw token split, input,
output, cache-read, cache-creation, each of which prices differently, with a `spend_micros`
derived at read time from your configured prices. A consumer with its own negotiated pricing
reconstructs cost exactly from the split.

Config management got the same treatment. Validate a candidate config without applying it. Apply
one atomically: in-flight requests finish on the old snapshot, new ones see the new one, and
surviving lanes keep their learned health. Breakers, cooldowns, latency profiles, all carried by
model identity across the swap. Reload from disk with one call. Roll back to a retained version.
And because learned health now persists across restarts, the recovery story for a truly broken
config is the honest one: fix it and restart. Sub-second, and Busbar comes back remembering which
lanes were misbehaving.

## Still one binary

Everything above ships in the same single static Rust binary. We roughly doubled the surface (hooks,
auth chains, the whole config plane) and the `FROM scratch` Docker image is still a handful of
megabytes, compressed. The
default path, with no hooks and no chains configured, is byte-identical to 1.2; the zero-cost floor
is a design rule, not an accident. Over 2,000 tests, the full suite green with every plugin compiled
out, on Linux, macOS, and Windows.

## What's next

Hooks make Busbar the place your middleware runs; the frozen admin API makes it the thing your
tooling manages. Next is filling both ecosystems in, starting with a context-compression hook
we'll have more to say about very soon.

Get it at **[getbusbar.com](https://getbusbar.com)**. If you're running multi-provider LLM
traffic in production, I'd love to talk.
