---
title: "Busbar 1.3: The API Release"
description: "Everything you could only do by editing YAML and restarting, you now do over one authenticated, audited, frozen HTTP API — read the running config, apply a validated change atomically, roll back to any version, mint and revoke keys, register hooks. And the routing hook grew into a hook system: gates, taps, and rewrites on every request."
date: 2026-07-14
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

For its whole life so far, Busbar has been driven by a file. You wrote `config.yaml`, you restarted the process, and the running gateway was whatever the file said the last time it booted. That is a fine way to run a daemon and a terrible way to run a **control plane**. A control plane is something other software drives, and other software does not SSH in and edit YAML.

So the headline of **1.3 is the API**. Everything the config file can express, the API can now do — over one authenticated surface, live, with no restart and no file edit. Read the running config. Apply a validated change atomically. Roll back to any previous version. Register, replace, or remove a hook. Mint, rotate, or revoke a key. Adjust budgets and rate limits. From Terraform, Ansible, CI, or a dashboard you build yourself. The whole surface is **`/api/v1/admin`**, versioned, and frozen additive-only.

And the second half of the release: the routing hook I've written about grew up into a hook **system**. What was one seam — rank a pool's members — is now gates, taps, and rewrites, firing concurrently on every request, on the normalized IR, so one hook works across all six protocols at once.

## The config file stops being the only way in

Here's the part I care about. This is not a handful of read endpoints bolted onto the side. It is a full config plane, and it holds the same contract the boot pipeline does.

An apply atomically swaps the running config snapshot: new requests see the new config, requests already in flight finish on the old one, and — this is the load-bearing part — surviving lanes keep their learned health **by identity**, not by list position. Reorder your pool members, add a model, and Busbar does not forget which lanes were misbehaving. The health state now even survives a restart: kill Busbar, fix the config, start it again, and it comes back sub-second still remembering which breakers were tripped.

```bash
# Read the config ETag, then apply a change guarded against it
ETAG=$(curl -sI -H "x-admin-token: $TOK" \
  http://localhost:8080/api/v1/admin/config | grep -i ^etag | cut -d' ' -f2)

curl -s -X POST -H "x-admin-token: $TOK" -H "If-Match: $ETAG" \
  -H 'content-type: application/json' \
  --data @proposed.json \
  http://localhost:8080/api/v1/admin/config/apply
```

Your hand-written `config.yaml` is never touched. API-applied changes persist to a Busbar-owned overlay file (set `BUSBAR_CONFIG_OVERLAY`), and the effective config is base plus overlay — both human-readable, so "who set this, and when" is always answerable. If an overlay ever goes bad, `--safe-mode` boots from your base config alone. And every mutation lands in an audit log: who changed what, when, attributed to the principal that made it. See the [Admin API guide](/docs/admin-api/).

## Endpoints are the easy part. The contract is the product.

Anyone can expose a hundred routes. What makes an API something you build tooling against for years is that its shape does not move and its edges are consistent. I spent this release on that, not on the route count.

One error envelope, everywhere. Every `/api/v1/admin` error — including a `401`, a `404` on an unmatched path, a `405` on a wrong method — is the same JSON shape, and you branch on a **frozen `code`**, never on the human-facing message:

```json
{ "error": { "code": "version_conflict", "message": "If-Match `41` is stale" } }
```

The taxonomy has one deliberate split that matters if you build automation: a retryable **`version_conflict`** (your `If-Match` is stale — re-read for a fresh ETag and retry) versus a terminal **`conflict`** (the request contradicts server state in a way a retry cannot fix — governance disabled, a base-defined hook, a self-lockout guard). Your retry loop distinguishes those two without ever string-matching a message.

Around that error shape sits the rest of one consistent contract:

- **One list envelope** — `{items, next_cursor}` — with opaque cursors. Round-trip `next_cursor` verbatim; a foreign or malformed cursor is a loud `400`, never a silent skip.
- **One concurrency mechanism** — RFC-7232 `If-Match`/ETag on every mutable resource. There is no second body-level `expected_version` twin to keep in sync. A malformed `If-Match` is a `400`, never silently treated as "no guard".
- **`Idempotency-Key`** on both secret-minting POSTs (`POST /keys`, `POST /keys/{id}/rotate`), so a retried mint returns the first response verbatim — including the once-shown secret — instead of double-minting.
- **A self-describing `openapi.json`** — the OpenAPI 3.1 schema of the whole surface, with each operation annotated with its required scope. Point a client generator at it.

I put the wire through **three independent contract-audit rounds on the Admin API and two on the hook wire**, and fixed every finding before the freeze. That freeze is the actual deliverable: v1 is additive-only. New fields may appear; no field is ever removed or repurposed; no error `code` ever changes meaning; the mount prefix and the scope matrix are pinned by tests. A breaking change would ship as `/admin/v2/` alongside v1 — never in place. Build against v1 and it keeps working. If you've ever built tooling on an API that quietly re-shaped a field under you, you know why I spent the release here.

## The routing hook grew into a hook system

The other half of 1.3. For the last few posts the hook has been one thing: rank a pool's members. Now hooks are **control-plane citizens** with three jobs.

Every hook is one of two kinds. A **tap** watches — fire-and-forget observation (logging, audit, metering, shipping to a SIEM) that can never delay or fail a request, and picks its stage with `at:` (`request`, `route`, `attempt`, `completion`, including the synthetic rejected-completion so an audit tap sees denials, not just served traffic). A **gate** decides — fire-and-wait, answering with exactly one reply arm:

| Arm | Effect |
|---|---|
| nothing / abstain | no opinion; Busbar proceeds as it would |
| **reject** | no upstream dispatched; caller gets a dialect-native error (status clamped 400–499) |
| **restrict** | only members carrying these `tags` may serve — and it holds across failover |
| **order** | rank the surviving candidates; that becomes the failover walk |
| **rewrite** | replace the request body before dispatch |

Routes rank, gates decide, taps watch. The `restrict` arm is the one I'm most pleased with: a gate can reply "only members tagged `baa` may serve this," and the restriction persists across every failover hop — compliance-constrained routing (data residency, BAA-only lanes) without teaching your router a thing about compliance.

Hooks are defined once by name and referenced anywhere — in a pool's `hooks:` list (which carries both its ranking strategy and any gates) or in `global_hooks:` to fire on every request:

```yaml
hooks:
  request-log:  { kind: tap,  socket: /run/busbar/log.sock,  prompt: ro }
  pii-guard:    { kind: gate, socket: /run/busbar/pii.sock,  prompt: ro, on_error: reject }
  headroom:     { kind: gate, socket: /run/busbar/hr.sock,   prompt: rw, global: true }

global_hooks: [request-log, pii-guard]     # attach to EVERY request

pools:
  chat:
    hooks: [cheapest, pii-guard]           # base ordering + a gate
    members:
      - target: claude-opus
      - target: claude-opus-bedrock
        tags: ["baa"]
```

All of a request's gates fire **concurrently** against the same candidate set, then reconcile deterministically: any reject wins, restrictions intersect, the last order in the priority chain ranks what survives. So the added latency is the slowest gate, not the sum.

Three properties make this safe to run on the request path, and they are structural, not conventional. It's **fail-safe**: a slow, crashed, or wrong hook degrades to a safe default per its `on_error` and can never block, hang, or fail a request. It's **grant-gated**: by default a hook sees shapes — sizes, counts, flags, live lane signals — never prompt text or caller identity; content and identity arrive only by explicit per-hook grant (`prompt:`/`user:`), and those grants are immutable after registration, so you cannot wire a hook in blind and quietly raise it to read content later. And it's **cross-protocol by construction**: hooks fire on the normalized IR, after the request is understood and before dispatch, so **one hook works across every protocol and provider at once**. The full contract is in the [hooks guide](/docs/hooks/).

## The rewrite arm, across all six protocols

The newest arm deserves its own note. A trusted gate carrying `prompt: rw` can replace the request body before dispatch — context compression, redaction — and because it fires on the normalized form, one rewrite hook works across all six protocols at once. Rewrites persist across failover, token accounting is on the provider-reported usage of the **rewritten** body (so the savings are real and measured, not estimated off to the side), and a malformed or slow rewrite proceeds with the original body untouched. A broken compressor can never corrupt a request. That's the subject of the next post — a compression gate that reports its own savings.

## "Your AI Control Plane" now extends to what runs on it

Here's where the two halves of the release meet. Busbar is your AI control plane — and in 1.3 that reaches past Busbar itself to the hooks running on it. A hook **self-describes its settings** and **self-reports its own operational metrics**, both over the same frozen Admin API that manages everything else:

```bash
# Push new settings to a running hook — commits only on the hook's version-echoing ack
curl -s -X PATCH -H "x-admin-token: $TOK" -H 'content-type: application/json' \
  --data '{"min_savings_pct":25}' \
  http://localhost:8080/api/v1/admin/hooks/headroom/settings

# Is it running what we pushed? desired vs reported, with a drift verdict
curl -s -H "x-admin-token: $TOK" \
  http://localhost:8080/api/v1/admin/hooks/headroom/status
```

`GET /hooks/{name}/schema` proxies the hook's own settings JSON Schema verbatim — one declaration that any tooling reading JSON Schema renders as a config form. `GET /hooks/{name}/status` live-queries the hook over its transport and returns `{name, desired, reported, drift, metrics, as_of, source}` — the settings it is *actually* running against Busbar's desired copy, with a **drift** verdict you can alert on, plus its self-reported metrics.

The point: a dashboard built on Busbar sees what every plug is doing, through one API. No per-plugin dashboards, no second box to run. I'll walk the whole self-reporting wire — schema, drift, and the Prometheus-shaped metrics array — in the next post on the Headroom compression gate.

## FinOps: Busbar exposes the inputs of cost, not just its own number

`GET /api/v1/admin/usage` is the fleet FinOps read, and it's built on one principle. It reports per-model and per-key consumption as the **raw token split** — input, output, cache-read, and cache-creation, each of which prices differently — in fixed UTC-day buckets:

```json
{
  "window": { "start": 1782950400, "end": 1783036800 },
  "as_of": 1782998113,
  "currency": "USD",
  "total": { "tokens_input": 91240, "tokens_output": 30112,
             "tokens_cache_read": 402000, "tokens_cache_creation": 12050,
             "requests": 512, "spend_micros": 1834200 },
  "by_model": [ { "model": "smart", "provider": "anthropic", "tokens_input": 91240 } ],
  "by_key":   [ { "id": "vk_ab12cd34ef56ab78", "name": "ci", "tokens_input": 91240 } ],
  "by_key_truncated": false
}
```

`spend_micros` is derived at read time from your configured prices — a convenience, and explicitly a **mutable estimate**, never a ledger charge. The reason the raw split is right there next to it: a consumer with its own negotiated per-model pricing reconstructs cost *exactly* from the split, using its own price catalog. Busbar exposes the inputs of cost, not just its own number. And every unit stays attributable — an over-cap `by_key` list carries an `others` remainder so `total == sum(by_key) + others` always holds.

## Auth, governance, and health, briefly

A few more things landed under the same banner, so I'll keep them short:

- **Auth is a pluggable chain.** Authentication is now an ordered chain of modules — each identifies the caller, rejects, or passes to the next. Token auth is the first module and the default, and it's removable. Auth always fails closed. Budgets, rate limits, pool access, and audit all follow the authenticated principal, whoever issued it.
- **The admin surface has its own chain and scopes.** A scope ladder — `read-only` ⊂ `hooks-register` ⊂ `full`, derived from method + path, never the body — replaces the single shared admin token. Mint a CI token that can only lint configs, or only register hooks. The chain itself is live-mutable via `PUT /admin-auth`, and guarded so a change that would lock the caller out is refused, not applied.
- **Group-based governance.** `group_map:` grants admin scopes and data-plane access (allowed pools, rate limits, budgets) to identity-provider groups in one place, and a group-mapped user is governed by exactly the machinery a virtual key uses.
- **Config reload and durable health.** `POST /config/reload` re-reads your files and applies them atomically — the GitOps primitive: push config, call reload, no restart, no health amnesia.

## Migrating from 1.2

One breaking change, and it's a clean cut. 1.3 reshapes how hooks and policies are configured: hooks are now defined once by name and referenced everywhere, which means the old inline `policy:` block and the transport-named `route:` values (`route: socket`, `route: webhook`) are **removed**. A pool's `route:` now takes a hook name or a native strategy name (`weighted`/`cheapest`/`fastest`/`least_busy`/`usage`).

Existing configs need a one-time update — and there are no silent fallbacks. An old-form key reports a clear startup error naming exactly what to write instead. The `route: script` embedded Rhai policy, deprecated in 1.2.1, is also gone; a compiled hook over a socket or an HTTP webhook does the same job with real process isolation. The full walkthrough is the 1.2.x → 1.3 migration guide (`docs/migration-1.3.md`).

## What this sets up

1.3 turns Busbar from a gateway you configure into a control plane you drive. The config file still works exactly as before — it's just no longer the only door. Everything else drives it over a contract that won't move under you, and the hooks running on it report themselves through that same contract.

Get it at **[getbusbar.com](https://getbusbar.com)**. The next post takes the rewrite arm and the self-reporting wire and puts them together: a compression gate you configure and watch entirely through the API, with no second dashboard. If you're building tooling against Busbar, the [Admin API](/docs/admin-api/) and [hooks](/docs/hooks/) guides are the contract — I'd love to hear what you build on it.
