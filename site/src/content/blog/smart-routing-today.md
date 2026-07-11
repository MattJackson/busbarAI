---
title: "The smart router you want already exists. It's a hook."
description: "Everyone asks for automatic model selection by task, latency, quality, and cost. You don't need a new product for that. You need a request-path hook that sees the right signals, and a control plane that keeps the hook honest. Busbar ships both today. Here's a working smart router in one Python file."
date: 2026-07-11
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

A user told me this week: "The best model should be selected automatically based on the task, latency, quality, and cost."

I agree. And I want to show why that sentence does not describe a new product. It describes a hook. Busbar, Your AI Control Plane, ships that hook today, and in this post I build the whole thing: a task-aware smart router in one Python file, wired into a pool, with a fail-safe that means it can never take your traffic down.

## The shape of the problem

"Pick the best model automatically" splits into two jobs that people usually blur together.

The first job is the decision. Given a request and a set of models, rank them. This is policy. It changes weekly, it depends on your evals and your budget, and no vendor default will match your judgment for long.

The second job is everything around the decision. See live latency and load. Enforce the ranking. Fail over when the top pick is down. Never let the decision layer itself become an outage. This is infrastructure, and it does not change weekly.

Busbar's position is simple: you own the first job, the control plane owns the second. The seam between them is `route: webhook`. Before each request's failover loop, Busbar POSTs a small projection of the request plus every candidate in the pool to a sidecar you run, and reads back a ranked preference list. That is the entire contract.

## What the hook actually sees

The payload is deliberately small. For the request: the pool name, the ingress protocol, message count, whether tools are declared, total prompt size in characters, the requested `max_tokens`, and whether it streams. For each candidate: the model name, the operator-declared `tier` and `cost_per_mtok`, a rolling latency EWMA in milliseconds, live free concurrency slots, remaining request budget, and rate-limit headroom from Governance.

Notice what is missing: the prompt. Busbar never sends message content to an external sink. That is a Security stance, not an oversight. Your routing sidecar classifies on shape, not on words.

That turns out to be enough. Here is the classifier from the example, using only fields Busbar really sends:

```python
def classify(req):
    total_chars = req.get("total_chars") or 0
    max_tokens = req.get("max_tokens") or 0
    if req.get("has_tools"):
        return "code"          # tool and agent traffic wants the capable tier
    if max_tokens >= 4096 or total_chars > 24_000:
        return "long-form"     # ~4 chars per token, so 24k chars is ~6k tokens
    if not req.get("stream") and req.get("message_count", 0) <= 1:
        return "bulk"          # single-shot, non-interactive: optimize cost
    return "quick-answer"      # interactive default: optimize latency
```

Each bucket then scores every candidate with different weights over the live signals:

```python
w_cost, w_lat, w_conc, tiers = BUCKETS[bucket]
s = (w_cost * cost_score        # 1 - cost/max_cost across the pool
   + w_lat  * latency_score     # 1 - latency/max_latency (EWMA)
   + w_conc * concurrency_score)  # free slots / max free slots
if cand.get("tier") in tiers:
    s += TIER_BOOST             # the operator's quality judgment
if headroom is not None:
    s *= 0.5 + 0.5 * headroom   # back off lanes near their rate cap
```

Sort descending, return `{"order": [idx, ...]}`. Done. The whole server, with logging and error handling, is about 115 lines of stdlib Python. It lives in the repo under `examples/smart-router/`, next to a Rhai version that runs the same logic in-process for builds with the `script-policy` feature.

The config is one pool:

```yaml
pools:
  smart-router:
    route: webhook
    policy:
      url: "http://127.0.0.1:8787/"
      timeout_ms: 150        # the default hard deadline
      on_error: weighted     # the default fallback
    members:
      - target: claude-sonnet
        tier: large
        cost_per_mtok: 3.0
      - target: gpt-4o-mini
        tier: small
        cost_per_mtok: 0.15
      # ... tier and cost_per_mtok on each member feed the policy
```

Any client speaking any of Busbar's six protocols hits `smart-router` as if it were a model, and Translate carries the request to whichever backend wins. Every response tells you what happened: `x-busbar-route-policy: webhook` and `x-busbar-route-target: gpt-4o-mini`. That is Observability on every single decision.

## The part that makes it safe to run

Here is the reason this belongs in a control plane and not in your app code. The hook is advisory. It can never become load-bearing.

The decision has a hard deadline, `policy.timeout_ms`, which defaults to 150 ms. If the sidecar is slow, the decision is cut off and Busbar applies `on_error`, which defaults to plain weighted round-robin. Same for a crash, a non-2xx, or malformed JSON. A broken sidecar is indistinguishable from having no policy at all. Kill the router mid-traffic and requests keep flowing.

And the ranking feeds the same Failover loop everything else uses. If the policy's first choice is tripped or at capacity, Busbar walks to the second with the normal circuit-breaker machinery. If the policy drops a candidate from its list, that lane is demoted, not excluded, so a buggy ranking can never strand a healthy model. The policy proposes. The control plane disposes.

## Honest words about "quality"

Task, latency, and cost are measurable at request time, and the hook sees all three live. Quality is not measurable at request time, and I won't pretend it is.

What quality means here: you run your evals, you form a judgment about which models are good at what, and you encode that judgment as `tier` and `tags` on your pool members. The hook reads those labels and boosts accordingly. Busbar is the enforcement point for your judgment, not the source of it. Anyone selling you request-time quality magic is selling you a hidden eval you didn't run and can't audit. I would rather give you the seam and let you plug in labels you actually believe.

## What 1.3 could add

The seam is deliberately minimal today, and building this example showed me where it could grow. On my roadmap thinking, not a promise:

- A native `smart` policy with configurable bucket weights, so the common case needs no sidecar at all.
- `tags` in the webhook payload. The Rhai script sees them today; the webhook only sees `tier`.
- Opt-in, coarse content hints (a code-likeness flag, a language hint) computed inside Busbar so prompt text still never leaves the process.
- Per-lane rate headroom, so the signal differentiates candidates instead of the caller's key.

If any of those would change what you build, tell me. The hook is the product here, and it gets better when people push on it.

The full example, the Rhai variant, and a README with the scoring math are in the repo under `examples/smart-router/`. The wire format and the sandbox details are in the [routing guide](/docs/routing/).
