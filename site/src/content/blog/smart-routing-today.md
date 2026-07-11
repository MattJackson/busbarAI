---
title: "The smart router you want is a hook"
description: "Everyone asks for automatic model selection by task, latency, quality, and cost. It is not a product, it is a hook. Busbar runs yours two ways: a compiled Rust binary on a local socket that decides in about 8 microseconds, or a webhook in any language. Both wired to the same failover and fail-safe machinery."
date: 2026-07-11
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

A user told me this week: "The best model should be selected automatically based on the task, latency, quality, and cost."

I agree. And I want to show why that sentence does not describe a new product. It describes a hook, and it should stay a hook: the policy is your judgment, and your judgment does not belong compiled into someone else's core. Busbar, Your AI Control Plane, runs that hook two ways, and in this post I show both, measured honestly: a compiled Rust binary on a local Unix socket that decides in about **8 microseconds**, and a webhook in any language for everywhere else. Both plug into the same failover, circuit-breaker, and fail-safe machinery, so neither can take your traffic down. (Everything here is built on the 1.2.1 release.)

## The shape of the problem

"Pick the best model automatically" splits into two jobs that people usually blur together.

The first job is the decision. Given a request and a set of models, rank them. This is policy. It changes weekly, it depends on your evals and your budget, and no vendor default will match your judgment for long.

The second job is everything around the decision. See live latency and load. Enforce the ranking. Fail over when the top pick is down. Never let the decision layer itself become an outage. This is infrastructure, and it does not change weekly.

Busbar's position is simple: you own the first job, the control plane owns the second. The seam between them is a hook, and Busbar gives you two ways to run the exact same decision.

## The decision, in three steps

Whichever way you run it, the logic is small and the same. Classify the request into a task bucket from shape alone, score every candidate through that bucket's weights over the live signals, sort.

**Classify** on shape, never content: tools declared means code, a big `max_tokens` or a long prompt means long-form, a single-shot non-streaming call means bulk, everything else is a quick interactive answer.

**Score** turns the bucket into dials. A code request weights capability and latency; a bulk request weights cost. Each candidate scores on its live cost, latency, and free concurrency, plus a boost for the operator-declared quality `tier`, then scaled down as a lane nears its rate-limit cap.

**Sort** descending, return the order. That is the whole policy. It is not a static "if X use Y" table and it is not blind cost math: one classification step picks the weights, then a scoring pass applies them to the live signals of every candidate, so the same pool serves a code request and a bulk request ranked differently.

## Answer one: a Rust binary on a socket, about 8 microseconds

`route: socket` points Busbar at a compiled binary you run, listening on a local Unix domain socket. Busbar writes the request-and-candidates projection as one line of JSON, your binary writes back the ranked order, the connection stays open. No HTTP stack, no network, no interpreter.

```yaml
pools:
  chat:
    route: socket
    policy:
      socket: /run/busbar/router.sock
      timeout_ms: 150        # the hard deadline
      on_error: weighted     # the fail-safe
    members:
      - target: claude-sonnet
        tier: large
        cost_per_mtok: 3.0
      - target: gpt-4o-mini
        tier: small
        cost_per_mtok: 0.15
```

Measured end to end through Busbar's real transport, against the real example binary running as a separate process: about **7.9 microseconds** median per decision, p99 around 12. Your policy is a separate process, so a crash in it is contained; Busbar never spawns or supervises it, connects lazily, and reconnects across restarts of your binary. Kill your router mid-traffic and requests keep flowing.

The hook itself is about a hundred lines of Rust, standard library plus serde, and the whole policy is the classify-and-score above:

```rust
fn weights(r: &Req) -> (f64, f64, f64, &'static [&'static str]) {
    if r.has_tools {
        (0.20, 0.40, 0.40, &["large", "primary"]) // code: capability + latency
    } else if r.max_tokens.unwrap_or(0) >= 4096 || r.total_chars > 24_000 {
        (0.40, 0.20, 0.40, &["large", "primary"]) // long-form
    } else if !r.stream && r.message_count <= 1 {
        (0.60, 0.10, 0.30, &["small", "overflow"]) // bulk: optimize cost
    } else {
        (0.30, 0.50, 0.20, &["small", "overflow"]) // interactive: optimize latency
    }
}
```

## Answer two: a webhook, in any language, on any OS

The socket hook is Unix-only and compiled. When you want the policy in whatever your team already ships, or you are on Windows, you write a webhook. Set `route: webhook`, point it at a sidecar you run, and Busbar POSTs the same projection over HTTP and reads back the same ranked `{"order":[...]}`. The example is about a hundred lines of Go, standard library only, and its `classify` is the same shape as the Rust one:

```go
func classify(r request) weights {
    switch {
    case r.HasTools: // tool / agent traffic wants the capable tier
        return weights{0.10, 0.20, 0.20, []string{"large", "primary"}}
    case (r.MaxTokens != nil && *r.MaxTokens >= 4096) || r.TotalChars > 24000: // long-form
        return weights{0.20, 0.10, 0.20, []string{"large", "primary"}}
    case !r.Stream && r.MessageCount <= 1: // single-shot: optimize cost
        return weights{0.60, 0.10, 0.30, []string{"small", "overflow"}}
    default: // interactive default: optimize latency
        return weights{0.30, 0.50, 0.20, []string{"small", "overflow"}}
    }
}
```

Same classify, same weights, same sort, and critically the same wire contract: both transports carry byte-identical JSON, so a hook graduates from a webhook prototype to a compiled socket binary without changing its logic. Both examples are in the repo under [`examples/smart-router/`](https://github.com/MattJackson/busbarAI/tree/main/examples/smart-router). The webhook adds the HTTP round trip the socket does not, but it stays under a millisecond co-located and it runs anywhere.

## What the hook sees, and what it does not

Both paths see the same projection. For the request: pool name, ingress protocol, message count, whether tools are declared, total prompt size in characters, requested `max_tokens`, whether it streams. For each candidate: model name, operator-declared `tier` and `cost_per_mtok`, a rolling latency EWMA, live free concurrency, remaining budget, and rate-limit headroom from Governance.

Notice what is missing: the prompt. Routing is a shape decision, so by default Busbar sends no message content with it, and the policy classifies on sizes, counts, and flags, not on words. Your prompts do not leave the process just to pick a model. That is a Security default, not an accident, but it is not a wall: content is a separate, explicit, per-hook switch, off unless you turn it on. Default deny, opt in on purpose. That switch is exactly what makes the next hooks possible, which is where this goes.

Any client speaking any of Busbar's six protocols hits the pool as if it were a model, and Translate carries the request to whichever backend wins. Every response tells you what happened: `x-busbar-route-policy` and `x-busbar-route-target`. That is Observability on every single decision.

## The part that makes it safe to run

Here is the reason this belongs in a control plane and not in your app code. The hook is advisory. It can never become load-bearing.

The decision has a hard deadline, `policy.timeout_ms`, which defaults to 150 ms. If the sidecar is slow, the decision is cut off and Busbar applies `on_error`, which defaults to plain weighted round-robin. Same for a crash, a non-2xx, or malformed JSON. A broken sidecar is indistinguishable from having no policy at all. Kill the router mid-traffic and requests keep flowing.

And the ranking feeds the same Failover loop everything else uses. If the policy's first choice is tripped or at capacity, Busbar walks to the second with the normal circuit-breaker machinery. If the policy drops a candidate from its list, that lane is demoted, not excluded, so a buggy ranking can never strand a healthy model. The policy proposes. The control plane disposes.

## What it costs, measured

You can reproduce both numbers yourself; the benchmark and the commands are in [`examples/smart-router/bench/`](https://github.com/MattJackson/busbarAI/tree/main/examples/smart-router/bench), all on an Apple M5 Pro, all through Busbar's real transport code against real separate processes.

- **Socket hook: about 7.9 microseconds** median per decision (p99 about 12, 50,000 samples). A compiled Rust binary over a kept-alive local socket. The whole Busbar layer adds tens of microseconds to a request, so the decision is close to free.
- **Webhook: sub-millisecond** on a co-located sidecar, plus whatever the network hop costs if it is not co-located. You trade some latency for any-language, any-OS reach.

Either way it is far under the 150 ms deadline, after which Busbar coerces the decision to the pool's `on_error` fallback and the request proceeds anyway. (For the record: Busbar previously offered an embedded script engine for this, and the interpreter alone cost about 108 microseconds per decision, twenty times the entire compiled hook round trip. It is deprecated as of 1.2.1. When the same logic runs 20x faster in a separate process that cannot crash the control plane, an embedded interpreter is the wrong tool.)

## Honest words about "quality"

Task, latency, and cost are measurable at request time, and the hook sees all three live. Quality is not measurable at request time, and I won't pretend it is.

What quality means here: you run your evals, you form a judgment about which models are good at what, and you encode that judgment as `tier` and `tags` on your pool members. The hook reads those labels and boosts accordingly. Busbar is the enforcement point for your judgment, not the source of it. Anyone selling you request-time quality magic is selling you a hidden eval you didn't run and can't audit. I would rather give you the seam and let you plug in labels you actually believe.

## Why a hook, and not a feature

Here is the thinking behind all of this. I build hooks so a team can encode its own policy without the core carrying fifty features that ninety-five percent of users will never turn on. Smart routing is the perfect example: it is not one behavior, it is your behavior, and it changes with your evals and your budget. I even prototyped building this router into the core, measured it at two thirds of a microsecond, and then took it back out. Fast was not the question. Whose judgment ships in the binary was the question, and the answer is yours, not mine.

So the core carries the seam and the guarantees: the projection, the deadline, the fail-safe, the failover integration. The policy stays a hook, and the hook ladder is a speed-versus-reach choice you make per pool: the webhook for any language on any OS, the socket binary when you want the decision in single-digit microseconds. Same contract on both rungs.

The next question is distribution. A routing policy someone already tuned for their workload is one you should be able to start from instead of writing from scratch, the same way you reach for a package. Call it a Hooks Repository: a place teams publish and share hooks. I would genuinely like your thoughts on this. Grow a shared hook ecosystem around the seam? Tell me what would actually change how you run this.

## What 1.3 could add

The native policy and the webhook are the two answers today. Building them showed me where the seam should grow next. On my roadmap thinking, not a promise:

- `tags` in the hook payload, so a policy can route on your own labels, not just `tier`.
- An explicit, per-hook content switch, off by default. Routing never needs your prompt, but the next hooks do: PII redaction, audit, and guardrails. A hook that can see the request can reject one that carries PII before it ever leaves your network, and that is impossible if the hook is blind to content. So content stays default-off and opt-in, per hook, your call, never a global firehose.
- The caller's identity to a hook, again opt-in, so "route by who" (Production gets Opus, the intern gets denied) becomes a hook decision, not just an access rule.

If any of those would change what you build, tell me. The hook is the product here, and it gets better when people push on it.

The Rust socket hook, the Go webhook, a README with the scoring math, and the benchmark are in the repo under [`examples/smart-router/`](https://github.com/MattJackson/busbarAI/tree/main/examples/smart-router). The wire format lives in the [routing guide](/docs/routing/).
