---
title: "The smart router you want is a hook. Here it is, in 0.67 microseconds."
description: "Everyone asks for automatic model selection by task, latency, quality, and cost. It is not a product, it is a hook. Busbar gives you two ways to run it: a native policy it ships that ranks in 0.67 microseconds, or your own webhook in any language. Both wired to the same failover and fail-safe machinery."
date: 2026-07-11
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

A user told me this week: "The best model should be selected automatically based on the task, latency, quality, and cost."

I agree. And I want to show why that sentence does not describe a new product. It describes a hook. Busbar, Your AI Control Plane, gives you two ways to run that hook, and in this post I show both, measured honestly: a native policy Busbar ships that ranks a request in about **0.67 microseconds**, and a webhook you write in any language when you want logic of your own. Both plug into the same failover, circuit-breaker, and fail-safe machinery, so neither can take your traffic down. (Everything here is built on the 1.2.1 release.)

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

## Answer one: the native policy Busbar ships

You do not have to write it. Busbar ships this exact logic as a native routing policy. One line:

```yaml
pools:
  chat:
    route: smart
    members:
      - target: claude-sonnet
        tier: large
        cost_per_mtok: 3.0
      - target: gpt-4o-mini
        tier: small
        cost_per_mtok: 0.15
```

`route: smart` classifies, scores, and ranks in-process, compiled, no sidecar and no script. On an Apple M5 Pro it ranks a request in about **0.67 microseconds** (666 nanoseconds median, measured, see the benchmark). That is not a typo. The whole Busbar layer adds tens of microseconds to a request, so a routing decision at two thirds of a microsecond is free in any way that matters. You set `tier` and `cost_per_mtok` on each member; the policy does the rest, per request.

## Answer two: your own hook, in any language

The native policy is opinionated on purpose. When you want your own logic, weights you tuned on your own evals, or a rule the built-in does not have, you write a webhook. Set `route: webhook`, point it at a sidecar you run, and Busbar POSTs the same request-and-candidates projection before each failover loop and reads back a ranked `{"order":[...]}`. The sidecar is any language. The example is about a hundred lines of Go, standard library only, and its `classify` is the same shape as the native one:

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

Same classify, same weights, same sort as the native policy, now yours to change. The full sidecar and a `route: webhook` config are in the repo under [`examples/smart-router/`](https://github.com/MattJackson/busbarAI/tree/main/examples/smart-router). A webhook adds a network round trip the native policy does not, but it stays under a millisecond on a co-located sidecar and it lets you write the decision in whatever your team already runs.

## What the hook sees, and what it does not

Both paths see the same projection. For the request: pool name, ingress protocol, message count, whether tools are declared, total prompt size in characters, requested `max_tokens`, whether it streams. For each candidate: model name, operator-declared `tier` and `cost_per_mtok`, a rolling latency EWMA, live free concurrency, remaining budget, and rate-limit headroom from Governance.

Notice what is missing: the prompt. Routing is a shape decision, so by default Busbar sends no message content with it, and the policy classifies on sizes, counts, and flags, not on words. Your prompts do not leave the process just to pick a model. That is a Security default, not an accident, but it is not a wall: content is a separate, explicit, per-hook switch, off unless you turn it on. Default deny, opt in on purpose. That switch is exactly what makes the next hooks possible, which is where this goes.

Any client speaking any of Busbar's six protocols hits the pool as if it were a model, and Translate carries the request to whichever backend wins. Every response tells you what happened: `x-busbar-route-policy` and `x-busbar-route-target`. That is Observability on every single decision.

## The part that makes it safe to run

Here is the reason this belongs in a control plane and not in your app code. The hook is advisory. It can never become load-bearing.

The decision has a hard deadline, `policy.timeout_ms`, which defaults to 150 ms. If the sidecar is slow, the decision is cut off and Busbar applies `on_error`, which defaults to plain weighted round-robin. Same for a crash, a non-2xx, or malformed JSON. A broken sidecar is indistinguishable from having no policy at all. Kill the router mid-traffic and requests keep flowing.

And the ranking feeds the same Failover loop everything else uses. If the policy's first choice is tripped or at capacity, Busbar walks to the second with the normal circuit-breaker machinery. If the policy drops a candidate from its list, that lane is demoted, not excluded, so a buggy ranking can never strand a healthy model. The policy proposes. The control plane disposes.

## What it costs, measured

You can reproduce both numbers yourself; the benchmark is in [`examples/smart-router/bench/`](https://github.com/MattJackson/busbarAI/tree/main/examples/smart-router/bench), all on an Apple M5 Pro.

- **Native `route: smart`: about 0.67 microseconds** median to rank a request (666 ns, 50,000 samples). In-process, compiled, no network, no interpreter. It is a rounding error on the request.
- **Webhook: sub-millisecond** on a co-located sidecar, plus whatever the network hop costs if it is not co-located. You trade a little latency for the freedom to write the decision in any language.

Either way it is far under the 150 ms deadline, after which Busbar coerces the decision to the pool's `on_error` fallback and the request proceeds anyway. (For the record: I first prototyped the in-process path with an embedded script interpreter and it landed near 100 microseconds, over a hundred times slower than native. That is why the shipped in-process answer is compiled, not scripted.)

## Honest words about "quality"

Task, latency, and cost are measurable at request time, and the hook sees all three live. Quality is not measurable at request time, and I won't pretend it is.

What quality means here: you run your evals, you form a judgment about which models are good at what, and you encode that judgment as `tier` and `tags` on your pool members. The hook reads those labels and boosts accordingly. Busbar is the enforcement point for your judgment, not the source of it. Anyone selling you request-time quality magic is selling you a hidden eval you didn't run and can't audit. I would rather give you the seam and let you plug in labels you actually believe.

## Why a hook, and not a feature

Here is the thinking behind all of this. I build hooks so a team can encode its own policy without the core carrying fifty features that ninety-five percent of users will never turn on. So why did I then build `route: smart` into the core?

Because the common case deserves to be instant and free, and the custom case deserves to exist. Native `smart` is the opinionated default: no sidecar, no code, 0.67 microseconds. The webhook is the escape hatch: your logic, your language, when the default is not your judgment. The core stays small and sharp because the native policy is knob-light and the interesting variation lives in the hook, not in a growing pile of config.

The next question is distribution. A routing policy someone already tuned for their workload is one you should be able to start from instead of writing from scratch, the same way you reach for a package. Call it a Hooks Repository: a place teams publish and share hooks. I would genuinely like your thoughts on this. Grow a shared hook ecosystem around the seam, keep expanding the native policies, or both? Tell me what would actually change how you run this.

## What 1.3 could add

The native policy and the webhook are the two answers today. Building them showed me where the seam should grow next. On my roadmap thinking, not a promise:

- Configurable bucket weights on the native `smart` policy, so you can retune the dials in config without dropping to a webhook.
- `tags` in the hook payload, so a policy can route on your own labels, not just `tier`.
- An explicit, per-hook content switch, off by default. Routing never needs your prompt, but the next hooks do: PII redaction, audit, and guardrails. A hook that can see the request can reject one that carries PII before it ever leaves your network, and that is impossible if the hook is blind to content. So content stays default-off and opt-in, per hook, your call, never a global firehose.
- The caller's identity to a hook, again opt-in, so "route by who" (Production gets Opus, the intern gets denied) becomes a hook decision, not just an access rule.

If any of those would change what you build, tell me. The hook is the product here, and it gets better when people push on it.

The native `smart` policy, the Go webhook example, a README with the scoring math, and the benchmark are in the repo under [`examples/smart-router/`](https://github.com/MattJackson/busbarAI/tree/main/examples/smart-router). The wire format lives in the [routing guide](/docs/routing/).
