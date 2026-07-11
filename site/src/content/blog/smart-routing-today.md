---
title: "The smart router you want is a hook"
description: "Everyone asks for automatic model selection by task, latency, quality, and cost. It is not a product, it is a hook. Busbar runs yours two ways: a compiled Rust binary on a local socket that decides in about 8 microseconds, or a webhook in any language. Both wired to the same failover and fail-safe machinery."
date: 2026-07-11
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
discussion: "https://github.com/MattJackson/busbarAI/discussions/14"
---

A user told me this week: "The best model should be selected automatically based on the task, latency, quality, and cost."

I agree. And I want to show why that sentence does not describe a new product. It describes a hook, and it should stay a hook: the policy is your judgment, and your judgment does not belong compiled into someone else's core. Busbar runs that hook two ways, and in this post I show both, measured honestly: a compiled Rust binary on a local Unix socket that decides in about **8 microseconds (µs)**, and a webhook in any language for everywhere else. Both plug into the same failover, circuit-breaker, and fail-safe machinery, so neither can take your traffic down. Any client speaking any of Busbar's six protocols hits the pool as if it were a model, and Translate carries the request to whichever backend wins. (Everything here is built on the 1.2.1 release.)

## The shape of the problem

"Pick the best model automatically" splits into two jobs that people usually blur together.

The first job is the decision. Given a request and a set of models, rank them. This is policy. It changes weekly, it depends on your evals and your budget, and no vendor default will match your judgment for long.

The second job is everything around the decision. See live latency and load. Enforce the ranking. Fail over when the top pick is down. Never let the decision layer itself become an outage. This is infrastructure, and it does not change weekly.

Busbar's position is simple: you own the first job, the control plane owns the second. The seam between them is a hook, and Busbar gives you two ways to run the exact same decision.

## The decision, in three steps

Whichever way you run it, the logic is small and the same. Classify the request into a task bucket from shape alone, score every candidate through that bucket's weights over the live signals, sort.

**Classify** on shape: tools declared means agent or code work. A big `max_tokens` or a long prompt means long-form work. One message with streaming turned off is almost always a script or a cron job, not a person, so it gets treated as batch work. Everything else is a person waiting on an answer. Routing does not need to read your prompt to do any of this, so by default it does not get it.

**Score** is the reality check. Each kind of request has a favorite lane, but the favorite gets a head start, not the win: every lane is scored on how it is doing right now, its price, its latency, its free capacity, weighed by what this kind of request cares about. The favorite gets a bonus on top; a lane near its rate limit gets trimmed.

**Sort** by score, best first, and return that order. That is the whole policy. It is not a static "if X use Y" table and it is not blind cost math: the classification names a favorite, the scoring routes to reality, and the same pool serves a code request and a batch request ranked differently.

## Answer one: a Rust binary on a socket, about 8 microseconds

The pool's name is the model your clients call. Name it whatever you want; here it is `my-smart-model`, and any SDK or a bare curl can ask for it like any other model:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{
    "model": "my-smart-model",
    "messages": [{"role": "user", "content": "hi"}]
  }'
```

Behind that name sits the pool and its hook. `route: socket` points Busbar at a compiled binary you run, listening on a local Unix domain socket. Busbar writes the request-and-candidates projection as one line of JSON, your binary writes back the ranked order, the connection stays open. No HTTP stack, no network, no interpreter.

```yaml
pools:
  my-smart-model:
    route: socket
    policy:
      socket: /run/busbar/router.sock
      timeout_ms: 1          # the hard deadline (the default: hooks are fast)
      on_error: weighted     # the fail-safe
    members:
      - target: claude-fable
        tier: fable          # the ladder every dev knows:
        cost_per_mtok: 25.0  # best and most expensive ...
      - target: claude-opus
        tier: opus
        cost_per_mtok: 15.0
      - target: claude-sonnet
        tier: sonnet
        cost_per_mtok: 3.0
      - target: claude-haiku
        tier: haiku          # ... down to cheap and fast
        cost_per_mtok: 0.8
```

Measured end to end through Busbar's real transport, against the real example binary running as a separate process: median **7.9 µs** per decision, p99 12 µs. Your policy is a separate process, so a crash in it is contained; Busbar never spawns or supervises it, connects lazily, and reconnects across restarts of your binary.

The hook itself is about a hundred lines of Rust, standard library plus serde, and the whole policy fits in your head. In pseudocode:

```text
step 1: classify the request by its shape.
        each kind of request has a favorite lane.

  has tools?              -> agent/code   favorite: "fable"
  big ask or big prompt?  -> long-form    favorite: "opus"
  single-shot, no stream? -> batch        favorite: "haiku"
  otherwise               -> interactive  favorite: "sonnet"

step 2: reality-check the favorite against the live pool.
        the favorite gets a head start, not the win.

  score every lane on how it is doing RIGHT NOW:
  its price, its speed, its free capacity
  (batch cares mostly about price, interactive about speed)

  the favorite gets a bonus on top of its score
  a lane close to its rate limit gets trimmed

  a healthy favorite wins. a saturated, slow favorite
  loses to a healthy lane. that is the point: the
  request routes to reality, not to the plan.

sort by score, best first. That order is the reply.
```

Each signal is normalized against the pool, so "how cheap" means cheapest-in-this-pool, not cheap in the abstract. A lane missing a signal (no cost declared, no latency yet) scores neutral, never punished. The real code, commented line by line, is in the repo.

<svg viewBox="0 0 940 250" role="img" aria-label="The decision flow: a request arrives, your hook classifies it by shape, names a favorite lane, and reality-checks every lane against its live signals; the ranked order goes back to Busbar, which dispatches with failover and the circuit breaker intact." style="width:100%;height:auto;max-width:940px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <defs>
    <marker id="sr-arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="940" height="250" fill="#ffffff"/>
  <rect x="188" y="52" width="546" height="160" rx="14" fill="none" stroke="#a3e635" stroke-width="2" stroke-dasharray="7 6"/>
  <text x="461" y="80" text-anchor="middle" fill="#4d7c0f" font-size="12.5" font-weight="700" letter-spacing="0.04em">YOUR HOOK · ONE DECISION · ABOUT 8 µS</text>
  <g stroke="#94a3b8" stroke-width="2" marker-end="url(#sr-arw)">
    <line x1="158" y1="140" x2="200" y2="140"/>
    <line x1="352" y1="140" x2="380" y2="140"/>
    <line x1="524" y1="140" x2="552" y2="140"/>
    <line x1="722" y1="140" x2="764" y2="140"/>
  </g>
  <g>
    <rect x="18" y="106" width="140" height="68" rx="10" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="88" y="136" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Request</text>
    <text x="88" y="154" text-anchor="middle" fill="#64748b" font-size="10">"model": "my-smart-model"</text>
    <rect x="204" y="106" width="148" height="68" rx="10" fill="#f7fee7" stroke="#a3e635" stroke-width="2"/>
    <text x="278" y="130" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Classify</text>
    <text x="278" y="147" text-anchor="middle" fill="#4d7c0f" font-size="10.5">shape only, no content</text>
    <text x="278" y="161" text-anchor="middle" fill="#4d7c0f" font-size="10.5">tools? size? streaming?</text>
    <rect x="384" y="106" width="136" height="68" rx="10" fill="#f7fee7" stroke="#a3e635" stroke-width="2"/>
    <text x="452" y="130" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Favorite</text>
    <text x="452" y="147" text-anchor="middle" fill="#4d7c0f" font-size="10.5">the plan: agent work</text>
    <text x="452" y="161" text-anchor="middle" fill="#4d7c0f" font-size="10.5">wants "fable"</text>
    <rect x="556" y="106" width="162" height="68" rx="10" fill="#f7fee7" stroke="#a3e635" stroke-width="2"/>
    <text x="637" y="130" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Reality check</text>
    <text x="637" y="147" text-anchor="middle" fill="#4d7c0f" font-size="10.5">score EVERY lane live:</text>
    <text x="637" y="161" text-anchor="middle" fill="#4d7c0f" font-size="10.5">price · speed · free slots</text>
    <rect x="768" y="106" width="154" height="68" rx="10" fill="#f8fafc" stroke="#e2e8f0"/>
    <text x="845" y="130" text-anchor="middle" fill="#0f172a" font-size="14" font-weight="700">Dispatch</text>
    <text x="845" y="147" text-anchor="middle" fill="#64748b" font-size="10.5">busbar walks the order,</text>
    <text x="845" y="161" text-anchor="middle" fill="#64748b" font-size="10.5">failover + breaker intact</text>
  </g>
  <text x="461" y="236" text-anchor="middle" fill="#64748b" font-size="11">hook slow, wrong, or dead? Busbar falls back to its default after 1 ms and the request proceeds anyway</text>
</svg>

Here is the decision it actually makes. One pool, the four lanes above, with live signals at this moment: `claude-fable` ($25/Mtok, 400 ms, 16 free slots), `claude-opus` ($15, 320 ms, 12 free), `claude-sonnet` ($3, 150 ms, 10 free), `claude-haiku` ($0.80, 95 ms, 6 free). The expensive lanes sit idle; the cheap ones are busy. Two requests walk in:

```text
request A: has_tools=true         -> agent/code bucket, favorite "fable"
  claude-fable:   signals 0.40  + boost 0.50 = 0.90   <- first
  claude-sonnet:  signals 0.68               = 0.68
  claude-haiku:   signals 0.65               = 0.65
  claude-opus:    signals 0.46               = 0.46
  reply: {"order":[0,2,3,1]}  -> the frontier model gets the agent work

request B: single-shot, no stream -> batch bucket, favorite "haiku"
  claude-haiku:   signals 0.77  + boost 0.50 = 1.27   <- first
  claude-sonnet:  signals 0.78               = 0.78
  claude-opus:    signals 0.49               = 0.49
  claude-fable:   signals 0.30               = 0.30
  reply: {"order":[3,2,1,0]}  -> the cheap model gets the batch job
```

Same pool, same four lanes, and `claude-fable` goes from first to last depending on what walked in. That is the whole idea: based on the request's shape, choose the lane. And the boost is a tilt, not a mandate: a preferred lane that is saturated and slow scores near zero on its live signals and a healthy lane outranks it. The failover loop then walks whatever order comes back, breaker rules intact.

## Answer two: a webhook, in any language, on any OS

The socket hook is Unix-only and compiled. When you want the policy in whatever your team already ships, or you are on Windows, you write a webhook. Set `route: webhook`, point it at a sidecar you run, and Busbar POSTs the same projection over HTTP and reads back the same ranked `{"order":[...]}`:

```yaml
pools:
  my-smart-model:
    route: webhook
    policy:
      url: "http://127.0.0.1:8787/"
      timeout_ms: 1          # the same hard deadline
      on_error: weighted     # the same fail-safe
    members:
      - target: claude-fable
        tier: fable          # the ladder every dev knows:
        cost_per_mtok: 25.0  # best and most expensive ...
      - target: claude-opus
        tier: opus
        cost_per_mtok: 15.0
      - target: claude-sonnet
        tier: sonnet
        cost_per_mtok: 3.0
      - target: claude-haiku
        tier: haiku          # ... down to cheap and fast
        cost_per_mtok: 0.8
```

The example sidecar is about a hundred lines of Go, standard library only, and it makes the exact same decision: classify on shape, score through the bucket's dials, sort. Same classify, same weights, same sort, and critically the same wire contract: both transports carry byte-identical JSON, so a hook graduates from a webhook prototype to a compiled socket binary without changing its logic. Both examples are in the repo under [`examples/smart-router/`](https://github.com/MattJackson/busbarAI/tree/main/examples/smart-router). The webhook adds the HTTP round trip the socket does not: about 34 µs co-located, measured the same way, and it runs anywhere.

## What the hook sees, and what it does not

Both paths see the same projection. For the request: pool name, ingress protocol, message count, whether tools are declared, total prompt size in characters, requested `max_tokens`, whether it streams. For each candidate: model name, operator-declared `tier` and `cost_per_mtok`, a rolling latency EWMA, live free concurrency, remaining budget, and rate-limit headroom from Governance.

Notice what is missing: the prompt. Routing is a shape decision, so by default Busbar sends no message content with it, and the policy classifies on sizes, counts, and flags, not on words. Your prompts do not leave the process just to pick a model. That is a Security default, not an accident, but it is not a wall: content is a separate, explicit, per-hook switch, off unless you turn it on. Default deny, opt in on purpose. That switch is what makes the next hooks, like PII redaction and guardrails, possible at all.

## The part that makes it safe to run

Here is the reason this belongs in a control plane and not in your app code. The hook is advisory. It can never become load-bearing.

The decision has a hard deadline, `policy.timeout_ms`, which defaults to 1 millisecond. That default is a statement: hooks are fast, and a deadline should say so. A co-located socket hook decides in about 8 µs and a co-located webhook in about 34 µs, so 1 ms is 20x headroom or more. If your hook is legitimately slower, it calls a database, crosses the network, or asks a model, you raise the deadline; the default does not pay for it. If the hook is slow, the decision is cut off and Busbar applies `on_error`, which defaults to plain weighted round-robin. Same for a crash, a non-2xx, or malformed JSON. A broken sidecar is indistinguishable from having no policy at all. Kill the router mid-traffic and requests keep flowing.

And the ranking feeds the same Failover loop everything else uses. If the policy's first choice is tripped or at capacity, Busbar walks to the second with the normal circuit-breaker machinery. If the policy drops a candidate from its list, that lane is demoted, not excluded, so a buggy ranking can never strand a healthy model. The policy proposes. The control plane disposes.

Every response tells you what happened: `x-busbar-route-policy` and `x-busbar-route-target` are on every reply. That is Observability on every single decision, not sampled, not opt-in.

## What it costs, measured

You can reproduce both numbers yourself; the benchmark and the commands are in [`examples/smart-router/bench/`](https://github.com/MattJackson/busbarAI/tree/main/examples/smart-router/bench), all on an Apple M5 Pro, all through Busbar's real transport code against real separate processes.

- **Socket hook:** median 7.9 µs, p99 12 µs (50,000 samples). A compiled Rust binary over a kept-alive local socket. The whole Busbar layer adds tens of µs to a request, so the decision is close to free.
- **Webhook:** median 34 µs, p99 47 µs (20,000 samples), co-located over loopback, plus whatever the network hop costs if it is not. You trade roughly 4x the socket's latency for any-language, any-OS reach; both are noise next to an LLM call.

Either way it is far under even the 1 ms default deadline, after which Busbar coerces the decision to the pool's `on_error` fallback and the request proceeds anyway. (For the record: Busbar previously offered an embedded script engine for this, and the interpreter alone cost about 108 µs per decision, twenty times the entire compiled hook round trip. It is deprecated as of 1.2.1. When the same logic runs 20x faster in a separate process that cannot crash the control plane, an embedded interpreter is the wrong tool.)

## Honest words about "quality"

Task, latency, and cost are measurable at request time, and the hook sees all three live. Quality is not measurable at request time, and I won't pretend it is.

What quality means here: you run your evals, you form a judgment about which models are good at what, and you encode that judgment as `tier` and `tags` on your pool members. The hook reads those labels and boosts accordingly. Busbar is the enforcement point for your judgment, not the source of it. Anyone selling you request-time quality magic is selling you a hidden eval you didn't run and can't audit. I would rather give you the seam and let you plug in labels you actually believe.

## Why a hook, and not a feature

Here is the thinking behind all of this. I build hooks so a team can encode its own policy without the core carrying fifty features that ninety-five percent of users will never turn on. Smart routing is the perfect example: it is not one behavior, it is your behavior, and it changes with your evals and your budget. I even prototyped building this router into the core, measured it at 0.67 µs, and then took it back out. Fast was not the question. Whose judgment ships in the binary was the question, and the answer is yours, not mine.

So the core carries the seam and the guarantees: the projection, the deadline, the fail-safe, the failover integration. The policy stays a hook, and the hook ladder is a speed-versus-reach choice you make per pool: the webhook for any language on any OS, the socket binary when you want the decision in single-digit µs. Same contract on both rungs.

The next question is distribution. A routing policy someone already tuned for their workload is one you should be able to start from instead of writing from scratch, the same way you reach for a package. Call it a Hooks Repository: a place teams publish and share hooks. I would genuinely like your thoughts on this. Grow a shared hook ecosystem around the seam? Tell me what would actually change how you run this.

## What 1.3 could add

The native policy and the webhook are the two answers today. Building them showed me where the seam should grow next. On my roadmap thinking, not a promise:

- `tags` in the hook payload, so a policy can route on your own labels, not just `tier`.
- An explicit, per-hook content switch, off by default. Routing never needs your prompt, but the next hooks do: PII redaction, audit, and guardrails. A hook that can see the request can reject one that carries PII before it ever leaves your network, and that is impossible if the hook is blind to content. So content stays default-off and opt-in, per hook, your call, never a global firehose.
- The caller's identity to a hook, again opt-in, so "route by who" (Production gets Opus, the intern gets denied) becomes a hook decision, not just an access rule.

If any of those would change what you build, tell me. The hook is the product here, and it gets better when people push on it.

The Rust socket hook, the Go webhook, a README with the scoring math, and the benchmark are in the repo under [`examples/smart-router/`](https://github.com/MattJackson/busbarAI/tree/main/examples/smart-router). The wire format lives in the [routing guide](/docs/routing/).
