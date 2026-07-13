---
title: "Run Claude Code through Busbar"
description: "Point Claude Code at Busbar with one environment variable and get observability, failover, budgets, and on-path middleware for the coding agent you already use — without changing anything about how it works."
date: 2026-07-12
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

Claude Code talks to the Anthropic API. Busbar speaks the Anthropic protocol natively — a client
using the Anthropic SDK can't tell it isn't talking to Anthropic. Put those two facts together and
you get something useful: you can run Claude Code *through* Busbar by setting one environment
variable, and Claude Code never knows the difference.

## How

Claude Code honors `ANTHROPIC_BASE_URL`. Point it at a Busbar pool that has a Claude model in it:

```sh
export ANTHROPIC_BASE_URL="https://your-busbar:8080/my-pool"
export ANTHROPIC_API_KEY="vk_…"   # a Busbar-issued key, not your raw Anthropic key
claude
```

That's the whole integration. Claude Code sends `POST /v1/messages`; Busbar's Anthropic ingress
answers it, translating to whatever the pool's backend actually speaks and streaming the response
back in the exact shape Claude Code expects. Your real provider keys live in Busbar's config, on
your network — not in the agent's environment on every laptop.

## Why

The point isn't to add a hop for its own sake. It's that Claude Code, on its own, is a black box
pointed straight at a provider. Putting Busbar in the middle makes it something you can see and
steer:

- **See what it's doing.** Every request and every token Claude Code spends shows up in Busbar's
  `/metrics` and OTLP traces, per key and per pool. The agent's token bill stops being a surprise
  on your invoice.
- **Don't go down mid-session.** Give the pool more than one way to reach Claude — a second
  Anthropic key, or a Bedrock/Vertex Claude lane as fallback. When one returns a 529 or trips its
  breaker, Busbar fails over in-flight to the next without dropping your session.
- **Budgets and rate limits.** Cap spend per key or per team, throttle requests, and revoke a key
  the moment you need to — all without touching the agent.
- **Middleware on the path.** Redaction, audit, and context compression run as hooks *inside*
  Busbar's request path, so they apply to Claude Code transparently. (More on the compression one
  in a couple of days.)

## Pros and cons, honestly

**Pros:** one environment variable, no code change; Claude Code stays exactly Claude Code; your
provider keys move off every developer's machine into one governed place; and you can front
multiple Claude providers behind a single endpoint.

**Cons:** it's one more hop — a sub-millisecond one, measured from Busbar's own clock (tens of
microseconds of gateway time; see the [benchmark](/docs/benchmark/)), but a hop you now operate.
Busbar is a single static binary with no dependencies, so "operate" is light, but it's yours to
run. And you have to trust it with your traffic — which is exactly why it's self-hosted and your
keys never leave your network.

## The simple version

If you already run Busbar, this is one variable away. If you don't, it's a single binary and a
few lines of config to front the model Claude Code is already using — and once it's in the path,
everything else Busbar does (failover, budgets, observability, hooks) comes along for free.

Get it at **[getbusbar.com](https://getbusbar.com)**.
