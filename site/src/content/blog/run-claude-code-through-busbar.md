---
title: "Run Claude Code through Busbar"
description: "Point Claude Code at Busbar with one environment variable — get observability, failover, and budgets for the agent you already use. Then the twist: because Busbar translates between protocols, you can point Claude Code at a Gemini or Bedrock model instead."
date: 2026-07-13
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
ogImage: "/og/claude-code-busbar.png"
---

Claude Code is great as we all know, but on its own it's a black box pointed straight at
one provider. You can't see what it spends, you can't fail it over when a key rate-limits mid-session,
and you can't put anything on its path. I wanted it to stay exactly as good as it is — and become
something I can see, steer, and rely on. That's the whole reason to run it through a control plane.

Busbar speaks the Anthropic protocol natively, so a client using the Anthropic SDK can't tell it
isn't talking to Anthropic. Claude Code is such a client. Put Busbar in the middle with one
environment variable and Claude Code never knows the difference — but now:

- **You can see what it's doing.** Every request and every token, per key and per pool, in Busbar's
  `/metrics` and OTLP traces. The agent's token bill stops being a surprise on your invoice.
- **It doesn't go down mid-session.** Give the pool a second key or a fallback lane; when one trips a
  529 or its breaker, Busbar fails over in-flight without dropping your session.
- **You can put things on its path.** Redaction, audit, and context compression run as hooks inside
  Busbar's request path — transparently, with no change to the agent.

## And here's the part that gets me

"Point it at a provider" doesn't have to mean Anthropic anymore.

A control plane does a lot — routing, failover, observability, budgets, middleware on the path — and
one of the things Busbar does underneath all of that is translate losslessly between the six wire
protocols it speaks. Claude Code sends the Anthropic Messages format; Busbar can translate that, on
the fly, into a Bedrock Converse call or Gemini's `generateContent` — and translate the response back
into exactly the shape Claude Code expects. So you can **run Claude Code against a model on Bedrock,
or against Gemini**, without Claude Code knowing it's not talking to Anthropic at all.

Same agent you know. Different brain behind it. You change one line of Busbar config, not one line of
Claude Code.

## The demo: Claude Code, driven by Amazon Nova Pro

I actually ran this. Here's a Busbar pool named `claude-code` whose one member is Amazon's Nova Pro,
on AWS Bedrock:

```yaml
# config.yaml
models:
  amazon-nova:
    provider: bedrock
    upstream_model: amazon.nova-pro-v1:0   # the real model that answers
pools:
  claude-code:
    members:
      - target: amazon-nova
```

Point Claude Code at the pool. The one *new* variable is the base URL — Busbar routes by the pool in
the URL, so that redirect is the whole integration. The other is the API key Claude Code already uses,
set to a Busbar-issued token:

```sh
export ANTHROPIC_BASE_URL="http://localhost:8080/claude-code"   # the one that redirects it
export ANTHROPIC_API_KEY="vk_…"                                 # already set — now a Busbar token
claude
```

Nova itself wants two small tweaks — an output-token cap and prompt caching off (`CLAUDE_CODE_MAX_OUTPUT_TOKENS`,
`DISABLE_PROMPT_CACHING`) — but those are about Nova's limits, not about Claude Code, which runs unchanged.

Then I launched the real Claude Code window and gave it an agentic coding task — write a small Sudoku
web app across three files (`app.py`, an `http.server` serving a 9×9 grid; `solver.py`, a backtracking
solver; and a `README.md`), then list the folder and report back. The kind of thing that loops through
several tool calls, each one answered by Nova:

![The real Claude Code window building a Sudoku web app, every turn answered by Amazon Nova Pro on Bedrock through Busbar](/demo/claude-nova.gif)

That's the actual Claude Code TUI — same welcome screen, same tool-call cards. It writes all three files,
runs `ls -la`, and reports `DONE`. The model behind every step is Amazon Nova; the `<thinking>` blocks
are Nova's, not Claude's. Busbar translated each Anthropic request into a Bedrock Converse call and the
response back again — the agent never knew.

The receipt, because "trust me" isn't a demo. Bedrock's usage counter starts at zero, and I read AWS's
own CloudWatch numbers for Nova Pro — wholly independent of anything Busbar reports — right before the
run and right after it:

```console
# before
nova-pro   invocations=0   input_tokens=0
# after
nova-pro   invocations=8   input_tokens=17,880
```

Zero to eight invocations, ~17,900 input tokens — one Claude Code session that believed it was talking
to Anthropic, served entirely by Nova. To swap in Gemini, or to put Claude behind two keys with
failover, or to add a compression hook — you edit the pool, not the agent.

## The simple version

If you already run Busbar, this is one variable away. If you don't, it's a single static binary and a
few lines of config to front the model Claude Code is already using — and once it's in the path,
everything else Busbar does comes along for free.

Get it at **[getbusbar.com](https://getbusbar.com)**.
