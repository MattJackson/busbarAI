---
title: "Run Claude Code through Busbar"
description: "Point Claude Code at Busbar with one environment variable — get observability, failover, and budgets for the agent you already use. Then the twist: because Busbar translates between protocols, you can point Claude Code at a Gemini or Bedrock model instead."
date: 2026-07-12
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

Claude Code is the best coding agent I've used, and on its own it's a black box pointed straight at
one provider. You can't see what it spends, you can't fail it over when a key rate-limits mid-session,
and you can't put anything on its path. I wanted it to stay exactly as good as it is — and become
something I can see, steer, and rely on. That's the whole reason to run it through a gateway.

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

Busbar's whole job is lossless translation between the six wire protocols it speaks. Claude Code
sends the Anthropic Messages format; Busbar can translate that, on the fly, into Gemini's
`generateContent` or a Bedrock Converse call — and translate the response back into exactly the shape
Claude Code expects. So you can **run Claude Code against Gemini, or against Bedrock**, without Claude
Code knowing it's not talking to Anthropic at all.

Same agent you know. Different brain behind it. You change one line of Busbar config, not one line of
Claude Code.

## The demo

A Busbar pool named `claude-code`, pointed at a **Gemini** model:

```yaml
# config.yaml
pools:
  claude-code:
    members:
      - target: gemini-2.5-pro     # the model actually answering
        weight: 1
```

Point Claude Code at that pool:

```sh
export ANTHROPIC_BASE_URL="http://localhost:8080/claude-code"
export ANTHROPIC_API_KEY="vk_…"   # a Busbar-issued key, not a raw provider key
claude
```

Now run it. Claude Code sends Anthropic; Gemini answers:

```console
$ claude "explain what src/forward/mod.rs does in two sentences"
● Busbar translated the Anthropic request to Gemini and streamed it back —
  Claude Code rendered it like any other response.

$ curl -s localhost:8080/metrics | grep claude-code
busbar_requests_total{pool="claude-code",backend="gemini",status="200"} 1
busbar_tokens_total{pool="claude-code",backend="gemini",kind="input"} 812
```

The agent thinks it talked to Anthropic. The metrics show Gemini served it. To swap in Bedrock, or to
put Claude behind two keys with failover, or to add a compression hook — you edit the pool, not the
agent.

## The simple version

If you already run Busbar, this is one variable away. If you don't, it's a single static binary and a
few lines of config to front the model Claude Code is already using — and once it's in the path,
everything else Busbar does comes along for free.

Get it at **[getbusbar.com](https://getbusbar.com)**.
