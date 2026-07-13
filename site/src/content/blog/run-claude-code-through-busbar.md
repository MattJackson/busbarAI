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

## The demo: Claude Code, driven by Amazon Nova

I actually ran this. Here's a Busbar pool named `claude-code` whose one member is Amazon's Nova Lite,
on AWS Bedrock:

```yaml
# config.yaml
models:
  amazon-nova:
    provider: bedrock
    upstream_model: amazon.nova-lite-v1:0   # the real model that answers
pools:
  claude-code:
    members:
      - target: amazon-nova
```

Point Claude Code at the pool. The only integration is the base URL:

```sh
export ANTHROPIC_BASE_URL="http://localhost:8080/claude-code"
export ANTHROPIC_API_KEY="vk_…"        # a Busbar-issued token
export ANTHROPIC_MODEL="claude-code"   # the pool name
claude
```

Then I gave it a small agentic task — create a file, read it back, count the words, list the
directory — the kind of thing that makes Claude Code loop through several tool calls. Every one of
those turns was answered by Nova:

![Claude Code running an agentic task through Busbar, every turn answered by Amazon Nova on Bedrock](/demo/claude-nova.gif)

That's the real CLI. Claude Code plans, writes `notes.txt`, reads it back, writes `count.txt`, runs
`ls`, and reports DONE — and the model behind every step is Nova, not Claude. One agentic prompt fanned
out into about ten back-and-forth calls, and Busbar translated each Anthropic request into a Bedrock
Converse call and the response back again.

Two sets of receipts, because "trust me" isn't a demo. Busbar counts every call it routes to the
Bedrock backend:

```console
$ curl -s localhost:8080/metrics -H "authorization: Bearer vk_…" | grep claude-code
busbar_requests_total{ingress_protocol="anthropic",pool="claude-code",outcome="ok"} 19
```

And AWS Bedrock's own CloudWatch usage for `nova-lite` — independent of anything Busbar reports:

```console
$ aws cloudwatch get-metric-statistics --namespace AWS/Bedrock \
    --metric-name Invocations   --dimensions Name=ModelId,Value=amazon.nova-lite-v1:0 ...
17.0
$ ... --metric-name InputTokenCount ...
9839.0
$ ... --metric-name OutputTokenCount ...
900.0
```

The agent thinks it talked to Anthropic. Busbar's metrics and AWS's own console agree it was Nova. To
swap in Gemini, or to put Claude behind two keys with failover, or to add a compression hook — you edit
the pool, not the agent.

## The simple version

If you already run Busbar, this is one variable away. If you don't, it's a single static binary and a
few lines of config to front the model Claude Code is already using — and once it's in the path,
everything else Busbar does comes along for free.

Get it at **[getbusbar.com](https://getbusbar.com)**.
