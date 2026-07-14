---
title: "Valuable before the second provider exists"
ogImage: "/og/valuable-before-the-second-provider.png"
description: "Why a control plane earns its keep with one provider: key custody, hard caps, and real metrics on day one, plus an option you can exercise mid-incident."
date: 2026-07-09
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

Everyone files an LLM gateway under "multi-provider failover," so teams with one provider conclude it isn't for them yet. I think that's exactly backwards, and I want to walk through why using my own setup.

## I run Busbar with one provider and no features

Straight passthrough. One provider, same protocol in and out, byte-for-byte, nothing enabled. That configuration already changed my security posture the day I switched to it:

- **The provider key moved out of every app deployment** and into one process. My applications carry a Busbar token I can revoke instantly. A leaked app credential is no longer a leaked provider account, and rotating the real key takes one restart.
- **A runaway loop hits my ceiling, not my bill.** `max_concurrent` is a hard cap on concurrency per model. An agent stuck in a retry spiral gets queued at the cap.
- **The traffic became visible.** Direct SDK calls are invisible; through Busbar, every request shows up in `/metrics` and `/stats`, and the circuit breaker classifies failures by default. A provider degradation is a graph, not a surprise.
- **The request path got stricter for free**: SSRF-guarded upstream URLs, constant-time token comparison, request-body caps, secrets never logged.

The cost of that hop is tens of microseconds. Busbar will report its own overhead on every response if you ask it to (`Server-Timing`, one config flag), so you don't have to take my word for it.

So even if nothing ever went wrong, I'd keep it there. But something went wrong.

## Then Anthropic went down

My provider had a bad day, as every provider eventually does. Here's the part that matters: **the provider I failed over to did not exist in my stack when the outage started.** I opened a Z.ai account, added it to Busbar's config, and flipped traffic. It speaks the OpenAI-compatible protocol, so "integrating" it was a few lines of YAML: a name, a base URL, an env var for the key.

The outage ended for my app the moment the config flipped. No redeploy, no code change, no emergency pull request: the recovery was an edit to a YAML file, not an engineering project. The app was written against one provider's SDK and still is. It has no idea anything happened, because the model name it calls is a config value in Busbar, not a dependency in the code.

That's the thing the "failover" framing undersells. Failover between two configured providers is table stakes. What I actually used was the ability to *manufacture* a second provider mid-incident, because Busbar was already holding the seam where providers plug in.

## The compliance version of the same story

A prospect told me recently: we only use Bedrock, our data involves PHI, and unless we sign BAAs with Anthropic or OpenAI directly, it stays that way. So what's a multi-provider gateway for?

Same answer. Point the Bedrock SDK's `endpoint_url` at Busbar today and change nothing else. Same-protocol traffic passes through byte-for-byte, and because Busbar runs in your own infrastructure, no new entity enters the PHI path; your BAAs stay exactly where they are. You get the key custody, the caps, and the visibility now. And the day a direct BAA lands, or a cheaper model fits a workload, that backend is a new lane in `config.yaml`. Your application, written against the Bedrock SDK, never changes and never learns which model answered.

Without the control plane already in place, that day starts with rewriting every LLM integration you own. With it, the migration you'll eventually want is a config edit you've already paid for.

## The option is the product

The endpoint swap is a one-line change. What it buys is an option on every provider that exists or will exist, exercisable in minutes, without touching application code. Most days the option just sits there while you enjoy better key custody and real metrics. On the bad day, it's the whole product.

Busbar is open source at **[getbusbar.com](https://getbusbar.com)**. If you're running LLM traffic in production, on one provider or five, I'd love to hear what breaks.
