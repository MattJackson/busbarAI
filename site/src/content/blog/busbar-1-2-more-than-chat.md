---
title: "Busbar 1.2: more than chat"
description: "Embeddings, moderations, image generation, and audio — transcription and speech — now run through Busbar, and every one is cross-protocol. An OpenAI client can call embeddings on Bedrock, images on Gemini, audio on either, and get the answer back in its own dialect. Lossless, both ways."
date: 2026-07-10
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

For its whole life so far, Busbar has done one thing extremely well: it takes a chat request in any of six wire protocols, routes it to a pool of backends, and translates it losslessly to whatever the backend speaks — and back. Chat was the whole job.

With **1.2, Busbar speaks more than chat.** Four new operations land on top of it, and every one is cross-protocol from day one:

- **Embeddings**
- **Moderations**
- **Image generation**
- **Audio** — transcription (speech-to-text, including speech-to-English translation) and speech (text-to-speech)

## Cross-protocol is the whole point

Here's the part I care about. These aren't four passthrough endpoints bolted on. They go through the same lossless translation layer chat already uses, so you can mix a client dialect and a backend that have never heard of each other.

Concretely, the matrix that works today:

- **Embeddings** from an OpenAI-dialect client onto **OpenAI**, **Amazon Bedrock** (Titan), **Cohere** (v2), or **Google Gemini** (`embedContent`).
- **Image generation** onto **OpenAI**, **Gemini** (Imagen), or **Bedrock** (Titan).
- **Audio** onto **OpenAI** and **Gemini**.

Point your OpenAI SDK at Busbar, call `client.embeddings.create(...)`, and land on a Bedrock Titan or a Gemini backend without changing a line. The vectors come back in the shape your SDK expects. Ask for an image and route it to Imagen; ask for a transcription and route it to Gemini. Your code never learns where it went.

And it's lossless *both ways* — responses and **errors**. If the backend rejects the request, you get the error in your own protocol's envelope, not a leaked upstream shape you have to special-case. Token and usage accounting survives the round trip too, on every operation, not just chat.

## What happens when a backend can't do it

Not every backend implements every operation. Anthropic has no image endpoint. So what happens when you call images against an Anthropic-backed lane?

You get a clean **404, in your own dialect.** Not a 500, not a crash, not a malformed body, and — this is the load-bearing part — not a lane that goes down and takes other traffic with it. An unsupported operation is an ordinary, well-formed "not here," rendered in the protocol you called with.

## Under the hood

Briefly, because it's why the above was tractable rather than a pile of special cases: the request path is now four clean layers — Router → RequestHandler → OperationHandler → IR. Each operation is a small codec over the same reliability engine that already does pools, failover, and fault-attributed circuit breaking. Chat is just operation #1; it isn't privileged anymore. Adding an operation means writing a codec, not touching routing or the breaker.

Billing moved to a polymorphic model in the same release — tokens, duration, characters, images, or a flat unit, whichever an operation naturally meters on. Turning those units into actual dollar costs is a pricing engine I'm building for 1.3.

## Chat is exactly where you left it

I ran the whole thing through the acceptance harness: **58/58 offline, and chat is byte-for-byte identical to before.** None of this changed the request you're already sending. It just means the same gateway now carries four more kinds of it.

Get it at **[getbusbar.com](https://getbusbar.com)**. If you're running multi-provider traffic and want embeddings or audio to survive a backend swap the same way your chat already does, I'd love to hear how it goes.
