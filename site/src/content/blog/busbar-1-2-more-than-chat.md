---
title: "Busbar 1.2: more than chat"
description: "Embeddings, moderations, image generation, and audio (transcription and speech) now run through Busbar, and every one is cross-protocol. A Gemini client can call embeddings on Bedrock, an OpenAI client can route images and audio to Gemini, and every answer comes back in the caller's own dialect. Lossless, both ways."
date: 2026-07-10
author: "Matthew Jackson"
authorTitle: "Founder, Busbar"
---

For its whole life so far, Busbar has done one thing extremely well: it takes a chat request in any of six wire protocols, routes it to a pool of backends, and translates it losslessly to whatever the backend speaks, and back. Chat was the whole job. That is the core of Busbar as an AI control plane, and until now it only carried one kind of traffic.

With **1.2, Busbar speaks more than chat.** Five new operations land on top of it, and every one is cross-protocol: embeddings, moderations, image generation, audio (transcription, speech-to-English translation, and text-to-speech), and rerank.

## Cross-protocol is the whole point

Here's the part I care about. These aren't four passthrough endpoints bolted on. They go through the same lossless translation layer chat already uses, so you can mix a client dialect and a backend that have never heard of each other.

Concretely, the matrix that works today:

<div class="cap-matrix">
  <style>
    .cap-matrix { background: #0f172a; border-radius: 14px; padding: 1rem 1.25rem; margin: 1.5rem 0; overflow-x: auto; }
    .cap-matrix table { width: 100%; min-width: 480px; border-collapse: collapse; font-size: 0.85rem; color: #e2e8f0; }
    .cap-matrix th, .cap-matrix td { padding: 0.45rem 0.6rem; text-align: center; }
    .cap-matrix thead th { font-weight: 600; }
    .cap-matrix th:first-child, .cap-matrix td:first-child { text-align: left; }
    .cap-matrix tbody tr { border-top: 1px solid #1e293b; }
    .cap-matrix tbody th { font-weight: 600; }
    .cap-matrix .yes { color: #a3e635; font-weight: 700; }
    .cap-matrix .no { color: #334155; }
    .cap-matrix caption { caption-side: bottom; color: #94a3b8; font-size: 0.75rem; padding-top: 0.6rem; text-align: left; }
  </style>
  <table>
    <caption>Backend coverage per operation in 1.2. Any client dialect that speaks the operation can call it.</caption>
    <thead>
      <tr><th>Operation</th><th>OpenAI</th><th>Anthropic</th><th>Gemini</th><th>Bedrock</th><th>Cohere</th></tr>
    </thead>
    <tbody>
      <tr><th>Chat</th><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
      <tr><th>Embeddings</th><td class="yes">✓</td><td class="no">·</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
      <tr><th>Images</th><td class="yes">✓</td><td class="no">·</td><td class="yes">✓</td><td class="yes">✓</td><td class="no">·</td></tr>
      <tr><th>Audio</th><td class="yes">✓</td><td class="no">·</td><td class="yes">✓</td><td class="no">·</td><td class="no">·</td></tr>
      <tr><th>Moderations</th><td class="yes">✓</td><td class="no">·</td><td class="no">·</td><td class="no">·</td><td class="no">·</td></tr>
      <tr><th>Rerank</th><td class="no">·</td><td class="no">·</td><td class="no">·</td><td class="yes">✓</td><td class="yes">✓</td></tr>
    </tbody>
  </table>
</div>

Point a Gemini SDK at Busbar, ask for embeddings, and land on a Bedrock backend without changing a line. The vectors come back in the shape your SDK expects. Any pairing the matrix allows works the same way, in any direction, for images and audio too. Your code never learns where it went.

Rerank is the newest row: Cohere's v2 rerank and Bedrock's rerank models, cross-protocol between the two, and the clean dialect-native 404 everywhere else.

And it's lossless *both ways*: responses and errors. If the backend rejects the request, you get the error in your own protocol's envelope, not a leaked upstream shape you have to special-case. Token and usage accounting survives the round trip too, on every operation, not just chat.

## What happens when a backend can't do it

The dots in the matrix are real gaps: some backends just don't do some operations. So what happens when you call images against an Anthropic-backed lane?

You get a clean **404, in your own dialect.** Not a 500, not a crash, not a malformed body, and (this is the load-bearing part) not a lane that goes down and takes other traffic with it. An unsupported operation is an ordinary, well-formed "not here," rendered in the protocol you called with.

## Under the hood

Briefly, because it's why the above was tractable rather than a pile of special cases. The request path is now four clean layers: Router → RequestHandler → OperationHandler → IR. Each operation is a small codec over the same reliability engine that already does pools, failover, and fault-attributed circuit breaking. Chat is just operation #1; it isn't privileged anymore. Adding an operation means writing a codec, not touching routing or the breaker.

Billing moved to a polymorphic model in the same release: tokens, duration, characters, images, or a flat unit, whichever an operation naturally meters on. Turning those units into actual dollar costs is a pricing engine I'm building for 1.3.

## Chat is exactly where you left it

I ran the whole thing through the acceptance harness: **58/58 offline, and chat is byte-for-byte identical to before.** None of this changed the request you're already sending. It just means the same AI control plane now carries four more kinds of it.

Get it at **[getbusbar.com](https://getbusbar.com)**. If you're running multi-provider traffic and want embeddings or audio to survive a backend swap the same way your chat already does, I'd love to hear how it goes.
