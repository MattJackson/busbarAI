# Busbar

**Point your existing SDK at one URL and reach every LLM vendor — with real failover, not a `try/except`.**

[![CI](https://github.com/MattJackson/busbarAI/actions/workflows/ci.yml/badge.svg)](https://github.com/MattJackson/busbarAI/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MattJackson/busbarAI?include_prereleases)](https://github.com/MattJackson/busbarAI/releases)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
![Binary](https://img.shields.io/badge/binary-7.4MB%20static-success)
![Cold start](https://img.shields.io/badge/cold%20start-%3C15ms-success)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange)

Your code already speaks OpenAI (or Anthropic, or Gemini). Change the base URL to Busbar, and `model: "fast"` becomes a *pool* — Claude, GPT, and Gemini behind one name, load-balanced by weight, with mid-request failover when a vendor degrades. Your application code never learns that any of it happened.

```diff
- client = OpenAI(api_key=OPENAI_KEY)
+ client = OpenAI(api_key=BUSBAR_TOKEN, base_url="http://busbar:8080")

  client.chat.completions.create(
-     model="gpt-4o-mini",
+     model="fast",          # a pool: 80% Claude, 20% GPT-4o-mini, Gemini on failover
      messages=[{"role": "user", "content": "Hello!"}],
  )
```

That request left as OpenAI, may have been *served* by Anthropic, and came back as OpenAI — translated losslessly both ways. If Anthropic had returned a 429 mid-flight, Busbar would have rerouted to another pool member before your client saw a byte. One vendor's bad day stops being your outage.

It's **one static 7.4 MB binary** — no Python sidecar, no runtime, no interpreter, no dependency tree, no GC pauses in your request path. It binds and starts serving in **under 15 ms**. Download it, point two YAML files at it, run it.

> The name is from electrical distribution: a busbar takes one feed and fans it out across many breakered circuits — one entry point, weighted distribution, per-circuit protection. That's exactly the shape of this thing.

---

## Why you'll want it

**The model becomes a config value, not a dependency.** Switching from GPT to Claude — or splitting traffic 80/20 between them — is an edit to `config.yaml`, not a code change and a deploy. No per-vendor SDKs in your app.

**Failover is a real subsystem, not an `except` block.** Weighted smooth round-robin across a pool, a per-(pool, lane) circuit breaker with exponential cooldown and single-flight half-open recovery, deadline- and hop-capped failover, session affinity, and oversized-request failover to a larger-context member. It honors upstream `Retry-After`. It reroutes a streaming response right up until the first byte reaches your client.

**Translation is lossless, and the hard parts are handled.** Same-protocol calls pass through untouched — `cache_control`, thinking blocks, citations, and native usage accounting all survive. Cross-protocol calls go through a superset IR that also reconciles dialect asymmetries: an OpenAI request with no `max_tokens` routed to Anthropic (which requires one) gets a configured default instead of a rejection, and a caller-supplied value is always preserved. Even `temperature` is carried as `f64`, because an `f32` round-trip would quietly turn `0.7` into `0.699999988`.

**It penalizes the right failures.** A backend is ejected for *upstream* faults — 5xx, overload, rate-limit, billing/quota, auth — but **never** for a client `4xx`. A healthy lane is never marked dead because a caller sent a malformed or oversized request. Most gateways get this wrong.

**It's boring in your request path, on purpose.** SSRF-safe (destinations come only from your vetted catalog, never from request data), constant-time token comparison, SHA-256-hashed virtual keys, bounded request bodies, fully parameterized SQL, and secrets that never touch the logs.

## How it's different

If you're already weighing the options:

- **vs. a hand-rolled `try/except` over two SDK clients** — that gives you fallback, not failover: no health tracking, no weighting, no breaker, no streaming boundary, and a new branch every time you add a vendor. Busbar makes adding a vendor three lines of YAML.
- **vs. Python-based gateways (e.g. LiteLLM)** — Busbar is a single native binary with no interpreter, no virtualenv, and no GC in the hot path. The reliability primitives (SWRR, the two-stage breaker, context-length failover) are first-class, not add-ons.
- **vs. hosted routers (e.g. OpenRouter)** — Busbar runs in *your* infrastructure with *your* vendor keys. Nothing about your traffic or prompts leaves your network, and you pay your providers directly.

**Thesis: protocols, not providers.** Implement a handful of wire protocols losslessly, and every vendor that speaks one is just a catalog entry — a name, a `base_url`, and the env var holding its key. Six protocols are implemented; 42 vetted providers ship as catalog entries, and any OpenAI-compatible endpoint (including your own) is three lines of YAML.

> **Status: 1.0.0-rc.2 — feature-complete and API-stable. Release-candidate validation underway ahead of 1.0.0.** AGPL-3.0.

## Quick start

### 1. Get the binary

Grab a release for your platform (Linux, macOS, Windows — Intel and ARM) from the [releases page](https://github.com/MattJackson/busbarAI/releases), or build from source:

```bash
cargo build --release   # → target/release/busbar
```

### 2. Configure

Busbar reads two YAML files. `providers.yaml` is the shipped catalog (protocol, `base_url`, error map per provider — you rarely touch it). `config.yaml` is your deployment. **Keys are never written into config** — only the *names* of the env vars that hold them; `${VAR}` is expanded at load time, and an unset referenced variable is a loud startup failure.

```yaml
listen: "0.0.0.0:8080"

auth:
  mode: token
  client_tokens: ["${BUSBAR_CLIENT_TOKEN}"]

providers:
  anthropic: { api_key_env: ANTHROPIC_KEY }
  openai:    { api_key_env: OPENAI_KEY }

models:
  claude-sonnet: { provider: anthropic, max_concurrent: 20 }
  gpt-4o-mini:   { provider: openai,    max_concurrent: 50 }

pools:
  fast:
    members:
      - { target: claude-sonnet, weight: 8 }
      - { target: gpt-4o-mini,   weight: 2 }
```

### 3. Run

```bash
export BUSBAR_CLIENT_TOKEN=changeme ANTHROPIC_KEY=sk-ant-... OPENAI_KEY=sk-...
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml ./target/release/busbar
```

### 4. Call it

Clients append the protocol path themselves, exactly as their SDK would. Anthropic-format client hitting one model:

```bash
curl -s http://localhost:8080/claude-sonnet/v1/messages \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" -H "content-type: application/json" \
  -d '{"model":"ignored","max_tokens":256,"messages":[{"role":"user","content":"Hello!"}]}'
```

OpenAI-format client whose `model` selects the cross-protocol `fast` pool:

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" -H "content-type: application/json" \
  -d '{"model":"fast","messages":[{"role":"user","content":"Hello!"}]}'
```

Busbar rewrites the request's `model` to the selected member and injects the provider credential; the caller's own `model` and key fields are ignored (except in `passthrough` auth mode, where the caller's key is forwarded upstream).

## Protocol support

Busbar's scope is the **protocol count (6)**, not the provider count. Each protocol is a first-class *ingress* and *egress* — the format a client speaks, the format a backend speaks, or both.

| Protocol | Upstream wire surface | Auth | Req | Resp | Stream | Tools |
|---|---|---|:-:|:-:|:-:|:-:|
| `anthropic` | `/v1/messages` | bearer + `x-api-key` | ✅ | ✅ | ✅ | ✅ |
| `openai` | `/v1/chat/completions` | bearer (or `api-key` for Azure) | ✅ | ✅ | ✅ | ✅ |
| `gemini` | `:generateContent` / `:streamGenerateContent` | `x-goog-api-key` | ✅ | ✅ | ✅ | ✅ |
| `bedrock` | Converse / ConverseStream | AWS **SigV4** | ✅ | ✅ | ✅ | ✅ |
| `responses` | `/v1/responses` | bearer | ✅ | ✅ | ✅ | ✅ |
| `cohere` | `/v2/chat` | bearer | ✅ | ✅ | ✅ | ✅ |

Streaming is first-class for all six: Gemini via `:streamGenerateContent?alt=sse`, Bedrock by decoding the binary `application/vnd.amazon.eventstream` frames and re-framing them as the caller's protocol, the rest via SSE.

## Routing

| Route | Targets |
|---|---|
| `POST /<name>/v1/messages` | Anthropic ingress; `<name>` is a model (`/claude-sonnet`) **or** a pool (`/fast`) |
| `POST /<provider>/<model>/v1/messages` | ad-hoc direct route to one provider+model, no pool needed |
| `POST /v1/chat/completions` | OpenAI ingress; the body's `model` selects the model or pool |
| `GET /stats` · `GET /healthz` · `GET /metrics` | per-lane health (JSON) · liveness · Prometheus |
| `/admin/keys` (POST/GET/DELETE) | virtual-key management (governance only) |

Cross-protocol translation applies to all three targeting modes: the ingress protocol is fixed by the route, and if the chosen lane speaks something else, Busbar translates through the IR.

## Features

| Feature | What it does |
|---|---|
| Pools & weighting | Smooth weighted round-robin across lanes; concurrency caps stack into one aggregate |
| Failover | Per-pool deadline + hop cap + member exclusions, applied across direct, ad-hoc, and pooled routes |
| Exhaustion policy | `reject` / `status_503` / `least_bad` / `fallback_pool:<name>` |
| Circuit breaker | Two-stage classify → disposition; `error_rate` or `consecutive` trips; exponential cooldown; single-flight half-open recovery; honors `Retry-After` |
| Session affinity | Sticky-by-header routing while a member stays healthy |
| Context-length failover | Oversized request fails over to a larger-context member without penalizing the smaller lane |
| Health probing | `none` / `dead` / `active` background probes per provider |
| Governance | Virtual keys, allowed-pools ACLs, token-accurate budgets, RPM/TPM limits — durable in embedded SQLite, off by default |
| Observability | Prometheus `/metrics`, optional OTLP traces, optional request-log webhook |

Full field-by-field config reference, with defaults and worked examples, lives in [`docs/configuration.md`](docs/configuration.md); the architecture and the protocols-not-providers thesis are in [`docs/architecture.md`](docs/architecture.md) and [`docs/roadmap.md`](docs/roadmap.md).

## Security

Busbar sits in your request path, so it's built to be unremarkable there: no caller-controlled upstreams (destinations come from your vetted `providers.yaml`, never from request data, so it's SSRF-safe), constant-time comparison of client and admin tokens, virtual keys stored only as SHA-256 hashes, request bodies bounded at 32 MiB (even in open-relay mode), fully parameterized governance SQL, and provider keys / tokens / bodies kept out of the logs. These are exercised by the test suite (267 tests) and were the focus of a dedicated hardening pass. To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Build & platforms

Single Rust binary, stable toolchain (edition 2021). CI builds and tests on Linux, macOS, and Windows; releases ship `x86_64`/`aarch64` Linux, Intel/Apple-Silicon macOS, and `x86_64` Windows.

```bash
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

## Contributing & license

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Licensed **AGPL-3.0-or-later** ([LICENSE](LICENSE)). Because Busbar typically runs as a network service, the AGPL's §13 network-use clause applies: run a modified Busbar and let others reach it over a network, and you must offer them the corresponding modified source.
