<p align="center">
  <img src="assets/busbar-logo.png" alt="Busbar" width="104" height="104">
</p>

<h1 align="center">Busbar</h1>

<p align="center"><strong>Your AI Control Plane.</strong> Self-hosted, in a single Rust binary: one endpoint speaks every major SDK; fault-aware circuit breaking and in-flight failover keep your app serving when your providers aren't.</p>

[![CI](https://github.com/MattJackson/busbarAI/actions/workflows/ci.yml/badge.svg)](https://github.com/MattJackson/busbarAI/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MattJackson/busbarAI?include_prereleases)](https://github.com/MattJackson/busbarAI/releases)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Docker image size](https://img.shields.io/docker/image-size/getbusbar/busbar?sort=semver&label=image)](https://hub.docker.com/r/getbusbar/busbar)

📖 **Docs:** [getbusbar.com](https://getbusbar.com)  
⚡ **Install:** `curl -fsSL https://getbusbar.com/install.sh | sh`  
🐳 **Docker:** [`getbusbar/busbar`](https://hub.docker.com/r/getbusbar/busbar) — `FROM scratch`, multi-arch, cosign-signed  
📊 **Footprint** (measured, v1.3.2): ~4.3 MB image · ~5.6 MB idle RSS · 36 / 40 / 53 µs request handling (p50 / p90 / p99, n=50k vs instant mock)  
🤖 **Agent-readable:** [getbusbar.com/llms.txt](https://getbusbar.com/llms.txt)

Busbar sits between your application and every AI provider. Point any SDK at one URL (OpenAI, Anthropic, Gemini, Bedrock, Cohere, or the Responses API) and Busbar routes each request to the backends you chose, translating losslessly between protocols where they differ: chat, embeddings, images, audio, and moderations. When a provider fails, it keeps serving.

> **Stable.** The API, config schema, and the six wire-protocol contracts are frozen under Semantic Versioning. Every release ships an SBOM and a build-provenance attestation. Apache-2.0. (Current version: the Release badge above — never hand-written, so it can't go stale.)

---

## The one-line change

Your code already speaks OpenAI (or Anthropic, or Gemini). Swap the base URL:

```diff
- client = OpenAI(api_key=OPENAI_KEY)
+ client = OpenAI(api_key=BUSBAR_TOKEN, base_url="http://busbar:8080")

  # `model` now names a single model OR a pool you define in config
  # (e.g. "fast" = 80% Claude / 20% GPT-4o, Gemini on failover)
  client.chat.completions.create(model="fast", messages=[...])
```

That request left your app as OpenAI. It may have been served by Anthropic, and it came back as OpenAI, translated in both directions. If Anthropic had returned a 429 before the first byte, Busbar would have moved on to the next pool member without your client noticing. The model name is a config value, not a code dependency.

---

## What's inside

- **Six wire protocols**, lossless in both directions; any client protocol reaches any pool → [Protocols](https://getbusbar.com/docs/protocols/)
- **Fault-attributed circuit breaking** and streaming-safe in-flight failover → [Reliability](https://getbusbar.com/docs/reliability/)
- **Weighted pools** with smooth weighted round-robin, session affinity, and per-lane concurrency caps → [Reliability](https://getbusbar.com/docs/reliability/)
- **Routing policies.** Five built-ins, or your own logic as a webhook or Rhai script. A policy sees each member's cost, latency, live concurrency, budget, and rate headroom, and a failing policy falls back instead of blocking → [Routing](https://getbusbar.com/docs/routing/)
- **Native TLS and optional mTLS**, terminated by Busbar itself, with no reverse proxy in front → [Security](https://getbusbar.com/docs/security/)
- **Governance** when you want it: virtual keys, budgets, RPM/TPM limits, spend tracking → [Governance](https://getbusbar.com/docs/guides/governance/)
- **A verified provider catalog**, plus any provider on the six protocols in a few lines of YAML → [Providers](https://getbusbar.com/docs/providers/)
- **Hardening throughout**: SSRF guards, constant-time auth, SHA-256 key storage, secrets never logged → [SECURITY.md](SECURITY.md)
- **Observability** over open standards: Prometheus `/metrics`, OTLP traces, a per-request audit webhook → [Configuration](https://getbusbar.com/docs/configuration/)

Busbar shares an arena with LiteLLM and OpenRouter, but it was built reliability-first, and the differences are bigger than a feature list. The honest comparison lives at **[Why Busbar](https://getbusbar.com/docs/why-busbar/)**.

---

## Quickstart

```bash
curl -fsSL https://getbusbar.com/install.sh | sh        # busbar + providers.yaml into ./
```

A minimal `config.yaml`. Keys come from environment variables; the config names the variable and never holds the key:

```yaml
providers:
  anthropic: { api_key_env: ANTHROPIC_KEY }          # the NAME of the env var, not the key
models:
  claude: { provider: anthropic, max_concurrent: 10 }
pools:
  fast: { members: [ { target: claude, weight: 1 } ] }
```

```bash
export ANTHROPIC_KEY=sk-ant-...
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml ./busbar
curl -s localhost:8080/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"fast","messages":[{"role":"user","content":"Hello!"}]}'
```

Full walkthrough → **[Getting Started](https://getbusbar.com/docs/getting-started/)**

---

## Docs & license

Full documentation is at **[getbusbar.com](https://getbusbar.com)** (agent-readable at [llms.txt](https://getbusbar.com/llms.txt)). Contributor docs (architecture, internals, ADRs) live in [`docs/`](docs/).

Single Rust binary, MSRV 1.87. Contributions welcome ([CONTRIBUTING.md](CONTRIBUTING.md)). Licensed **Apache-2.0** ([LICENSE](LICENSE)): permissive, commercial-friendly, with an explicit patent grant.
