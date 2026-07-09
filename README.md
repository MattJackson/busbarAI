<p align="center">
  <img src="brand/png/busbar-primary-512.png" alt="Busbar" width="104" height="104">
</p>

<h1 align="center">Busbar</h1>

<p align="center"><strong>The reliability layer for LLM traffic.</strong> One endpoint speaks every major SDK; fault-aware circuit breaking and in-flight failover keep your app serving when your providers aren't.</p>

[![CI](https://github.com/MattJackson/busbarAI/actions/workflows/ci.yml/badge.svg)](https://github.com/MattJackson/busbarAI/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MattJackson/busbarAI?include_prereleases)](https://github.com/MattJackson/busbarAI/releases)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-1.1.0-brightgreen)

📖 **Docs:** [getbusbar.com](https://getbusbar.com)  
⚡ **Install:** `curl -fsSL https://getbusbar.com/install.sh | sh`  
🐳 **Docker:** [`getbusbar/busbar`](https://hub.docker.com/r/getbusbar/busbar) — `FROM scratch`, ~5 MB, multi-arch, cosign-signed  
🤖 **Agent-readable:** [getbusbar.com/llms.txt](https://getbusbar.com/llms.txt)

Busbar sits between your application and your LLM providers. Point any SDK: OpenAI, Anthropic, Gemini, Bedrock, Cohere, Responses, at one URL, and it routes, translates, and **keeps serving through provider failures**. It's a different class of tool than a proxy with a long model list.

> **You define a model name and its backends. Busbar accepts _any_ input protocol: OpenAI, Anthropic, Gemini, Bedrock, Cohere, Responses, and routes and translates accordingly.** One model name, reachable by every client; you choose what runs behind it.

- **Speaks every protocol losslessly, both ways**: not flattened to OpenAI shape, so Anthropic thinking blocks, structured-output schemas, and Bedrock tool use survive the hop. Use whatever SDK your code already speaks, reach every model, swap providers with a config edit.
- **Fails over inside the request**: before your client sees a byte, even mid-stream, across protocol families. Not a 500 your user feels, not a 3am page.
- **A circuit breaker on every provider connection**: classifies each error (provider outage, your bad request, context-length, hard auth/billing failure) and treats each differently instead of retrying into a wall.
- **A programmable request path**: routing is the first *hook*: your policy steers each request by cost, latency, live concurrency, budget, or rate headroom, native, or your own logic via **webhook** (any language) or a sandboxed **Rhai script**. A broken or slow hook never blocks a request, and the same fail-safe machinery is built to carry PII-steering, audit, and guardrails.
- **Encrypted, zero-trust transport, built in**: Busbar terminates TLS itself (cert + key in config, no reverse proxy). Turn on **mTLS** and only clients holding a certificate signed by your CA can connect *at all*, rejected at the handshake, before any HTTP or token check. Zero-trust without a service mesh.

A single static Rust binary, no Python sidecar, no interpreter, no GC in the request path. Linux and macOS (Intel and ARM), Windows (Intel). Your keys, your network, your data path.

> **Status: 1.1.0**: stable. The HTTP API, configuration schema, and the six wire-protocol contracts are frozen under Semantic Versioning. Hardened across a multi-round security and correctness audit; releases ship a CycloneDX SBOM and a verifiable build-provenance attestation. AGPL-3.0.

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

That request left as OpenAI, may have been served by Anthropic, and came back as OpenAI: translated losslessly both ways. If Anthropic returned a 429 mid-flight, Busbar rerouted to the next pool member before your client saw a single byte. **The model name is a config value, not a code dependency.**

---

## What's inside

- **Six wire protocols**, lossless both ways: any client protocol reaches any pool → [Protocols](https://getbusbar.com/protocols/)
- **Fault-attributed circuit breaking** + **streaming-safe in-flight failover** → [Reliability](https://getbusbar.com/reliability/)
- **Weighted pools**: smooth weighted round-robin, session affinity, per-lane concurrency → [Reliability](https://getbusbar.com/reliability/)
- **Hooks: a programmable request path**: routing is hook #1: `weighted` / `cheapest` / `fastest` / `least_busy` / `usage` natively, plus operator-owned **webhook** and **Rhai script** policies. A policy sees per-member cost, latency, live concurrency, budget, and rate headroom: your logic, in any language, fail-safe (a timeout or error falls back, never blocks the request) → [Routing](https://getbusbar.com/routing/)
- **Native TLS + optional mTLS**: Busbar terminates TLS itself (cert + key in config, no reverse proxy needed). Turn on mutual TLS to require a client certificate signed by your CA; clients without one are rejected at the handshake, before any HTTP or bearer-token check. TLS = encrypted and server-verified out of the box; mTLS = only your cert-holding clients can connect at all: zero-trust without a service mesh → [Security](https://getbusbar.com/security/)
- **Governance**: virtual keys, budgets, RPM/TPM limits, spend tracking → [Governance](https://getbusbar.com/guides/governance/)
- **Vetted provider catalog**: plus any provider on the six protocols in a few lines of YAML → [Providers](https://getbusbar.com/providers/)
- **Security-hardened**: SSRF guards, constant-time auth, SHA-256 key storage, secrets never logged → [SECURITY.md](SECURITY.md)
- **Observability**: Prometheus `/metrics` (per-key spend / budget / tokens, per-lane breaker state), OTLP traces, per-request audit webhook → [Configuration](https://getbusbar.com/configuration/)

Same arena as **LiteLLM** / **OpenRouter**: the difference is that Busbar is built reliability-first. → **[Why Busbar](https://getbusbar.com/why-busbar/)**

---

## Quickstart

```bash
curl -fsSL https://getbusbar.com/install.sh | sh        # busbar + providers.yaml into ./
```

A minimal `config.yaml` (keys come from env vars, named here: never written into config):

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

Full walkthrough → **[Getting Started](https://getbusbar.com/getting-started/)**

---

## Docs & license

Full documentation at **[getbusbar.com](https://getbusbar.com)** (agent-readable: [llms.txt](https://getbusbar.com/llms.txt)). Contributor docs: architecture, internals, ADRs, in [`docs/`](docs/).

Single Rust binary, MSRV 1.87. Contributions welcome ([CONTRIBUTING.md](CONTRIBUTING.md)). Licensed **AGPL-3.0-or-later** ([LICENSE](LICENSE)), because Busbar runs as a network service, the AGPL §13 network-use clause applies.
