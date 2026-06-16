# Busbar

**The reliability layer for LLM traffic.** One endpoint speaks every major SDK; fault-aware circuit breaking and in-flight failover keep your app serving when your providers aren't.

[![CI](https://github.com/MattJackson/busbarAI/actions/workflows/ci.yml/badge.svg)](https://github.com/MattJackson/busbarAI/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MattJackson/busbarAI?include_prereleases)](https://github.com/MattJackson/busbarAI/releases)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)
![Status](https://img.shields.io/badge/status-1.0.0--rc.4-blue)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange)

📖 **Docs: [ai-bus.bar](https://ai-bus.bar)** · ⚡ **Install:** `curl -fsSL https://ai-bus.bar/install.sh | sh` · 🤖 **Agent-readable:** [ai-bus.bar/llms.txt](https://ai-bus.bar/llms.txt)

Busbar is a gateway that sits between your application and your LLM providers. Point any SDK — OpenAI, Anthropic, Gemini, Bedrock, Cohere — at one URL, and it routes, translates, and **keeps serving through provider failures**.

> **You define a model name and its backends. Busbar accepts _any_ input protocol — OpenAI, Anthropic, Gemini, Bedrock, Cohere, Responses — and routes and translates accordingly.** One model name, reachable by every client; you choose what runs behind it.

Three things make it a different class of tool than a proxy with a long model list:

**1. It speaks every protocol losslessly — both ways.**
Six wire protocols, native on ingress *and* egress, translated through one internal format rich enough to hold every protocol's features — so nothing gets dropped. Busbar does **not** flatten everything to OpenAI shape the way most gateways do, so provider-native features — Anthropic thinking blocks, Gemini safety settings, Bedrock tool use — survive the hop.
→ *What that enables:* use whatever SDK your code already speaks — and reach **every** model through it; move a workload from Claude to Gemini with a config edit instead of a code migration; adopt a new model the day it ships. Provider independence becomes an operational property, not a rewrite.

**2. It fails over inside the request — before your client sees a byte, even mid-stream.**
→ *What that enables:* a provider 429 or 5xx becomes a silent reroute across your pool — including **across protocol families**, Anthropic → OpenAI → Gemini — not a 500 your user feels and not a 3am page. Reliability your app gets for free, instead of a pile of per-provider retry code. (This compounds with lossless translation: a normalize-to-OpenAI proxy can only fail over among OpenAI-shaped backends; Busbar bridges the whole field.)

**3. It knows whose fault a failure is.**
A circuit breaker on every provider connection classifies every error — provider outage, *your* bad request, context-length, hard auth/billing failure — and treats each differently instead of retrying into a wall.
→ *What that enables:* a flaky provider is pulled from rotation automatically and probed back in gently; a malformed 400 never poisons a healthy lane; an overly long prompt fails *over* to a bigger-context model instead of just failing.

Runs in your own infrastructure today — a single static binary for Linux, macOS, and Windows (Intel and ARM): your keys, your network, your data path, no third party in the middle.

> **Status: 1.0.0-rc.4 — feature-complete and API-stable, hardened across a multi-round security and correctness audit. Release-candidate validation continuing ahead of 1.0.0.** AGPL-3.0.

---

## The one-line change

Your code already speaks OpenAI (or Anthropic, or Gemini). Swap the base URL:

```diff
- client = OpenAI(api_key=OPENAI_KEY)
+ client = OpenAI(api_key=BUSBAR_TOKEN, base_url="http://busbar:8080")

  # the rest of your code is untouched — `model` now names a single model
  # OR a pool you define in config (e.g. "fast" = 80% Claude / 20% GPT-4o, Gemini on failover)
  client.chat.completions.create(
      model="fast",
      messages=[{"role": "user", "content": "Hello!"}],
  )
```

That request left as OpenAI, may have been served by Anthropic, and came back as OpenAI — translated losslessly both ways. If Anthropic returned a 429 mid-flight, Busbar rerouted to the next pool member before your client saw a single byte. The model name is a config value, not a code dependency.

---

## A different class of product

Most LLM gateways are a proxy with a model list: normalize every request to one shape, forward it, list a lot of providers. Busbar is built as **reliability infrastructure** first — the breaker, the in-flight failover, and the lossless translation are the core, not add-ons.

| | Busbar | Self-hosted proxy | Hosted router |
|---|---|---|---|
| **Cross-protocol translation** | Native, lossless both ways — keeps provider-native features | Normalized to OpenAI shape (lossy) | OpenAI shape only |
| **Circuit breaking** | Per-(pool, lane), fault-attributed | Basic retry / cooldown | Not exposed |
| **Failover** | Mid-request, before first byte — streaming-safe, across protocols | Exception-level retry | None |
| **Weighted pools** | Smooth weighted round-robin + session affinity | Limited | Limited |
| **Governance** | Built-in virtual keys, budgets, ACLs | Add-on | Dashboard |
| **Keys & prompts** | Stay in your network | Stay in your network | Transit a third party |
| **Runtime** | Single static binary | Python + dependencies | n/a (hosted) |

If you've used **LiteLLM** or **OpenRouter**: same arena. The difference is depth — fault-attributed circuit breaking, true in-flight (streaming-safe) failover, and *lossless* cross-protocol translation that doesn't make you trade away each provider's native features. Self-hosted is how it ships today, not what it is.

---

## 60-second quickstart

### 1. Get the binary

Download a release for your platform (Linux, macOS, Windows — Intel and ARM) from the [releases page](https://github.com/MattJackson/busbarAI/releases), or build from source:

```bash
cargo build --release   # → target/release/busbar
```

### 2. Write a minimal config

Busbar reads two YAML files. `providers.yaml` is the shipped catalog — protocol, `base_url`, and error mappings for a curated set of vetted providers. You rarely touch it. `config.yaml` is your deployment. Keys are never written into config; only the names of the env vars that hold them. `${VAR}` is expanded at load time, and an unset referenced variable is a loud startup failure.

```yaml
# config.yaml — minimal working example
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
    on_exhausted:
      action: least_bad
```

### 3. Run

```bash
export BUSBAR_CLIENT_TOKEN=changeme ANTHROPIC_KEY=sk-ant-... OPENAI_KEY=sk-...
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml ./busbar
```

### 4. Send a request

OpenAI SDK or raw curl against the `fast` pool — Busbar selects the lane, translates if needed, and returns a native OpenAI response:

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" \
  -H "content-type: application/json" \
  -d '{"model":"fast","messages":[{"role":"user","content":"Hello!"}]}'
```

Or target a single model directly via the Anthropic ingress route:

```bash
curl -s http://localhost:8080/claude-sonnet/v1/messages \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" \
  -H "content-type: application/json" \
  -d '{"model":"ignored","max_tokens":256,"messages":[{"role":"user","content":"Hello!"}]}'
```

Check that any lane is serving: `curl http://localhost:8080/healthz`

---

## Protocol support

Busbar's scope is the protocol count, not the provider count. Each protocol is a first-class ingress and egress — any combination translates through a superset intermediate representation (IR) with no information loss.

| Protocol | Upstream path | Auth | Req | Resp | Stream | Tools |
|---|---|---|:-:|:-:|:-:|:-:|
| `anthropic` | `/v1/messages` | bearer / `x-api-key` | ✅ | ✅ | ✅ | ✅ |
| `openai` | `/v1/chat/completions` | bearer | ✅ | ✅ | ✅ | ✅ |
| `gemini` | `:generateContent` / `:streamGenerateContent` | `x-goog-api-key` | ✅ | ✅ | ✅ | ✅ |
| `bedrock` | Converse / ConverseStream | AWS SigV4 | ✅¹ | ✅ | ✅ | ✅ |
| `responses` | `/v1/responses` | bearer | ✅ | ✅ | ✅ | ✅ |
| `cohere` | `/v2/chat` | bearer | ✅ | ✅ | ✅ | ✅ |

¹ Bedrock **ingress** requires `auth.mode: passthrough` or `none`. Busbar does not verify inbound SigV4 (`sigv4.rs` is sign-only), so a SigV4-signed request under `token` or governance mode carries no bearer token Busbar can match and is rejected with 403 AccessDenied. Egress to a Bedrock backend — where Busbar signs the request — is unconditional.

Streaming is first-class for all six. Gemini supports both `?alt=sse` and native JSON-array framing (what the google-generativeai SDK uses by default). Bedrock streaming is decoded from binary `application/vnd.amazon.eventstream` frames on egress and re-encoded into CRC32-valid binary frames on ingress, so a native AWS SDK client receives exactly the ConverseStream response it expects.

**A curated catalog of vetted providers** ships in `providers.yaml` — Anthropic, OpenAI, Gemini, Groq, Together, Fireworks, Mistral, xAI, DeepSeek, Cohere, Cerebras, AWS Bedrock, and more. We vet rather than scrape: each entry's error-code mappings are hand-verified because they drive the breaker's fault attribution — a wrong mapping is a reliability bug, not a bigger number. And you're never limited to the list — any provider that speaks one of the six protocols (including your own deployment) is a few lines of YAML *you* add, no code and no waiting on us. See [Adding a provider](docs/providers.md).

---

## Ingress routes

| Route | Protocol | Model/pool selection |
|---|---|---|
| `POST /<name>/v1/messages` | Anthropic | `<name>` is a model name or pool name |
| `POST /<provider>/<model>/v1/messages` | Anthropic | Ad-hoc direct route; no pool needed |
| `POST /v1/chat/completions` | OpenAI | Body's `model` field |
| `POST /v1/responses` | Responses | Body's `model` field |
| `POST /v2/chat` | Cohere | Body's `model` field |
| `POST /v1beta/models/{model}:generateContent` | Gemini | URL path segment (`/v1/models/...` also accepted) |
| `POST /v1beta/models/{model}:streamGenerateContent` | Gemini | URL path segment |
| `POST /model/{modelId}/converse` | Bedrock | URL path segment |
| `POST /model/{modelId}/converse-stream` | Bedrock | URL path segment |
| `GET /healthz` | — | Liveness; 200 if any lane is ready, 503 otherwise |
| `GET /stats` | — | Per-lane health snapshot (auth required) |
| `GET /metrics` | — | Prometheus exposition |
| `POST /admin/keys` · `GET /admin/keys` | — | Mint / list virtual keys (governance) |
| `DELETE /admin/keys/{id}` · `GET /admin/keys/{id}/usage` | — | Revoke / usage (governance) |

Cross-protocol translation is automatic: the ingress protocol is fixed by the route; if the chosen lane speaks a different protocol, Busbar translates through the IR. The client sees its own protocol's native response in every case.

---

## Reliability features

### Pools and weighted routing

A pool is a named set of models with weights. Traffic is distributed via smooth weighted round-robin. Add or reweight members in `config.yaml` without touching application code.

```yaml
pools:
  smart:
    members:
      - { target: claude-sonnet, weight: 2 }
      - { target: gpt-4o,        weight: 2 }
      - { target: gemini-1.5-pro, weight: 1 }
```

Each lane has an independent concurrency semaphore (`max_concurrent`). Session affinity pins a session to a lane by request header while that lane stays healthy.

### Circuit breaking

Every (pool, lane) pair has its own breaker — a tripped lane in one pool does not affect its state in another. The breaker runs a two-stage pipeline: normalize the raw upstream signal to a canonical class, then map the class to a disposition.

| Upstream signal | Disposition |
|---|---|
| 5xx, 429, 529, 408, network error | Transient — exponential cooldown, then probe |
| 401/403, billing quota | Hard down — 30-minute sticky cooldown |
| 4xx from a client-side bad request | Client fault — lane is never penalized |
| Context-length exceeded (400/413) | Context-length failover — no penalty |

Cooldown is exponential with ±10% jitter to prevent thundering-herd reconvergence. Upstream `Retry-After` is honored as a floor. Recovery is single-flight: exactly one request probes a cooled-down lane; all others wait or fail over.

Trip modes: `error_rate` (errors/total over a sliding window, gated by a minimum request count) or `consecutive` (N consecutive failures).

### Failover

Failover is bounded by a per-pool deadline and hop cap (defaults: 120 s, 3 hops). Already-tried lanes are excluded per request. Exhaustion policies when all members are tripped: `reject` (503 with `Retry-After`), `least_bad` (send to the soonest-recovering member, logged as degraded), or `fallback_pool:<name>` (route to another pool).

**The failover boundary is the first byte.** Before any byte reaches your client, a pre-first-byte failure triggers a failover hop. After the first byte, failover is not possible; a mid-stream SSE failure is surfaced as an error event in the stream.

### Governance (optional)

Virtual keys with per-key budget caps (daily, monthly, or total), RPM/TPM limits, and pool ACLs. Backed by embedded SQLite; managed via the `/admin/keys` API. Off by default — enable with a one-line config entry.

Secrets are stored only as SHA-256 hashes and shown plaintext exactly once at mint. Spend under concurrency is best-effort (the cap is a soft guard, not a hard atomic limit); RPM is precise.

---

## Observability

- **`GET /metrics`** — Prometheus text exposition, always on. Metrics include `busbar_requests_total`, `busbar_upstream_failures_total`, `busbar_breaker_trips_total`, `busbar_failovers_total`, `busbar_request_duration_seconds`, `busbar_translations_total`.
- **OTLP traces** — optional; set `observability.otlp_endpoint` in config.
- **Request-log webhook** — optional fire-and-forget POST per request; set `observability.request_log_webhook_url`.

---

## Security posture

Busbar sits in your request path and is built to be unremarkable there:

- **No caller-controlled upstreams.** Destinations come only from your vetted `providers.yaml`, never from request data. SSRF guards run at startup on every `base_url` and on both observability sinks.
- **Constant-time token comparison** across the full allowlist, using a bitwise-OR fold — no list-position timing oracle.
- **Virtual keys stored only as SHA-256 hashes.** The plaintext secret is shown once at mint and never stored.
- **Request bodies bounded at 32 MiB** in all auth modes.
- **Fully parameterized governance SQL.** No SQL injection surface.
- **Credentials never reach the logs.** Provider keys, tokens, and virtual key hashes are redacted in all log output.
- **Auth failures return the caller's native error envelope** — same shape as a genuine provider rejection, no Busbar vocabulary, no distinction between wrong/missing/disabled.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## For managers: why Busbar

If you use more than one LLM provider — or plan to — you are building vendor lock-in into your application layer every day you don't have a gateway. When a provider has an outage, you get paged. When you want to try a new model, you write code. When you need to control spend or enforce rate limits per team or project, you have no surface to do it on.

Busbar addresses these as infrastructure, not application logic:

- **One vendor's outage stops being your outage.** The circuit breaker detects degradation before you do, and failover happens inside a single request before the client sees a byte.
- **Switching or splitting traffic between models is a config edit, not a deploy.** Your application sends `model: "fast"` and you decide what "fast" means in YAML.
- **You keep control of cost.** Virtual keys with budget and rate limits give you a governance layer without building one.
- **Nothing leaves your network.** Unlike hosted routers, Busbar runs in your infra with your keys. Your prompts do not transit a third party.
- **No runtime tax.** A single ~8 MB static binary. No Python sidecar, no interpreter, no GC in the request path. Deploy it like nginx.

---

## Documentation

**Start here**

| Document | Contents |
|---|---|
| [`docs/getting-started.md`](docs/getting-started.md) | Install, configure, and make your first request — end to end |
| [`docs/why-busbar.md`](docs/why-busbar.md) | The case for Busbar — the problems it solves and how it compares |
| [`docs/configuration.md`](docs/configuration.md) | Full config reference — every key, default, and validation rule |
| [`docs/protocols.md`](docs/protocols.md) | The six wire protocols and lossless cross-protocol translation |
| [`docs/reliability.md`](docs/reliability.md) | Pools, fault-attributed circuit breaking, in-flight failover, governance |

**Going deeper**

| Document | Contents |
|---|---|
| [`docs/operations.md`](docs/operations.md) | Running in production, health probing, governance, troubleshooting |
| [`docs/architecture.md`](docs/architecture.md) | How Busbar works — the IR, protocol translation, routing |
| [`docs/internals.md`](docs/internals.md) | Deep dive: breaker FSM, SWRR, governance store, streaming |
| [`docs/development.md`](docs/development.md) | Adding a protocol or provider, module map |
| [`docs/adr/`](docs/adr/) | Architecture decision records |

---

## Build and platforms

Single Rust binary, MSRV 1.87, edition 2021. CI builds and tests on Linux and Windows; releases cross-build macOS. Releases ship `x86_64`/`aarch64` Linux, Intel/Apple-Silicon macOS, and `x86_64` Windows.

```bash
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

---

## Contributing and license

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

Licensed **AGPL-3.0-or-later** ([LICENSE](LICENSE)). Because Busbar typically runs as a network service, the AGPL's §13 network-use clause applies: run a modified Busbar and let others reach it over a network, and you must offer them the corresponding modified source.