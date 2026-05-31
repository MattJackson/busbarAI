# Busbar

> A fast, native-protocol LLM gateway with weighted pool composition and correct
> billing-vs-client failure handling.

Busbar sits in front of multiple LLM providers and routes each request to a model
or a **pool** of models, with per-member health tracking via a circuit breaker. It
speaks each provider's **native protocol** where it can and only translates when a
request crosses protocols — so homogeneous calls pass through losslessly
(preserving `cache_control`, thinking blocks, citations, native usage accounting).

The name comes from electrical distribution: a busbar takes one feed and fans it
out across many breakered circuits — one entry point, weighted distribution,
per-circuit protection.

> **Project status: 0.14.0 (pre-1.0), in active development.** Working today:
> **six protocols** — Anthropic, OpenAI (chat completions), Google **Gemini**, AWS **Bedrock**
> (Converse), OpenAI **Responses**, and **Cohere** (v2 Chat) — each read/written natively, with **full cross-protocol
> translation** through a lossless superset IR (request *and* response, streaming *and*
> non-streaming, both directions — e.g. an OpenAI-format client driving a Gemini backend, or vice
> versa). Plus named/ad-hoc routing, **weighted** pools (smooth WRR) with failover + session
> affinity, a two-stage **circuit breaker**, **context-length failover**, and **observability**:
> a Prometheus `/metrics` endpoint (request/attempt/failure/failover/breaker-trip/translation
> counters + latency histogram), optional **OpenTelemetry** OTLP trace export, and an optional
> fire-and-forget **request-log webhook** (both opt-in via an `observability` config section).
> All protocols are first-class including streaming: Gemini uses `:streamGenerateContent`,
> Bedrock uses native AWS **SigV4** auth + ConverseStream (busbar decodes the binary
> `application/vnd.amazon.eventstream` frames and translates them to the caller's protocol),
> and Cohere uses the v2 `/v2/chat` Chat API.
> And **governance** (opt-in `governance` config section, durable in embedded SQLite per ADR-0009):
> **virtual keys** (busbar-issued, distinct from provider keys) with per-key **allowed-pools** ACLs
> (403), **budgets** (402 when exceeded), and **rate limits** (429 + Retry-After), administered via
> an admin-token-guarded **management API** (`/admin/keys` CRUD + usage); budgets are token-accurate
> (per-request fee + per-1k-token cost from response usage). A vetted catalog of **42 providers**
> ships in `providers.yaml` (per-provider `path` override for version-in-base-url endpoints). Builds
> and runs on **Linux, macOS, and Windows** (Intel + ARM binaries shipped per release).
> busbar is **not bearer-only**: auth is a per-protocol/provider seam (Gemini uses `x-goog-api-key`,
> Bedrock uses **SigV4**, and a per-provider `auth: api-key` override drives **Azure OpenAI**).
> Roadmap (1.0): a **Google Vertex AI** auth adapter (the `gemini` protocol behind GCP OAuth2) on
> the same signing seam; then 1.0 hardening (docs, soak, security review). APIs and config may
> change before 1.0. See [`docs/roadmap.md`](docs/roadmap.md) for the protocols-not-providers
> thesis and the auth-adapter design.

## Why Busbar

- **Native protocols first.** No mandatory OpenAI-shaped lingua franca; translation
  is confined to cross-protocol hops, so provider-specific features survive.
- **Correct failure semantics.** A backend is ejected for *upstream* faults (5xx,
  overload, rate-limit, billing/quota) but never for *client-supplied* 4xx (a
  malformed or oversized request). A healthy backend is never penalized because a
  caller sent garbage.
- **Single static binary.** Deploy-and-done, no runtime, no GC pauses.

## Quick start

```bash
# Build
cargo build --release

# Configure: providers.yaml (shipped defs) + config.yaml (deployment with keys)
export ANTHROPIC_KEY=sk-ant-...
export ZAI_KEY=...

# Run (BUSBAR_PROVIDERS defaults to /etc/busbar/providers.yaml, BUSBAR_CONFIG to /etc/busbar/config.yaml)
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml ./target/release/busbar
```

The two-file model separates vetted provider knowledge (`providers.yaml`) from operator deployment config (`config.yaml`). Operators reference providers by NAME in `config.yaml` and supply their keys via env vars.

## API

Clients append `/v1/messages` themselves, matching the Anthropic SDK.

| Method · Route | Purpose |
|---|---|
| `POST /<name>/v1/messages` | Anthropic-format ingress; `<name>` is a model (`/glm-4.6`) **or** a pool (`/glm`) |
| `POST /<provider>/<model>/v1/messages` | ad-hoc direct route (`/z.ai/glm-4.6`) |
| `POST /v1/chat/completions` | OpenAI-format ingress; the `model` field in the body selects the model/pool |
| `GET /stats` | per-member health, counts, and pool membership (JSON) |
| `GET /healthz` | `200` if any member is usable, else `503` |

Clients use their native SDK: the Anthropic SDK appends `/v1/messages`, the OpenAI SDK appends
`/v1/chat/completions`. When the chosen backend speaks a different protocol than the ingress,
Busbar translates the request through its lossless superset IR. The router rewrites the
request's `model` field and injects the provider's credential — the caller's own model/key
fields are ignored.

## Configuration

Busbar uses a two-file model:

- **`providers.yaml`** (shipped): contains vetted provider definitions with protocol, base_url, and error_map. Operators rarely modify this file.
- **`config.yaml`** (deployment): operator-owned config that references providers by NAME from `providers.yaml` and supplies their keys via `api_key_env`.

Providers declare a `base_url` and the **env var name** holding their key in `providers.yaml`. Models declare a `provider` and `max_concurrent`; pools are named lists of models whose concurrency caps stack into one aggregate. Keys are never stored in config files—only env var names.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a
security issue, see [SECURITY.md](SECURITY.md).

## License

Busbar is licensed under the **GNU Affero General Public License v3.0 or later**
([AGPL-3.0-or-later](LICENSE)). Because Busbar is typically run as a network
service, the AGPL's §13 network-use clause applies: if you run a modified Busbar
and let others interact with it over a network, you must offer them the
corresponding modified source.
