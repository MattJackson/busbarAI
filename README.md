# Busbar

> A fast, native-protocol LLM gateway: weighted pool composition, lossless
> cross-protocol translation, and correct billing-vs-client failure handling — in
> one static Rust binary.

Busbar sits in front of your LLM providers and routes each request to a model or a
**pool** of models, tracking per-member health with a circuit breaker. Its thesis
is **protocols, not providers**: it implements a small set of *wire protocols*
losslessly and translates between any two of them through a superset intermediate
representation (IR). A provider is just a catalog entry — a name, a `base_url`, and
the name of the env var holding its key. No per-vendor integration code.

When a client speaks the same protocol as the chosen backend, the request passes
through untouched — preserving `cache_control`, thinking blocks, citations, and
native usage accounting. When they differ, busbar translates request *and*
response, streaming *and* non-streaming, in either direction (e.g. an OpenAI-format
client driving a Gemini backend, or vice versa).

The name comes from electrical distribution: a busbar takes one feed and fans it
out across many breakered circuits — one entry point, weighted distribution,
per-circuit protection.

> **Project status: 0.17.2 (pre-1.0), in active development.** APIs and config may
> change before 1.0. See [`docs/roadmap.md`](docs/roadmap.md) for the
> protocols-not-providers thesis and the auth-adapter design.

## Why Busbar

- **Protocols, not providers.** Six wire protocols implemented losslessly; 42
  vetted providers ship as catalog entries in `providers.yaml`, and you can add any
  OpenAI-compatible endpoint (including your own) with three lines of YAML.
- **Lossless cross-protocol translation.** A superset IR plus a `ProtocolReader` /
  `ProtocolWriter` seam means a client speaking one protocol can reach a backend
  speaking another — request and response, streamed or buffered, both directions.
- **Not bearer-only.** Auth is a per-protocol/provider seam, not one hard-coded
  scheme: bearer, Gemini's `x-goog-api-key`, Azure's `api-key` header, and AWS
  **SigV4** for Bedrock all ride the same signing hook.
- **Correct failure semantics.** A backend is ejected for *upstream* faults (5xx,
  overload, rate-limit, billing/quota, auth) but never for *client-supplied* 4xx (a
  malformed or oversized request). A healthy backend is never penalized because a
  caller sent garbage.
- **Resilience built in.** Weighted smooth round-robin across lanes, per-pool
  failover with deadlines and exclusions, a two-stage circuit breaker with
  exponential cooldown backoff, session affinity, context-length failover, and
  optional active health probing.
- **Optional governance.** Busbar-issued virtual keys with allowed-pools ACLs,
  token-accurate budgets, and RPM/TPM rate limits, administered over an
  admin-guarded management API and persisted in embedded SQLite.
- **Single static binary.** Deploy-and-done. No runtime, no GC pauses. Builds for
  Linux, macOS, and Windows (Intel + ARM).

## Protocol support

Busbar's scope is the **protocol count (6)**, not the provider count. Each protocol
is a first-class ingress *and* egress: it can be the format a client speaks, the
format a backend speaks, or both.

| Protocol | Wire surface (upstream) | Auth shape | Request | Response | Streaming | Tools |
|---|---|---|---|---|---|---|
| `anthropic` | `/v1/messages` | bearer + `x-api-key` | ✅ | ✅ | ✅ | ✅ |
| `openai` | `/v1/chat/completions` | bearer (or `api-key` for Azure) | ✅ | ✅ | ✅ | ✅ |
| `gemini` | `:generateContent` / `:streamGenerateContent` | `x-goog-api-key` | ✅ | ✅ | ✅ | ✅ |
| `bedrock` | Converse / ConverseStream | AWS **SigV4** | ✅ | ✅ | ✅ | ✅ |
| `responses` | `/v1/responses` | bearer | ✅ | ✅ | ✅ | ✅ |
| `cohere` | `/v2/chat` | bearer | ✅ | ✅ | ✅ | ✅ |

Streaming is first-class for every protocol: Gemini uses `:streamGenerateContent?alt=sse`,
Bedrock uses ConverseStream (busbar decodes the binary
`application/vnd.amazon.eventstream` frames and re-frames them as the caller's
protocol), and the others use SSE.

## Quick start

### 1. Build

```bash
cargo build --release
```

### 2. Configure

Busbar reads two files. `providers.yaml` is the vetted catalog (shipped — you
rarely edit it); `config.yaml` is your deployment, referencing providers by name
and naming the env vars that hold their keys. **Keys are never written into config
files** — only env-var names. `${VAR}` placeholders are expanded at load time, and
an unset referenced variable is a hard, loud startup failure.

A minimal `config.yaml`:

```yaml
listen: "0.0.0.0:8080"

auth:
  mode: token
  client_tokens:
    - "${BUSBAR_CLIENT_TOKEN}"

providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
  openai:
    api_key_env: OPENAI_KEY

models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
  gpt-4o-mini:
    provider: openai
    max_concurrent: 50

pools:
  fast:
    members:
      - target: claude-sonnet
        weight: 8
      - target: gpt-4o-mini
        weight: 2
```

The referenced providers (`anthropic`, `openai`) are already defined in the shipped
`providers.yaml`, which supplies their protocol, `base_url`, and error map.

### 3. Run

```bash
export BUSBAR_CLIENT_TOKEN=changeme
export ANTHROPIC_KEY=sk-ant-...
export OPENAI_KEY=sk-...

# BUSBAR_PROVIDERS defaults to /etc/busbar/providers.yaml, BUSBAR_CONFIG to /etc/busbar/config.yaml
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml ./target/release/busbar
```

### 4. Call it

Clients append the protocol path themselves, exactly as their SDK would. An
Anthropic-format client targeting the `claude-sonnet` model:

```bash
curl -s http://localhost:8080/claude-sonnet/v1/messages \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" \
  -H "content-type: application/json" \
  -d '{
        "model": "ignored-busbar-rewrites-this",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "Hello!"}]
      }'
```

A cross-protocol example — an **OpenAI-format** client whose body's `model`
resolves to the `fast` pool (which contains a Gemini-, Anthropic-, or
OpenAI-backed member). Busbar translates the OpenAI request to the chosen member's
protocol and translates the response back:

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" \
  -H "content-type: application/json" \
  -d '{
        "model": "fast",
        "messages": [{"role": "user", "content": "Hello!"}]
      }'
```

Busbar rewrites the request's `model` field to the selected member and injects the
provider's credential — the caller's own `model` and key fields are ignored (except
in `passthrough` auth mode, where the caller's key is forwarded upstream).

## Routing model

| Method · Route | Purpose |
|---|---|
| `POST /<name>/v1/messages` | Anthropic-format ingress; `<name>` is a model (`/claude-sonnet`) **or** a pool (`/fast`) |
| `POST /<provider>/<model>/v1/messages` | ad-hoc direct route to one provider+model (`/anthropic/claude-sonnet`) |
| `POST /v1/chat/completions` | OpenAI-format ingress; the body's `model` field selects the model or pool |
| `GET /stats` | per-lane health, counts, and pool membership (JSON) |
| `GET /healthz` | `200` if any lane is usable, else `503` |
| `GET /metrics` | Prometheus exposition (always on, no auth) |
| `POST /admin/keys`, `GET /admin/keys`, `DELETE /admin/keys/:id`, `GET /admin/keys/:id/usage` | virtual-key management API (governance only) |

Three ways to target a backend:

- **Direct** — `/<model>/v1/messages`: route to one named model.
- **Ad-hoc** — `/<provider>/<model>/v1/messages`: route to a specific provider+model
  without defining a pool (the provider must own the model).
- **Pooled** — `/<pool>/v1/messages` or the `model` field of `/v1/chat/completions`:
  weighted distribution across the pool's members with failover.

**Cross-protocol** routing works across all three: the ingress protocol is fixed by
the route (`anthropic` for `/v1/messages`, `openai` for `/v1/chat/completions`), and
if the selected lane speaks a different protocol, busbar translates losslessly
through its IR.

## Features

| Feature | Summary | Docs |
|---|---|---|
| Pools & weighting | Smooth weighted round-robin (SWRR) across lanes; concurrency caps stack into one aggregate | [configuration.md](docs/configuration.md) |
| Failover | Per-pool deadline + hop cap + member exclusions | [configuration.md](docs/configuration.md) |
| Exhaustion policy | `reject` / `status_503` / `least_bad` / `fallback_pool:<name>` | [configuration.md](docs/configuration.md) |
| Circuit breaker | Two-stage classify → disposition; `error_rate` or `consecutive` trips; exponential cooldown; Retry-After honored | [operations.md](docs/operations.md) |
| Session affinity | Sticky-by-header routing while a member stays healthy | [configuration.md](docs/configuration.md) |
| Context-length failover | Oversized request fails over to a larger-context member without penalizing the smaller lane | [architecture.md](docs/architecture.md) |
| Active health probing | `none` / `dead` / `active` background probes per provider | [operations.md](docs/operations.md) |
| Governance | Virtual keys, allowed-pools ACLs, token-accurate budgets, RPM/TPM limits | [operations.md](docs/operations.md) |
| Observability | Prometheus `/metrics`, optional OTLP traces, optional request-log webhook | [operations.md](docs/operations.md) |

## Observability

- **`GET /metrics`** — Prometheus text exposition, always on, no auth required
  (protect it at the network layer if needed). Metrics include
  `busbar_requests_total`, `busbar_upstream_attempts_total`,
  `busbar_upstream_failures_total`, `busbar_breaker_trips_total`,
  `busbar_failovers_total`, `busbar_translations_total`, and the
  `busbar_request_duration_seconds` histogram.
- **`GET /stats`** — per-lane health snapshot (inflight, ok/err counts, breaker
  state, cooldown remaining, budget) and pool membership, as JSON.
- **`GET /healthz`** — liveness: `200` when at least one lane is usable.
- **OTLP traces** (opt-in) and a **request-log webhook** (opt-in) via the
  `observability` config section.

## Governance (optional)

When the `governance` section is enabled, clients authenticate with busbar-issued
**virtual keys** instead of the static `auth` tokens. Each key carries an
allowed-pools ACL (403 on violation), a spend budget (402 when exceeded), and
RPM/TPM rate limits (429 + `Retry-After`). Budgets are token-accurate: a flat
per-request fee plus a per-1000-token charge derived from response usage.
Enforcement state is durable in embedded SQLite. Keys are minted and revoked over
the admin-token-guarded `/admin/keys` management API. See
[docs/operations.md](docs/operations.md).

## Configuration summary

Two files, both YAML with `${VAR}` interpolation:

- **`providers.yaml`** (shipped catalog): each entry maps a provider name to its
  `protocol`, `base_url`, optional `error_map`, optional `path` override (for
  version-in-base-url endpoints), optional `auth` override (e.g. `api-key` for
  Azure), and optional `health` probing config.
- **`config.yaml`** (your deployment): `listen`, `auth`, the `providers` you use
  (name + `api_key_env`), `models` (provider + `max_concurrent` + optional
  `max_requests` lifetime cap), `pools` (weighted members + failover + affinity +
  breaker + on_exhausted), and optional `observability` / `governance` sections.

The full field-by-field reference with defaults and worked examples lives in
[docs/configuration.md](docs/configuration.md).

## Build, CI, and platforms

Busbar is a single Rust binary on stable toolchain (edition 2021). CI builds and
tests on Linux, macOS, and Windows; releases ship binaries for five targets:

| Target | Platform |
|---|---|
| `x86_64-unknown-linux-gnu` | Linux (Intel/AMD) |
| `aarch64-unknown-linux-gnu` | Linux (ARM) |
| `x86_64-apple-darwin` | macOS (Intel) |
| `aarch64-apple-darwin` | macOS (Apple Silicon) |
| `x86_64-pc-windows-msvc` | Windows |

```bash
cargo build --release
cargo test
cargo clippy --all-targets -- -D warnings
```

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). To report a
security issue, see [SECURITY.md](SECURITY.md).

## License

Busbar is licensed under the **GNU Affero General Public License v3.0 or later**
([AGPL-3.0-or-later](LICENSE)). Because Busbar is typically run as a network
service, the AGPL's §13 network-use clause applies: if you run a modified Busbar
and let others interact with it over a network, you must offer them the
corresponding modified source.
