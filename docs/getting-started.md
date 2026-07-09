# Getting Started with Busbar

Busbar is a self-hosted LLM gateway: a single static Rust binary that sits between your application and your LLM providers. Point any SDK at it, OpenAI, Anthropic, Gemini, Cohere, Bedrock, or the OpenAI Responses API, and Busbar routes each request to the provider (or pool of providers) you configured, translating between wire protocols when the ingress and egress differ.

It does the same job as LiteLLM or OpenRouter, one API in front of every model and provider, and goes further: it speaks six provider protocols natively (so any vendor's SDK can point at it, not just OpenAI-shaped ones), ships as one binary with no Python runtime and no third party in your data path, and gives you per-(pool, lane) circuit breaking with in-flight failover. You run it in your own infra and it holds your keys.

This guide takes you from zero to a working request in about five minutes.

<svg viewBox="0 0 800 130" role="img" aria-label="Four steps to a working request: install the binary, write a minimal config, run Busbar, then send a request." style="width:100%;height:auto;max-width:800px;font-family:ui-sans-serif,system-ui,sans-serif;">
  <defs>
    <marker id="gs-arw" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M0,0 L10,5 L0,10 z" fill="#94a3b8"/>
    </marker>
  </defs>
  <rect x="0" y="0" width="800" height="130" fill="#ffffff"/>
  <g stroke="#94a3b8" stroke-width="2" marker-end="url(#gs-arw)">
    <line x1="185" y1="68" x2="203" y2="68"/>
    <line x1="375" y1="68" x2="393" y2="68"/>
    <line x1="565" y1="68" x2="583" y2="68"/>
  </g>
  <g>
    <rect x="15"  y="30" width="170" height="76" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="43"  cy="60" r="14" fill="#a3e635"/><text x="43"  y="65" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">1</text>
    <text x="66"  y="57" fill="#0f172a" font-size="14" font-weight="700">Install</text>
    <text x="66"  y="77" fill="#64748b" font-size="10.5">one-line script</text>
    <rect x="205" y="30" width="170" height="76" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="233" cy="60" r="14" fill="#a3e635"/><text x="233" y="65" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">2</text>
    <text x="256" y="57" fill="#0f172a" font-size="14" font-weight="700">Configure</text>
    <text x="256" y="77" fill="#64748b" font-size="10.5">one provider + model</text>
    <rect x="395" y="30" width="170" height="76" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="423" cy="60" r="14" fill="#a3e635"/><text x="423" y="65" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">3</text>
    <text x="446" y="57" fill="#0f172a" font-size="14" font-weight="700">Run</text>
    <text x="446" y="77" fill="#64748b" font-size="10.5">serves on :8080</text>
    <rect x="585" y="30" width="170" height="76" rx="12" fill="#f8fafc" stroke="#e2e8f0"/>
    <circle cx="613" cy="60" r="14" fill="#a3e635"/><text x="613" y="65" text-anchor="middle" fill="#1a2e05" font-size="13" font-weight="700">4</text>
    <text x="636" y="57" fill="#0f172a" font-size="14" font-weight="700">Request</text>
    <text x="636" y="77" fill="#64748b" font-size="10.5">point any SDK at it</text>
  </g>
</svg>

---

## What you need

- An API key for at least one supported provider (Anthropic, OpenAI, Gemini, Cohere, or AWS Bedrock credentials)
- The Busbar binary (see below)
- `curl` or any LLM SDK

---

## Step 1: Get the binary

**One-line install** (macOS / Linux), detects your platform, downloads the latest release binary *and* the provider catalog into the current directory, and prints the next steps:

```bash
curl -fsSL https://getbusbar.com/install.sh | sh
```

Drops `busbar` and `providers.yaml` where you run it (no sudo). To install onto your PATH instead: `BUSBAR_INSTALL_DIR=/usr/local/bin curl -fsSL https://getbusbar.com/install.sh | sh`.

**Or download manually**: grab the archive for your platform from the [latest release](https://github.com/MattJackson/busbarAI/releases/latest) (Linux `x86_64`/`aarch64`, macOS Intel/Apple Silicon, Windows `x86_64`), plus the provider catalog from [getbusbar.com/providers.yaml](https://getbusbar.com/providers.yaml). The binary is self-contained, no runtime, no virtualenv, no dependencies:

```bash
tar -xzf busbar-*.tar.gz   # extracts the `busbar` binary
chmod +x busbar
./busbar --version
```

**Or use Docker** — a `FROM scratch` image (the static binary plus the provider catalog, ~5 MB compressed, amd64 + arm64), cosign-signed with build provenance:

```bash
docker run -d -p 8080:8080 \
  -e ANTHROPIC_KEY \
  -v "$PWD/config.yaml:/etc/busbar/config.yaml:ro" \
  getbusbar/busbar
```

The provider catalog ships inside the image at `/etc/busbar/providers.yaml`, so you only mount `config.yaml` (written in [Step 2](#step-2-write-a-minimal-config)). Pin an exact version (`getbusbar/busbar:1.1.0`) or ride `latest`. If you enable governance, give it a writable volume (e.g. `-v busbar-data:/var/lib/busbar` with `db_path: /var/lib/busbar/governance.db`).

**Or build from source** (requires Rust 1.87+):

```bash
cargo build --release      # binary at target/release/busbar
```

---

## Step 2: Write a minimal config

Busbar reads two YAML files:

- `providers.yaml`: the shipped provider catalog (protocol, `base_url`, error maps). You almost never edit this. The one-line installer fetches it for you, or grab it from [getbusbar.com/providers.yaml](https://getbusbar.com/providers.yaml).
- `config.yaml`, your deployment: which providers to activate, their key env-var names, your models, and optionally pools.

**Important, keys are never written into config.** `api_key_env` names the *environment variable* that holds a provider's key; Busbar reads the key from there at startup. (Separately, `${VAR}` tokens elsewhere in `config.yaml` are also expanded from the environment at load time.) An unset referenced variable is a loud startup failure, not a silent skip.

### Minimal `config.yaml` (one provider, one model, no auth)

This is the smallest config that boots and serves requests. Use it on a local machine to try Busbar quickly.

```yaml
# config.yaml (dev/minimal, no client auth gate)
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY   # the NAME of the env var to read the key from, NOT the key itself

models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 10
```

The key itself is never in this file. `api_key_env: ANTHROPIC_KEY` tells Busbar "read this provider's key from the `$ANTHROPIC_KEY` environment variable at startup", so you set the real secret in your environment ([Step 3](#step-3-set-environment-variables-and-run)), and `config.yaml` stays safe to commit and share.

Save this as `config.yaml` in your working directory.

`providers.yaml` must also be present. The one-line installer fetches it for you. If you built from source it lives in the repo root; otherwise grab it from [getbusbar.com/providers.yaml](https://getbusbar.com/providers.yaml).

### What the fields mean

| Field | What it does |
|---|---|
| `providers.<name>.api_key_env` | Name of the environment variable holding this provider's API key |
| `models.<name>.provider` | Which provider entry in the `providers` block this model calls |
| `models.<name>.max_concurrent` | Max simultaneous in-flight requests to this model (the concurrency semaphore); must be ≥ 1 |

`providers` and `models` are the only required sections. `listen` defaults to `0.0.0.0:8080`. `auth` defaults to `none` (open relay) when omitted, fine for local dev, not for production.

---

## Step 3: Set environment variables and run

```bash
# the actual secret, this is what `api_key_env: ANTHROPIC_KEY` in config.yaml points at
export ANTHROPIC_KEY=sk-ant-...

BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml ./busbar
```

Busbar logs a startup event indicating the listen address (`busbar listening`, with the bound address as a field). It accepts requests immediately: Prometheus/TSC calibration is deferred to a background thread, so it never blocks the hot path at boot.

**Check liveness:**

```bash
curl -s http://localhost:8080/healthz
# → ok
```

`/healthz` is always unauthenticated and returns `200 ok` when at least one lane is ready, `503 no usable lanes` when every lane's circuit breaker is open. It is side-effect-free and never steals a recovery probe.

---

## Step 4: Send a request

### Via curl: Anthropic-format ingress

The model name goes in the URL path: `POST /<model-name>/v1/messages`. Busbar resolves `<model-name>` against your configured pools first, then your models, and routes the request to the matching lane.

```bash
curl -s http://localhost:8080/claude-sonnet/v1/messages \
  -H "Content-Type: application/json" \
  -d '{
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "What is a busbar?"}]
  }' | jq .
```

You get back a standard Anthropic Messages response. Because both ingress and egress are Anthropic here, Busbar relays it as a native same-protocol passthrough. Routing keys off the name in the URL, not the `model` field in the body.

### Via curl, OpenAI-format ingress

The model name goes in the request body: `POST /v1/chat/completions`. This works with any OpenAI SDK or tool that targets `http://localhost:8080` as the base URL.

```bash
curl -s http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "claude-sonnet",
    "messages": [{"role": "user", "content": "What is a busbar?"}]
  }' | jq .
```

Busbar translates the request from OpenAI format to Anthropic format on the way out, and the response from Anthropic format back to OpenAI format on the way in, through its intermediate representation, transparently. Your client receives a standard `chat.completion` object, with the answer in `choices[0].message.content`.

### Via the OpenAI Python SDK

```python
from openai import OpenAI

client = OpenAI(
    api_key="unused",          # no client auth gate in the minimal config
    base_url="http://localhost:8080",
)

response = client.chat.completions.create(
    model="claude-sonnet",     # busbar model name, not OpenAI's
    messages=[{"role": "user", "content": "What is a busbar?"}],
)
print(response.choices[0].message.content)
```

The OpenAI SDK has no idea it's talking to an Anthropic backend. Swap `model="claude-sonnet"` to any model or pool name you configured; no other change required.

### Via the Anthropic Python SDK

```python
import anthropic

client = anthropic.Anthropic(
    api_key="unused",
    base_url="http://localhost:8080",
)

message = client.messages.create(
    model="claude-sonnet",     # the model name from your config
    max_tokens=256,
    messages=[{"role": "user", "content": "What is a busbar?"}],
)
print(message.content[0].text)
```

The Anthropic SDK sends `x-api-key`; Busbar accepts it on the `/v1/messages` routes.

---

## Step 5: Add a second provider and a pool

Once the single-provider setup is working, extend the config to introduce a pool. A pool is a named group of models with weighted load balancing, per-member circuit breaking, and automatic failover.

```yaml
# config.yaml, two providers, two models, one pool, with client auth
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
  gpt-4o:
    provider: openai
    max_concurrent: 20

pools:
  smart:
    members:
      - target: claude-sonnet
        weight: 2
      - target: gpt-4o
        weight: 1
```

Set the additional environment variables and restart busbar:

```bash
export ANTHROPIC_KEY=sk-ant-...
export OPENAI_KEY=sk-...
export BUSBAR_CLIENT_TOKEN=your-token-here

BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml ./busbar
```

Now call the pool by name. Both ingress styles work against a pool:

```bash
# OpenAI ingress, model field selects the pool
curl -s http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model": "smart", "messages": [{"role": "user", "content": "Hello!"}]}'

# Anthropic ingress, pool name in the URL path
curl -s http://localhost:8080/smart/v1/messages \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"max_tokens": 256, "messages": [{"role": "user", "content": "Hello!"}]}'
```

With `weight: 2` on `claude-sonnet` and `weight: 1` on `gpt-4o`, Busbar distributes via smooth weighted round-robin, roughly two of every three requests go to Claude and one to GPT-4o. If `claude-sonnet`'s breaker trips (on upstream 5xx, 429, timeout, or network errors), Busbar fails the request over to `gpt-4o`, provided the failure happens before the first byte of the response reaches your client. After the first byte, in-flight failover is no longer possible.

### What "cross-protocol" means here

`claude-sonnet` speaks Anthropic; `gpt-4o` speaks OpenAI. A client using OpenAI-format ingress (`/v1/chat/completions`) is making an OpenAI request. When Busbar routes that request to `claude-sonnet`, it translates the request from OpenAI to Anthropic format, and the response back, losslessly, through its intermediate representation. When it routes to `gpt-4o`, it passes through natively. Your client never needs to know.

---

## Checking health and stats

**Liveness** (always unauthenticated):

```bash
curl -s http://localhost:8080/healthz
```

Returns `200 ok` if any lane is ready, `503 no usable lanes` otherwise.

**Per-lane topology** (`/stats`):

```bash
curl -s http://localhost:8080/stats \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" | jq .
```

`/stats` goes through the auth middleware, so under `auth.mode: token` (or governance) it requires a valid token; under `mode: none` it is open. It returns a per-lane snapshot: `model`, `provider`, `max_concurrent`, `inflight`, `free_slots`, `ok`/`err`/`client_fault` counts, `usable`, `dead`, `dead_reason`, `cooldown_remaining_s`, `streak`, and `budget`. A governance key restricted to specific `allowed_pools` only sees the pools and lanes it can reach.

**Prometheus metrics** (`/metrics`):

```bash
curl -s http://localhost:8080/metrics \
  -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN"
```

Prometheus scrape exposition. Like `/stats`, `/metrics` is subject to the auth middleware (it is *not* auth-exempt, telemetry is a fingerprinting surface), so it requires a token under `token`/governance mode and is open under `none`/`passthrough`. Key metrics: `busbar_requests_total`, `busbar_upstream_failures_total`, `busbar_breaker_trips_total`, `busbar_request_duration_seconds`, `busbar_translations_total`.

---

## Common setup variations

### auth: none (local dev, open relay)

Omit the `auth` block entirely, or set `mode: none`. No `Authorization` header required. Do not use in production.

### auth: passthrough (forward your own key)

```yaml
auth:
  mode: passthrough
```

The caller's own token (`Authorization: Bearer`, `x-api-key`, or `x-goog-api-key`) is forwarded directly to the upstream provider. Use this when each caller has their own provider key and you want Busbar purely for routing and protocol translation, not credential management.

Note: `passthrough` is incompatible with `governance.enabled: true` (validation rejects the combination).

### Bedrock egress (Busbar signs requests with SigV4)

Add a Bedrock provider. The key env var holds `ACCESS_KEY_ID:SECRET_ACCESS_KEY` (or with an optional third segment `:SESSION_TOKEN`):

```yaml
providers:
  bedrock:
    api_key_env: AWS_BEDROCK_CREDS

models:
  claude-bedrock:
    provider: bedrock
    max_concurrent: 10
```

```bash
export AWS_BEDROCK_CREDS="AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

Busbar signs each outbound request with SigV4 (region parsed from the host); your clients call Busbar normally with a Busbar token. OpenAI-format clients can reach Bedrock backends this way with no SDK changes.

**Bedrock ingress** (acting as a Bedrock endpoint for native AWS SDK clients) has two tracks:

- **Without governance** (`auth.mode: passthrough` or `none`): Busbar does not verify the inbound SigV4 signature. The credential is forwarded upstream (passthrough) or ignored (none).
- **With governance** (`auth.mode: token` + `governance.enabled: true`): Busbar verifies the inbound SigV4 signature natively (`src/auth.rs` `verify_bedrock_sigv4`). Mint a virtual key with `"issue_aws_credential": true` via `POST /admin/keys`; the response includes `aws_access_key_id` + `aws_secret_access_key` (shown once). Configure your Bedrock SDK with those credentials: Busbar verifies the signature, then enforces the key's budget / RPM / TPM / allowed-pools. No `passthrough` required.

### Injecting `max_tokens` for cross-protocol calls

If you route OpenAI-format requests to an Anthropic backend, Anthropic's API requires a `max_tokens` field that OpenAI clients often omit. Busbar injects a default only on cross-protocol translation to a backend that requires `max_tokens` (Anthropic Messages) when the source omitted it. The default is 4096 unless you override it per model:

```yaml
models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    default_max_tokens: 8192
```

A caller-supplied `max_tokens` is always preserved; this only applies when the field is absent and the egress requires it. It has no effect on same-protocol passthrough.

---

## Production checklist

Before taking Busbar out of dev mode:

- [ ] Set `auth.mode: token` with at least one `client_tokens` entry (or enable governance for per-key virtual tokens)
- [ ] Enable inbound TLS: add a `tls` block (`cert_file` + `key_file`) so the client↔Busbar hop is encrypted, and, for zero-trust deployments, set `client_ca_file` to require client certs (mTLS). See [`docs/operations.md#inbound-tls--mutual-tls-mtls`](operations.md#inbound-tls--mutual-tls-mtls)
- [ ] Set `max_concurrent` on every model to a value your provider tier actually supports
- [ ] Set `max_requests` to `-1` (unlimited lifetime budget) or a finite positive budget per model
- [ ] Verify `/healthz` returns `200` and `/stats` shows all lanes `usable: true` before routing production traffic
- [ ] Consider `health.mode: dead` on providers you care about (re-probes tripped lanes so they recover faster after an outage clears)
- [ ] Set `RUST_LOG=info` (the default); increase to `debug` only temporarily for diagnostics

---

## What's next

- **Full config reference**: every field, default, and validation rule: [`docs/configuration.md`](configuration.md)
- **Pools, breakers, and failover**: pool member weighting, breaker tuning, session affinity, context-length failover, exhaustion policies: [`docs/configuration.md#pools`](configuration.md#pools)
- **Running in production**: TLS termination, systemd unit, Docker, `/stats` monitoring, breaker diagnosis: [`docs/operations.md`](operations.md)
- **Governance**: virtual keys, per-key budgets and rate limits, the `/admin` API: [`docs/operations.md`](operations.md)
- **Architecture**: how the IR works, the six-protocol model, why `f64` and not `f32`: [`docs/architecture.md`](architecture.md)