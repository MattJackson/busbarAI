# Configuration reference

Busbar reads **two YAML files**:

- **`providers.yaml`** — the vetted provider catalog (shipped). Maps provider names
  to protocol, base URL, error map, and optional path/auth/health overrides.
  Operators rarely edit this.
- **`config.yaml`** — your deployment. References providers by name, supplies the
  env vars holding their keys, and declares models, pools, auth, observability, and
  governance.

Both files are loaded at startup and support `${VAR}` environment interpolation
(see [Environment interpolation](#environment-interpolation)). The file paths come
from `BUSBAR_PROVIDERS` and `BUSBAR_CONFIG` (defaults
`/etc/busbar/providers.yaml` and `/etc/busbar/config.yaml`).

> Defaults below are taken from `src/config.rs`. Where the runtime breaker default
> differs from the per-field serde default, both are noted.

---

## Table of contents

- [Environment interpolation](#environment-interpolation)
- [`providers.yaml`](#providersyaml)
- [`config.yaml`](#configyaml)
  - [`listen`](#listen)
  - [`auth`](#auth)
  - [`providers`](#providers)
  - [`models`](#models)
  - [`pools`](#pools)
    - [members & weights](#members--weights)
    - [`failover`](#failover)
    - [`on_exhausted`](#on_exhausted)
    - [`affinity`](#affinity)
    - [`breaker`](#breaker)
    - [context-length failover](#context-length-failover)
  - [`observability`](#observability)
  - [`governance`](#governance)

---

## Environment interpolation

Any `${VAR}` token in either file is replaced with the value of environment
variable `VAR` at load time. **An unset referenced variable is a fatal startup
error** (fail loud), and `${}` (empty name) is an error. Interpolation scans the
whole file, including commented-out lines, so a `${VAR}` inside a comment must
still resolve.

Secrets are never written into config. You name the env var that holds a key
(`api_key_env`), and you may reference tokens via `${...}` (e.g.
`client_tokens: ["${BUSBAR_CLIENT_TOKEN}"]`).

---

## `providers.yaml`

A map of provider name → definition. Example entries:

```yaml
anthropic:
  protocol: anthropic
  base_url: https://api.anthropic.com
  error_map: {}

zai-api:
  protocol: openai
  base_url: https://api.z.ai/api/paas/v4
  path: /chat/completions          # version lives in base_url; override the appended path
  error_map:
    "1113": billing
    "1302": rate_limit
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `protocol` | string | no | `anthropic` | One of `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, `cohere`. An unknown protocol is a startup panic. |
| `base_url` | string | **yes** | — | Scheme + host (+ optional version prefix). Should be `https://` for any external endpoint: the shipped catalog enforces this, but custom entries are not checked at startup, so an `http://` URL you supply will be used as-is. Trailing slash is trimmed. |
| `error_map` | map<string,string> | no | `{}` | Maps a provider-specific JSON error **code** → canonical disposition. Recognized values: `billing`, `rate_limit`, `auth`, `overloaded`, `server_error`, `timeout`, `network`, `client_error`, `context_length` (all nine breaker dispositions; an unrecognized value is ignored). HTTP-status errors (401/429/5xx/…) are classified by the breaker without an `error_map`; this is only for provider JSON codes. |
| `path` | string | no | protocol's standard path | Overrides the upstream request path appended to `base_url`. Use it when the API version is in `base_url` and the endpoint is e.g. `/chat/completions` (no `/v1`), or to carry Azure's `?api-version=` + deployment. |
| `auth` | string | no | protocol's native auth | `bearer` (default for openai/anthropic/responses/cohere), or `api-key` to send an `api-key: <key>` header instead of bearer (Azure OpenAI). Gemini (`x-goog-api-key`) and Bedrock (SigV4) auth is determined by their protocol. |
| `health` | object | no | none | Active health-probe config for this provider's lanes; see [`health`](#health). |

The shipped catalog contains 42 providers across the six protocols (OpenAI-compatible
hosts, Anthropic, Gemini, Bedrock, Responses, Cohere). To add any
OpenAI-compatible endpoint not in the catalog, add an entry here (or, for
workspace-specific hosts, directly in `config.yaml`'s `providers` map as an
override).

### Per-provider deployment overrides

In `config.yaml`, a provider entry may override the catalog's `protocol`,
`base_url`, `error_map` (merged, deployment wins per code), `path`, `auth`, and
`health`.
This is rarely needed; the common case is just `api_key_env`.

---

## `config.yaml`

### `listen`

```yaml
listen: "0.0.0.0:8080"
```

| Field | Type | Default |
|---|---|---|
| `listen` | string (`host:port`) | `0.0.0.0:8080` |

### `auth`

Front-door authentication for clients (superseded by virtual keys when
[governance](#governance) is enabled).

```yaml
auth:
  mode: token
  client_tokens:
    - "${BUSBAR_CLIENT_TOKEN}"
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `mode` | string | `none` | `token`, `passthrough`, or `none`. An unknown mode is a startup panic. |
| `client_tokens` | list<string> | `[]` | Allowed bearer tokens (env-interpolated). Compared in constant time. |

Modes:

- **`token`** — clients must send `Authorization: Bearer <token>` matching the
  allowlist. `/stats` and `/metrics` require a valid token (telemetry is an
  information-disclosure surface); only `/healthz` is always open. In
  `none`/`passthrough` mode `/metrics` is admitted unconditionally.
- **`passthrough`** — the client's own bearer token is forwarded to the upstream
  provider as the credential. Useful when busbar should not hold keys. Upstream
  `401`/`403` is attributed to the caller and relayed verbatim (the lane is not
  penalized).
- **`none`** — open relay; no client auth. Dev only — busbar prints a loud warning
  at startup.

**Bedrock ingress caveat.** A `token`-mode (and governance) check only recognises
bearer-style carriers — `Authorization: Bearer`, `x-api-key`, `x-goog-api-key`.
Native Bedrock SDK clients authenticate with AWS SigV4 (`Authorization:
AWS4-HMAC-SHA256 …`), and busbar does **not** verify inbound SigV4 (`src/sigv4.rs`
is sign-only — no inbound verifier exists). So a SigV4-signed Bedrock request
carries no token busbar can match and is rejected `403` (AccessDenied) in `token`/governance mode
(a genuine SigV4 rejection is 403, not 401).
**Bedrock ingress must therefore run under `passthrough` (or `none`)**, where the
caller's SigV4 credentials are accepted and forwarded upstream. This applies to both
`converse` and `converse-stream`. The other five ingress protocols use bearer-style
auth and work in every mode.

### `providers`

The providers this deployment uses, by catalog name, each naming the env var that
holds its key.

```yaml
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
  gemini:
    api_key_env: GEMINI_KEY
  bedrock:
    # SigV4: ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]
    api_key_env: AWS_BEDROCK_CREDS
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `api_key_env` | string | **yes** | Name of the env var holding the credential. An empty/unset key logs a warning at startup; the lane runs but will fail auth. |
| `protocol`, `base_url`, `error_map`, `path`, `auth`, `health` | — | no | Catalog overrides (see above). |

**Auth shapes by protocol/provider:**

| Backend | Credential format | Header / signing |
|---|---|---|
| anthropic | API key | `x-api-key: <key>` and `Authorization: Bearer <key>` + `anthropic-version` |
| openai / responses / cohere | API key | `Authorization: Bearer <key>` |
| openai + `auth: api-key` (Azure) | API key | `api-key: <key>` |
| gemini | API key | `x-goog-api-key: <key>` |
| bedrock | `ACCESS_KEY_ID:SECRET_ACCESS_KEY[:SESSION_TOKEN]` | AWS SigV4 per request; region parsed from the `bedrock-runtime.<region>.amazonaws.com` host |

### `models`

A model is a **lane**: one model on one provider, with its own concurrency
semaphore and health state.

```yaml
models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    max_requests: -1
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `provider` | string | **yes** | — | Must name a provider in this file's `providers` map. |
| `max_concurrent` | integer | **yes** | — | Concurrency cap (semaphore size) for this lane. In a pool, members' caps stack into one aggregate. |
| `max_requests` | integer | no | `-1` | Lifetime request budget; `-1` = unlimited. When the budget reaches 0 the lane becomes unusable (cost cap). Decremented on success. |
| `default_max_tokens` | integer | no | `4096` | Injected only on a cross-protocol hop to a backend that requires `max_tokens` (Anthropic) when the caller omitted it. Falls back to 4096 when unset. Must be > 0. |

A model can be targeted directly (`POST /<model>/v1/messages`), ad-hoc
(`POST /<provider>/<model>/v1/messages`), or via a pool.

### `pools`

A pool is a named, weighted set of member models. **Pools are optional** — a
deployment can route directly to models without defining any pool.

```yaml
pools:
  fast:
    members:
      - target: claude-haiku
      - target: gpt-4o-mini
```

Target a pool with `POST /<pool>/v1/messages`, or the `model` field of
`POST /v1/chat/completions`.

#### members & weights

```yaml
pools:
  balanced:
    members:
      - target: claude-sonnet
        weight: 8        # ~80%
      - target: gpt-4o
        weight: 2        # ~20%
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `target` | string | **yes** | — | Name of a model in `models`. |
| `weight` | integer | no | `1` | Relative share under smooth weighted round-robin (SWRR), computed over the *healthy* subset. |
| `context_max` | integer | no | none | This member's max context window, for [context-length failover](#context-length-failover). |

Selection uses Nginx-style smooth weighted round-robin over the currently-usable
members, so a tripped or at-capacity member is skipped and its share spreads across
the rest automatically.

#### `failover`

Bounds how long/often busbar retries across members for a single request.

```yaml
pools:
  resilient:
    members:
      - target: claude-sonnet
        weight: 3
      - target: gpt-4o
        weight: 2
      - target: glm-4.6
        weight: 1
    failover:
      deadline_secs: 30
      cap: 3
      exclusions:
        - glm-4.6      # kept for capacity, never used as a failover destination
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `deadline_secs` | integer | `120` | Wall-clock budget for the whole request across hops; exceeded → `503`. |
| `cap` | integer | `3` | Maximum number of failover attempts (hops) for one request. |
| `exclusions` | list<string> | none | Member model names removed from the candidate set entirely — never selected, primary or failover. A per-pool member blocklist. |

Failover is allowed only **before the first upstream byte reaches the client**.
After streaming has begun, an upstream failure cannot fail over (the client already
holds a partial response); busbar instead records the breaker failure and emits an
SSE `error` event, and the client must retry.

If no per-pool `failover` block is set, busbar falls back to the compiled-in defaults
(`deadline_secs: 120`, `cap: 3`). There is no cross-pool inheritance of failover config.

#### `on_exhausted`

What to do when every member is tripped/excluded/at-capacity.

```yaml
pools:
  primary:
    members:
      - target: claude-sonnet
      - target: gpt-4o
    on_exhausted:
      action: fallback_pool:overflow

  overflow:
    members:
      - target: claude-haiku
      - target: gpt-4o-mini
    on_exhausted:
      action: least_bad
```

| `action` value | Behavior |
|---|---|
| `reject` / `status_503` / `503` | Return `503 Service Unavailable` (with `Retry-After` set to the soonest member's cooldown expiry). |
| `least_bad` | Serve the member whose cooldown expires soonest, even though it's Open. A degraded path, logged loudly. |
| `fallback_pool:<name>` | Route to another named pool entirely. Loop-guarded (visited pools tracked). |

Default when `on_exhausted` is omitted: `status_503`. (Note: a bare
`action: fallback_pool` without `:<name>` is a startup error; the per-field default
string is `reject`.)

#### `affinity`

Pin a session to one member while it stays healthy (so provider-side cache/state
stays warm), keyed by a request header.

```yaml
pools:
  smart:
    members:
      - target: claude-sonnet
      - target: gpt-4o
      - target: gemini-1.5-pro
    affinity:
      mode: session
      header_name: x-session-id   # this is the default
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `mode` | string | `session` | `session` is the supported mode. |
| `header_name` | string | `x-session-id` | Request header carrying the session key. |

Affinity is a *preference*, not a hard pin: if the sticky member is unusable, busbar
falls back to normal SWRR selection.

#### `breaker`

Per-pool circuit-breaker tuning. Omit the block entirely for the defaults.

```yaml
pools:
  sensitive:
    members:
      - target: claude-sonnet
      - target: gpt-4o
    breaker:
      trip:
        mode: consecutive     # trip on a short streak rather than a windowed rate
        n: 2
      base_cooldown_secs: 5
      max_cooldown_secs: 60
```

| Field | Type | Default (block present) | Notes |
|---|---|---|---|
| `trip.mode` | string | `error_rate` | `error_rate` (fraction of failures in a window) or `consecutive` (a streak). |
| `trip.window_s` | integer | `30` | Sliding window for `error_rate`. |
| `trip.threshold` | float | `0.5` | Error fraction that trips (`error_rate` mode). |
| `trip.min_requests` | integer | `5` | Floor: never trip on `error_rate` below this many in-window outcomes. |
| `trip.n` | integer | `3` | Consecutive failures that trip (`consecutive` mode). |
| `base_cooldown_secs` | integer | `15` | First cooldown after a trip. |
| `max_cooldown_secs` | integer | `120` | Ceiling for the exponential cooldown backoff. |

> **Defaults** are identical whether the `breaker:` block is present (with fields
> omitted) or absent entirely: `base_cooldown_secs: 15`, `max_cooldown_secs: 120`,
> `trip.mode: error_rate`, `window_s: 30`, `threshold: 0.5`, `min_requests: 5`,
> `trip.n: 3`.

A server `Retry-After` header is always honored as a cooldown floor, on top of the
computed backoff. See [operations.md](operations.md) for the full breaker state
machine.

#### context-length failover

Declare each member's `context_max` so an oversized request fails over to a
larger-context member instead of erroring — without penalizing the smaller lane
(it was healthy; the request simply didn't fit).

```yaml
pools:
  long-context:
    members:
      - target: claude-sonnet
        context_max: 200000
      - target: gemini-1.5-pro
        context_max: 2000000
```

When a lane returns a context-length error, busbar excludes from *this request* any
candidate whose known `context_max` is ≤ the failed lane's, then fails over to a
larger (or unknown-context) member.

### `observability`

All sinks optional; absent = disabled. The Prometheus `/metrics` endpoint is always
enabled and needs no config (it is auth-gated like `/stats`, not publicly open — see
[Auth](#auth)).

```yaml
observability:
  otlp_endpoint: "http://localhost:4318/v1/traces"
  request_log_webhook_url: "https://logs.example.com/busbar"
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `otlp_endpoint` | string | none | When set, busbar installs an OpenTelemetry tracer and exports spans via OTLP/HTTP. |
| `request_log_webhook_url` | string | none | When set, busbar fires a best-effort (fire-and-forget) JSON request-log POST per request. |

### `governance`

Optional. When `enabled: true`, clients authenticate with busbar-issued **virtual
keys** instead of the static `auth` tokens, and are subject to per-key allowed-pools
ACLs, budgets, and rate limits. State persists in embedded SQLite.

```yaml
governance:
  enabled: true
  db_path: /var/lib/busbar/governance.db
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
  price_per_request_cents: 1
  price_per_1k_tokens_cents: 50
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | Master switch. |
| `db_path` | string | `busbar-governance.db` | SQLite file for durable key/usage state. |
| `admin_token` | string | none | Bearer token guarding the `/admin/keys` API. **No token → the admin API is disabled (401).** |
| `price_per_request_cents` | integer | `1` | Flat per-request budget charge. |
| `price_per_1k_tokens_cents` | integer | `0` | Per-1000-token charge (input + output, from response usage). |

Per-request budget spend = `price_per_request_cents` + `tokens/1000 *
price_per_1k_tokens_cents`. See [operations.md](operations.md) for the admin API and
per-key fields (allowed-pools, budget period, RPM/TPM).
