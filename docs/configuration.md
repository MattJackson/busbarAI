# Configuration reference

Busbar reads **two YAML files** at startup:

| File | Default path | Env override | Purpose |
|---|---|---|---|
| Provider catalog | `/etc/busbar/providers.yaml` | `BUSBAR_PROVIDERS` | Shipped map of provider names → protocol, base URL, error map. Operators rarely edit this. |
| Deployment config | `/etc/busbar/config.yaml` | `BUSBAR_CONFIG` | Your site's providers (with API key env vars), models, pools, auth, observability, and governance. |

Both files support `${VAR}` environment interpolation before YAML is parsed. A missing or malformed env var reference is a fatal startup error, Busbar refuses to boot rather than run with an incomplete config.

> All defaults below are sourced from `crates/busbar/src/config/mod.rs`, `crates/busbar/src/breaker.rs`, `crates/busbar/src/health.rs`, and `crates/busbar/src/proto/mod.rs`. Where a serde field default differs from a runtime constant, both are noted.

---

## Table of contents

- [Environment variables](#environment-variables)
- [Environment interpolation](#environment-interpolation)
- [`providers.yaml`](#providersyaml)
  - [Catalog fields](#catalog-fields)
  - [Health probing](#health-probing)
- [`config.yaml`](#configyaml)
  - [`listen`](#listen)
  - [`tls`](#tls)
  - [`auth`](#auth)
  - [`providers`](#providers)
  - [`models`](#models)
  - [`pools`](#pools)
    - [Members and weights](#members-and-weights)
    - [Pool `hooks`: ordering and gates](#pool-hooks-ordering-and-gates)
    - [`breaker`](#breaker)
    - [`failover`](#failover)
    - [`on_exhausted`](#on_exhausted)
    - [`affinity`](#affinity)
    - [Context-length failover](#context-length-failover)
  - [`limits`](#limits)
  - [`observability`](#observability)
  - [`governance`](#governance)
  - [`security`](#security)
- [Minimal working example](#minimal-working-example)
- [Full annotated example](#full-annotated-example)
- [Startup validation summary](#startup-validation-summary)

---

## Environment variables

These are the only environment variables read by Busbar (excluding test-only `BUSBAR_T_*` / `BUSBAR_SENTINEL_*` names):

| Variable | Where read | Purpose / default |
|---|---|---|
| `BUSBAR_PROVIDERS` | `main.rs` | Path to `providers.yaml`. Default: `/etc/busbar/providers.yaml`. |
| `BUSBAR_CONFIG` | `main.rs` | Path to `config.yaml`. Default: `/etc/busbar/config.yaml`. |
| `RUST_LOG` | `observability.rs` | Log level: `error`, `warn`, `info`, `debug`, or `trace`. Default: `info`. |
| *(each provider's `api_key_env` value)* | `main.rs` | The env var **named by** `api_key_env` holds that provider's upstream credential. Read once at boot per provider. |
| *(any `${VAR}` in `config.yaml`)* | `config.rs` | Expanded before YAML is parsed. Unset → fatal boot error. |

`BUSBAR_CLIENT_TOKEN` and `BUSBAR_ADMIN_TOKEN` are not special-cased in the code. They appear in the shipped `config.yaml` only because the file references `${BUSBAR_CLIENT_TOKEN}` and `${BUSBAR_ADMIN_TOKEN}`. Any variable names work.

---

## Environment interpolation

### Syntax

Only the **brace form** `${NAME}` is expanded. Bare `$NAME` is passed through unchanged.

```yaml
auth:
  client_tokens:
    - "${BUSBAR_CLIENT_TOKEN}"    # expanded: the env var's value is substituted
    - "$BUSBAR_OTHER_TOKEN"       # NOT expanded, passed verbatim as a literal string
```

### Error cases

| Situation | Behavior |
|---|---|
| `${NAME}` where `NAME` is unset | Fatal boot error: `unset environment variable: NAME` |
| `${NAME` with no closing `}` | Fatal boot error: `unclosed variable reference...` |
| `${}` (empty name) | Fatal boot error: `empty variable name in ${}` |
| Value contains a control character (`\n`, `\r`, `\t`, NUL, DEL, U+0085, U+2028, U+2029) | Fatal boot error, prevents YAML-structure injection via env vars |

Ordinary punctuation (`: / @ . - # "`) in env var values is allowed. Interpolation scans the entire raw file, including commented-out lines, so a `${VAR}` in a comment must still resolve.

---

## `providers.yaml`

A map of provider name → `ProviderDef`. The shipped catalog is a curated set of verified providers across the six supported protocols. You can add an entry for any OpenAI-compatible endpoint not already in the catalog.

### Catalog fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `protocol` | string | no | `anthropic` | One of the six supported wire protocols: `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, `cohere`. An unknown protocol is a startup error. |
| `base_url` | string | **yes** | n/a | Scheme + host (+ optional path prefix). Must start with `https://` for external endpoints. An `http://` URL in the catalog is not blocked at parse time but will be rejected by the SSRF guard on deployment use. Trailing slash is trimmed. |
| `error_map` | map<string, string> | no | `{}` | Maps a provider-specific error **code string** (from the JSON error body) to a canonical disposition class. Valid values: `rate_limit`, `overloaded`, `server_error`, `timeout`, `network`, `auth`, `billing`, `client_error`, `context_length`. An unrecognized class value is a startup error. HTTP-status classification (401→auth, 429→rate_limit, 5xx→server_error, etc.) applies automatically without an `error_map`; this field is only for provider-specific JSON codes. |
| `path` | string | no | Protocol's standard path | Overrides the upstream request path appended to `base_url`. Must begin with `/`. Static, ignores the per-request model. Use when the API version is in `base_url` and the endpoint path differs from the protocol default (e.g. `/chat/completions` without `/v1`). |
| `path_base` | string | no | Protocol's default base | For URL-model protocols: overrides the hardcoded base segment while the per-request suffix is still appended. Must begin with `/`. On **Gemini** it replaces `/v1beta/models` (suffix `/{model}:verb`) to reach Google Vertex AI's `/v1/projects/{project}/locations/{location}/publishers/google/models` layout; on **Anthropic** it enables Claude-on-Vertex (the model moves into a `:rawPredict`/`:streamRawPredict` suffix and the body carries `anthropic_version` in place of `model`). Config-only, no code. |
| `auth` | string | no | Protocol's native auth | The egress auth mechanism. `bearer` (sends `Authorization: Bearer <key>`) · `api-key` (sends `api-key: <key>`, for Azure OpenAI) · `jwt-bearer` (OAuth 2.0 JWT-bearer, RFC 7523: mints + auto-refreshes a bearer from a service-account key in `api_key_env`; e.g. Google Vertex AI) · `oauth-client-credentials` (OAuth 2.0 client-credentials, RFC 6749 §4.4: `api_key_env` holds `client_id:client_secret`, exchanged at `token_url` for a bearer; e.g. Azure OpenAI via Entra ID). When unset, each protocol uses its native scheme: bearer for anthropic/openai/responses/cohere, `x-goog-api-key` for gemini, AWS SigV4 for bedrock. |
| `token_url` | string | no | none | OAuth token endpoint for `auth: oauth-client-credentials`, where busbar POSTs the client credentials for a bearer. Required for that auth; must be https for a public host. |
| `scope` | string | no | none | OAuth scope for `auth: oauth-client-credentials`. Required for that auth. |
| `health` | object | no | none | Active health-probe config. See [Health probing](#health-probing). |

> **OAuth self-minting (`jwt-bearer` / `oauth-client-credentials`): boot window.** These lanes mint
> their first bearer token in the background at startup and on every config reload. For the brief window
> before that first mint completes, the lane has no token and requests routed to it fail auth (upstream
> 401); a burst can trip the lane's breaker, which then recovers automatically once the token lands (the
> active health prober skips the lane until it is ready, so probing never parks it). This self-heals in
> well under a second. But if you route heavy traffic to a freshly-booted OAuth lane, expect a few 401s
> until the first token mints. Static-key lanes (`bearer` / `api-key` / SigV4) have no such window.

Example entries:

```yaml
anthropic:
  protocol: anthropic
  base_url: https://api.anthropic.com

azure-openai:
  protocol: openai
  base_url: https://myaccount.openai.azure.com/openai/deployments/gpt-4o
  path: /chat/completions?api-version=2024-02-01
  auth: api-key    # sends api-key: <key> instead of Authorization: Bearer

zai-api:
  protocol: openai
  base_url: https://api.z.ai/api/paas/v4
  path: /chat/completions
  error_map:
    "1113": billing
    "1302": rate_limit
```

### Per-provider deployment overrides

In `config.yaml`, a provider entry may selectively override the catalog's `protocol`, `base_url`, `error_map` (merged: deployment entries win per code), `path`, `path_base`, `auth`, `token_url`, `scope`, and `health`. The only always-required field in the deployment entry is `api_key_env`.

### Health probing

Health probing sends one minimal token request per interval per lane. It runs on a background task; probe outcomes run through the same disposition pipeline as organic traffic (2xx recovers the lane, transient failures increment the breaker, hard errors set the lane dead for 30 min).

| Field | Type | Default | Notes |
|---|---|---|---|
| `mode` | string | `none` | `none` (passive only, breaker updates on organic traffic), `dead` (re-probe only tripped lanes), `active` (probe all lanes at every interval). `active` sends one billable request per lane per interval. |
| `interval_secs` | integer | `30` | Seconds between probes. Floored at 1. |
| `timeout_secs` | integer | `5` | Per-probe request timeout. Floored at 1. |

```yaml
anthropic:
  protocol: anthropic
  base_url: https://api.anthropic.com
  health:
    mode: dead
    interval_secs: 30
    timeout_secs: 5
```

A provider with no API key configured (`api_key_env` unset or its value empty) will not be probed regardless of the `health` block.

---

## `config.yaml`

### `listen`

```yaml
listen: "0.0.0.0:8080"
```

| Field | Type | Default |
|---|---|---|
| `listen` | string (`host:port`) | `0.0.0.0:8080` |

The value is passed directly to `tokio::net::TcpListener::bind`. An invalid or already-bound address is a fatal startup error.

---

### `tls`

Optional. When present, Busbar terminates inbound TLS natively (and, with
`client_ca_file`, requires mutual TLS). When **absent**, Busbar serves plain HTTP,
the historical default, unchanged.

```yaml
tls:
  cert_file: /etc/busbar/tls/fullchain.pem  # PEM cert chain, leaf first
  key_file:  /etc/busbar/tls/privkey.pem    # PEM private key (PKCS#8 / PKCS#1 / SEC1)
  client_ca_file: /etc/busbar/tls/ca.pem    # optional: present ⇒ mTLS required
```

| Field | Type | Default |
|---|---|---|
| `cert_file` | string (path) |, (required when `tls` is set) |
| `key_file` | string (path) |, (required when `tls` is set) |
| `client_ca_file` | string (path) | unset (no client-cert requirement) |

Certs/keys are loaded once at startup; any missing or unparseable file is a fatal
startup error naming the file. ALPN advertises http/1.1. Rotate certs by replacing
the files and restarting. Full operational guide:
[`operations.md`](operations.md#inbound-tls--mutual-tls-mtls).

---

### `auth`

Front-door authentication for clients. This chain is what gates requests by default. When [governance](#governance) is **active** (a `governance.admin_token` is set), governance virtual keys supersede static `auth` entirely: every request must then carry a valid enabled virtual key. With no admin token governance is inert and this chain applies unchanged.

```yaml
auth:
  chain: [tokens]
  upstream_credentials: own
  client_tokens:
    - "${BUSBAR_CLIENT_TOKEN}"
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `chain` | list<string> | no | `[]` | The ordered authentication chain, each name a compiled-in auth module (the built-in is `tokens`). `[]` (default) is the open front door: no client authentication, development only, loud startup warning. An unknown module name is a startup error. |
| `upstream_credentials` | string | no | `own` | Whose key hits the provider: `own` (Busbar's configured lane credential) or `passthrough` (forward the caller's own token upstream; Busbar holds no keys). |
| `client_tokens` | list<string> | no | `[]` | The `tokens` module's allowlist (env-interpolated). Required to be non-empty when `tokens` is in the chain. All comparisons are constant-time (no timing oracle). Inert when `tokens` is not in the chain. |
| `modules` | map | no | `{}` | Per-module trust-boundary caps, keyed by module name (see below). |
| `mode` | string | no | n/a | **Removed in 1.3** (was `token`/`passthrough`/`none`). The `auth` block rejects unknown keys, so a stale `mode:` is a hard parse error. Mapping: `mode: token` → `chain: [tokens]`; `mode: none` → `chain: []`; `mode: passthrough` → `chain: []` + `upstream_credentials: passthrough`. |

**Token extraction order:** `Authorization: Bearer`, then `x-api-key`, then `x-goog-api-key`. Blank values are treated as absent.

**Semantics:**

- **`chain: [tokens]`**: the client must send a token matching an entry in `client_tokens`. Every route except `/healthz` requires a valid token (including `/stats` and `/metrics`, which are information-disclosure surfaces).
- **`upstream_credentials: passthrough`**: the caller's own token is forwarded to the upstream provider. An upstream 401/403 response is attributed to the caller; the breaker's `auth`/`billing` disposition fires, which hard-downs the lane for 30 minutes: so callers with bad keys will suppress that lane for everyone for 30 minutes. Use with care.
- **`chain: []`**: open relay, no client authentication. `/metrics` and `/stats` are admitted unconditionally. Development only; Busbar logs a loud warning at startup.

**Startup validation:**
- `tokens` in the chain + empty effective `client_tokens` → startup error (every request would be rejected).
- `chain: []` + non-empty `client_tokens` → startup warning (the list has no effect).
- `upstream_credentials: passthrough` + a provider whose `api_key_env` resolves to a non-empty value → startup warning (credential-leak risk: an unauthenticated caller's request could carry Busbar's own key to the upstream).

**Bedrock ingress.** Native Bedrock SDK clients authenticate with AWS SigV4 (`Authorization: AWS4-HMAC-SHA256 …`). There are two tracks:

- **Without governance** (`chain: []`, with or without `upstream_credentials: passthrough`): Busbar does not verify the inbound SigV4 signature. The header is forwarded upstream (passthrough) or ignored entirely. Use this for transparent Bedrock proxying without per-key controls.
- **With active governance** (`chain: [tokens]` + `governance.admin_token` set): Busbar verifies the inbound SigV4 signature natively (`crates/busbar/src/auth/mod.rs` `verify_bedrock_sigv4`, including body-hash integrity). Mint a key with `"issue_aws_credential": true`; the response includes `aws_access_key_id` + `aws_secret_access_key` (shown once). The Bedrock SDK authenticates with that pair; Busbar verifies the signature, then applies the key's budget / RPM / TPM / allowed-pools. No `passthrough` required.

All other five ingress protocols use bearer-style auth and work with every chain configuration.

#### `auth.modules`: per-module trust-boundary caps

An auth module is a fully trusted endpoint: a module asserting `groups: ["busbar-admins"]` IS
asserting an admin. Two operator-owned caps bound any module's blast radius, applying wherever
the module appears (the data-plane `chain` or `admin_auth`):

```yaml
auth:
  modules:
    corp-ad:
      allowed_groups: [llm-users, busbar-viewers]   # groups this module may assert
      max_admin_scope: read-only                    # ceiling regardless of group_map
```

| Field | Default | Notes |
|---|---|---|
| `allowed_groups` | absent (no cap) | Busbar intersects the module's returned groups with this allowlist BEFORE `group_map` resolution: a module cannot claim a group you did not pre-authorize for it. |
| `max_admin_scope` | `read-only` | Ceiling on the admin scope obtainable through this module, regardless of what `group_map` grants: `read-only` \| `hooks-register` \| `full`. `full` is an explicit opt-in, warned at startup. The built-in `admin-tokens` operator credential is exempt (it is the root credential). |

---

### `admin_auth` and `group_map`

The admin API (`/api/v1/admin/*`) authenticates through its own chain, `admin_auth:` (default
`[admin-tokens]`, the single operator token), and `group_map:` maps identity-provider GROUPS to
authority, both admin and data-plane:

```yaml
admin_auth: [admin-tokens]

group_map:
  busbar-admins:  { admin_scope: full }
  busbar-viewers: { admin_scope: read-only }
  llm-users:      { allowed_pools: [my-pool], rpm_limit: 600 }
```

| Field | Notes |
|---|---|
| `admin_scope` | The admin authority this group grants: `read-only` \| `hooks-register` \| `full`. Absent = none. The most permissive of a principal's mapped groups wins (then the module ceiling applies). |
| `allowed_pools` | DATA-PLANE grant: pools this group may target. Setting it (even `[]` = every pool) is what grants inference access at all; a group with only `admin_scope` confers none. Pool lists union across a principal's groups. |
| `rpm_limit` / `tpm_limit` / `max_budget_cents` | Rate and spend caps for principals granted through this group, enforced by exactly the machinery a virtual key uses, keyed by the principal. Most-permissive union: a granting group without a cap lifts that axis; otherwise the max wins. |

Unmapped groups grant nothing (fail closed): with governance active (an `admin_token` set), an
identified principal whose groups earn no `allowed_pools` grant is rejected outright.

The admin chain is live-mutable over the API (`PUT /api/v1/admin/auth`) with an anti-lockout guard;
see the [Admin API guide](./admin-api.md).

---

### `providers`

Declares which catalog providers this deployment uses and supplies the env var holding each one's credential.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `api_key_env` | string | **yes** | n/a | Name of the env var that holds the upstream API key or credential. Read once at boot. An unset or empty env var logs a startup warning; the lane starts but will fail upstream auth. |
| `protocol` | string | no | Catalog value | Override the catalog protocol. Rarely needed. |
| `base_url` | string | no | Catalog value | Override the upstream base URL. Must use `https://` for public/external hosts. Plain `http://` is permitted only for private or loopback hosts (e.g. a local Ollama or vLLM instance). Cloud-metadata hosts are blocked regardless of scheme (see SSRF guard). |
| `error_map` | map<string, string> | no | `{}` merged onto catalog | Merged with the catalog's `error_map`; deployment entries win per code. |
| `path` | string | no | Catalog value | Override the upstream path. Must begin with `/`. |
| `path_base` | string | no | Catalog value | Override the URL-model base segment (Gemini or Anthropic), keeping the per-request verb suffix. Must begin with `/`. For Gemini-on-Vertex and Claude-on-Vertex. |
| `auth` | string | no | Catalog value | `bearer`, `api-key`, `jwt-bearer` (OAuth service-account, e.g. Vertex AI), or `oauth-client-credentials` (e.g. Azure Entra ID). |
| `token_url` | string | no | Catalog value | OAuth token endpoint for `oauth-client-credentials`. |
| `scope` | string | no | Catalog value | OAuth scope for `oauth-client-credentials`. |
| `health` | object | no | Catalog value | Override the catalog's health probe config. |
| `allow_metadata_hosts` | list<string> | no | `[]` | Per-provider surgical exception: hosts/IPs to unblock from the cloud-metadata SSRF denylist for **this provider only**. See [Security: Provider upstreams & SSRF](/docs/security/#the-control-matrix). |

**Credential format by protocol:**

| Protocol | `api_key_env` value format | How it's sent |
|---|---|---|
| `anthropic` | API key (`sk-ant-api…`) or OAuth token (`sk-ant-oat…`) | `x-api-key: <key>` for API keys; `Authorization: Bearer <key>` for OAuth tokens. Mode is inferred from the key prefix; both headers are sent if the prefix is unrecognized. `anthropic-version` header is always added. |
| `openai` / `responses` / `cohere` | API key | `Authorization: Bearer <key>` |
| `openai` + `auth: api-key` (Azure) | API key | `api-key: <key>` |
| `gemini` | API key | `x-goog-api-key: <key>` |
| `bedrock` | `ACCESS_KEY_ID:SECRET_ACCESS_KEY` or `ACCESS_KEY_ID:SECRET_ACCESS_KEY:SESSION_TOKEN` | AWS SigV4: signed per request. Region is parsed from the host in `base_url` (e.g. `bedrock-runtime.us-east-1.amazonaws.com`). |

```yaml
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
  openai:
    api_key_env: OPENAI_KEY
  gemini:
    api_key_env: GEMINI_KEY
    health:
      mode: dead
      interval_secs: 60
  bedrock-us-east-1:
    api_key_env: AWS_BEDROCK_CREDS   # ACCESS:SECRET or ACCESS:SECRET:SESSION
```

**Reserved name:** a provider named `admin` (or any name beginning with `admin/`) is a startup error.

---

### `models`

A model is a **lane**: one model at one provider, with its own concurrency semaphore, lifetime budget, and breaker cell. Models must be defined here before they can be used as pool members or targeted directly.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `provider` | string | **yes** | n/a | Must name a key in this file's `providers` map. |
| `max_concurrent` | integer | no | unset (unbounded) | Optional per-lane concurrency limiter: the max simultaneous in-flight requests for this lane (semaphore size). **Omit it for no cap** (unbounded): a limiter you opt into, mirroring `max_requests`. Set a positive integer to cap. Must be ≥ 1 when set (`0` = a lane that never admits a request = startup error). |
| `max_requests` | integer | no | `-1` | Lifetime request budget. `-1` (default) = unlimited. When the counter reaches `0` the lane is unusable. Must not be `0` (zero budget = permanently unusable = startup error). |
| `default_max_tokens` | integer | no | `4096` | Injected **only** on a cross-protocol hop to a backend that requires `max_tokens` (Anthropic protocol) when the caller omitted it. Has no effect on same-protocol passthrough. Must be > 0 when set. |
| `upstream_model` | string | no | the config key | The model id sent to the provider on the wire (request body for body-model protocols; URL path for path-model protocols like Bedrock/Gemini; and health probes). Defaults to the config key. Set it when the key can't be the wire id: most commonly to run the **same model behind two providers** (the keys must differ, but each needs its own provider-specific model string). Must be non-empty when set. Metrics, breaker cells, and logs still key off the config key, not this. |
| `attempt_timeout_ms` | integer | no | unset (no cap) | Per-attempt cap, in milliseconds, on time to **response headers** (the hang detector). If the provider has not started answering within the cap, the attempt is treated exactly like a transport timeout: the breaker records a transient failure and the request fails over to the next pool member within the same request. Because the cap covers only connect + headers, a healthy long **stream body** is never cut off by it. A pool member's own `attempt_timeout_ms` overrides this per pool. Must be ≥ 1 when set (0 is a startup error); always floored by the request's remaining `failover.timeout_secs` budget. |
| `reasoning` | bool | no | `false` | Operator declaration that this model accepts reasoning/thinking request parameters (Anthropic `thinking`, Gemini `thinkingConfig`, OpenAI `reasoning_effort`). Gates the [cross-protocol reasoning carry](#cross-protocol-reasoning-reasoning): without the flag, a translated reasoning ask is dropped at the seam (warned) and never sent, so a non-reasoning model can never 400 from translation. Capability is per-model, not per-provider (Sonnet takes `thinking`; Haiku rejects it). You declare what you deployed, like `context_max`. A pool member's `reasoning` overrides this per pool. Same-protocol passthrough ignores it. |
| `prompt_caching` | bool | no | `false` | Operator declaration that this model accepts prompt-cache markers on dialects where the marker is **model-gated**: Bedrock Converse's `cachePoint`, which Claude accepts but Amazon Nova hard-rejects with a 400 ("extraneous key"). The cache twin of `reasoning`: without the flag, cross-protocol `cache_control` breakpoints headed to such a dialect are dropped at the seam (warned) and the request proceeds uncached, fail-safe, never a translation-induced 400. Set it on Claude-on-Bedrock models to keep their prompt caching across the Anthropic→Bedrock translation. Dialects whose cache form is universally accepted (the Anthropic API's `cache_control`) ignore the flag, as does same-protocol passthrough (byte-exact). |

```yaml
models:
  claude-sonnet-4-5:
    provider: anthropic
    max_concurrent: 20
    max_requests: -1
    default_max_tokens: 8192

  gpt-4o:
    provider: openai
    max_concurrent: 20

  gemini-1.5-pro:
    provider: gemini
    max_concurrent: 15

  nova-pro:
    provider: bedrock-us-east-1
    max_concurrent: 10
```

**Direct routing:** a model named `my-model` is reachable at `POST /my-model/v1/messages` (Anthropic ingress). The ad-hoc route `POST /{provider}/{model}/v1/messages` bypasses the model map entirely: it routes to the named provider with the named model string, using no pool.

**Reserved name:** a model named `admin` is a startup error.

#### Same model, two providers (`upstream_model`)

To run one real model: say Claude 3.5 Sonnet, behind **both** Anthropic and Bedrock in a single failover pool, the two model keys must differ (keys are unique), but each provider expects its own model string. `upstream_model` carries the provider-specific wire id while the key stays a stable operator alias:

```yaml
models:
  sonnet-anthropic:
    provider: anthropic
    max_concurrent: 20
    upstream_model: claude-3-5-sonnet-20241022             # what Anthropic expects on the wire
  sonnet-bedrock:
    provider: bedrock-us-east-1
    max_concurrent: 10
    upstream_model: anthropic.claude-3-5-sonnet-20241022-v2:0   # Bedrock's modelId

pools:
  sonnet:                                  # clients call ONE name: POST /sonnet/v1/messages
    members:
      - target: sonnet-anthropic
        weight: 3                          # primary
      - target: sonnet-bedrock
        weight: 1                          # cross-provider failover lane
```

Clients always address `sonnet`; when Anthropic rate-limits or trips its breaker, busbar fails over in-flight to the **same model** on Bedrock. Health probes use `upstream_model` too, so a lane can't report healthy on the alias while real traffic fails on the wrong upstream id. Models without a collision (e.g. `gpt-4o`) need no `upstream_model`: the key already is the wire id.

---

### `pools`

A pool is a named, weighted group of model lanes with shared failover, breaker, and affinity config. Pools are optional, a deployment can route directly to models without any pools.

**Target a pool** with `POST /smart/v1/messages` (Anthropic ingress), or by setting `"model": "smart"` in `POST /v1/chat/completions` (OpenAI ingress), `POST /v2/chat` (Cohere), etc.

**Reserved name:** a pool named `admin` is a startup error. A pool name must not collide with any provider or model name.

#### Members and weights

```yaml
pools:
  smart:
    members:
      - target: claude-sonnet-4-5
        weight: 8
      - target: gpt-4o
        weight: 2
      - target: gemini-1.5-pro
        weight: 1
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `target` | string | **yes** | n/a | Name of a model in `models`. Must be a configured model; a missing model is a startup error. |
| `weight` | integer | no | `1` | Relative selection share under smooth weighted round-robin (SWRR), computed over the currently healthy/usable members. Must be ≥ 1. `0` is a startup error. |
| `context_max` | integer | no | none | This member's maximum context window (tokens). Used for [context-length failover](#context-length-failover). |
| `attempt_timeout_ms` | integer | no | the model's value | Per-attempt time-to-response-headers cap for this member **in this pool**, overriding the model-level `attempt_timeout_ms`. Lets the same model carry different hang tolerances per pool (e.g. `10000` in a batch pool, `50` in a latency-critical one). Must be ≥ 1 when set (0 is a startup error). See [Per-attempt timeouts](#per-attempt-timeouts-attempt_timeout_ms). |
| `reasoning` | bool | no | the model's value | Per-pool override of the model-level `reasoning` capability flag (member wins), so the same lane can allow thinking in a research pool and refuse it in a latency-critical one. See [Cross-protocol reasoning](#cross-protocol-reasoning-reasoning). |
| `tier` | string | no | none | Operator-declared routing tier label (e.g. `"primary"`, `"overflow"`, `"large"`, `"small"`). Inert for plain weighted pools (no hooks). Exposed to gate hooks as the `tier` field on each candidate. See [Pool `hooks`](#pool-hooks-ordering-and-gates). |
| `cost_per_mtok` | float | no | none | Operator-declared cost in currency units per million tokens. Drives the `cheapest` ordering strategy and is exposed to gate hooks. Inert when unset or for plain weighted pools. |
| `tags` | list<string> | no | `[]` | Free-form string labels (e.g. `["opus", "large-context"]`). The `restrict` gate verb intersects the candidate set against these tags (compliance pinning). Exposed to gate hooks for tag-based candidate selection. Inert for plain weighted pools. |

Selection uses Nginx-style smooth weighted round-robin (SWRR) across the healthy subset. A tripped, dead, or capacity-exhausted member is skipped and its share redistributes to the remaining members automatically. Selection state is isolated per-pool (separate SWRR shard), so unrelated pools that share a lane select independently.

**Empty `members` list is a startup error.**

A pool spanning members that use different underlying protocols produces a startup **warning** (not an error). Cross-protocol requests are translated via the IR (intermediate representation), which is lossless for all standard fields. Source-only fields (e.g. OpenAI `logprobs`, `n`) are dropped before reaching a foreign backend.

---

#### Per-attempt timeouts (`attempt_timeout_ms`)

Some providers fail by **hanging**: the connection opens, then nothing comes back for minutes. The ordinary transport timeout is sized for a full response and is far too long to catch this. `attempt_timeout_ms` caps how long a single attempt may wait for **response headers**; when it expires, the attempt is recorded as a transient failure on that member's breaker cell and the request fails over to the next member, all within the same request.

Two layers, member wins over model:

```yaml
models:
  gemini-pro:
    provider: gemini
    max_concurrent: 20
    attempt_timeout_ms: 10000     # model-level default: give it 10s anywhere

pools:
  batch:
    members:
      - target: gemini-pro        # inherits the model's 10000ms
      - target: gpt-4o
  realtime:
    members:
      - target: gemini-pro
        attempt_timeout_ms: 50    # THIS pool can't wait: hop after 50ms
      - target: gpt-4o
```

Details:

- The cap covers **connect + time to response headers only**. A healthy stream that has started answering is never cut off mid-body by it.
- Expiry is classified like a network timeout: it counts toward the breaker's transient streak (repeated hangs trip the lane) and shows up in metrics as `disposition="attempt_timeout"` on `busbar_upstream_failures_total` and `reason="attempt_timeout"` on `busbar_failovers_total`.
- The cap is always floored by the request's remaining [`failover.timeout_secs`](#failover) budget; it can never extend a request past that.
- Unset means no per-attempt cap (the transport timeout still applies). `0` is a startup error; disable by omitting the field.

---

#### Cross-protocol reasoning (`reasoning`)

The reasoning/thinking ask translates between the three protocols that model it: OpenAI `reasoning_effort` and Responses `reasoning.effort` (words), Anthropic `thinking.budget_tokens` and Gemini `thinkingConfig.thinkingBudget` (token budgets). Number to number is a straight copy; words and numbers convert through the effort table below. The response-side thinking content (thinking blocks, thought parts) already translates losslessly and needs no configuration.

The ask is **gated per lane** because thinking support is per-model, not per-protocol, and Busbar keeps no model database. `reasoning: true` on a model (or a pool member, which wins) declares "this backend accepts thinking params":

```yaml
models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    reasoning: true       # this model accepts thinking params
  claude-haiku:
    provider: anthropic
    max_concurrent: 40    # no flag: a translated reasoning ask is dropped (warned), never sent
```

With the flag set, an OpenAI client's `reasoning_effort: "high"` reaches this Claude lane as `thinking: {type: enabled, budget_tokens: 16384}`; a Gemini client's `thinkingBudget: 6000` reaches it as `budget_tokens: 6000`. Without the flag the request still succeeds, thinking at the backend's default level.

The effort table (word ↔ number conversion, both directions) is operator-tunable:

```yaml
limits:
  reasoning_effort_budgets:   # defaults shown; must be ascending, all > 0
    minimal: 1024
    low: 4096
    medium: 8192
    high: 16384
```

Guard rails, applied automatically: the budget is clamped to leave at least 1024 answer tokens under `max_tokens` (Anthropic requires `budget_tokens < max_tokens`), and when `max_tokens` is too small to fit any thinking the ask is dropped with a warn. Anthropic rejects `temperature`/`top_k` alongside thinking, so those knobs are omitted (warned) when a thinking ask is emitted to an Anthropic backend. Gemini's dynamic `-1` round-trips to Gemini verbatim and projects elsewhere as `medium`.

---

#### Pool `hooks`: ordering and gates

A pool names the hooks it wants (an **ordering strategy** and/or **gates**) in one `hooks: [...]` list. The ordering strategy decides the **order** in which healthy members are tried; gates can **reject**, **restrict**, or **order** the request before dispatch. The default (no list, or no strategy named) is `weighted` (SWRR), zero-cost and byte-identical to the pre-hooks baseline. The full hook model (the registry, taps vs gates, grants, reply arms, and guarantees) lives in [Hooks](hooks.md).

```yaml
hooks:                      # top-level registry: define each hook once
  smart-router:
    kind: gate
    socket: /run/busbar/router.sock

pools:
  smart:
    hooks: [cheapest, smart-router]    # base ordering strategy + a gate, one list
    members:
      - target: claude-sonnet-4-5
        weight: 2
        context_max: 200000
        tier: primary
        cost_per_mtok: 3.0
        tags: ["sonnet", "fast"]
      - target: gpt-4o
        weight: 1
        context_max: 128000
        tier: primary
        cost_per_mtok: 5.0
        tags: ["gpt4"]
      - target: gpt-4o-mini
        weight: 1
        tier: overflow
        cost_per_mtok: 0.15
        tags: ["cheap"]
```

**The pool `hooks:` list:**

- **At most one ordering strategy** (`weighted`, `cheapest`, `fastest`, `least_busy`, or `usage`) sets the pool's base ranking. Naming none leaves the base defaulted: the registry's `default: true` hook (if one exists) becomes the base, else the compiled-in `weighted`.
- **Any other name is a gate reference** into the top-level `hooks:` registry (must exist and be `kind: gate`; a dangling name or a tap is a startup error).
- **Several gates may share the list.** All decision gates (the pool's and any `global_hooks`) fire **concurrently** per request and reconcile deterministically: any `reject` wins (the lowest-`priority` gate's status/message surfaces), `restrict`s intersect (an empty intersection applies that gate's `on_empty`, fail-closed by default), and with multiple `order`s the last in the chain wins. A restriction persists across every failover hop.

**Top-level `hooks:` registry fields** (per named hook; full reference in [Hooks](hooks.md)):

| Field | Type | Default | Description |
|---|---|---|---|
| `kind` | `tap` \| `gate` | required | `gate` = fire-and-wait (may rank/reject/restrict/rewrite); `tap` = fire-and-forget observation. |
| `socket` | string | none | Absolute Unix-domain-socket path of the operator-run hook binary (lazy connect; Unix only). Exactly one of `socket`/`webhook`. |
| `webhook` | string | none | Sidecar URL. SSRF-guarded (loopback allowed; RFC-1918/CGNAT/link-local/metadata blocked; remote must be `https://`). |
| `timeout_ms` | integer | `1` | Hard wall-clock deadline for a gate decision. Co-located socket ≈ 8 µs, webhook ≈ 34 µs. Raise it when the hook does I/O. On timeout the decision is coerced to `on_error`. |
| `on_error` | string | `nothing` | Fallback when a gate times out / errors / saturates: `nothing` (default: do not participate, a failing non-routing gate can never displace another gate's verdict), `weighted` (the ordering floor; same behavior, the name for ordering gates), `reject` (fail closed; security gates set this), `first`, or the NAME of a fallback hook (a chain, proven terminating at boot). A gate's deliberate `reject` reply is a decision, not a failure. `on_error` never applies to it. |
| `prompt` | `no` \| `ro` \| `rw` | `no` | Prompt-content grant: `ro` sends the prompt read-only; `rw` additionally allows a `rewrite` reply. `rw` on a tap is a startup error. Immutable after registration; enforced both directions. |
| `user` | `no` \| `ro` | `no` | Caller-identity grant: governance key id/name (never the secret) + the body's end-user field. |
| `priority` | integer | `0` | Chain ordering key: orders the rewrite transform chain and tie-breaks the phase-2 reconcile (which reject surfaces; which order is "last"). Ties keep globals first, then config order. |
| `on_empty` | string | `reject` | A restrict gate's empty-intersection behavior: `reject` (fail closed, 503) or `weighted` (advisory escape: that gate's restriction is skipped). |
| `global` | boolean | `false` | Fire on every request (overlay on top of each pool's own hooks): inline sugar for listing the name in `global_hooks:`. |
| `default` | boolean | `false` | Make this hook THE base ordering for pools that named no strategy (replacement, not overlay). At most one hook may set it. A second is a startup error. |
| `settings` | map | `{}` | Opaque settings pushed to the hook via the `configure` wire message: as the first message on every socket (re)connection, and live via `PATCH /api/v1/admin/hooks/{name}/settings` (commit-on-ack). Busbar never interprets the contents. |

The per-member `tier`, `cost_per_mtok`, and `tags` fields documented in [Members and weights](#members-and-weights) above feed the ordering strategies and gate candidates. Gate observability: the `x-busbar-route-policy` / `x-busbar-route-target` response headers name the deciding hook and chosen lane.

---

#### `breaker`

Per-(pool, lane) circuit-breaker tuning. The breaker state is independent per pool: a lane open in pool A can be closed in pool B. Lane-global state (hard-down, lifetime budget, concurrency semaphore) is shared across all pools.

```yaml
pools:
  primary:
    members:
      - target: claude-sonnet-4-5
      - target: gpt-4o
    breaker:
      trip:
        mode: error_rate
        window_secs: 30
        threshold: 0.5
        min_requests: 5
      base_cooldown_secs: 15
      max_cooldown_secs: 120
```

| Field | Type | Default | Validation | Notes |
|---|---|---|---|---|
| `trip.mode` | string | `error_rate` | Must be `error_rate` or `consecutive` | **`error_rate`**: trips when `errors/total ≥ threshold` over `window_secs` seconds, with at least `min_requests` outcomes in the window. **`consecutive`**: trips after `consecutive_n` consecutive failures regardless of window. |
| `trip.window_secs` | integer | `30` | Must be ≥ 1 | Sliding outcome window for `error_rate` mode. Outcomes older than `window_secs` are evicted. (Renamed from `window_s` in 1.0.0; the old key still loads via a serde alias.) |
| `trip.threshold` | float | `0.5` | Must be in `(0.0, 1.0]` | Error fraction threshold for `error_rate` mode. `0.5` means more than half of outcomes in the window must be errors to trip. |
| `trip.min_requests` | integer | `5` | Must be ≥ 1 | `error_rate` mode: minimum outcomes required in the window before the threshold is evaluated. Prevents tripping on a single failure with no baseline. |
| `trip.consecutive_n` | integer | `3` | Must be ≥ 1 | `consecutive` mode: number of consecutive failures that trip the breaker. (Renamed from `n` in 1.0.0; the old key still loads via a serde alias.) |
| `base_cooldown_secs` | integer | `15` | Must be ≥ 1 | Initial cooldown duration after a trip. Subsequent trips without a successful recovery double the cooldown (exponential backoff). |
| `max_cooldown_secs` | integer | `120` | Must be ≥ `base_cooldown_secs` | Maximum cooldown regardless of backoff. |

**Cooldown details.** Cooldown is exponential: `base * 2^streak`, clamped to `max_cooldown_secs`, with ±10% random jitter (seeded from time, cell address, and streak) to decorrelate simultaneous failures. A provider `Retry-After` header is always honored as a **floor** on the computed cooldown (no config knob; always enabled), hard-capped at 24 hours to prevent overflow.

**Recovery.** When a cooldown expires the breaker transitions to HalfOpen. Exactly one request becomes the recovery probe (via a single CAS); `/healthz` and SWRR selection reads never steal the probe. If the probe succeeds, the breaker closes; if it fails, the cooldown doubles and the cycle repeats.

**Disposition by error class:**

| Class | Breaker effect | Lane penalty |
|---|---|---|
| `rate_limit`, `overloaded`, `server_error`, `timeout`, `network` | Transient: increments error counter / streak, may trip | Yes |
| `auth`, `billing` | Hard-down, 30-minute sticky cooldown (`HARD_DOWN_COOLDOWN_SECS = 1800`); recovers only via successful health probe | Yes (hard) |
| `client_error` | Client fault, relayed verbatim | None |
| `context_length` | Context failover, fails over to larger-context member | None |

A `context_length` classification is suppressed on any 5xx response, it cannot mask an upstream outage.

**Omitting the `breaker` block** uses all defaults above. The defaults match ADR-0002.

---

#### `failover`

Bounds how long Busbar will retry across members for a single request.

```yaml
pools:
  resilient:
    members:
      - target: claude-sonnet-4-5
        weight: 3
      - target: gpt-4o
        weight: 2
      - target: gemini-1.5-pro
        weight: 1
    failover:
      timeout_secs: 30
      max_hops: 3
      exclusions:
        - gemini-1.5-pro   # never used as a failover destination; still receives primary traffic
```

| Field | Type | Default | Validation | Notes |
|---|---|---|---|---|
| `timeout_secs` | integer | `120` | Must be ≥ 1 | Wall-clock budget for the entire request across all hops. Exceeded → 503 immediately. (Renamed from `deadline_secs` in 1.0.0; the old key still loads via a serde alias.) |
| `max_hops` | integer | `3` | n/a | Maximum number of failover hops for one request. A hop is one upstream attempt that fails before the first response byte. (Renamed from `cap` in 1.0.0; the old key still loads via a serde alias.) |
| `exclusions` | list<string> | none | Each entry must name a member of **this** pool | Model names that are **never** selected as a failover destination, primary or otherwise. Use to reserve a member for affinity-only use or to permanently exclude a degraded lane. |

**Failover boundary: the first upstream byte.** Failover is only possible before the first byte of the upstream response reaches the client. Once streaming has begun (any SSE or event-stream byte sent to the client), an upstream failure cannot fail over. Busbar instead records the breaker penalty and emits an in-band SSE error event. The client is responsible for retrying at the application level.

**Budget refund.** The lifetime `max_requests` counter is decremented optimistically when a 2xx header is received. If the response body then fails to deliver (transport error after headers), the decrement is reversed, so a partial-body transport failure does not permanently consume a budget slot.

---

#### `on_exhausted`

What to do when every member of the pool is tripped, dead, or concurrency-exhausted.

```yaml
pools:
  primary:
    members:
      - target: claude-sonnet-4-5
      - target: gpt-4o
    on_exhausted:
      action: fallback_pool:overflow

  overflow:
    members:
      - target: claude-sonnet-4-5
      - target: gpt-4o-mini
    on_exhausted:
      action: least_bad
```

| Action value | Behavior |
|---|---|
| `reject` (also `503`, `status_503`, `status503`) | Return `503 Service Unavailable` with a `Retry-After` header set to the soonest member cooldown expiry. This is the default when `on_exhausted` is omitted. |
| `least_bad` (also `least-bad`, `leastbad`) | Route to the member whose cooldown expires soonest, even though it is Open. The request is likely to fail, but degraded service is preferred over a hard 503. This is logged as a degraded dispatch. |
| `fallback_pool:<name>` | Route the request to another named pool and run its full selection logic. Cycles (`primary → overflow → primary`) and self-references are detected at startup and are errors. |

**Unknown or malformed `action` values are a fatal startup error** (not a runtime 503).

---

#### `affinity`

Pin a session to one pool member while that member remains healthy. Useful to keep provider-side prompt caches warm or to maintain conversational state.

```yaml
pools:
  smart:
    members:
      - target: claude-sonnet-4-5
      - target: gpt-4o
    affinity:
      mode: session
      header_name: x-session-id
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `mode` | string | `session` | `session` is the only supported value. Any other value is a startup error. |
| `header_name` | string | `x-session-id` | Request header whose value identifies the session. |

Affinity is a **preference, not a hard pin**. If the sticky member is tripped, dead, or at capacity, Busbar falls back to normal SWRR selection without failing the request.

---

#### Context-length failover

Declare each member's `context_max` so an oversized request fails over to a larger-context member instead of returning an error: and without penalizing the smaller lane, since a context-length overflow is not an upstream fault.

```yaml
pools:
  long-context:
    members:
      - target: claude-sonnet-4-5
        context_max: 200000
      - target: gemini-1.5-pro
        context_max: 1000000
```

When a member returns a context-length error, busbar:
1. Excludes from the **current request** any candidate whose known `context_max` is ≤ the failed lane's.
2. Fails over to a member with a larger (or unknown) `context_max`.
3. Records no breaker penalty against the smaller lane.

Members without `context_max` set are always eligible for context-length failover (their capacity is unknown; Busbar treats unknown as potentially unlimited).

---

### `limits`

Optional. Exposes ten operational limits — mostly previously hardcoded, plus `max_inbound_concurrent` and `pool_idle_timeout_secs` — so operators can tune them without rebuilding. All fields default to their historical values, so omitting this block is a no-op.

```yaml
limits:
  max_inbound_concurrent: 8192    # 0 = unlimited; > 0 adds a global concurrency cap
  request_body_max_bytes: 33554432  # 32 MiB
  upstream_request_timeout_secs: 300
  tls_handshake_timeout_secs: 10
  pool_max_idle_per_host: 64
  pool_idle_timeout_secs: 300     # 5 min
  hard_down_cooldown_secs: 1800   # 30 min
  upstream_error_body_max_bytes: 262144  # 256 KiB
  max_honored_retry_after_secs: 86400 # 24 h
  default_max_tokens: 4096
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `max_inbound_concurrent` | integer | `8192` | Global inbound concurrency cap, applied outermost (before request bodies are buffered), so it is the global bound on peak request memory: worst case is this limit times `request_body_max_bytes`. `0` = unlimited (no cap layer installed, the pre-1.5.0 posture). |
| `request_body_max_bytes` | integer | `33554432` | Maximum inbound request body size (bytes). Exceeding this returns a protocol-native 413. |
| `upstream_request_timeout_secs` | integer | `300` | Per-upstream-request wall-clock timeout. Applies to both the connect and the full response. |
| `tls_handshake_timeout_secs` | integer | `10` | Wall-clock cap on each inbound TLS handshake; prevents slowloris / handshake-flood. Ignored when `tls:` is absent. |
| `pool_max_idle_per_host` | integer | `64` | HTTP connection pool idle connection limit per upstream host. |
| `pool_idle_timeout_secs` | integer | `300` | How long an idle keep-alive connection stays in the upstream pool before being closed. The 300s default keeps the warm working set alive across inter-burst gaps (TCP keepalive validates idle sockets in the meantime); lower it to shed idle sockets sooner. |
| `hard_down_cooldown_secs` | integer | `1800` | Sticky cooldown for `auth`/`billing` breaker dispositions (hard-down). Recovering these lanes requires a successful health probe. |
| `upstream_error_body_max_bytes` | integer | `262144` | Maximum bytes buffered from a non-2xx upstream response body for error classification. |
| `max_honored_retry_after_secs` | integer | `86400` | Maximum value honored from an upstream `Retry-After` header (to prevent overflow). |
| `default_max_tokens` | integer | `4096` | Gateway-wide default injected on cross-protocol hops to Anthropic when the caller omitted `max_tokens`. Overridden by a per-model `default_max_tokens` when set. |

---

### `observability`

All sinks are opt-in. Prometheus `/metrics` is always on and needs no config entry. It is auth-gated (same rules as `/stats`) and is not an unauthenticated endpoint.

```yaml
observability:
  otlp_endpoint: "http://localhost:4318/v1/traces"
  request_log_webhook_url: "https://logs.example.com/busbar"
  emit_server_timing: true
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `otlp_endpoint` | string | none | When set, installs an OTLP/HTTP trace exporter. Loopback `http://` is allowed (standard collector default). Remote endpoints must use `https://`. SSRF-guarded: rejects RFC-1918, link-local, CGNAT, metadata hosts. Traces are flushed on graceful shutdown. |
| `request_log_webhook_url` | string | none | When set, fires a fire-and-forget JSON POST per completed request: `{ts, ingress_protocol, pool, outcome, latency_ms}`. Must be `https://`. SSRF-guarded (same classes as `otlp_endpoint` plus broadcast). At most 64 deliveries in flight; drops rather than queues. 2-second delivery timeout. |
| `emit_server_timing` | bool | `false` | Controls whether the `Server-Timing: busbar;dur=<ms>` response header is emitted on every response. Defaults to `false`, the header is an in-band busbar fingerprint, so it is suppressed by default for backend indistinguishability. Set to `true` to enable it as a latency probe. |

**OTLP credential hygiene.** If your OTLP endpoint requires auth, supply credentials in the URL userinfo (`https://user:pass@collector.example.com/…`): Busbar moves them to an `Authorization: Basic` header and strips them from the URL before logging, so they do not appear in logs or spans.

---

### `governance`

The virtual-key governance layer. **Governance is always available but INERT by default**: it enforces nothing until you set `governance.admin_token` (and mint keys via the admin API). This section only *configures* it; it has no `enabled` switch.

- **Inert (default, no `admin_token`):** governance enforces nothing. Requests are gated by the static [`auth`](#auth) chain (`[tokens]` or open relay) **exactly as if governance were absent**. A default deploy behaves the same as before governance was on-by-default. The `/api/v1/admin` key-management API is disabled (no token to guard it), so no virtual keys can be minted.
- **Active (`admin_token` set):** enforcement turns on. Static `auth` tokens are superseded and **every inference request must resolve to an enabled busbar-issued virtual key**. Per-key controls apply: allowed pools (ACL), budget (cents), budget period, and rate limits (RPM/TPM). The admin API (guarded by the admin token) is what mints those keys.

The store defaults to **in-memory (ephemeral RAM)**: zero setup, but keys/budgets/usage reset on restart. Choose a durable `store` (`sqlite`, `postgres`, `redis`, each a loadable plugin) for persistence.

> **Durable-store caveat.** If you point governance at a durable store that already holds virtual keys from a prior run but then run with **no `admin_token`**, governance is inert and those persisted keys are **NOT enforced** (their budget / RPM / TPM / allowed_pools are bypassed and access falls through to the static `auth.chain`). Busbar detects this at boot and emits a **loud error** (`durable governance store contains N key(s) but no admin_token is set … set governance.admin_token to enforce them`) on stderr and at ERROR level. Set `governance.admin_token` to re-activate enforcement.

```yaml
governance:
  # store: memory        # default — ephemeral RAM; omit for the default
  admin_token: "${BUSBAR_ADMIN_TOKEN}"   # set this to ACTIVATE enforcement
  price_per_request_cents: 1
  price_per_1k_tokens_cents: 50
  # For persistence, choose a durable store (a loadable plugin dropped in plugins_dir):
  # store: sqlite                            # single-node durable
  # db_path: /var/lib/busbar/governance.db
  # store: postgres                          # shared across a cluster
  # db_path: "postgres://user:pass@host/busbar"
  # store: redis                             # shared across a cluster
  # db_path: "redis://host:6379"
  # plugins_dir: plugins                     # where store plugins are loaded from (default: plugins)
  # usage_flush_interval_ms: 100             # write-behind flush cadence for durable stores
  # trust:                                   # plugin signing policy (see "Plugin trust" below)
  #   on_untrusted: log                      # halt | alert | log (default) | allow
```

| Field | Type | Required | Default | Validation | Notes |
|---|---|---|---|---|---|
| `store` | string | no | `memory` | one of `memory` \| `sqlite` \| `postgres` \| `redis` | Backend for keys + counters. `memory` (default) is ephemeral RAM (resets on restart). `sqlite`/`postgres`/`redis` are durable, each loaded as a plugin from `plugins_dir`. |
| `admin_token` | string | no | none (governance INERT, admin API disabled) | Must be non-empty (non-whitespace) when present | The activation gate. Absent = governance inert (static `auth` chain applies, no admin API). Present = enforcement on; guards the `/api/v1/admin/keys` API. A blank/whitespace-only value is a startup error. |
| `db_path` | string | no | `busbar-governance.db` | n/a | Connection target for a durable store: a SQLite file path (`store: sqlite`), or a libpq/redis URL (`store: postgres` / `redis`). Unused for `store: memory`. |
| `price_per_request_cents` | integer | no | `1` | Negative values clamped to 0 | Flat per-request charge against each virtual key's budget (in cents). |
| `price_per_1k_tokens_cents` | integer | no | `0` | Negative values clamped to 0 | Per-1,000-token charge (input + output tokens from response usage metadata). |
| `plugins_dir` | string | no | `plugins` | n/a | Directory the engine loads store (and other) plugins from. A durable `store` other than `memory` is a plugin library dropped here (e.g. `store: sqlite` loads `libbusbar_store_sqlite_plugin` from this directory). Path is relative to the working directory. |
| `trust` | table | no | see below | n/a | Plugin signing/trust policy applied to each plugin's signed manifest at load. Sub-keys: `on_untrusted` (`halt` \| `alert` \| `log` (default) \| `allow`) and `publishers` (a list of `{ name, public_key }` allowlisted ed25519 publishers). See [Plugin trust](#plugin-trust) below. |
| `sqlite_busy_timeout_ms` | integer | no | `5000` | n/a | SQLite `busy_timeout` (milliseconds) for the governance store under write contention. Applies to `store: sqlite`. |
| `rate_sweep_interval` | integer | no | `256` | Must be ≥ 1 | How often (every N admissions) the in-memory rate-limit map evicts idle entries. Correctness does not depend on it (per-key windows reset on lookup); it only bounds memory. `0` is rejected at startup. |
| `usage_flush_interval_ms` | integer | no | `100` | n/a | Write-behind flush cadence (milliseconds) for the in-memory governance usage/budget counters. On an ungraceful crash (`kill -9` / power loss) at most this many ms of accrued spend/requests can be lost; a graceful shutdown flushes fully. Only relevant with a durable `store`. |

**Budget spend per request:** `price_per_request_cents + (total_tokens / 1000) * price_per_1k_tokens_cents`.

**Enforcement semantics (important for operators):**
- **RPM is precise.** The per-minute counter is incremented synchronously on admission.
- **TPM is best-effort.** Token counts are fed post-response; concurrent in-flight requests are not pre-charged. The first request of each rate window is always admitted.
- **Budget admission is a hard, atomic cap.** The budget check and the flat per-request charge are one atomic conditional UPSERT (`charge_within_budget`): a request whose fee would push the window's spend past `max_budget_cents` is rejected before it is forwarded, and a concurrent burst cannot race past the limit. The **token-priced component** (`price_per_1k_tokens_cents`) is accrued post-response, so spend from requests already in flight when the cap is neared can land after admission; that overshoot is bounded by in-flight parallelism. A request admitted and then failing upstream (non-2xx) has its flat fee refunded. Admission is an in-memory operation and never touches the durable store, so the cap holds even if the store is unreachable; durability is a write-behind concern (flushed every `usage_flush_interval_ms`), not an admission-path one.

**Incompatible combination:** an active governance engine (`admin_token` set) + `auth.upstream_credentials: passthrough` is a startup error. Active governance supersedes passthrough (every request must resolve to a virtual key); the combination is unsupported. (With no `admin_token`, governance is inert and the pairing carries no requirement.)

**Virtual key format:** `sk-bb-<32 hex characters>` (128-bit CSPRNG). Shown in plaintext exactly once at mint; stored as SHA-256 hash only. Key IDs have the form `vk_<16 hex characters>`.

**Admin API routes** (guarded by the admin token, not a virtual key):

| Route | Method | Description |
|---|---|---|
| `/api/v1/admin/keys` | `POST` | Mint a new virtual key. Returns plaintext bearer `secret` once. Pass `"issue_aws_credential": true` to also receive `aws_access_key_id` + `aws_secret_access_key` for Bedrock-SDK clients (both shown once). |
| `/api/v1/admin/keys` | `GET` | List all keys (metadata only; no secrets). |
| `/api/v1/admin/keys/{id}` | `PATCH` | Update key fields. Three-state semantics: absent = unchanged, `null` = clear to unlimited, value = set. |
| `/api/v1/admin/keys/{id}/usage` | `GET` | Current-window spend, tokens, and request count. |
| `/api/v1/admin/keys/{id}` | `DELETE` | Revoke a key. Returns 404 if not found (not idempotent). |

See [operations.md](operations.md) for the full admin API payload schemas and virtual key fields, including the `issue_aws_credential` Bedrock SigV4 option.

#### Durable stores

The default `store: memory` is ephemeral RAM (keys, budgets, and usage reset on restart) and needs no plugin. Every durable backend ships as a droppable dynamic-library plugin that busbar loads at boot from `plugins_dir` over a stable store C ABI:

| `store` | Plugin library | `db_path` target |
|---|---|---|
| `sqlite` | `libbusbar_store_sqlite_plugin.{so,dll,dylib}` | SQLite file path (default `busbar-governance.db`); single-node durable. |
| `postgres` | `libbusbar_store_postgres_plugin.{so,dll,dylib}` | `postgres://` libpq URL; shared across a cluster. |
| `redis` | `libbusbar_store_redis_plugin.{so,dll,dylib}` | `redis://` URL; shared across a cluster. |

If the configured store's plugin is not present in `plugins_dir`, busbar fails to start with a message naming the expected library file. Set `store: memory` (no plugin) to run without a durable backend.

#### Plugin trust

A plugin ships a signed sidecar manifest (`<library>.manifest.json`: name, version, kind, author/homepage/source_url, publisher, the library `sha256`, and an ed25519 signature over the whole manifest). At boot-load busbar verifies it against `governance.trust`. A valid signature from an allowlisted publisher (`trust.publishers`) is TRUSTED; anything else (unsigned, unknown publisher, or tampered) is handled per `trust.on_untrusted`:

| `on_untrusted` | Behavior |
|---|---|
| `halt` | Only approved (signed by an allowlisted publisher) plugins load; an untrusted plugin is a boot error. |
| `alert` | Loads the untrusted plugin but flags it. |
| `log` (default) | Loads the untrusted plugin with a warning. Keeps unsigned plugins working out of the box. |
| `allow` | Loads without flagging (development). |

```yaml
governance:
  store: sqlite
  trust:
    on_untrusted: halt
    publishers:
      - name: busbar
        public_key: "<hex ed25519 public key>"
```

Because the signature covers the whole manifest and the manifest pins the library by `sha256`, neither the manifest nor the library can be altered or swapped independently. A malformed publisher key is a boot error, not a silent skip.

---

### `security`

Optional. Extends or overrides the hardcoded cloud-metadata SSRF denylist. When absent, only the built-in denylist applies. See [Security: Provider upstreams & SSRF](https://getbusbar.com/docs/security/) for the full threat model, the complete denylist, and worked examples.

```yaml
security:
  blocked_metadata_hosts:
    - "169.254.100.1"
  allow_metadata_hosts:
    - "metadata.google.internal"
  allow_all_metadata: false   # default; set true only for dev, logs a startup WARNING
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `blocked_metadata_hosts` | list<string> | `[]` | Additional hosts/IPs appended to the hardcoded denylist. Entries may be IP literals or DNS hostnames. Matched with the same obfuscation-aware canonicalization as the built-in list. |
| `allow_metadata_hosts` | list<string> | `[]` | Hosts/IPs to **unblock globally**: removed from the effective denylist for all providers. Use per-provider `allow_metadata_hosts` for a narrower exception. |
| `allow_all_metadata` | bool | `false` | Disables the SSRF guard entirely. Every cloud-metadata endpoint becomes reachable by every provider. **Logs a startup WARNING.** Development use only. |

**Precedence:** a host is blocked iff it is in the denylist (hardcoded union `blocked_metadata_hosts`) **and not** in any allow-override (`security.allow_metadata_hosts` union that provider's `allow_metadata_hosts`) **and not** `allow_all_metadata`. Allow always wins.

---

## Minimal working example

The smallest config that parses and resolves. `providers` and `models` are the only required top-level sections.

**`config.yaml`:**

```yaml
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY

models:
  claude:
    provider: anthropic
    max_concurrent: 10
```

**Required environment variable:** `ANTHROPIC_KEY` must be set.

**Routes available:**
- `POST /claude/v1/messages`: Anthropic ingress, directly to the `claude` model.
- `GET /healthz`, readiness check.
- `GET /metrics`, Prometheus (admitted unconditionally under `chain: []`).

`listen` defaults to `0.0.0.0:8080`. No auth gate. No pools.

---

## Full annotated example

This example requires: `BUSBAR_CLIENT_TOKEN`, `BUSBAR_ADMIN_TOKEN`, `ANTHROPIC_KEY`, `OPENAI_KEY`, `GEMINI_KEY`.

```yaml
listen: "0.0.0.0:8080"

# ---------------------------------------------------------------------------
# Auth: clients send Authorization: Bearer <BUSBAR_CLIENT_TOKEN>
# Governance is ACTIVATED below (admin_token is set), so this static chain
# becomes vestigial — governance virtual keys supersede static tokens once an
# admin_token is set. With no admin_token, this chain is what gates requests.
# ---------------------------------------------------------------------------
auth:
  chain: [tokens]
  client_tokens:
    - "${BUSBAR_CLIENT_TOKEN}"

# ---------------------------------------------------------------------------
# Providers: declare which catalog providers this deployment uses.
# api_key_env names the env var holding each provider's credential.
# ---------------------------------------------------------------------------
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
    health:
      mode: dead           # re-probe only tripped lanes, every 30s
      interval_secs: 30
      timeout_secs: 5

  openai:
    api_key_env: OPENAI_KEY

  gemini:
    api_key_env: GEMINI_KEY

# ---------------------------------------------------------------------------
# Models: one lane per model. Each lane has its own semaphore and breaker.
# ---------------------------------------------------------------------------
models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    max_requests: -1          # unlimited lifetime budget
    default_max_tokens: 4096  # injected on cross-protocol hops to Anthropic only

  gpt-4o:
    provider: openai
    max_concurrent: 20

  gemini-1.5-pro:
    provider: gemini
    max_concurrent: 15

  gpt-4o-mini:
    provider: openai
    max_concurrent: 30        # high capacity overflow lane

# ---------------------------------------------------------------------------
# Pools: named groups of weighted lanes with failover and breaker config.
# context_max is a per-member field (here used for context-length failover).
# ---------------------------------------------------------------------------
pools:
  # Primary pool, weighted SWRR with session affinity and a tight breaker.
  smart:
    members:
      - target: claude-sonnet
        weight: 2
        context_max: 200000
      - target: gpt-4o
        weight: 2
        context_max: 128000
      - target: gemini-1.5-pro
        weight: 1
        context_max: 1000000

    affinity:
      mode: session
      header_name: x-session-id

    breaker:
      trip:
        mode: consecutive     # trip fast on a short streak
        consecutive_n: 2
      base_cooldown_secs: 5
      max_cooldown_secs: 60

    failover:
      timeout_secs: 30        # total wall-clock budget across all hops
      max_hops: 3             # at most 3 failover attempts

    on_exhausted:
      action: fallback_pool:overflow

  # Overflow pool, used when every smart member is tripped.
  overflow:
    members:
      - target: claude-sonnet
        weight: 3
      - target: gpt-4o-mini
        weight: 1
    on_exhausted:
      action: least_bad       # serve degraded rather than hard 503

  # Cost-optimized pool, cheapest available member first.
  # cost_per_mtok on each member drives the cheapest ordering strategy.
  batch:
    hooks: [cheapest]
    members:
      - target: gpt-4o-mini
        weight: 1
        cost_per_mtok: 0.15
        tags: ["cheap"]
      - target: claude-sonnet
        weight: 1
        cost_per_mtok: 3.0
    failover:
      timeout_secs: 120
      max_hops: 3
    on_exhausted:
      action: reject

# ---------------------------------------------------------------------------
# Observability: traces and per-request webhook logging.
# /metrics is always on (no config needed).
# ---------------------------------------------------------------------------
observability:
  otlp_endpoint: "http://localhost:4318/v1/traces"
  request_log_webhook_url: "https://logs.example.com/busbar"
  emit_server_timing: true

# ---------------------------------------------------------------------------
# Governance: virtual keys, budgets, rate limits.
# Setting admin_token ACTIVATES enforcement (every request must resolve to a
# virtual key). With no admin_token, governance is inert and the static auth
# chain above applies. Note: upstream_credentials: passthrough is incompatible
# with an ACTIVE governance engine (admin_token set).
# ---------------------------------------------------------------------------
governance:
  store: sqlite                            # durable (a loadable plugin); omit for the RAM default
  db_path: /var/lib/busbar/governance.db
  admin_token: "${BUSBAR_ADMIN_TOKEN}"     # set this to turn enforcement ON
  price_per_request_cents: 1
  price_per_1k_tokens_cents: 50
```

---

## Startup validation summary

Busbar validates the merged config before accepting any traffic. Fatal errors abort startup; warnings are logged and startup continues.

**Errors (fatal):**

| Rule | Condition |
|---|---|
| Provider name reserved | Any provider named `admin` or beginning with `admin/` |
| Protocol unknown | `protocol` not in `{anthropic, openai, gemini, bedrock, responses, cohere}` |
| `base_url` SSRF | `base_url` resolves to a cloud-metadata/IMDS host (e.g. `169.254.169.254`, `100.100.100.200`, `metadata.google.internal`) or uses an alternate IP encoding (decimal-int, hex, octal, IPv4-mapped IPv6) that decodes to a metadata address |
| `base_url` plaintext | `base_url` uses `http://` with a public (non-private, non-loopback) host: plain HTTP to a public host would expose the API key on the wire |
| `error_map` value unknown | A value in `error_map` is not one of the nine canonical disposition classes |
| `auth` value unknown | `auth` field value not `bearer`, `api-key`, `jwt-bearer`, or `oauth-client-credentials` |
| `affinity.mode` value unknown | `affinity.mode` not `session` (the only supported value) |
| Removed `token` field set | The 1.0.0-removed `auth.token` field is present, rejected at parse as an unknown field (`unknown field \`token\``); move its value into `client_tokens` |
| `path` malformed | `path` does not begin with `/` |
| Model name reserved | Model named `admin` |
| `provider` reference missing | `models.<name>.provider` does not name a configured provider |
| `max_concurrent: 0` | A concurrency semaphore of 0 never grants a permit (omit the field for unbounded; `0` is the only rejected value) |
| `max_requests: 0` | Zero lifetime budget = permanently unusable lane |
| `default_max_tokens: 0` | Would be injected upstream and rejected |
| Pool name reserved | Pool named `admin` |
| Pool name collision | Pool name matches a provider or model name |
| Empty `members` | A pool with no members is un-routable |
| `weight: 0` | Pool member weight of 0 is invalid |
| `target` reference missing | Pool member `target` does not name a configured model |
| `failover.timeout_secs: 0` | Zero failover deadline |
| `failover.exclusions` dangling | An exclusion names a model not in the pool |
| Fallback pool cycle | `on_exhausted: fallback_pool:<X>` where following the chain creates a cycle |
| Fallback pool self-reference | `on_exhausted: fallback_pool:<self>` |
| Fallback pool unknown | `on_exhausted: fallback_pool:<name>` where `name` is not a configured pool |
| `on_exhausted` malformed | Unrecognized `action` string |
| `affinity.mode` unknown | Any value other than `session` |
| Pool `hooks:` names more than one ordering strategy | A pool has one base ordering |
| Pool `hooks:` gate name not in the registry | Every non-strategy name must reference a top-level `hooks:` entry |
| Pool `hooks:` names a tap | Only a gate (fire-and-wait) can influence routing |
| Hook with neither/both of `socket` and `webhook` | Exactly one transport per hook |
| Hook `webhook` SSRF-blocked | RFC-1918, CGNAT, link-local, and metadata hosts are blocked (loopback allowed) |
| `prompt: rw` on a `kind: tap` hook | A tap observes; it can never rewrite |
| More than one hook with `default: true` | At most one default base ordering (error names both hooks) |
| Hook named after a built-in | Registry names must not shadow the compiled-in plugin names |
| `route:` / `policy:` / `hook:` pool keys | Removed/retired keys; each parse error names the `hooks: [...]` fix |
| Breaker `max_cooldown < base_cooldown` | Cooldown ceiling below the base |
| `tokens` in `auth.chain` + empty `client_tokens` | Every request would be rejected |
| `auth.chain` names an unknown module | Every chain entry must be a compiled-in auth module |
| `auth.mode` present | Removed in 1.3. Write `chain:` + `upstream_credentials:` |
| `governance.admin_token` set but blank/whitespace-only | Admin API would be silently inaccessible (an unset token is fine: governance is simply inert) |
| `governance.admin_token` set + `upstream_credentials: passthrough` | Unsupported combination (active governance supersedes passthrough) |
| `${VAR}` unset in config | Unresolvable interpolation reference |
| `${}` or unclosed `${` | Malformed interpolation syntax |

**Warnings (non-fatal):**

| Condition |
|---|
| `chain: []` (open front door) with non-empty `client_tokens` (allowlist has no effect) |
| `upstream_credentials: passthrough` with a provider whose API key env var is non-empty (credential-leak risk) |
| Heterogeneous pool (members span more than one backend protocol, cross-protocol translation applies) |
| `api_key_env` names an env var that is unset or empty at boot (lane will fail auth) |
| `allowed_pools` on a virtual key (admin API) names a pool not currently configured |
| `chain: [tokens]` or `chain: []` with governance ACTIVE (`admin_token` set): static auth is superseded; effective mode is governance virtual keys |
| Durable governance store holding keys with no `admin_token` set: governance is inert; those persisted keys are NOT enforced (boot emits a loud error) |
