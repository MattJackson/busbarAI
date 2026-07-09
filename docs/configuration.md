# Configuration reference

Busbar reads **two YAML files** at startup:

| File | Default path | Env override | Purpose |
|---|---|---|---|
| Provider catalog | `/etc/busbar/providers.yaml` | `BUSBAR_PROVIDERS` | Shipped map of provider names → protocol, base URL, error map. Operators rarely edit this. |
| Deployment config | `/etc/busbar/config.yaml` | `BUSBAR_CONFIG` | Your site's providers (with API key env vars), models, pools, auth, observability, and governance. |

Both files support `${VAR}` environment interpolation before YAML is parsed. A missing or malformed env var reference is a fatal startup error, Busbar refuses to boot rather than run with an incomplete config.

> All defaults below are sourced from `src/config.rs`, `src/breaker.rs`, `src/health.rs`, and `src/proto/mod.rs`. Where a serde field default differs from a runtime constant, both are noted.

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
    - [`route` and `policy`](#route-and-policy)
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

A map of provider name → `ProviderDef`. The shipped catalog is a curated set of vetted providers across the six supported protocols. You can add an entry for any OpenAI-compatible endpoint not already in the catalog.

### Catalog fields

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `protocol` | string | no | `anthropic` | One of the six supported wire protocols: `anthropic`, `openai`, `gemini`, `bedrock`, `responses`, `cohere`. An unknown protocol is a startup error. |
| `base_url` | string | **yes** | n/a | Scheme + host (+ optional path prefix). Must start with `https://` for external endpoints. An `http://` URL in the catalog is not blocked at parse time but will be rejected by the SSRF guard on deployment use. Trailing slash is trimmed. |
| `error_map` | map<string, string> | no | `{}` | Maps a provider-specific error **code string** (from the JSON error body) to a canonical disposition class. Valid values: `rate_limit`, `overloaded`, `server_error`, `timeout`, `network`, `auth`, `billing`, `client_error`, `context_length`. An unrecognized class value is a startup error. HTTP-status classification (401→auth, 429→rate_limit, 5xx→server_error, etc.) applies automatically without an `error_map`; this field is only for provider-specific JSON codes. |
| `path` | string | no | Protocol's standard path | Overrides the upstream request path appended to `base_url`. Must begin with `/`. Use when the API version is in `base_url` and the endpoint path differs from the protocol default (e.g. `/chat/completions` without `/v1`). |
| `auth` | string | no | Protocol's native auth | `bearer` (sends `Authorization: Bearer <key>`) or `api-key` (sends `api-key: <key>`, for Azure OpenAI). When unset, each protocol uses its native scheme: bearer for anthropic/openai/responses/cohere, `x-goog-api-key` for gemini, AWS SigV4 for bedrock. Setting `auth: api-key` forces the `api-key:` header regardless of protocol (rarely useful outside Azure OpenAI). |
| `health` | object | no | none | Active health-probe config. See [Health probing](#health-probing). |

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

In `config.yaml`, a provider entry may selectively override the catalog's `protocol`, `base_url`, `error_map` (merged: deployment entries win per code), `path`, `auth`, and `health`. The only always-required field in the deployment entry is `api_key_env`.

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

Front-door authentication for clients. When [governance](#governance) is enabled, governance virtual keys supersede static `auth` entirely, every request must carry a valid virtual key.

```yaml
auth:
  mode: token
  client_tokens:
    - "${BUSBAR_CLIENT_TOKEN}"
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `mode` | string | no | `none` | `token`, `passthrough`, or `none` (case-insensitive). An unknown value is a startup error. |
| `client_tokens` | list<string> | no | `[]` | Allowed bearer tokens (env-interpolated). Required to be non-empty when `mode: token`. All comparisons are constant-time (no timing oracle). |
| `token` | string | no | n/a | **Removed in 1.0.0.** The `auth` block now rejects unknown keys, so setting `token:` is a hard parse error (`unknown field \`token\``): the gateway refuses to boot. Move its value into the `client_tokens` allowlist instead. |

**Token extraction order (for `token` and `passthrough` modes):** `Authorization: Bearer`, then `x-api-key`, then `x-goog-api-key`. Blank values are treated as absent.

**Mode semantics:**

- **`token`**: the client must send `Authorization: Bearer <token>` matching an entry in `client_tokens`. Every route except `/healthz` requires a valid token (including `/stats` and `/metrics`, which are information-disclosure surfaces).
- **`passthrough`**: the caller's own token is forwarded to the upstream provider. Busbar holds no keys in this mode. An upstream 401/403 response is attributed to the caller; the breaker's `auth`/`billing` disposition fires, which hard-downs the lane for 30 minutes: so callers with bad keys will suppress that lane for everyone for 30 minutes. Use with care.
- **`none`**: open relay, no client authentication. `/metrics` and `/stats` are admitted unconditionally. Development only; Busbar logs a loud warning at startup.

**Startup validation:**
- `mode: token` + empty effective `client_tokens` → startup error (every request would be rejected).
- `mode: none` + non-empty `client_tokens` → startup warning (the list has no effect).
- `mode: passthrough` + a provider whose `api_key_env` resolves to a non-empty value → startup warning (credential-leak risk: an unauthenticated caller's request will carry Busbar's own key to the upstream).

**Bedrock ingress.** Native Bedrock SDK clients authenticate with AWS SigV4 (`Authorization: AWS4-HMAC-SHA256 …`). There are two tracks:

- **Without governance** (`mode: passthrough` or `none`): Busbar does not verify the inbound SigV4 signature. The header is forwarded upstream (passthrough) or ignored entirely (none). Use this for transparent Bedrock proxying without per-key controls.
- **With governance** (`mode: token` + `governance.enabled: true`): Busbar verifies the inbound SigV4 signature natively (`src/auth.rs` `verify_bedrock_sigv4`, including body-hash integrity). Mint a key with `"issue_aws_credential": true`; the response includes `aws_access_key_id` + `aws_secret_access_key` (shown once). The Bedrock SDK authenticates with that pair; Busbar verifies the signature, then applies the key's budget / RPM / TPM / allowed-pools. No `passthrough` required.

All other five ingress protocols use bearer-style auth and work in every mode.

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
| `auth` | string | no | Catalog value | `bearer` or `api-key`. |
| `health` | object | no | Catalog value | Override the catalog's health probe config. |
| `allow_metadata_hosts` | list<string> | no | `[]` | Per-provider surgical exception: hosts/IPs to unblock from the cloud-metadata SSRF denylist for **this provider only**. See [Security: Provider upstreams & SSRF](/security/#the-control-matrix). |

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
| `max_concurrent` | integer | **yes** | n/a | Maximum simultaneous in-flight requests for this lane (semaphore size). Must be ≥ 1. |
| `max_requests` | integer | no | `-1` | Lifetime request budget. `-1` = unlimited. When the counter reaches `0` the lane is unusable. Must not be `0` (zero budget = permanently unusable = startup error). |
| `default_max_tokens` | integer | no | `4096` | Injected **only** on a cross-protocol hop to a backend that requires `max_tokens` (Anthropic protocol) when the caller omitted it. Has no effect on same-protocol passthrough. Must be > 0 when set. |
| `upstream_model` | string | no | the config key | The model id sent to the provider on the wire (request body for body-model protocols; URL path for path-model protocols like Bedrock/Gemini; and health probes). Defaults to the config key. Set it when the key can't be the wire id: most commonly to run the **same model behind two providers** (the keys must differ, but each needs its own provider-specific model string). Must be non-empty when set. Metrics, breaker cells, and logs still key off the config key, not this. |

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
| `tier` | string | no | none | Operator-declared routing tier label (e.g. `"primary"`, `"overflow"`, `"large"`, `"small"`). Inert for `route: weighted` pools. Exposed to webhook and script policies as the `tier` field on each candidate. See [`route` and `policy`](#route-and-policy). |
| `cost_per_mtok` | float | no | none | Operator-declared cost in currency units per million tokens. Drives the `cheapest` native policy (sort ascending) and is exposed to webhook/script policies. Inert when unset or when `route: weighted`. |
| `tags` | list<string> | no | `[]` | Free-form string labels (e.g. `["opus", "large-context"]`). Inert for `route: weighted` pools. Exposed to webhook/script policies for tag-based candidate selection. |

Selection uses Nginx-style smooth weighted round-robin (SWRR) across the healthy subset. A tripped, dead, or capacity-exhausted member is skipped and its share redistributes to the remaining members automatically. Selection state is isolated per-pool (separate SWRR shard), so unrelated pools that share a lane select independently.

**Empty `members` list is a startup error.**

A pool spanning members that use different underlying protocols produces a startup **warning** (not an error). Cross-protocol requests are translated via the IR (intermediate representation), which is lossless for all standard fields. Source-only fields (e.g. OpenAI `logprobs`, `n`) are dropped before reaching a foreign backend.

---

#### `route` and `policy`

A pool's routing policy decides the **order** in which healthy members are tried. The default: `weighted` (SWRR), is zero-cost and unchanged from the pre-routing-policy baseline. Any other `route` value wires a pluggable policy that runs once per request, before the failover loop. The full guide, including external policies and signals, lives in the [routing guide](https://getbusbar.com/routing/).

```yaml
pools:
  smart:
    route: native
    policy:
      name: cheapest
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

**Pool-level fields:**

| Field | Type | Default | Notes |
|---|---|---|---|
| `route` | string (enum) | `weighted` | Routing transport. One of `weighted`, `native`, `webhook`, `script`. `weighted` (default/absent) is zero-cost SWRR: no policy object is constructed and behavior is byte-identical to the baseline. Any other value runs a pluggable policy once per request before the failover loop. |
| `policy` | object | none | Transport configuration. Only `webhook` is validated at boot (a missing or SSRF-blocked `policy.url` is a startup error); a misconfigured `native` or `script` policy is not fatal, it degrades to weighted SWRR. Parsed but inert when `route: weighted`. |

**`route` enum values:**

| Value | Description |
|---|---|
| `weighted` | **Default.** Smooth weighted round-robin (SWRR) over healthy members. Zero added overhead: the existing SWRR hot path, unchanged. |
| `native` | A Busbar-built policy selected by `policy.name`. Sync, no I/O, no external deps. |
| `webhook` | An operator HTTP sidecar. Busbar POSTs a request projection and waits for a ranked preference list, bounded by `policy.timeout_ms`. |
| `script` | An embedded Rhai script (behind the `script-policy` cargo feature). Compiled at startup; evaluated per request in a sandboxed thread pool. |

`route:` also accepts the bare native policy names `cheapest`, `fastest`, `least_busy`, and `usage` as shorthand for `route: native` + `policy.name: <name>`. See the [Routing guide](/routing/) for what each policy does.

**`policy` block fields:**

| Field | Type | Default | Transport | Description |
|---|---|---|---|---|
| `name` | string | none | `native` | Native policy name. Required when `route: native`. Valid values: `weighted`, `cheapest`, `fastest`, `least_busy`, `usage`. An unknown value is a startup error. |
| `url` | string | none | `webhook` | Operator sidecar URL. Required when `route: webhook`. Validated by the routing SSRF guard: loopback (`127.0.0.1`, `localhost`) is allowed; RFC-1918, link-local, CGNAT (100.64/10), and cloud metadata hosts are blocked. Plain `http://` is allowed for loopback; remote endpoints must use `https://`. |
| `timeout_ms` | integer | `150` | `webhook`, `script` | Hard wall-clock deadline for the policy decision in milliseconds. On timeout the decision is coerced to `on_error`. |
| `on_error` | string (enum) | `weighted` | `webhook`, `script` | Fallback when the policy times out, errors, abstains, or its in-flight queue is saturated. `weighted` (SWRR), `reject` (503), or `first` (first member in config order). |
| `script` | string | none | `script` | Inline Rhai source string. Exactly one of `script` or `script_file` is required when `route: script`. Mutually exclusive with `script_file`. |
| `script_file` | string | none | `script` | Path to a Rhai script file on disk. Alternative to inline `script`. |

The per-member `tier`, `cost_per_mtok`, and `tags` fields documented in [Members and weights](#members-and-weights) above feed these policies. See the [routing guide](https://getbusbar.com/routing/) for the native policy catalog, the webhook wire format, the Rhai script environment and sandbox limits, and the `x-busbar-route-policy` / `x-busbar-route-target` observability headers.

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

| `action` value | Behavior |
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

Optional. Exposes nine operational limits: eight previously hardcoded, plus the new `max_inbound_concurrent`, so operators can tune them without rebuilding. All fields default to their historical values, so omitting this block is a no-op.

```yaml
limits:
  max_inbound_concurrent: 0       # 0 = unlimited; > 0 adds a global concurrency cap
  request_body_max_bytes: 33554432  # 32 MiB
  upstream_request_timeout_secs: 300
  tls_handshake_timeout_secs: 10
  pool_max_idle_per_host: 64
  hard_down_cooldown_secs: 1800   # 30 min
  upstream_error_body_max_bytes: 262144  # 256 KiB
  max_honored_retry_after_secs: 86400 # 24 h
  default_max_tokens: 4096
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `max_inbound_concurrent` | integer | `0` | Global inbound concurrency cap. `0` = unlimited (no cap layer installed). Any positive value installs an outermost concurrency-limit middleware before routing. |
| `request_body_max_bytes` | integer | `33554432` | Maximum inbound request body size (bytes). Exceeding this returns a protocol-native 413. |
| `upstream_request_timeout_secs` | integer | `300` | Per-upstream-request wall-clock timeout. Applies to both the connect and the full response. |
| `tls_handshake_timeout_secs` | integer | `10` | Wall-clock cap on each inbound TLS handshake; prevents slowloris / handshake-flood. Ignored when `tls:` is absent. |
| `pool_max_idle_per_host` | integer | `64` | HTTP connection pool idle connection limit per upstream host. |
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

Optional virtual-key governance layer. When enabled, static `auth` tokens are superseded, every request must carry a busbar-issued virtual key. Per-key controls: allowed pools (ACL), budget (cents), budget period, and rate limits (RPM/TPM). State is durable in embedded SQLite.

```yaml
governance:
  enabled: true
  db_path: /var/lib/busbar/governance.db
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
  price_per_request_cents: 1
  price_per_1k_tokens_cents: 50
```

| Field | Type | Required | Default | Validation | Notes |
|---|---|---|---|---|---|
| `enabled` | bool | no | `false` | n/a | Master switch. |
| `db_path` | string | no | `busbar-governance.db` | n/a | Path to the SQLite file. The directory must exist and be writable. |
| `admin_token` | string | no | none (admin API disabled) | Must be non-empty (non-whitespace) when `enabled: true` | Guards the `/admin/keys` API. If absent when `enabled: true`, Busbar refuses to start (the admin API would be silently inaccessible). |
| `price_per_request_cents` | integer | no | `1` | Negative values clamped to 0 | Flat per-request charge against each virtual key's budget (in cents). |
| `price_per_1k_tokens_cents` | integer | no | `0` | Negative values clamped to 0 | Per-1,000-token charge (input + output tokens from response usage metadata). |
| `budget_on_store_error` | string | no | `allow` | `allow` or `deny` | Behavior when the budget store errors during the atomic admission check-and-charge. `allow` (default) fails open, the request proceeds, preserving availability on a store hiccup. `deny` fails closed, the request is rejected, providing a hard budget guarantee for security/regulated deployments. A definitive over-budget result always rejects regardless of this setting. |
| `sqlite_busy_timeout_ms` | integer | no | `5000` | n/a | SQLite `busy_timeout` (milliseconds) for the governance store under write contention. |
| `rate_sweep_interval` | integer | no | `256` | Must be ≥ 1 | How often (every N admissions) the in-memory rate-limit map evicts idle entries. Correctness does not depend on it (per-key windows reset on lookup); it only bounds memory. `0` is rejected at startup. |

**Budget spend per request:** `price_per_request_cents + (total_tokens / 1000) * price_per_1k_tokens_cents`.

**Enforcement semantics (important for operators):**
- **RPM is precise.** The per-minute counter is incremented synchronously on admission.
- **TPM is best-effort.** Token counts are fed post-response; concurrent in-flight requests are not pre-charged. The first request of each rate window is always admitted.
- **Budget is best-effort/soft under concurrency.** The budget check and deduction are not atomic; concurrent requests can overshoot. Overshoot is bounded by the degree of parallelism, not unbounded. On store errors, behavior is controlled by `budget_on_store_error` (default `allow` = fail open; set `deny` for fail-closed hard guarantee).

**Incompatible combination:** `enabled: true` + `auth.mode: passthrough` is a startup error. Governance supersedes passthrough; the combination is unsupported.

**Virtual key format:** `sk-bb-<32 hex characters>` (128-bit CSPRNG). Shown in plaintext exactly once at mint; stored as SHA-256 hash only. Key IDs have the form `vk_<16 hex characters>`.

**Admin API routes** (guarded by the admin token, not a virtual key):

| Route | Method | Description |
|---|---|---|
| `/admin/keys` | `POST` | Mint a new virtual key. Returns plaintext bearer `secret` once. Pass `"issue_aws_credential": true` to also receive `aws_access_key_id` + `aws_secret_access_key` for Bedrock-SDK clients (both shown once). |
| `/admin/keys` | `GET` | List all keys (metadata only; no secrets). |
| `/admin/keys/{id}` | `PATCH` | Update key fields. Three-state semantics: absent = unchanged, `null` = clear to unlimited, value = set. |
| `/admin/keys/{id}/usage` | `GET` | Current-window spend, tokens, and request count. |
| `/admin/keys/{id}` | `DELETE` | Revoke a key. Returns 404 if not found (not idempotent). |

See [operations.md](operations.md) for the full admin API payload schemas and virtual key fields, including the `issue_aws_credential` Bedrock SigV4 option.

---

### `security`

Optional. Extends or overrides the hardcoded cloud-metadata SSRF denylist. When absent, only the built-in denylist applies. See [Security: Provider upstreams & SSRF](https://getbusbar.com/security/) for the full threat model, the complete denylist, and worked examples.

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
- `GET /metrics`, Prometheus (admitted unconditionally under `mode: none`).

`listen` defaults to `0.0.0.0:8080`. No auth gate. No pools.

---

## Full annotated example

This example requires: `BUSBAR_CLIENT_TOKEN`, `BUSBAR_ADMIN_TOKEN`, `ANTHROPIC_KEY`, `OPENAI_KEY`, `GEMINI_KEY`.

```yaml
listen: "0.0.0.0:8080"

# ---------------------------------------------------------------------------
# Auth: clients send Authorization: Bearer <BUSBAR_CLIENT_TOKEN>
# Governance is enabled below, so this becomes vestigial, governance keys
# supersede static tokens once governance is active.
# ---------------------------------------------------------------------------
auth:
  mode: token
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
  # cost_per_mtok on each member drives the native cheapest policy.
  batch:
    route: native
    policy:
      name: cheapest
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
# Note: mode: passthrough is incompatible with governance.enabled: true.
# ---------------------------------------------------------------------------
governance:
  enabled: true
  db_path: /var/lib/busbar/governance.db
  admin_token: "${BUSBAR_ADMIN_TOKEN}"
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
| `auth` value unknown | `auth` field value not `bearer` or `api-key` |
| `auth.mode` value unknown | `auth.mode` not one of `token`, `passthrough`, `none` (case-insensitive) |
| `affinity.mode` value unknown | `affinity.mode` not `session` (the only supported value) |
| Removed `token` field set | The 1.0.0-removed `auth.token` field is present, rejected at parse as an unknown field (`unknown field \`token\``); move its value into `client_tokens` |
| `path` malformed | `path` does not begin with `/` |
| Model name reserved | Model named `admin` |
| `provider` reference missing | `models.<name>.provider` does not name a configured provider |
| `max_concurrent: 0` | A concurrency semaphore of 0 never grants a permit |
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
| `route: native` + no `policy.name` | Native transport requires a policy name |
| `route: native` + unknown `policy.name` | Name must be one of `weighted`, `cheapest`, `fastest`, `least_busy`, `usage` |
| `route: webhook` + no `policy.url` | Webhook transport requires a sidecar URL |
| `route: webhook` + SSRF-blocked `policy.url` | RFC-1918, CGNAT, link-local, and metadata hosts are blocked (loopback allowed) |
| `route: script` + neither `policy.script` nor `policy.script_file` | Script transport requires a Rhai source |
| `route: script` + both `policy.script` and `policy.script_file` | Mutually exclusive |
| `route: script` without the `script-policy` feature | Script transport not compiled into the binary |
| Breaker `max_cooldown < base_cooldown` | Cooldown ceiling below the base |
| `auth.mode: token` + empty `client_tokens` | Every request would be rejected |
| `auth.mode` unknown | Value not in `{token, passthrough, none}` |
| `governance.enabled: true` + no `admin_token` | Admin API silently inaccessible |
| `governance.enabled: true` + `auth.mode: passthrough` | Unsupported combination |
| `${VAR}` unset in config | Unresolvable interpolation reference |
| `${}` or unclosed `${` | Malformed interpolation syntax |

**Warnings (non-fatal):**

| Condition |
|---|
| `auth.mode: none` with non-empty `client_tokens` (allowlist has no effect) |
| `auth.mode: passthrough` with a provider whose API key env var is non-empty (credential-leak risk) |
| Heterogeneous pool (members span more than one backend protocol, cross-protocol translation applies) |
| `api_key_env` names an env var that is unset or empty at boot (lane will fail auth) |
| `allowed_pools` on a virtual key (admin API) names a pool not currently configured |
| `auth.mode: token` or `auth.mode: none` with governance enabled (static auth is superseded; effective mode is governance virtual keys) |
