# Configuration reference

Busbar reads **two YAML files** at startup:

| File | Default path | Env override | Purpose |
|---|---|---|---|
| Provider catalog | `/etc/busbar/providers.yaml` | `BUSBAR_PROVIDERS` | Shipped map of provider names → protocol, base URL, error map. Operators rarely edit this. |
| Deployment config | `/etc/busbar/config.yaml` | `BUSBAR_CONFIG` | Your site's providers (with secret references for credentials), models, pools, auth, groups, pricing, store, and observability. |

Both files support `${VAR}` environment interpolation before YAML is parsed. A missing or malformed env var reference is a fatal startup error, Busbar refuses to boot rather than run with an incomplete config.

> Looking for a one-page map of every key? See [Config at a glance](config-at-a-glance.md).
>
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
  - [`groups`](#groups)
  - [`rate_card` and `per_request_fee`](#rate_card-and-per_request_fee)
  - [`store`](#store)
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
  - [Virtual keys and enforcement](#virtual-keys-and-enforcement)
  - [`plugins`](#plugins)
  - [`security`](#security)
  - [`advanced`](#advanced)
- [Migrating a 1.4.x config](#migrating-a-14x-config)
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
| *(each provider's `api_key: { env: VAR }` reference)* | `main.rs` | The env var **named by** the secret reference holds that provider's upstream credential. Resolved once at boot per provider. |
| *(any `${VAR}` in `config.yaml`)* | `config.rs` | Expanded before YAML is parsed. Unset → fatal boot error. |

`BUSBAR_ADMIN_TOKEN` is not special-cased in the code. It appears in the shipped `config.yaml` only because the file references `{ env: BUSBAR_ADMIN_TOKEN }` under `auth.admin_auth`. Any variable name works.

---

## Environment interpolation

### Syntax

Only the **brace form** `${NAME}` is expanded. Bare `$NAME` is passed through unchanged.

```yaml
providers:
  internal:
    base_url: "https://${LLM_GATEWAY_HOST}/v1"   # expanded: the env var's value is substituted
    api_key: { env: INTERNAL_KEY }               # NOT interpolation: a secret REFERENCE, resolved at boot
```

Most secrets never need `${VAR}` interpolation at all: credential fields are secret references
(`{ env: VAR }` / `{ file: /path }` / `{ module: <secret-plugin> }`) resolved by the secret
subsystem at boot. Interpolation remains for non-secret values (hosts, paths, names).

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
| `auth` | string | no | Protocol's native auth | The egress auth mechanism. `bearer` (sends `Authorization: Bearer <key>`) · `api-key` (sends `api-key: <key>`, for Azure OpenAI) · `jwt-bearer` (OAuth 2.0 JWT-bearer, RFC 7523: mints + auto-refreshes a bearer from a service-account key resolved via `api_key`; e.g. Google Vertex AI) · `oauth-client-credentials` (OAuth 2.0 client-credentials, RFC 6749 §4.4: the `api_key` reference resolves to `client_id:client_secret`, exchanged at `token_url` for a bearer; e.g. Azure OpenAI via Entra ID). When unset, each protocol uses its native scheme: bearer for anthropic/openai/responses/cohere, `x-goog-api-key` for gemini, AWS SigV4 for bedrock. |
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

In `config.yaml`, a provider entry may selectively override the catalog's `protocol`, `base_url`, `error_map` (merged: deployment entries win per code), `path`, `path_base`, `auth`, `token_url`, `scope`, and `health`. The only always-required field in the deployment entry is `api_key` (a secret reference).

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

A provider whose `api_key` reference resolves to an empty value will not be probed regardless of the `health` block.

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
  cert: { file: /etc/busbar/tls/fullchain.pem }  # PEM cert chain, leaf first (secret reference)
  key:  { file: /etc/busbar/tls/privkey.pem }    # PEM private key (PKCS#8 / PKCS#1 / SEC1)
  client_ca: { file: /etc/busbar/tls/ca.pem }    # optional: present = mTLS required
```

| Field | Type | Default |
|---|---|---|
| `cert` | secret reference | (required when `tls` is set) |
| `key` | secret reference | (required when `tls` is set) |
| `client_ca` | secret reference | unset (no client-cert requirement) |

Each value is a secret REFERENCE (`{ file: ... }` / `{ env: VAR }` / `{ module: <secret-plugin> }`)
resolving to PEM bytes. The same shape configures the admin listener under `admin_tls:` (with
`client_ca` gating admin mTLS; a network-exposed `admin_listen` without `admin_tls.client_ca`
refuses to boot unless `admin_insecure: true` is set deliberately).

Certs/keys are loaded once at startup; any missing or unparseable file is a fatal
startup error naming the file. ALPN advertises http/1.1. Rotate certs by replacing
the files and restarting. Full operational guide:
[`operations.md`](operations.md#inbound-tls--mutual-tls-mtls).

---

### `auth`

Front-door identity for the data plane plus the admin chain and role policy. Data-plane callers
authenticate through `auth.chain` (ordered module entries); the built-in `keys` module verifies
busbar's own signed virtual keys, and identity-provider integrations load as `kind: auth`
plugins. Static token allowlists are GONE in 1.5.0: every caller carries either a minted signed
key or an IdP credential a chain module verifies.

```yaml
auth:
  signing_key: { file: /run/secrets/busbar-signing.key }  # optional; generated 0600 on first boot
  upstream_credentials: own
  chain:
    - keys                                                # built-in signed-key verifier (no config)
    - ad: { max_admin_scope: full, settings: { server: "ldaps://corp", base_dn: "dc=corp" } }
  admin_auth:
    - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }
  role_bindings:
    ad:
      growth-eng: { allowed_pools: [fast], group: growth }
      platform:   { group: acme, admin_scope: full }      # allowed_pools omitted = ALL pools
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `signing_key` | secret reference | no | generated on first boot | The ed25519 key busbar signs virtual-key tokens with. Fleet-shared (every node verifying the same tokens resolves the same key). Absent: busbar generates a keypair on first boot and persists it with mode 0600 (dev zero-config). Rotating it revokes every outstanding key. |
| `upstream_credentials` | string | no | `own` | Whose key hits the provider: `own` (busbar's configured lane credential) or `passthrough` (forward the caller's own token upstream; busbar holds no keys). |
| `chain` | list of module entries | no | `[]` | The ordered DATA-PLANE authentication chain. Each entry is a bare module name (`- keys`) or a single-key map `- <module>: { max_admin_scope?, settings? }` where `settings` is the module's own opaque config. `[]` (default) is the open front door: development only, loud startup warning. An unknown module name is a startup error. |
| `admin_auth` | list of module entries | no | `[admin-tokens]` | The chain gating `/api/v1/admin/*`. The built-in `admin-tokens` module carries the operator credential as a secret reference (`token:`). `[]` = OPEN admin (dev only; loud warning). |
| `role_bindings` | map | no | `{}` | Role policy, NESTED BY MODULE: `role_bindings.<module>.<role> -> { allowed_pools?, group?, admin_scope? }`. See below. |

**Per-entry typed fields** (alongside the module's opaque `settings`):

| Field | Default | Notes |
|---|---|---|
| `max_admin_scope` | `read-only` | Ceiling on the admin scope obtainable through this module, regardless of what `role_bindings` grants: `read-only` \| `hooks-register` \| `full`. `full` from an external module is an explicit opt-in. The built-in `admin-tokens` operator credential is exempt (it is the root credential). |
| `token` | none | The operator admin credential, for the built-in `admin-tokens` module only (a secret reference). |
| `settings` | `{}` | The module's own opaque configuration, passed to the auth plugin verbatim. |

**Token extraction order (data plane):** `Authorization: Bearer`, then `x-api-key`, then
`x-goog-api-key`. Blank values are treated as absent.

**Bedrock ingress.** Native Bedrock SDK clients authenticate with AWS SigV4. Mint a key with
`"issue_aws_credential": true`; the response includes `aws_access_key_id` +
`aws_secret_access_key` (shown once). Busbar verifies the inbound SigV4 signature natively
(including body-hash integrity), then applies the key's group limits and pool ACL.

#### `auth.role_bindings`: module-scoped role policy

A role asserted by an auth module earns exactly what the binding under THAT module grants,
nothing else: `ad.platform` and `oidc.platform` are distinct grants, and a module can never ride
another module's binding. An unbound role grants nothing (fail closed).

| Field | Notes |
|---|---|
| `allowed_pools` | DATA-PLANE grant: pools this role may target. OMITTED = ALL pools; an explicit `[]` = NO pools (an empty list is the empty set, everywhere in the 1.5.0 config). Pool lists union across a principal's granting roles; any omitted grant widens the union to all pools. |
| `group` | The `groups:` bucket this role's principals charge through. Absent = no group (authed + unlimited). With several bound groups the first in role order wins. |
| `admin_scope` | The admin authority this role grants: `read-only` \| `hooks-register` \| `full`. Absent = none. The most permissive of a principal's bound roles wins, then the asserting module's `max_admin_scope` ceiling applies. |

Admin access is therefore EITHER a role's `admin_scope` (through an IdP module in `admin_auth`)
OR the `admin-tokens` operator token. The admin chain is live-mutable over the API
(`PUT /api/v1/admin/auth`) with an anti-lockout guard; see the [Admin API guide](./admin-api.md).

---

### `groups`

The ONE limit tree. A group is a named enforcement bucket: an ordered list of generic limits plus
an optional `parent` forming an acyclic chain (depth <= 8). Keys are pure auth and carry no limits;
a key binds to at most one group at mint, and every request walks the chain UP through `parent`,
enforcing EVERY limit of EVERY group (AND, atomically, all-or-nothing charging).

```yaml
groups:
  acme:
    limits:
      - { requests: 500, per: minute }
      - { budget: 1000000, per: month }
  growth:
    parent: acme
    limits:
      - { requests: 50, per: minute }
      - { budget: 200000, per: month }
  bob:
    parent: growth
    enabled: true                    # false = freeze this group (and every descendant's traffic)
    limits:
      - { requests: 10,   per: minute }
      - { requests: 1000, per: day }
      - { concurrent: 5 }            # no `per` = instantaneous in-flight cap
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `parent` | string | none | The parent group; must exist; the chain must be acyclic and at most 8 deep (validated with paste-ready fixes). |
| `enabled` | bool | `true` | `false` FREEZES the group: every request charging through it (its own keys and every descendant's) is rejected with a 403 naming the group, while its usage history is kept. |
| `limits` | list | `[]` | Each entry has exactly ONE metric key: `requests`, `tokens`, or `budget` with a required `per:` window (`minute` \| `hour` \| `day` \| `month` \| `total`), or `concurrent` with NO `per:` (instantaneous). A metric repeated for the same window keeps the most restrictive amount. |

**Metric semantics:**

- **`requests`** is precise: the counter increments synchronously at admission. Rejection: 429
  naming the bucket (e.g. `group 'bob': requests per minute`) with `Retry-After` to the window
  roll (`total` never rolls, so no header).
- **`tokens`** is best-effort post-paid: tokens land after each response, so the cap blocks the
  NEXT request once the ledgered total crosses it. Rejection: 429 + `Retry-After`.
- **`budget`** derives at admission from the bucket's token ledger x the current `rate_card`
  plus `per_request_fee` x its request count, in abstract cents. Rejection: the vendor's native
  quota status (429 for most protocols; Bedrock's quota shape is 400-class), naming the bucket.
- **`concurrent`** is an in-flight gauge: incremented at admission, released when the response
  stream completes. Rejection: 429, no `Retry-After`.

---

### `rate_card` and `per_request_fee`

The ONLY cost source. Tokens are the ledger; every dollar figure is DERIVED at read time as
`tokens x rate_card + requests x per_request_fee`, so correcting a rate is a config edit + reload
with no re-billing and no data migration.

```yaml
rate_card:
  sonnet-anthropic: { input_utok: 3.0, output_utok: 15.0, cache_read_utok: 0.3, cache_write_utok: 3.75 }
  sonnet-bedrock:   { input_utok: 2.8, output_utok: 14.0 }
per_request_fee: 0
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `rate_card` | map | absent (token pricing = 0) | Per-model, per-tier token rates in MICRO-units (1e-6 abstract cost unit) per token; an omitted tier prices 0. ALL-OR-NOTHING: absent = every model's tokens price at 0 (budgets count only the flat fee); present = AUTHORITATIVE and COMPLETE: every configured model must have an entry or boot/`--validate` fail with a paste-ready stub of exactly the missing models. With a card present, a request for an arbitrary passthrough model with no rate is rejected pre-forward. |
| `per_request_fee` | integer | `0` | Flat charge per request in abstract cents, charged at admission into every chain bucket's request count (refunded on a non-2xx outcome). |

The rate numbers are **abstract cost units**: busbar does pure integer math and never knows what
currency they represent. Currency, symbols, and FX are display concerns owned by your dashboard.
Routing's `cheapest` strategy derives its per-member scalar from the card as
`(input_utok + output_utok) / 2`; pool members carry no cost fields.

---

### `store`

The durable store as a plugin instance: `{ module, settings }`. The default `memory` module is the
compiled-in ephemeral RAM store (keys, usage, and the audit log reset on restart); every durable
backend is a signed plugin tarball.

```yaml
store:
  module: postgres
  settings: { url: "postgres://user:pass@host/busbar" }
```

| `module` (alias or canonical name) | Plugin tarball | `settings` |
|---|---|---|
| `memory` (default) | compiled in, no plugin | none |
| `sqlite` / `busbar-store-sqlite` | `busbar-store-sqlite-<ver>-<target>.tar.gz` | `db_path` (file path), `busy_timeout_ms` (default 5000) |
| `postgres` / `busbar-store-postgres` | `busbar-store-postgres-<ver>-<target>.tar.gz` | `url` (`postgres://` libpq URL); cluster-shared |
| `redis` / `busbar-store-redis` | `busbar-store-redis-<ver>-<target>.tar.gz` | `url` (`redis://`, `rediss://` for TLS); cluster-shared |

`settings` is the store module's OWN opaque configuration, passed through verbatim; a third-party
store plugin documents its own keys. A non-`memory` store requires `plugins.enabled: true` and the
store's tarball in `plugins.dir`, or busbar refuses to boot naming the flag/plugin.

**Fleet semantics (honest):** with a cluster-shared store (postgres/redis) behind N busbar nodes,
virtual keys, accumulated usage, the audit log, and the revocation denylist are genuinely shared.
The limit hard caps are enforced PER NODE from each node's in-memory counters and reconciled
durably through ADDITIVE flushes, so the shared store converges on the true fleet total, but
between flushes N nodes splitting traffic can admit up to ~N times a configured cap. The caps are
not a synchronous cluster-wide gate.

**Backend caveats:** the Redis store supports TLS (`rediss://`), transparent reconnect, and atomic
multi-key cascades (MULTI/EXEC), and scrubs the URL password from error strings; it writes WITHOUT
TTLs (usage/metering/audit grow unboundedly by design: apply your own retention). The Postgres
store currently connects `NoTls` and without automatic reconnect: run it over a trusted network
segment (or a TLS-terminating proxy such as pgbouncer/stunnel) and let your supervisor restart
busbar on a persistent connection loss.

---

### `providers`

Declares which catalog providers this deployment uses and supplies the env var holding each one's credential.

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `api_key` | secret reference | **yes** | n/a | The upstream credential as a secret reference: `{ env: VAR }`, `{ file: /path }`, or `{ module: <secret-plugin>, settings: {...} }`. Resolved once at boot. A reference resolving to an empty value logs a startup warning; the lane starts but will fail upstream auth. |
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

**Credential format by protocol** (the VALUE the `api_key` reference resolves to):

| Protocol | Resolved credential format | How it's sent |
|---|---|---|
| `anthropic` | API key (`sk-ant-api…`) or OAuth token (`sk-ant-oat…`) | `x-api-key: <key>` for API keys; `Authorization: Bearer <key>` for OAuth tokens. Mode is inferred from the key prefix; both headers are sent if the prefix is unrecognized. `anthropic-version` header is always added. |
| `openai` / `responses` / `cohere` | API key | `Authorization: Bearer <key>` |
| `openai` + `auth: api-key` (Azure) | API key | `api-key: <key>` |
| `gemini` | API key | `x-goog-api-key: <key>` |
| `bedrock` | `ACCESS_KEY_ID:SECRET_ACCESS_KEY` or `ACCESS_KEY_ID:SECRET_ACCESS_KEY:SESSION_TOKEN` | AWS SigV4: signed per request. Region is parsed from the host in `base_url` (e.g. `bedrock-runtime.us-east-1.amazonaws.com`). |

```yaml
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
  openai:
    api_key: { env: OPENAI_KEY }
  gemini:
    api_key: { file: /run/secrets/gemini-key }
    health:
      mode: dead
      interval_secs: 60
  bedrock-us-east-1:
    api_key: { env: AWS_BEDROCK_CREDS }   # ACCESS:SECRET or ACCESS:SECRET:SESSION
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
      - model: sonnet-anthropic
        weight: 3                          # primary
      - model: sonnet-bedrock
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
      - model: claude-sonnet-4-5
        weight: 8
      - model: gpt-4o
        weight: 2
      - model: gemini-1.5-pro
        weight: 1
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `model` | string | **yes** | n/a | Name of a model in `models`. Must be a configured model; a missing model is a startup error. (Renamed from the 1.4.x `target`; the old key is a startup error.) |
| `weight` | integer | no | `1` | Relative selection share under smooth weighted round-robin (SWRR), computed over the currently healthy/usable members. Must be ≥ 1. `0` is a startup error. |
| `context_max` | integer | no | none | This member's maximum context window (tokens). Used for [context-length failover](#context-length-failover). |
| `attempt_timeout_ms` | integer | no | the model's value | Per-attempt time-to-response-headers cap for this member **in this pool**, overriding the model-level `attempt_timeout_ms`. Lets the same model carry different hang tolerances per pool (e.g. `10000` in a batch pool, `50` in a latency-critical one). Must be ≥ 1 when set (0 is a startup error). See [Per-attempt timeouts](#per-attempt-timeouts-attempt_timeout_ms). |
| `reasoning` | bool | no | the model's value | Per-pool override of the model-level `reasoning` capability flag (member wins), so the same lane can allow thinking in a research pool and refuse it in a latency-critical one. See [Cross-protocol reasoning](#cross-protocol-reasoning-reasoning). |
| `tier` | string | no | none | Operator-declared routing tier label (e.g. `"primary"`, `"overflow"`, `"large"`, `"small"`). Inert for plain weighted pools (no hooks). Exposed to gate hooks as the `tier` field on each candidate. See [Pool `hooks`](#pool-hooks-ordering-and-gates). |
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
      - model: gemini-pro         # inherits the model's 10000ms
      - model: gpt-4o
  realtime:
    members:
      - model: gemini-pro
        attempt_timeout_ms: 50    # THIS pool can't wait: hop after 50ms
      - model: gpt-4o
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

A pool names the hooks it wants in ONE ordered `hooks: [...]` list, inline, where they run. There
is NO top-level `hooks:` registry block in 1.5.0: a hook instance is defined at its point of use.
Two spellings per entry:

- a **bare name** is a built-in ordering strategy: `weighted` \| `cheapest` \| `fastest` \|
  `least_busy` \| `usage` (at most one per pool: it sets the base ranking; the default is
  `weighted`, the zero-cost SWRR baseline);
- a **module ref** is an out-of-process (or plugin) hook instance:
  `{ module: webhook|socket|<kind: hook plugin>, settings: {...}, kind?, timeout_ms?, on_error?,
  on_empty?, prompt?, user?, priority?, at? }`. The built-in transports are `webhook`
  (`settings.url`, an HTTPS sidecar) and `socket` (`settings.path`, a Unix domain socket).

```yaml
pools:
  smart:
    hooks:
      - cheapest                                       # base ordering strategy
      - { module: socket, settings: { path: /run/busbar/router.sock },
          kind: gate, timeout_ms: 2, on_error: nothing }
    members:
      - model: claude-sonnet-4-5
        weight: 2
        context_max: 200000
        tier: primary
        tags: ["sonnet", "fast"]
      - model: gpt-4o
        weight: 1
        context_max: 128000
        tier: primary
        tags: ["gpt4"]
      - model: gpt-4o-mini
        weight: 1
        tier: overflow
        tags: ["cheap"]

global_hooks:                                          # fire on EVERY request, ordered
  - { module: webhook, settings: { url: "https://sidecar.internal/pii" },
      kind: gate, timeout_ms: 5, on_error: reject, prompt: ro }
```

**Semantics:**

- The `cheapest` strategy derives each member's cost scalar from the top-level `rate_card`
  (members carry no cost fields).
- All decision gates (the pool's and any `global_hooks`) fire **concurrently** per request and
  reconcile deterministically: any `reject` wins (the lowest-`priority` gate's status/message
  surfaces), `restrict`s intersect (an empty intersection applies that gate's `on_empty`,
  fail-closed by default), and with multiple `order`s the last in the chain wins. A restriction
  persists across every failover hop.

**Module-ref typed fields** (alongside the module's opaque `settings`; full model in
[Hooks](hooks.md)):

| Field | Type | Default | Description |
|---|---|---|---|
| `kind` | `tap` \| `gate` | `gate` in a pool list, `tap` in `global_hooks` | `gate` = fire-and-wait (may rank/reject/restrict/rewrite); `tap` = fire-and-forget observation. |
| `settings` | map | `{}` | The module's own opaque config: `url` for `webhook` (SSRF-guarded: loopback allowed; RFC-1918/CGNAT/link-local/metadata blocked; remote must be `https://`), `path` for `socket`; anything else is pushed to the hook via the `configure` wire message. |
| `timeout_ms` | integer | `1` | Hard wall-clock deadline for a gate decision. Raise it when the hook does I/O. On timeout the decision is coerced to `on_error`. |
| `on_error` | keyword or ref | `nothing` | Fallback when a gate times out / errors / saturates: a bare terminal (`nothing` \| `weighted` \| `reject` \| `first`) or a structured hook reference `{ hook: <name> }` (a chain, proven terminating at boot). A gate's deliberate `reject` reply is a decision, not a failure. |
| `on_empty` | string | `reject` | A restrict gate's empty-intersection behavior: `reject` (fail closed, 503) or `weighted` (advisory escape). |
| `prompt` | `no` \| `ro` \| `rw` | `no` | Prompt-content grant: `ro` sends the prompt read-only; `rw` additionally allows a `rewrite` reply. `rw` on a tap is a startup error. |
| `user` | `no` \| `ro` | `no` | Caller-identity grant: governance key id/name (never the secret) + the body's end-user field. |
| `priority` | integer | `0` | Chain ordering key: orders the rewrite transform chain and tie-breaks the reconcile. |
| `at` | string | `request` | TAP observation stage: `request` \| `route` \| `attempt` \| `completion`. Inert on a gate. |

The per-member `tier` and `tags` fields documented in [Members and weights](#members-and-weights)
feed the ordering strategies and gate candidates. Gate observability: the
`x-busbar-route-policy` / `x-busbar-route-target` response headers name the deciding hook and
chosen lane.

---

#### `breaker`

Per-(pool, lane) circuit-breaker tuning. The breaker state is independent per pool: a lane open in pool A can be closed in pool B. Lane-global state (hard-down, lifetime budget, concurrency semaphore) is shared across all pools.

```yaml
pools:
  primary:
    members:
      - model: claude-sonnet-4-5
      - model: gpt-4o
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
| `trip.window_secs` | integer | `30` | Must be ≥ 1 | Sliding outcome window for `error_rate` mode. Outcomes older than `window_secs` are evicted. (`window_secs` is the ONLY spelling; the pre-1.0 `window_s` alias is gone and fails boot.) |
| `trip.threshold` | float | `0.5` | Must be in `(0.0, 1.0]` | Error fraction threshold for `error_rate` mode. `0.5` means more than half of outcomes in the window must be errors to trip. |
| `trip.min_requests` | integer | `5` | Must be ≥ 1 | `error_rate` mode: minimum outcomes required in the window before the threshold is evaluated. Prevents tripping on a single failure with no baseline. |
| `trip.consecutive_n` | integer | `3` | Must be ≥ 1 | `consecutive` mode: number of consecutive failures that trip the breaker. (`consecutive_n` is the ONLY spelling; the pre-1.0 `n` alias is gone and fails boot.) |
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
      - model: claude-sonnet-4-5
        weight: 3
      - model: gpt-4o
        weight: 2
      - model: gemini-1.5-pro
        weight: 1
    failover:
      timeout_secs: 30
      max_hops: 3
      exclusions:
        - gemini-1.5-pro   # never used as a failover destination; still receives primary traffic
```

| Field | Type | Default | Validation | Notes |
|---|---|---|---|---|
| `timeout_secs` | integer | `120` | Must be ≥ 1 | Wall-clock budget for the entire request across all hops. Exceeded → 503 immediately. (`timeout_secs` is the ONLY spelling; the `deadline_secs` alias is gone and fails boot.) |
| `max_hops` | integer | `3` | n/a | Maximum number of failover hops for one request. A hop is one upstream attempt that fails before the first response byte. (`max_hops` is the ONLY spelling; the `cap` alias is gone and fails boot.) |
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
      - model: claude-sonnet-4-5
      - model: gpt-4o
    on_exhausted: { fallback_pool: overflow }

  overflow:
    members:
      - model: claude-sonnet-4-5
      - model: gpt-4o-mini
    on_exhausted: least_bad
```

A keyword stays bare; a reference is structured (the 1.5.0 `on_X` convention):

| Value | Behavior |
|---|---|
| `reject` | Return `503 Service Unavailable` with a `Retry-After` header set to the soonest member cooldown expiry. This is the default when `on_exhausted` is omitted. |
| `least_bad` | Route to the member whose cooldown expires soonest, even though it is Open. The request is likely to fail, but degraded service is preferred over a hard 503. This is logged as a degraded dispatch. |
| `{ fallback_pool: <name> }` | Route the request to another named pool and run its full selection logic. Cycles (`primary` to `overflow` back to `primary`) and self-references are detected at startup and are errors. |

**Unknown keywords or a malformed structure are a fatal startup error** (not a runtime 503).

---

#### `affinity`

Pin a session to one pool member while that member remains healthy. Useful to keep provider-side prompt caches warm or to maintain conversational state.

```yaml
pools:
  smart:
    members:
      - model: claude-sonnet-4-5
      - model: gpt-4o
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
      - model: claude-sonnet-4-5
        context_max: 200000
      - model: gemini-1.5-pro
        context_max: 1000000
```

When a member returns a context-length error, busbar:
1. Excludes from the **current request** any candidate whose known `context_max` is ≤ the failed lane's.
2. Fails over to a member with a larger (or unknown) `context_max`.
3. Records no breaker penalty against the smaller lane.

Members without `context_max` set are always eligible for context-length failover (their capacity is unknown; Busbar treats unknown as potentially unlimited).

---

### `limits`

Optional. Exposes eleven operational limits (mostly previously hardcoded, plus `max_inbound_concurrent`, `pool_idle_timeout_secs`, and `request_body_read_timeout_secs`) so operators can tune them without rebuilding. All fields default to their historical values, so omitting this block is a no-op.

```yaml
limits:
  max_inbound_concurrent: 8192    # 0 = unlimited; > 0 adds a global concurrency cap
  request_body_max_bytes: 33554432  # 32 MiB
  upstream_request_timeout_secs: 300
  tls_handshake_timeout_secs: 10
  request_body_read_timeout_secs: 30  # max gap between inbound body frames (slow-loris body defense)
  pool_max_idle_per_host: 1024
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
| `request_body_read_timeout_secs` | integer | `30` | Maximum time allowed between inbound request-body frames before the connection is dropped. Closes the slow-loris body gap the header-read timeout does not cover. |
| `pool_max_idle_per_host` | integer | `1024` | HTTP connection pool idle connection limit per upstream host. |
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
  otlp_url: "http://localhost:4318/v1/traces"
  request_log_webhook_url: "https://logs.example.com/busbar"
  emit_server_timing: true
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `otlp_url` | string | none | When set, installs an OTLP/HTTP trace exporter. Loopback `http://` is allowed (standard collector default). Remote endpoints must use `https://`. SSRF-guarded: rejects RFC-1918, link-local, CGNAT, metadata hosts. Traces are flushed on graceful shutdown. |
| `request_log_webhook_url` | string | none | When set, fires a fire-and-forget JSON POST per completed request: `{ts, ingress_protocol, pool, outcome, latency_ms}`. Must be `https://`. SSRF-guarded (same classes as `otlp_url` plus broadcast). At most 64 deliveries in flight; drops rather than queues. 2-second delivery timeout. |
| `emit_server_timing` | bool | `false` | Controls whether the `Server-Timing: busbar;dur=<ms>` response header is emitted on every response. Defaults to `false`, the header is an in-band busbar fingerprint, so it is suppressed by default for backend indistinguishability. Set to `true` to enable it as a latency probe. |

**OTLP credential hygiene.** If your OTLP endpoint requires auth, supply credentials in the URL userinfo (`https://user:pass@collector.example.com/…`): Busbar moves them to an `Authorization: Basic` header and strips them from the URL before logging, so they do not appear in logs or spans.

---

### Virtual keys and enforcement

The 1.5.0 identity/enforcement model in one page. (The config pieces live in the sections above:
[`auth`](#auth) for the chain and role bindings, [`groups`](#groups) for the limit tree,
[`rate_card`](#rate_card-and-per_request_fee) for pricing, [`store`](#store) for durability.)

**A minted key is a busbar-SIGNED, EXPIRING token** `{sub, exp, kid}` (ed25519, signed with
`auth.signing_key`). Verification is stateless: signature + expiry + a small revocation denylist.
Policy (the bound `group`, `allowed_pools`) is resolved from the store by `sub`, so an operator
can rebind or freeze a key without re-issuing the credential. Keys are PURE AUTH: they carry NO
limits; every cap lives on the bound group's chain, and a key with no group is authed +
unlimited (access only).

**Mint** (`POST /api/v1/admin/keys`, guarded by `auth.admin_auth`):

```json
{ "name": "bob-laptop", "group": "bob", "allowed_pools": ["fast"],
  "labels": { "team": "growth" }, "expires_in": "7d" }
```

- `group` must name a configured `groups:` entry (400 otherwise). Omitted = unlimited key.
- `allowed_pools` omitted = ALL pools; an explicit `[]` = NO pools (C6: an empty list is the
  empty set). The intent is stored exactly as given.
- `expires_in` / `expires_at` are mutually exclusive; the default lifetime is 90 days.
- `"issue_aws_credential": true` additionally returns `aws_access_key_id` +
  `aws_secret_access_key` for Bedrock-SDK (SigV4) clients: both shown once.
- The signed token is returned ONCE and never stored (the store holds the binding, ledger, and
  denylist, not the token).

**Enforcement** walks the bound group's chain at admission and ANDs every limit (see
[`groups`](#groups) for per-metric semantics). Spend derives at check time from the token ledger
x the current `rate_card` + `per_request_fee` x requests: tokens are the only stored truth, so a
rate correction reprices everything on the next read. A key bound to a group missing from the
running config fails CLOSED (the rejection names the unconfigured bucket); minting validates the
group exists, and boot re-checks every stored key.

**Admin API routes** (guarded by `auth.admin_auth`, served on `admin_listen`):

| Route | Method | Description |
|---|---|---|
| `/api/v1/admin/keys` | `POST` | Mint a key. Returns the signed token once (`"issue_aws_credential": true` adds the AWS pair, also shown once). |
| `/api/v1/admin/keys` | `GET` | List key metadata: `{id, name, allowed_pools, group, enabled, created_at, labels}` (never a secret). |
| `/api/v1/admin/keys/{id}` | `PATCH` | `{enabled?, group??}`: freeze/unfreeze the binding, or rebind/unbind the group (three-state: absent = unchanged, `null` = unbind, value = rebind to an existing group). |
| `/api/v1/admin/keys/{id}/usage` | `GET` | The key's all-time attribution counters (derived spend, tokens, requests) plus chain-derived `rate_headroom`. |
| `/api/v1/admin/keys/{id}` | `DELETE` | Revoke: adds the subject to the durable denylist (enforced immediately, survives restart). Returns 404 if not found. |

See [operations.md](operations.md) for worked payloads and [admin-api.md](admin-api.md) for the
full admin contract (which carries its own version, independent of the binary's SemVer).

---

### `plugins`

The dynamic plugin subsystem: signed plugin tarballs (store, secret, auth, and hook plugins share the same machinery) that busbar verifies and loads at boot. **Off by default**: with `plugins.enabled: false` (or the whole block absent) no plugin is ever discovered or loaded, and a tarball dropped into the directory is inert. See [plugins.md](plugins.md) for the plugin author guide, the artifact format, and the full trust model.

```yaml
plugins:
  enabled: true                 # MASTER SWITCH, default false. Off = no plugin ever loads.
  dir: plugins                  # where the signed .tar.gz plugin tarballs live (default: plugins)
  trust:
    # busbar's own release key is EMBEDDED in the binary: busbar-signed plugins verify with
    # zero configuration. This block is for THIRD-PARTY publishers and explicit opt-ins.
    publishers:                 # third-party ed25519 signing keys (allowlist)
      - name: acme
        public_key: "<64-hex ed25519 public key>"
    allow_unsigned: false       # default false: unsigned/tampered plugins are logged + skipped
    allow_third_party: false    # default false: signed-but-unknown-publisher plugins are skipped
  min_versions:                 # anti-downgrade floors, keyed by manifest name (third-party;
    acme-store-dynamo: "2.0.0"  # first-party is automatically floored at the binary's version)
```

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `enabled` | bool | no | `false` | Master switch. `false`/absent = NO plugin loads (drop-is-inert). A non-`memory` `store.module` with plugins disabled is a boot error naming this flag. |
| `dir` | string | no | `plugins` | Directory holding the signed plugin tarballs (`*.tar.gz`), relative to the working directory. Filenames are irrelevant: identity comes from each tarball's signed manifest. |
| `trust.publishers` | list | no | empty | Third-party publishers: `{ name, public_key }` pairs (hex ed25519). The name `busbar` is reserved for the embedded release key and cannot be configured. |
| `trust.allow_unsigned` | bool | no | `false` | EXPLICIT opt-in to load plugins with no valid signature (unsigned/tampered). Without it they are logged and skipped, never `dlopen`ed. |
| `trust.allow_third_party` | bool | no | `false` | EXPLICIT opt-in to load validly-signed plugins from a publisher NOT in `publishers`. |
| `min_versions` | map | no | empty | Anti-downgrade floors: manifest `name` -> minimum `version`. A floored plugin must prove (trusted signature at/above the floor) that it meets it; no opt-in flag can bypass a floor. First-party plugins are automatically floored at the running binary's version. |

**Fail-closed guarantees:** with plugins enabled, ANY invalid tarball or manifest in `dir` (unparseable, missing/malformed fields, sha256 mismatch, unsupported `abi_version`) aborts boot naming the file and reason; any name/alias conflict between loadable plugins aborts boot naming both. `busbar --validate` runs the exact same pipeline ahead of time (zero side effects, nothing loaded), and `busbar --list-plugins` prints the manifest-only inventory with each plugin's signature verdict and load status.

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
    api_key: { env: ANTHROPIC_KEY }

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

This example requires: `BUSBAR_ADMIN_TOKEN`, `ANTHROPIC_KEY`, `OPENAI_KEY`, `GEMINI_KEY`.

```yaml
listen: "0.0.0.0:8080"
admin_listen: "127.0.0.1:8081"      # the admin API always runs on its own listener

# ---------------------------------------------------------------------------
# Auth: data-plane callers present minted signed keys (the built-in `keys`
# verifier); the admin API is gated by the admin-tokens operator credential.
# ---------------------------------------------------------------------------
auth:
  # signing_key: { file: /run/secrets/busbar-signing.key }  # absent = generated on first boot
  chain:
    - keys
  admin_auth:
    - admin-tokens: { token: { env: BUSBAR_ADMIN_TOKEN } }

# ---------------------------------------------------------------------------
# Groups: the ONE limit tree. Keys bind to a group at mint; enforcement walks
# the chain and ANDs every limit.
# ---------------------------------------------------------------------------
groups:
  growth:
    limits:
      - { requests: 600, per: minute }
      - { budget: 2000000, per: month }
      - { concurrent: 64 }

# ---------------------------------------------------------------------------
# Pricing: the ONE cost source (abstract micro-units per token, per model).
# ---------------------------------------------------------------------------
rate_card:
  claude-sonnet: { input_utok: 3.0, output_utok: 15.0, cache_read_utok: 0.3, cache_write_utok: 3.75 }
  gpt-4o:        { input_utok: 2.5, output_utok: 10.0 }
  gpt-4o-mini:   { input_utok: 0.15, output_utok: 0.6 }
  gemini-1.5-pro: { input_utok: 1.25, output_utok: 5.0 }
per_request_fee: 1

# ---------------------------------------------------------------------------
# Store: durable keys/usage/audit/denylist (a loadable plugin; omit the block
# for the ephemeral RAM default).
# ---------------------------------------------------------------------------
store:
  module: sqlite
  settings: { db_path: /var/lib/busbar/governance.db }

# ---------------------------------------------------------------------------
# Providers: secret references name where each credential lives.
# ---------------------------------------------------------------------------
providers:
  anthropic:
    api_key: { env: ANTHROPIC_KEY }
    health:
      mode: dead           # re-probe only tripped lanes, every 30s
      interval_secs: 30
      timeout_secs: 5

  openai:
    api_key: { env: OPENAI_KEY }

  gemini:
    api_key: { env: GEMINI_KEY }

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
# ---------------------------------------------------------------------------
pools:
  # Primary pool, weighted SWRR with session affinity and a tight breaker.
  smart:
    members:
      - model: claude-sonnet
        weight: 2
        context_max: 200000
      - model: gpt-4o
        weight: 2
        context_max: 128000
      - model: gemini-1.5-pro
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

    on_exhausted: { fallback_pool: overflow }

  # Overflow pool, used when every smart member is tripped.
  overflow:
    members:
      - model: claude-sonnet
        weight: 3
      - model: gpt-4o-mini
        weight: 1
    on_exhausted: least_bad   # serve degraded rather than hard 503

  # Cost-optimized pool: the cheapest strategy derives each member's cost
  # from the rate_card above (members carry no cost fields).
  batch:
    hooks: [cheapest]
    members:
      - model: gpt-4o-mini
        weight: 1
        tags: ["cheap"]
      - model: claude-sonnet
        weight: 1
    failover:
      timeout_secs: 120
      max_hops: 3
    on_exhausted: reject

# ---------------------------------------------------------------------------
# Observability: traces and per-request webhook logging.
# /metrics is always on (no config needed).
# ---------------------------------------------------------------------------
observability:
  otlp_url: "http://localhost:4318/v1/traces"
  request_log_webhook_url: "https://logs.example.com/busbar"
  emit_server_timing: true
```

Then mint a key for each caller (shown once; bind it to a group):

```bash
curl -s -X POST http://127.0.0.1:8081/api/v1/admin/keys \
  -H "authorization: Bearer $BUSBAR_ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"team-growth","group":"growth","expires_in":"30d"}'
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
| 1.x config detected | A 1.x structural marker is present (a `governance:` block, `auth.group_map:`, `auth.mode:`, a top-level `hooks:` block, `api_key_env`, `target:` in a pool member): boot refuses with "this looks like a busbar 1.x config; run `busbar --migrate-config`" |
| `path` malformed | `path` does not begin with `/` |
| Model name reserved | Model named `admin` |
| `provider` reference missing | `models.<name>.provider` does not name a configured provider |
| Unknown top-level key | Any unrecognized top-level key in `config.yaml` (typo fail-closed; every nested block already rejects unknown keys) |
| Plugin store without plugins | `store.module` names a plugin (anything but `memory`) while `plugins.enabled` is `false`/absent; the error names the flag |
| Invalid plugin artifact | With plugins enabled: any tarball in `plugins.dir` that fails structural validation (unreadable/hostile archive, malformed or incomplete manifest, `sha256` mismatch, unsupported `abi_version`); the error names the file and reason |
| Plugin conflict | Two loadable plugins share a `name` or `alias`, or an alias collides with another plugin's name; the error names both |
| Plugin store unresolved | `store.module` does not resolve to a loadable `kind: store` plugin (missing, skipped by trust with the reason attached, or the wrong kind) |
| `max_concurrent: 0` | A concurrency semaphore of 0 never grants a permit (omit the field for unbounded; `0` is the only rejected value) |
| `max_requests: 0` | Zero lifetime budget = permanently unusable lane |
| `default_max_tokens: 0` | Would be injected upstream and rejected |
| Pool name reserved | Pool named `admin` |
| Pool name collision | Pool name matches a provider or model name |
| Empty `members` | A pool with no members is un-routable |
| `weight: 0` | Pool member weight of 0 is invalid |
| `model` reference missing | A pool member's `model` does not name a configured model |
| `failover.timeout_secs: 0` | Zero failover deadline |
| `failover.exclusions` dangling | An exclusion names a model not in the pool |
| Fallback pool cycle | `on_exhausted: fallback_pool:<X>` where following the chain creates a cycle |
| Fallback pool self-reference | `on_exhausted: fallback_pool:<self>` |
| Fallback pool unknown | `on_exhausted: fallback_pool:<name>` where `name` is not a configured pool |
| `on_exhausted` malformed | Not `reject`, `least_bad`, or `{ fallback_pool: <pool> }` |
| `affinity.mode` unknown | Any value other than `session` |
| Pool `hooks:` names more than one ordering strategy | A pool has one base ordering |
| Pool `hooks:` bare name not a built-in strategy | An out-of-process hook is an inline `{ module: ... }` ref; bare names are only `weighted`/`cheapest`/`fastest`/`least_busy`/`usage` |
| Unknown hook module | An inline ref's `module` is not `webhook`, `socket`, or a loaded `kind: hook` plugin |
| Hook transport missing | `module: webhook` without `settings.url`, or `module: socket` without `settings.path` |
| Hook `webhook` SSRF-blocked | RFC-1918, CGNAT, link-local, and metadata hosts are blocked in `settings.url` (loopback allowed) |
| `prompt: rw` on a `kind: tap` hook | A tap observes; it can never rewrite |
| Groups tree faults | A `parent` that does not exist (paste-ready stub), a cycle (the path is printed), or a chain deeper than 8 |
| Malformed group limit | A limit without exactly one metric key, a windowed metric without `per:`, or `concurrent` with a `per:` |
| Breaker `max_cooldown < base_cooldown` | Cooldown ceiling below the base |
| Rate card incomplete | `rate_card` present but missing an entry for a configured model (a paste-ready zeroed stub of the missing models is printed) |
| `auth.chain` names an unknown module | Every chain entry must be the built-in `keys` or a loaded `kind: auth` plugin |
| `role_bindings` faults | A binding under a module not in any chain, or a bound `group` that does not exist in `groups:` |
| Admin token blank | The `admin-tokens` `token` secret reference resolves to a blank/whitespace-only value |
| Exposed admin without mTLS | A non-loopback `admin_listen` without `admin_tls.client_ca`, unless `admin_insecure: true` is set deliberately |
| `${VAR}` unset in config | Unresolvable interpolation reference |
| `${}` or unclosed `${` | Malformed interpolation syntax |

**Warnings (non-fatal):**

| Condition |
|---|
| `chain: []` (open front door): no client authentication, development only |
| `upstream_credentials: passthrough` with a provider whose credential reference resolves non-empty (credential-leak risk) |
| Heterogeneous pool (members span more than one backend protocol, cross-protocol translation applies) |
| A provider `api_key` reference resolves empty at boot (lane will fail auth) |
| `allowed_pools` on a virtual key (admin API) names a pool not currently configured |
| The ephemeral `memory` store with minted keys: keys, usage, and the revocation denylist reset on restart (choose a durable `store.module` for persistence) |

---

## Migrating a 1.4.x config

The config format is an operator artifact outside the SemVer freeze; it changed shape in 1.5.0
WITH tooling:

1. `busbar --migrate-config old-config.yaml > config-1.5.yaml`: mechanically converts every
   deterministic change and prints `# TODO(migrate)` / `# WARNING(migrate)` comments where a human
   must decide. The loudest warning: every `allowed_pools: []` occurrence, whose meaning FLIPPED
   (it used to mean all pools, it now means NO pools).
2. Review the TODO/WARNING items, then `busbar --validate` the result.
3. Re-mint every virtual key (`POST /api/v1/admin/keys`): 1.4.x bearer secrets and static
   `client_tokens` no longer authenticate. 1.5.0 keys are signed tokens that expire (default 90
   days), the release's security headline.

Booting a 1.x config directly REFUSES with a named error pointing at the migrator; nothing from
1.x can boot-and-silently-flip semantics.
