# Config at a glance

Every top-level key of `config.yaml` (busbar 1.5.0), what it owns, and its shape: one page, no
prose. The full reference with defaults, validation rules, and worked examples is
[configuration.md](configuration.md); the canonical bootable example is
[`examples/clean-config-1.5.0.yaml`](../examples/clean-config-1.5.0.yaml).

Design rules the whole surface follows: the object that OWNS a concept is the only place it is
defined; every loadable unit is `module` + `settings`; every secret is a reference
(`{ env: VAR }` / `{ file: /path }` / `{ module: <secret-plugin>, settings: {...} }`); an OMITTED
list means "all", an explicit `[]` means "none"; windows are nouns
(`minute|hour|day|month|total`); `on_X` handlers are a bare keyword or a structured ref; unknown
keys fail boot.

## Transport

| Key | Owns | Shape / default |
|---|---|---|
| `listen` | The data-plane bind | `"0.0.0.0:8080"` (default) |
| `admin_listen` | The admin-plane bind (always its own listener) | `"127.0.0.1:8081"` (default; loopback) |
| `admin_insecure` | Waive the exposed-admin-requires-mTLS boot guard | `false` (default; deliberate opt-in) |
| `tls` | Inbound TLS/mTLS for the data plane | `{ cert: <secret-ref>, key: <secret-ref>, client_ca?: <secret-ref> }`; absent = plain HTTP |
| `admin_tls` | TLS/mTLS for the admin listener | Same shape; `client_ca` present = admin mTLS. A non-loopback `admin_listen` without it refuses to boot (unless `admin_insecure`) |

## Identity: `auth`

| Key | Owns | Shape / default |
|---|---|---|
| `auth.signing_key` | The ed25519 key that signs virtual-key tokens (fleet-shared; rotate = revoke-all) | Secret ref; absent = generated 0600 on first boot |
| `auth.upstream_credentials` | Whose key hits the provider | `own` (default) \| `passthrough` |
| `auth.chain` | The ordered DATA-PLANE auth chain | List of module entries: `- keys` (bare, the built-in signed-key verifier) or `- <module>: { max_admin_scope?, settings? }`. `[]` (default) = open front door (dev only) |
| `auth.admin_auth` | The chain gating `/api/v1/admin/*` | Default `[admin-tokens]`; the built-in carries `token: <secret-ref>`. `[]` = open admin (dev only) |
| `auth.role_bindings` | Role policy, NESTED BY MODULE (pure auth) | `<module>: { <role>: { allowed_pools?, group?, admin_scope? } }`. Omitted `allowed_pools` = all pools, `[]` = none; `admin_scope` = `read-only\|hooks-register\|full` |

Keys themselves are minted over the admin API (`POST /api/v1/admin/keys`), not configured: a
minted key is a signed expiring token bound to at most one group.

## Limits: `groups`

The ONE limit tree. Keys carry no limits; every cap lives here.

```yaml
groups:
  <name>:
    parent: <group>          # optional; acyclic, depth <= 8
    enabled: true            # false = freeze this group (and every descendant's traffic)
    limits:
      - { requests: 500, per: minute }   # requests|tokens|budget need a per: window
      - { budget: 1000000, per: month }
      - { concurrent: 5 }                # instantaneous in-flight cap: NO per:
```

Chain-AND enforced at admission (atomic, all-or-nothing); rejections name the exact blocking
bucket (group + metric + window).

## Pricing: `rate_card` + `per_request_fee`

| Key | Owns | Shape / default |
|---|---|---|
| `rate_card` | The ONLY cost source: per-model, per-tier token rates (abstract MICRO-units/token) | `<model>: { input_utok, output_utok, cache_read_utok, cache_write_utok }`. ALL-OR-NOTHING: absent = tokens price 0; present = must cover every configured model |
| `per_request_fee` | Flat abstract cents charged per request at admission | `0` (default) |

## Durability: `store`

| Key | Owns | Shape / default |
|---|---|---|
| `store.module` | The durable store plugin (keys, ledger, audit, denylist) | `memory` (default, compiled-in, ephemeral) \| `sqlite` \| `postgres` \| `redis` \| a third-party store plugin name |
| `store.settings` | The store module's OWN opaque config | sqlite: `{ db_path, busy_timeout_ms? }`; postgres/redis: `{ url }` |

## Routing surface: `providers`, `models`, `pools`, `global_hooks`

| Key | Owns | Shape / default |
|---|---|---|
| `providers.<name>` | A deployment of a catalog provider | `{ api_key: <secret-ref>, protocol?, base_url?, error_map?, path?, path_base?, auth?, token_url?, scope?, health?, allow_metadata_hosts? }` |
| `models.<name>` | One lane (model at a provider) | `{ provider, max_concurrent?, max_requests?, default_max_tokens?, upstream_model?, attempt_timeout_ms?, reasoning?, prompt_caching? }` |
| `pools.<name>.members` | Weighted lane membership | `[{ model, weight?, context_max?, tier?, tags?, attempt_timeout_ms?, reasoning? }]` (no cost fields: pricing lives on `rate_card`) |
| `pools.<name>.hooks` | Ordering strategy + gates, inline, ordered | Bare strategy (`weighted\|cheapest\|fastest\|least_busy\|usage`, at most one) and/or module refs `{ module: webhook\|socket\|<hook-plugin>, settings: { url\|path, ... }, kind?, timeout_ms?, on_error?, on_empty?, prompt?, user?, priority?, at? }` |
| `pools.<name>.breaker` | Per-(pool, lane) circuit breaking | `{ base_cooldown_secs, max_cooldown_secs, trip: { mode: error_rate\|consecutive, window_secs, threshold, min_requests, consecutive_n } }` |
| `pools.<name>.failover` | Per-request retry budget | `{ timeout_secs, max_hops, exclusions? }` |
| `pools.<name>.on_exhausted` | All-members-down behavior | `reject` (default) \| `least_bad` \| `{ fallback_pool: <pool> }` |
| `pools.<name>.affinity` | Session pinning | `{ mode: session, header_name? }` (default header `x-session-id`) |
| `global_hooks` | Hook instances firing on EVERY request, ordered | Module refs only (same shape as pool refs; default `kind: tap`) |

## Plugins: `plugins`

| Key | Owns | Shape / default |
|---|---|---|
| `plugins.enabled` | MASTER SWITCH | `false` (default): no plugin ever loads |
| `plugins.dir` | Where signed tarballs live | `plugins` (default) |
| `plugins.trust` | Signature policy | `{ publishers: [{name, public_key}], allow_unsigned: false, allow_third_party: false }` (busbar's release key is embedded; untrusted plugins are never dlopened) |
| `plugins.min_versions` | Anti-downgrade floors | `<plugin-name>: "<min version>"` (first-party auto-floored at the binary version) |

## Operational: `security`, `observability`, `limits`, `metrics`, `health`, `routing`, `advanced`

| Key | Owns | Shape / default |
|---|---|---|
| `security` | SSRF metadata denylist tuning | `{ blocked_metadata_hosts: [], allow_metadata_hosts: [], allow_all_metadata: false }` |
| `observability` | Opt-in sinks | `{ otlp_url?, request_log_webhook_url?, max_inflight_webhook_deliveries: 64, webhook_delivery_timeout_secs: 2, emit_server_timing: false }` |
| `limits` | Global operational caps | `{ upstream_request_timeout_secs: 300, request_body_max_bytes: 33554432, pool_max_idle_per_host: 1024, pool_idle_timeout_secs: 300, max_inbound_concurrent: 8192, hard_down_cooldown_secs: 1800, upstream_error_body_max_bytes: 262144, tls_handshake_timeout_secs: 10, request_body_read_timeout_secs: 30, max_honored_retry_after_secs: 86400, default_max_tokens: 4096, reasoning_effort_budgets: { minimal: 1024, low: 4096, medium: 8192, high: 16384 } }` |
| `metrics` | Scrape tunables | `{ key_gauge_limit: 2000 }` |
| `health` | Process-wide probe fallbacks | `{ default_probe_interval_secs: 30, default_probe_timeout_secs: 5 }` |
| `routing` | Global default gate deadline | `{ default_policy_timeout_ms: 1 }` |
| `advanced` | Internal tuning (normally omitted) | `{ rate_sweep_interval: 256, usage_flush_interval_ms: 100 }` |

## Not config (but adjacent)

- **Minting keys**: `POST /api/v1/admin/keys` with `{ name, group?, allowed_pools?, labels?,
  expires_in|expires_at?, issue_aws_credential? }`; the signed token is shown once and expires
  (default 90 days).
- **Migrating from 1.4.x**: `busbar --migrate-config old.yaml` prints the converted config with
  TODO/WARNING comments; booting a 1.x config refuses with a named error.
- **Validation**: `busbar --validate` runs the exact boot pipeline (config + plugins) with zero
  side effects; a clean validate means a clean boot.
