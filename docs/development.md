# Development, onboarding & workflow

Developer-facing guide to building, testing, and extending busbar. For the
operator/runtime view see [operations.md](operations.md) and
[configuration.md](configuration.md); for the public request-lifecycle overview
see [architecture.md](architecture.md); for the design deep-dive see
[internals.md](internals.md) and the [ADRs](adr/).

Contribution mechanics (PR checklist, formatting, the exhaustive-match invariant)
live in [CONTRIBUTING.md](../CONTRIBUTING.md), this doc covers the codebase map
and the two common extension tasks.

---

## Repo layout, `src/` module map

| Module | Owns |
|---|---|
| `main.rs` | Startup. Loads `providers.yaml` + `config.yaml` (with `${ENV}` interpolation), `resolve()`s them, validates, builds lanes/pools/`App`, wires governance + observability + plugins, spawns health probers, and builds both listeners (the data-plane axum router and the separate admin router). |
| `config/mod.rs` | The deploy/provider/pool schema (`DeployCfg`, `ProviderDef`, `ProviderDeploy`, `ModelCfg`, `PoolCfg`, `PoolMember`, `FailoverCfg`, `AffinityCfg`, `BreakerCfg`, `HealthCfg`, `GovernanceCfg`, `ObservabilityCfg`, `PluginsCfg`, `OnExhausted`), `${ENV}` interpolation, and `resolve()` (merge catalog def + deployment override). `config/overlay.rs` handles the live config-apply overlay. |
| `config_validate/` | Post-resolve config validation (fail-loud diagnostics before lanes are built), including the SSRF host guard shared with the webhook path. |
| `state.rs` | Runtime types: `Lane`, `WeightedLane`, `PoolRuntime`, and the `App` shared state. Re-exports `StateStore` from `store/`. |
| `ingress/mod.rs` | Axum handlers, one per ingress protocol: `openai_ingress` (`/v1/chat/completions`), `cohere_ingress` (`/v2/chat`), `responses_ingress` (`/v1/responses`), `gemini_ingress` (`/v1/models/{*rest}` and `/v1beta/models/{*rest}`, both prefixes route to the same handler), `bedrock_converse` / `bedrock_converse_stream` (`/model/{model_id}/converse[-stream]`), `named` (`/{name}/v1/messages`), `adhoc` (`/{provider}/{model}/v1/messages`); the shared `ingress_body_model` body/path-model resolution; governance pre-checks; affinity-header resolution. `ingress/dispatch.rs` carries the operation-level dispatch. |
| `auth/mod.rs` | `AuthMiddleware` and the `auth_middleware` layer: it runs the data-plane `auth.chain` (an ordered list of `AuthModule`s; an empty chain is the open front door), opens `/healthz`, gates `/metrics` like any other route, resolves virtual keys, and threads the caller token. `UpstreamCreds` (`Own` / `Passthrough`) is the separate egress-credential mode. The old `AuthMode` enum is gone. Constant-time token compare lives in the `busbar-api` auth contract. |
| `proxy/engine/mod.rs` | The forwarding engine: `forward` / `forward_with_pool` (selection → translate → sign → POST → classify → stream/failover), `RequestCtx` (deadline + exclusions + visited-pools), the before-first-byte failover boundary + cross-protocol stream wiring, `lane_auth_headers` (the `api-key` auth-adapter seam), and the `on_exhausted` handlers (`Status503`/`FallbackPool`/`LeastBad`). `proxy/select.rs`, `proxy/egress.rs`, `proxy/hooks.rs`, and `proxy/usage.rs` split out selection, egress, the hook seam, and usage metering. |
| `breaker.rs` | The protocol-agnostic Stage 1b/2 classifier: `StatusClass`, `Disposition`, `RawUpstreamError`, `CanonicalSignal`, `normalize_raw_error`, `classify` (exhaustive). |
| `store/mod.rs` | The breaker FSM + lane state: `StateStore` trait, `LaneState`, `BreakerCell` / `BreakerCellAccess`, `OutcomeWindow`, SWRR `select_weighted`, the lane-default vs `_in(pool, …)` method split, `BreakerCfg`/`TripConfig`, test time injection. The concrete `InMemoryStore` is in `store/in_memory.rs`. (This is the runtime breaker store, distinct from the governance `Store` trait below.) |
| `ir/mod.rs` | The superset IR (ADR-0005): `IrRequest`, `IrResponse`, `IrMessage`, `IrBlock`, `IrTool`, `IrUsage`, `IrStreamEvent`, `IrDelta`, `StreamDecodeState`. Modality-specific IR (audio, image, embeddings, moderation, rerank) sits in sibling files under `ir/`. |
| `proto/mod.rs` | The protocol seam: `ProtocolReader` / `ProtocolWriter` traits, `Protocol`, `ProtocolRegistry`, `SigningContext`, `probe_body` default. `proto/detect.rs` sniffs the ingress protocol; `proto/openai_family.rs` holds the shared OpenAI-family bits; `proto/stream.rs` is the cross-protocol stream translator and SSE reframing. |
| `proto/{anthropic,openai_chat,openai_responses,gemini,bedrock,cohere}/` | One folder-module per protocol: each holds the Reader (wire→IR + error extraction) and Writer (IR→wire + auth + paths). Bedrock's writer overrides `sign_request` for SigV4. |
| `sigv4.rs` | Hand-rolled AWS SigV4 (RustCrypto sha2 + hmac, no AWS SDK): `sign_v4`, `signing_key`, `uri_encode_path`, `format_amz_time`, `sha256_hex`. |
| `governance/mod.rs` | Virtual keys + budgets + rate limits (ADR-0009): `GovState`, `VirtualKey`, budget/rate windows, key hashing, and the token-ledger cost model. The governance `Store` trait itself lives in the `busbar-api` crate (`crates/api/src/store.rs`); concrete backends are separate crates (`busbar-store-memory` compiled in by default, `busbar-store-sqlite` / `-postgres` / `-redis` as static or dynamically-loaded plugins chosen by `governance.store`). |
| `admin/` | The admin API: `admin/mod.rs` mounts the `/api/v1/admin/*` handlers (keys, usage, config, hooks, plugins) on the separate admin listener, `admin/v1/` is the frozen JSON contract, and `admin/rate.rs` / `admin/audit.rs` carry admin rate-limiting and the hash-chained audit log. |
| `health.rs` | Active health probing (`spawn_probers`, `probe_lane` using each protocol's `probe_body`) and the `/stats` + `/healthz` handlers. |
| `metrics.rs` | Prometheus recorder init + the `busbar_*` metric name constants. |
| `observability.rs` | Optional OTLP tracer init + the fire-and-forget request-log webhook (with its own SSRF guard). |
| `eventstream.rs` | Codec for Bedrock's binary `application/vnd.amazon.eventstream` frames: `drain_frames` decodes ConverseStream responses; `encode_frame`/`encode_exception_frame` re-encode CRC32-valid frames for Bedrock-ingress streaming. |
| `test_support/` | `#[cfg(test)]` in-crate mock-upstream harness (`MockServer`, `MockServerState`, `MockResponse`). Each module also carries its own `#[cfg(test)] mod tests`. See [testing.md](testing.md). |

---

## Build / test / lint

Single Rust binary, stable toolchain, edition 2021.

```bash
cargo build                                   # debug build
cargo build --release                         # release binary -> target/release/busbar
cargo test                                    # full in-crate suite
cargo clippy --all-targets -- -D warnings     # lints must be clean (treat warnings as errors)
cargo fmt --all                               # format (rustfmt.toml in repo)
```

The test suite is **in-crate**: a shared
`#[cfg(test)] mod test_support` provides the `MockServer` harness, and each module
carries its own `#[cfg(test)] mod tests`. There are no `tests/` integration
binaries: everything runs under `cargo test`. See [testing.md](testing.md).

---

## Running locally

Busbar reads two YAML files, located via env vars:

| Env var | Default | Purpose |
|---|---|---|
| `BUSBAR_PROVIDERS` | `/etc/busbar/providers.yaml` | The verified provider catalog (shipped). |
| `BUSBAR_CONFIG` | `/etc/busbar/config.yaml` | Your deployment. |

Both files support `${VAR}` interpolation expanded at load time; an unset
referenced variable is a hard startup failure. Provider keys are supplied via the
env vars named by each provider's `api_key_env`, never written into the files.

```bash
export BUSBAR_CLIENT_TOKEN=dev-token
export ANTHROPIC_KEY=sk-ant-...
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml cargo run
curl -s localhost:8080/healthz
curl -s -H "Authorization: Bearer $BUSBAR_CLIENT_TOKEN" localhost:8080/stats | jq
```

Full field reference: [configuration.md](configuration.md).

---

## Adding a new protocol

A protocol is the unit of busbar's scope (the count to grow is **6**, not the
provider count). To add one:

1. **Implement `ProtocolReader`** (`crates/busbar/src/proto/mod.rs` defines the trait):
   - `read_request(body) -> IrRequest`: wire JSON → IR (ADR-0005 contract: model
     every field you can; stash adjacent fields in `IrRequest.extra`; hold
     `temperature` as the f64 it already is).
   - `read_response(body) -> IrResponse` and `read_response_event(s)`, wire → IR.
     For a flat stream, use the `&mut StreamDecodeState` to synthesize the IR's
     block boundaries (one chunk → `0..n` events); for a 1:1 stream, ignore it.
   - `extract_error(status, body) -> RawUpstreamError`, Stage 1a: pull out the
     HTTP status and any in-body `provider_code`.
   - `classify`, the simple two-stage convenience wrapper.
   - `clone_box`.
2. **Implement `ProtocolWriter`**:
   - `write_request(ir) -> Value`, `write_response(ir)`, `write_response_event(ir)`
    : IR → wire.
   - `rewrite_model(body, model)`, set the selected lane's model on the body.
   - `upstream_path` (+ optionally `upstream_path_for` / `upstream_path_for_stream`
     if the path embeds the model or differs for streaming, as Gemini's does).
   - `auth_headers(key)` for static headers; override `sign_request(key, ctx)` only
     if the protocol signs the whole request (as Bedrock does for SigV4).
   - You get `probe_body` **for free** from the default impl: it serializes a
     one-token IR request through your own `write_request`, so active health
     probing works with no extra code.
   - `clone_box`.
3. **Register it** in `crates/busbar/src/proto/mod.rs`: add a `Protocol::<name>()` constructor,
   a `protocol_for` arm, and an entry in `ProtocolRegistry::with_builtins`. Add the
   `StreamTranslate::new` flags if it has a non-SSE wire (like Bedrock's binary
   eventstream) or a special terminator.
4. **IR contract:** the IR is a superset. If your protocol introduces a content
   kind the IR can't represent, extend the `IrBlock` / event enums: and then every
   other writer must handle the new variant (the exhaustive matches will tell you).
5. **Test it** through the `MockServer` harness and the cross-protocol round-trip
   tests in `crates/busbar/src/proto/mod.rs` (`test_probe_body_valid_for_all_protocols` already
   asserts every protocol produces a valid probe body).

The `Reader`/`Writer` files (`crates/busbar/src/proto/<name>/`) are the only per-protocol code;
the registry + IR + forward path are protocol-agnostic.

---

## Adding a new provider

A provider is **just a catalog entry**: no code. Add it to `providers.yaml`:

```yaml
my-provider:
  protocol: openai            # one of the 6 implemented protocols
  base_url: https://api.example.com
  error_map:                  # optional: map vendor codes -> StatusClass (Stage 1b)
    "insufficient_quota": billing
  path: /chat/completions     # optional: override the protocol's default path
  auth: api-key               # optional: 'bearer' (default) | 'api-key'
  health:                     # optional: active probing
    mode: dead                # none | dead | active
    interval_secs: 30
    timeout_secs: 5
```

Then reference it from `config.yaml` (supplying only the env var that holds the
key) and point a model at it:

```yaml
providers:
  my-provider:
    api_key_env: MY_PROVIDER_KEY
models:
  my-model:
    provider: my-provider
    max_concurrent: 20
```

Notes on the seams:

- **`error_map`** is the data-driven Stage 1b override (see
  [internals.md](internals.md#3-the-two-stage-disposition-pipeline-adr-0002)). Keys
  are the provider's in-body codes; values are `StatusClass` strings
  (`billing`, `rate_limit`, `auth`, `server_error`, `timeout`, `network`,
  `overloaded`, `context_length`, `client_error`). The deployment's `error_map`
  in `config.yaml` merges over the catalog's.
- **`path`** overrides the protocol's default upstream path verbatim: used by
  OpenAI-compatible providers that embed the API version in `base_url` and serve
  `/chat/completions` (no `/v1`), and by Azure (which carries `?api-version=` and
  the deployment in the path).
- **`auth: api-key`** is the **auth-adapter seam** (`lane_auth_headers` in
  `proxy/engine/mod.rs`): it sends an `api-key: <key>` header instead of the protocol's
  native auth (used by Azure OpenAI). For genuinely new auth shapes (e.g. an OAuth2
  token mint), the seam to extend is `ProtocolWriter::sign_request`, the same hook
  Bedrock uses for SigV4: see the roadmap in [roadmap.md](roadmap.md).

`resolve()` (`crates/busbar/src/config/mod.rs`) merges the deployment over the catalog def; a
`config.yaml` provider name not present in `providers.yaml` is a fail-loud startup
error.

---

## Coding conventions observed

These are conventions visible in the code; treat the [CONTRIBUTING.md](../CONTRIBUTING.md)
checklist as authoritative.

- **SPDX header.** Every `src/**/*.rs` file (including each `proto/<name>/` module) starts with
  `// SPDX-License-Identifier: Apache-2.0` + `// Copyright (C) 2026 Busbar Inc and contributors`.
- **No `_ =>` catch-all in the disposition/breaker matches.** The exhaustive match
  on `StatusClass`/`Disposition` is how the compiler enforces that every failure
  mode is handled; the arms even use `unreachable!()` for classes that cannot
  reach a given arm. This is a stated project invariant (CONTRIBUTING.md §5).
- **`error_map` is data, not code.** Provider quirks belong in YAML, not in a
  match arm.
- **Test time is injectable, not real.** Breaker/FSM logic reads time via
  `store::now()` (the public crate function), which `InMemoryStore` internally
  wraps in a private `now_secs()` that, under `#[cfg(test)]`, is shadowed to
  delegate to `now_for_test()`; tests inject time via `store::set_now_for_test`.
  Don't call `SystemTime::now()` directly in breaker-adjacent code.
- **`#[cfg_attr(not(test), allow(dead_code))]`** marks the lane-default breaker
  methods that release code reaches only via the `_in` variants but tests exercise
  directly: keep that pattern when adding parallel default/`_in` methods.

- **No `memchr` dependency.** Byte scanning (e.g. the SSE frame splitting and
  translation-body boundary scans) is done with plain slice iteration, not the
  `memchr` crate. Keep it that way, don't add `memchr` (or pull it in transitively
  for scanning) when a small hand-rolled scan will do.
