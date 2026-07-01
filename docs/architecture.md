# Architecture

This document traces a request end-to-end and explains the two seams that make
busbar's thesis, *protocols, not providers*, work: the **superset IR** with its
`ProtocolReader` / `ProtocolWriter` traits, and the **two-stage failure-disposition
pipeline**.

## Request lifecycle

```
                client (any protocol)
                        │
                        ▼
        ┌────────────────────────────────────────────────┐
        │  HTTP router (axum)                              │
        │  route fixes ingress protocol (one per proto):   │
        │   /<...>/v1/messages          → anthropic        │
        │   /v1/chat/completions        → openai           │
        │   /v1/responses               → responses        │
        │   /v2/chat                    → cohere           │
        │   /v1/models/{model}:...      → gemini           │
        │   /v1beta/models/{model}:...  → gemini           │
        │   /model/{id}/converse[-stream] → bedrock        │
        └───────────────┬──────────────────────────────────┘
                        ▼
        ┌───────────────────────────────────┐
        │  auth middleware                   │
        │   token | passthrough | none, OR   │
        │   virtual-key lookup (governance)  │
        └───────────────┬───────────────────┘
                        ▼
        ┌───────────────────────────────────┐
        │  governance checks (if enabled)    │
        │   allowed-pools (403)              │
        │   budget       (429 / 400 bedrock)│
        │   rate limit   (429 + Retry-After)│
        └───────────────┬───────────────────┘
                        ▼
        ┌───────────────────────────────────┐
        │  pool/lane selection               │
        │   affinity preference → SWRR over  │
        │   the healthy candidate subset     │
        └───────────────┬───────────────────┘
                        ▼
        ┌───────────────────────────────────┐
        │  per-attempt (up to failover cap): │
        │   1. translate request (IR) if     │
        │      ingress proto ≠ lane proto    │
        │   2. rewrite model, inject creds   │
        │      (bearer / api-key / SigV4)    │
        │   3. POST upstream                 │
        │   4. classify outcome → disposition│
        │       ├─ 2xx        → stream/relay │
        │       ├─ client 4xx → relay, no    │
        │       │               penalty      │
        │       ├─ transient  → trip-eval,   │
        │       │               failover     │
        │       ├─ hard-down  → dead lane    │
        │       │   (auth → relay; billing → │
        │       │    failover)               │
        │       └─ context-len→ exclude small│
        │                       lanes, retry │
        └───────────────┬───────────────────┘
                        ▼
        ┌───────────────────────────────────┐
        │  response                          │
        │   same proto  → passthrough        │
        │   cross proto → translate each SSE │
        │     (or eventstream) frame to the  │
        │     caller's protocol              │
        │   tap usage → charge virtual key   │
        └───────────────┬───────────────────┘
                        ▼
                     client
```

### 1. Ingress & protocol detection

The route table (`src/main.rs` `build_router`, `src/route.rs`) determines the
**ingress protocol** by path, not by sniffing the body. All six protocols are
first-class ingress, one handler per protocol (Gemini's handler is reachable via
two path prefixes, `v1` and `v1beta`):

- `POST /{name}/v1/messages` → ingress `anthropic`. `name` is a model or a pool.
- `POST /{provider}/{model}/v1/messages` → ingress `anthropic`, ad-hoc direct route.
- `POST /v1/chat/completions` → ingress `openai`. The body's `model` field names the
  model or pool.
- `POST /v1/responses` → ingress `responses` (OpenAI Responses API). Model in the body.
- `POST /v2/chat` → ingress `cohere`. Model in the body.
- `POST /v1/models/{*rest}` and `POST /v1beta/models/{*rest}` → ingress `gemini`. Both the
  stable `v1` and the `v1beta` path prefixes are accepted by the same handler, because the
  google-generativeai / Gen AI SDKs use either surface. The model and the action
  (`:generateContent` / `:streamGenerateContent`) are packed into the last path
  segment after a `:`; axum can't split on `:` inside a segment, so the tail is
  captured with a wildcard and split in `gemini_ingress`.
- `POST /model/{model_id}/converse` and `/model/{model_id}/converse-stream` → ingress
  `bedrock`. The model is in the path; the streaming variant is selected by the
  endpoint suffix.

This splits cleanly into **body-model protocols** (`openai`, `responses`, `cohere`, the model/pool lives in the request body) and **path-model protocols**
(`anthropic`, `gemini`, `bedrock`: the model/pool lives in the URL). A small
injection shim normalises both into the same internal model/pool selection so the
rest of the pipeline is protocol-agnostic.

Management/observability routes (`/stats`, `/healthz`, `/metrics`,
`/admin/keys...`) are handled separately.

### 2. Authentication

`auth_middleware` (`src/auth.rs`) runs before routing:

- `/healthz` is always open (liveness probes must not require a token).
- `/metrics` is **not** exempted, Prometheus telemetry (lane/pool topology,
  per-protocol counters, error rates) is an information-disclosure surface, so it
  goes through the same auth check as any other route. It requires a valid client
  token in `token` mode (or a virtual key under governance), and is admitted
  unconditionally only in `none`/`passthrough` mode. Restrict at the network layer
  if you need unauthenticated scraping.
- `/admin/*` requires the governance **admin token** (as `Authorization: Bearer` or
  `X-Admin-Token`); disabled (401) if no admin token is configured.
- With **governance enabled**, the caller's bearer token must resolve to an enabled
  virtual key, which is attached to the request for downstream ACL/budget checks.
- With governance disabled, the static `AuthMode` applies (`token` allowlist,
  `passthrough`, or `none`). The caller's bearer token is threaded through for
  passthrough forwarding.
- **Bedrock ingress** has two modes depending on governance:
  - *Without governance* (`passthrough` or `none`): `extract_client_token` reads only bearer-style carriers and ignores the SigV4 header, which is forwarded upstream (passthrough) or ignored (none).
  - *With governance* (`token` mode + `governance.enabled: true`): `src/auth.rs` `verify_bedrock_sigv4` intercepts requests that carry `Authorization: AWS4-HMAC-SHA256`, verifies the full SigV4 signature plus body-hash integrity (`x-amz-content-sha256`), and, on success, attaches the resolved virtual key's `GovCtx` so all governance checks apply. The AWS credential pair (`aws_access_key_id` + `aws_secret_access_key`) is minted via `POST /admin/keys` with `"issue_aws_credential": true`. Note: `src/sigv4.rs` provides signing primitives; the inbound verifier lives in `src/auth.rs`.

### 3. Governance checks

When a virtual key is resolved, the route handler enforces, in order:
allowed-pools (`403`), budget (`429`, or `400` for Bedrock ingress), and rate
limits (`429` + `Retry-After`) *before* forwarding. Budget exhaustion does **not**
emit `402`: no upstream vendor returns `402` for an over-quota condition, so a
`402` would be a router-side tell. Instead each ingress writer maps to its native
quota shape: `429` (`insufficient_quota`) for OpenAI / Responses / Anthropic /
Gemini / Cohere, and `400` (`ServiceQuotaExceededException`) for Bedrock. The flat
per-request fee is charged at request completion;
token-based spend is charged when the response stream completes (token-accurate
accounting). See [operations.md](operations.md).

### 4. Pool / lane selection

For a pool target, `forward_with_pool` (`src/forward.rs`) selects a member:

1. **Affinity preference**: if a session header is present and the sticky member is
   usable, use it; otherwise fall through.
2. **Exclusions**: configured `failover.exclusions` and already-tried lanes (across
   failover hops) are removed from the candidate set.
3. **SWRR**: `select_weighted` (`src/store.rs`) runs Nginx-style smooth weighted
   round-robin over the *usable* candidates, using per-pool `current_weight` state.
   A lane is usable only if it isn't dead, isn't out of lifetime budget, and its
   breaker cell admits it.
4. **Concurrency**: the selected lane's semaphore permit is acquired (a lane at its
   `max_concurrent` cap is skipped/awaited).

A direct/ad-hoc route is the degenerate case: a single-member candidate set of
weight 1.

### 5. Cross-protocol translation (the IR seam)

If the ingress protocol differs from the selected lane's protocol, busbar
translates the **request** through the superset IR:

```
ingress.reader().read_request(body)  →  IrRequest  →  lane.writer().write_request(ir)
```

The IR (`src/ir.rs`) is a superset of all six protocols' representable content:
system blocks, messages with text / thinking (+signature) / tool-use / tool-result
/ image blocks, tools (name + description + JSON schema), `max_tokens`,
`temperature` (held as `f64` so a caller's value never silently mutates), a `stream`
flag, and an `extra` passthrough map for fields outside the modeled subset
(`top_p`, etc.). Same-protocol requests skip the IR entirely and pass through
byte-for-byte.

`ProtocolReader` and `ProtocolWriter` (`src/proto/mod.rs`) are the per-protocol
edges:

- **`ProtocolReader`**: `read_request` (wire → IR), `read_response` /
  `read_response_event(s)` (wire → IR, with stateful fan-out for flat streams like
  OpenAI's), and `extract_error` / `classify` (the breaker's Stage 1).
- **`ProtocolWriter`**: `write_request` (IR → wire), `write_response` /
  `write_response_event` (IR → wire), `rewrite_model`, `upstream_path[_for[_stream]]`,
  and the **auth hooks**: `auth_headers(key)` for static headers and
  `sign_request(key, ctx)` for per-request signing (overridden by Bedrock for
  SigV4). It also provides `probe_body`: a one-token request used by active health
  probes, so every protocol gets a valid probe for free.

A `Protocol` bundles a name + reader + writer; the `ProtocolRegistry` resolves them
by name at startup. This is the entire reason a "provider" needs no code: any
backend speaking a known protocol is just a catalog row.

### 6. Upstream auth & dispatch

The handler builds the upstream URL (`base_url` + the protocol's path, or the
provider's `path` override), selects the key (lane key, or the caller's key in
passthrough mode), and computes auth via `sign_request` against a `SigningContext`
(host, canonical URI, body, timestamp). For most protocols this is static headers;
for Bedrock it computes AWS SigV4 with the region parsed from the host. The model
field is rewritten to the selected lane's model.

### 7. Two-stage failure disposition

Every non-2xx upstream response is run through a pipeline that decides **who is at
fault** and therefore what to do (`src/forward.rs`, `src/breaker.rs`):

```
Stage 1a  proto.reader().extract_error(status, body)  → RawUpstreamError
Stage 1b  normalize_raw_error(raw, provider.error_map) → CanonicalSignal (StatusClass)
Stage 2   classify_disposition(signal)                 → Disposition
```

`Disposition` is matched **exhaustively** (a project invariant: no `_ =>` catch-all
in breaker matches):

| Disposition | Cause (StatusClass) | Lane effect | Request effect |
|---|---|---|---|
| `ClientFault` | client 4xx (400/404/422, context-aside) | none (tracked separately as `client_fault`) | relay verbatim to caller |
| `TransientUpstream` | 5xx, timeout, network, overloaded, rate-limit | trip evaluation + cooldown (rate-limit honors Retry-After) | **failover** to next candidate |
| `HardDown` | billing/quota, auth (401/403) | lane marked dead (breaker trip) | auth → relay error to caller; billing → failover |
| `ContextLength` | context-length-exceeded | none (lane was healthy) | exclude ≤-context candidates, failover to a larger lane |

This is the core correctness property: **a healthy backend is never ejected because
a caller sent a bad request.** In `passthrough` mode, a `401`/`403` is the *caller's*
key failing, so it is relayed verbatim without touching lane health.

### 8. Response translation & usage accounting

On success, the response is streamed (SSE or Bedrock event-stream) or buffered:

- **Same protocol**: passthrough; native usage accounting and provider-specific
  fields survive untouched.
- **Cross protocol**: `StreamTranslate` (`src/proto/mod.rs`) composes
  `egress.reader().read_response_events` with
  `ingress.writer().write_response_event`, re-framing each upstream event into the
  caller's wire format. It reassembles frames split across chunks, threads stream
  decode state, decodes Bedrock's binary `application/vnd.amazon.eventstream` on
  egress and re-encodes it (CRC32-valid frames) for Bedrock ingress, and emits the
  correct ingress terminator (`data: [DONE]` for OpenAI; Anthropic's
  `message_stop` carries its own).

In both cases a usage tap reads token counts from the response (protocol-agnostic
extraction across all six wire shapes), and, when governance is on, charges the
resolved virtual key's budget at stream completion. Failover is only possible
*before the first byte* reaches the client; a mid-stream upstream failure records
the breaker fault and emits a native error in the caller's protocol, an SSE
`error` event for SSE clients, a binary `:message-type: exception` frame for
Bedrock-ingress (AWS eventstream) clients.

## Circuit-breaker state

Breaker state is **per-(pool, lane)**, stored in `src/store.rs`. The FSM is Closed →
Open → HalfOpen → Closed, with exponential cooldown backoff and single-flight
half-open probing. See [operations.md](operations.md) for the full state machine,
trip modes, and recovery behavior.

## Observability hooks

Metrics are emitted at the ingress boundary (`busbar_requests_total`, the duration
histogram) and at each upstream attempt/failure/trip/failover/translation
(`src/metrics.rs`, `src/forward.rs`). Optional OTLP spans and a request-log webhook
are configured via the `observability` section.
