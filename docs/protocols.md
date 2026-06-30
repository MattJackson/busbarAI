# Wire protocols and cross-protocol translation

Busbar just **listens**. Your client decides which protocol it speaks — OpenAI, Anthropic, Gemini, Bedrock, Cohere, or Responses — by which URL it calls, and Busbar accepts it. It implements all six protocols as both **ingress** (what your client speaks *to* Busbar) and **egress** (what Busbar speaks to your backend). When the two differ, Busbar translates through one internal format rich enough to hold every protocol's features — losslessly, in both directions. Your client code never changes: it speaks its own native protocol and gets its own native responses back.

This document covers:

1. [One protocol in, any backend out](#one-protocol-in-any-backend-out)
1. [What "point any SDK at one URL" means in practice](#what-point-any-sdk-at-one-url-means)
2. [The six protocols](#the-six-protocols) — ingress route, auth carrier, SDK wiring, notes
3. [Body-model vs path-model ingress](#body-model-vs-path-model-ingress)
4. [Cross-protocol translation](#cross-protocol-translation)
5. [What survives translation and what does not](#what-survives-translation-and-what-does-not)
6. [Worked example: OpenAI SDK calling Anthropic Claude](#worked-example-openai-sdk-calling-anthropic-claude)
7. [Worked example: Anthropic SDK calling a Gemini backend](#worked-example-anthropic-sdk-calling-a-gemini-backend)

---

## One protocol in, any backend out

Each request Busbar receives speaks **one** protocol — the one the client chose. You can pick *any* of the six on the way in, but a single request is exactly one of them. The important part: a pool has **no fixed input protocol**. It's just a routing target. So different clients can reach the *same* pool, each in its own protocol, and Busbar fans each request out to whichever backend in the pool serves it — translating both ways when they differ.

Say you define a pool `fast` backed by Claude Opus (an `anthropic` backend) and GPT (an `openai` backend). Each of these clients can hit it natively, with no extra configuration:

| Your client speaks | It calls | Names `fast` via | Gets back |
|---|---|---|---|
| OpenAI | `POST /v1/chat/completions` | body `{"model": "fast"}` | an OpenAI response |
| Anthropic | `POST /fast/v1/messages` | URL path | an Anthropic response |
| Gemini | `POST /v1beta/models/fast:generateContent` | URL path | a Gemini response |
| Bedrock | `POST /model/fast/converse` | URL path | a Bedrock response |
| Cohere | `POST /v2/chat` | body `{"model": "fast"}` | a Cohere response |
| Responses | `POST /v1/responses` | body `{"model": "fast"}` | a Responses reply |

Client 1 makes an **OpenAI** request to `fast`; client 2 makes a **Bedrock** request to the *same* `fast`. Each request carries one input protocol — its own — and gets its response back in that same protocol: the OpenAI client gets an OpenAI body even when Claude (Anthropic) answered. You never declare an "input protocol" on a pool; Busbar listens on all six and accepts whatever each client speaks.

**One protocol in (any of the six), any backend out.** The client picks the protocol; you pick the backends.

---

## What "point any SDK at one URL" means

Every major LLM provider ships (or is compatible with) a client SDK. Those SDKs are tightly coupled to a specific base URL and a specific wire protocol: the OpenAI Python SDK always speaks the OpenAI Chat Completions protocol; the Anthropic SDK always speaks the Anthropic Messages protocol; the Google Gen AI SDK always speaks the Gemini protocol.

Busbar registers one ingress route per protocol. Because the protocol is fixed by the URL path — not by sniffing the body or headers — you configure your existing SDK to talk to Busbar by changing exactly two things:

- **`base_url`** — point it at Busbar instead of the vendor.
- **API key** — give it a Busbar client token (or your vendor key in `passthrough` mode) instead of the vendor key.

Nothing else changes in your application code. The SDK still calls the same method (`chat.completions.create`, `messages.create`, whatever). The body it constructs is valid for its native protocol. Busbar accepts it on the matching ingress route, resolves the model/pool, and forwards — translating to the lane's protocol if necessary.

The key architectural guarantee: **Busbar's ingress is statically determined by the URL path**. Each protocol lives at its own routes. No heuristics, no body-sniffing, no content negotiation. (When nothing matches a registered route, Busbar's fallback handler defaults to the OpenAI error envelope for the 404 — but live ingress is always path-determined.)

---

## The six protocols

### `anthropic` — Anthropic Messages API

**Ingress routes:**

```
POST /{name}/v1/messages
POST /{provider}/{model}/v1/messages
```

`{name}` resolves first against your configured pools, then against your configured models. The two-segment form (`{provider}/{model}`) is an ad-hoc direct route that bypasses pool configuration and hits a specific provider+model pair directly — useful for debugging or for models you don't need to pool.

**Auth carrier (ingress):** `Authorization: Bearer <token>` or `x-api-key: <token>`. Both are accepted; bearer takes precedence. (Busbar's token-extraction precedence is `Authorization: Bearer`, then `x-api-key`, then `x-goog-api-key` — the same single Busbar token validates identically through any of those carriers.)

**Auth header (egress to Anthropic backend):** `x-api-key: <key>` (Anthropic's native carrier) by default, or `Authorization: Bearer <key>` if the provider's `auth` field is set to `bearer`. The shipped Anthropic catalog entry sets no `auth` field, so it uses the native `x-api-key`.

**Upstream path:** `POST /v1/messages`

**Key property:** Anthropic is the only protocol that **requires** `max_tokens` on every request (its writer is the only one whose `requires_max_tokens()` returns `true`). On a cross-protocol hop where the source omitted it (OpenAI, Gemini, Cohere, Responses, and Bedrock do not require it), Busbar injects the lane's `default_max_tokens` setting, or `4096` if none is configured. A caller-supplied value is always preserved verbatim.

**SDK wiring (Python):**

```python
import anthropic

client = anthropic.Anthropic(
    api_key="your-busbar-token",
    base_url="http://busbar:8080/my-pool",   # ← {name} is the pool or model
)

message = client.messages.create(
    model="ignored",   # busbar overwrites this with the selected lane's model
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
```

The Anthropic SDK appends `/v1/messages` to `base_url`, producing `POST /my-pool/v1/messages` — exactly the ingress route Busbar registers for `anthropic`.

**Note on streaming:** Anthropic ingress receives SSE (`text/event-stream`) from Busbar, regardless of which backend served the response. If the backend is Anthropic, the SSE frames pass through byte-for-byte. If it is any other protocol, Busbar re-frames the translated IR events as Anthropic SSE.

---

### `openai` — OpenAI Chat Completions

**Ingress route:**

```
POST /v1/chat/completions
```

**Auth carrier (ingress):** `Authorization: Bearer <token>`.

**Auth header (egress):** `Authorization: Bearer <key>`.

**Upstream path:** `POST /v1/chat/completions`

**Model selection:** The `"model"` field in the request body names the model or pool. Busbar reads it, resolves it against your configured pools and models, and rewrites it to the upstream model name before forwarding.

**SDK wiring (Python):**

```python
from openai import OpenAI

client = OpenAI(
    api_key="your-busbar-token",
    base_url="http://busbar:8080",
)

response = client.chat.completions.create(
    model="my-pool",     # a busbar pool or model name
    messages=[{"role": "user", "content": "Hello"}],
)
```

The OpenAI SDK appends `/v1/chat/completions` to `base_url`. Busbar resolves `"my-pool"` against pool configuration, picks a lane by SWRR, translates if the lane speaks a different protocol, and returns the response in OpenAI Chat Completions format.

**Streaming:** `stream: true` in the body. Busbar emits SSE with the `data: [DONE]` terminator the OpenAI SDK expects. Each chunk carries a stable `id`, `created`, and `model` field — replayed from the synthesis anchor so the chunk shape is indistinguishable from native OpenAI responses.

---

### `responses` — OpenAI Responses API

**Ingress route:**

```
POST /v1/responses
```

**Auth carrier (ingress):** `Authorization: Bearer <token>`.

**Auth header (egress):** `Authorization: Bearer <key>`.

**Upstream path:** `POST /v1/responses`

**Model selection:** Same as `openai` — the `"model"` field in the body.

This protocol is the newer OpenAI surface (as distinct from the older Chat Completions shape). Busbar handles it identically to `openai` in terms of routing and auth; the reader/writer pair is specialized to the Responses API's wire format.

---

### `cohere` — Cohere Chat API (v2)

**Ingress route:**

```
POST /v2/chat
```

**Auth carrier (ingress):** `Authorization: Bearer <token>`.

**Auth header (egress):** `Authorization: Bearer <key>`.

**Upstream path:** `POST /v2/chat`

**Model selection:** The `"model"` field in the request body.

**SDK wiring (Python):** Use the Cohere v2 client, which issues `POST /v2/chat`:

```python
import cohere

co = cohere.ClientV2(
    api_key="your-busbar-token",
    base_url="http://busbar:8080",
)

response = co.chat(
    model="my-pool",
    messages=[{"role": "user", "content": "Hello"}],
)
```

Busbar resolves the pool, translates if needed, and returns a Cohere-shaped response.

---

### `gemini` — Google Gemini / Gen AI

**Ingress routes:**

```
POST /v1/models/{model}:generateContent
POST /v1/models/{model}:streamGenerateContent
POST /v1beta/models/{model}:generateContent
POST /v1beta/models/{model}:streamGenerateContent
```

Both the stable `/v1/` and the beta `/v1beta/` path prefixes are accepted by the same handler (registered as `/v1/models/{*rest}` and `/v1beta/models/{*rest}`). The Google `google-generativeai` and `google-genai` SDKs use either surface depending on the version and the method called; Busbar accepts both so you do not need to know which one your SDK version issues.

**Auth carrier (ingress):** `x-goog-api-key: <token>` (the header the Gemini SDK sends). Busbar also accepts `Authorization: Bearer` on this route (any of Busbar's carriers validate the same token). Under `token` or governance mode, the value is matched against your Busbar client tokens — not forwarded to Google.

**Auth header (egress to Gemini backend):** `x-goog-api-key: <key>`.

**Upstream path:** `/v1beta/models/{model}:generateContent` (non-stream) or `/v1beta/models/{model}:streamGenerateContent?alt=sse` (stream).

**Model selection (path-model):** The model is in the URL path — not in the body. The segment after `/models/` and before the `:action` suffix is the model identifier. See [Body-model vs path-model ingress](#body-model-vs-path-model-ingress) for how Busbar handles this.

**Streaming formats:** Gemini supports two streaming framing modes:
- **SSE (`?alt=sse`)** — standard `text/event-stream`. This is what Busbar uses on the egress path. On ingress, Busbar accepts both.
- **JSON-array framing** — the default when `?alt=sse` is absent, which is what the `google-generativeai` SDK uses by default. Busbar detects the absence of `?alt=sse` on a streaming ingress request, sets a router-internal shim key (`__busbar_gemini_json_array`), and re-frames the translated response as a JSON array rather than SSE — so the SDK receives what it expects.

**SDK wiring (Python):**

```python
import google.generativeai as genai

genai.configure(
    api_key="your-busbar-token",
    client_options={"api_endpoint": "http://busbar:8080"},
)

model = genai.GenerativeModel("my-pool")   # pool or model name
response = model.generate_content("Hello")
```

---

### `bedrock` — AWS Bedrock Converse API

**Ingress routes:**

```
POST /model/{model_id}/converse
POST /model/{model_id}/converse-stream
```

**Auth carrier (ingress):** AWS SDKs sign requests with SigV4 (`Authorization: AWS4-HMAC-SHA256 ...`). Busbar supports two tracks for Bedrock ingress depending on whether governance is enabled.

**Track A — Without governance (`auth.mode: passthrough` or `none`):** Busbar does not verify the inbound SigV4 signature. Bearer-style carriers (`Authorization: Bearer`, `x-api-key`, `x-goog-api-key`) are the only tokens Busbar's auth middleware reads in these modes. The SigV4 header is forwarded upstream to the Bedrock backend (passthrough) or ignored entirely (none). Use this when you want AWS SDK clients to target Busbar as a transparent Bedrock proxy with pooling and failover but without per-key governance controls.

**Track B — With governance (`auth.mode: token` + `governance.enabled: true`):** Busbar verifies the inbound SigV4 signature natively (`src/auth.rs` `verify_bedrock_sigv4`). An operator mints a virtual key with `"issue_aws_credential": true` via `POST /admin/keys`; the response returns an `aws_access_key_id` + `aws_secret_access_key` alongside the usual bearer `secret` (both shown once, never again). The Bedrock SDK authenticates with that credential pair — Busbar verifies the signature and body integrity (`x-amz-content-sha256`), then attaches the same `GovCtx` a bearer request would, so budget / RPM / TPM / allowed-pools all apply. No passthrough is required; governance and Bedrock-ingress coexist.

**Auth header (egress to Bedrock backend):** Per-request AWS SigV4, computed by Busbar using the key from the lane's `api_key_env` environment variable. The key format is `ACCESS_KEY_ID:SECRET_ACCESS_KEY` (or `ACCESS_KEY_ID:SECRET_ACCESS_KEY:SESSION_TOKEN` for temporary credentials) — Busbar splits on up to three colon-separated parts. The region is parsed from the Bedrock `base_url` hostname.

**Upstream paths:** `POST /model/{model}/converse` (non-stream) and `POST /model/{model}/converse-stream` (stream).

**Model selection (path-model):** The model is `{model_id}` in the ingress URL path.

**Wire format:** Bedrock uses a binary `application/vnd.amazon.eventstream` framing for streaming, with real CRC32 checksums. Busbar decodes these frames on the egress path (when a Bedrock backend is the upstream) and re-encodes translated events as valid binary eventstream frames for Bedrock-ingress clients. Non-stream responses use JSON.

**SDK wiring (Python):**

```python
import boto3

bedrock = boto3.client(
    "bedrock-runtime",
    region_name="us-east-1",
    endpoint_url="http://busbar:8080",
)

response = bedrock.converse(
    modelId="my-pool",     # busbar pool or model name
    messages=[{"role": "user", "content": [{"text": "Hello"}]}],
)
```

---

## Body-model vs path-model ingress

The six protocols split into two groups based on where the target model (or pool name) lives in the request:

### Body-model protocols: `openai`, `responses`, `cohere`

The `"model"` field is in the JSON body. Busbar reads it, resolves it, and begins the forwarding pipeline. The `"stream"` intent is also in the body (`"stream": true`).

These three protocols share one ingress implementation (`route::ingress_body_model`). The only difference between them is the protocol name and the shape of their native error envelopes.

### Path-model protocols: `gemini`, `bedrock`

The model and stream intent live in the URL, not the body:

- **Gemini:** `/v1beta/models/{model}:generateContent` (non-stream) vs `/v1beta/models/{model}:streamGenerateContent` (stream). The model and action are packed into the last path segment separated by `:`. Axum cannot split on `:` inside a single path segment, so the wildcard tail (`*rest`) is captured and split on the last colon in the handler.
- **Bedrock:** `/model/{model_id}/converse` vs `/model/{model_id}/converse-stream`. Busbar determines stream intent from which route matched.

Because the body does not carry `"model"` or `"stream"`, Busbar injects them into the parsed body before running the same pool-resolution and forwarding code as body-model protocols. This injection is internal — the upstream never sees it (the injected shim keys are stripped before the egress write).

### `anthropic` — routed by path, handled separately

Anthropic ingress takes its pool-or-model name from the URL (`{name}` in `/{name}/v1/messages`), so like the path-model protocols the model field in the Anthropic body does not drive routing. But it is handled by its own handlers rather than the shared body/path-model code: `route::named` for `/{name}/v1/messages` and `route::adhoc` for the two-segment ad-hoc form (`/{provider}/{model}/v1/messages`).

---

## Cross-protocol translation

When the ingress protocol and the selected lane's egress protocol differ, Busbar translates through a superset intermediate representation (IR). This is the single mechanism that makes "point any SDK at Busbar and reach any backend" work.

### The translation pipeline

**Request translation** (`forward::translate_request_cross_protocol`):

```
ingress.reader().read_request(body)   →   IrRequest   →   egress.writer().write_request(ir)
```

Steps, in order:

1. The ingress reader parses the request body into an `IrRequest`.
2. If the egress protocol requires `max_tokens` (only Anthropic returns `true` for `requires_max_tokens()`), and the IR has none, the lane's `default_max_tokens` is injected (falling back to `4096`).
3. Tool IDs are remapped from the egress backend's native shape to what the ingress client expects on the response side.
4. The `extra` map — which holds unmodeled source-protocol fields like OpenAI's `logprobs` or `n` — is cleared before writing. This is the structural leak guard: OpenAI-only fields must not reach an Anthropic or Gemini backend, where they would be rejected or silently ignored.
5. The egress writer serializes the IR into the upstream protocol's wire format.
6. Router shim keys are stripped (the Gemini JSON-array flag, and `"stream"` for path-model egress where stream intent is in the URL).
7. The `"model"` field is rewritten to the selected lane's actual model identifier.

(When ingress and egress are the same protocol, steps 1–5 are skipped — only shim-key cleanup and model rewrite run.)

**Response translation** (non-streaming):

```
egress.reader().read_response(body)   →   IrResponse   →   ingress.writer().write_response(ir)
```

The upstream response is buffered (up to 32 MiB), parsed, and re-serialized in the caller's protocol format. On a cross-protocol hop, the upstream-assigned `id` is stripped and the ingress writer mints a native-format ID; `model` and `created` are preserved as the synthesis anchor.

**Response translation (streaming):** `StreamTranslate` composes the reader and writer event-by-event:

```
while let Some(event) = egress.reader().read_response_events(frame, &mut state) {
    ingress.writer().write_response_event(event)  →  emitted to client
}
```

Busbar reassembles frames that arrive split across TCP chunks, threads per-request `StreamDecodeState` (necessary for protocols like OpenAI whose flat chunk stream requires block-boundary synthesis), and emits the correct framing for the ingress protocol — SSE for the five SSE protocols on ingress (with the `data: [DONE]` terminator for OpenAI), Gemini's JSON-array framing when `?alt=sse` was absent, or binary CRC32-valid eventstream frames for Bedrock-ingress clients.

### Same-protocol passthrough

When ingress and egress protocols match, the IR round-trip is still used, but `StreamTranslate::new_same_proto` runs a byte-exact passthrough: the translator re-emits the original frame bytes verbatim instead of re-serializing from IR. This keeps same-protocol traffic lossless and just as cheap as native passthrough while using the same code path as cross-protocol traffic.

A `busbar_translations_total{from, to}` Prometheus counter is incremented per cross-protocol hop and is not touched for same-protocol requests.

### Non-2xx cross-protocol responses

Upstream error responses (non-2xx) are **never** relayed verbatim on a cross-protocol hop. The upstream error is parsed, classified, and re-serialized as a native error envelope in the ingress protocol's shape. For example, a `429` from a Gemini backend reaching an OpenAI-ingress client is reshaped into an OpenAI-shaped error with `type: "rate_limit_error"`. The error kind mapping is deterministic (`401` → `authentication_error`, `403` → `permission_error`, `429` → `rate_limit_error`, `503` → `overloaded`, `504` → `timeout`, other 5xx → `api_error`, other 4xx → `invalid_request_error`); each ingress writer renders that kind into its own native envelope (e.g. OpenAI emits `authentication_error` with `code: "invalid_api_key"`).

Same-protocol error responses (`4xx`) are relayed verbatim.

---

## What survives translation and what does not

### What "lossless" means here

Busbar's translation is **lossless** in a specific, testable sense: **neither end can tell the hop happened.**

- **The client is never confused.** It gets a response its own SDK parses cleanly, in its own protocol's shape, that never contradicts what it sent — no `finish_reason`/`stop_reason` outside its enum, no field in a shape its validator rejects, no identifier minted by a foreign vendor.
- **The backend never rejects the request.** What Busbar sends upstream is a valid request in the *backend's* protocol — never a foreign-shaped structured-output object, an off-enum image format, a non-alternating message sequence, or any field the backend 400s as malformed.

The reference is native-to-native: a translated exchange should behave exactly as if the client had spoken the backend's protocol directly. A difference counts as *loss* only if it trips one of those two tests — a client that can't parse what it got back, or a backend that rejects what it was sent. Field-level differences that trip neither test (e.g. an upstream `id` replaced with an ingress-native one) are not loss.

Where a construct genuinely has **no representation** in the target protocol — a rare, inherent limit, see [Lost on a cross-protocol hop](#lost-on-a-cross-protocol-hop) — Busbar degrades it to the closest valid native form **and emits a `warn!`**, never something either end would reject. The degradation is observable in logs; it is never silent and never yields an unparseable or malformed wire body.

### Always preserved

These fields survive a cross-protocol hop because they are first-class in the IR:

| Field | IR representation |
|---|---|
| `system` prompt | `IrRequest.system` |
| Messages (user / assistant / tool turns) | `IrRequest.messages: Vec<IrMessage>` |
| Text blocks | `IrBlock::Text { text, cache_control, citations }` |
| Thinking / extended-thinking blocks | `IrBlock::Thinking { text, signature, cache_control }` |
| Tool definitions | `IrRequest.tools` — `IrTool { name, description, input_schema }` |
| Tool-use and tool-result blocks | `IrBlock::ToolUse`, `IrBlock::ToolResult` |
| Image blocks | `IrBlock::Image { media_type, data, cache_control }` |
| Prompt-cache breakpoints (`cache_control`) | First-class on text, tool-use, tool-result, **thinking, and image** blocks — an Anthropic cache breakpoint survives a same-protocol re-serialize instead of vanishing |
| Structured output (`response_format` / `responseSchema`) | `IrRequest.response_format` — mapped into **each backend's native shape** (OpenAI `json_schema`, Cohere `json_object`, Gemini `responseMimeType`/`responseSchema`), never forwarded in a foreign shape the backend rejects |
| Stop reason (`finish_reason` / `stop_reason` / `finishReason`) | Normalized to a **valid member of each protocol's enum** on egress — an unknown/foreign reason degrades to that protocol's SDK-safe value rather than leaking an off-enum string the client can't parse |
| `max_tokens` | `IrRequest.max_tokens` |
| `temperature` | `IrRequest.temperature: f64` (not f32 — no lossy round-trip) |
| `top_p`, `top_k` | `IrRequest.top_p`, `IrRequest.top_k` |
| `stop` sequences | `IrRequest.stop: Vec<String>` |
| `stream` flag | `IrRequest.stream` |
| `frequency_penalty`, `presence_penalty`, `seed` | First-class IR fields; survive cross-protocol hops (dropped with `warn!` where the target protocol has no analog) |
| Grounding/web-search citations | `IrCitation` (with `raw` escape hatch for byte-exact Anthropic re-emit); streaming `citations_delta` included |
| Serving model name | `IrResponse.model` (so pooled cross-protocol responses report which model served) |
| Token usage | `IrUsage` (input/output tokens, with input-usage backfill on streams that only report it at message start) |

**Usage-token cross-protocol nuance (Anthropic/Bedrock → OpenAI/Gemini/Responses):** Anthropic and Bedrock responses carry a separate `cache_creation` token bucket that has no equivalent field in the OpenAI, Gemini, or Responses wire shapes. When such a response is translated to one of those protocols, the reported `prompt_tokens` / `input_tokens` total *includes* cache-creation tokens (so billing is complete), but the `cached_tokens` sub-field reflects only cache-read tokens — because the target wire shape has no cache-creation bucket to place them in. Billing is unaffected (all consumed tokens are counted); only the sub-field breakdown differs.

### Lost on a cross-protocol hop

Fields that are not modeled in the IR do not survive a translated hop — they live only in the `extra` passthrough map, which is cleared at the cross-protocol seam. Examples:

- **OpenAI-only (no IR analog):** `logprobs`, `n` (multiple completions), `logit_bias`. These flow through `extra` verbatim on same-protocol OpenAI passthrough and are stripped on a cross-protocol hop.
- **Other source-protocol-specific fields** that no IR field models are likewise stored in `extra` and dropped at the seam.
- **Protocol-specific identifiers:** The upstream's `id` field is stripped and replaced with an ingress-native minted ID on cross-protocol responses (so Anthropic `msg_...` IDs don't appear in OpenAI responses).

### The `extra` map

Fields that the ingress reader encounters but does not model as first-class IR fields are stored in `IrRequest.extra` (a passthrough JSON map). On a same-protocol passthrough they reach the upstream unchanged. On a cross-protocol hop, `extra` is cleared in its entirety before the egress write (the same step that drops `logprobs` and `n`) — intentionally, so source-protocol-specific fields never reach a backend that rejects unknown fields.

### Same-protocol note

On same-protocol routes, none of the above applies. The request body is forwarded byte-for-byte; the response body is streamed byte-for-byte. Every field, every annotation, every vendor extension survives because nothing is parsed.

---

## Worked example: OpenAI SDK calling Anthropic Claude

**Scenario:** Your application uses the OpenAI Python SDK. You want to route requests to Claude through Busbar using the OpenAI Chat Completions wire format on ingress, while the backend speaks the Anthropic Messages protocol.

### 1. Configure Busbar

```yaml
# config.yaml
listen: "0.0.0.0:8080"

auth:
  mode: token
  client_tokens: ["${BUSBAR_TOKEN}"]

providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY

models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    default_max_tokens: 4096

pools:
  fast:
    members:
      - target: claude-sonnet
        weight: 1
```

```bash
export BUSBAR_TOKEN=my-local-token
export ANTHROPIC_KEY=sk-ant-...
BUSBAR_PROVIDERS=./providers.yaml BUSBAR_CONFIG=./config.yaml ./busbar
```

### 2. Call it with the OpenAI SDK

```python
from openai import OpenAI

client = OpenAI(
    api_key="my-local-token",   # your busbar token, not an OpenAI key
    base_url="http://localhost:8080",
)

response = client.chat.completions.create(
    model="fast",               # the busbar pool name
    messages=[
        {"role": "user", "content": "What is the capital of France?"},
    ],
)

print(response.choices[0].message.content)
```

### What happens on the wire

1. The OpenAI SDK issues `POST http://localhost:8080/v1/chat/completions` with body:

   ```json
   {
     "model": "fast",
     "messages": [{"role": "user", "content": "What is the capital of France?"}]
   }
   ```

2. Busbar's auth middleware reads `Authorization: Bearer my-local-token`, matches it against `client_tokens`, and admits the request.

3. The route handler (`route::openai_ingress`) reads `"model": "fast"` from the body, resolves `fast` against the pool table, and picks `claude-sonnet` via SWRR.

4. `claude-sonnet` maps to the `anthropic` provider (egress protocol `anthropic`). Ingress protocol is `openai`. They differ — translation runs.

5. `translate_request_cross_protocol`:
   - The OpenAI reader parses the body into an `IrRequest` with one user message and `stream: false`.
   - No `max_tokens` in the IR. Anthropic `requires_max_tokens()` returns `true`. The lane's `default_max_tokens: 4096` is injected → `IrRequest.max_tokens = Some(4096)`.
   - The Anthropic writer serializes to (with `"model"` rewritten to the lane's actual model):

     ```json
     {
       "model": "<lane model>",
       "max_tokens": 4096,
       "messages": [{"role": "user", "content": "What is the capital of France?"}]
     }
     ```

6. Busbar issues `POST https://api.anthropic.com/v1/messages` with `x-api-key: sk-ant-...` and the translated body.

7. Anthropic returns a Messages-format response:

   ```json
   {
     "id": "msg_01XFDUDYJgAACzvnptvVoYEL",
     "type": "message",
     "role": "assistant",
     "content": [{"type": "text", "text": "Paris."}],
     "model": "<anthropic model>",
     "stop_reason": "end_turn",
     "usage": {"input_tokens": 14, "output_tokens": 5}
   }
   ```

8. Response translation runs (`anthropic` → `openai`):
   - The upstream `id` (`msg_01XFD...`) is stripped; Busbar mints an OpenAI-format ID. `model` and `created` are preserved.
   - The Anthropic reader parses to an `IrResponse` carrying the text block, `stop_reason: "end_turn"`, and usage `{input: 14, output: 5}`.
   - The OpenAI writer serializes to a `chat.completion` object:

     ```json
     {
       "id": "chatcmpl-<busbar-minted>",
       "object": "chat.completion",
       "created": 1718000000,
       "model": "<anthropic model>",
       "choices": [{
         "index": 0,
         "message": {"role": "assistant", "content": "Paris."},
         "finish_reason": "stop"
       }],
       "usage": {"prompt_tokens": 14, "completion_tokens": 5, "total_tokens": 19}
     }
     ```

9. The OpenAI SDK receives a response it considers valid OpenAI Chat Completions output. `response.choices[0].message.content` is `"Paris."`. The SDK is unaware that Anthropic served it.

---

## Worked example: Anthropic SDK calling a Gemini backend

**Scenario:** Your application uses the Anthropic Python SDK. You want to route some requests to a Gemini backend (for cost or capability reasons) without changing any application code.

### 1. Configure Busbar

```yaml
providers:
  anthropic:
    api_key_env: ANTHROPIC_KEY
  gemini:
    api_key_env: GEMINI_KEY

models:
  claude-sonnet:
    provider: anthropic
    max_concurrent: 20
    default_max_tokens: 4096
  gemini-flash:
    provider: gemini
    max_concurrent: 30
    default_max_tokens: 4096

pools:
  smart:
    members:
      - target: claude-sonnet
        weight: 3
      - target: gemini-flash
        weight: 1
```

### 2. Call it with the Anthropic SDK

```python
import anthropic

client = anthropic.Anthropic(
    api_key="my-busbar-token",
    base_url="http://localhost:8080/smart",   # {name} = the pool
)

message = client.messages.create(
    model="ignored",   # overridden by busbar
    max_tokens=512,
    messages=[{"role": "user", "content": "Summarize the water cycle in two sentences."}],
)

print(message.content[0].text)
```

When SWRR selects the `gemini-flash` lane (roughly a quarter of the time at these weights), the request is an `anthropic`-ingress → `gemini`-egress translation:

- The Anthropic reader parses the body — including `max_tokens: 512` (caller-supplied, so no injection needed).
- The Gemini writer serializes to the Gemini `generateContent` shape, mapping the messages array and the user's `max_tokens` to Gemini's `generationConfig.maxOutputTokens`.
- Busbar constructs the upstream URL `POST <gemini base_url>/v1beta/models/<lane model>:generateContent` with `x-goog-api-key: <GEMINI_KEY>`.
- Gemini responds in its own format; the Gemini reader parses it; the Anthropic writer produces an Anthropic Messages response. The Anthropic SDK receives it and sees a valid `Message` object. `message.content[0].text` holds the response.

When SWRR selects the `claude-sonnet` lane (the rest of the time), the ingress and egress protocols are both `anthropic` — no translation; the body passes through byte-for-byte, with the model field rewritten and the `x-api-key` header injected.

The application code is identical in both cases.

---

## Protocol compatibility matrix

The IR is a superset every reader maps into and every writer maps out of, and the protocol registry constructs all six reader/writer pairs — so every ingress can target every egress.

| Ingress ↓ / Egress → | `anthropic` | `openai` | `gemini` | `bedrock` | `responses` | `cohere` |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| `anthropic` | passthrough | translated | translated | translated | translated | translated |
| `openai` | translated | passthrough | translated | translated | translated | translated |
| `gemini` | translated | translated | passthrough | translated | translated | translated |
| `bedrock` | translated | translated | translated | passthrough | translated | translated |
| `responses` | translated | translated | translated | translated | passthrough | translated |
| `cohere` | translated | translated | translated | translated | translated | passthrough |

"Passthrough" means the request and response bodies are forwarded byte-for-byte with no IR round-trip. "Translated" means the request and each response frame passes through the IR. Both paths produce valid wire output in the ingress protocol.

A heterogeneous pool (members spanning more than one egress protocol) emits a warning at startup. The warning is informational — the pool works — but tells you that some requests through it will translate and some will not, depending on which lane SWRR picks.

---

## Quick reference: routes and SDK swap

| Protocol | Ingress route(s) | SDK config — change `base_url` to | Auth header sent by SDK |
|---|---|---|---|
| `anthropic` | `POST /{name}/v1/messages` | `http://busbar:8080/<pool-or-model>` | `x-api-key` or `Authorization: Bearer` |
| `openai` | `POST /v1/chat/completions` | `http://busbar:8080` | `Authorization: Bearer` |
| `responses` | `POST /v1/responses` | `http://busbar:8080` | `Authorization: Bearer` |
| `cohere` | `POST /v2/chat` | `http://busbar:8080` | `Authorization: Bearer` |
| `gemini` | `POST /v1[beta]/models/{model}:generateContent[Stream]` | `http://busbar:8080` (via `api_endpoint`) | `x-goog-api-key` |
| `bedrock` | `POST /model/{model_id}/converse[-stream]` | `http://busbar:8080` (via `endpoint_url`) | SigV4 — with governance: minted `aws_access_key_id`/`aws_secret_access_key` (verified by Busbar); without governance: `auth.mode: passthrough` or `none` |