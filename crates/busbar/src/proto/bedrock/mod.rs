// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Bedrock Converse protocol reader/writer implementation.

use super::openai_family::{
    ERR_TYPE_AUTHENTICATION, ERR_TYPE_INSUFFICIENT_QUOTA, ERR_TYPE_INVALID_REQUEST,
    ERR_TYPE_NOT_FOUND, ERR_TYPE_PERMISSION, ERR_TYPE_RATE_LIMIT,
};
use super::*;

/// The two response headers a native AWS Bedrock endpoint ALWAYS emits (lowercase on the wire):
/// the per-request id the AWS SDK surfaces via `*Output::request_id()`, and the error-type header
/// the SDK reads BEFORE the body `__type` for typed-exception dispatch. Defined here (the Bedrock
/// dialect's home) and used within this module; surfaced externally only via the writer vtable
/// (`BedrockWriter::ingress_response_request_id` / `ingress_relayed_response_header_names`), so
/// the production sites that capture, forward, or synthesize these headers cannot drift on spelling.
const HDR_AMZN_REQUEST_ID: &str = "x-amzn-requestid";
const HDR_AMZN_ERROR_TYPE: &str = "x-amzn-errortype";

/// The four AWS Bedrock Converse exception names that appear in BOTH the request-level error path
/// (`error_kind_to_bedrock_type`) and the stream-exception path (`bedrock_stream_exception_for`).
/// Named so both functions reference the same const rather than repeating bare literals that could
/// silently diverge on a typo; the single-use exception names in those functions are left bare.
const EXC_THROTTLING: &str = "ThrottlingException";
const EXC_VALIDATION: &str = "ValidationException";
const EXC_SERVICE_UNAVAILABLE: &str = "ServiceUnavailableException";
const EXC_INTERNAL_SERVER: &str = "InternalServerException";

/// The binary framing content-type that AWS Bedrock Converse streaming uses. Both the response
/// `Content-Type` and the egress `Accept` header for a `ConverseStream` call must carry exactly
/// this value; named so neither site can silently diverge.
const APPLICATION_VND_AMAZON_EVENTSTREAM: &str = "application/vnd.amazon.eventstream";

/// The Bedrock-side spelling of the "overloaded" error type that AWS's own error responses carry
/// in their `__type` field (`ServiceUnavailableException` maps back to this on a round-trip).
/// Distinguished from `crate::proxy::KIND_OVERLOADED` ("overloaded"), which is busbar's own
/// internal kind vocabulary. Both map to `ServiceUnavailableException` via
/// `error_kind_to_bedrock_type`; named here so the match arm is a const pattern rather than a
/// bare literal.
const ERR_TYPE_OVERLOADED: &str = super::openai_family::ERR_TYPE_OVERLOADED;

/// Map busbar's generic error `kind` vocabulary to the AWS Bedrock Converse exception name carried
/// in `__type`. AWS's Converse error model is a fixed, closed set of exception shapes
/// (`ValidationException`, `ThrottlingException`, `AccessDeniedException`, `ResourceNotFoundException`,
/// `ModelTimeoutException`, `ServiceUnavailableException`, `InternalServerException`,
/// `ServiceQuotaExceededException`, `ModelErrorException`); a native SDK matches on exactly these.
/// Any kind without a Bedrock-native counterpart falls back to `ValidationException` (the generic
/// client-error shape) — chosen deliberately over a catch-all so the wire `__type` is always a real
/// AWS exception name. This is the inverse of the `__type` token `extract_error` reads back, so a
/// same-protocol error round-trips its structured type.
pub(crate) fn error_kind_to_bedrock_type(kind: &str) -> &'static str {
    match kind {
        ERR_TYPE_INVALID_REQUEST | "invalid_request" | "validation" | "bad_request" => {
            EXC_VALIDATION
        }
        ERR_TYPE_RATE_LIMIT | "rate_limit" | "too_many_requests" | "throttling" => EXC_THROTTLING,
        ERR_TYPE_AUTHENTICATION | ERR_TYPE_PERMISSION | "auth" | "forbidden" | "unauthorized" => {
            "AccessDeniedException"
        }
        "not_found" | ERR_TYPE_NOT_FOUND | "model_not_found" => "ResourceNotFoundException",
        crate::proxy::KIND_TIMEOUT | "model_timeout" => "ModelTimeoutException",
        crate::proxy::KIND_OVERLOADED
        | ERR_TYPE_OVERLOADED
        | "service_unavailable"
        | "unavailable" => EXC_SERVICE_UNAVAILABLE,
        "quota_exceeded" | "service_quota_exceeded" | ERR_TYPE_INSUFFICIENT_QUOTA => {
            "ServiceQuotaExceededException"
        }
        crate::proxy::KIND_API_ERROR | "internal_error" | crate::proxy::KIND_SERVER_ERROR => {
            EXC_INTERNAL_SERVER
        }
        // No native Bedrock counterpart: fall back to the generic client-error exception so the
        // wire `__type` is still a real AWS exception name a native SDK can decode.
        _ => EXC_VALIDATION,
    }
}

/// Mint a UUID-v4-shaped request id (`8-4-4-4-12` lowercase hex) for the `x-amzn-RequestId` header a
/// native AWS Bedrock response always carries — on EVERY response, success and error, stream and
/// non-stream (the AWS SDK exposes it via `*Output::request_id()`; an absent header makes that return
/// `None`, which is impossible with a real endpoint and a deterministic proxy tell). Uses the OS
/// CSPRNG; returns `None` (so the caller simply OMITS the header) if entropy is unavailable — this is
/// on the request path and must never panic. Single source of truth: every path — success
/// (`proto/mod.rs` via `wrap_buffered_as_stream` / `proxy engine` via `maybe_attach_response_request_id`)
/// and error (`proxy::ingress_error` and the `main.rs` fallback, both via
/// `attach_bedrock_error_headers`) — reaches this through the writer vtable, so there are no private
/// copies.
pub(crate) fn synth_amzn_request_id() -> Option<String> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).ok()?;
    // RFC 4122 v4 layout (version + variant bits) so the value is a well-formed UUID.
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    // One allocation for the 32-char lowercase hex string (was 17+ via per-byte `format!`).
    let s = hex::encode(buf);
    Some(format!(
        "{}-{}-{}-{}-{}",
        &s[0..8],
        &s[8..12],
        &s[12..16],
        &s[16..20],
        &s[20..32]
    ))
}

/// Attach the `x-amzn-RequestId` and `x-amzn-errortype` headers a native AWS Bedrock error response
/// ALWAYS carries to an already-built response. `x-amzn-errortype` mirrors the body `__type` (via
/// `error_kind_to_bedrock_type`, the single source of truth) so header and body agree; the request
/// id is the only request-id surface the AWS SDK exposes via `*Output::request_id()`. This module-
/// private helper is the single source of those headers, dispatched through the
/// `BedrockWriter::attach_error_response_headers` vtable method — the only caller; `proxy engine::
/// ingress_error`, `ingress`, and `auth.rs` reach it through that vtable (not by name), so they
/// cannot drift on which headers a Bedrock error must carry. Best-effort: if entropy or header
/// encoding fails we skip that header rather than panic — this runs on the request path.
fn attach_bedrock_error_headers(headers: &mut axum::http::HeaderMap, kind: &str) {
    if let Some(id) = synth_amzn_request_id() {
        if let Ok(hv) = HeaderValue::from_str(&id) {
            headers.insert(HeaderName::from_static(HDR_AMZN_REQUEST_ID), hv);
        }
    }
    let errortype = error_kind_to_bedrock_type(kind);
    if let Ok(hv) = HeaderValue::from_str(errortype) {
        headers.insert(HeaderName::from_static(HDR_AMZN_ERROR_TYPE), hv);
    }
}

/// Map a mid-stream `IrError` to the native AWS Converse *ConverseStream output-union* member name
/// the SDK's stream decoder recognizes, plus the human-readable message.
///
/// This is DISTINCT from `error_kind_to_bedrock_type` (which maps the full closed set of
/// REQUEST-level / HTTP Converse exceptions). The ConverseStream response is a Smithy event stream
/// whose modeled mid-stream error events are a SMALLER, fixed union of exactly five shapes:
/// `InternalServerException`, `ModelStreamErrorException`, `ValidationException`,
/// `ThrottlingException`, and `ServiceUnavailableException`. Request-level shapes such as
/// `ModelTimeoutException`, `AccessDeniedException`, and `ServiceQuotaExceededException` are NOT
/// members of that union: a native AWS SDK ConverseStream decoder sees such an `:exception-type`,
/// fails to match it against the stream union, and treats it as an unknown/unmodeled event — so it
/// can never raise the typed mid-stream exception (an indistinguishability tell). We therefore fold
/// every error class onto one of the five legal stream members:
///
/// - `RateLimit` → `ThrottlingException`
/// - `Overloaded` → `ServiceUnavailableException`
/// - `ClientError` / `ContextLength` → `ValidationException`
/// - `Timeout` → `ModelStreamErrorException` (the stream-internal failure shape)
/// - `Auth` / `Billing` / `ServerError` / `Network` → `InternalServerException`
///
/// `Auth` and `Billing` have no stream-union counterpart, so they fold into the generic
/// `InternalServerException` rather than leaking a request-level name onto the stream. Each class is
/// matched explicitly — no catch-all — so a new `StatusClass` variant fails to compile here.
///
/// Shared by `write_response_exception` (the StreamTranslate exception-frame path) and the fallback
/// `write_response_event` Error arm (also a stream-output context) so both stay consistent. The
/// message prefers the upstream's `provider_signal`, falling back to the exception name.
fn bedrock_stream_exception_for(err: &crate::proto::IrError) -> (&'static str, String) {
    let exception_name = match err.class {
        StatusClass::RateLimit => EXC_THROTTLING,
        StatusClass::Overloaded => EXC_SERVICE_UNAVAILABLE,
        StatusClass::ClientError | StatusClass::ContextLength => EXC_VALIDATION,
        StatusClass::Timeout => "ModelStreamErrorException",
        StatusClass::Auth
        | StatusClass::Billing
        | StatusClass::ServerError
        | StatusClass::Network => EXC_INTERNAL_SERVER,
    };
    let message = err
        .provider_signal
        .clone()
        .unwrap_or_else(|| exception_name.to_string());
    (exception_name, message)
}

/// `extra` key under which the Bedrock reader stashes the positions of native Converse `cachePoint`
/// content blocks (the prompt-cache markers, `{"cachePoint": {"type": "default"}}`) that appear
/// INSIDE the `system` array and inside each message's `content` array.
///
/// A `cachePoint` block has NO IR `IrBlock` counterpart (the IR models only
/// Text/Thinking/ToolUse/ToolResult/Image), so without this capture the reader silently DROPPED
/// every `cachePoint` on a same-protocol Bedrock passthrough — disabling prompt caching the caller
/// explicitly requested and turning a cache HIT into a full re-bill of the cached prefix on every
/// turn (a real cost regression). It is a Bedrock-NATIVE marker with no cross-protocol meaning, so
/// stashing it in `extra` is exactly right: it survives a same-protocol round-trip and is correctly
/// dropped on the cross-protocol seam (where `extra` is cleared) rather than leaking a Bedrock-only
/// token onto a foreign wire.
///
/// The stash records each block's ORIGINAL absolute index in its native array so `write_request`
/// can splice it back at the same position. Shape:
/// ```json
/// {
///   "system":   [ { "i": <usize>, "block": <cachePoint value> }, ... ],
///   "messages": [ { "m": <usize>, "i": <usize>, "block": <cachePoint value> }, ... ]
/// }
/// ```
/// The leading `__busbar` prefix keeps it from colliding with any real Bedrock top-level key, and
/// `write_request` consumes it (never re-emitting it via the trailing extra-merge), so the sentinel
/// never appears on the wire.
const CACHE_POINTS_SENTINEL: &str = "__busbar_bedrock_cache_points";

/// `extra` key under which the Bedrock reader stashes the positions of native Converse `guardContent`
/// content blocks (the inline Guardrails markers, `{"guardContent": {"text": {"text": ...,
/// "qualifiers": [...]}}}` or `{"guardContent": {"image": {...}}}`) that appear INSIDE the `system`
/// array and inside each message's `content` array.
///
/// A `guardContent` block has NO IR `IrBlock` counterpart (the IR models only
/// Text/Thinking/ToolUse/ToolResult/Image): the qualifiers (`grounding_source` / `query` /
/// `guard_content`) that tell Bedrock Guardrails which spans to evaluate are not expressible as a
/// plain Text block. Without this capture the reader silently DROPPED every `guardContent` on a
/// same-protocol Bedrock passthrough — disabling the inline content-classification the caller
/// explicitly requested (a guardrail the operator relies on for safety/compliance no longer sees the
/// marked span), making the proxy behaviourally divergent from a direct AWS call. It is a
/// Bedrock-NATIVE marker with no cross-protocol meaning, so stashing it in `extra` is exactly right:
/// it survives a same-protocol round-trip and is correctly dropped on the cross-protocol seam (where
/// `extra` is cleared) rather than leaking a Bedrock-only token onto a foreign wire.
///
/// The stash records each block's ORIGINAL absolute index in its native array (the same
/// `{ "i": <usize>, "block": <value> }` / `{ "m": <usize>, "i": <usize>, "block": <value> }` shape as
/// the `cachePoint` stash) so `write_request` can splice it back at the same position via the shared
/// `splice_cache_points` helper. The leading `__busbar` prefix keeps it from colliding with any real
/// Bedrock top-level key, and `write_request` consumes it (never re-emitting it via the trailing
/// extra-merge), so the sentinel never appears on the wire.
const GUARD_CONTENT_SENTINEL: &str = "__busbar_bedrock_guard_content";

/// AWS Bedrock ConverseStream wire event-type names — the discriminator on every stream frame (the
/// SDK's `:event-type` header, surfaced as the `"type"` tag on busbar's decoded JSON). Named once here
/// so no bare wire literal is scattered across the reader / writer / framing, and so a typo is a
/// COMPILE error rather than a silent frame-type mismatch. The set is closed: a native ConverseStream
/// emits exactly these (exception frames carry their own type names, handled separately).
const ET_MESSAGE_START: &str = "messageStart";
const ET_CONTENT_BLOCK_START: &str = "contentBlockStart";
const ET_CONTENT_BLOCK_DELTA: &str = "contentBlockDelta";
const ET_CONTENT_BLOCK_STOP: &str = "contentBlockStop";
const ET_MESSAGE_STOP: &str = "messageStop";
const ET_METADATA: &str = "metadata";

/// The Bedrock `metadata`-frame `metrics` object and its `latencyMs` field: a native ConverseStream
/// reports the stream's real end-to-end latency here. Named so the framing seam that injects it
/// (`BedrockStreamFraming::inject_streaming_metrics`) carries no bare wire literal.
const FIELD_METRICS: &str = "metrics";
const FIELD_LATENCY_MS: &str = "latencyMs";

/// Source-spelling hint for `top_k` (PF — losslessness). Bedrock carries `top_k` in
/// `additionalModelRequestFields` under two spellings: `top_k` (snake_case) and `topK` (camelCase,
/// the form some model families require). The reader lifts EITHER into the first-class IR `top_k`,
/// but a naive writer always re-emits `top_k` — silently RENAMING a native Bedrock->Bedrock
/// passthrough that arrived as `topK`. Mirroring `MAX_COMPLETION_TOKENS_SENTINEL` in `proto::openai_chat`,
/// the reader stamps this sentinel in `extra` when the source spelling was `topK`; the writer then
/// re-emits `topK` (else canonical `top_k`) and CONSUMES the sentinel so it never reaches the wire.
/// `extra` is cleared on the cross-protocol seam, so cross-protocol egress (no sentinel) always emits
/// the canonical `top_k`. The leading `__busbar` prefix never collides with a real Bedrock field.
const TOP_K_CAMEL_SENTINEL: &str = "__busbar_top_k_camel";

/// Clamp a temperature to Bedrock's native `[0.0, 1.0]` range, returning `(clamped, was_clamped)`
/// where `was_clamped` is `true` iff the clamp ACTUALLY changed the value. Mirrors
/// `anthropic::clamp_temperature_for_anthropic` (PF non-silent clamp): OpenAI / Responses accept
/// temperature up to 2.0, so a cross-protocol request can carry a value Bedrock's API rejects with a
/// hard 400 ValidationException; the writer forwards the closest valid value instead of bouncing the
/// request, and uses `was_clamped` to emit a `warn!` so the mutation is NOT silent. Factored out so
/// the non-silent-on-change contract is unit-testable without a tracing subscriber.
fn clamp_temperature_for_bedrock(temperature: f64) -> (f64, bool) {
    // Totality guard, mirroring `anthropic::clamp_temperature_for_anthropic`: a non-finite value
    // (NaN/±Inf) is unreachable via valid JSON (sonic_rs rejects it at parse), but `f64::clamp`
    // would return NaN and `NaN != NaN` would spuriously report `was_clamped`. Pass it through
    // unchanged with `was_clamped == false` so the helper is total and the two siblings agree.
    if !temperature.is_finite() {
        return (temperature, false);
    }
    let clamped = temperature.clamp(0.0, 1.0);
    (clamped, clamped != temperature)
}

/// Read a native Bedrock Converse `reasoningContent` content block into an IR `Thinking` block, or
/// `None` when the block carries neither known member (forward-compatibility: a future
/// `reasoningContent` union member is left undecoded rather than mis-mapped).
///
/// The Converse `reasoningContent` union has two members:
///   - `reasoningText` (`{ "text", "signature" }`) → `Thinking { text, signature }` (the common case;
///     `signature` is the model's opaque reasoning token, preserved verbatim for a faithful
///     round-trip — Bedrock requires it echoed back on a follow-up turn).
///   - `redactedContent` (opaque base64 bytes) → `Thinking { text: <bytes>, redacted: true }` so the
///     writer can re-emit `redactedContent` rather than leaking the bytes as a plaintext
///     `reasoningText`; non-Bedrock writers (no native analog) DROP the typed redacted block.
///
/// Mirrors anthropic.rs `read_block`'s `"thinking"` arm (text + optional signature → `Thinking`).
fn read_bedrock_reasoning_block(reasoning: &serde_json::Value) -> Option<crate::ir::IrBlock> {
    if let Some(reasoning_text) = reasoning.get("reasoningText") {
        let text = reasoning_text
            .get("text")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let signature = reasoning_text
            .get("signature")
            .and_then(|s| s.as_str().map(String::from));
        return Some(crate::ir::IrBlock::Thinking {
            text,
            signature,
            redacted: false,
            cache_control: None,
        });
    }
    if let Some(redacted) = reasoning.get("redactedContent").and_then(|r| r.as_str()) {
        return Some(crate::ir::IrBlock::Thinking {
            text: redacted.to_string(),
            signature: None,
            redacted: true,
            cache_control: None,
        });
    }
    None
}

/// Build a native Bedrock Converse `reasoningContent` content block (`{"reasoningContent": ...}`) from
/// an IR `Thinking { text, signature }` — the inverse of `read_bedrock_reasoning_block`.
///
/// A REDACTED `Thinking` (`redacted == true`) re-emits the opaque `redactedContent` member (the bytes
/// are in `text`); any other `Thinking` re-emits a `reasoningText` member, attaching `signature` only
/// when present (Bedrock omits the field for an unsigned reasoning block rather than emitting
/// `"signature": null`). Used by both `write_request` (assistant-turn passthrough) and `write_response`
/// (model reasoning output).
fn bedrock_reasoning_block(
    text: &str,
    signature: &Option<String>,
    redacted: bool,
) -> serde_json::Value {
    if redacted {
        return serde_json::json!({ "reasoningContent": { "redactedContent": text } });
    }
    let mut reasoning_text = serde_json::Map::new();
    reasoning_text.insert("text".to_string(), serde_json::json!(text));
    if let Some(sig) = signature {
        reasoning_text.insert("signature".to_string(), serde_json::json!(sig));
    }
    serde_json::json!({ "reasoningContent": { "reasoningText": serde_json::Value::Object(reasoning_text) } })
}

/// Build a native Bedrock Converse `image` block body (`{ "format", "source": { … } }`) from a typed
/// IR `IrImageSource`, or `None` when the image cannot be represented natively.
///
/// The Bedrock Converse `image` block has only two source shapes: `source.bytes` (base64) and
/// `source.s3Location` (an S3 URI). It has NO arbitrary-URL source. The typed `IrImageSource` maps
/// cleanly onto this:
///   - `Base64 { media_type, data }` → `source.bytes`, normalizing the MIME subtype onto Converse's
///     `ImageFormat` union {png, jpeg, gif, webp} (jpg→jpeg; unknown→png with a warn).
///   - `Vendor { vendor: "bedrock", value }` → `source.s3Location` re-emitted faithfully (the reader
///     captured a native `s3Location` source here, preserving `uri`/`bucketOwner` for a lossless
///     same-protocol round-trip).
///   - `Url(_)` (no Converse arbitrary-URL source) and a FOREIGN `Vendor` (e.g. a Responses `file_id`)
///     have no native projection — DROP with a warn rather than emit a corrupt `bytes` block.
fn bedrock_image_block(source: &crate::ir::IrImageSource) -> Option<serde_json::Value> {
    match source {
        // A Bedrock-produced vendor reference is an `s3Location` (stored as `{format, s3Location}`);
        // re-emit it faithfully. A vendor reference from ANOTHER protocol has no Bedrock projection.
        crate::ir::IrImageSource::Vendor { vendor, value } if *vendor == "bedrock" => {
            let format_str = value
                .get("format")
                .and_then(|f| f.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("png");
            let s3_location = value
                .get("s3Location")
                .cloned()
                .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
            Some(serde_json::json!({
                "format": format_str,
                "source": { "s3Location": s3_location }
            }))
        }
        // Bedrock Converse has no arbitrary-URL image source, and a foreign vendor reference (a
        // Responses file_id) has no Converse projection — emitting either as base64 `bytes` would
        // corrupt the block. Drop with a warn.
        crate::ir::IrImageSource::Url(_) | crate::ir::IrImageSource::Vendor { .. } => {
            tracing::warn!(
                "dropping image with no Bedrock Converse projection (URL or foreign vendor ref)"
            );
            None
        }
        crate::ir::IrImageSource::Base64 { media_type, data } => {
            // Map the MIME subtype onto a member of Bedrock Converse's `ImageFormat` union
            // {png, jpeg, gif, webp}. `image/jpg` (and casing variants) is NOT a member — Bedrock
            // spells it `jpeg` — so emitting it verbatim 400s a valid client image. Normalize
            // jpg→jpeg; an empty/unsupported subtype coerces to `png` (with a warn) to keep the block
            // valid rather than emit a `format: ""` the SDK rejects.
            let format_str = match media_type.strip_prefix("image/").filter(|s| !s.is_empty()) {
                Some(subtype) => match subtype.to_ascii_lowercase().as_str() {
                    "jpeg" | "jpg" => "jpeg",
                    "png" => "png",
                    "gif" => "gif",
                    "webp" => "webp",
                    _ => {
                        tracing::warn!(
                            media_type = %media_type,
                            "coercing unsupported image subtype to format=png: not a member of \
                             Bedrock Converse's ImageFormat union {{png, jpeg, gif, webp}}"
                        );
                        "png"
                    }
                },
                None => {
                    tracing::warn!(
                        media_type = %media_type,
                        "coercing malformed image media_type to format=png: not a well-formed \
                         'image/<subtype>'"
                    );
                    "png"
                }
            };
            Some(serde_json::json!({
                "format": format_str,
                "source": { "bytes": data }
            }))
        }
    }
}

/// Build a native Bedrock Converse prompt-cache marker block (`{"cachePoint": {"type": "default"}}`).
///
/// This is the Converse content-block / tool-list element AWS uses to mark a prompt-cache boundary:
/// everything BEFORE the marker (in the same `system` / message `content` / `toolConfig.tools` array)
/// is cached as a prefix. The IR carries the equivalent boundary as a first-class `cache_control`
/// field ON a block / tool (set by e.g. the Anthropic reader); the Bedrock writer projects that field
/// to this marker emitted IMMEDIATELY AFTER the block / tool it applies to, which is the position
/// Bedrock expects (the breakpoint sits after the content it closes). Factored out so the one marker
/// shape has a single definition and the cross-protocol write path is unit-testable.
fn bedrock_cache_point() -> serde_json::Value {
    serde_json::json!({ "cachePoint": { "type": "default" } })
}

/// Read the `cache_control` off the LAST block pushed onto an IR content vector, used by the Bedrock
/// reader to map a native `cachePoint` adjacency back onto the preceding block's first-class IR
/// `cache_control` field (so a Bedrock->Bedrock and Bedrock->Anthropic round-trip preserves the
/// prompt-cache boundary cross-protocol, not only via the positional `CACHE_POINTS_SENTINEL` stash
/// which is dropped on the cross-protocol seam). Only the block kinds that carry a `cache_control`
/// field (Text / ToolUse / ToolResult) can hold the boundary; a `cachePoint` following a block kind
/// with no such field (Thinking / Image) is left to the positional stash alone. Setting the field is
/// idempotent and additive: it does NOT disable the same-protocol stash, so byte-identical
/// same-protocol round-trips are unaffected (the writer suppresses the inline emission whenever the
/// stash is present — see `write_request`).
fn set_preceding_block_cache_control(blocks: &mut [crate::ir::IrBlock]) {
    if let Some(last) = blocks.last_mut() {
        let cc = Some(crate::ir::CacheControl {
            kind: crate::ir::CacheKind::Ephemeral,
        });
        match last {
            crate::ir::IrBlock::Text { cache_control, .. }
            | crate::ir::IrBlock::ToolUse { cache_control, .. }
            | crate::ir::IrBlock::ToolResult { cache_control, .. } => {
                *cache_control = cc;
            }
            // Thinking / Image have no `cache_control` field; the positional stash carries the marker.
            crate::ir::IrBlock::Thinking { .. }
            | crate::ir::IrBlock::Image { .. }
            | crate::ir::IrBlock::Json(_) => {}
        }
    }
}

/// Splice captured `cachePoint` blocks back into a freshly-written content array at the ORIGINAL
/// absolute positions the reader recorded, reconstructing the native ordering on a same-protocol
/// passthrough. `entries` are the per-array stash records (`{ "i": <usize>, "block": <value> }`)
/// pulled from the `CACHE_POINTS_SENTINEL` object; a record missing `i`/`block`, or whose index
/// exceeds the current array length, is skipped rather than mis-placed (defensive — the reader
/// always writes both fields with an in-range index, but `extra` survives an arbitrary
/// cross-protocol hop and an out-of-range index must never panic on the request path).
///
/// Records are applied in ASCENDING index order: each insertion shifts later elements right by one,
/// and because the reader recorded indices against the ORIGINAL array (which contained the
/// cachePoints), inserting at the recorded index in ascending order reproduces the original layout
/// exactly. Insertion uses a bounds-clamped `min(len)` so a stale/foreign index lands at the end
/// instead of panicking.
fn splice_cache_points(arr: &mut Vec<serde_json::Value>, entries: &[serde_json::Value]) {
    // Collect (index, block) pairs, then sort by index so ascending insertion preserves layout.
    let mut pending: Vec<(usize, serde_json::Value)> = Vec::new();
    for entry in entries {
        let Some(idx) = entry.get("i").and_then(|v| v.as_u64()) else {
            continue;
        };
        let Some(block) = entry.get("block") else {
            continue;
        };
        pending.push((idx as usize, block.clone()));
    }
    pending.sort_by_key(|(idx, _)| *idx);
    for (idx, block) in pending {
        let pos = idx.min(arr.len());
        arr.insert(pos, block);
    }
}

/// Concatenate two optional `{ "i", "block" }` marker-entry slices (e.g. the captured `cachePoint`
/// and `guardContent` stashes for one array) into a single owned `Vec` for a SINGLE `splice_cache_points`
/// pass. Both classes recorded their indices against the SAME original array, so they MUST be spliced
/// together (the helper sorts the combined batch by index): two separate passes would let the first
/// pass's insertions shift the second pass's recorded indices, mis-placing the second class. Either
/// or both inputs may be `None`/empty; the result preserves every entry verbatim.
fn merge_marker_entries(
    a: Option<&Vec<serde_json::Value>>,
    b: Option<&Vec<serde_json::Value>>,
) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::new();
    if let Some(entries) = a {
        out.extend_from_slice(entries);
    }
    if let Some(entries) = b {
        out.extend_from_slice(entries);
    }
    out
}

/// Derive the AWS region for SigV4 scope from a Bedrock endpoint host.
///
/// AWS resolves the signing region from the endpoint, not from a single hard-coded prefix. A naive
/// `strip_prefix("bedrock-runtime.")` mis-handles every non-vanilla endpoint shape and silently
/// signs for the wrong region, which AWS rejects with `SignatureDoesNotMatch` — surfaced as a
/// confusing 403 the operator cannot distinguish from a credential error. We therefore match the
/// known Bedrock service labels (with or without the `-fips` qualifier) and any VPC-interface
/// (`vpce`) front, taking the dotted label that immediately follows the service label as the region:
///
///   - `bedrock-runtime.<region>.amazonaws.com`
///   - `bedrock-runtime-fips.<region>.amazonaws.com`
///   - `bedrock-runtime.<region>.vpce.amazonaws.com`
///   - `vpce-0abc...-1xyz.bedrock-runtime.<region>.vpce.amazonaws.com` (interface-endpoint front)
///   - `bedrock.<region>.amazonaws.com` (the control-plane label, defensively)
///
/// Returns `Some(region)` only when a Bedrock service label is found AND the following label looks
/// like an AWS region token (one or more alphabetic dash-parts then a numeric part, e.g.
/// `us-east-1`, `ap-southeast-2`, `eu-central-1`, `us-gov-west-1`, `us-iso-east-1`); otherwise
/// `None`. The caller logs a `tracing::warn!` and falls back to
/// `us-east-1` for `None`, so a mis-derived region is no longer silent. Pure string parsing on a
/// `&str` — no panic, no allocation of the host.
fn derive_sigv4_region(host: &str) -> Option<&str> {
    // An AWS region token: one or more alphabetic dash-parts followed by a final numeric part.
    //   3-part canonical:  us-east-1, ap-southeast-2, eu-central-1, ca-central-1
    //   4-part partitions: us-gov-west-1, us-gov-east-1 (GovCloud), us-iso-east-1, us-isob-east-1
    //                      (ISO), and any future >=3-part naming scheme.
    // We accept any dash token of >= 3 parts whose leading parts are all ASCII-alphabetic and whose
    // FINAL part is all ASCII-digits, so the parser tracks real AWS region shapes regardless of how
    // many middle direction/partition segments AWS adds. We still reject obvious non-regions (a bare
    // label, a 2-part token, an IP octet, a CNAME segment) because they fail the >=3 / alpha+digit
    // structure. The old code hard-required EXACTLY 3 parts, which silently rejected every GovCloud
    // and ISO region and fell the caller back to a wrong `us-east-1` SigV4 scope (403
    // SignatureDoesNotMatch).
    fn looks_like_region(label: &str) -> bool {
        let parts: Vec<&str> = label.split('-').collect();
        // Need at least <area>-<direction>-<number>; no empty parts (rejects leading/trailing/
        // doubled dashes).
        if parts.len() < 3 || parts.iter().any(|p| p.is_empty()) {
            return false;
        }
        let Some((last, leading)) = parts.split_last() else {
            return false;
        };
        last.bytes().all(|x| x.is_ascii_digit())
            && leading
                .iter()
                .all(|p| p.bytes().all(|x| x.is_ascii_alphabetic()))
    }

    // Walk the dotted labels; when we hit a Bedrock service label, the NEXT label is the region.
    let labels: Vec<&str> = host.split('.').collect();
    for (i, label) in labels.iter().enumerate() {
        if matches!(
            *label,
            "bedrock-runtime" | "bedrock-runtime-fips" | "bedrock" | "bedrock-fips"
        ) {
            if let Some(next) = labels.get(i + 1) {
                if looks_like_region(next) {
                    return Some(next);
                }
            }
        }
    }
    None
}

/// Read a native Bedrock Converse `image` content block into an `IrBlock::Image`, or `None` when
/// the block carries no usable source.
///
/// The Converse `ImageSource` union has TWO members: `source.bytes` (base64) and
/// `source.s3Location` (`{"uri":...,"bucketOwner":...}`). The old reader only decoded `bytes`, so an
/// S3-referenced image read with `data = ""` — silently dropping the image, diverging from a direct
/// AWS call and breaking a same-protocol passthrough. We now ALSO probe `source.s3Location` and,
/// when present, carry the whole s3Location object (plus the captured `format`) in the typed
/// `IrImageSource::Vendor { vendor: "bedrock", value }` escape so `bedrock_image_block` can re-emit
/// `source.s3Location` on same-protocol egress (a foreign writer drops the vendor ref). A base64
/// image reads as `IrImageSource::Base64`. A block with neither source yields `None` so a
/// content-less image is not injected as an empty-bytes block.
fn read_bedrock_image_block(image: &serde_json::Value) -> Option<crate::ir::IrBlock> {
    let format_str = image
        .get("format")
        .and_then(|f| f.as_str())
        .unwrap_or("")
        .to_string();
    let source = image.get("source");

    // Prefer inline base64 `bytes`.
    if let Some(bytes) = source.and_then(|s| s.get("bytes")).and_then(|b| b.as_str()) {
        return Some(crate::ir::IrBlock::Image {
            source: crate::ir::IrImageSource::Base64 {
                media_type: format!("image/{}", format_str),
                data: bytes.to_string(),
            },
            cache_control: None,
        });
    }

    // Otherwise, an `s3Location` source — a Bedrock-scoped reference the typed `S3` variant carries
    // as `{format, s3Location}` so the writer re-emits a faithful `source.s3Location` block on
    // same-protocol egress instead of dropping the image.
    if let Some(s3_location) = source.and_then(|s| s.get("s3Location")) {
        if s3_location.is_object() {
            return Some(crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Vendor {
                    vendor: "bedrock",
                    value: serde_json::json!({
                        "format": format_str,
                        "s3Location": s3_location.clone(),
                    }),
                },
                cache_control: None,
            });
        }
    }

    None
}

/// Normalize Bedrock Converse's native `toolConfig.toolChoice` into the IR union (PF-H1).
///
/// Bedrock shape: `{"auto":{}}` → `Auto`, `{"any":{}}` → `Required` (must call some tool),
/// `{"tool":{"name":"X"}}` → the targeted `Tool{name:"X"}`. Bedrock has NO native "none". An
/// absent or unrecognized shape yields `None` (omitted) so a request that never carried a directive
/// does not gain a spurious one. Takes the whole `toolConfig` object so the caller can pass
/// `obj.get("toolConfig")` directly.
fn read_bedrock_tool_choice(
    tool_config: Option<&serde_json::Value>,
) -> Option<crate::ir::IrToolChoice> {
    let tc = tool_config?.get("toolChoice")?.as_object()?;
    if tc.contains_key("auto") {
        Some(crate::ir::IrToolChoice::Auto)
    } else if tc.contains_key("any") {
        Some(crate::ir::IrToolChoice::Required)
    } else if let Some(tool) = tc.get("tool") {
        tool.get("name")
            .and_then(|n| n.as_str())
            .map(|name| crate::ir::IrToolChoice::Tool {
                name: name.to_string(),
            })
    } else {
        None
    }
}

/// Emit the IR tool-choice union in Bedrock's native `toolChoice` shape (PF-H1).
///
/// Returns `None` for `IrToolChoice::None`: Bedrock Converse has no native "don't call a tool"
/// directive, so the closest faithful behavior is to omit `toolChoice` entirely (the backend then
/// applies its own default) rather than emit an invalid shape.
fn write_bedrock_tool_choice(tc: &crate::ir::IrToolChoice) -> Option<serde_json::Value> {
    match tc {
        crate::ir::IrToolChoice::Auto => Some(serde_json::json!({"auto": {}})),
        crate::ir::IrToolChoice::Required => Some(serde_json::json!({"any": {}})),
        crate::ir::IrToolChoice::Tool { name } => Some(serde_json::json!({"tool": {"name": name}})),
        crate::ir::IrToolChoice::None => None,
    }
}

/// Bedrock stopReason → canonical IR stop_reason.
fn stop_reason_map(ward: &str) -> crate::ir::IrStopReason {
    use crate::ir::IrStopReason as S;
    match ward {
        "end_turn" => S::EndTurn,
        "tool_use" => S::ToolUse,
        "max_tokens" => S::MaxTokens,
        "stop_sequence" => S::StopSequence,
        // Both moderation outcomes fold to the canonical `Safety`.
        "content_filtered" | "guardrail_intervened" => S::Safety,
        _ => S::Other,
    }
}

/// Canonical IR stop_reason → Bedrock stopReason (inverse of `stop_reason_map`).
fn stop_reason_reverse(canonical: crate::ir::IrStopReason) -> &'static str {
    use crate::ir::IrStopReason as S;
    match canonical {
        S::EndTurn => "end_turn",
        S::ToolUse => "tool_use",
        S::MaxTokens => "max_tokens",
        S::StopSequence => "stop_sequence",
        S::Safety => "content_filtered",
        // refusal / error / pause_turn / other have no valid Converse `stopReason` → degrade to
        // end_turn rather than emit an off-spec value a strict Converse client rejects.
        S::Refusal | S::Error | S::PauseTurn | S::Other => "end_turn",
    }
}

/// Read the prompt-cache token fields off a Bedrock Converse `usage` object into the IR's
/// `(cache_creation_input_tokens, cache_read_input_tokens)` pair. AWS names the write side
/// `cacheWriteInputTokens` (tokens written to the cache this turn = a cache *creation* in
/// Anthropic terminology) and the read side `cacheReadInputTokens` (per the Bedrock
/// `TokenUsage` shape). Both are OPTIONAL on the wire — a model/region without prompt caching,
/// or a request that neither created nor read a cache entry, simply omits them — so each maps
/// to `None` when absent (distinct from `Some(0)`, which a backend may legitimately send when
/// caching was active but contributed zero tokens). The old code hardcoded both to `None`,
/// silently dropping real cache accounting on every read; this plumbs the actual values so a
/// Bedrock→Bedrock (and Bedrock→Anthropic) round-trip preserves cache usage.
fn read_cache_usage(
    usage_obj: Option<&serde_json::Map<String, serde_json::Value>>,
) -> (Option<u64>, Option<u64>) {
    let cache_creation_input_tokens = usage_obj
        .and_then(|u| u.get("cacheWriteInputTokens"))
        .and_then(|v| v.as_u64());
    let cache_read_input_tokens = usage_obj
        .and_then(|u| u.get("cacheReadInputTokens"))
        .and_then(|v| v.as_u64());
    (cache_creation_input_tokens, cache_read_input_tokens)
}

/// Write the IR's prompt-cache token fields back onto a Bedrock Converse `usage` object, the
/// inverse of `read_cache_usage`. Emits `cacheWriteInputTokens` from `cache_creation_input_tokens`
/// and `cacheReadInputTokens` from `cache_read_input_tokens`, and ONLY when the IR carries a value
/// (`Some`) — a `None` field is omitted rather than serialized as `0`, so a Bedrock→Bedrock
/// round-trip of a no-cache response stays byte-identical to native AWS (which omits the fields
/// when caching was inactive) and never fabricates a cache-accounting tell. The old writer dropped
/// these fields entirely.
fn write_cache_usage(
    usage_obj: &mut serde_json::Map<String, serde_json::Value>,
    usage: &crate::ir::IrUsage,
) {
    if let Some(ccit) = usage.cache_creation_input_tokens {
        usage_obj.insert("cacheWriteInputTokens".to_string(), ccit.into());
    }
    if let Some(crit) = usage.cache_read_input_tokens {
        usage_obj.insert("cacheReadInputTokens".to_string(), crit.into());
    }
}

/// Upper bound applied to the upstream-controlled Bedrock ConverseStream `contentBlockIndex` at
/// every stream read site (`contentBlockStart` / `contentBlockDelta` / `contentBlockStop`). The
/// wire value is attacker-controllable: a hostile/buggy backend can send an arbitrarily huge index
/// (up to `u64::MAX`), which the old code cast straight to `usize` and forwarded into IR
/// `BlockStart`/`BlockDelta`/`BlockStop` indices. A downstream ingress writer keying per-index
/// state off that value would then allocate/track against a pathological index. A real Converse
/// stream emits small sequential block indices (0, 1, 2, …); any larger value is malformed, so we
/// clamp to this bounded cap before it enters the IR. Mirrors the OpenAI reader's `MAX_TOOL_INDEX`
/// and the Cohere reader's `MAX_TOOL_FRAME_INDEX` clamps.
const MAX_CONTENT_BLOCK_INDEX: u64 = 1023;

/// Read the upstream-controlled `contentBlockIndex` off a Bedrock ConverseStream frame, defaulting
/// to 0 when absent/non-numeric, and clamp it to `MAX_CONTENT_BLOCK_INDEX` so a crafted huge index
/// can never be forwarded into an IR block index. Shared by all three stream read sites so the
/// clamp stays uniform.
fn clamp_content_block_index(data: &serde_json::Value) -> usize {
    data.get("contentBlockIndex")
        .and_then(|i| i.as_u64())
        .unwrap_or(0)
        .min(MAX_CONTENT_BLOCK_INDEX) as usize
}

#[derive(Clone)]
pub(crate) struct BedrockReader;

/// Bedrock-ingress per-stream framing state machine. A native AWS SDK ConverseStream emits the terminal
/// information as a `messageStop` frame FOLLOWED by EXACTLY ONE `metadata` (usage) frame — but the IR
/// carries a single combined `MessageDelta{stop_reason, usage}` (the egress reader collapses any
/// protocol's stop/usage into one), and a foreign backend can split stop vs usage across two events. So
/// this state machine fans the combined delta into a stop-only delta (→ `messageStop`) plus, when usage
/// rode with the stop, a usage-only delta (→ `metadata`); otherwise it DEFERS the metadata to a trailing
/// usage-only delta (OpenAI `include_usage`) or — if none arrives (default OpenAI streaming) — to the
/// finish-time flush. The `emitted`/`pending` flags enforce the one-metadata invariant however the
/// backend split the terminal info. Built per stream via [`BedrockWriter::new_stream_framing`]; reached
/// only on Bedrock ingress.
#[derive(Default)]
struct BedrockStreamFraming {
    /// Whether a `metadata` (usage) frame has ALREADY been emitted for this stream. Guards the
    /// exactly-one-metadata invariant: suppress a duplicate usage-only delta, and skip the finish flush.
    emitted: bool,
    /// Set when a combined stop-delta arrived with all-zero usage so the `metadata` frame was DEFERRED
    /// (awaiting a trailing usage-only delta). If that delta never arrives (default OpenAI streaming),
    /// `on_finish` flushes a single best-effort zero-usage `metadata` so the stream is never missing its
    /// terminal frame.
    pending: bool,
}

impl super::StreamFraming for BedrockStreamFraming {
    fn abort_exception_type(&self) -> Option<&'static str> {
        // A native ConverseStream that aborts emits a modeled exception frame; busbar uses
        // `InternalServerException` (the generic server-fault type) so the close is well-formed for the
        // AWS SDK decoder. Keeps the Bedrock wire exception-type name in this module, not the agnostic
        // translator (which calls this seam and names no wire type).
        Some(EXC_INTERNAL_SERVER)
    }

    fn inject_streaming_metrics(
        &self,
        event_type: &str,
        data: &mut serde_json::Value,
        started_at: Option<std::time::Instant>,
    ) {
        // A native ConverseStream `metadata` frame carries a `metrics` object with the stream's real
        // `latencyMs`. Inject the elapsed wall-clock since the first byte was fed; if timing is somehow
        // unavailable, OMIT `metrics` entirely rather than emit a tell-tale `0`. The writer leaves
        // `metrics` off so this is the single source of it. Only the `metadata` frame is special.
        if event_type != ET_METADATA {
            return;
        }
        if let Some(start) = started_at {
            // u128 → u64 for JSON; saturate (elapsed never realistically exceeds u64 ms).
            let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
            if let Some(obj) = data.as_object_mut() {
                let mut metrics = serde_json::Map::new();
                metrics.insert(
                    FIELD_LATENCY_MS.to_string(),
                    serde_json::Value::from(elapsed_ms),
                );
                obj.insert(
                    FIELD_METRICS.to_string(),
                    serde_json::Value::Object(metrics),
                );
            }
        }
    }

    fn on_combined_stop_delta(
        &mut self,
        stop_reason: crate::ir::IrStopReason,
        stop_sequence: Option<String>,
        usage: &crate::ir::IrUsage,
    ) -> Option<Vec<crate::ir::IrStreamEvent>> {
        // Frame 1: stop-only delta → `messageStop` (usage, if any, rides frame 2).
        let mut events = vec![crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some(stop_reason),
            stop_sequence: stop_sequence.clone(),
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        }];
        // Frame 2: `metadata` carrying the token usage — but a native ConverseStream emits EXACTLY ONE
        // `metadata`. Emit it ONLY if real usage rode WITH the stop (the native Bedrock→Bedrock case
        // AND any egress that bundles usage into the stop delta). If usage is all-zero, this is an
        // OpenAI `include_usage` stop chunk whose tokens arrive in a SEPARATE trailing usage-only delta
        // — DEFER the metadata to that delta so we emit it once with the REAL tokens, never a zero-usage
        // frame.
        // Guard the metadata frame on `!self.emitted` so a (malformed/adversarial) egress that emits a
        // SECOND combined stop-delta with usage cannot produce a second `metadata` frame — the
        // exactly-one-metadata invariant holds even against a hostile backend. A well-behaved egress
        // (all 6 readers) emits at most one terminal stop-delta, so this is byte-identical for real
        // streams; once emitted, a repeat call yields only the (idempotent) stop frame.
        // Cache-only usage counts too: a FULL cache hit can carry `input_tokens == 0 &&
        // output_tokens == 0` yet non-zero `cache_read_input_tokens` / `cache_creation_input_tokens`.
        // Omitting the cache fields deferred the metadata frame and later flushed a ZERO-usage
        // `metadata` frame, so the Bedrock client SDK's stream-metadata callback under-reported the
        // cache tokens on the wire. Include them so the real usage is emitted inline. (audit c2r4.)
        let has_usage = usage.input_tokens != 0
            || usage.output_tokens != 0
            || usage.cache_read_input_tokens.unwrap_or(0) != 0
            || usage.cache_creation_input_tokens.unwrap_or(0) != 0;
        if !self.emitted {
            if has_usage {
                events.push(crate::ir::IrStreamEvent::MessageDelta {
                    stop_reason: None,
                    stop_sequence,
                    usage: usage.clone(),
                });
                self.emitted = true;
                self.pending = false;
            } else {
                // Deferred: the stop carried no usage. The trailing usage-only delta (OpenAI
                // `include_usage`) will emit the metadata if it arrives — but in DEFAULT OpenAI
                // streaming (no `include_usage`) it never does, so mark the metadata pending and let
                // `on_finish` flush a single zero-usage `metadata` frame at end-of-stream. A native
                // ConverseStream ALWAYS ends with a metadata frame; its total absence is a proxy tell
                // and loses token accounting.
                self.pending = true;
            }
        }
        Some(events)
    }

    fn on_usage_only_delta(&mut self) -> Option<bool> {
        // A usage-only delta (`stop_reason: None`) → a `metadata` frame. This is the trailing OpenAI
        // `include_usage` chunk (or a native usage frame). Emit at most once: suppress it if a
        // `metadata` already rode with the stop above, so the stream carries exactly one metadata frame
        // regardless of how the egress backend split stop vs usage.
        if self.emitted {
            return Some(false);
        }
        self.emitted = true;
        self.pending = false; // the deferral is now resolved
        Some(true)
    }

    fn on_finish(&mut self) -> Option<crate::ir::IrStreamEvent> {
        // If a combined stop-delta deferred the `metadata` frame (zero usage, expecting a trailing
        // usage-only delta) and that delta never arrived — the DEFAULT OpenAI streaming case — flush a
        // single best-effort zero-usage `metadata` frame now.
        if !self.pending || self.emitted {
            return None;
        }
        self.emitted = true;
        self.pending = false;
        Some(crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        })
    }
}

#[derive(Clone)]
pub(crate) struct BedrockWriter;

/// Wrap a SINGLE non-stream `IrResponse` into a Bedrock ConverseStream binary `eventstream` byte
/// sequence (`application/vnd.amazon.eventstream`), for the case where a bedrock-ingress client
/// requested `ConverseStream` (`wants_stream`) but the cross-protocol upstream answered with a
/// BUFFERED (non-SSE) 2xx. Returning that single response as `application/json` + a non-stream
/// Converse body is undecodable by the AWS SDK's eventstream decoder (it expects framed
/// `messageStart`/`contentBlockDelta`/…/`messageStop`/`metadata` events) — a hard functional failure
/// and a deterministic proxy tell on the headline bedrock-ingress surface. This synthesizes the
/// native frame sequence a real ConverseStream emits for the same completion: one `messageStart`,
/// then per content block a `contentBlockStart` + its `contentBlockDelta`(s) + `contentBlockStop`,
/// then `messageStop` (carrying the stop reason) and a trailing `metadata` frame (carrying token
/// usage) — matching the two-frame stop/usage split the Bedrock writer's `MessageDelta` arm expects.
/// Each event is rendered through the SAME `bedrock` writer used on the live streaming path and
/// encoded via `eventstream::encode_frame`, so the bytes are byte-for-byte what a native stream sends.
/// Never panics on the request path: a frame whose payload fails to serialize is skipped.
pub(crate) fn bedrock_response_to_eventstream(
    ir: &crate::ir::IrResponse,
    elapsed_ms: Option<u64>,
) -> Vec<u8> {
    use crate::ir::{IrBlock, IrBlockMeta, IrDelta, IrStreamEvent, IrUsage};
    let writer = crate::proto::Protocol::bedrock();
    let writer = writer.writer();
    let mut out: Vec<u8> = Vec::new();
    // Render one IR stream event through the bedrock writer and append the encoded frame (if the
    // writer maps it to a native frame; some IR events have no Bedrock analog and yield None).
    let push = |ev: &IrStreamEvent, out: &mut Vec<u8>| {
        if let Some((event_type, mut payload)) = writer.write_response_event(ev) {
            // A native ConverseStream `metadata` frame ALWAYS carries a `metrics.latencyMs` (the SDK
            // surfaces it via `ConverseStreamMetadataEvent::metrics()`); the bedrock writer's
            // `MessageDelta` arm deliberately omits `metrics`, and the LIVE StreamTranslate path injects
            // it there (`proto::mod.rs`). On this BUFFERED synthesis path StreamTranslate is bypassed,
            // so inject it HERE too — otherwise `metrics == None`, which a real endpoint never returns
            // (a deterministic proxy tell). Use the request's elapsed wall-clock, consistent with the
            // live path; if timing is unavailable OMIT `metrics` rather than emit a tell-tale `0`.
            if event_type == ET_METADATA {
                if let (Some(ms), Some(obj)) = (elapsed_ms, payload.as_object_mut()) {
                    let mut metrics = serde_json::Map::new();
                    metrics.insert(FIELD_LATENCY_MS.to_string(), serde_json::Value::from(ms));
                    obj.insert(
                        FIELD_METRICS.to_string(),
                        serde_json::Value::Object(metrics),
                    );
                }
            }
            if let Ok(bytes) = crate::json::to_vec(&payload) {
                out.extend_from_slice(&crate::eventstream::encode_frame(&event_type, &bytes));
            }
        }
    };

    // messageStart
    push(
        &IrStreamEvent::MessageStart {
            role: ir.role,
            usage: None,
            id: None,
            created: None,
            model: ir.model.clone(),
        },
        &mut out,
    );

    // Per content block: contentBlockStart → contentBlockDelta(s) → contentBlockStop. Mirror the
    // live streaming fan-out (`read_response_events`) so the SDK sees the same per-block framing.
    for (index, block) in ir.content.iter().enumerate() {
        match block {
            IrBlock::Text { text, .. } => {
                push(
                    &IrStreamEvent::BlockStart {
                        index,
                        block: IrBlockMeta::Text,
                    },
                    &mut out,
                );
                push(
                    &IrStreamEvent::BlockDelta {
                        index,
                        delta: IrDelta::TextDelta(text.clone()),
                    },
                    &mut out,
                );
                push(&IrStreamEvent::BlockStop { index }, &mut out);
            }
            IrBlock::ToolUse {
                id, name, input, ..
            } => {
                push(
                    &IrStreamEvent::BlockStart {
                        index,
                        block: IrBlockMeta::ToolUse {
                            id: id.clone(),
                            name: name.clone(),
                        },
                    },
                    &mut out,
                );
                push(
                    &IrStreamEvent::BlockDelta {
                        index,
                        delta: IrDelta::InputJsonDelta(input.to_string()),
                    },
                    &mut out,
                );
                push(&IrStreamEvent::BlockStop { index }, &mut out);
            }
            // A Thinking (reasoningContent) block DOES have native ConverseStream frames — the
            // Bedrock writer emits `contentBlockStart{reasoningContent:{}}` for the
            // `IrBlockMeta::Thinking` start and `contentBlockDelta{reasoningContent:{…}}` for the
            // ThinkingDelta / SignatureDelta / RedactedReasoningDelta deltas. The old comment claimed
            // the writer maps them to None and skipped the block, silently dropping upstream
            // reasoning on a cross-protocol→Bedrock streaming client. Synthesize the same
            // start/delta(s)/stop the live streaming path produces. (found: audit c2r2.)
            IrBlock::Thinking {
                text,
                signature,
                redacted,
                ..
            } => {
                push(
                    &IrStreamEvent::BlockStart {
                        index,
                        block: IrBlockMeta::Thinking,
                    },
                    &mut out,
                );
                if *redacted {
                    // Opaque encrypted reasoning — `text` holds the bytes, ONE delta carries them.
                    push(
                        &IrStreamEvent::BlockDelta {
                            index,
                            delta: IrDelta::RedactedReasoningDelta(text.clone()),
                        },
                        &mut out,
                    );
                } else {
                    push(
                        &IrStreamEvent::BlockDelta {
                            index,
                            delta: IrDelta::ThinkingDelta(text.clone()),
                        },
                        &mut out,
                    );
                    if let Some(sig) = signature {
                        push(
                            &IrStreamEvent::BlockDelta {
                                index,
                                delta: IrDelta::SignatureDelta(sig.clone()),
                            },
                            &mut out,
                        );
                    }
                }
                push(&IrStreamEvent::BlockStop { index }, &mut out);
            }
            // ToolResult/Image/Json blocks have no native ConverseStream content-delta frame on this
            // synthesized path; skip them. Enumerated EXPLICITLY (no `_` catch-all) so a future
            // `IrBlock` variant is a COMPILE error here rather than silent data loss.
            IrBlock::ToolResult { .. } | IrBlock::Image { .. } | IrBlock::Json(_) => {}
        }
    }

    // messageStop (stop reason) then metadata (usage) — the writer's `MessageDelta` arm maps a
    // stop_reason-bearing delta to `messageStop` and a usage-only delta to `metadata`, exactly the
    // two native frames a real ConverseStream ends with.
    // Default the synthesized stop reason from the IR CONTENT, not unconditionally `end_turn`. A
    // native Bedrock Converse reports `tool_use` for a turn that emitted a tool call; if the buffered
    // IR carried a ToolUse block but no explicit stop_reason (a cross-protocol 2xx whose upstream
    // omitted it), default to the canonical `tool_use` so `stop_reason_reverse` yields `tool_use` and
    // an AWS SDK consumer keying agentic control flow off stopReason re-invokes the tool. Only fall
    // back to `end_turn` when the completion carried no tool call.
    let default_stop_reason = if ir
        .content
        .iter()
        .any(|b| matches!(b, IrBlock::ToolUse { .. }))
    {
        crate::ir::IrStopReason::ToolUse
    } else {
        crate::ir::IrStopReason::EndTurn
    };
    push(
        &IrStreamEvent::MessageDelta {
            stop_reason: ir.stop_reason.or(Some(default_stop_reason)),
            usage: IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            stop_sequence: None,
        },
        &mut out,
    );
    push(
        &IrStreamEvent::MessageDelta {
            stop_reason: None,
            usage: ir.usage.clone(),
            stop_sequence: None,
        },
        &mut out,
    );
    out
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

mod reader;
mod writer;
pub(crate) use writer::sigv4_sign_headers;
