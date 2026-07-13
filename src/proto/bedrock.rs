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
/// (`proto/mod.rs` via `wrap_buffered_as_stream` / `forward.rs` via `maybe_attach_response_request_id`)
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
/// `BedrockWriter::attach_error_response_headers` vtable method — the only caller; `forward.rs::
/// ingress_error`, `route.rs`, and `auth.rs` reach it through that vtable (not by name), so they
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

impl ProtocolReader for BedrockReader {
    fn uses_sigv4_ingress_auth(&self) -> bool {
        // A Bedrock-SDK client signs inbound requests with AWS SigV4 (access-key-id + secret tied to
        // a busbar virtual key), not a bearer token — so the auth middleware runs the SigV4 verify
        // path for bedrock ingress. Every other protocol uses the default (bearer / api-key).
        true
    }

    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the body once. Bedrock error responses carry the human-readable
        // text in `message` and the machine-readable error type in `__type`
        // (e.g. `ValidationException`, `ThrottlingException`). The structured
        // type is what the breaker's error_map keys on for fine-grained routing,
        // so it must come from `__type`, not from `message`.
        let (provider_code, structured_type) = match crate::json::parse::<serde_json::Value>(body) {
            Ok(json) => {
                let provider_code = json
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(String::from);
                // AWS may also serialise the type as `__type` containing a
                // shape ARN suffix (e.g. `com.amazon...#ThrottlingException`);
                // keep only the trailing type token in that case.
                let structured_type = json
                    .get("__type")
                    .and_then(|t| t.as_str())
                    .map(|t| t.rsplit(['#', '/']).next().unwrap_or(t).to_string());
                (provider_code, structured_type)
            }
            Err(_) => (None, None),
        };

        // Bedrock has no distinct context-length error CODE: an oversized request comes back as a
        // generic `ValidationException` whose human-readable `message` carries the signal (e.g.
        // "Input is longer than the maximum number of tokens allowed" or a "maximum-tokens …
        // requested" phrasing). Without surfacing the canonical `context_length_exceeded` code here,
        // the breaker pipeline (normalize_raw_error → StatusClass) would route an oversized request
        // as a plain ClientError and PENALIZE the lane instead of failing over without penalty. Mirror
        // `AnthropicReader::extract_error`: scan the raw body for the context-length phrasing and
        // override `provider_code` so the breaker (breaker.rs `code == "context_length_exceeded"`)
        // maps it to `StatusClass::ContextLength`. Keep this in sync with the `classify` helper below.
        //
        // GATE THE SCAN ON A 400. Bedrock ONLY emits an oversized-context error as a `400
        // ValidationException` — never as a 5xx. The raw body-text scan, left ungated, would also
        // fire on a 5xx whose body merely happened to echo the phrasing (e.g. an upstream
        // server-error envelope quoting the request, or a proxied error message), misclassifying a
        // genuine ServerError as ContextLength and triggering a no-penalty failover that masks an
        // unhealthy lane. Confining the override to `status == 400` means a 5xx can never trip it
        // (the structured ServerError path is preserved), while every real Bedrock context-length
        // error — which is always a 400 — is still caught.
        let provider_code = if status == StatusCode::BAD_REQUEST {
            let lower = String::from_utf8_lossy(body).to_lowercase();
            if lower.contains("input is longer than the maximum number of tokens")
                || (lower.contains("maximum-tokens") && lower.contains("requested"))
                || (lower.contains("exceeds the maximum")
                    && (lower.contains("token") || lower.contains("context")))
            {
                Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string())
            } else {
                provider_code
            }
        } else {
            provider_code
        };

        crate::breaker::RawUpstreamError {
            http_status: status.as_u16(),
            provider_code,
            structured_type,
            retry_after_secs: None,
        }
    }

    #[cfg(test)]
    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal {
        let text = String::from_utf8_lossy(body);
        let lower = text.to_lowercase();

        // Keep this set of context-length phrasings in LOCKSTEP with the production
        // `extract_error` above (R21 #17 added the third `exceeds the maximum` pattern there but
        // not here, drifting the two). All three must match identically so the test-only classifier
        // mirrors what the breaker actually sees. The `status == 400` gate is ALSO part of that
        // lockstep (R23 LOW #14): `extract_error` only runs the body-scan override on a 400
        // ValidationException, so a 5xx body that happens to echo context-length phrasing must NOT
        // be reclassified as ContextLength here either — it falls through to the ServerError arm
        // below.
        if status == StatusCode::BAD_REQUEST
            && (lower.contains("input is longer than the maximum number of tokens")
                || (lower.contains("maximum-tokens") && lower.contains("requested"))
                || (lower.contains("exceeds the maximum")
                    && (lower.contains("token") || lower.contains("context"))))
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some(crate::proxy::PROVIDER_CODE_CONTEXT_LENGTH.to_string()),
                retry_after: None,
            };
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            return CanonicalSignal {
                class: StatusClass::RateLimit,
                provider_signal: Some("429".to_string()),
                retry_after: None,
            };
        }

        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return CanonicalSignal {
                class: StatusClass::Auth,
                provider_signal: Some("auth".to_string()),
                retry_after: None,
            };
        }

        if status.is_server_error() {
            return CanonicalSignal {
                class: StatusClass::ServerError,
                provider_signal: Some("5xx".to_string()),
                retry_after: None,
            };
        }

        if status.is_client_error() {
            return CanonicalSignal {
                class: StatusClass::ClientError,
                provider_signal: Some(format!("{}", status.as_u16())),
                retry_after: None,
            };
        }

        CanonicalSignal {
            class: StatusClass::ClientError,
            provider_signal: None,
            retry_after: None,
        }
    }

    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        // Collect every unmodeled top-level request field into `extra` so a same-protocol
        // Bedrock->Bedrock passthrough re-emits them faithfully (see `write_request`, which merges
        // `req.extra`). Without this, native Converse fields this reader does not explicitly model —
        // `topP`, `topK`, `stopSequences`, `additionalModelRequestFields`, `guardrailConfig`,
        // `additionalModelResponseFieldPaths`, `performanceConfig`, `promptVariables`, etc. — are
        // silently dropped, changing model behaviour (guardrails disabled, sampling reset) and making
        // the proxy behaviourally divergent from a direct AWS call. Mirrors the Gemini/Cohere readers.
        // `stream` is the route-injected streaming discriminant captured into `IrRequest.stream`
        // below; it is intentionally NOT echoed via `extra` (a native Bedrock body never carries it,
        // and re-emitting it would be a tell). All other modeled keys are re-serialised by
        // `write_request` from the structured IR, so excluding them here avoids a double-emit.
        // NOTE: `inferenceConfig` is DELIBERATELY NOT modeled-out here. This reader only typed two of
        // its sub-fields (`maxTokens`, `temperature`); the rest — `stopSequences`, `topP`, `topK`,
        // `stopCriteria`, and any future AWS-defined sub-field — were silently dropped on both
        // same-protocol passthrough AND cross-protocol egress, changing model behaviour (no stop at
        // the requested sequences, different sampling) and making the proxy behaviourally divergent
        // from a direct AWS call. So we capture the WHOLE raw `inferenceConfig` object into `extra`
        // (preserving every sub-field verbatim) and let `write_request` overlay the two typed fields
        // (`maxTokens`/`temperature`) onto that raw object. The two typed fields are still parsed into
        // the structured IR below for cross-protocol egress; the raw capture is what makes a
        // Bedrock->Bedrock passthrough re-emit `stopSequences`/`topP`/`topK` faithfully.
        // The modeled top-level keys this reader handles structurally (so they must NOT be swept into
        // `extra`). Held as a sorted `&'static` slice and probed with `binary_search`: a fixed,
        // four-element membership set that was previously a `HashSet` rebuilt (and heap-allocated) on
        // every `read_request` call on the Bedrock ingress hot path. A sorted-slice binary search is
        // allocation-free and faster than hashing for a set this small. MUST stay sorted for
        // `binary_search` — keep alphabetical when editing.
        // NOTE: `toolConfig` is DELIBERATELY NOT modeled-out here (mirroring `inferenceConfig`). This
        // reader only typed ONE of its sub-fields — `tools` (extracted into `ir.tools` below) — while
        // the rest, notably `toolChoice` (`{auto:{}}` / `{any:{}}` / `{tool:{name:...}}`, the
        // force-tool-use control) and any future AWS-defined sub-field, were silently dropped on a
        // same-protocol passthrough whenever the writer rebuilt the body. A native AWS client that sets
        // `toolChoice: {any: {}}` to force mandatory tool use would have that constraint stripped,
        // changing model behaviour (the model may skip the tool) and diverging from a direct AWS call.
        // So we capture the WHOLE raw `toolConfig` object into `extra` (preserving `toolChoice`
        // verbatim) and let `write_request` overlay the typed `tools` array onto that raw object. The
        // `tools` array is still parsed into the structured IR below for cross-protocol egress; the raw
        // capture is what makes a Bedrock->Bedrock passthrough re-emit `toolChoice` faithfully.
        const MODELED_KEYS: &[&str] = &["messages", "model", "stream", "system"];
        debug_assert!(
            MODELED_KEYS.windows(2).all(|w| w[0] < w[1]),
            "MODELED_KEYS must stay sorted for binary_search"
        );

        let mut extra = serde_json::Map::new();
        for (key, value) in obj.iter() {
            if MODELED_KEYS.binary_search(&key.as_str()).is_err() {
                extra.insert(key.clone(), value.clone());
            }
        }

        // Captures native `cachePoint` markers (with their ORIGINAL absolute array index) so the
        // writer can re-emit them at the same position on a same-protocol passthrough. See
        // `CACHE_POINTS_SENTINEL`. Kept as `Value`s ready to nest under the sentinel object.
        let mut system_cache_points: Vec<serde_json::Value> = Vec::new();
        let mut message_cache_points: Vec<serde_json::Value> = Vec::new();
        // Captured native `guardContent` (inline Guardrails) markers, same stash shape as the
        // cachePoint capture; see `GUARD_CONTENT_SENTINEL`.
        let mut system_guard_content: Vec<serde_json::Value> = Vec::new();
        let mut message_guard_content: Vec<serde_json::Value> = Vec::new();

        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(system_arr) = obj.get("system").and_then(|s| s.as_array()) {
            for (idx, sys_val) in system_arr.iter().enumerate() {
                if let Some(text_val) = sys_val.get("text").and_then(|t| t.as_str()) {
                    system_blocks.push(crate::ir::IrBlock::Text {
                        text: text_val.to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    });
                } else if let Some(cache_point) = sys_val.get("cachePoint") {
                    // No IR counterpart for a prompt-cache marker; stash it with its original index
                    // so the writer re-emits it verbatim at the same position (a same-protocol
                    // passthrough keeps prompt caching enabled instead of silently dropping it).
                    system_cache_points.push(serde_json::json!({
                        "i": idx,
                        "block": { "cachePoint": cache_point.clone() },
                    }));
                    // ALSO map the marker onto the preceding block's first-class IR `cache_control`
                    // (H3 cross-protocol): the positional stash above is dropped on the cross-protocol
                    // seam, so without this a Bedrock->Anthropic hop would lose the prompt-cache
                    // boundary. Additive — the stash still drives the byte-identical same-protocol
                    // round-trip; the writer suppresses the inline `cache_control` emission whenever
                    // the stash is present, so the two never double-emit.
                    set_preceding_block_cache_control(&mut system_blocks);
                } else if let Some(guard_content) = sys_val.get("guardContent") {
                    // No IR counterpart for an inline Guardrails marker; stash it with its original
                    // index so the writer re-emits it verbatim at the same position (a same-protocol
                    // passthrough keeps the guardrail span the caller marked instead of silently
                    // dropping it). See `GUARD_CONTENT_SENTINEL`.
                    system_guard_content.push(serde_json::json!({
                        "i": idx,
                        "block": { "guardContent": guard_content.clone() },
                    }));
                }
            }
        }

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();
        if let Some(msgs_arr) = obj.get("messages").and_then(|m| m.as_array()) {
            for (msg_idx, msg_val) in msgs_arr.iter().enumerate() {
                let role_str = msg_val.get("role").and_then(|r| r.as_str()).unwrap_or("");

                let role = match role_str {
                    "user" => crate::ir::IrRole::User,
                    "assistant" => crate::ir::IrRole::Assistant,
                    _ => {
                        return Err(IrError {
                            class: StatusClass::ClientError,
                            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
                            retry_after: None,
                        })
                    }
                };

                let mut msg_content: Vec<crate::ir::IrBlock> = Vec::new();
                if let Some(content_arr) = msg_val.get("content").and_then(|c| c.as_array()) {
                    for (block_idx, content_val) in content_arr.iter().enumerate() {
                        if let Some(text_val) = content_val.get("text").and_then(|t| t.as_str()) {
                            msg_content.push(crate::ir::IrBlock::Text {
                                text: text_val.to_string(),
                                cache_control: None,
                                citations: Vec::new(),
                            });
                        } else if let Some(tool_use) = content_val.get("toolUse") {
                            let tu_id = tool_use
                                .get("toolUseId")
                                .and_then(|id| id.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = tool_use
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let input = tool_use
                                .get("input")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null);

                            msg_content.push(crate::ir::IrBlock::ToolUse {
                                id: tu_id,
                                name,
                                input,
                                cache_control: None,
                            });
                        } else if let Some(tool_result) = content_val.get("toolResult") {
                            let tu_id = tool_result
                                .get("toolUseId")
                                .and_then(|id| id.as_str())
                                .unwrap_or("")
                                .to_string();

                            let mut inner_content: Vec<crate::ir::IrBlock> = Vec::new();
                            if let Some(inner_arr) =
                                tool_result.get("content").and_then(|c| c.as_array())
                            {
                                for inner_val in inner_arr {
                                    if let Some(text_val) =
                                        inner_val.get("text").and_then(|t| t.as_str())
                                    {
                                        inner_content.push(crate::ir::IrBlock::Text {
                                            text: text_val.to_string(),
                                            cache_control: None,
                                            citations: Vec::new(),
                                        });
                                    } else if let Some(json_val) = inner_val.get("json") {
                                        // A native Converse `{"json": <value>}` tool-result block is
                                        // structured data with no text/image analog — carry it as the
                                        // typed `IrBlock::Json` so `write_request` re-emits a faithful
                                        // `{"json": ...}` block on same-protocol egress (the old reader
                                        // serialized it into a `{"text": "..."}` string, losing the
                                        // json/text distinction).
                                        inner_content
                                            .push(crate::ir::IrBlock::Json(json_val.clone()));
                                    } else if let Some(image) = inner_val.get("image") {
                                        // The Converse `ToolResultContentBlock` union also includes
                                        // `image` (and `document`/`video`). Decode `image`
                                        // symmetric with the WRITER, which emits an `image` inside a
                                        // toolResult (see `write_request`) — the old reader skipped
                                        // any non-text/json block, silently dropping image tool
                                        // results and making read/write asymmetric. `document` and
                                        // `video` have no IR block counterpart (the IR models only
                                        // Text/Thinking/ToolUse/ToolResult/Image), so they remain
                                        // unrepresentable and are left undecoded — a documented
                                        // limitation, not a silent class-wide loss of all binary
                                        // tool-result content.
                                        if let Some(block) = read_bedrock_image_block(image) {
                                            inner_content.push(block);
                                        }
                                    } else if let Some(document) = inner_val.get("document") {
                                        // `document`/`video` members of the ToolResultContentBlock
                                        // union have no IR block counterpart and were silently lost.
                                        // Best-effort: an AWS DocumentBlock carries text only nested
                                        // under `source.content[].text` (there is NO flat `.text`);
                                        // flatten any such text into an IR Text block so a textual
                                        // document survives. Always warn so the (partial) loss is
                                        // observable rather than silent.
                                        tracing::warn!(
                                            "bedrock tool-result `document` block has no IR \
                                             counterpart; flattening any nested source text, \
                                             dropping the rest"
                                        );
                                        if let Some(content_arr) = document
                                            .get("source")
                                            .and_then(|s| s.get("content"))
                                            .and_then(|c| c.as_array())
                                        {
                                            for piece in content_arr {
                                                if let Some(t) =
                                                    piece.get("text").and_then(|t| t.as_str())
                                                {
                                                    inner_content.push(crate::ir::IrBlock::Text {
                                                        text: t.to_string(),
                                                        cache_control: None,
                                                        citations: Vec::new(),
                                                    });
                                                }
                                            }
                                        }
                                    } else if inner_val.get("video").is_some() {
                                        // `video` likewise has no IR counterpart and no flat text to
                                        // salvage — warn instead of dropping silently.
                                        tracing::warn!(
                                            "bedrock tool-result `video` block has no IR \
                                             counterpart; dropping it"
                                        );
                                    }
                                }
                            }

                            let is_error = tool_result
                                .get("status")
                                .and_then(|s| s.as_str())
                                .map(|s| s == "error")
                                .unwrap_or(false);

                            msg_content.push(crate::ir::IrBlock::ToolResult {
                                tool_use_id: tu_id,
                                content: inner_content,
                                is_error,
                                cache_control: None,
                            });
                        } else if let Some(image) = content_val.get("image") {
                            // Decode both `source.bytes` (base64) AND `source.s3Location` (an S3
                            // URI) — the two members of the Converse `ImageSource` union. An
                            // S3-referenced image is stashed under the `image_s3` sentinel so the
                            // writer re-emits `source.s3Location` on same-protocol egress instead of
                            // dropping it (the old reader only read `bytes`, silently losing it).
                            if let Some(block) = read_bedrock_image_block(image) {
                                msg_content.push(block);
                            }
                        } else if let Some(reasoning) = content_val.get("reasoningContent") {
                            // A native Converse `reasoningContent` (extended-thinking) block maps onto
                            // IR `Thinking { text, signature }` (mirroring anthropic.rs `thinking`).
                            // The old reader skipped every non-text/toolUse/toolResult/image/cachePoint
                            // block, so an assistant turn carrying its prior reasoning had that
                            // reasoning silently DROPPED on a same-protocol passthrough — and Bedrock
                            // REQUIRES the signed reasoning echoed back on the follow-up turn, so the
                            // loss made the proxy diverge from a direct AWS call. `redactedContent` is
                            // carried via the redacted-signature sentinel so it re-emits faithfully.
                            // A future union member yields `None` (left undecoded, not mis-mapped).
                            // `redacted` is a typed flag the reader sets only on a genuine native
                            // `redactedContent` member, so a client cannot forge a redacted block via a
                            // `reasoningText.signature` — no ingress scrub needed.
                            if let Some(block) = read_bedrock_reasoning_block(reasoning) {
                                msg_content.push(block);
                            }
                        } else if let Some(cache_point) = content_val.get("cachePoint") {
                            // No IR counterpart for a prompt-cache marker; stash it with its
                            // (message, block) index so the writer re-emits it verbatim at the same
                            // position on a same-protocol passthrough (prompt caching stays enabled
                            // instead of being silently dropped — a real cost regression otherwise).
                            message_cache_points.push(serde_json::json!({
                                "m": msg_idx,
                                "i": block_idx,
                                "block": { "cachePoint": cache_point.clone() },
                            }));
                            // ALSO map the marker onto the preceding block's first-class IR
                            // `cache_control` (H3 cross-protocol) so the prompt-cache boundary
                            // survives a Bedrock->Anthropic hop where the positional stash is dropped.
                            // Additive — see `set_preceding_block_cache_control`; the writer suppresses
                            // the inline emission while the stash is present, so no double-emit.
                            set_preceding_block_cache_control(&mut msg_content);
                        } else if let Some(guard_content) = content_val.get("guardContent") {
                            // No IR counterpart for an inline Guardrails marker; stash it with its
                            // (message, block) index so the writer re-emits it verbatim at the same
                            // position on a same-protocol passthrough (the guardrail span the caller
                            // marked stays present instead of being silently dropped). See
                            // `GUARD_CONTENT_SENTINEL`.
                            message_guard_content.push(serde_json::json!({
                                "m": msg_idx,
                                "i": block_idx,
                                "block": { "guardContent": guard_content.clone() },
                            }));
                        }
                    }
                }

                messages.push(crate::ir::IrMessage {
                    role,
                    content: msg_content,
                });
            }
        }

        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tool_config) = obj.get("toolConfig").and_then(|t| t.as_object()) {
            if let Some(tools_arr) = tool_config.get("tools").and_then(|t| t.as_array()) {
                for tool_val in tools_arr {
                    if let Some(tool_spec) = tool_val.get("toolSpec").and_then(|t| t.as_object()) {
                        let name = tool_spec
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let description = tool_spec
                            .get("description")
                            .and_then(|d| d.as_str().map(String::from));

                        let input_schema = if let Some(input_schema) = tool_spec.get("inputSchema")
                        {
                            input_schema
                                .get("json")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null)
                        } else {
                            serde_json::Value::Null
                        };

                        tools.push(crate::ir::IrTool {
                            name,
                            description,
                            input_schema,
                            cache_control: None,
                        });
                    } else if tool_val.get("cachePoint").is_some() {
                        // A `cachePoint` entry in the `toolConfig.tools` array marks the prompt-cache
                        // boundary for the tool DEFINITIONS preceding it (Anthropic places the same
                        // breakpoint on a tool). Map it onto the preceding tool's first-class IR
                        // `cache_control` (H3) so the boundary survives the cross-protocol seam. There
                        // is no positional tool-cachePoint stash, so this is the sole carrier; on
                        // same-protocol egress the writer re-emits the marker from this field. A
                        // leading cachePoint with no preceding tool has nothing to attach to and is
                        // dropped (a tool-list prefix boundary with an empty prefix is a no-op).
                        //
                        // LOW (accepted): degenerate tools-array cachePoint shapes — a LEADING
                        // cachePoint (no preceding tool) or DOUBLED adjacent cachePoints — do not
                        // byte-round-trip (the leading one is dropped; doubled ones collapse onto the
                        // one preceding tool's single boolean field). This is a no-op only on inputs
                        // AWS itself REJECTS (a tool-cache breakpoint with an empty/duplicate prefix is
                        // not a valid Converse `toolConfig`), so there is no valid request whose
                        // fidelity it harms; not worth a positional stash to preserve invalid shapes.
                        if let Some(last) = tools.last_mut() {
                            last.cache_control = Some(crate::ir::CacheControl {
                                kind: crate::ir::CacheKind::Ephemeral,
                            });
                        }
                    }
                }
            }
        }

        // Promote Bedrock's native `toolConfig.toolChoice` into the IR union (PF-H1) so a forced /
        // targeted directive survives the cross-protocol seam instead of degrading to `auto`.
        let tool_choice = read_bedrock_tool_choice(obj.get("toolConfig"));

        let max_tokens = if let Some(inference_config) =
            obj.get("inferenceConfig").and_then(|i| i.as_object())
        {
            inference_config
                .get("maxTokens")
                .and_then(|v| v.as_u64())
                .filter(|&v| v > 0)
                // Bounds-checked: a bare `as u32` would silently TRUNCATE (wrap) a value above
                // u32::MAX (e.g. 5_000_000_000 → 705_032_704) and forward it as a real cap the
                // caller never asked for, diverging from a direct AWS call. Drop out-of-range
                // values to None so the backend applies its own default. Mirrors the Gemini reader.
                .and_then(|v| u32::try_from(v).ok())
        } else {
            None
        };

        let inference_config = obj.get("inferenceConfig").and_then(|i| i.as_object());
        let temperature =
            inference_config.and_then(|ic| ic.get("temperature").and_then(|v| v.as_f64()));
        // Promoted sampling controls in Bedrock's `inferenceConfig`: topP and stopSequences. `topK`
        // is NOT an inferenceConfig field (it lives in model-specific `additionalModelRequestFields`),
        // so it is promoted from THERE (see `top_k` below). These two are ALSO preserved verbatim in
        // the raw `inferenceConfig` captured into `extra` for the same-protocol passthrough; the IR
        // fields are what carry them across the cross-protocol seam (where `extra` is cleared). The
        // writer's overlay re-emits the typed fields onto the raw object, so a Bedrock->Bedrock
        // round-trip is unaffected (the overlaid value equals the captured one).
        let top_p = inference_config.and_then(|ic| ic.get("topP").and_then(|v| v.as_f64()));
        // Promote `top_k` (PF-H1 fidelity fix). Bedrock's Converse API carries `top_k` only via the
        // model-specific `additionalModelRequestFields` escape hatch (it has no `inferenceConfig`
        // home). Anthropic-on-Bedrock and several model families spell it `top_k`; some use `topK`.
        // Accept either so a native Bedrock request that pins top_k populates the first-class IR field
        // and survives the cross-protocol seam (where `extra` is cleared) instead of vanishing. The
        // raw `additionalModelRequestFields` is still captured verbatim into `extra` for the
        // same-protocol passthrough; the writer overlays the typed `top_k` back onto it.
        // Track which spelling the source used so the writer can re-emit it (losslessness): prefer
        // snake_case `top_k`, fall back to camelCase `topK`. `top_k_was_camel` is true only when the
        // value came from the `topK` key, so a same-protocol passthrough that spelled it `topK`
        // round-trips byte-identically instead of being renamed to `top_k`.
        let amrf = obj
            .get("additionalModelRequestFields")
            .and_then(|v| v.as_object());
        let mut top_k_was_camel = false;
        let top_k = amrf
            .and_then(|amrf| {
                amrf.get("top_k").or_else(|| {
                    top_k_was_camel = true;
                    amrf.get("topK")
                })
            })
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok());
        // Only meaningful when a usable top_k actually came from the camel key; reset otherwise so a
        // present-but-`top_k`-spelled (or absent/out-of-range) value never stamps the sentinel.
        top_k_was_camel &= top_k.is_some();
        let stop =
            crate::ir::read_stop_sequences(inference_config.and_then(|ic| ic.get("stopSequences")));

        // Stash any captured `cachePoint` markers (with their original positions) under the sentinel
        // so `write_request` re-emits them at the same spots on a same-protocol passthrough. Only
        // inserted when at least one was present, so a request that never used prompt caching does
        // not gain a stray key (and the byte-exact round-trip of a cache-free body is preserved).
        if !system_cache_points.is_empty() || !message_cache_points.is_empty() {
            let mut cache_points = serde_json::Map::new();
            if !system_cache_points.is_empty() {
                cache_points.insert(
                    "system".to_string(),
                    serde_json::Value::Array(system_cache_points),
                );
            }
            if !message_cache_points.is_empty() {
                cache_points.insert(
                    "messages".to_string(),
                    serde_json::Value::Array(message_cache_points),
                );
            }
            extra.insert(
                CACHE_POINTS_SENTINEL.to_string(),
                serde_json::Value::Object(cache_points),
            );
        }

        // Stash any captured `guardContent` markers (with their original positions) under the
        // sentinel so `write_request` re-emits them at the same spots on a same-protocol passthrough.
        // Only inserted when at least one was present, so a request that used no inline guardrails
        // does not gain a stray key (preserving the byte-exact round-trip of a guard-free body).
        if !system_guard_content.is_empty() || !message_guard_content.is_empty() {
            let mut guard_content = serde_json::Map::new();
            if !system_guard_content.is_empty() {
                guard_content.insert(
                    "system".to_string(),
                    serde_json::Value::Array(system_guard_content),
                );
            }
            if !message_guard_content.is_empty() {
                guard_content.insert(
                    "messages".to_string(),
                    serde_json::Value::Array(message_guard_content),
                );
            }
            extra.insert(
                GUARD_CONTENT_SENTINEL.to_string(),
                serde_json::Value::Object(guard_content),
            );
        }

        // Stamp the source-spelling hint when top_k arrived as camelCase `topK`, so the writer
        // re-emits `topK` on a same-protocol passthrough (else the canonical `top_k`). `extra` is
        // cleared on the cross-protocol seam, so the sentinel naturally vanishes there and a
        // cross-protocol egress emits the canonical `top_k`. Only inserted when it produced a usable
        // value, so a body that never carried a camel top_k does not gain a stray key.
        if top_k_was_camel {
            extra.insert(
                TOP_K_CAMEL_SENTINEL.to_string(),
                serde_json::Value::Bool(true),
            );
        }

        Ok(crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: system_blocks,
            messages,
            tools,
            max_tokens,
            temperature,
            top_p,
            top_k,
            stop,
            tool_choice,
            // Bedrock's native Converse request body has no `stream` field — streaming is selected
            // by the endpoint (converse vs converse-stream). The Bedrock ingress route therefore
            // INJECTS `"stream": true` into the body for converse-stream requests before this reader
            // runs (see `ingress_path_model`), so on a Bedrock-INGRESS cross-protocol request the
            // re-parsed IR must carry that flag through — otherwise the target egress writer is never
            // told to produce a streaming body and a client that called /converse-stream silently
            // gets a buffered (non-streaming) response. Defaults to false when the field is absent
            // (a native Bedrock egress reads the flag from the endpoint, not the body, so this is
            // a no-op for the same-protocol path).
            stream: obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false),
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra,
        })
    }

    fn read_response_events(
        &self,
        _event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();

        if !data.is_object() {
            return out;
        }

        match data.get("type").and_then(|t| t.as_str()) {
            Some(ET_MESSAGE_START) => {
                if !state.started {
                    state.started = true;
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id: None,
                        created: None,
                        model: None,
                    });
                }
            }

            Some(ET_CONTENT_BLOCK_START) => {
                let idx = clamp_content_block_index(data);

                if let Some(start_obj) = data.get("start").and_then(|s| s.as_object()) {
                    if let Some(tool_use) = start_obj.get("toolUse").and_then(|t| t.as_object()) {
                        // Mirror the `state.started` guard the text branch (below) enforces: a
                        // BlockStart must NEVER precede the MessageStart it belongs to. Without this
                        // guard, a `contentBlockStart` arriving before `messageStart` (malformed or
                        // reordered stream) would emit a tool BlockStart ahead of MessageStart,
                        // breaking the IR ordering invariant downstream consumers rely on. Skip it.
                        if state.started {
                            let tu_id = tool_use
                                .get("toolUseId")
                                .and_then(|id| id.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = tool_use
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();

                            out.push(IrStreamEvent::BlockStart {
                                index: idx,
                                block: crate::ir::IrBlockMeta::ToolUse { id: tu_id, name },
                            });
                        }
                    } else if start_obj.contains_key("reasoningContent")
                        && state.started
                        && !state.thinking_block_open
                    {
                        // Some Bedrock-compatible backends prefix a streamed reasoning block with an
                        // explicit `contentBlockStart` carrying an (empty) `reasoningContent` start
                        // object, rather than implying the block on the first delta. Open the Thinking
                        // block here so the following `reasoningContent` deltas attach to it; the
                        // delta arm's lazy-open then sees the flag already set and does not re-open it.
                        // (The native AWS `ContentBlockStart` union only models `toolUse`, so a real
                        // AWS stream never takes this branch — it lazily opens on the first delta.)
                        state.thinking_block_open = true;
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Thinking,
                        });
                    } else if start_obj.is_empty() && state.started && !state.text_block_open {
                        // The native Bedrock ConverseStream wire sends `contentBlockStart` with an
                        // empty `start: {}` for a text block. Only that empty-object shape opens a
                        // Text block. A `start` object carrying an unrecognized key (e.g. a future
                        // `image`/`reasoningContent` block type) is NOT a text block: skip it rather
                        // than mis-opening a spurious Text block (forward-compatibility). Mirrors the
                        // defensive Gemini/Cohere readers.
                        state.text_block_open = true;
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Text,
                        });
                    }
                } else if state.started && !state.text_block_open {
                    // No `start` object at all → a text block (the absent-`start` text shape).
                    state.text_block_open = true;
                    out.push(IrStreamEvent::BlockStart {
                        index: idx,
                        block: crate::ir::IrBlockMeta::Text,
                    });
                }
            }

            Some(ET_CONTENT_BLOCK_DELTA) => {
                let idx = clamp_content_block_index(data);

                if let Some(delta_obj) = data.get("delta").and_then(|d| d.as_object()) {
                    if delta_obj.contains_key("text") {
                        let text_val = delta_obj
                            .get("text")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string();

                        out.push(IrStreamEvent::BlockDelta {
                            index: idx,
                            delta: crate::ir::IrDelta::TextDelta(text_val),
                        });
                    } else if let Some(tool_use) =
                        delta_obj.get("toolUse").and_then(|t| t.as_object())
                    {
                        if let Some(input_str) = tool_use.get("input").and_then(|i| i.as_str()) {
                            out.push(IrStreamEvent::BlockDelta {
                                index: idx,
                                delta: crate::ir::IrDelta::InputJsonDelta(input_str.to_string()),
                            });
                        }
                    } else if let Some(reasoning) = delta_obj
                        .get("reasoningContent")
                        .and_then(|r| r.as_object())
                    {
                        // Native Bedrock ConverseStream streams the model's extended-thinking as a
                        // `reasoningContent` member on `contentBlockDelta`. The buffered reader
                        // (`read_bedrock_reasoning_block`) already preserves this in the non-streaming
                        // path; the streaming path used to silently DROP it — no Thinking BlockStart
                        // and no ThinkingDelta/SignatureDelta were ever emitted. Mirror the buffered
                        // logic here: lazily open the Thinking block on the FIRST reasoningContent
                        // delta (the wire sends NO dedicated `contentBlockStart` for a reasoning
                        // block — it is implied by the first delta), then emit the matching delta.
                        //
                        // The `ReasoningContentBlockDelta` union has three members:
                        //   - `text`            → ThinkingDelta(text)            (plaintext reasoning)
                        //   - `signature`       → SignatureDelta(signature)      (the opaque token)
                        //   - `redactedContent` → RedactedReasoningDelta(bytes)    (opaque encrypted
                        //                         reasoning). A typed delta distinct from the plaintext
                        //                         ThinkingDelta keeps the redacted block to ONE IR
                        //                         delta → ONE Bedrock frame, so the writer re-emits
                        //                         `redactedContent: <bytes>` faithfully without a
                        //                         plaintext `text` leak; non-Bedrock writers drop it.
                        if state.started && !state.thinking_block_open {
                            state.thinking_block_open = true;
                            out.push(IrStreamEvent::BlockStart {
                                index: idx,
                                block: crate::ir::IrBlockMeta::Thinking,
                            });
                        }
                        if state.thinking_block_open {
                            if let Some(text) = reasoning.get("text").and_then(|t| t.as_str()) {
                                out.push(IrStreamEvent::BlockDelta {
                                    index: idx,
                                    delta: crate::ir::IrDelta::ThinkingDelta(text.to_string()),
                                });
                            } else if let Some(sig) =
                                reasoning.get("signature").and_then(|s| s.as_str())
                            {
                                out.push(IrStreamEvent::BlockDelta {
                                    index: idx,
                                    delta: crate::ir::IrDelta::SignatureDelta(sig.to_string()),
                                });
                            } else if let Some(redacted) =
                                reasoning.get("redactedContent").and_then(|r| r.as_str())
                            {
                                out.push(IrStreamEvent::BlockDelta {
                                    index: idx,
                                    delta: crate::ir::IrDelta::RedactedReasoningDelta(
                                        redacted.to_string(),
                                    ),
                                });
                            }
                            // A future `reasoningContent` delta member with none of the three known
                            // keys carries no representable IR delta; the block stays open and the
                            // unknown member is skipped (forward-compat), mirroring the buffered
                            // reader's `None` arm.
                        }
                    }
                }
            }

            Some(ET_CONTENT_BLOCK_STOP) => {
                let idx = clamp_content_block_index(data);

                // Clear `text_block_open` on ANY contentBlockStop while a text block is open, not
                // only at index 0. Bedrock indexes text blocks that follow a tool-use block at
                // index > 0 (reachable via cross-protocol ingress where a tool-use precedes text).
                // The old `idx == 0` guard left the flag set for a text block opened at index N>0,
                // so the `!state.text_block_open` guard in contentBlockStart stayed true-blocked and
                // every subsequent text block was suppressed — silently dropping the rest of the
                // text content. At most one text block is open at a time on this wire (a new text
                // block only opens once the prior is closed), so the open flag unambiguously belongs
                // to the block whose stop we are processing; tool-use stops never set the flag.
                if state.text_block_open {
                    state.text_block_open = false;
                }

                // Clear the reasoning-block open flag on its stop too, so a subsequent reasoning
                // block (or a reasoning-then-text sequence) opens cleanly. At most one block of a
                // given kind is open at a time on this wire, so the stop unambiguously closes the
                // open thinking block; a text/tool stop with no thinking block open is a no-op here.
                if state.thinking_block_open {
                    state.thinking_block_open = false;
                }

                out.push(IrStreamEvent::BlockStop { index: idx });
            }

            Some(ET_MESSAGE_STOP) => {
                // Bedrock splits the stop reason (`messageStop` frame) from the token usage (a
                // following `metadata` frame). To emit ONE combined `MessageDelta{stop_reason, usage}`
                // — so a cross-protocol ingress (e.g. Anthropic) sees the SINGLE `message_delta` a
                // native non-Bedrock stream carries, instead of two (the previous behavior was a
                // detectable tell) — we BUFFER the stop_reason here and pair it with the usage when
                // `metadata` arrives (see below). The combined delta is emitted from the `metadata`
                // branch.
                //
                // The terminal `MessageStop` is also DEFERRED to the `metadata` branch and emitted
                // AFTER the combined `MessageDelta`. The combined delta carries stop_reason + usage and
                // must precede the terminal stop in IR order, so that a non-eventstream ingress writer
                // (e.g. Anthropic) emits `message_delta` BEFORE `message_stop` — the native order. If
                // the `MessageStop` were emitted here (on `messageStop`, which arrives BEFORE
                // `metadata`), the IR order would be MessageStop-then-MessageDelta and the Anthropic
                // ingress would write `message_stop` before `message_delta` — a wrong, detectable
                // ordering. A bedrock->bedrock round-trip is unaffected: the `MessageStop` IR event
                // maps to no wire frame (`BedrockWriter` returns `None`), and the combined delta is
                // re-split into the native `messageStop` + `metadata` frame pair by `StreamTranslate`.
                state.pending_stop_reason = data
                    .get("stopReason")
                    .and_then(|s| s.as_str())
                    .map(stop_reason_map);
            }

            Some(ET_METADATA) => {
                // Usage trails the stop reason (Bedrock sends `metadata` after `messageStop`). Pair it
                // with the stop_reason buffered from the preceding `messageStop` frame into ONE
                // combined MessageDelta, so a cross-protocol ingress emits a single `message_delta`/
                // usage event (native fidelity) rather than two. A bedrock->bedrock round-trip re-splits
                // this combined delta back into the native `messageStop` + `metadata` frame pair in the
                // writer (`BedrockWriter::write_response_event` fan-out, driven by `StreamTranslate`).
                //
                // The terminal `MessageStop` is emitted HERE, AFTER the combined delta, so the IR order
                // is delta-then-stop and the ingress writer emits its native `message_delta` then
                // `message_stop` (Finding: delta-before-stop ordering). It is pushed unconditionally
                // (even when `metadata` carries no `usage`) so the downstream stream always receives its
                // terminal frame once `metadata` arrives.
                // Emit the combined MessageDelta UNCONDITIONALLY — even when `metadata` carries no
                // `usage` object. Native AWS Bedrock always sends `usage` here, but a mock /
                // Bedrock-compatible backend (common in staging & integration tests) may omit it. The
                // old code took `pending_stop_reason` only INSIDE the `usage` guard, so a usage-less
                // `metadata` dropped the buffered stop_reason entirely and terminated the stream with a
                // bare MessageStop — no preceding MessageDelta. For a Bedrock→Anthropic translation that
                // is a protocol-ordering violation (the Anthropic SDK expects `message_delta` before
                // `message_stop`) AND a silent loss of the stop_reason. We therefore build a usage from
                // whatever the frame carries (zero when absent — harmless) and always emit the delta,
                // consuming the buffered stop_reason, BEFORE the terminal MessageStop. A bare
                // `metadata` with neither usage nor a buffered stop_reason yields a zero-usage,
                // stop_reason-less delta, which is benign.
                let usage_obj = data.get("usage").and_then(|u| u.as_object());
                let (cache_creation_input_tokens, cache_read_input_tokens) =
                    read_cache_usage(usage_obj);
                let usage = crate::ir::IrUsage {
                    input_tokens: usage_obj
                        .and_then(|u| u.get("inputTokens"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    output_tokens: usage_obj
                        .and_then(|u| u.get("outputTokens"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    cache_creation_input_tokens,
                    cache_read_input_tokens,
                };

                out.push(IrStreamEvent::MessageDelta {
                    stop_reason: state.pending_stop_reason.take(),
                    stop_sequence: None,
                    usage,
                });
                out.push(IrStreamEvent::MessageStop);
            }

            // Bedrock mid-stream exception event shapes. The `ConverseStream.responseStream` output
            // union has EXACTLY five modeled error-event members — `internalServerException`,
            // `modelStreamErrorException`, `validationException`, `throttlingException`, and
            // `serviceUnavailableException` — any of which can arrive in place of (or before)
            // `messageStop`. (`modelTimeoutException` is a REQUEST-level Converse exception, NOT a
            // member of this stream union, so a real AWS endpoint never emits it mid-stream; it is
            // therefore not accepted here — see `bedrock_stream_exception_for`'s docstring.) Surface
            // a recognized event as an `IrStreamEvent::Error` so the downstream ingress writer
            // terminates the client stream with a protocol-shaped error rather than silently dropping
            // the event and leaving the client on a hanging / EOF-without-terminator stream.
            Some(
                exc @ ("internalServerException"
                | "modelStreamErrorException"
                | "throttlingException"
                | "validationException"
                | "serviceUnavailableException"),
            ) => {
                let message = data
                    .get("message")
                    .and_then(|m| m.as_str())
                    .map(String::from);
                // Map each of the five outer-bound exception strings to its StatusClass. Every one
                // the outer `Some(exc @ (...))` arm can bind is listed explicitly (the two
                // server-error strings inclusive) so the class mapping is co-located with the string
                // set rather than hiding behind a `_ => ServerError` default — a new exception added
                // to the outer union without a class here would surface as the documented
                // `other =>` arm, which we keep (not a `_` wildcard) only because `&str` matches are
                // never type-exhaustive; the outer pattern is the real guard.
                let class = match exc {
                    "throttlingException" => StatusClass::RateLimit,
                    "validationException" => StatusClass::ClientError,
                    "serviceUnavailableException" => StatusClass::Overloaded,
                    "internalServerException" | "modelStreamErrorException" => {
                        StatusClass::ServerError
                    }
                    // Unreachable given the outer `Some(exc @ (...))` guard restricts `exc` to the
                    // five strings above. A NAMED binding (not a `_` wildcard, per the no-catch-all
                    // rule — mirrors the `other =>` pattern in proto::openai_family::bearer_error_code)
                    // keeps the arm explicit; ServerError is the safe class for any exception event
                    // whose class is otherwise unknown.
                    other => {
                        let _ = other;
                        StatusClass::ServerError
                    }
                };
                out.push(IrStreamEvent::Error(crate::proto::IrError {
                    class,
                    provider_signal: message.or_else(|| Some(exc.to_string())),
                    retry_after: None,
                }));
            }

            // Any other (or absent) event type is a no-op. This is NOT a disposition/breaker match:
            // it is the wire event-type demux for an open-ended, vendor-extensible event stream, so
            // an unrecognized future event must be skipped (not error) to avoid breaking forward
            // compatibility. The error-bearing event types are handled explicitly above.
            Some(_) | None => {}
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let output_val = obj.get("output").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let message_val = output_val.get("message").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some(crate::proto::SIGNAL_IR_PARSE.to_string()),
            retry_after: None,
        })?;

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();

        if let Some(content_arr) = message_val.get("content").and_then(|c| c.as_array()) {
            for block_val in content_arr {
                if let Some(text_val) = block_val.get("text").and_then(|t| t.as_str()) {
                    content.push(crate::ir::IrBlock::Text {
                        text: text_val.to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    });
                } else if let Some(tool_use) = block_val.get("toolUse").and_then(|t| t.as_object())
                {
                    let tu_id = tool_use
                        .get("toolUseId")
                        .and_then(|id| id.as_str())
                        .unwrap_or("")
                        .to_string();
                    let name = tool_use
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    let input = tool_use
                        .get("input")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);

                    content.push(crate::ir::IrBlock::ToolUse {
                        id: tu_id,
                        name,
                        input,
                        cache_control: None,
                    });
                } else if let Some(reasoning) = block_val.get("reasoningContent") {
                    // A Converse response message can carry a `reasoningContent` (extended-thinking)
                    // block — the model's reasoning output. Mirror the request-side reader: map it
                    // onto IR `Thinking { text, signature }` via `read_bedrock_reasoning_block` (and
                    // the redacted-signature sentinel for `redactedContent`). The old response loop
                    // skipped it entirely, silently DROPPING the model's reasoning so a
                    // bedrock->bedrock passthrough lost the thinking block (and a cross-protocol
                    // egress could not surface it). A future union member yields `None` (undecoded).
                    if let Some(block) = read_bedrock_reasoning_block(reasoning) {
                        content.push(block);
                    } else {
                        tracing::warn!(
                            "dropping Converse response reasoningContent block with no decodable \
                             member (neither reasoningText nor redactedContent)"
                        );
                    }
                } else if let Some(image) = block_val.get("image") {
                    // An assistant Converse response can carry an `image` content block (model
                    // image output / tool-rendered image). Mirror the request-side readers
                    // (`read_request` content loop + the `toolResult` inner loop), which both decode
                    // `image` via `read_bedrock_image_block` — handling both `source.bytes` (base64)
                    // and `source.s3Location` (stashed under the `image_s3` sentinel for faithful
                    // re-emit). Without this arm the response loop silently DROPPED the image,
                    // diverging from a direct AWS call. A block with neither source yields `None`
                    // (no empty-bytes block injected).
                    if let Some(block) = read_bedrock_image_block(image) {
                        content.push(block);
                    } else {
                        tracing::warn!(
                            "dropping Converse response image block with no decodable source \
                             (neither source.bytes nor source.s3Location)"
                        );
                    }
                }
            }
        }

        let stop_reason_val = obj
            .get("stopReason")
            .and_then(|s| s.as_str())
            .map(stop_reason_map);

        // Treat an absent `usage` object leniently, mirroring the streaming path
        // (`read_response_events` defaults each token field to 0 when `metadata` carries no usage):
        // fall back to zero counts rather than hard-erroring. A missing `usage` is an upstream
        // response-format quirk (mock/staging backend, or a future model variant), not a client
        // error, so a spurious `ClientError` here would mislabel the cause and confuse retry logic.
        let usage_obj = obj.get("usage");
        let (cache_creation_input_tokens, cache_read_input_tokens) =
            read_cache_usage(usage_obj.and_then(|u| u.as_object()));
        let usage = crate::ir::IrUsage {
            input_tokens: usage_obj
                .and_then(|u| u.get("inputTokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage_obj
                .and_then(|u| u.get("outputTokens"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens,
            cache_read_input_tokens,
        };

        Ok(crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason: stop_reason_val,
            usage,
            // Identity capture for same-protocol passthrough fidelity. The AWS Converse response
            // body is deliberately minimal: it has NO `id`, NO `created`, NO `system_fingerprint`,
            // and NO stop-sequence echo (`stopReason` is the discriminant, captured above; `usage`
            // is captured above). The only identity AWS returns is the `x-amzn-RequestId` HTTP
            // header, which is not part of the body this reader sees. So every body-level identity
            // field is `None` here — that is the faithful capture of what Bedrock actually sends,
            // and a bedrock→bedrock passthrough reproduces the native (id-less) body exactly.
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }
}

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

impl ProtocolWriter for BedrockWriter {
    fn upstream_path(&self) -> &str {
        "/model"
    }

    /// Converse's `cachePoint` marker is validated per-model: Anthropic Claude accepts it, Amazon
    /// Nova 400s with "extraneous key [cachePoint] is not permitted". Cross-protocol cache asks
    /// therefore need the lane's `prompt_caching` capability assertion before this writer may
    /// project them (see `cache_markers_model_gated` on the trait).
    fn cache_markers_model_gated(&self) -> bool {
        true
    }

    fn upstream_path_for(&self, model: &str) -> String {
        format!("/model/{}/converse", model)
    }

    fn upstream_path_for_stream(&self, model: &str, stream: bool) -> String {
        // streaming uses ConverseStream (binary application/vnd.amazon.eventstream response).
        if stream {
            format!("/model/{}/converse-stream", model)
        } else {
            format!("/model/{}/converse", model)
        }
    }

    fn auth_headers(&self, _key: &str) -> Vec<(HeaderName, HeaderValue)> {
        // Bedrock auth is per-request SigV4 — see `sign_request`. Static headers can't carry it.
        vec![]
    }

    /// AWS SigV4 signing for the Converse request. The lane key encodes credentials as
    /// `ACCESS_KEY_ID:SECRET_ACCESS_KEY` or `ACCESS_KEY_ID:SECRET_ACCESS_KEY:SESSION_TOKEN`; the
    /// region is parsed from the host (`bedrock-runtime.<region>.amazonaws.com`); service=`bedrock`.
    fn sign_request(
        &self,
        key: &str,
        ctx: &super::SigningContext,
    ) -> Vec<(HeaderName, HeaderValue)> {
        let mut parts = key.splitn(3, ':');
        let (access, secret, token) = match (parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(s), tok) if !a.is_empty() && !s.is_empty() => (a, s, tok),
            _ => return vec![], // misconfigured key → no signature (AWS will 403, surfaced as auth)
        };
        // Derive the SigV4 scope region from the endpoint host robustly (FIPS, VPC-interface, and
        // control-plane labels — not just the vanilla `bedrock-runtime.<region>.` prefix). A region
        // that cannot be derived no longer silently signs for `us-east-1`: we WARN (with the actual
        // host) so a mis-derived region in a multi-region failover setup is diagnosable, then fall
        // back to `us-east-1` (the historical default) so a genuinely region-less endpoint still
        // attempts to sign rather than failing closed. The host is operator-config-derived (tracing
        // it is fine; it is not a client-facing body).
        let region = match derive_sigv4_region(&ctx.host) {
            Some(r) => r,
            None => {
                tracing::warn!(
                    host = %ctx.host,
                    "could not derive AWS region from Bedrock endpoint host; defaulting SigV4 scope \
                     to us-east-1 (signing may fail with SignatureDoesNotMatch if the endpoint is \
                     in another region) — set the lane host to a \
                     bedrock-runtime[-fips].<region>.amazonaws.com form"
                );
                "us-east-1"
            }
        };
        let service = "bedrock";
        let (amzdate, datestamp) = crate::sigv4::format_amz_time(ctx.timestamp_epoch);
        let payload_hash = crate::sigv4::sha256_hex(ctx.body);

        // Validate the session token as a wire HeaderValue BEFORE adding it to the SIGNED set, so
        // the signed header set and the emitted header set can never diverge. If a session (STS)
        // token contains a byte `HeaderValue::from_str` rejects (e.g. an ASCII control char),
        // the previous code signed `x-amz-security-token` (committing the signature to it) but then
        // silently dropped the header on the wire — yielding a request whose signature claims the
        // token header is present while it is absent, which AWS rejects with SignatureDoesNotMatch
        // (a confusing 403, not the intended graceful "misconfigured credential" path). Instead,
        // bail to the same empty-header path used for a structurally-misconfigured key (request goes
        // out unsigned → AWS 403 surfaced as auth), with a diagnostic so the operator can see why.
        let token_header = match token {
            Some(t) => match HeaderValue::from_str(t) {
                Ok(v) => Some(v),
                Err(_) => {
                    tracing::warn!(
                        "Bedrock lane session token contains a byte rejected by HeaderValue \
                         (e.g. a control char); skipping signing to avoid a signed-but-absent \
                         x-amz-security-token header. Request goes out unsigned (AWS will 403)."
                    );
                    return vec![];
                }
            },
            None => None,
        };

        let mut signed = vec![
            (
                "content-type".to_string(),
                crate::proxy::APPLICATION_JSON.to_string(),
            ),
            ("host".to_string(), ctx.host.clone()),
            (
                crate::sigv4::X_AMZ_CONTENT_SHA256.to_string(),
                payload_hash.clone(),
            ),
            (crate::sigv4::X_AMZ_DATE.to_string(), amzdate.clone()),
        ];
        if let Some(t) = token {
            signed.push((
                crate::sigv4::X_AMZ_SECURITY_TOKEN.to_string(),
                t.to_string(),
            ));
        }

        let (signature, signed_headers) = crate::sigv4::sign_v4(
            secret,
            region,
            service,
            "POST",
            &ctx.canonical_uri,
            "",
            &signed,
            &payload_hash,
            &amzdate,
            &datestamp,
        );
        let authorization = {
            use crate::sigv4::{SIGV4_ALGORITHM, SIGV4_TERMINATION};
            format!(
                "{SIGV4_ALGORITHM} Credential={access}/{datestamp}/{region}/{service}/{SIGV4_TERMINATION}, \
                 SignedHeaders={signed_headers}, Signature={signature}"
            )
        };

        // Headers to ADD to the wire request (content-type + host are set elsewhere / by the client).
        // The authorization value embeds `access` (the AWS access key id) taken directly from the
        // lane key config. A key id containing a control character (CR/LF) or any byte >= 0x80
        // makes `HeaderValue::from_str` fail. This runs on the request hot path, so we must NOT
        // panic: a malformed credential takes the same graceful "misconfigured key" path as the
        // parse failure above (return an empty header set → request goes out unsigned → AWS 403,
        // surfaced upstream as an auth failure) rather than aborting the request-handling task.
        let (Ok(authorization_val), Ok(amzdate_val), Ok(payload_hash_val)) = (
            HeaderValue::from_str(&authorization),
            HeaderValue::from_str(&amzdate),
            HeaderValue::from_str(&payload_hash),
        ) else {
            return vec![];
        };

        let mut out = vec![
            (
                HeaderName::from_static(crate::proto::HDR_AUTHORIZATION),
                authorization_val,
            ),
            (
                HeaderName::from_static(crate::sigv4::X_AMZ_DATE),
                amzdate_val,
            ),
            (
                HeaderName::from_static(crate::sigv4::X_AMZ_CONTENT_SHA256),
                payload_hash_val,
            ),
        ];
        // Use the HeaderValue validated up front (above): the signed set and the wire set are now
        // gated by the same check, so they can never diverge into a signed-but-absent token header.
        if let Some(v) = token_header {
            out.push((
                HeaderName::from_static(crate::sigv4::X_AMZ_SECURITY_TOKEN),
                v,
            ));
        }
        out
    }

    // Bedrock carries the target model in the request URL, not the body, so this is a no-op and
    // never changes the body → always reports `false` for pristine-tracking (a same-protocol Bedrock
    // passthrough is never made non-pristine by model rewriting).
    fn rewrite_model_if_needed(&self, _body: &mut serde_json::Value, _model: &str) -> bool {
        false
    }

    // NOTE: Bedrock Converse treats `inferenceConfig.maxTokens` as OPTIONAL (it applies the model's
    // default when omitted, and this writer omits an empty `inferenceConfig` entirely). So Bedrock
    // does NOT override `requires_max_tokens` — injecting a default here would silently cap output.

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        // The reasoning carry has no Bedrock Converse shape in this pass; dropped observably (matching
        // the penalties/top_k convention) rather than silently.
        if req.reasoning.is_some() {
            tracing::warn!(
                "dropping cross-protocol reasoning/thinking ask: no Bedrock Converse mapping in this release"
            );
        }
        let mut out = serde_json::Map::new();

        // The captured native `cachePoint` markers (see `CACHE_POINTS_SENTINEL`). On a same-protocol
        // passthrough this carries the prompt-cache markers the reader stashed; on cross-protocol
        // egress `extra` is cleared so this is absent and no Bedrock-only marker leaks onto a foreign
        // wire. Borrowed once here; the `system`/`messages` sub-arrays are spliced back below and the
        // sentinel is then SKIPPED by the trailing extra-merge so it never reaches the wire.
        let cache_points = req
            .extra
            .get(CACHE_POINTS_SENTINEL)
            .and_then(|v| v.as_object());
        let system_cache_points = cache_points
            .and_then(|cp| cp.get("system"))
            .and_then(|v| v.as_array());
        let message_cache_points = cache_points
            .and_then(|cp| cp.get("messages"))
            .and_then(|v| v.as_array());

        // The captured native `guardContent` markers (see `GUARD_CONTENT_SENTINEL`); same stash
        // shape as the cachePoint markers and spliced back via the same shared helper. Consumed here
        // and SKIPPED by the trailing extra-merge so the sentinel never reaches the wire.
        let guard_content = req
            .extra
            .get(GUARD_CONTENT_SENTINEL)
            .and_then(|v| v.as_object());
        let system_guard_content = guard_content
            .and_then(|gc| gc.get("system"))
            .and_then(|v| v.as_array());
        let message_guard_content = guard_content
            .and_then(|gc| gc.get("messages"))
            .and_then(|v| v.as_array());

        // When the positional cachePoint stash is present (same-protocol Bedrock passthrough) it is
        // the authority for cachePoint placement (spliced below at the recorded indices for a
        // byte-identical round-trip), so the inline `cache_control`-driven emission is SUPPRESSED to
        // avoid emitting the same marker twice. On the cross-protocol seam `extra` is cleared, so the
        // stash is absent and the inline emission (from the first-class IR `cache_control`) is the
        // sole carrier — projecting an Anthropic cache breakpoint onto a native Bedrock cachePoint.
        let emit_inline_system_cache = system_cache_points.is_none();
        if !req.system.is_empty() || system_cache_points.is_some() || system_guard_content.is_some()
        {
            let mut text_arr: Vec<serde_json::Value> = Vec::new();
            for block in &req.system {
                if let crate::ir::IrBlock::Text {
                    text,
                    cache_control,
                    ..
                } = block
                {
                    text_arr.push(serde_json::json!({ "text": text }));
                    // H3: emit a Bedrock `cachePoint` AFTER the block that carries the IR
                    // `cache_control` boundary (the position Bedrock expects — the breakpoint closes
                    // the prefix before it). Suppressed when the positional stash owns placement.
                    if emit_inline_system_cache && cache_control.is_some() {
                        text_arr.push(bedrock_cache_point());
                    }
                }
            }

            // Re-emit any captured `cachePoint` / `guardContent` markers at their original
            // positions so prompt caching and inline guardrails survive a same-protocol round-trip
            // instead of being silently dropped. BOTH marker classes recorded indices against the
            // SAME original array, so they must be spliced as ONE sorted batch (the helper sorts by
            // index): splicing them in two passes would let the first pass's insertions shift the
            // second pass's recorded indices off by one. `merge_marker_entries` concatenates the two
            // `{ "i", "block" }` lists for a single ascending splice.
            let merged = merge_marker_entries(system_cache_points, system_guard_content);
            splice_cache_points(&mut text_arr, &merged);

            if !text_arr.is_empty() {
                out.insert("system".to_string(), serde_json::Value::Array(text_arr));
            }
        }

        // Same suppression gate as the system array (above): when the positional message-cachePoint
        // stash is present it owns placement (byte-identical same-protocol round-trip), so inline
        // `cache_control`-driven emission is suppressed; cross-protocol (stash cleared) it is the sole
        // carrier of the prompt-cache boundary.
        let emit_inline_message_cache = message_cache_points.is_none();
        let mut msgs_arr: Vec<serde_json::Value> = Vec::new();
        for (msg_idx, msg) in req.messages.iter().enumerate() {
            let role_str = match msg.role {
                crate::ir::IrRole::User => "user",
                crate::ir::IrRole::Assistant => "assistant",
                // A Tool-role IR message carries `toolResult` blocks; Bedrock Converse has no
                // freestanding "tool" role — a tool result is a `toolResult` content block inside a
                // USER-turn message, so mapping Tool → "user" is the correct native wire shape.
                crate::ir::IrRole::Tool => "user",
                // System text is extracted by the caller into `req.system` (emitted as the top-level
                // `system` array above), so a System-role MESSAGE should never reach the Bedrock
                // wire. If one somehow escapes extraction, skip it rather than silently mislabeling
                // it as a "user" turn (which would inject system instructions as a user message and
                // corrupt the conversation). Each role is handled explicitly — no catch-all.
                crate::ir::IrRole::System => continue,
            };

            let mut content_arr: Vec<serde_json::Value> = Vec::new();
            for block in &msg.content {
                // H3: the prompt-cache boundary carried on this block, if any. Emitted as a
                // `cachePoint` block IMMEDIATELY AFTER the block below (the position Bedrock expects).
                // Suppressed when the positional stash owns placement (same-protocol passthrough).
                let block_cache_control = match block {
                    crate::ir::IrBlock::Text { cache_control, .. }
                    | crate::ir::IrBlock::ToolUse { cache_control, .. }
                    | crate::ir::IrBlock::ToolResult { cache_control, .. } => {
                        cache_control.as_ref()
                    }
                    crate::ir::IrBlock::Thinking { .. }
                    | crate::ir::IrBlock::Image { .. }
                    | crate::ir::IrBlock::Json(_) => None,
                };
                match block {
                    crate::ir::IrBlock::Text { text, .. } => {
                        content_arr.push(serde_json::json!({ "text": text }));
                    }
                    crate::ir::IrBlock::ToolUse {
                        id, name, input, ..
                    } => {
                        content_arr.push(serde_json::json!({"toolUse": {"toolUseId": id, "name": name, "input": input}}));
                    }
                    crate::ir::IrBlock::ToolResult {
                        tool_use_id,
                        content,
                        is_error,
                        ..
                    } => {
                        let mut inner_content: Vec<serde_json::Value> = Vec::new();
                        for inner_block in content {
                            match inner_block {
                                crate::ir::IrBlock::Text { text, .. } => {
                                    inner_content.push(serde_json::json!({ "text": text }));
                                }
                                // Bedrock Converse natively supports structured tool-result content
                                // via a `{"json": <value>}` block (the inverse of what `read_request`
                                // decodes). Preserve the actual content instead of collapsing it to
                                // the constant string `"{}"`: a JSON-string Text-equivalent or a
                                // structured result that arrives via the IR is re-encoded faithfully.
                                crate::ir::IrBlock::Json(value) => {
                                    // A structured-json tool-result block re-emits as a native
                                    // `{"json": <value>}` block, restoring same-protocol fidelity.
                                    inner_content.push(serde_json::json!({ "json": value }));
                                }
                                crate::ir::IrBlock::Image { source, .. } => {
                                    if let Some(image_block) = bedrock_image_block(source) {
                                        inner_content
                                            .push(serde_json::json!({ "image": image_block }));
                                    }
                                }
                                crate::ir::IrBlock::ToolUse {
                                    id, name, input, ..
                                } => {
                                    // Nested ToolUse inside a tool result has no native Bedrock
                                    // tool-result shape; carry it as a structured `json` block rather
                                    // than discarding the call identity.
                                    inner_content.push(serde_json::json!({
                                        "json": { "toolUseId": id, "name": name, "input": input }
                                    }));
                                }
                                crate::ir::IrBlock::ToolResult {
                                    tool_use_id,
                                    is_error,
                                    ..
                                } => {
                                    // A tool result nested inside another tool result is not a native
                                    // Bedrock shape; preserve its identity as a `json` block instead
                                    // of emitting a meaningless `"{}"` placeholder.
                                    inner_content.push(serde_json::json!({
                                        "json": { "toolUseId": tool_use_id, "isError": is_error }
                                    }));
                                }
                                // Thinking blocks have no representable Bedrock tool-result shape and
                                // carry no result data; omit them entirely (with a trace) rather than
                                // emitting a misleading placeholder block.
                                crate::ir::IrBlock::Thinking { .. } => {
                                    tracing::warn!(
                                        "dropping non-representable Thinking block inside a Bedrock toolResult"
                                    );
                                }
                            }
                        }

                        let status_str = if *is_error { "error" } else { "success" };
                        content_arr.push(serde_json::json!({"toolResult": {"toolUseId": tool_use_id, "content": inner_content, "status": status_str}}));
                    }
                    crate::ir::IrBlock::Image { source, .. } => {
                        if let Some(image_block) = bedrock_image_block(source) {
                            content_arr.push(serde_json::json!({ "image": image_block }));
                        }
                    }
                    crate::ir::IrBlock::Thinking {
                        text,
                        signature,
                        redacted,
                        ..
                    } => {
                        // Re-emit the assistant turn's reasoning as a native Converse
                        // `reasoningContent` block (the inverse of `read_request`'s reasoningContent
                        // decode). The old writer dropped every Thinking block here, so a
                        // bedrock->bedrock passthrough lost the signed reasoning Bedrock requires
                        // echoed back on a follow-up turn. The redacted-signature sentinel re-emits
                        // `redactedContent`; any other Thinking re-emits `reasoningText`.
                        content_arr.push(bedrock_reasoning_block(text, signature, *redacted));
                    }
                    crate::ir::IrBlock::Json(_) => {
                        // Structured-json content is only a tool-result content member; it has no
                        // top-level message-content shape, so omit it from a message turn.
                    }
                }
                // H3: emit the prompt-cache boundary as a `cachePoint` block right after the block it
                // applies to. Only Text/ToolUse/ToolResult carry `cache_control` (see
                // `block_cache_control`); a block whose write produced nothing (e.g. a dropped Image)
                // still emits no cachePoint here because such kinds carry no `cache_control` field.
                // Suppressed when the positional stash owns placement (same-protocol round-trip).
                if emit_inline_message_cache && block_cache_control.is_some() {
                    content_arr.push(bedrock_cache_point());
                }
            }

            // Re-emit any captured `cachePoint` / `guardContent` markers for THIS message at their
            // original positions so prompt caching and inline guardrails survive a same-protocol
            // round-trip. Spliced BEFORE the empty-content placeholder below so a message whose only
            // block was a `cachePoint`/`guardContent` re-emits the marker rather than a bare `""`
            // placeholder. `msg_idx` matches the reader's recorded message index on the Bedrock
            // passthrough path (the Bedrock reader only emits User/Assistant turns, so no System-role
            // `continue` desyncs the count). BOTH classes are collected for this message and spliced
            // as ONE sorted batch (see `merge_marker_entries`) so cachePoint insertions cannot shift
            // guardContent's recorded indices.
            let for_this_msg: Vec<serde_json::Value> = message_cache_points
                .into_iter()
                .chain(message_guard_content)
                .flatten()
                .filter(|e| e.get("m").and_then(|v| v.as_u64()) == Some(msg_idx as u64))
                .cloned()
                .collect();
            if !for_this_msg.is_empty() {
                splice_cache_points(&mut content_arr, &for_this_msg);
            }

            // F4: Bedrock Converse requires strictly ALTERNATING user/assistant turns — two
            // consecutive messages of the same role are a 400 ValidationException. After the
            // Tool→"user" role mapping above, common IR shapes produce consecutive "user" turns: a
            // Tool-result turn followed by a real user turn, or several tool results that arrived as
            // separate Tool messages ([Assistant(tool_use…), Tool(result1), Tool(result2)] →
            // assistant,user,user). Coalesce this turn INTO the previous emitted message when they
            // share a role, so the wire conversation always alternates. On a same-protocol Bedrock
            // passthrough the input already alternates, so this never fires and byte-identity holds.
            if let Some(prev_content) = msgs_arr
                .last_mut()
                .filter(|last| last.get("role").and_then(|r| r.as_str()) == Some(role_str))
                .and_then(|last| last.get_mut("content"))
                .and_then(|c| c.as_array_mut())
            {
                // Merge: append this turn's blocks to the previous same-role message. An empty
                // content_arr appends nothing (no stray placeholder needed — the turn is absorbed).
                prev_content.append(&mut content_arr);
                continue;
            }

            // A user/assistant/tool turn whose blocks were ALL non-representable (e.g. a
            // thinking-only assistant message, or a block kind that produced nothing above)
            // would otherwise yield an empty `content_arr`. Dropping the whole message loses
            // turn structure and can break strict user/assistant alternation that Bedrock
            // Converse enforces (a 400 ValidationException). Mirror the Anthropic writer
            // (`write_message`/`write_block`, which emit `""` for an empty content body) by
            // substituting a minimal placeholder text block so the turn survives the seam.
            // System-role messages never reach here (they `continue` during role mapping).
            if content_arr.is_empty() {
                content_arr.push(serde_json::json!({ "text": "" }));
            }
            let mut msg_obj = serde_json::Map::new();
            msg_obj.insert("role".to_string(), serde_json::json!(role_str));
            msg_obj.insert("content".to_string(), serde_json::Value::Array(content_arr));
            msgs_arr.push(serde_json::Value::Object(msg_obj));
        }

        if !msgs_arr.is_empty() {
            out.insert("messages".to_string(), serde_json::Value::Array(msgs_arr));
        }

        // Rebuild `inferenceConfig` by OVERLAYING the two typed fields (`maxTokens`/`temperature`)
        // onto the RAW `inferenceConfig` object the reader captured into `extra`. This preserves
        // every sub-field the reader does not model (`stopSequences`, `topP`, `topK`, `stopCriteria`,
        // future AWS additions) on a same-protocol passthrough while still letting a cross-protocol
        // egress (where `extra` carries no `inferenceConfig`) emit a config built purely from the
        // typed IR. The typed fields WIN over any same-named raw entry so the structured IR remains
        // the source of truth for the values it models. `extra`'s raw `inferenceConfig` is consumed
        // here (not re-emitted by the trailing extra-merge), so there is no double-emit.
        let mut inference_config = req
            .extra
            .get("inferenceConfig")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(max_tokens) = req.max_tokens {
            inference_config.insert("maxTokens".to_string(), serde_json::json!(max_tokens));
        }
        if let Some(temperature) = req.temperature {
            // Clamp to Bedrock's native [0.0, 1.0] (PF-M1). OpenAI / Responses accept temperature up
            // to 2.0, so a cross-protocol request can carry a value Bedrock's API rejects with a hard
            // 400 ValidationException; clamping forwards the closest valid value instead. NON-SILENT
            // (mirrors the Anthropic writer): warn ONLY when the clamp actually changed the value, so
            // the divergence is visible in logs rather than silently rewriting a caller's temperature.
            let (clamped, was_clamped) = clamp_temperature_for_bedrock(temperature);
            if was_clamped {
                tracing::warn!(
                    requested_temperature = temperature,
                    clamped_temperature = clamped,
                    "clamping temperature to Bedrock's [0.0, 1.0] range; the requested value was \
                     out of range and would be rejected with a 400 ValidationException",
                );
            }
            inference_config.insert("temperature".to_string(), serde_json::json!(clamped));
        }
        // Promoted sampling controls overlaid in Bedrock's inferenceConfig shape (typed IR wins over
        // the raw captured value, so same-protocol round-trips re-emit the identical value and
        // cross-protocol egress emits the value carried in the IR). `top_k` has no inferenceConfig
        // home — it is emitted below via `additionalModelRequestFields` (PF-H1 fidelity fix).
        if let Some(top_p) = req.top_p {
            inference_config.insert("topP".to_string(), serde_json::json!(top_p));
        }
        if !req.stop.is_empty() {
            inference_config.insert("stopSequences".to_string(), serde_json::json!(req.stop));
        }

        if !inference_config.is_empty() {
            out.insert(
                "inferenceConfig".to_string(),
                serde_json::Value::Object(inference_config),
            );
        }

        // response_format (D3): Bedrock Converse has NO native top-level `response_format` /
        // structured-output field (structured output is model-specific and rides in
        // `additionalModelRequestFields`, which we do not synthesize here). The reader never sets
        // `response_format` on the same-protocol (Bedrock→Bedrock) path — same-protocol relays the raw
        // upstream body and never reaches this writer — so this only fires for a CROSS-PROTOCOL IR
        // (e.g. an OpenAI/Responses request carrying `response_format`) reaching the Bedrock egress.
        // Dropping it silently is exactly the lossy mutation busbar exists to avoid, so emit a `warn!`
        // so the divergence is observable rather than invisible (mirrors the Anthropic egress). The
        // directive is dropped, not forwarded: there is no native key to carry it on Converse.
        if req.response_format.is_some() {
            tracing::warn!(
                parameter = "response_format",
                "dropping response_format on Bedrock egress: Converse has no native \
                 response_format field, so the structured-output directive from a cross-protocol \
                 request is NOT forwarded"
            );
        }

        // Rebuild `toolConfig` by OVERLAYING the typed `tools` array onto the RAW `toolConfig` object
        // the reader captured into `extra`. This preserves every sub-field the reader does not model —
        // notably `toolChoice` (`{auto:{}}` / `{any:{}}` / `{tool:{name:...}}`, the force-tool-use
        // control) and any future AWS addition — on a same-protocol passthrough while still letting a
        // cross-protocol egress (where `extra` carries no `toolConfig`) emit a config built purely from
        // the typed IR `tools`. The typed `tools` array WINS over any same-named raw entry so the
        // structured IR remains the source of truth for the tools it models. `extra`'s raw `toolConfig`
        // is consumed here (not re-emitted by the trailing extra-merge), so there is no double-emit.
        //
        // The whole `toolConfig` is emitted only when there is something to emit — either typed tools
        // OR a non-empty raw object (e.g. a `toolChoice` with no tools). AWS rejects a `toolConfig`
        // with an empty `tools` array, so we never write a bare `{}`/`{tools:[]}` shape.
        let mut tool_config = req
            .extra
            .get("toolConfig")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut tool_spec = serde_json::Map::new();
                tool_spec.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    tool_spec.insert("description".to_string(), serde_json::json!(desc));
                }

                let mut input_schema = serde_json::Map::new();
                input_schema.insert("json".to_string(), tool.input_schema.clone());
                tool_spec.insert(
                    "inputSchema".to_string(),
                    serde_json::Value::Object(input_schema),
                );

                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("toolSpec".to_string(), serde_json::Value::Object(tool_spec));
                tools_arr.push(serde_json::Value::Object(tool_obj));

                // H3: a tool-definition prompt-cache boundary is emitted as a `cachePoint` element in
                // the `toolConfig.tools` array right after the tool it closes (the prefix of tool
                // schemas up to here is cached). Unlike the system/message arrays there is no
                // positional tools-cachePoint stash, so the typed `cache_control` field is the SOLE
                // carrier on BOTH the same-protocol path (the raw `toolConfig.tools` is clobbered by
                // this typed rebuild) and the cross-protocol path — no suppression gate needed.
                if tool.cache_control.is_some() {
                    tools_arr.push(bedrock_cache_point());
                }
            }

            tool_config.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }
        // Emit `toolChoice` from the typed IR union (PF-H1). The reader promoted a native `toolChoice`
        // into `req.tool_choice`, but the RAW `toolConfig` cloned from `extra` (same-protocol Bedrock
        // passthrough) still carries the original `toolChoice` key — drop it first so the typed value
        // is the single source of truth and there is no stale duplicate. `IrToolChoice::None` has no
        // native Bedrock representation, so `write_bedrock_tool_choice` returns `None` and no
        // `toolChoice` is emitted in that case.
        tool_config.remove("toolChoice");
        // `toolChoice` is only valid alongside a non-empty `tools` array: Bedrock Converse rejects a
        // `toolConfig` that carries a `toolChoice` with no tools (F3 — ValidationException). So emit
        // the typed tool-choice ONLY when tools are present (typed `req.tools` above, or a raw
        // `toolConfig.tools` preserved from same-protocol `extra`). A tool_choice that arrives with no
        // surviving tools (e.g. a cross-protocol request whose tools could not be projected) is
        // dropped with a warn rather than emitted into an invalid body.
        if tool_config.contains_key("tools") {
            if let Some(tc) = &req.tool_choice {
                match write_bedrock_tool_choice(tc) {
                    Some(v) => {
                        tool_config.insert("toolChoice".to_string(), v);
                    }
                    // L4: `IrToolChoice::None` ("do NOT call a tool") has no native Converse directive,
                    // so it degrades to omitting `toolChoice` (the backend applies its own default,
                    // which may still call a tool). Previously SILENT; warn so it is observable.
                    None => {
                        tracing::warn!(
                            "dropping tool_choice=None: Bedrock Converse has no 'do not call a tool' \
                             directive, so toolChoice is omitted and the backend may still call a tool"
                        );
                    }
                }
            }
        } else if req.tool_choice.is_some() {
            tracing::warn!(
                "dropping tool_choice with no accompanying tools: Bedrock Converse rejects a \
                 toolConfig whose toolChoice has no tools array, so it is omitted"
            );
        }
        // Emit `toolConfig` only when it carries a `tools` array. AWS rejects a bare `{}`/`{tools:[]}`
        // and a `{toolChoice:…}` with no tools, so a config that ended up with neither typed nor raw
        // tools (only a now-dropped toolChoice) must not be emitted at all.
        if tool_config.contains_key("tools") {
            out.insert(
                "toolConfig".to_string(),
                serde_json::Value::Object(tool_config),
            );
        }

        // Emit `top_k` (PF-H1 fidelity fix). Bedrock's Converse API has no `inferenceConfig` slot for
        // top_k; it rides in the model-specific `additionalModelRequestFields` escape hatch. OVERLAY
        // the typed IR `top_k` (as `top_k`) onto the RAW `additionalModelRequestFields` the reader
        // captured into `extra` — same pattern as `inferenceConfig`/`toolConfig`. This re-emits a
        // same-protocol Bedrock->Bedrock top_k faithfully AND carries a cross-protocol top_k (e.g.
        // from Anthropic, where `extra` is cleared) onto the wire instead of dropping it. The raw
        // `additionalModelRequestFields` is consumed here (skipped in the trailing extra-merge) to
        // avoid a double-emit. The typed `top_k` WINS over any same-named raw entry.
        let mut additional_fields = req
            .extra
            .get("additionalModelRequestFields")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        if let Some(top_k) = req.top_k {
            // Preserve the source spelling on a same-protocol passthrough: re-emit camelCase `topK`
            // when the reader stamped the sentinel (the body arrived as `topK`), else the canonical
            // snake_case `top_k`. The sentinel only survives on the same-protocol path (`extra` is
            // cleared cross-protocol), so cross-protocol egress always takes the `top_k` branch.
            let key = if req.extra.contains_key(TOP_K_CAMEL_SENTINEL) {
                "topK"
            } else {
                "top_k"
            };
            additional_fields.insert(key.to_string(), serde_json::json!(top_k));
        }
        if !additional_fields.is_empty() {
            out.insert(
                "additionalModelRequestFields".to_string(),
                serde_json::Value::Object(additional_fields),
            );
        }

        for (key, value) in &req.extra {
            // `inferenceConfig` and `toolConfig` were already consumed above (typed fields overlaid
            // onto the raw object); re-inserting the raw copy here would clobber that overlay and drop
            // the typed `maxTokens`/`temperature` (inferenceConfig) or `tools` (toolConfig). Every
            // other unmodeled field passes through verbatim.
            if key == "inferenceConfig" || key == "toolConfig" {
                continue;
            }
            // `additionalModelRequestFields` was already consumed above (typed `top_k` overlaid onto
            // the raw object); re-inserting the raw copy here would clobber that overlay and drop the
            // typed `top_k`. Skip it to avoid the double-emit (mirrors inferenceConfig/toolConfig).
            if key == "additionalModelRequestFields" {
                continue;
            }
            // The cachePoint stash is a busbar-internal sentinel, NOT a real Bedrock top-level
            // field — it was already consumed above (spliced back into `system`/`messages`). Emitting
            // it verbatim would leak the sentinel object onto the wire (an invalid body and a proxy
            // tell), so skip it here. Mirrors the inferenceConfig/toolConfig consume-don't-re-emit.
            if key == CACHE_POINTS_SENTINEL {
                continue;
            }
            // The guardContent stash is likewise a busbar-internal sentinel, already consumed above
            // (spliced back into `system`/`messages`). Skip it so it never leaks onto the wire.
            if key == GUARD_CONTENT_SENTINEL {
                continue;
            }
            // The top_k source-spelling hint is a busbar-internal sentinel, already consumed above
            // (it selected the `topK`/`top_k` key emitted into `additionalModelRequestFields`). Skip
            // it so it never leaks onto the wire (an invalid body and a proxy tell).
            if key == TOP_K_CAMEL_SENTINEL {
                continue;
            }
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        match ev {
            IrStreamEvent::MessageStart { .. } => Some((
                ET_MESSAGE_START.to_string(),
                serde_json::json!({ "role": "assistant" }),
            )),

            IrStreamEvent::BlockStart { index, block } => match block {
                // AWS ConverseStream emits a `contentBlockStart` frame at the start of EVERY content
                // block, including text blocks, with an empty `start` struct. A native AWS SDK uses
                // this event to initialize its per-block streaming decoder; omitting it for text
                // blocks leaves the following `contentBlockDelta`s orphaned (no preceding start),
                // which strict SDK parsers discard or reject — and is a detectable proxy tell.
                crate::ir::IrBlockMeta::Text => Some((
                    ET_CONTENT_BLOCK_START.to_string(),
                    serde_json::json!({ "contentBlockIndex": index, "start": {} }),
                )),
                crate::ir::IrBlockMeta::ToolUse { id, name } => Some((
                    ET_CONTENT_BLOCK_START.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "start": { "toolUse": { "toolUseId": id, "name": name } }
                    }),
                )),
                // A reasoning (extended-thinking) block opens with a `contentBlockStart` whose
                // `start` carries an (empty) `reasoningContent` object — the inverse of the reader's
                // lazy-open. Without this the streamed reasoning deltas were orphaned and the block
                // dropped on Bedrock egress; mirror the buffered `write_response` reasoningContent
                // re-emit on the streaming path. (Image has no streaming-start projection on Bedrock
                // — image blocks are not streamed as `contentBlock*` frames — so it stays None.)
                crate::ir::IrBlockMeta::Thinking => Some((
                    ET_CONTENT_BLOCK_START.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "start": { "reasoningContent": {} }
                    }),
                )),
                crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "text": text }
                    }),
                )),

                crate::ir::IrDelta::InputJsonDelta(json_str) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "toolUse": { "input": json_str } }
                    }),
                )),

                // Streamed extended-thinking. The Bedrock `ReasoningContentBlockDelta` union carries
                // EITHER a `text` (plaintext reasoning) OR a `signature` (the opaque reasoning token)
                // OR a `redactedContent` (opaque encrypted bytes) per frame — each IR delta maps to
                // exactly ONE ConverseStream frame, so the single-frame-per-event constraint holds.
                // This is the streaming inverse of `bedrock_reasoning_block`'s buffered logic.
                crate::ir::IrDelta::ThinkingDelta(text) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "reasoningContent": { "text": text } }
                    }),
                )),

                // A genuine reasoning signature token re-emits under `signature`.
                crate::ir::IrDelta::SignatureDelta(sig) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "reasoningContent": { "signature": sig } }
                    }),
                )),
                // A streamed redacted-reasoning delta re-emits the opaque bytes under `redactedContent`
                // (never as a plaintext `signature`) — the streaming inverse of `bedrock_reasoning_block`.
                crate::ir::IrDelta::RedactedReasoningDelta(redacted) => Some((
                    ET_CONTENT_BLOCK_DELTA.to_string(),
                    serde_json::json!({
                        "contentBlockIndex": index,
                        "delta": { "reasoningContent": { "redactedContent": redacted } }
                    }),
                )),
                // L2-5: Bedrock ConverseStream has no streaming-citation delta shape; suppress
                // rather than emit a non-native frame (the citation is preserved in the IR and
                // re-emitted by any protocol that does model streaming citations).
                crate::ir::IrDelta::CitationsDelta(_) => None,
                // Bedrock Converse has no logprobs shape; dropped.
                crate::ir::IrDelta::LogprobsDelta(_) => None,
            },

            IrStreamEvent::BlockStop { index } => Some((
                ET_CONTENT_BLOCK_STOP.to_string(),
                serde_json::json!({ "contentBlockIndex": index }),
            )),

            // The native Bedrock ConverseStream wire carries `stopReason` in a `messageStop` frame
            // and token `usage` in a SEPARATE `metadata` frame that FOLLOWS it. The IR, however,
            // carries ONE combined `MessageDelta{stop_reason, usage}` (the reader collapses the two
            // native frames into one so a cross-protocol ingress sees a single `message_delta`/usage
            // event). A single `(event_type, json)` return cannot emit two frames, so the two-frame
            // FAN-OUT for a Bedrock INGRESS lives in `StreamTranslate::translate_event` (proto/mod.rs),
            // which splits a combined delta into a stop-only delta (→ here, `messageStop`) and a
            // usage-only delta (→ here, `metadata`) before calling this writer, and injects the real
            // `metrics.latencyMs` onto the `metadata` frame.
            //
            // This arm therefore maps each (already-split) MessageDelta to its single native frame:
            //   - stop_reason = Some(...)  → `messageStop` (the stop discriminant; usage ignored)
            //   - stop_reason = None       → `metadata` carrying the real token usage (no `metrics`
            //                                here — the StreamTranslate fan-out adds it with the real
            //                                elapsed wall-clock, or omits it when timing is absent;
            //                                fabricating a `latencyMs: 0` was itself a detectable tell).
            // Bedrock has no stop_sequence field in its stream, so `stop_sequence` is ignored here.
            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => match stop_reason {
                Some(reason) => Some((
                    ET_MESSAGE_STOP.to_string(),
                    serde_json::json!({ "stopReason": stop_reason_reverse(*reason) }),
                )),
                None => {
                    let mut usage_obj = serde_json::Map::new();
                    usage_obj.insert("inputTokens".to_string(), usage.input_tokens.into());
                    usage_obj.insert("outputTokens".to_string(), usage.output_tokens.into());
                    // Saturating add: token counts arrive from an untrusted upstream
                    // (`as_u64().unwrap_or(0)` in the reader); a pathological/hostile pair
                    // near `u64::MAX` would panic this request-path code under
                    // overflow-checks (all debug builds, opt-in release) or silently wrap to
                    // a nonsense `totalTokens` in plain release. Mirror the Gemini writer's
                    // explicit `saturating_add` so the total clamps at `u64::MAX` instead.
                    usage_obj.insert(
                        "totalTokens".to_string(),
                        usage
                            .input_tokens
                            .saturating_add(usage.output_tokens)
                            .into(),
                    );
                    write_cache_usage(&mut usage_obj, usage);
                    Some((
                        ET_METADATA.to_string(),
                        serde_json::json!({ "usage": usage_obj }),
                    ))
                }
            },

            IrStreamEvent::MessageStop => None,

            // A mid-stream error on the Bedrock-ingress path. The fully native representation is an
            // AWS modeled-exception EVENT-STREAM frame (`:message-type: exception` +
            // `:exception-type: <ExceptionName>`), which `StreamTranslate` now emits via
            // `write_response_exception` + `eventstream::encode_exception_frame` BEFORE reaching this
            // arm (a Bedrock-ingress stream never routes an `Error` through `write_response_event`).
            // This arm therefore only fires if a non-eventstream consumer ever drives a Bedrock
            // writer with an `Error` event; it falls back to a normal `event`-typed frame naming a
            // real ConverseStream-output exception (via `bedrock_stream_exception_for`, the five-member
            // stream union — NOT the request-level HTTP set) so the type token is still a genuine AWS
            // stream-event name rather than the literal `"error"` or a non-stream request shape.
            IrStreamEvent::Error(err) => {
                let (exception_name, message) = bedrock_stream_exception_for(err);
                Some((
                    exception_name.to_string(),
                    serde_json::json!({ "message": message }),
                ))
            }
        }
    }

    /// A Bedrock-ingress stream signals a mid-stream error with a MODELED-EXCEPTION event-stream
    /// frame (`:message-type: exception`), which `StreamTranslate` emits via
    /// `eventstream::encode_exception_frame`. This maps the IR error to that frame's
    /// `(exception_name, message)` using `bedrock_stream_exception_for` — the FIVE-member
    /// ConverseStream output-union (`InternalServerException`, `ModelStreamErrorException`,
    /// `ValidationException`, `ThrottlingException`, `ServiceUnavailableException`), NOT the larger
    /// request-level HTTP exception set — so a native AWS SDK stream decoder always recognizes the
    /// `:exception-type` as a modeled stream event. Shares the mapping with the (fallback)
    /// `write_response_event` Error arm so both stay consistent.
    fn write_response_exception(&self, err: &crate::proto::IrError) -> Option<(String, String)> {
        let (exception_name, message) = bedrock_stream_exception_for(err);
        Some((exception_name.to_string(), message))
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        let mut content_arr: Vec<serde_json::Value> = Vec::new();

        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    if !text.is_empty() {
                        content_arr.push(serde_json::json!({ "text": text }));
                    }
                }

                crate::ir::IrBlock::ToolUse {
                    id, name, input, ..
                } => {
                    content_arr.push(serde_json::json!({
                        "toolUse": {
                            "toolUseId": id,
                            "name": name,
                            "input": input
                        }
                    }));
                }

                crate::ir::IrBlock::Image { source, .. } => {
                    // An assistant response CAN legitimately carry an Image block (e.g. a
                    // cross-protocol egress whose source emitted an image in the model turn).
                    // Bedrock Converse natively represents it as an `{"image": ...}` content block.
                    // A source kind with no native Bedrock projection (URL / file_id) returns `None`
                    // and is omitted with a trace by the helper, never corrupting the block.
                    if let Some(image_block) = bedrock_image_block(source) {
                        content_arr.push(serde_json::json!({ "image": image_block }));
                    }
                }
                crate::ir::IrBlock::Json(_) => {
                    // Structured-json content has no top-level Bedrock response shape (it is only a
                    // tool-result content member); omit it from an assistant response turn.
                }

                crate::ir::IrBlock::Thinking {
                    text,
                    signature,
                    redacted,
                    ..
                } => {
                    // Re-emit the model's reasoning as a native Converse `reasoningContent` block
                    // (the inverse of `read_response`'s reasoningContent decode), instead of silently
                    // dropping it. A same-protocol passthrough reproduces the thinking block, and a
                    // cross-protocol egress that carried reasoning into the IR can surface it. The
                    // redacted-signature sentinel re-emits `redactedContent`; any other Thinking
                    // re-emits `reasoningText`.
                    content_arr.push(bedrock_reasoning_block(text, signature, *redacted));
                }

                // A `toolResult` is a USER-turn content block in Bedrock Converse; it has no place
                // in an ASSISTANT response message, so it is the only genuine no-op here. Handled
                // explicitly — no catch-all.
                crate::ir::IrBlock::ToolResult { .. } => {}
            }
        }

        // Bedrock Converse rejects an assistant message with an empty `content` array
        // (ValidationException), exactly as `write_request` guards every turn. A response whose
        // blocks were ALL non-representable here (e.g. thinking-only, or a stray toolResult) would
        // otherwise emit `content: []`. Mirror the request-side guard with a minimal placeholder
        // text block so the body stays valid.
        if content_arr.is_empty() {
            content_arr.push(serde_json::json!({ "text": "" }));
        }

        let reverse_reason =
            stop_reason_reverse(resp.stop_reason.unwrap_or(crate::ir::IrStopReason::EndTurn));

        // Identity emission. The native AWS Converse response body (the shape the official SDK
        // deserializes — `output` / `stopReason` / `usage` / optional `metrics`) carries NO id or
        // `created` field; AWS returns the request id only in the `x-amzn-RequestId` HTTP header.
        // Injecting a synthesized `id`/`created` into the JSON body would therefore be a
        // proxy-tell, not fidelity — so we deliberately do NOT add one. (The inverse direction — a
        // Bedrock egress feeding an OpenAI/Anthropic ingress that DOES require a body id — is the
        // job of that ingress writer, not this one; no Bedrock-side id synthesizer is wired into the
        // production path, so none is shipped.) `stopReason` and `usage` (the only identity-bearing
        // fields Bedrock emits) are reproduced exactly from the captured IR below, so a
        // same-protocol round-trip is byte-identical.
        let mut usage_obj = serde_json::Map::new();
        usage_obj.insert("inputTokens".to_string(), resp.usage.input_tokens.into());
        usage_obj.insert("outputTokens".to_string(), resp.usage.output_tokens.into());
        // Saturating add, same rationale as the streaming `metadata` frame: token counts are
        // upstream-derived and unbounded, so a bare `u64 + u64` here is an overflow-panic
        // (overflow-checks) / silent-wrap (release) hazard on the buffered Converse body.
        usage_obj.insert(
            "totalTokens".to_string(),
            resp.usage
                .input_tokens
                .saturating_add(resp.usage.output_tokens)
                .into(),
        );
        write_cache_usage(&mut usage_obj, &resp.usage);

        serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": content_arr
                }
            },
            "stopReason": reverse_reason,
            "usage": usage_obj
        })
    }

    /// Native AWS Bedrock Converse error envelope. The Converse error model (REST-JSON protocol)
    /// serializes every modeled exception as a flat body whose human-readable detail lives in a
    /// lowercase `"message"` member, with the machine-readable exception name in `"__type"` (the
    /// exact two fields `BedrockReader::extract_error` reads back). A native AWS SDK deserializes
    /// the typed exception from `__type` and surfaces the text from `message`; serving the generic
    /// `{"error":{...}}` envelope here would make a Bedrock SDK fail to decode the error. We map
    /// busbar's generic `kind` to the closed AWS exception set via `error_kind_to_bedrock_type` so
    /// the `__type` is always a real Converse exception name. Served as `application/json`.
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "__type": error_kind_to_bedrock_type(kind),
            "message": message,
        })
    }

    fn quota_exceeded_status(&self) -> StatusCode {
        // AWS Bedrock surfaces an over-quota condition as `ServiceQuotaExceededException`, a
        // 400-class error — NOT the 429 every other vendor uses.
        StatusCode::BAD_REQUEST
    }

    fn attach_error_response_headers(
        &self,
        headers: &mut axum::http::HeaderMap,
        kind: &str,
        _envelope: &serde_json::Value,
    ) {
        // A real AWS Bedrock runtime response ALWAYS carries `x-amzn-RequestId` (the only request-id
        // surface the AWS SDK exposes via `*Output::request_id()`) and `x-amzn-errortype` == the body
        // `__type`. Omitting them was distinguishable from native Bedrock and left the SDK request id
        // empty on the most-exercised failover error surface.
        attach_bedrock_error_headers(headers, kind);
    }

    fn ingress_is_eventstream(&self) -> bool {
        // A native AWS SDK Bedrock client decodes a BINARY `application/vnd.amazon.eventstream`
        // body, not SSE text. Mid-stream errors must be binary exception frames (not SSE `event:`
        // text) — writing SSE text into a binary eventstream body yields an undecodable prelude/CRC.
        true
    }

    fn new_stream_framing(&self) -> Box<dyn super::StreamFraming> {
        // Bedrock-ingress per-stream framing: the messageStop/metadata two-frame deferral and the
        // exactly-one-metadata invariant. Lives here, in the Bedrock module, so the agnostic
        // translator names no Bedrock wire shape.
        Box::<BedrockStreamFraming>::default()
    }

    fn streaming_content_type(&self) -> &'static str {
        // Bedrock ingress expects a BINARY `application/vnd.amazon.eventstream` body; the encoder
        // is implemented and wired (`StreamTranslate` packs each event into a CRC-valid frame).
        // Returns this instead of the default `text/event-stream` so the response CT matches the
        // body framing the client actually receives — mislabeling it as SSE would break the SDK.
        APPLICATION_VND_AMAZON_EVENTSTREAM
    }

    fn egress_user_agent(&self) -> &'static str {
        // AWS Bedrock is reached via boto3/botocore; the SDK's UA is the backend-facing fingerprint
        // guard. Pinned — see `EGRESS_UA_BEDROCK` in forward.rs.
        crate::proxy::EGRESS_UA_BEDROCK
    }

    fn egress_accept(&self, wants_stream: bool) -> &'static str {
        // botocore/boto3 sends `application/vnd.amazon.eventstream` on a ConverseStream call and
        // `application/json` on a non-stream Converse call — the headline Bedrock egress surface.
        if wants_stream {
            APPLICATION_VND_AMAZON_EVENTSTREAM
        } else {
            crate::proxy::APPLICATION_JSON
        }
    }

    fn has_model_in_url(&self) -> bool {
        // Bedrock encodes the model in the URL path (`/model/{id}/converse`), NOT the body.
        // The body `model` field must be stripped on the same-protocol passthrough path so the
        // native Converse backend does not see an unexpected field.
        true
    }

    fn auth_failure_status_and_kind(&self) -> (axum::http::StatusCode, &'static str) {
        // A real AWS SigV4 rejection returns HTTP 403 AccessDenied (NOT 401). The AWS SDK keys
        // its typed `AccessDeniedException` off the 403 status, so returning 401 here would be
        // a deterministic proxy tell and a mismatched typed-exception class on the SDK side.
        (axum::http::StatusCode::FORBIDDEN, "auth")
    }

    fn wrap_buffered_as_stream(
        &self,
        ir: &crate::ir::IrResponse,
        elapsed_ms: Option<u64>,
    ) -> Option<Vec<u8>> {
        // A Bedrock-ingress client that requested ConverseStream but received a buffered (non-SSE)
        // 2xx response from the upstream must get a native binary eventstream frame sequence, not a
        // bare `application/json` Converse body that the SDK's eventstream decoder cannot parse
        // (hard decode failure and a deterministic proxy tell). Delegate to the module-local free fn
        // which synthesizes the full frame sequence through this same writer — the call sites now
        // dispatch through the vtable instead of branching on `ingress_protocol == "bedrock"`.
        Some(bedrock_response_to_eventstream(ir, elapsed_ms))
    }

    fn inject_response_metrics(&self, value: &mut serde_json::Value, elapsed_ms: Option<u64>) {
        // A native AWS Bedrock Converse (non-stream) response ALWAYS populates `metrics.latencyMs`
        // (the SDK surfaces it via `ConverseOutput::metrics().latency_ms()`). The bedrock writer's
        // `write_response` deliberately omits it (timing is unknown at that layer); inject the real
        // request elapsed wall-clock here, and OMIT rather than fabricate a tell-tale `0` if timing
        // is unavailable — the same policy the streaming path applies on the `metadata` frame.
        if let (Some(ms), Some(obj)) = (elapsed_ms, value.as_object_mut()) {
            let mut metrics = serde_json::Map::new();
            metrics.insert(FIELD_LATENCY_MS.to_string(), serde_json::Value::from(ms));
            obj.insert(
                FIELD_METRICS.to_string(),
                serde_json::Value::Object(metrics),
            );
        }
    }

    fn ingress_relays_amzn_headers(&self) -> bool {
        // A real AWS Bedrock endpoint ALWAYS carries `x-amzn-RequestId` (the only request-id surface
        // the AWS SDK exposes via `*Output::request_id()`) and `x-amzn-errortype` on every response.
        // Their absence is a detectable proxy tell and leaves the SDK's `request_id()` returning None.
        true
    }

    fn ingress_response_request_id(
        &self,
        upstream_request_id: Option<&str>,
    ) -> Option<(&'static str, String)> {
        // A real ConverseStream/Converse response carries `x-amzn-RequestId`. Forward the captured
        // upstream id verbatim on a same-protocol passthrough (the streaming path captures one);
        // synthesize otherwise (the non-stream/cross-protocol case supplies `None`). Identical to the
        // prior inline `upstream_amzn_id.or_else(synth_amzn_request_id)` / synth-only attaches.
        // Synthesis failure (no entropy) omits the header rather than panicking.
        upstream_request_id
            .map(String::from)
            .or_else(synth_amzn_request_id)
            .map(|id| (HDR_AMZN_REQUEST_ID, id))
    }

    fn ingress_relayed_response_header_names(&self) -> &'static [&'static str] {
        // Forwarded VERBATIM on a same-protocol bedrock passthrough: `x-amzn-RequestId` and
        // `x-amzn-errortype` (AWS SDKs dispatch the typed exception from errortype BEFORE the body
        // `__type`; absence is a detectable tell).
        &[HDR_AMZN_REQUEST_ID, HDR_AMZN_ERROR_TYPE]
    }

    fn auth_failure_message(&self) -> &'static str {
        // AWS conveys AccessDenied via `__type` / `x-amzn-errortype`, not message prose.
        ""
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

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
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn stop_reason_reverse_never_leaks_foreign_tokens() {
        use crate::ir::IrStopReason as S;
        assert_eq!(stop_reason_reverse(S::EndTurn), "end_turn");
        assert_eq!(stop_reason_reverse(S::ToolUse), "tool_use");
        assert_eq!(stop_reason_reverse(S::Safety), "content_filtered");
        // Foreign / off-enum reasons degrade to end_turn rather than emit an off-spec Converse
        // `stopReason` a strict client rejects. (A Bedrock `guardrail_intervened` read folds to
        // `Safety`, which writes back as `content_filtered`.)
        assert_eq!(read_bedrock_stop_reason_guardrail(), S::Safety);
        assert_eq!(stop_reason_reverse(S::Refusal), "end_turn");
        assert_eq!(stop_reason_reverse(S::Error), "end_turn");
        assert_eq!(stop_reason_reverse(S::Other), "end_turn");
    }

    fn read_bedrock_stop_reason_guardrail() -> crate::ir::IrStopReason {
        stop_reason_map("guardrail_intervened")
    }

    // Cross-protocol response-id synthesis is NOT wired into any production path (Bedrock's own
    // body has no id field, and the inverse direction is the consuming ingress writer's job — see
    // `write_response`). The helper trio below was previously shipped in the production binary under
    // `#[cfg_attr(not(test), allow(dead_code))]`; it is now confined to the test module so 1.0 does
    // not carry dead production scaffolding. If/when the cross-protocol id-population seam lands, the
    // trio moves back into production scope (and loses this test-only home).

    /// Monotonic per-process counter so two ids minted in the same wall-clock second still differ.
    static SYNTH_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Current unix time in whole seconds; a pre-epoch clock degrades to 0 rather than panicking.
    fn unix_now_secs() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Mint a syntactically-plausible, collision-resistant `<hex16>-<hex16>` token from
    /// (unix seconds + a monotonic counter) — no UUID crate, no panic.
    fn synth_response_id() -> String {
        let n = SYNTH_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{:016x}-{:016x}", unix_now_secs(), n)
    }

    #[test]
    fn test_bedrock_sigv4_sign_request_structure() {
        // SigV4 header assembly + scope/region derivation. (The signing crypto itself is
        // verified against AWS's published vector in sigv4::tests.)
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            canonical_uri: crate::sigv4::uri_encode_path("/model/anthropic.claude:0/converse"),
            body: br#"{"messages":[]}"#,
            timestamp_epoch: 1_440_938_160, // 20150830T123600Z
            upstream_creds: crate::auth::UpstreamCreds::Own,
        };
        let headers = writer.sign_request("AKIDEXAMPLE:SECRETKEY", &ctx);

        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.as_str() == name)
                .map(|(_, v)| v.to_str().unwrap().to_string())
        };
        let auth = get("authorization").expect("authorization header");
        assert!(
            auth.starts_with(
                // golden wire-contract literal (kept bare on purpose)
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, "
            ),
            "scope/region derived from host; got: {auth}"
        );
        // golden wire-contract literal (kept bare on purpose)
        assert!(auth.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"));
        assert!(auth.contains("Signature="));
        assert_eq!(get("x-amz-date").as_deref(), Some("20150830T123600Z")); // golden wire-contract literal (kept bare on purpose)
        assert!(get("x-amz-content-sha256").is_some()); // golden wire-contract literal (kept bare on purpose)
                                                        // No session token configured → no security-token header.
        assert!(get("x-amz-security-token").is_none()); // golden wire-contract literal (kept bare on purpose)
    }

    #[test]
    fn test_bedrock_sigv4_session_token() {
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.eu-west-1.amazonaws.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
            upstream_creds: crate::auth::UpstreamCreds::Own,
        };
        let headers = writer.sign_request("AKID:SECRET:SESSIONTOKEN", &ctx);
        let tok = headers
            .iter()
            .find(|(k, _)| k.as_str() == "x-amz-security-token") // golden wire-contract literal (kept bare on purpose)
            .map(|(_, v)| v.to_str().unwrap().to_string());
        assert_eq!(tok.as_deref(), Some("SESSIONTOKEN"));
        // region parsed from the eu-west-1 host + token in the signed set.
        let auth = headers
            .iter()
            .find(|(k, _)| k.as_str() == "authorization")
            .map(|(_, v)| v.to_str().unwrap().to_string())
            .unwrap();
        assert!(auth.contains("/eu-west-1/bedrock/aws4_request")); // golden wire-contract literal (kept bare on purpose)
        assert!(auth.contains("x-amz-security-token")); // golden wire-contract literal (kept bare on purpose)
    }

    #[test]
    fn test_bedrock_sigv4_misconfigured_key_no_signature() {
        // A key without ACCESS:SECRET shape yields no headers (AWS will 403 → surfaced as auth).
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
            upstream_creds: crate::auth::UpstreamCreds::Own,
        };
        assert!(writer.sign_request("not-a-valid-key", &ctx).is_empty());
    }

    fn bedrock_rich_fixture() -> serde_json::Value {
        serde_json::json!({
            "system": [{"text": "You are a helpful assistant."}],
            "messages": [
                {"role": "user", "content": [{"text": "What is the weather in San Francisco?"}]},
                {"role": "assistant", "content": [{"toolUse": {"toolUseId": "tool_123", "name": "get_weather", "input": {"city": "San Francisco"}}}]},
                {"role": "user", "content": [{"toolResult": {"toolUseId": "tool_123", "content": [{"text": "Sunny, 72°F"}], "status": "success"}}]}
            ],
            "inferenceConfig": {"maxTokens": 1024, "temperature": 0.7},
            "toolConfig": {
                "tools": [{
                    "toolSpec": {
                        "name": "get_weather",
                        "description": "Get weather for a city",
                        "inputSchema": {"json": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}
                    }
                }]
            },
            "top_p": 0.95
        })
    }

    #[test]
    fn test_write_request() {
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![crate::ir::IrBlock::Text {
                text: "You are a helpful assistant.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "What is the weather in San Francisco?".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::ToolUse {
                        id: "tool_123".to_string(),
                        name: "get_weather".to_string(),
                        input: serde_json::json!({"city": "San Francisco"}),
                        cache_control: None,
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "tool_123".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "Sunny, 72°F".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                        cache_control: None,
                    }],
                },
            ],
            tools: vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: Some("Get weather for a city".to_string()),
                input_schema: serde_json::json!({"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}),
                cache_control: None,
            }],
            max_tokens: Some(1024),
            temperature: Some(0.7_f64),
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };

        let writer = BedrockWriter;
        let json = writer.write_request(&ir);

        assert_eq!(
            json.get("system")
                .and_then(|s| s.as_array())
                .and_then(|a| a.first())
                .and_then(|b| b.get("text"))
                .and_then(|t| t.as_str()),
            Some("You are a helpful assistant.")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.first())
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("text"))
                .and_then(|t| t.as_str()),
            Some("What is the weather in San Francisco?")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.get(1))
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("toolUse"))
                .and_then(|tu| tu.get("toolUseId"))
                .and_then(|id| id.as_str()),
            Some("tool_123")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.get(1))
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("toolUse"))
                .and_then(|tu| tu.get("name"))
                .and_then(|n| n.as_str()),
            Some("get_weather")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.get(1))
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("toolUse"))
                .and_then(|tu| tu.get("input"))
                .and_then(|i| i.get("city"))
                .and_then(|c| c.as_str()),
            Some("San Francisco")
        );
        assert_eq!(
            json.get("messages")
                .and_then(|m| m.as_array())
                .and_then(|a| a.get(2))
                .and_then(|msg| msg.get("content"))
                .and_then(|c| c.as_array())
                .and_then(|arr| arr.first())
                .and_then(|b| b.get("toolResult"))
                .and_then(|tr| tr.get("status"))
                .and_then(|s| s.as_str()),
            Some("success")
        );
        assert_eq!(
            json.get("inferenceConfig")
                .and_then(|ic| ic.get("maxTokens"))
                .and_then(|m| m.as_u64()),
            Some(1024)
        );
        assert_eq!(
            json.get("inferenceConfig")
                .and_then(|ic| ic.get("temperature"))
                .and_then(|t| t.as_f64()),
            Some(0.7)
        );
        assert_eq!(
            json.get("toolConfig")
                .and_then(|tc| tc.get("tools"))
                .and_then(|ts| ts.as_array())
                .and_then(|arr| arr.first())
                .and_then(|t| t.get("toolSpec"))
                .and_then(|spec| spec.get("name"))
                .and_then(|n| n.as_str()),
            Some("get_weather")
        );
    }

    #[test]
    fn test_read_request() {
        let reader = BedrockReader;
        let j = bedrock_rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        assert!(!ir.system.is_empty());
        if let crate::ir::IrBlock::Text { text, .. } = &ir.system[0] {
            assert_eq!(text, "You are a helpful assistant.");
        } else {
            panic!("system[0] should be Text block");
        }

        assert_eq!(ir.messages.len(), 3);

        if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
            assert_eq!(text, "What is the weather in San Francisco?");
        } else {
            panic!("messages[0].content[0] should be Text block");
        }

        if let crate::ir::IrBlock::ToolUse {
            id, name, input, ..
        } = &ir.messages[1].content[0]
        {
            assert_eq!(id, "tool_123");
            assert_eq!(name, "get_weather");
            match input {
                serde_json::Value::Object(obj) => {
                    assert_eq!(obj.get("city"), Some(&serde_json::json!("San Francisco")));
                }
                _ => panic!("input should be Object"),
            }
        } else {
            panic!("messages[1].content[0] should be ToolUse block");
        }

        if let crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
            ..
        } = &ir.messages[2].content[0]
        {
            assert_eq!(tool_use_id, "tool_123");
            assert!(!is_error);
            if let crate::ir::IrBlock::Text { text, .. } = &content[0] {
                assert_eq!(text, "Sunny, 72°F");
            } else {
                panic!("toolResult content[0] should be Text block");
            }
        } else {
            panic!("messages[2].content[0] should be ToolResult block");
        }

        assert_eq!(ir.max_tokens, Some(1024));
        assert_eq!(ir.temperature, Some(0.7_f64));
        assert_eq!(ir.tools.len(), 1);
        let crate::ir::IrTool {
            ref name,
            ref description,
            ..
        } = ir.tools[0];
        assert_eq!(name, "get_weather");
        assert_eq!(description.as_deref(), Some("Get weather for a city"));
    }

    #[test]
    fn test_roundtrip() {
        let reader = BedrockReader;
        let writer = BedrockWriter;

        // Same-protocol passthrough fidelity is a WIRE->IR->WIRE byte-identity guarantee: a native
        // Converse body read into the IR and written back must reproduce the original body exactly.
        // (Note: an IR->WIRE->IR round-trip is intentionally NOT idempotent for the typed
        // `inferenceConfig` sub-fields — the reader now captures the whole raw `inferenceConfig` into
        // `extra` so unmodeled sub-fields survive passthrough (finding-2 fix), so reading a written
        // body re-populates `extra.inferenceConfig`. The contract that matters is the wire round-trip
        // below.)
        let wire = serde_json::json!({
            "system": [{"text": "You are helpful."}],
            "messages": [{"role": "user", "content": [{"text": "Hello!"}]}],
            "inferenceConfig": {"maxTokens": 512, "temperature": 0.7}
        });

        let ir = reader
            .read_request(&wire)
            .expect("read round-trip should succeed");
        let wire_after = writer.write_request(&ir);

        assert_eq!(
            wire, wire_after,
            "same-protocol wire round-trip must be byte-identical"
        );
    }

    #[test]
    fn test_temperature_fidelity() {
        let j = serde_json::json!({"inferenceConfig": {"temperature": 0.7}, "messages": [{"role": "user", "content": [{"text": "hi"}]}]});
        let reader = BedrockReader;
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        assert_eq!(ir.temperature, Some(0.7_f64));
    }

    #[test]
    fn test_read_response_decode() {
        let j = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "Let me check the weather for you."},
                        {"toolUse": {"toolUseId": "tu_1", "name": "get_weather", "input": {"city": "SF"}}}
                    ]
                }
            },
            "stopReason": "tool_use",
            "usage": {
                "inputTokens": 42,
                "outputTokens": 15,
                "totalTokens": 57
            }
        });

        let reader = BedrockReader;
        let resp = reader
            .read_response(&j)
            .expect("read_response should succeed");

        assert_eq!(resp.role, crate::ir::IrRole::Assistant);
        assert_eq!(resp.content.len(), 2);

        if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
            assert_eq!(text, "Let me check the weather for you.");
        } else {
            panic!("content[0] should be Text block");
        }

        if let crate::ir::IrBlock::ToolUse {
            id, name, input, ..
        } = &resp.content[1]
        {
            assert_eq!(id, "tu_1");
            assert_eq!(name, "get_weather");
            match input {
                serde_json::Value::Object(obj) => {
                    assert_eq!(obj.get("city"), Some(&serde_json::json!("SF")));
                }
                _ => panic!("input should be Object"),
            }
        } else {
            panic!("content[1] should be ToolUse block");
        }

        assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::ToolUse));
        assert_eq!(resp.usage.input_tokens, 42);
        assert_eq!(resp.usage.output_tokens, 15);
    }

    #[test]
    fn test_read_write_response_roundtrip() {
        let j = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "Hello, world!"}]
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 10,
                "outputTokens": 5,
                "totalTokens": 15
            }
        });

        let reader = BedrockReader;
        let writer = BedrockWriter;

        let resp = reader
            .read_response(&j)
            .expect("read_response should succeed");
        let written = writer.write_response(&resp);

        assert_eq!(
            written, j,
            "round-trip must be byte-identical for text-only response"
        );
    }

    #[test]
    fn test_stream_decode_sequence() {
        use crate::ir::IrStreamEvent;

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events: Vec<_> = vec![
            (serde_json::json!({"type": "messageStart", "role": "assistant"})),
            (serde_json::json!({
                "type": "contentBlockStart",
                "contentBlockIndex": 0,
                "start": {}
            })),
            (serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"text": "Hello"}
            })),
            (serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"text": ", world!"}
            })),
            (serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0})),
            (serde_json::json!({
                "type": "messageStop",
                "stopReason": "end_turn"
            })),
            (serde_json::json!({
                "type": "metadata",
                "usage": {"inputTokens": 10, "outputTokens": 5}
            })),
        ]
        .into_iter()
        .flat_map(|data| reader.read_response_events("", &data, &mut state))
        .collect();

        // Seven events: MessageStart, text BlockStart, 2×BlockDelta, BlockStop, ONE combined
        // MessageDelta{stop_reason, usage} (from `metadata`, which BUFFERS the stop_reason from the
        // preceding `messageStop` frame), and the terminal MessageStop (also from `metadata`, emitted
        // AFTER the delta). The combined delta precedes the terminal stop so a non-eventstream ingress
        // (e.g. Anthropic) writes `message_delta` then `message_stop` — the native order (finding:
        // delta-before-stop). Previously the order was stop-then-delta (MessageStop on `messageStop`,
        // MessageDelta on `metadata`), which made the Anthropic ingress emit `message_stop` first.
        assert_eq!(events.len(), 7);

        match &events[0] {
            IrStreamEvent::MessageStart { role, usage, .. } => {
                assert_eq!(*role, crate::ir::IrRole::Assistant);
                assert!(usage.is_none());
            }
            _ => panic!("event[0] should be MessageStart"),
        }

        match &events[1] {
            IrStreamEvent::BlockStart { index, block } => {
                assert_eq!(*index, 0);
                assert!(matches!(block, crate::ir::IrBlockMeta::Text));
            }
            _ => panic!("event[1] should be BlockStart"),
        }

        match &events[2] {
            IrStreamEvent::BlockDelta { index, delta } => {
                assert_eq!(*index, 0);
                if let crate::ir::IrDelta::TextDelta(text) = delta {
                    assert_eq!(text, "Hello");
                } else {
                    panic!("event[2] should be TextDelta");
                }
            }
            _ => panic!("event[2] should be BlockDelta"),
        }

        match &events[3] {
            IrStreamEvent::BlockDelta { index, delta } => {
                assert_eq!(*index, 0);
                if let crate::ir::IrDelta::TextDelta(text) = delta {
                    assert_eq!(text, ", world!");
                } else {
                    panic!("event[3] should be TextDelta");
                }
            }
            _ => panic!("event[3] should be BlockDelta"),
        }

        match &events[4] {
            IrStreamEvent::BlockStop { index } => assert_eq!(*index, 0),
            _ => panic!("event[4] should be BlockStop"),
        }

        // The `metadata` event emits ONE combined MessageDelta carrying BOTH the buffered stop_reason
        // (from the preceding `messageStop` frame) AND the real usage — a single
        // `message_delta`-equivalent event, matching what a native non-Bedrock stream emits (finding:
        // combined MessageDelta). It precedes the terminal MessageStop so the ingress writer emits the
        // delta before the stop.
        match &events[5] {
            IrStreamEvent::MessageDelta {
                stop_reason, usage, ..
            } => {
                assert_eq!(stop_reason, &Some(crate::ir::IrStopReason::EndTurn));
                assert_eq!(usage.input_tokens, 10);
                assert_eq!(usage.output_tokens, 5);
            }
            _ => {
                panic!("event[5] should be the combined MessageDelta carrying stop_reason + usage")
            }
        }

        // The terminal MessageStop is emitted from the `metadata` branch AFTER the combined delta, so
        // the IR order is delta-then-stop. The ingress writer therefore emits `message_delta` then the
        // terminal `message_stop` — the native order a non-Bedrock stream carries.
        match &events[6] {
            IrStreamEvent::MessageStop => {}
            _ => panic!("event[6] should be the terminal MessageStop"),
        }
    }

    #[test]
    fn test_write_response_event() {
        let writer = BedrockWriter;

        let delta_ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        };

        if let Some((event_type, payload)) = writer.write_response_event(&delta_ev) {
            assert_eq!(event_type, "contentBlockDelta");
            assert_eq!(
                payload.get("contentBlockIndex").and_then(|i| i.as_u64()),
                Some(0)
            );
            assert_eq!(
                payload
                    .get("delta")
                    .and_then(|d| d.as_object())
                    .and_then(|o| o.get("text"))
                    .and_then(|t| t.as_str()),
                Some("hi")
            );
        } else {
            panic!("write_response_event should return Some for BlockDelta");
        }

        let delta_ev2 = IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };

        if let Some((event_type, payload)) = writer.write_response_event(&delta_ev2) {
            assert_eq!(event_type, "messageStop");
            assert_eq!(
                payload.get("stopReason").and_then(|s| s.as_str()),
                Some("tool_use")
            );
        } else {
            panic!("write_response_event should return Some for MessageDelta with tool_use");
        }
    }

    // --- Regression tests for the 1.0 hardening pass -------------------------------------------

    /// Regression: a malformed lane credential (access key id containing a control char that
    /// `HeaderValue::from_str` rejects) must NOT panic the request-handling task. It takes the
    /// same graceful path as a structurally-misconfigured key: an empty header set, so the
    /// request goes out unsigned and AWS surfaces a 403 auth error instead of aborting the task.
    #[test]
    fn test_bedrock_sigv4_control_char_in_access_key_no_panic() {
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
            upstream_creds: crate::auth::UpstreamCreds::Own,
        };
        // CR/LF embedded in the access key id → invalid Authorization header value
        // (HeaderValue::from_str rejects ASCII control chars, including CR/LF). This is the
        // header-injection / misconfiguration vector the finding describes.
        let headers = writer.sign_request("AKID\r\nINJECT:SECRET", &ctx);
        assert!(
            headers.is_empty(),
            "control-char access key must yield no headers (graceful), not panic; got: {headers:?}"
        );

        // A bare NUL / control byte is likewise rejected gracefully rather than panicking.
        let headers2 = writer.sign_request("AKID\u{0001}X:SECRET", &ctx);
        assert!(
            headers2.is_empty(),
            "control-char access key must yield no headers; got: {headers2:?}"
        );

        // Sanity: a well-formed key still produces the full signed header set.
        let ok = writer.sign_request("AKIDEXAMPLE:SECRETKEY", &ctx);
        assert!(
            ok.iter().any(|(k, _)| k.as_str() == "authorization"),
            "valid key still signs"
        );
    }

    /// Regression: `extract_error` must read the machine-readable error type from the AWS `__type`
    /// field (used by the breaker's error_map for fine-grained routing), keeping the
    /// human-readable text in `provider_code` from `message`. Previously both were set from
    /// `message`, so error_map rules keyed on `structured_type` never matched.
    #[test]
    fn test_extract_error_structured_type_from_type_field() {
        let reader = BedrockReader;
        let body = br#"{"__type":"ThrottlingException","message":"Rate exceeded"}"#;
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, body);
        assert_eq!(raw.http_status, 429);
        assert_eq!(raw.provider_code.as_deref(), Some("Rate exceeded"));
        assert_eq!(
            raw.structured_type.as_deref(),
            Some("ThrottlingException"),
            "structured_type must come from __type, not the message"
        );
    }

    /// `__type` is sometimes serialised as a shape ARN suffix
    /// (`com.amazon.coral.service#ValidationException`); only the trailing type token is kept.
    #[test]
    fn test_extract_error_strips_type_arn_prefix() {
        let reader = BedrockReader;
        let body =
            br#"{"__type":"com.amazon.coral.service#ValidationException","message":"bad input"}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(raw.provider_code.as_deref(), Some("bad input"));
        assert_eq!(raw.structured_type.as_deref(), Some("ValidationException"));
    }

    /// When `__type` is absent, `structured_type` is None (no longer duplicated from `message`).
    #[test]
    fn test_extract_error_no_type_field_yields_none_structured_type() {
        let reader = BedrockReader;
        let body = br#"{"message":"something went wrong"}"#;
        let raw = reader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, body);
        assert_eq!(raw.provider_code.as_deref(), Some("something went wrong"));
        assert!(
            raw.structured_type.is_none(),
            "structured_type must NOT be duplicated from message"
        );
    }

    /// A non-JSON body parses gracefully to (None, None) — single parse, no panic.
    #[test]
    fn test_extract_error_non_json_body() {
        let reader = BedrockReader;
        let raw = reader.extract_error(StatusCode::BAD_GATEWAY, b"<html>502</html>");
        assert_eq!(raw.http_status, 502);
        assert!(raw.provider_code.is_none());
        assert!(raw.structured_type.is_none());
    }

    /// A ConverseStream that ends after `messageStop` WITHOUT a trailing `metadata` event
    /// (malformed/truncated upstream) emits NO terminal MessageStop and NO combined MessageDelta:
    /// both are deferred to the `metadata` frame so the combined `MessageDelta{stop_reason, usage}`
    /// can precede the terminal `MessageStop` in IR order (Finding: delta-before-stop, so a
    /// non-eventstream ingress writes `message_delta` then `message_stop` — the native order). The
    /// stop_reason from `messageStop` is buffered but, absent the `metadata` it pairs with, is
    /// dropped on truncation — exactly as token usage was already dropped on a metadata-less stream.
    /// Native ConverseStream always sends `metadata` after `messageStop`; a genuine mid-stream
    /// truncation also drops the downstream HTTP connection, so the client already sees a broken
    /// stream rather than a clean terminator. Modeled mid-stream errors take the separate
    /// `*Exception` → `IrStreamEvent::Error` path, which is unaffected.
    #[test]
    fn test_stream_metadata_less_defers_terminator() {
        use crate::ir::IrStreamEvent;

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events: Vec<_> = vec![
            serde_json::json!({"type": "messageStart", "role": "assistant"}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"text": "Hi"}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
            serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
            // NOTE: no `metadata` event — the upstream truncated here.
        ]
        .into_iter()
        .flat_map(|data| reader.read_response_events("", &data, &mut state))
        .collect();

        // `messageStop` only BUFFERS the stop_reason now; without the trailing `metadata` neither the
        // combined MessageDelta nor the terminal MessageStop is emitted.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::MessageStop)),
            "no terminal MessageStop is emitted on a metadata-less stream (deferred to metadata); got: {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
            "no combined MessageDelta is emitted without metadata; got: {events:?}"
        );
        // The buffered stop_reason is retained in decode state (it would pair with `metadata`).
        assert_eq!(
            state.pending_stop_reason,
            Some(crate::ir::IrStopReason::EndTurn)
        );
    }

    /// Exactly one terminal MessageStop is emitted across the full happy-path sequence
    /// (messageStop + metadata) — no duplicate terminator.
    #[test]
    fn test_stream_emits_single_message_stop_with_metadata() {
        use crate::ir::IrStreamEvent;

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events: Vec<_> = vec![
            serde_json::json!({"type": "messageStart", "role": "assistant"}),
            serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
            serde_json::json!({"type": "metadata", "usage": {"inputTokens": 3, "outputTokens": 1}}),
        ]
        .into_iter()
        .flat_map(|data| reader.read_response_events("", &data, &mut state))
        .collect();

        let stop_count = events
            .iter()
            .filter(|e| matches!(e, IrStreamEvent::MessageStop))
            .count();
        assert_eq!(
            stop_count, 1,
            "exactly one terminal MessageStop expected; got: {events:?}"
        );
    }

    // --- 1.0 ingress: native error envelope + response-identity fidelity ----------------------

    /// The native Bedrock Converse error envelope is a flat `{"__type", "message"}` body (the exact
    /// shape `extract_error` reads back) — NOT the generic `{"error":{...}}` default. A generic kind
    /// maps to a real AWS exception name in `__type`, and the human text lands in lowercase
    /// `message`. There must be no top-level `error` object (that would be a non-native tell).
    #[test]
    fn test_write_error_native_bedrock_shape() {
        let writer = BedrockWriter;
        let v = writer.write_error(400, "invalid_request_error", "bad input");
        assert_eq!(
            v.get("message").and_then(|m| m.as_str()),
            Some("bad input"),
            "human text must be in lowercase `message`"
        );
        assert_eq!(
            v.get("__type").and_then(|t| t.as_str()),
            Some("ValidationException"),
            "generic kind must map to a native Converse exception name in `__type`"
        );
        assert!(
            v.get("error").is_none(),
            "must NOT carry the generic `{{\"error\":...}}` envelope (non-native tell)"
        );
        // Serializes cleanly (served as application/json).
        let s = serde_json::to_string(&v).expect("error envelope must serialize");
        assert!(s.contains("\"__type\""));
    }

    /// Kind → Bedrock exception-name mapping covers the common categories and falls back to a real
    /// exception name (never an invented one) for anything unmapped.
    #[test]
    fn test_error_kind_to_bedrock_type_mapping() {
        assert_eq!(
            error_kind_to_bedrock_type("rate_limit_error"),
            "ThrottlingException"
        );
        assert_eq!(error_kind_to_bedrock_type("auth"), "AccessDeniedException");
        assert_eq!(
            error_kind_to_bedrock_type("not_found"),
            "ResourceNotFoundException"
        );
        assert_eq!(
            error_kind_to_bedrock_type(ERR_TYPE_OVERLOADED),
            "ServiceUnavailableException"
        );
        // Regression (R9 HIGH): the forward layer emits the BARE kind `"overloaded"` for every
        // operational 503 path (lane exhaustion, deadline exceeded, no usable lane). It must map to
        // ServiceUnavailableException — NOT fall through to the ValidationException catch-all, which
        // would pair an HTTP 503 with a 400-class `__type` AWS never produces, making an AWS SDK
        // raise a non-retryable client fault instead of a retryable ServiceUnavailableException.
        assert_eq!(
            error_kind_to_bedrock_type(crate::proxy::KIND_OVERLOADED),
            "ServiceUnavailableException"
        );
        assert_eq!(
            error_kind_to_bedrock_type("api_error"),
            "InternalServerException"
        );
        // Unmapped → still a real AWS exception name, not a catch-all literal.
        assert_eq!(
            error_kind_to_bedrock_type("some_future_kind"),
            "ValidationException"
        );
    }

    /// The native error envelope round-trips back through `extract_error`: a Bedrock SDK (and the
    /// breaker's own reader) recovers both the structured type from `__type` and the text from
    /// `message`. This is the indistinguishability check that ties the writer to the reader.
    #[test]
    fn test_write_error_roundtrips_through_extract_error() {
        let writer = BedrockWriter;
        let reader = BedrockReader;
        let v = writer.write_error(429, "rate_limit_error", "Rate exceeded");
        let body = serde_json::to_vec(&v).expect("serialize");
        let raw = reader.extract_error(StatusCode::TOO_MANY_REQUESTS, &body);
        assert_eq!(raw.provider_code.as_deref(), Some("Rate exceeded"));
        assert_eq!(raw.structured_type.as_deref(), Some("ThrottlingException"));
    }

    /// Same-protocol passthrough fidelity: reading a native Converse response and writing it back
    /// preserves stopReason + usage exactly, and the written body carries NO synthesized identity
    /// (`id`/`created`) — the native Converse body has none, so injecting one would be a tell.
    #[test]
    fn test_response_identity_same_protocol_roundtrip_no_synth() {
        let reader = BedrockReader;
        let writer = BedrockWriter;

        let j = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "Hello, world!"}]
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}
        });

        let resp = reader.read_response(&j).expect("read_response");
        // Capture: Bedrock's minimal body yields no body-level identity.
        assert_eq!(resp.id, None, "Converse body has no id to capture");
        assert_eq!(
            resp.created, None,
            "Converse body has no created to capture"
        );
        assert_eq!(resp.system_fingerprint, None);
        assert_eq!(resp.stop_sequence, None);
        // stopReason + usage are present (the identity-bearing fields Bedrock does emit).
        assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::EndTurn));
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 5);

        let written = writer.write_response(&resp);
        assert_eq!(
            written, j,
            "same-protocol round-trip must be byte-identical"
        );
        // No proxy-tell identity fields injected into the native body.
        assert!(written.get("id").is_none(), "native body must carry no id");
        assert!(
            written.get("created").is_none(),
            "native body must carry no created"
        );
    }

    /// Cross-protocol synthesis: minting a Bedrock-flavored response id never panics and yields a
    /// unique, non-empty token (so an OpenAI/Anthropic ingress fed by a Bedrock egress can always
    /// get a valid body id). Uniqueness comes from the monotonic counter even within one second.
    #[test]
    fn test_synth_response_id_unique_and_nonempty() {
        let a = synth_response_id();
        let b = synth_response_id();
        assert!(!a.is_empty(), "synthesized id must be non-empty");
        assert!(!b.is_empty(), "synthesized id must be non-empty");
        assert_ne!(a, b, "two synthesized ids minted back-to-back must differ");
        // Shape sanity: `<hex16>-<hex16>` (no panic on parse of either half).
        let (lhs, rhs) = a.split_once('-').expect("synth id has a `-` separator");
        assert_eq!(lhs.len(), 16, "left half is 16 hex chars");
        assert_eq!(rhs.len(), 16, "right half is 16 hex chars");
        assert!(u64::from_str_radix(lhs, 16).is_ok());
        assert!(u64::from_str_radix(rhs, 16).is_ok());
    }

    // --- Round 2 regression tests --------------------------------------------------------------

    /// Regression (writer): a stream MessageDelta with `stop_reason = None` (the usage-only trailing
    /// delta the reader emits from the Bedrock `metadata` event, or a cross-protocol egress's usage
    /// frame) must be reframed as a native `metadata` frame carrying the real token usage — NOT a
    /// second `messageStop` (the old behavior, which both discarded usage and produced two
    /// `messageStop` frames, a distinguishable tell). A delta WITH a stop_reason still maps to
    /// `messageStop`.
    #[test]
    fn test_write_response_event_usage_delta_is_metadata_frame() {
        let writer = BedrockWriter;

        // Usage-only delta → `metadata` frame with the real usage (and a derived totalTokens).
        let usage_only = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 11,
                output_tokens: 7,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (et, payload) = writer
            .write_response_event(&usage_only)
            .expect("usage-only delta must emit a frame");
        assert_eq!(
            et, "metadata",
            "usage-only delta must be a `metadata` frame, not messageStop"
        );
        assert_eq!(
            payload
                .pointer("/usage/inputTokens")
                .and_then(|v| v.as_u64()),
            Some(11)
        );
        assert_eq!(
            payload
                .pointer("/usage/outputTokens")
                .and_then(|v| v.as_u64()),
            Some(7)
        );
        assert_eq!(
            payload
                .pointer("/usage/totalTokens")
                .and_then(|v| v.as_u64()),
            Some(18),
            "totalTokens must be inputTokens + outputTokens"
        );

        // Stop-reason delta still maps to `messageStop` (the stop discriminant).
        let stop = IrStreamEvent::MessageDelta {
            stop_reason: Some(crate::ir::IrStopReason::ToolUse),
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (et2, payload2) = writer
            .write_response_event(&stop)
            .expect("stop delta must emit a frame");
        assert_eq!(et2, "messageStop");
        assert_eq!(
            payload2.get("stopReason").and_then(|s| s.as_str()),
            Some("tool_use")
        );
    }

    /// Regression (writer): a text BlockStart must emit a native `contentBlockStart` frame with an
    /// empty `start` struct (AWS emits one for every block, text included) so a native SDK can
    /// initialize its block decoder and the following deltas are not orphaned.
    #[test]
    fn test_write_response_event_text_block_start_emits_frame() {
        let writer = BedrockWriter;
        let ev = IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        };
        let (et, payload) = writer
            .write_response_event(&ev)
            .expect("text BlockStart must emit a contentBlockStart frame");
        assert_eq!(et, "contentBlockStart");
        assert_eq!(
            payload.get("contentBlockIndex").and_then(|i| i.as_u64()),
            Some(0)
        );
        assert!(
            payload
                .get("start")
                .and_then(|s| s.as_object())
                .map(|o| o.is_empty())
                .unwrap_or(false),
            "text block start must carry an empty `start` struct; got {payload}"
        );
    }

    /// Regression (reader): a mid-stream Bedrock exception event (`internalServerException` etc.)
    /// must surface as an `IrStreamEvent::Error` rather than being silently swallowed by a catch-all,
    /// so a client whose stream hits an upstream model error receives a protocol-shaped error frame
    /// instead of a hanging / EOF-without-terminator stream.
    #[test]
    fn test_stream_decode_surfaces_midstream_exception() {
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "internalServerException",
                "message": "the model is on fire"
            }),
            &mut state,
        );
        assert_eq!(
            events.len(),
            1,
            "exactly one Error event expected; got {events:?}"
        );
        match &events[0] {
            IrStreamEvent::Error(err) => {
                assert_eq!(err.class, StatusClass::ServerError);
                assert_eq!(err.provider_signal.as_deref(), Some("the model is on fire"));
            }
            other => panic!("expected IrStreamEvent::Error, got {other:?}"),
        }

        // A throttling exception maps to the RateLimit class and falls back to the exception name
        // when no `message` is present.
        let throttle = reader.read_response_events(
            "",
            &serde_json::json!({"type": "throttlingException"}),
            &mut state,
        );
        match throttle.as_slice() {
            [IrStreamEvent::Error(err)] => {
                assert_eq!(err.class, StatusClass::RateLimit);
                assert_eq!(err.provider_signal.as_deref(), Some("throttlingException"));
            }
            other => panic!("expected a single RateLimit Error; got {other:?}"),
        }

        // An unrecognized (future / non-error) event type is still a silent no-op.
        let unknown = reader.read_response_events(
            "",
            &serde_json::json!({"type": "someFutureEvent"}),
            &mut state,
        );
        assert!(
            unknown.is_empty(),
            "unknown event types must be skipped; got {unknown:?}"
        );

        // Regression (R9 MEDIUM): `modelTimeoutException` is a REQUEST-level Converse exception, NOT
        // a member of the `ConverseStream.responseStream` output union (which has exactly five
        // members), so a real AWS endpoint never emits it mid-stream. It must be treated as an
        // unrecognized event (silent no-op) — NOT accepted as a stream exception and re-emitted as
        // `ModelStreamErrorException`, which would mutate the exception type across a same-protocol
        // boundary.
        let model_timeout = reader.read_response_events(
            "",
            &serde_json::json!({"type": "modelTimeoutException", "message": "slow"}),
            &mut state,
        );
        assert!(
            model_timeout.is_empty(),
            "modelTimeoutException is not a ConverseStream output-union member; must be skipped, \
             got {model_timeout:?}"
        );
    }

    /// Regression (R9 HIGH): `bedrock_image_block` must never emit `format: ""`. An exact `"image/"`
    /// media_type (empty subtype) once slipped past the `strip_prefix(...).unwrap_or("png")` fallback
    /// — `strip_prefix` returns `Some("")`, not `None` — producing a `format: ""` block outside
    /// Bedrock's `ImageFormat` union that the SDK rejects with a ValidationException. It must fall
    /// back to `png`, like a missing/unprefixed media_type.
    #[test]
    fn test_bedrock_image_block_empty_subtype_falls_back_to_png() {
        // Exact `"image/"` prefix with an empty subtype.
        let block = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
            media_type: "image/".to_string(),
            data: ("QQ==").to_string(),
        })
        .expect("base64 image must emit a block");
        assert_eq!(
            block.pointer("/format").and_then(|f| f.as_str()),
            Some("png"),
            "empty subtype must fall back to png, never an empty `format`; got {block}"
        );
        assert_eq!(
            block.pointer("/source/bytes").and_then(|b| b.as_str()),
            Some("QQ==")
        );

        // A real subtype is preserved verbatim.
        let jpeg = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
            media_type: "image/jpeg".to_string(),
            data: ("QQ==").to_string(),
        })
        .expect("jpeg must emit a block");
        assert_eq!(
            jpeg.pointer("/format").and_then(|f| f.as_str()),
            Some("jpeg")
        );

        // A media_type with no `image/` prefix also falls back to png (unchanged behavior).
        let bare = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
            media_type: "png".to_string(),
            data: ("QQ==").to_string(),
        })
        .expect("bare png must emit a block");
        assert_eq!(
            bare.pointer("/format").and_then(|f| f.as_str()),
            Some("png")
        );

        // The URL sentinel is still dropped (no corrupt block).
        assert!(
            bedrock_image_block(&crate::ir::IrImageSource::Url(
                ("https://example.com/x.png").to_string()
            ))
            .is_none(),
            "URL-source image must be dropped, not emitted as a base64 block"
        );
    }

    /// Regression (reader): the injected `stream` flag on a Bedrock-INGRESS converse-stream request
    /// must be read into the IR so a cross-protocol egress writer produces a streaming body. A body
    /// without the flag (native Bedrock egress, where streaming is endpoint-selected) defaults false.
    #[test]
    fn test_read_request_honors_injected_stream_flag() {
        let reader = BedrockReader;

        let streaming = serde_json::json!({
            "stream": true,
            "messages": [{"role": "user", "content": [{"text": "hi"}]}]
        });
        let ir = reader.read_request(&streaming).expect("read_request");
        assert!(
            ir.stream,
            "injected `stream: true` must be read into the IR"
        );

        let buffered = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}]
        });
        let ir2 = reader.read_request(&buffered).expect("read_request");
        assert!(
            !ir2.stream,
            "absent `stream` defaults to false (native egress)"
        );
    }

    /// Regression (writer): a System-role message that escapes the caller's system extraction is
    /// SKIPPED, not silently emitted as a `user` turn (which would inject system text as a user
    /// message). A Tool-role message is still emitted as a `user` turn (the native shape for a
    /// `toolResult` block).
    #[test]
    fn test_write_request_skips_system_role_message() {
        let writer = BedrockWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::System,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "leaked system text".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "t1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "ok".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                        cache_control: None,
                    }],
                },
            ],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };

        let json = writer.write_request(&req);
        let msgs = json
            .get("messages")
            .and_then(|m| m.as_array())
            .expect("messages array");
        assert_eq!(
            msgs.len(),
            1,
            "the System-role message must be dropped; got {msgs:?}"
        );
        assert_eq!(
            msgs[0].get("role").and_then(|r| r.as_str()),
            Some("user"),
            "the surviving Tool-role message maps to a user turn"
        );
        // The leaked system text must not appear anywhere on the wire.
        let wire = serde_json::to_string(&json).unwrap();
        assert!(
            !wire.contains("leaked system text"),
            "system text must not leak onto the wire; got {wire}"
        );
    }

    /// Regression (writer): a non-Text block inside a ToolResult must be re-encoded faithfully
    /// (Image → Bedrock `{"image":...}`, ToolUse/ToolResult → `{"json":...}`), never collapsed to
    /// the constant string `"{}"` placeholder the old catch-all produced.
    #[test]
    fn test_write_request_tool_result_preserves_non_text_content() {
        let writer = BedrockWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: vec![crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Base64 {
                            media_type: "image/png".to_string(),
                            data: "BASE64DATA".to_string(),
                        },
                        cache_control: None,
                    }],
                    is_error: false,
                    cache_control: None,
                }],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };

        let json = writer.write_request(&req);
        let inner = json
            .pointer("/messages/0/content/0/toolResult/content/0")
            .expect("tool result inner content block");
        assert_eq!(
            inner.pointer("/image/format").and_then(|v| v.as_str()),
            Some("png"),
            "image inner block must be a native Bedrock image block; got {inner}"
        );
        assert_eq!(
            inner
                .pointer("/image/source/bytes")
                .and_then(|v| v.as_str()),
            Some("BASE64DATA")
        );
        // The old `"{}"` placeholder must be gone.
        let wire = serde_json::to_string(&json).unwrap();
        assert!(
            !wire.contains(r#"{"text":"{}"}"#),
            "must not emit the `{{}}` placeholder; got {wire}"
        );
    }

    /// Regression (writer): a stream Error event names a REAL Converse exception (mapped from the IR
    /// error class) as its event-type token instead of the non-native literal `"error"`. (The
    /// `:message-type: exception` framing itself is the encoder's job — see the production
    /// mid-stream-error path in forward.rs — and is out of this unit's scope.)
    #[test]
    fn test_write_response_event_error_names_real_exception() {
        let writer = BedrockWriter;

        let throttle = IrStreamEvent::Error(crate::proto::IrError {
            class: StatusClass::RateLimit,
            provider_signal: Some("slow down".to_string()),
            retry_after: None,
        });
        let (et, payload) = writer
            .write_response_event(&throttle)
            .expect("error event must emit a frame");
        assert_eq!(
            et, "ThrottlingException",
            "event-type token must be a real Converse exception name, not `error`"
        );
        assert_eq!(
            payload.get("message").and_then(|m| m.as_str()),
            Some("slow down")
        );

        // A server-class error maps to InternalServerException and falls back to the exception name
        // when no provider_signal is present.
        let server = IrStreamEvent::Error(crate::proto::IrError {
            class: StatusClass::ServerError,
            provider_signal: None,
            retry_after: None,
        });
        let (et2, payload2) = writer
            .write_response_event(&server)
            .expect("error event must emit a frame");
        assert_eq!(et2, "InternalServerException");
        assert_eq!(
            payload2.get("message").and_then(|m| m.as_str()),
            Some("InternalServerException")
        );
    }

    // --- Round 3 regression tests --------------------------------------------------------------

    /// Regression (reader): unmodeled top-level request fields must be collected into `extra` so a
    /// same-protocol Bedrock->Bedrock passthrough re-emits them faithfully (via `write_request`'s
    /// extra-merge). Previously `extra` was built empty and every native Converse field this reader
    /// does not explicitly model — `topP`, `topK`, `stopSequences`, `guardrailConfig`,
    /// `additionalModelRequestFields`, etc. — was silently dropped, disabling guardrails / resetting
    /// sampling on passthrough. The fully-modeled keys (system/messages/toolConfig/stream) must NOT
    /// leak into `extra` (they are re-serialised from the structured IR; a double-emit / echoed
    /// `stream` would be a tell). `inferenceConfig` is the exception: it is only PARTIALLY modeled
    /// (just `maxTokens`/`temperature`), so the WHOLE raw object is now captured into `extra` to
    /// preserve its unmodeled sub-fields (`stopSequences`/`topP`/`topK`/...) — see the finding-2 fix.
    #[test]
    fn test_read_request_collects_unmodeled_fields_into_extra() {
        let reader = BedrockReader;
        let j = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 10},
            "system": [{"text": "sys"}],
            "toolConfig": {"tools": []},
            "stream": true,
            "topP": 0.95,
            "topK": 40,
            "stopSequences": ["STOP"],
            "guardrailConfig": {"guardrailIdentifier": "gr-1", "guardrailVersion": "1"},
            "additionalModelRequestFields": {"foo": "bar"}
        });
        let ir = reader.read_request(&j).expect("read_request");

        // Unmodeled fields are preserved verbatim.
        assert_eq!(ir.extra.get("topP"), Some(&serde_json::json!(0.95)));
        assert_eq!(ir.extra.get("topK"), Some(&serde_json::json!(40)));
        assert_eq!(
            ir.extra.get("stopSequences"),
            Some(&serde_json::json!(["STOP"]))
        );
        assert_eq!(
            ir.extra.get("guardrailConfig"),
            Some(&serde_json::json!({"guardrailIdentifier": "gr-1", "guardrailVersion": "1"}))
        );
        assert_eq!(
            ir.extra.get("additionalModelRequestFields"),
            Some(&serde_json::json!({"foo": "bar"}))
        );

        // `inferenceConfig` IS now captured verbatim into `extra` (it is only partially modeled, so
        // its raw object preserves unmodeled sub-fields for passthrough; finding-2 fix).
        assert_eq!(
            ir.extra.get("inferenceConfig"),
            Some(&serde_json::json!({"maxTokens": 10})),
            "inferenceConfig must be captured into extra verbatim"
        );

        // `toolConfig` IS now captured verbatim into `extra` (it is only partially modeled — only
        // `tools` is typed into `ir.tools`; `toolChoice` and future sub-fields are unmodeled — so the
        // raw object preserves them for passthrough; R15 toolChoice fix).
        assert_eq!(
            ir.extra.get("toolConfig"),
            Some(&serde_json::json!({"tools": []})),
            "toolConfig must be captured into extra verbatim"
        );

        // Fully-modeled keys must NOT be duplicated into `extra` (avoids double-emit / echoed
        // `stream`). `inferenceConfig` and `toolConfig` are intentionally absent from this list now
        // (they are only partially modeled; see above).
        for k in ["system", "messages", "stream"] {
            assert!(
                ir.extra.get(k).is_none(),
                "modeled key `{k}` must not leak into extra; got {:?}",
                ir.extra
            );
        }
        // `stream` is still captured in the structured field.
        assert!(
            ir.stream,
            "injected stream flag still captured structurally"
        );
    }

    /// Regression (reader + writer): a full passthrough — read a native Converse request carrying
    /// unmodeled fields, then write it back — must re-emit `topP`/`stopSequences`/`guardrailConfig`
    /// onto the wire, never strip them. Uses the existing rich fixture (which carries `top_p`).
    #[test]
    fn test_request_passthrough_preserves_unmodeled_fields() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let j = bedrock_rich_fixture(); // carries a top-level `top_p`
        let ir = reader.read_request(&j).expect("read_request");
        let out = writer.write_request(&ir);
        assert_eq!(
            out.get("top_p").and_then(|v| v.as_f64()),
            Some(0.95),
            "unmodeled `top_p` must survive a Bedrock->Bedrock passthrough; got {out}"
        );
    }

    /// Regression (R15 toolChoice): `toolConfig.toolChoice` (the force-tool-use control:
    /// `{auto:{}}` / `{any:{}}` / `{tool:{name:...}}`) is an UNMODELED sub-field of `toolConfig` —
    /// only `toolConfig.tools` is typed into `ir.tools`. The old code listed `toolConfig` in
    /// `MODELED_KEYS`, so the raw object never reached `extra` and the writer rebuilt `toolConfig`
    /// from `ir.tools` ALONE, silently dropping `toolChoice` on a Bedrock->Bedrock passthrough
    /// whenever the body was rebuilt. A native AWS client that sent `toolChoice: {any: {}}` to force a
    /// tool call would have that constraint stripped, changing model behaviour. The reader now
    /// captures the whole raw `toolConfig` into `extra` and the writer overlays the typed `tools`
    /// array onto it, preserving `toolChoice`.
    #[test]
    fn test_request_passthrough_preserves_tool_choice() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let j = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "weather?"}]}],
            "toolConfig": {
                "tools": [{
                    "toolSpec": {
                        "name": "get_weather",
                        "inputSchema": {"json": {"type": "object"}}
                    }
                }],
                "toolChoice": {"any": {}}
            }
        });
        let ir = reader.read_request(&j).expect("read_request");

        // The tools array is parsed into the structured IR (for cross-protocol egress)...
        assert_eq!(ir.tools.len(), 1);
        assert_eq!(ir.tools[0].name, "get_weather");
        // ...and the whole raw toolConfig (incl. toolChoice) is preserved in `extra` for passthrough.
        assert_eq!(
            ir.extra
                .get("toolConfig")
                .and_then(|tc| tc.get("toolChoice")),
            Some(&serde_json::json!({"any": {}})),
            "raw toolChoice must be captured into extra; got {:?}",
            ir.extra
        );

        let out = writer.write_request(&ir);
        let tc = out
            .get("toolConfig")
            .and_then(|v| v.as_object())
            .expect("toolConfig must be re-emitted");
        // toolChoice survives the round-trip...
        assert_eq!(
            tc.get("toolChoice"),
            Some(&serde_json::json!({"any": {}})),
            "toolChoice must survive a Bedrock->Bedrock passthrough; got {out}"
        );
        // ...and the typed tools array is re-emitted (one toolSpec).
        assert_eq!(
            tc.get("tools").and_then(|t| t.as_array()).map(|a| a.len()),
            Some(1),
            "rebuilt tools array must be present; got {out}"
        );
    }

    /// Regression (R15 toolChoice): on the CROSS-protocol seam `extra` is cleared, so a writer driven
    /// by an IR with `ir.tools` but no `extra.toolConfig` must still emit a valid `toolConfig` built
    /// purely from the typed tools (no `toolChoice`, since the IR has no field for it). And a degenerate
    /// IR with neither typed tools nor a raw `toolConfig` must NOT emit a bare/empty `toolConfig` (AWS
    /// rejects a `toolConfig` with no `tools`).
    #[test]
    fn test_write_request_tool_config_cross_protocol_and_empty() {
        let writer = BedrockWriter;

        // Cross-protocol shape: typed tools, empty extra (seam cleared it).
        let ir_tools = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![],
            tools: vec![crate::ir::IrTool {
                name: "f".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                cache_control: None,
            }],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = writer.write_request(&ir_tools);
        let tc = out
            .get("toolConfig")
            .and_then(|v| v.as_object())
            .expect("toolConfig must be emitted from typed tools alone");
        assert_eq!(
            tc.get("tools").and_then(|t| t.as_array()).map(|a| a.len()),
            Some(1)
        );
        assert!(
            tc.get("toolChoice").is_none(),
            "no toolChoice should appear cross-protocol (IR has no field for it); got {out}"
        );

        // No tools, no raw toolConfig → no toolConfig key at all.
        let ir_empty = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out_empty = writer.write_request(&ir_empty);
        assert!(
            out_empty.get("toolConfig").is_none(),
            "no toolConfig must be emitted when there are no tools; got {out_empty}"
        );
    }

    /// Regression (reader): a text block that opens at index > 0 (after a preceding tool-use block,
    /// reachable via cross-protocol ingress) must have its `text_block_open` flag cleared on its
    /// contentBlockStop, so a LATER text block still emits a fresh BlockStart. The old `idx == 0`
    /// guard left the flag set for a text block at index N>0, suppressing all subsequent text
    /// BlockStarts and silently dropping the rest of the text content.
    #[test]
    fn test_stream_text_block_after_tool_not_dropped() {
        use crate::ir::IrStreamEvent;
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events: Vec<_> = vec![
            serde_json::json!({"type": "messageStart", "role": "assistant"}),
            // tool-use block at index 0
            serde_json::json!({
                "type": "contentBlockStart",
                "contentBlockIndex": 0,
                "start": {"toolUse": {"toolUseId": "t1", "name": "f"}}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
            // text block at index 1 (start has no `start` object → text)
            serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 1}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 1,
                "delta": {"text": "first"}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 1}),
            // a SECOND text block at index 2 — must still open (flag was cleared at idx 1 stop)
            serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 2}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 2,
                "delta": {"text": "second"}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 2}),
        ]
        .into_iter()
        .flat_map(|d| reader.read_response_events("", &d, &mut state))
        .collect();

        // Two text BlockStarts must appear (at index 1 and index 2).
        let text_starts: Vec<usize> = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockStart {
                    index,
                    block: crate::ir::IrBlockMeta::Text,
                } => Some(*index),
                _ => None,
            })
            .collect();
        assert_eq!(
            text_starts,
            vec![1, 2],
            "both text blocks (idx 1 and idx 2) must emit a BlockStart; got {events:?}"
        );
        // Both text deltas survive.
        let deltas: Vec<String> = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockDelta {
                    delta: crate::ir::IrDelta::TextDelta(t),
                    ..
                } => Some(t.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(deltas, vec!["first".to_string(), "second".to_string()]);
    }

    /// Regression (reader): a `contentBlockStart` whose `start` object carries an UNRECOGNIZED key
    /// (not `toolUse`, and not the empty `{}` text shape — e.g. a future `image`/`reasoningContent`
    /// block) must NOT be mis-opened as a Text block. Only an empty `start: {}` (or an absent
    /// `start`) opens text. Forward-compatibility / defensive parsing.
    #[test]
    fn test_stream_unrecognized_start_does_not_open_text() {
        use crate::ir::IrStreamEvent;
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let _ = reader.read_response_events(
            "",
            &serde_json::json!({"type": "messageStart", "role": "assistant"}),
            &mut state,
        );
        // A `start` with an unrecognized key — must emit nothing (no spurious Text BlockStart).
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "contentBlockStart",
                "contentBlockIndex": 0,
                "start": {"reasoningContent": {"foo": "bar"}}
            }),
            &mut state,
        );
        assert!(
            !evs.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    block: crate::ir::IrBlockMeta::Text,
                    ..
                }
            )),
            "an unrecognized `start` key must not open a Text block; got {evs:?}"
        );
        assert!(
            !state.text_block_open,
            "text_block_open must remain false for an unrecognized start shape"
        );

        // The empty `start: {}` text shape still opens a Text block (sanity).
        let evs2 = reader.read_response_events(
            "",
            &serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 0, "start": {}}),
            &mut state,
        );
        assert!(
            evs2.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    block: crate::ir::IrBlockMeta::Text,
                    ..
                }
            )),
            "an empty `start: {{}}` must still open a Text block; got {evs2:?}"
        );
    }

    /// Regression (writer): a session (STS) token containing a byte `HeaderValue` rejects (control
    /// char / >= 0x80) must NOT produce a request signed over `x-amz-security-token` with the header
    /// absent (which AWS rejects with SignatureDoesNotMatch). The signed set and the wire set are
    /// gated by the same up-front validation, so an un-encodable token bails to the graceful
    /// empty-header path (unsigned request → AWS 403 as auth) — no panic, no divergence.
    #[test]
    fn test_bedrock_sigv4_unencodable_session_token_bails_gracefully() {
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
            upstream_creds: crate::auth::UpstreamCreds::Own,
        };
        // Session token with an embedded control char → un-encodable HeaderValue.
        let headers = writer.sign_request("AKID:SECRET:TOK\r\nEN", &ctx);
        assert!(
            headers.is_empty(),
            "un-encodable session token must yield no headers (graceful), not a signed-but-absent \
             token header; got {headers:?}"
        );
        // A bare control byte (e.g. NUL / U+0001) likewise bails — `HeaderValue::from_str` rejects
        // ASCII control characters, the same vector as the misconfigured access-key path.
        let headers2 = writer.sign_request("AKID:SECRET:TOK\u{0001}EN", &ctx);
        assert!(
            headers2.is_empty(),
            "control-byte token must bail; got {headers2:?}"
        );

        // Sanity: a clean token still signs AND emits the token header, and the signed set commits
        // to it (so the two never diverge in the success case either).
        let ok = writer.sign_request("AKID:SECRET:CLEANTOKEN", &ctx);
        let auth = ok
            .iter()
            .find(|(k, _)| k.as_str() == "authorization")
            .map(|(_, v)| v.to_str().unwrap().to_string())
            .expect("authorization header");
        assert!(
            auth.contains("x-amz-security-token"), // golden wire-contract literal (kept bare on purpose)
            "clean token must be in the signed header set"
        );
        assert!(
            ok.iter().any(
                |(k, v)| k.as_str() == "x-amz-security-token" // golden wire-contract literal (kept bare on purpose)
                && v.to_str().unwrap() == "CLEANTOKEN"
            ),
            "clean token must be emitted on the wire; got {ok:?}"
        );
    }

    /// Regression (writer): a usage-only delta's `metadata` frame carries the real `usage` but does
    /// NOT fabricate a `metrics` object at the writer layer. The native ConverseStream `metrics`
    /// object reports the stream's REAL `latencyMs`, which the writer cannot know — so it is injected
    /// (with the elapsed wall-clock) by `StreamTranslate::emit_ir_event` on the Bedrock-ingress path,
    /// or OMITTED when timing is unavailable. Emitting a hard-coded `latencyMs: 0` here (the old
    /// behavior) was itself a detectable tell (a real stream never reports exactly 0). The live
    /// latency injection is covered by the StreamTranslate test in proto/mod.rs.
    #[test]
    fn test_write_response_event_metadata_no_fabricated_metrics() {
        let writer = BedrockWriter;
        let usage_only = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 3,
                output_tokens: 2,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (et, payload) = writer
            .write_response_event(&usage_only)
            .expect("usage-only delta emits a metadata frame");
        assert_eq!(et, "metadata");
        assert!(
            payload.pointer("/metrics").is_none(),
            "writer must NOT fabricate a `metrics` object (latency is injected by StreamTranslate \
             or omitted); got {payload}"
        );
        // usage is still present and correct.
        assert_eq!(
            payload
                .pointer("/usage/totalTokens")
                .and_then(|v| v.as_u64()),
            Some(5)
        );
    }

    /// Regression (writer, streaming `metadata` frame): `totalTokens` is computed with a saturating
    /// add, so a pathological/hostile upstream sending token counts near `u64::MAX` clamps to
    /// `u64::MAX` instead of panicking under overflow-checks (debug / opt-in release) or silently
    /// wrapping to a near-zero nonsense total in plain release. Mirrors the Gemini writer's
    /// `test_stream_message_delta_total_token_count_saturates`.
    #[test]
    fn test_write_response_event_total_tokens_saturates() {
        let writer = BedrockWriter;
        let ev = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: u64::MAX,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (et, payload) = writer
            .write_response_event(&ev)
            .expect("usage-only delta emits a metadata frame");
        assert_eq!(et, "metadata");
        // No panic on the request path, and the total clamps at u64::MAX rather than wrapping to 0.
        assert_eq!(
            payload
                .pointer("/usage/totalTokens")
                .and_then(|v| v.as_u64()),
            Some(u64::MAX),
            "totalTokens must saturate, not wrap; got {payload}"
        );
        // Component counts are passed through untouched.
        assert_eq!(
            payload
                .pointer("/usage/inputTokens")
                .and_then(|v| v.as_u64()),
            Some(u64::MAX)
        );
        assert_eq!(
            payload
                .pointer("/usage/outputTokens")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    /// REGRESSION (audit c2r2): `bedrock_response_to_eventstream` (buffered 2xx → synthesized
    /// ConverseStream, used when a Bedrock-streaming client gets a non-streaming cross-protocol 2xx)
    /// must NOT drop a `Thinking` (reasoningContent) block. The old arm skipped it, silently losing
    /// upstream reasoning; it now synthesizes the `reasoningContent` start/delta/stop frames.
    #[test]
    fn eventstream_emits_reasoning_content_for_thinking_block() {
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::Thinking {
                    text: "let me think".to_string(),
                    signature: Some("sigblob".to_string()),
                    redacted: false,
                    cache_control: None,
                },
                crate::ir::IrBlock::Text {
                    text: "answer".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
            ],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let bytes = bedrock_response_to_eventstream(&resp, Some(5));
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains("reasoningContent"),
            "a Thinking block must synthesize a reasoningContent frame, not be dropped"
        );
        assert!(
            text.contains("let me think"),
            "the thinking text must ride a reasoningContent delta"
        );
        assert!(
            text.contains("sigblob"),
            "the reasoning signature must ride a signature delta"
        );
    }

    /// Regression (writer, non-stream `write_response` body): the buffered Converse `totalTokens`
    /// uses the same saturating add as the streaming frame, so an upstream response carrying token
    /// counts near `u64::MAX` does not panic (overflow-checks) or wrap (release).
    #[test]
    fn test_write_response_total_tokens_saturates() {
        let writer = BedrockWriter;
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: IrUsage {
                input_tokens: u64::MAX - 1,
                output_tokens: 100,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let body = writer.write_response(&resp);
        assert_eq!(
            body.pointer("/usage/totalTokens").and_then(|v| v.as_u64()),
            Some(u64::MAX),
            "totalTokens must saturate, not wrap; got {body}"
        );
        // A normal (non-overflowing) pair still sums exactly.
        let normal = crate::ir::IrResponse {
            usage: IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            ..resp
        };
        let body = writer.write_response(&normal);
        assert_eq!(
            body.pointer("/usage/totalTokens").and_then(|v| v.as_u64()),
            Some(15)
        );
    }

    /// Regression (R24 LOW#7 — writer, non-stream `write_response`): an assistant response carrying
    /// an `IrBlock::Image` must be PROJECTED as a native Bedrock `{"image": ...}` content block, not
    /// silently dropped by the old combined `ToolResult | Image => {}` no-op arm. A base64 image
    /// uses the `bytes` source and the subtype-derived `format`.
    #[test]
    fn test_write_response_projects_image_block() {
        let writer = BedrockWriter;
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "see image".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Base64 {
                        media_type: "image/png".to_string(),
                        data: "aGVsbG8=".to_string(),
                    },
                    cache_control: None,
                },
            ],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let body = writer.write_response(&resp);
        let content = body
            .pointer("/output/message/content")
            .and_then(|v| v.as_array())
            .expect("content array present");
        // Both the text block and the projected image block survive (2 entries, none dropped).
        assert_eq!(content.len(), 2, "image block must not be dropped: {body}");
        let image = content
            .iter()
            .find(|b| b.get("image").is_some())
            .expect("a native image block must be present");
        assert_eq!(
            image.pointer("/image/format").and_then(|v| v.as_str()),
            Some("png"),
            "image format derived from MIME subtype: {body}"
        );
        assert_eq!(
            image
                .pointer("/image/source/bytes")
                .and_then(|v| v.as_str()),
            Some("aGVsbG8="),
            "base64 image data carried as `bytes` source: {body}"
        );
    }

    /// Regression (R24 LOW#8 — writer, non-stream `write_response`): a response whose blocks are ALL
    /// non-representable in an assistant Converse message (here a lone `ToolResult`, which belongs to
    /// a user turn) must NOT emit an empty `content: []` array — Bedrock rejects that with a
    /// ValidationException. `write_request` already guards every turn; this mirrors that guard with a
    /// minimal placeholder text block.
    ///
    /// NOTE: a `Thinking` block is NO LONGER non-representable in a response (R25 MED #3 re-emits it
    /// as a native `reasoningContent` block), so it cannot be part of an "all non-representable" case;
    /// the lone `ToolResult` (genuinely a user-turn block) is the only remaining no-op here.
    #[test]
    fn test_write_response_empty_content_emits_placeholder() {
        let writer = BedrockWriter;
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::ToolResult {
                tool_use_id: "tu_1".to_string(),
                content: Vec::new(),
                is_error: false,
                cache_control: None,
            }],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let body = writer.write_response(&resp);
        let content = body
            .pointer("/output/message/content")
            .and_then(|v| v.as_array())
            .expect("content array present");
        assert!(
            !content.is_empty(),
            "content array must never be empty (Bedrock rejects it): {body}"
        );
        assert_eq!(
            content.len(),
            1,
            "exactly one placeholder block when all blocks are non-representable: {body}"
        );
        assert_eq!(
            content[0].get("text").and_then(|v| v.as_str()),
            Some(""),
            "placeholder is a minimal empty-text block (mirrors write_request): {body}"
        );
    }

    // --- Round 5 regression tests --------------------------------------------------------------

    /// Regression (finding 2 — reader+writer): an `inferenceConfig` carrying sub-fields this reader
    /// does NOT type (`stopSequences`, `topP`, `topK`, future AWS additions) must survive a
    /// same-protocol Bedrock->Bedrock passthrough, NOT be silently dropped. Previously
    /// `inferenceConfig` was modeled-out wholesale and only `maxTokens`/`temperature` were
    /// re-emitted, so `stopSequences` (a commonly-used generation-boundary control) and the
    /// `topP`/`topK` sampling knobs vanished — changing model behaviour vs a direct AWS call.
    #[test]
    fn test_inference_config_passthrough_preserves_unmodeled_subfields() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let wire = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {
                "maxTokens": 256,
                "temperature": 0.3,
                "topP": 0.9,
                "topK": 50,
                "stopSequences": ["\n\nHuman:", "END"]
            }
        });

        let ir = reader.read_request(&wire).expect("read_request");
        // The typed fields still flow into the structured IR (for cross-protocol egress).
        assert_eq!(ir.max_tokens, Some(256));
        assert_eq!(ir.temperature, Some(0.3));
        // The whole raw inferenceConfig is captured for passthrough fidelity.
        assert!(ir.extra.contains_key("inferenceConfig"));

        let out = writer.write_request(&ir);
        // Every sub-field — modeled AND unmodeled — must round-trip onto the wire.
        assert_eq!(
            out.pointer("/inferenceConfig/maxTokens")
                .and_then(|v| v.as_u64()),
            Some(256)
        );
        assert_eq!(
            out.pointer("/inferenceConfig/temperature")
                .and_then(|v| v.as_f64()),
            Some(0.3)
        );
        assert_eq!(
            out.pointer("/inferenceConfig/topP")
                .and_then(|v| v.as_f64()),
            Some(0.9),
            "topP must survive passthrough; got {out}"
        );
        assert_eq!(
            out.pointer("/inferenceConfig/topK")
                .and_then(|v| v.as_u64()),
            Some(50),
            "topK must survive passthrough; got {out}"
        );
        assert_eq!(
            out.pointer("/inferenceConfig/stopSequences"),
            Some(&serde_json::json!(["\n\nHuman:", "END"])),
            "stopSequences must survive passthrough; got {out}"
        );
        // The whole body round-trips byte-identically (no `inferenceConfig` double-emit).
        assert_eq!(out, wire, "full body must round-trip byte-identically");
    }

    /// PF-H1: `top_k` (a first-class IR field) must reach a Bedrock egress via
    /// `additionalModelRequestFields.top_k`. A cross-protocol request (e.g. Anthropic) carries `top_k`
    /// in the IR with an empty `extra`; the Bedrock writer must emit it instead of dropping it. And a
    /// native Bedrock request that pins `top_k` in `additionalModelRequestFields` must round-trip
    /// through the reader/writer.
    #[test]
    fn test_top_k_reaches_bedrock_via_additional_model_request_fields() {
        let writer = BedrockWriter;

        // Cross-protocol shape: top_k set in the IR, extra cleared (as the translate seam leaves it).
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: Some(64),
            temperature: None,
            top_p: None,
            top_k: Some(40),
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = writer.write_request(&ir);
        assert_eq!(
            out.pointer("/additionalModelRequestFields/top_k")
                .and_then(|v| v.as_u64()),
            Some(40),
            "top_k must be emitted under additionalModelRequestFields.top_k; got {out}"
        );

        // Native Bedrock round-trip: a request that pins top_k in additionalModelRequestFields must
        // read into the IR and re-emit faithfully (no double-emit of additionalModelRequestFields).
        let reader = BedrockReader;
        let wire = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 64},
            "additionalModelRequestFields": {"top_k": 40}
        });
        let ir2 = reader.read_request(&wire).expect("read_request");
        assert_eq!(ir2.top_k, Some(40), "reader must promote top_k into the IR");
        let out2 = writer.write_request(&ir2);
        assert_eq!(
            out2.pointer("/additionalModelRequestFields/top_k")
                .and_then(|v| v.as_u64()),
            Some(40),
            "top_k must survive the Bedrock round-trip; got {out2}"
        );
        assert_eq!(
            out2, wire,
            "native Bedrock body must round-trip byte-identically"
        );
    }

    /// Losslessness (top_k spelling preservation): a native Bedrock->Bedrock passthrough whose body
    /// spelled top_k as camelCase `topK` must round-trip byte-identically (NOT be renamed to
    /// `top_k`), while a cross-protocol egress (empty `extra`, no sentinel) still emits the canonical
    /// snake_case `top_k`.
    #[test]
    fn test_top_k_camel_spelling_round_trips_and_cross_protocol_stays_snake() {
        let reader = BedrockReader;
        let writer = BedrockWriter;

        // Same-protocol: source used camelCase `topK`. The reader lifts it into the IR AND stamps the
        // source-spelling sentinel; the writer re-emits `topK` and consumes the sentinel.
        let wire = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 64},
            "additionalModelRequestFields": {"topK": 40}
        });
        let ir = reader.read_request(&wire).expect("read_request");
        assert_eq!(ir.top_k, Some(40), "reader must promote topK into the IR");
        assert!(
            ir.extra.contains_key(TOP_K_CAMEL_SENTINEL),
            "reader must stamp the camel-spelling sentinel when source used topK"
        );
        let out = writer.write_request(&ir);
        assert_eq!(
            out.pointer("/additionalModelRequestFields/topK")
                .and_then(|v| v.as_u64()),
            Some(40),
            "topK source spelling must be preserved; got {out}"
        );
        assert!(
            out.pointer("/additionalModelRequestFields/top_k").is_none(),
            "must NOT also emit snake_case top_k; got {out}"
        );
        // The sentinel must be CONSUMED — never serialized to the wire.
        assert!(
            out.get(TOP_K_CAMEL_SENTINEL).is_none(),
            "the source-spelling sentinel must never reach the wire; got {out}"
        );
        assert_eq!(
            out, wire,
            "Bedrock->Bedrock topK body must round-trip byte-identically"
        );

        // Cross-protocol: top_k in the IR, `extra` cleared (as the translate seam leaves it) — no
        // sentinel, so the writer emits the canonical snake_case `top_k`.
        let ir_cross = crate::ir::IrRequest {
            top_k: Some(40),
            extra: serde_json::Map::new(),
            ..ir.clone()
        };
        let out_cross = writer.write_request(&ir_cross);
        assert_eq!(
            out_cross
                .pointer("/additionalModelRequestFields/top_k")
                .and_then(|v| v.as_u64()),
            Some(40),
            "cross-protocol egress (no sentinel) must emit canonical top_k; got {out_cross}"
        );
        assert!(
            out_cross
                .pointer("/additionalModelRequestFields/topK")
                .is_none(),
            "cross-protocol egress must NOT emit camelCase topK; got {out_cross}"
        );
    }

    /// PF (non-silent clamp): the Bedrock temperature clamp helper signals when it changes the value
    /// (so the writer can warn) and is a no-op (was_clamped=false) for in-range values.
    #[test]
    fn test_clamp_temperature_for_bedrock_signals_on_change() {
        // Out-of-range values are clamped AND flagged as changed.
        assert_eq!(clamp_temperature_for_bedrock(1.8), (1.0, true));
        assert_eq!(clamp_temperature_for_bedrock(2.0), (1.0, true));
        assert_eq!(clamp_temperature_for_bedrock(-0.5), (0.0, true));
        // In-range values pass through unchanged and are NOT flagged.
        assert_eq!(clamp_temperature_for_bedrock(0.7), (0.7, false));
        assert_eq!(clamp_temperature_for_bedrock(0.0), (0.0, false));
        assert_eq!(clamp_temperature_for_bedrock(1.0), (1.0, false));
    }

    /// Regression (finding 2): the typed IR fields WIN over a same-named raw `inferenceConfig` entry
    /// (the structured IR is the source of truth for the values it models), and a cross-protocol
    /// egress (no `inferenceConfig` in `extra`) still emits a config built purely from the typed IR.
    #[test]
    fn test_inference_config_typed_fields_override_raw_and_cross_protocol() {
        let writer = BedrockWriter;

        // Typed maxTokens overrides a stale raw value carried in extra.
        let mut extra = serde_json::Map::new();
        extra.insert(
            "inferenceConfig".to_string(),
            serde_json::json!({"maxTokens": 1, "topP": 0.5}),
        );
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: Some(999),
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra,
        };
        let out = writer.write_request(&ir);
        assert_eq!(
            out.pointer("/inferenceConfig/maxTokens")
                .and_then(|v| v.as_u64()),
            Some(999),
            "typed maxTokens must override the raw extra value; got {out}"
        );
        assert_eq!(
            out.pointer("/inferenceConfig/topP")
                .and_then(|v| v.as_f64()),
            Some(0.5),
            "unmodeled topP from raw config still survives"
        );

        // Cross-protocol egress: no inferenceConfig in extra → config built purely from typed IR.
        let ir2 = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: Some(42),
            temperature: Some(0.1),
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out2 = writer.write_request(&ir2);
        assert_eq!(
            out2.pointer("/inferenceConfig/maxTokens")
                .and_then(|v| v.as_u64()),
            Some(42)
        );
        assert_eq!(
            out2.pointer("/inferenceConfig/temperature")
                .and_then(|v| v.as_f64()),
            Some(0.1)
        );
        // No stray topP/stopSequences appear from nowhere.
        assert!(out2.pointer("/inferenceConfig/topP").is_none());
    }

    /// Regression (finding 3): a mid-stream `IrError` mapped for the ConverseStream output union must
    /// only ever name one of the FIVE legal stream-event exceptions. Request-level shapes
    /// (`ModelTimeoutException`, `AccessDeniedException`, `ServiceQuotaExceededException`) are NOT
    /// members of the stream union and would be treated as unknown/unmodeled by a native AWS SDK
    /// stream decoder — an indistinguishability tell. Both the exception-frame path
    /// (`write_response_exception`) and the fallback `write_response_event` Error arm use this map.
    #[test]
    fn test_stream_exception_only_emits_converse_stream_union_members() {
        let writer = BedrockWriter;
        const STREAM_UNION: [&str; 5] = [
            "InternalServerException",
            "ModelStreamErrorException",
            "ValidationException",
            "ThrottlingException",
            "ServiceUnavailableException",
        ];

        let cases = [
            (StatusClass::RateLimit, "ThrottlingException"),
            (StatusClass::Overloaded, "ServiceUnavailableException"),
            (StatusClass::ClientError, "ValidationException"),
            (StatusClass::ContextLength, "ValidationException"),
            // Timeout folds onto the stream-internal failure shape, NOT request-level
            // ModelTimeoutException (not a stream-union member).
            (StatusClass::Timeout, "ModelStreamErrorException"),
            // Auth / Billing have no stream-union counterpart → generic InternalServerException
            // (NOT AccessDeniedException / ServiceQuotaExceededException, which are request-level).
            (StatusClass::Auth, "InternalServerException"),
            (StatusClass::Billing, "InternalServerException"),
            (StatusClass::ServerError, "InternalServerException"),
            (StatusClass::Network, "InternalServerException"),
        ];

        for (class, expected) in cases {
            let err = crate::proto::IrError {
                class,
                provider_signal: Some("upstream detail".to_string()),
                retry_after: None,
            };
            // Exception-frame path.
            let (exc, msg) = writer
                .write_response_exception(&err)
                .expect("write_response_exception must map every class");
            assert_eq!(
                exc, expected,
                "class {class:?} must map to {expected} on the exception frame"
            );
            assert!(
                STREAM_UNION.contains(&exc.as_str()),
                "{exc} is not a ConverseStream output-union member"
            );
            assert_eq!(msg, "upstream detail", "message prefers provider_signal");

            // Fallback event-arm path uses the SAME stream union.
            let ev = IrStreamEvent::Error(crate::proto::IrError {
                class,
                provider_signal: None,
                retry_after: None,
            });
            let (et, payload) = writer
                .write_response_event(&ev)
                .expect("error event must emit a frame");
            assert_eq!(
                et, expected,
                "event-arm class {class:?} must also map to {expected}"
            );
            assert!(
                STREAM_UNION.contains(&et.as_str()),
                "{et} is not a ConverseStream output-union member"
            );
            // Falls back to the exception name when no provider_signal is present.
            assert_eq!(
                payload.get("message").and_then(|m| m.as_str()),
                Some(expected)
            );
        }

        // Explicitly assert the request-level-only shapes never appear on the stream path.
        for class in [
            StatusClass::Timeout,
            StatusClass::Auth,
            StatusClass::Billing,
        ] {
            let err = crate::proto::IrError {
                class,
                provider_signal: None,
                retry_after: None,
            };
            let (exc, _) = writer.write_response_exception(&err).unwrap();
            assert_ne!(exc, "ModelTimeoutException");
            assert_ne!(exc, "AccessDeniedException");
            assert_ne!(exc, "ServiceQuotaExceededException");
        }
    }

    /// Regression (class sweep — image `"image_url"` sentinel): a cross-protocol ingress
    /// (OpenAI/Responses) parses an `https://…` image into the IR as
    /// `Image{media_type: "image_url", data: <url>}`. The Bedrock Converse `image` block has no
    /// arbitrary-URL source (only base64 `bytes` / `s3Location`), so the URL must NOT be stuffed into
    /// `source.bytes` and labeled `format: "png"` (the old behavior — a corrupt block a native SDK
    /// rejects). Such a block is DROPPED (with a trace), never mangled. A genuine base64 image is
    /// still emitted natively.
    #[test]
    fn test_write_request_url_sentinel_image_not_emitted_as_base64() {
        let writer = BedrockWriter;

        // Top-level URL-sentinel image → dropped (no image block, no garbage bytes).
        let url = "https://example.com/cat.png";
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "look".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Url(url.to_string()),
                        cache_control: None,
                    },
                ],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = writer.write_request(&req);
        let wire = serde_json::to_string(&out).unwrap();
        assert!(
            !wire.contains(url),
            "URL must NOT be emitted as base64 image bytes; got {wire}"
        );
        assert!(
            !wire.contains("\"image\""),
            "no image block must be emitted for a URL sentinel; got {wire}"
        );
        // The accompanying text block still survives.
        assert_eq!(
            out.pointer("/messages/0/content/0/text")
                .and_then(|v| v.as_str()),
            Some("look")
        );

        // A genuine base64 image is still emitted natively.
        let req2 = crate::ir::IrRequest {
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Base64 {
                        media_type: "image/png".to_string(),
                        data: "QkFTRTY0".to_string(),
                    },
                    cache_control: None,
                }],
            }],
            ..req.clone()
        };
        let out2 = writer.write_request(&req2);
        assert_eq!(
            out2.pointer("/messages/0/content/0/image/format")
                .and_then(|v| v.as_str()),
            Some("png")
        );
        assert_eq!(
            out2.pointer("/messages/0/content/0/image/source/bytes")
                .and_then(|v| v.as_str()),
            Some("QkFTRTY0")
        );
    }

    /// Regression (R19 #16): a user/assistant turn whose blocks are ALL non-representable on the
    /// Bedrock wire (here a user message holding only a URL-sentinel image) must NOT be silently
    /// dropped. Dropping it loses turn structure and can break the strict user/assistant alternation
    /// Bedrock Converse enforces. The writer mirrors the Anthropic writer by emitting a minimal
    /// placeholder `{"text":""}` block so the turn (and its role) survives.
    ///
    /// NOTE: a Thinking block is NO LONGER non-representable on Bedrock (R25 MED #3 re-emits it as a
    /// native `reasoningContent` block), so the thinking-only assistant turn here now carries that
    /// reasoningContent block — NOT a placeholder. The remaining turn (a URL-sentinel image) is still
    /// non-representable and exercises the placeholder path.
    #[test]
    fn test_write_request_all_nonrepresentable_turn_kept_with_placeholder() {
        let writer = BedrockWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "hello".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                // Assistant turn carrying ONLY a thinking block (now re-emitted as reasoningContent).
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::Thinking {
                        text: "internal reasoning".to_string(),
                        signature: None,
                        redacted: false,
                        cache_control: None,
                    }],
                },
                // User turn carrying ONLY a URL-sentinel image (also non-representable here).
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Url(
                            "https://example.com/cat.png".to_string(),
                        ),
                        cache_control: None,
                    }],
                },
            ],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = writer.write_request(&req);

        // All three turns survive (old code dropped turns 1 and 2, yielding length 1).
        let msgs = out
            .get("messages")
            .and_then(|v| v.as_array())
            .expect("messages array present");
        assert_eq!(msgs.len(), 3, "no turn may be dropped; got {out:?}");

        // Roles preserved in order — alternation intact.
        assert_eq!(
            msgs[0].pointer("/role").and_then(|v| v.as_str()),
            Some("user")
        );
        assert_eq!(
            msgs[1].pointer("/role").and_then(|v| v.as_str()),
            Some("assistant")
        );
        assert_eq!(
            msgs[2].pointer("/role").and_then(|v| v.as_str()),
            Some("user")
        );

        // The assistant thinking-only turn now re-emits a native `reasoningContent` block (R25 MED
        // #3) — NOT a placeholder — so the turn survives carrying its reasoning rather than an empty
        // text stub.
        assert_eq!(
            msgs[1]
                .pointer("/content/0/reasoningContent/reasoningText/text")
                .and_then(|v| v.as_str()),
            Some("internal reasoning"),
            "thinking-only assistant turn must carry its reasoningContent block"
        );
        assert_eq!(
            msgs[1]
                .pointer("/content")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1)
        );
        // The image-only (URL-sentinel) user turn IS still non-representable, so it keeps the
        // placeholder text block.
        assert_eq!(
            msgs[2].pointer("/content/0/text").and_then(|v| v.as_str()),
            Some(""),
            "image-only (URL-sentinel) user turn must carry a placeholder text block"
        );
    }

    // --- Round 6 regression tests --------------------------------------------------------------

    /// Regression (findings 1+2 — SigV4 region derivation): the region is parsed robustly from the
    /// endpoint host across every real Bedrock shape (vanilla, FIPS, VPC-interface front,
    /// control-plane label), not just `bedrock-runtime.<region>.`. A host that yields no derivable
    /// region returns `None` (the caller warns and falls back to us-east-1) rather than silently
    /// guessing — so a mis-derived region is diagnosable instead of producing a confusing 403.
    #[test]
    fn test_derive_sigv4_region_shapes() {
        // Vanilla runtime endpoint.
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.us-east-1.amazonaws.com"),
            Some("us-east-1")
        );
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.ap-southeast-2.amazonaws.com"),
            Some("ap-southeast-2")
        );
        // FIPS endpoint (previously fell back to us-east-1 → cross-region mis-sign).
        assert_eq!(
            derive_sigv4_region("bedrock-runtime-fips.eu-west-1.amazonaws.com"),
            Some("eu-west-1")
        );
        // VPC-interface endpoint front (does NOT start with the bare prefix).
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.eu-central-1.vpce.amazonaws.com"),
            Some("eu-central-1")
        );
        assert_eq!(
            derive_sigv4_region(
                "vpce-0a1b2c3d4e5f-9zyxw.bedrock-runtime.ca-central-1.vpce.amazonaws.com"
            ),
            Some("ca-central-1")
        );
        // Control-plane label, defensively handled.
        assert_eq!(
            derive_sigv4_region("bedrock.us-west-2.amazonaws.com"),
            Some("us-west-2")
        );

        // 4-part AWS partition regions: GovCloud and ISO. The old EXACTLY-3-parts parser rejected
        // every one of these and silently signed for us-east-1 (403 SignatureDoesNotMatch).
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.us-gov-west-1.amazonaws.com"),
            Some("us-gov-west-1")
        );
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.us-gov-east-1.amazonaws.com"),
            Some("us-gov-east-1")
        );
        assert_eq!(
            derive_sigv4_region("bedrock-runtime-fips.us-gov-west-1.amazonaws.com"),
            Some("us-gov-west-1")
        );
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.us-iso-east-1.c2s.ic.gov"),
            Some("us-iso-east-1")
        );
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.us-isob-east-1.sc2s.sgov.gov"),
            Some("us-isob-east-1")
        );

        // Non-derivable hosts → None (caller warns + falls back to us-east-1).
        assert_eq!(derive_sigv4_region("my-cname-front.example.com"), None);
        assert_eq!(derive_sigv4_region("10.0.0.5"), None);
        assert_eq!(derive_sigv4_region("localhost"), None);
        // A Bedrock label whose following token is not a region (custom front) → None, not a wrong
        // guess from a non-region label.
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.internal.corp.example.com"),
            None
        );
        // Still reject obvious non-regions even though the part-count rule relaxed: a 2-part token,
        // a non-numeric final part, and a numeric leading part all fail the alpha+...+digit shape.
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.us-east.amazonaws.com"),
            None
        );
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.us-gov-west-foo.amazonaws.com"),
            None
        );
        assert_eq!(
            derive_sigv4_region("bedrock-runtime.1-gov-west-1.amazonaws.com"),
            None
        );
    }

    /// Regression (findings 1+2): a FIPS host in a non-us-east-1 region signs for THAT region's
    /// scope, not the silent `us-east-1` default the old prefix-only parser produced (which AWS
    /// rejects with SignatureDoesNotMatch). The signing crypto itself is covered by sigv4::tests;
    /// here we assert the derived scope region in the Authorization header.
    #[test]
    fn test_bedrock_sigv4_fips_host_derives_correct_region() {
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "bedrock-runtime-fips.eu-west-1.amazonaws.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
            upstream_creds: crate::auth::UpstreamCreds::Own,
        };
        let headers = writer.sign_request("AKID:SECRET", &ctx);
        let auth = headers
            .iter()
            .find(|(k, _)| k.as_str() == "authorization")
            .map(|(_, v)| v.to_str().unwrap().to_string())
            .expect("authorization header");
        assert!(
            auth.contains("/eu-west-1/bedrock/aws4_request"), // golden wire-contract literal (kept bare on purpose)
            "FIPS host must derive eu-west-1 scope, not the us-east-1 default; got: {auth}"
        );
        assert!(
            !auth.contains("/us-east-1/"),
            "must NOT silently fall back to us-east-1 for a derivable FIPS host; got: {auth}"
        );
    }

    /// Regression (findings 1+2): a non-derivable host falls back to us-east-1 (signing still
    /// proceeds, so a genuinely region-less endpoint is not failed closed) — the WARN is the
    /// operator-visible signal, asserted indirectly via the resulting scope.
    #[test]
    fn test_bedrock_sigv4_undecodable_host_falls_back_to_us_east_1() {
        let writer = BedrockWriter;
        let ctx = crate::proto::SigningContext {
            host: "my-cname-front.example.com".to_string(),
            canonical_uri: "/model/m/converse".to_string(),
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
            upstream_creds: crate::auth::UpstreamCreds::Own,
        };
        let headers = writer.sign_request("AKID:SECRET", &ctx);
        let auth = headers
            .iter()
            .find(|(k, _)| k.as_str() == "authorization")
            .map(|(_, v)| v.to_str().unwrap().to_string())
            .expect("authorization header");
        assert!(
            auth.contains("/us-east-1/bedrock/aws4_request"), // golden wire-contract literal (kept bare on purpose)
            "non-derivable host falls back to the us-east-1 default scope; got: {auth}"
        );
    }

    /// Regression (finding 3 — metadata WITHOUT usage): a `metadata` frame that lacks a `usage` key
    /// (a mock / Bedrock-compatible backend) must STILL emit the combined `MessageDelta` (consuming
    /// the stop_reason buffered from the preceding `messageStop`) BEFORE the terminal `MessageStop`,
    /// so a Bedrock→Anthropic translation keeps the native `message_delta`-before-`message_stop`
    /// ordering and never loses the stop_reason. Previously the delta lived inside the `usage` guard,
    /// so a usage-less metadata dropped the stop_reason and emitted a bare MessageStop.
    #[test]
    fn test_stream_metadata_without_usage_still_emits_delta_with_stop_reason() {
        use crate::ir::IrStreamEvent;

        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        let events: Vec<_> = vec![
            serde_json::json!({"type": "messageStart", "role": "assistant"}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"text": "Hi"}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
            serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
            // `metadata` arrives but carries NO `usage` key (mock backend).
            serde_json::json!({"type": "metadata", "metrics": {"latencyMs": 12}}),
        ]
        .into_iter()
        .flat_map(|data| reader.read_response_events("", &data, &mut state))
        .collect();

        // The combined MessageDelta must be present, carry the buffered stop_reason, and have
        // zero (harmless) usage since none was sent.
        let delta_idx = events
            .iter()
            .position(|e| matches!(e, IrStreamEvent::MessageDelta { .. }))
            .expect("a combined MessageDelta must be emitted even without usage");
        match &events[delta_idx] {
            IrStreamEvent::MessageDelta {
                stop_reason, usage, ..
            } => {
                assert_eq!(
                    stop_reason,
                    &Some(crate::ir::IrStopReason::EndTurn),
                    "stop_reason buffered from messageStop must survive a usage-less metadata"
                );
                assert_eq!(usage.input_tokens, 0);
                assert_eq!(usage.output_tokens, 0);
            }
            other => panic!("expected MessageDelta, got {other:?}"),
        }

        // The terminal MessageStop must follow the delta (delta-before-stop ordering).
        let stop_idx = events
            .iter()
            .position(|e| matches!(e, IrStreamEvent::MessageStop))
            .expect("a terminal MessageStop must be emitted");
        assert!(
            delta_idx < stop_idx,
            "MessageDelta must precede MessageStop; got {events:?}"
        );
        // Exactly one terminal stop, and the buffered stop_reason was consumed.
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, IrStreamEvent::MessageStop))
                .count(),
            1
        );
        assert!(
            state.pending_stop_reason.is_none(),
            "buffered stop_reason must be consumed by the delta"
        );
    }

    /// Regression (class sweep — image sentinel inside a toolResult): the same URL-sentinel guard
    /// applies to an `Image` nested in a `ToolResult`'s content — it must be dropped, not mangled
    /// into a base64 `image` block, while a base64 image inside a toolResult is still emitted.
    #[test]
    fn test_write_request_tool_result_url_sentinel_image_dropped() {
        let writer = BedrockWriter;
        let url = "https://example.com/in-tool.png";
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Tool,
                content: vec![crate::ir::IrBlock::ToolResult {
                    tool_use_id: "t1".to_string(),
                    content: vec![
                        crate::ir::IrBlock::Text {
                            text: "result".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        },
                        crate::ir::IrBlock::Image {
                            source: crate::ir::IrImageSource::Url(url.to_string()),
                            cache_control: None,
                        },
                    ],
                    is_error: false,
                    cache_control: None,
                }],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = writer.write_request(&req);
        let wire = serde_json::to_string(&out).unwrap();
        assert!(
            !wire.contains(url),
            "URL sentinel inside toolResult must not be emitted as base64; got {wire}"
        );
        // The text content of the toolResult still survives.
        assert_eq!(
            out.pointer("/messages/0/content/0/toolResult/content/0/text")
                .and_then(|v| v.as_str()),
            Some("result")
        );
        // Only the text inner block survives (the URL image was dropped).
        assert_eq!(
            out.pointer("/messages/0/content/0/toolResult/content")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            Some(1),
            "URL-sentinel image inner block must be dropped; got {out}"
        );
    }

    /// Regression (class sweep — maxTokens overflow): a `maxTokens` value above u32::MAX must be
    /// dropped to None (backend applies its default) rather than silently TRUNCATED (wrapped) into
    /// an arbitrary smaller cap by a bare `as u32`. Mirrors the hardened Gemini reader; an in-range
    /// value and the `> 0` filter are still honored.
    #[test]
    fn test_read_request_max_tokens_overflow_dropped_not_truncated() {
        let reader = BedrockReader;

        // Above u32::MAX → dropped to None (no truncation to 705_032_704).
        let body = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 5_000_000_000u64}
        });
        let ir = reader.read_request(&body).unwrap();
        assert_eq!(
            ir.max_tokens, None,
            "maxTokens above u32::MAX must drop to None, not wrap; got {:?}",
            ir.max_tokens
        );

        // Exactly u32::MAX is in range and preserved.
        let body = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": u32::MAX as u64}
        });
        let ir = reader.read_request(&body).unwrap();
        assert_eq!(ir.max_tokens, Some(u32::MAX));

        // Zero is still filtered out (> 0 guard).
        let body = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "inferenceConfig": {"maxTokens": 0}
        });
        let ir = reader.read_request(&body).unwrap();
        assert_eq!(ir.max_tokens, None);
    }

    /// Regression (reader, S3 image source): a message-level `image` block whose source is
    /// `s3Location` (not `bytes`) must be captured under the `image_s3` sentinel — not dropped with
    /// `data = ""` — so a same-protocol passthrough re-emits `source.s3Location` faithfully.
    #[test]
    fn test_read_request_image_s3_location_captured() {
        let reader = BedrockReader;
        let body = serde_json::json!({
            "messages": [{
                "role": "user",
                "content": [{
                    "image": {
                        "format": "jpeg",
                        "source": {
                            "s3Location": {
                                "uri": "s3://my-bucket/img.jpg",
                                "bucketOwner": "123456789012"
                            }
                        }
                    }
                }]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let block = &ir.messages[0].content[0];
        match block {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Vendor { vendor, value },
                ..
            } => {
                assert_eq!(
                    *vendor, "bedrock",
                    "S3-source image is a bedrock vendor reference"
                );
                assert_eq!(
                    value.pointer("/s3Location/uri").and_then(|v| v.as_str()),
                    Some("s3://my-bucket/img.jpg")
                );
                assert_eq!(
                    value
                        .pointer("/s3Location/bucketOwner")
                        .and_then(|v| v.as_str()),
                    Some("123456789012")
                );
                assert_eq!(
                    value.pointer("/format").and_then(|v| v.as_str()),
                    Some("jpeg")
                );
            }
            other => panic!("expected Image(Vendor) block, got {other:?}"),
        }
    }

    /// Regression (round-trip, S3 image source): a Bedrock body carrying an S3-sourced image must
    /// survive a reader→writer round-trip with its `source.s3Location` (uri + bucketOwner) and
    /// `format` intact — the old reader dropped the source, so the writer emitted nothing.
    #[test]
    fn test_image_s3_location_round_trip() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let body = serde_json::json!({
            "messages": [{
                "role": "user",
                "content": [{
                    "image": {
                        "format": "png",
                        "source": {
                            "s3Location": {
                                "uri": "s3://b/k.png",
                                "bucketOwner": "999988887777"
                            }
                        }
                    }
                }]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let out = writer.write_request(&ir);
        let img = out
            .pointer("/messages/0/content/0/image")
            .expect("image block must be re-emitted, not dropped");
        assert_eq!(
            img.pointer("/format").and_then(|v| v.as_str()),
            Some("png"),
            "format must round-trip; got {img}"
        );
        assert_eq!(
            img.pointer("/source/s3Location/uri")
                .and_then(|v| v.as_str()),
            Some("s3://b/k.png"),
            "s3Location.uri must round-trip; got {img}"
        );
        assert_eq!(
            img.pointer("/source/s3Location/bucketOwner")
                .and_then(|v| v.as_str()),
            Some("999988887777"),
            "s3Location.bucketOwner must round-trip; got {img}"
        );
        // The sentinel media_type must never leak onto the wire.
        let wire = serde_json::to_string(&out).unwrap();
        assert!(
            !wire.contains("image_s3"),
            "the image_s3 sentinel must not appear on the wire; got {wire}"
        );
        // No empty/base64 `bytes` source for an S3 image.
        assert!(
            img.pointer("/source/bytes").is_none(),
            "an S3 image must not be emitted with a bytes source; got {img}"
        );
    }

    /// Regression (reader, toolResult image): an `image` block inside a `toolResult.content` array
    /// must be decoded into an IR Image — symmetric with the writer's toolResult-image emission.
    /// The old reader skipped any non-text/json inner block, silently dropping image tool results.
    #[test]
    fn test_read_request_tool_result_decodes_image() {
        let reader = BedrockReader;
        let body = serde_json::json!({
            "messages": [{
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": "t1",
                        "status": "success",
                        "content": [
                            {"text": "see image"},
                            {"image": {"format": "png", "source": {"bytes": "QQ=="}}}
                        ]
                    }
                }]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::ToolResult { content, .. } => {
                assert_eq!(
                    content.len(),
                    2,
                    "both inner blocks must decode; got {content:?}"
                );
                match &content[1] {
                    crate::ir::IrBlock::Image {
                        source: crate::ir::IrImageSource::Base64 { media_type, data },
                        ..
                    } => {
                        assert_eq!(media_type, "image/png");
                        assert_eq!(data, "QQ==");
                    }
                    other => panic!("expected inner Image block, got {other:?}"),
                }
            }
            other => panic!("expected ToolResult block, got {other:?}"),
        }
    }

    /// Regression (round-trip, toolResult image): an S3-sourced image inside a toolResult survives
    /// reader→writer with its `source.s3Location` intact (the writer already emits `image` inside a
    /// toolResult; the reader must now decode it symmetrically).
    #[test]
    fn test_tool_result_image_s3_round_trip() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let body = serde_json::json!({
            "messages": [{
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": "t9",
                        "status": "success",
                        "content": [
                            {"image": {"format": "gif", "source": {"s3Location": {"uri": "s3://x/y.gif"}}}}
                        ]
                    }
                }]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let out = writer.write_request(&ir);
        let inner = out
            .pointer("/messages/0/content/0/toolResult/content/0/image")
            .expect("toolResult image must round-trip, not be dropped");
        assert_eq!(
            inner.pointer("/format").and_then(|v| v.as_str()),
            Some("gif")
        );
        assert_eq!(
            inner
                .pointer("/source/s3Location/uri")
                .and_then(|v| v.as_str()),
            Some("s3://x/y.gif"),
            "toolResult s3Location.uri must round-trip; got {inner}"
        );
    }

    /// Regression (writer): `bedrock_image_block` re-emits `source.s3Location` for a Bedrock-produced
    /// vendor reference (`{format, s3Location}`), and DROPS a vendor reference from another protocol
    /// (no Bedrock projection) rather than corrupting the source.
    #[test]
    fn test_bedrock_image_block_s3_vendor() {
        let source = crate::ir::IrImageSource::Vendor {
            vendor: "bedrock",
            value: serde_json::json!({
                "format": "png",
                "s3Location": { "uri": "s3://bk/i.png", "bucketOwner": "111122223333" }
            }),
        };
        let block = bedrock_image_block(&source).expect("bedrock vendor ref must emit a block");
        assert_eq!(
            block.pointer("/format").and_then(|f| f.as_str()),
            Some("png")
        );
        assert_eq!(
            block
                .pointer("/source/s3Location/uri")
                .and_then(|v| v.as_str()),
            Some("s3://bk/i.png")
        );
        assert_eq!(
            block
                .pointer("/source/s3Location/bucketOwner")
                .and_then(|v| v.as_str()),
            Some("111122223333")
        );
        // A vendor reference produced by ANOTHER protocol has no Bedrock projection → dropped.
        let foreign = crate::ir::IrImageSource::Vendor {
            vendor: "responses",
            value: serde_json::json!({ "file_id": "x" }),
        };
        assert!(
            bedrock_image_block(&foreign).is_none(),
            "a foreign vendor ref must be dropped"
        );
    }

    // --- Round 18 regression tests: prompt-cache token plumbing -------------------------------

    /// Regression (reader, non-streaming): a Converse response `usage` carrying
    /// `cacheReadInputTokens` / `cacheWriteInputTokens` must surface them on the IR usage as
    /// `cache_read_input_tokens` / `cache_creation_input_tokens`. The old reader hardcoded both
    /// to `None`, silently dropping real prompt-cache accounting — this asserts the real values
    /// round-trip out of the read path.
    #[test]
    fn test_read_response_plumbs_cache_tokens() {
        let reader = BedrockReader;
        let j = serde_json::json!({
            "output": { "message": { "role": "assistant", "content": [{"text": "hi"}] } },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 10,
                "outputTokens": 5,
                "totalTokens": 15,
                "cacheReadInputTokens": 64,
                "cacheWriteInputTokens": 128
            }
        });
        let resp = reader.read_response(&j).expect("read_response");
        assert_eq!(
            resp.usage.cache_read_input_tokens,
            Some(64),
            "cacheReadInputTokens must map to cache_read_input_tokens (was hardcoded None)"
        );
        assert_eq!(
            resp.usage.cache_creation_input_tokens,
            Some(128),
            "cacheWriteInputTokens must map to cache_creation_input_tokens (was hardcoded None)"
        );
    }

    /// Regression (reader): an absent cache field stays `None` (not `Some(0)`), so a no-cache
    /// response is distinguishable from a zero-token cache hit.
    #[test]
    fn test_read_response_absent_cache_tokens_are_none() {
        let reader = BedrockReader;
        let j = serde_json::json!({
            "output": { "message": { "role": "assistant", "content": [{"text": "hi"}] } },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 10, "outputTokens": 5, "totalTokens": 15}
        });
        let resp = reader.read_response(&j).expect("read_response");
        assert_eq!(resp.usage.cache_read_input_tokens, None);
        assert_eq!(resp.usage.cache_creation_input_tokens, None);
    }

    /// Regression (reader, streaming): the `metadata` event's `usage` cache fields must surface on
    /// the combined MessageDelta's IR usage (old code hardcoded both to `None`).
    #[test]
    fn test_read_stream_metadata_plumbs_cache_tokens() {
        use crate::ir::IrStreamEvent;
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;
        let events: Vec<IrStreamEvent> = [
            serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
            serde_json::json!({
                "type": "metadata",
                "usage": {
                    "inputTokens": 3,
                    "outputTokens": 1,
                    "cacheReadInputTokens": 9,
                    "cacheWriteInputTokens": 17
                }
            }),
        ]
        .into_iter()
        .flat_map(|data| reader.read_response_events("", &data, &mut state))
        .collect();

        let usage = events
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::MessageDelta { usage, .. } => Some(usage),
                _ => None,
            })
            .expect("a combined MessageDelta must be emitted");
        assert_eq!(usage.cache_read_input_tokens, Some(9));
        assert_eq!(usage.cache_creation_input_tokens, Some(17));
    }

    /// Regression (writer, non-streaming): IR usage cache fields must be emitted as
    /// `cacheReadInputTokens` / `cacheWriteInputTokens` on the native body (old writer omitted
    /// them entirely), and a full read→write round-trip of a cache-bearing usage is byte-identical.
    #[test]
    fn test_write_response_emits_cache_tokens_roundtrip() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let j = serde_json::json!({
            "output": { "message": { "role": "assistant", "content": [{"text": "hi"}] } },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 10,
                "outputTokens": 5,
                "totalTokens": 15,
                "cacheReadInputTokens": 64,
                "cacheWriteInputTokens": 128
            }
        });
        let resp = reader.read_response(&j).expect("read_response");
        let written = writer.write_response(&resp);
        assert_eq!(
            written
                .pointer("/usage/cacheReadInputTokens")
                .and_then(|v| v.as_u64()),
            Some(64),
            "writer must emit cacheReadInputTokens (was omitted)"
        );
        assert_eq!(
            written
                .pointer("/usage/cacheWriteInputTokens")
                .and_then(|v| v.as_u64()),
            Some(128),
            "writer must emit cacheWriteInputTokens (was omitted)"
        );
        assert_eq!(
            written, j,
            "cache-bearing round-trip must be byte-identical"
        );
    }

    /// Regression (writer): a `None` cache field is OMITTED, not serialized as `0` — so a no-cache
    /// response stays byte-identical to native AWS (which omits the fields when caching was idle).
    #[test]
    fn test_write_response_omits_absent_cache_tokens() {
        let writer = BedrockWriter;
        let resp = crate::ir::IrResponse {
            logprobs: Vec::new(),
            role: crate::ir::IrRole::Assistant,
            content: vec![],
            stop_reason: Some(crate::ir::IrStopReason::EndTurn),
            usage: IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        let written = writer.write_response(&resp);
        assert!(
            written.pointer("/usage/cacheReadInputTokens").is_none(),
            "absent cache_read must not be emitted as 0"
        );
        assert!(
            written.pointer("/usage/cacheWriteInputTokens").is_none(),
            "absent cache_creation must not be emitted as 0"
        );
    }

    /// Regression (writer, streaming): a usage-only MessageDelta carrying cache fields must emit
    /// them on the `metadata` frame's `usage` (old writer dropped them).
    #[test]
    fn test_write_stream_metadata_emits_cache_tokens() {
        let writer = BedrockWriter;
        let usage_only = IrStreamEvent::MessageDelta {
            stop_reason: None,
            stop_sequence: None,
            usage: IrUsage {
                input_tokens: 11,
                output_tokens: 7,
                cache_creation_input_tokens: Some(40),
                cache_read_input_tokens: Some(20),
            },
        };
        let (et, payload) = writer
            .write_response_event(&usage_only)
            .expect("usage-only delta must emit a frame");
        assert_eq!(et, "metadata");
        assert_eq!(
            payload
                .pointer("/usage/cacheReadInputTokens")
                .and_then(|v| v.as_u64()),
            Some(20)
        );
        assert_eq!(
            payload
                .pointer("/usage/cacheWriteInputTokens")
                .and_then(|v| v.as_u64()),
            Some(40)
        );
        // The pre-existing token fields are unaffected.
        assert_eq!(
            payload
                .pointer("/usage/inputTokens")
                .and_then(|v| v.as_u64()),
            Some(11)
        );
        assert_eq!(
            payload
                .pointer("/usage/totalTokens")
                .and_then(|v| v.as_u64()),
            Some(18)
        );
    }

    /// Regression (R20 MED #7): native Converse `cachePoint` blocks (the prompt-cache markers) that
    /// appear inside the `system` array and inside a message's `content` array were SILENTLY DROPPED
    /// by `read_request` (no IR `IrBlock` counterpart), so a same-protocol Bedrock->Bedrock
    /// passthrough re-emitted a body with prompt caching disabled — a real cost regression (a cache
    /// HIT becomes a full re-bill of the cached prefix every turn). They must now survive the
    /// read->write round-trip at their ORIGINAL positions. This test FAILS against the old code
    /// (the cachePoint blocks vanish) and passes after.
    #[test]
    fn test_cache_point_round_trip() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let wire = serde_json::json!({
            "system": [
                {"text": "you are a helpful assistant with a long static preamble"},
                {"cachePoint": {"type": "default"}}
            ],
            "messages": [
                {"role": "user", "content": [
                    {"text": "first big doc"},
                    {"cachePoint": {"type": "default"}},
                    {"text": "now the question"}
                ]},
                {"role": "assistant", "content": [
                    {"text": "an answer"}
                ]}
            ]
        });

        let ir = reader.read_request(&wire).expect("read_request");
        // The markers are stashed under the busbar-internal sentinel (Bedrock-native, no
        // cross-protocol meaning — so it lives in `extra`, not a first-class IR field).
        assert!(
            ir.extra.contains_key(CACHE_POINTS_SENTINEL),
            "cachePoint markers must be captured into extra; got {:?}",
            ir.extra
        );

        let out = writer.write_request(&ir);
        // The sentinel must NEVER leak onto the wire.
        assert!(
            out.get(CACHE_POINTS_SENTINEL).is_none(),
            "the cachePoint sentinel must not appear on the wire; got {out}"
        );
        // The whole body round-trips byte-identically: every cachePoint re-emitted at its position.
        assert_eq!(
            out, wire,
            "cachePoint markers must survive the round-trip at their original positions; got {out}"
        );
    }

    /// Regression (R20 MED #7): a message whose ONLY content block is a `cachePoint` (no
    /// representable text/tool block) must re-emit the marker rather than the empty-content `""`
    /// placeholder — the splice runs BEFORE the placeholder substitution, so the cachePoint keeps
    /// the turn non-empty and the prompt-cache boundary intact.
    #[test]
    fn test_cache_point_only_message_round_trip() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let wire = serde_json::json!({
            "messages": [
                {"role": "user", "content": [
                    {"text": "context block"}
                ]},
                {"role": "user", "content": [
                    {"cachePoint": {"type": "default"}}
                ]}
            ]
        });

        let ir = reader.read_request(&wire).expect("read_request");
        let out = writer.write_request(&ir);
        // The input carries two CONSECUTIVE `user` messages — a shape Bedrock Converse itself rejects
        // (roles must alternate). The F4 alternation fix coalesces them into ONE user turn, appending
        // the cachePoint AFTER the text block: the canonical, Bedrock-valid placement with identical
        // cache semantics (cache the prefix up to this point). The marker MUST survive the merge — the
        // original concern was that a cachePoint-only turn would degrade to a bare `text:""` placeholder
        // and LOSE the marker. (A pristine same-protocol Bedrock request never reaches this writer in
        // production: it takes the verbatim serialize short-circuit, so its exact bytes are preserved.)
        assert_eq!(
            out,
            serde_json::json!({
                "messages": [
                    {"role": "user", "content": [
                        {"text": "context block"},
                        {"cachePoint": {"type": "default"}}
                    ]}
                ]
            }),
            "consecutive user turns must coalesce (alternation) while preserving the cachePoint; got {out}"
        );
        // The cachePoint marker must still be present (not dropped to a bare text "").
        assert_eq!(
            out.pointer("/messages/0/content/1/cachePoint"),
            Some(&serde_json::json!({"type": "default"})),
            "the merged turn must carry the cachePoint marker; got {out}"
        );
    }

    /// A request that NEVER used prompt caching must not gain a stray sentinel key, and its body must
    /// round-trip byte-identically (the cachePoint capture is opt-in: zero markers → no `extra`
    /// entry, no behavioural change).
    #[test]
    fn test_no_cache_point_no_sentinel() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let wire = serde_json::json!({
            "system": [{"text": "plain system"}],
            "messages": [{"role": "user", "content": [{"text": "hi"}]}]
        });

        let ir = reader.read_request(&wire).expect("read_request");
        assert!(
            !ir.extra.contains_key(CACHE_POINTS_SENTINEL),
            "no cachePoint marker → no sentinel key; got {:?}",
            ir.extra
        );
        let out = writer.write_request(&ir);
        assert_eq!(
            out, wire,
            "cache-free body must round-trip byte-identically"
        );
    }

    /// `splice_cache_points` must NOT panic on a stale/foreign index (e.g. an `extra` that survived
    /// an unexpected hop): an out-of-range `i` is bounds-clamped to the array end, never indexing
    /// past it. Guards the no-panic-on-the-request-path rule.
    #[test]
    fn test_splice_cache_points_out_of_range_does_not_panic() {
        let mut arr = vec![serde_json::json!({"text": "only block"})];
        let entries = vec![
            serde_json::json!({"i": 999, "block": {"cachePoint": {"type": "default"}}}),
            // Missing fields are skipped, not panicked on.
            serde_json::json!({"block": {"cachePoint": {"type": "default"}}}),
            serde_json::json!({"i": 0}),
        ];
        splice_cache_points(&mut arr, &entries);
        // The valid (clamped) entry landed at the end; the malformed ones were skipped.
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[1].pointer("/cachePoint"),
            Some(&serde_json::json!({"type": "default"}))
        );
    }

    // --- Round 21 regression tests: audit findings --------------------------------------------

    /// Regression (R21 #1, ContextLength reachability): `extract_error` must synthesize the canonical
    /// `context_length_exceeded` provider_code for a real Bedrock oversized-context error body.
    /// Bedrock returns a generic `ValidationException` whose `message` carries the signal; the
    /// PRODUCTION `extract_error` (not just the `#[cfg(test)]` classify helper) must detect it so the
    /// breaker maps it to `StatusClass::ContextLength` and fails over without penalizing the lane.
    #[test]
    fn test_extract_error_synthesizes_context_length_exceeded() {
        let reader = BedrockReader;
        // The real AWS Bedrock validation message for an oversized request.
        let body = br#"{"__type":"ValidationException","message":"Input is longer than the maximum number of tokens allowed (200000) for this model."}"#;
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "an oversized-context ValidationException must surface the canonical \
             context_length_exceeded code; got {raw:?}"
        );

        // The alternate "maximum-tokens … requested" phrasing is also recognized.
        let body2 = br#"{"__type":"ValidationException","message":"The maximum-tokens limit was exceeded: 250000 requested."}"#;
        let raw2 = reader.extract_error(StatusCode::BAD_REQUEST, body2);
        assert_eq!(
            raw2.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "the maximum-tokens/requested phrasing must also map to context_length_exceeded; got {raw2:?}"
        );

        // A plain validation error (not context-length) keeps its human-readable message code —
        // the context-length scan must not over-trigger.
        let body3 =
            br#"{"__type":"ValidationException","message":"malformed request: unknown field foo"}"#;
        let raw3 = reader.extract_error(StatusCode::BAD_REQUEST, body3);
        assert_eq!(
            raw3.provider_code.as_deref(),
            Some("malformed request: unknown field foo"),
            "a non-context-length validation error must keep its message; got {raw3:?}"
        );
    }

    /// Regression (R21 #2, ordering invariant): the `contentBlockStart` toolUse arm must honor the
    /// same `state.started` guard the text branch enforces — a tool BlockStart must NEVER precede the
    /// MessageStart it belongs to. A `contentBlockStart` carrying a `toolUse` that arrives BEFORE
    /// `messageStart` (reordered/malformed stream) must emit NO BlockStart.
    #[test]
    fn test_stream_tool_block_start_before_message_start_is_dropped() {
        use crate::ir::IrStreamEvent;
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        // toolUse contentBlockStart BEFORE any messageStart: state.started is false → drop it.
        let evs = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "contentBlockStart",
                "contentBlockIndex": 0,
                "start": {"toolUse": {"toolUseId": "t1", "name": "f"}}
            }),
            &mut state,
        );
        assert!(
            !evs.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    block: crate::ir::IrBlockMeta::ToolUse { .. },
                    ..
                }
            )),
            "a tool BlockStart must not precede MessageStart; got {evs:?}"
        );

        // After a proper messageStart, the same toolUse start DOES emit a BlockStart (sanity).
        let _ = reader.read_response_events(
            "",
            &serde_json::json!({"type": "messageStart", "role": "assistant"}),
            &mut state,
        );
        let evs2 = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "contentBlockStart",
                "contentBlockIndex": 0,
                "start": {"toolUse": {"toolUseId": "t1", "name": "f"}}
            }),
            &mut state,
        );
        assert!(
            evs2.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    block: crate::ir::IrBlockMeta::ToolUse { .. },
                    ..
                }
            )),
            "after messageStart, a toolUse start must emit a ToolUse BlockStart; got {evs2:?}"
        );
    }

    /// Regression (R21 #3, json tool-result fidelity): a native Converse `{"json": <value>}` block
    /// inside a `toolResult.content` array must survive a same-protocol reader→writer round-trip as a
    /// `json` block — NOT be collapsed to a `text` block (the old behaviour, which lost the json/text
    /// distinction). Mirrors the image-sentinel round-trip.
    #[test]
    fn test_tool_result_json_block_round_trip() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let body = serde_json::json!({
            "messages": [{
                "role": "user",
                "content": [{
                    "toolResult": {
                        "toolUseId": "t1",
                        "status": "success",
                        "content": [
                            {"json": {"temperature": 72, "unit": "F", "nested": {"ok": true}}}
                        ]
                    }
                }]
            }]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let out = writer.write_request(&ir);
        let inner = out
            .pointer("/messages/0/content/0/toolResult/content/0/json")
            .expect("toolResult json block must round-trip as `json`, not be collapsed to text");
        assert_eq!(
            inner,
            &serde_json::json!({"temperature": 72, "unit": "F", "nested": {"ok": true}}),
            "the json tool-result value must round-trip verbatim; got {inner}"
        );
        // It must NOT have been re-emitted as a `text` block.
        assert!(
            out.pointer("/messages/0/content/0/toolResult/content/0/text")
                .is_none(),
            "a json tool-result block must not degrade to a text block; got {out}"
        );
    }

    /// Regression (R22 LOW #24, index clamp): the upstream-controlled `contentBlockIndex` is
    /// attacker-controllable and was forwarded UNCLAMPED into IR block indices at all three stream
    /// read sites (`contentBlockStart` / `contentBlockDelta` / `contentBlockStop`). A malicious huge
    /// index must now be clamped to `MAX_CONTENT_BLOCK_INDEX` before it reaches the IR, so a
    /// downstream ingress writer can never be driven to track/allocate against a pathological index.
    #[test]
    fn test_stream_huge_content_block_index_is_clamped() {
        use crate::ir::IrStreamEvent;
        let mut state = crate::ir::StreamDecodeState::default();
        let reader = BedrockReader;

        // Open the stream so the BlockStart `state.started` guard passes.
        let _ = reader.read_response_events(
            "",
            &serde_json::json!({"type": "messageStart", "role": "assistant"}),
            &mut state,
        );

        let huge = u64::MAX;
        let expected = MAX_CONTENT_BLOCK_INDEX as usize;

        // contentBlockStart (text shape: empty `start` object).
        let start = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "contentBlockStart",
                "contentBlockIndex": huge,
                "start": {}
            }),
            &mut state,
        );
        let start_idx = start.iter().find_map(|e| match e {
            IrStreamEvent::BlockStart { index, .. } => Some(*index),
            _ => None,
        });
        assert_eq!(
            start_idx,
            Some(expected),
            "a huge contentBlockIndex on contentBlockStart must be clamped to \
             MAX_CONTENT_BLOCK_INDEX; got {start:?}"
        );

        // contentBlockDelta.
        let delta = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": huge,
                "delta": {"text": "hi"}
            }),
            &mut state,
        );
        let delta_idx = delta.iter().find_map(|e| match e {
            IrStreamEvent::BlockDelta { index, .. } => Some(*index),
            _ => None,
        });
        assert_eq!(
            delta_idx,
            Some(expected),
            "a huge contentBlockIndex on contentBlockDelta must be clamped; got {delta:?}"
        );

        // contentBlockStop.
        let stop = reader.read_response_events(
            "",
            &serde_json::json!({
                "type": "contentBlockStop",
                "contentBlockIndex": huge
            }),
            &mut state,
        );
        let stop_idx = stop.iter().find_map(|e| match e {
            IrStreamEvent::BlockStop { index } => Some(*index),
            _ => None,
        });
        assert_eq!(
            stop_idx,
            Some(expected),
            "a huge contentBlockIndex on contentBlockStop must be clamped; got {stop:?}"
        );
    }

    /// Regression (R22 LOW #12, classify/extract_error lockstep): the `#[cfg(test)]` `classify`
    /// helper must recognize EVERY context-length phrasing the production `extract_error` does. R21
    /// #17 added a third pattern (`exceeds the maximum` + token/context) to `extract_error` but not
    /// to `classify`, so the two drifted. The classifier must now map that third phrasing to
    /// `StatusClass::ContextLength`, identically to `extract_error`.
    #[test]
    fn test_classify_third_context_length_pattern_matches_extract_error() {
        let reader = BedrockReader;
        // The third phrasing (R21 #17): "exceeds the maximum" + token/context.
        let body = br#"{"__type":"ValidationException","message":"The request exceeds the maximum context length for this model."}"#;

        // Production extract_error surfaces the canonical code...
        let raw = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "extract_error must recognize the `exceeds the maximum` phrasing; got {raw:?}"
        );

        // ...and the test-only classify must agree (lockstep).
        let signal = reader.classify(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            signal.class,
            StatusClass::ContextLength,
            "classify must map the `exceeds the maximum` phrasing to ContextLength, in lockstep \
             with extract_error; got {signal:?}"
        );
        assert_eq!(
            signal.provider_signal.as_deref(),
            Some("context_length_exceeded"),
            "classify must surface the canonical context_length_exceeded signal; got {signal:?}"
        );

        // The "token" branch variant also matches.
        let body_tok = br#"{"__type":"ValidationException","message":"Prompt exceeds the maximum number of input tokens."}"#;
        let signal_tok = reader.classify(StatusCode::BAD_REQUEST, body_tok);
        assert_eq!(
            signal_tok.class,
            StatusClass::ContextLength,
            "classify must match the token variant of the third pattern; got {signal_tok:?}"
        );
    }

    // --- Round 23 regression tests: audit findings --------------------------------------------

    /// Regression (R23 LOW #14, context-length body-scan gate): the `extract_error` context-length
    /// override must be GATED on a `400` — Bedrock only emits an oversized-context error as a `400
    /// ValidationException`. A 5xx whose body merely echoes context-length phrasing (an upstream
    /// server-error envelope quoting the request) must NOT be reclassified as
    /// `context_length_exceeded`: that would trigger a no-penalty failover masking an unhealthy
    /// lane. The 5xx must keep its structured signal so the breaker maps it to ServerError.
    #[test]
    fn test_extract_error_5xx_context_phrasing_not_reclassified() {
        let reader = BedrockReader;
        // A 5xx whose body happens to contain the canonical context-length phrasing.
        let body = br#"{"__type":"InternalServerException","message":"Input is longer than the maximum number of tokens allowed (200000) for this model."}"#;

        let raw = reader.extract_error(StatusCode::INTERNAL_SERVER_ERROR, body);
        assert_ne!(
            raw.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a 5xx body must NEVER be reclassified as context_length_exceeded; got {raw:?}"
        );
        assert_eq!(
            raw.http_status, 500,
            "the 5xx status must be preserved; got {raw:?}"
        );

        // Sanity: the SAME phrasing on a real 400 ValidationException IS still recognized (the gate
        // does not break the legitimate path).
        let raw_400 = reader.extract_error(StatusCode::BAD_REQUEST, body);
        assert_eq!(
            raw_400.provider_code.as_deref(),
            Some("context_length_exceeded"),
            "a 400 with context-length phrasing must still surface the canonical code; got {raw_400:?}"
        );

        // The test-only `classify` helper must agree (lockstep): a 5xx with the phrasing classifies
        // as ServerError, not ContextLength.
        let signal = reader.classify(StatusCode::INTERNAL_SERVER_ERROR, body);
        assert_eq!(
            signal.class,
            StatusClass::ServerError,
            "classify must map a 5xx context-phrasing body to ServerError, in lockstep with \
             extract_error; got {signal:?}"
        );
    }

    /// Regression (R23 LOW #15, response image completeness): the `read_response` content loop must
    /// carry an `image` block from a Converse response into the IR — the request-side readers
    /// already decode `image` via `read_bedrock_image_block`, but the response loop silently DROPPED
    /// it. A base64 `source.bytes` image in the assistant message must surface as an
    /// `IrBlock::Image`, and an `source.s3Location` image must surface under the `image_s3` sentinel.
    #[test]
    fn test_read_response_carries_image_block() {
        let reader = BedrockReader;

        // base64 source.bytes image in the response message content.
        let body = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": "here is the chart"},
                        {"image": {"format": "png", "source": {"bytes": "AAAA"}}}
                    ]
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 1, "outputTokens": 2}
        });
        let ir = reader.read_response(&body).expect("read_response");
        let img = ir.content.iter().find_map(|b| match b {
            crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Base64 { media_type, data },
                ..
            } => Some((media_type, data)),
            _ => None,
        });
        assert_eq!(
            img,
            Some((&"image/png".to_string(), &"AAAA".to_string())),
            "a base64 response image must be carried into IR as an Image block; got {:?}",
            ir.content
        );

        // s3Location source: surfaces under the image_s3 sentinel (stashed for faithful re-emit).
        let body_s3 = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"image": {"format": "jpeg", "source": {"s3Location": {"uri": "s3://b/k"}}}}
                    ]
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 1, "outputTokens": 2}
        });
        let ir_s3 = reader.read_response(&body_s3).expect("read_response s3");
        let has_s3 = ir_s3.content.iter().any(|b| {
            matches!(
                b,
                crate::ir::IrBlock::Image {
                    source: crate::ir::IrImageSource::Vendor {
                        vendor: "bedrock",
                        ..
                    },
                    ..
                }
            )
        });
        assert!(
            has_s3,
            "an s3Location response image must be carried into IR under the image_s3 sentinel; \
             got {:?}",
            ir_s3.content
        );
    }

    /// Regression (R25 MED #3): a native Converse `reasoningContent` (extended-thinking) block in a
    /// REQUEST message's `content[]` was SILENTLY DROPPED by `read_request` (no arm matched it), so a
    /// same-protocol Bedrock->Bedrock passthrough lost the signed reasoning Bedrock requires echoed
    /// back on a follow-up turn. It must now round-trip: reader carries it into IR `Thinking`, writer
    /// re-emits `reasoningContent`. FAILS against the old code (the block vanishes) and passes after.
    #[test]
    fn test_request_reasoning_content_round_trips() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let body = serde_json::json!({
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"reasoningContent": {"reasoningText": {"text": "let me think", "signature": "sig-abc"}}},
                        {"text": "the answer is 42"}
                    ]
                }
            ]
        });
        let ir = reader.read_request(&body).expect("read_request");
        // Reader carried reasoningContent into an IR Thinking block with the signature preserved.
        let thinking = ir.messages[0].content.iter().find_map(|b| match b {
            crate::ir::IrBlock::Thinking {
                text, signature, ..
            } => Some((text, signature)),
            _ => None,
        });
        assert_eq!(
            thinking,
            Some((&"let me think".to_string(), &Some("sig-abc".to_string()))),
            "reasoningContent must be carried into IR as a Thinking block; got {:?}",
            ir.messages[0].content
        );
        let out = writer.write_request(&ir);
        // Writer re-emits the reasoningContent block at the head of the content array.
        assert_eq!(
            out.pointer("/messages/0/content/0/reasoningContent/reasoningText/text")
                .and_then(|v| v.as_str()),
            Some("let me think"),
            "reasoningContent text must survive the round-trip; got {out}"
        );
        assert_eq!(
            out.pointer("/messages/0/content/0/reasoningContent/reasoningText/signature")
                .and_then(|v| v.as_str()),
            Some("sig-abc"),
            "reasoningContent signature must survive the round-trip; got {out}"
        );
        assert_eq!(
            out, body,
            "a reasoningContent-bearing request must round-trip byte-identically; got {out}"
        );
    }

    /// Regression (R25 MED #3): a `reasoningContent` block in a RESPONSE message's `content[]` was
    /// silently dropped by `read_response`. It must now round-trip through read->write. Also covers
    /// the `redactedContent` member (carried via the redacted-signature sentinel) so a redacted
    /// reasoning block re-emits as `redactedContent`, not a plaintext `reasoningText`.
    #[test]
    fn test_response_reasoning_content_round_trips() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let body = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"reasoningContent": {"reasoningText": {"text": "reasoning", "signature": "rs-1"}}},
                        {"text": "final"}
                    ]
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 3, "outputTokens": 4, "totalTokens": 7}
        });
        let ir = reader.read_response(&body).expect("read_response");
        assert!(
            ir.content.iter().any(|b| matches!(
                b,
                crate::ir::IrBlock::Thinking { text, signature , .. }
                    if text == "reasoning" && signature.as_deref() == Some("rs-1")
            )),
            "response reasoningContent must be carried into IR as a Thinking block; got {:?}",
            ir.content
        );
        let out = writer.write_response(&ir);
        assert_eq!(
            out, body,
            "a reasoningContent-bearing response must round-trip byte-identically; got {out}"
        );

        // redactedContent: carried via the sentinel signature, re-emitted as redactedContent.
        let redacted_body = serde_json::json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"reasoningContent": {"redactedContent": "RVhBTVBMRQ=="}},
                        {"text": "ok"}
                    ]
                }
            },
            "stopReason": "end_turn",
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}
        });
        let ir_r = reader.read_response(&redacted_body).expect("read redacted");
        assert!(
            ir_r.content.iter().any(|b| matches!(
                b,
                crate::ir::IrBlock::Thinking { text, redacted: true, .. }
                    if text == "RVhBTVBMRQ=="
            )),
            "redactedContent must be carried under the redacted-signature sentinel; got {:?}",
            ir_r.content
        );
        let out_r = writer.write_response(&ir_r);
        assert_eq!(
            out_r.pointer("/output/message/content/0/reasoningContent/redactedContent")
                .and_then(|v| v.as_str()),
            Some("RVhBTVBMRQ=="),
            "a redacted reasoning block must re-emit as redactedContent, not reasoningText; got {out_r}"
        );
        assert!(
            out_r
                .pointer("/output/message/content/0/reasoningContent/reasoningText")
                .is_none(),
            "a redacted reasoning block must NOT leak as a plaintext reasoningText; got {out_r}"
        );
    }

    /// Regression (R26 MED #3/#4): STREAMING extended-thinking (`reasoningContent` deltas on the
    /// ConverseStream wire) was SILENTLY DROPPED — `read_response_events` had no reasoning arm and
    /// `write_response_event` returned `None` for ThinkingDelta/SignatureDelta — even though the
    /// BUFFERED path (R25) preserved it. The streaming path must now mirror the buffered logic: the
    /// reader lazily opens a Thinking block on the first `reasoningContent` delta and emits
    /// ThinkingDelta/SignatureDelta; the writer re-emits them as `reasoningContent` frames. This test
    /// drives a full plaintext-reasoning ConverseStream through read->IR->write and asserts each IR
    /// reasoning event round-trips to its native frame. FAILS against the old code (no BlockStart for
    /// the reasoning block; ThinkingDelta/SignatureDelta produce no frame) and passes after.
    #[test]
    fn test_stream_reasoning_content_round_trips() {
        use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent};

        let reader = BedrockReader;
        let writer = BedrockWriter;
        let mut state = crate::ir::StreamDecodeState::default();

        // A native ConverseStream that streams a reasoning block (text deltas then a signature) and
        // then a normal text answer. The reasoning block is implied by its first `reasoningContent`
        // delta (no dedicated `contentBlockStart` on the wire), exactly as AWS streams it.
        let frames = vec![
            serde_json::json!({"type": "messageStart", "role": "assistant"}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"reasoningContent": {"text": "let me "}}
            }),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"reasoningContent": {"text": "think"}}
            }),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"reasoningContent": {"signature": "sig-xyz"}}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
            serde_json::json!({"type": "contentBlockStart", "contentBlockIndex": 1, "start": {}}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 1,
                "delta": {"text": "the answer"}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 1}),
        ];

        let events: Vec<IrStreamEvent> = frames
            .into_iter()
            .flat_map(|f| reader.read_response_events("", &f, &mut state))
            .collect();

        // The reader opened a Thinking block lazily on the first reasoningContent delta and emitted
        // the two ThinkingDeltas + the SignatureDelta.
        assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart { index: 0, block: IrBlockMeta::Thinking }
            )),
            "a Thinking BlockStart must be lazily opened on the first reasoningContent delta; got {events:?}"
        );
        let thinking_text: String = events
            .iter()
            .filter_map(|e| match e {
                IrStreamEvent::BlockDelta {
                    delta: IrDelta::ThinkingDelta(t),
                    ..
                } => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(
            thinking_text, "let me think",
            "the streamed reasoning text must be carried as ThinkingDeltas; got {events:?}"
        );
        assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockDelta { delta: IrDelta::SignatureDelta(s), .. } if s == "sig-xyz"
            )),
            "the reasoning signature must be carried as a SignatureDelta; got {events:?}"
        );

        // Round-trip every reasoning IR event back through the writer and confirm the native frames.
        let block_start = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Thinking,
            })
            .expect("Thinking BlockStart must produce a frame");
        assert_eq!(block_start.0, "contentBlockStart");
        assert!(
            block_start.1.pointer("/start/reasoningContent").is_some(),
            "a Thinking BlockStart must emit a reasoningContent start; got {}",
            block_start.1
        );

        let text_delta = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::ThinkingDelta("hello".to_string()),
            })
            .expect("ThinkingDelta must produce a frame");
        assert_eq!(text_delta.0, "contentBlockDelta");
        assert_eq!(
            text_delta
                .1
                .pointer("/delta/reasoningContent/text")
                .and_then(|v| v.as_str()),
            Some("hello"),
            "a ThinkingDelta must re-emit as reasoningContent.text; got {}",
            text_delta.1
        );

        let sig_delta = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::SignatureDelta("sig-xyz".to_string()),
            })
            .expect("SignatureDelta must produce a frame");
        assert_eq!(sig_delta.0, "contentBlockDelta");
        assert_eq!(
            sig_delta
                .1
                .pointer("/delta/reasoningContent/signature")
                .and_then(|v| v.as_str()),
            Some("sig-xyz"),
            "a SignatureDelta must re-emit as reasoningContent.signature; got {}",
            sig_delta.1
        );
        // A genuine signature must NOT leak as redactedContent.
        assert!(
            sig_delta
                .1
                .pointer("/delta/reasoningContent/redactedContent")
                .is_none(),
            "a real signature must not re-emit as redactedContent; got {}",
            sig_delta.1
        );
    }

    /// Regression (R26 MED #3/#4): the STREAMING redacted-reasoning case. A `reasoningContent`
    /// delta carrying `redactedContent` (opaque encrypted bytes) must survive read->IR->write on the
    /// streaming path, re-emitting as `redactedContent` — never leaking as a plaintext `text` or a
    /// `signature`. The reader maps it to a typed `RedactedReasoningDelta(bytes)` (one IR delta → one
    /// frame); the writer re-emits the bytes under `redactedContent`. FAILS against the old code (the
    /// redacted delta was dropped entirely) and passes after.
    #[test]
    fn test_stream_reasoning_redacted_round_trips() {
        use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent};

        let reader = BedrockReader;
        let writer = BedrockWriter;
        let mut state = crate::ir::StreamDecodeState::default();

        let frames = vec![
            serde_json::json!({"type": "messageStart", "role": "assistant"}),
            serde_json::json!({
                "type": "contentBlockDelta",
                "contentBlockIndex": 0,
                "delta": {"reasoningContent": {"redactedContent": "RVhBTVBMRQ=="}}
            }),
            serde_json::json!({"type": "contentBlockStop", "contentBlockIndex": 0}),
        ];

        let events: Vec<IrStreamEvent> = frames
            .into_iter()
            .flat_map(|f| reader.read_response_events("", &f, &mut state))
            .collect();

        // A Thinking block is opened and the redacted bytes ride on a sentinel-prefixed SignatureDelta.
        assert!(
            events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Thinking
                }
            )),
            "a Thinking BlockStart must open for a streamed redactedContent delta; got {events:?}"
        );
        let redacted_delta = events.iter().find_map(|e| match e {
            IrStreamEvent::BlockDelta {
                delta: IrDelta::RedactedReasoningDelta(s),
                ..
            } => Some(s.clone()),
            _ => None,
        });
        assert_eq!(
            redacted_delta.as_deref(),
            Some("RVhBTVBMRQ=="),
            "redacted reasoning bytes must ride on a typed RedactedReasoningDelta; got {events:?}"
        );
        // No plaintext ThinkingDelta must be emitted for a redacted block (no leak of the bytes as text).
        assert!(
            !events.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockDelta {
                    delta: IrDelta::ThinkingDelta(_),
                    ..
                }
            )),
            "a redacted reasoning block must NOT emit a plaintext ThinkingDelta; got {events:?}"
        );

        // Writer re-emits the bytes under redactedContent from a typed RedactedReasoningDelta.
        let frame = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: IrDelta::RedactedReasoningDelta(
                    redacted_delta.expect("redacted delta present"),
                ),
            })
            .expect("RedactedReasoningDelta must produce a frame");
        assert_eq!(frame.0, "contentBlockDelta");
        assert_eq!(
            frame
                .1
                .pointer("/delta/reasoningContent/redactedContent")
                .and_then(|v| v.as_str()),
            Some("RVhBTVBMRQ=="),
            "a RedactedReasoningDelta must re-emit the bytes as redactedContent; got {}",
            frame.1
        );
        assert!(
            frame
                .1
                .pointer("/delta/reasoningContent/signature")
                .is_none(),
            "a redacted reasoning delta must NOT leak as a plaintext signature; got {}",
            frame.1
        );
        assert!(
            frame.1.pointer("/delta/reasoningContent/text").is_none(),
            "a redacted reasoning delta must NOT leak as a plaintext text; got {}",
            frame.1
        );
    }

    /// Regression (R25 MED #4): native Converse `guardContent` (inline Guardrails) blocks that appear
    /// inside the `system` array and inside a message's `content` array were SILENTLY DROPPED by
    /// `read_request` (no IR `IrBlock` counterpart), so a same-protocol Bedrock->Bedrock passthrough
    /// re-emitted a body with the guardrail spans the caller marked stripped — disabling the inline
    /// content-classification the operator relies on. They must now survive the read->write round-trip
    /// at their ORIGINAL positions via the `GUARD_CONTENT_SENTINEL` stash. FAILS against the old code
    /// (the guardContent blocks vanish) and passes after.
    #[test]
    fn test_guard_content_round_trips() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let body = serde_json::json!({
            "system": [
                {"text": "be safe"},
                {"guardContent": {"text": {"text": "ground truth", "qualifiers": ["grounding_source"]}}}
            ],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"guardContent": {"text": {"text": "user query", "qualifiers": ["query"]}}},
                        {"text": "hello"}
                    ]
                }
            ]
        });
        let ir = reader.read_request(&body).expect("read_request");
        assert!(
            ir.extra.contains_key(GUARD_CONTENT_SENTINEL),
            "guardContent markers must be captured into extra; got {:?}",
            ir.extra
        );
        let out = writer.write_request(&ir);
        assert!(
            out.get(GUARD_CONTENT_SENTINEL).is_none(),
            "the guardContent sentinel must not appear on the wire; got {out}"
        );
        assert_eq!(
            out, body,
            "guardContent markers must survive the round-trip at their original positions; got {out}"
        );
    }

    /// Regression (R25 MED #4): when BOTH `cachePoint` and `guardContent` markers occupy DISTINCT
    /// positions in the SAME content array, they must be re-spliced together so neither shifts the
    /// other off its recorded index. This guards the single-batch merge (`merge_marker_entries`)
    /// against the naive two-pass splice that would mis-order them.
    #[test]
    fn test_guard_content_and_cache_point_interleave_preserved() {
        let reader = BedrockReader;
        let writer = BedrockWriter;
        let body = serde_json::json!({
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"guardContent": {"text": {"text": "q", "qualifiers": ["query"]}}},
                        {"text": "a"},
                        {"cachePoint": {"type": "default"}},
                        {"text": "b"}
                    ]
                }
            ]
        });
        let ir = reader.read_request(&body).expect("read_request");
        let out = writer.write_request(&ir);
        assert_eq!(
            out, body,
            "interleaved guardContent + cachePoint markers must round-trip at their original \
             positions; got {out}"
        );
    }

    /// A `reasoningContent` block carrying neither known member (a hypothetical future union member)
    /// must degrade gracefully — `read_bedrock_reasoning_block` returns `None` and the block is left
    /// undecoded rather than panicking or being mis-mapped to a Thinking with empty text.
    #[test]
    fn test_unknown_reasoning_member_does_not_panic() {
        let reader = BedrockReader;
        let body = serde_json::json!({
            "messages": [
                {
                    "role": "assistant",
                    "content": [
                        {"reasoningContent": {"futureMember": {"foo": "bar"}}},
                        {"text": "ok"}
                    ]
                }
            ]
        });
        let ir = reader.read_request(&body).expect("read_request");
        // No Thinking block synthesized from the unknown member.
        assert!(
            !ir.messages[0]
                .content
                .iter()
                .any(|b| matches!(b, crate::ir::IrBlock::Thinking { .. })),
            "an unknown reasoningContent member must not be mis-mapped to a Thinking block; got {:?}",
            ir.messages[0].content
        );
    }

    /// Helper: a minimal IR request carrying only a tool_choice (and one tool so toolConfig is valid).
    /// F4 conformance: consecutive same-role IR turns must coalesce so the Bedrock body alternates.
    /// The canonical trigger is the Tool→"user" role mapping: an assistant tool_use turn, then a
    /// Tool-result turn, then a follow-up User turn would emit assistant,user,user — which Bedrock
    /// Converse rejects (a 400). The two user turns must merge into one.
    #[test]
    fn consecutive_user_turns_coalesce_for_alternation() {
        let text_msg = |role, t: &str| crate::ir::IrMessage {
            role,
            content: vec![crate::ir::IrBlock::Text {
                text: t.to_string(),
                cache_control: None,
                citations: vec![],
            }],
        };
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![
                text_msg(crate::ir::IrRole::User, "q"),
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::ToolUse {
                        id: "t1".to_string(),
                        name: "get".to_string(),
                        input: serde_json::json!({}),
                        cache_control: None,
                    }],
                },
                // A Tool-result turn (maps to "user") immediately followed by a real User turn:
                // assistant, user, user on the wire without coalescing.
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "t1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "42".to_string(),
                            cache_control: None,
                            citations: vec![],
                        }],
                        is_error: false,
                        cache_control: None,
                    }],
                },
                text_msg(crate::ir::IrRole::User, "thanks"),
            ],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = BedrockWriter.write_request(&req);
        let msgs = out
            .get("messages")
            .and_then(|m| m.as_array())
            .expect("messages array");
        // Roles must strictly alternate: user, assistant, user (the Tool turn + trailing User merged).
        let roles: Vec<&str> = msgs
            .iter()
            .filter_map(|m| m.get("role").and_then(|r| r.as_str()))
            .collect();
        assert_eq!(
            roles,
            vec!["user", "assistant", "user"],
            "consecutive user turns must coalesce so roles alternate: {out}"
        );
        // The merged final user turn carries BOTH the toolResult and the trailing text.
        let last = msgs.last().expect("last message");
        let last_content = last
            .get("content")
            .and_then(|c| c.as_array())
            .expect("content array");
        assert!(
            last_content.iter().any(|b| b.get("toolResult").is_some()),
            "merged turn must keep the toolResult block: {out}"
        );
        assert!(
            last_content
                .iter()
                .any(|b| b.get("text").and_then(|t| t.as_str()) == Some("thanks")),
            "merged turn must keep the trailing user text: {out}"
        );
    }

    fn tool_choice_req(tc: Option<crate::ir::IrToolChoice>) -> crate::ir::IrRequest {
        crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![],
            tools: vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                cache_control: None,
            }],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: tc,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        }
    }

    /// F3 conformance: a `tool_choice` with NO accompanying tools must NOT produce a `toolConfig`.
    /// Bedrock Converse rejects a `toolConfig` whose `toolChoice` has no tools array (a 400). When a
    /// cross-protocol request carries a tool_choice but its tools could not be projected, the writer
    /// drops the orphan tool_choice and emits no toolConfig at all.
    #[test]
    fn tool_choice_without_tools_emits_no_tool_config() {
        for tc in [
            crate::ir::IrToolChoice::Auto,
            crate::ir::IrToolChoice::Required,
            crate::ir::IrToolChoice::Tool {
                name: "get_weather".to_string(),
            },
        ] {
            let mut req = tool_choice_req(Some(tc.clone()));
            req.tools = vec![]; // tool_choice set, but no tools survived
            let out = BedrockWriter.write_request(&req);
            assert!(
                out.get("toolConfig").is_none(),
                "toolConfig must be omitted entirely when tool_choice={tc:?} has no tools: {out}"
            );
        }
    }

    /// F5 conformance: the common `image/jpg` media_type (and casing variants) must normalize to
    /// Bedrock's `jpeg` ImageFormat, not pass through as the off-enum `jpg` that 400s.
    #[test]
    fn image_format_jpg_normalizes_to_jpeg() {
        for mt in ["image/jpg", "image/JPG", "image/Jpeg", "image/jpeg"] {
            let block = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
                media_type: mt.to_string(),
                data: "QUJD".to_string(),
            })
            .expect("image block");
            assert_eq!(
                block.get("format").and_then(|f| f.as_str()),
                Some("jpeg"),
                "media_type {mt:?} must emit Bedrock format=jpeg"
            );
        }
        // The other native formats are unaffected.
        for (mt, want) in [
            ("image/png", "png"),
            ("image/gif", "gif"),
            ("image/webp", "webp"),
        ] {
            let block = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
                media_type: mt.to_string(),
                data: "QUJD".to_string(),
            })
            .expect("image block");
            assert_eq!(block.get("format").and_then(|f| f.as_str()), Some(want));
        }
    }

    /// PF-H1: Bedrock `toolChoice:{any:{}}` (must call SOME tool) round-trips through the IR's
    /// `Required` variant — read promotes it, write re-emits the native `{any:{}}`.
    #[test]
    fn test_bedrock_tool_choice_any_required_roundtrips() {
        let reader = BedrockReader;
        let j = serde_json::json!({
            "messages": [],
            "toolConfig": {
                "tools": [{"toolSpec": {"name": "get_weather", "inputSchema": {"json": {}}}}],
                "toolChoice": {"any": {}}
            }
        });
        let ir = reader.read_request(&j).expect("read ok");
        assert_eq!(ir.tool_choice, Some(crate::ir::IrToolChoice::Required));

        let out = BedrockWriter.write_request(&ir);
        let tc = out
            .get("toolConfig")
            .and_then(|t| t.get("toolChoice"))
            .expect("toolChoice emitted");
        assert_eq!(tc, &serde_json::json!({"any": {}}));
    }

    /// PF-H1: Bedrock `toolChoice:{tool:{name}}` (forced specific tool) round-trips through the IR's
    /// `Tool{name}` variant.
    #[test]
    fn test_bedrock_tool_choice_specific_tool() {
        let reader = BedrockReader;
        let j = serde_json::json!({
            "messages": [],
            "toolConfig": {
                "tools": [{"toolSpec": {"name": "get_weather", "inputSchema": {"json": {}}}}],
                "toolChoice": {"tool": {"name": "get_weather"}}
            }
        });
        let ir = reader.read_request(&j).expect("read ok");
        assert_eq!(
            ir.tool_choice,
            Some(crate::ir::IrToolChoice::Tool {
                name: "get_weather".to_string()
            })
        );

        let out = BedrockWriter.write_request(&ir);
        let tc = out
            .get("toolConfig")
            .and_then(|t| t.get("toolChoice"))
            .expect("toolChoice emitted");
        assert_eq!(tc, &serde_json::json!({"tool": {"name": "get_weather"}}));
    }

    /// PF-H1: `IrToolChoice::None` has no native Bedrock representation, so the writer must omit
    /// `toolChoice` entirely (rather than emit an invalid shape) while still emitting the tools.
    #[test]
    fn test_bedrock_tool_choice_none_omitted_on_write() {
        let req = tool_choice_req(Some(crate::ir::IrToolChoice::None));
        let out = BedrockWriter.write_request(&req);
        let tool_config = out
            .get("toolConfig")
            .expect("toolConfig with tools emitted");
        assert!(
            tool_config.get("toolChoice").is_none(),
            "Bedrock has no native 'none' — toolChoice must be omitted; got {tool_config:?}"
        );
        assert!(
            tool_config.get("tools").is_some(),
            "tools must still be emitted"
        );
    }

    /// PF-H1: a request with no native `toolChoice` reads back as `tool_choice == None` (no spurious
    /// directive minted on translation).
    #[test]
    fn test_bedrock_tool_choice_absent_is_none() {
        let reader = BedrockReader;
        let j = serde_json::json!({
            "messages": [],
            "toolConfig": {"tools": [{"toolSpec": {"name": "f", "inputSchema": {"json": {}}}}]}
        });
        let ir = reader.read_request(&j).expect("read ok");
        assert_eq!(ir.tool_choice, None);
        let out = BedrockWriter.write_request(&ir);
        assert!(
            out.get("toolConfig")
                .and_then(|t| t.get("toolChoice"))
                .is_none(),
            "no toolChoice should be emitted when none was provided"
        );
    }

    // PF-M1: OpenAI/Responses ingress accepts temperature up to 2.0, but Bedrock's native range is
    // [0.0, 1.0] and rejects >1 with a hard 400 ValidationException. The writer must clamp.
    #[test]
    fn test_bedrock_writer_clamps_temperature_above_one() {
        let ir = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: Some(1.8),
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        };
        let out = BedrockWriter.write_request(&ir);
        assert_eq!(
            out.pointer("/inferenceConfig/temperature")
                .and_then(|v| v.as_f64()),
            Some(1.0),
            "an OpenAI-ingress temperature of 1.8 must clamp to 1.0 on the Bedrock writer; got {out}"
        );
    }

    // --- H3: cross-protocol cache_control <-> Bedrock cachePoint -------------------------------

    /// Helper: a bare IR request with the given system / messages / tools and an EMPTY `extra`
    /// (cross-protocol shape — the positional cachePoint stash is absent, so the writer drives
    /// cachePoint emission from the first-class `cache_control` field, not the stash).
    fn cache_ctrl_req(
        system: Vec<crate::ir::IrBlock>,
        messages: Vec<crate::ir::IrMessage>,
        tools: Vec<crate::ir::IrTool>,
    ) -> crate::ir::IrRequest {
        crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system,
            messages,
            tools,
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: None,
            extra: serde_json::Map::new(),
        }
    }

    fn ephemeral() -> Option<crate::ir::CacheControl> {
        Some(crate::ir::CacheControl {
            kind: crate::ir::CacheKind::Ephemeral,
        })
    }

    /// H3 (write): an IR message Text block carrying `cache_control` must emit a Bedrock `cachePoint`
    /// block IMMEDIATELY AFTER it (the position Bedrock expects). With an empty `extra` (cross-protocol
    /// shape) the first-class field is the sole driver — the old writer dropped it entirely.
    #[test]
    fn test_cache_control_on_message_block_emits_cache_point() {
        let req = cache_ctrl_req(
            vec![],
            vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "cache me".to_string(),
                        cache_control: ephemeral(),
                        citations: vec![],
                    },
                    crate::ir::IrBlock::Text {
                        text: "but not this".to_string(),
                        cache_control: None,
                        citations: vec![],
                    },
                ],
            }],
            vec![],
        );
        let out = BedrockWriter.write_request(&req);
        // The cachePoint sits AFTER the first text block (index 1), before the second text (index 2).
        assert_eq!(
            out.pointer("/messages/0/content/0/text")
                .and_then(|v| v.as_str()),
            Some("cache me"),
        );
        assert_eq!(
            out.pointer("/messages/0/content/1/cachePoint"),
            Some(&serde_json::json!({"type": "default"})),
            "a cache_control block must emit a trailing cachePoint; got {out}"
        );
        assert_eq!(
            out.pointer("/messages/0/content/2/text")
                .and_then(|v| v.as_str()),
            Some("but not this"),
            "the non-cached block must follow, with no extra cachePoint; got {out}"
        );
        // Exactly one cachePoint (the second, uncached block emits none).
        let count = out
            .pointer("/messages/0/content")
            .and_then(|c| c.as_array())
            .map(|a| a.iter().filter(|b| b.get("cachePoint").is_some()).count())
            .unwrap_or(0);
        assert_eq!(count, 1, "exactly one cachePoint expected; got {out}");
    }

    /// H3 (write): a system Text block carrying `cache_control` emits a trailing cachePoint in the
    /// `system` array (the system prefix is the canonical prompt-cache target).
    #[test]
    fn test_cache_control_on_system_block_emits_cache_point() {
        let req = cache_ctrl_req(
            vec![crate::ir::IrBlock::Text {
                text: "long static preamble".to_string(),
                cache_control: ephemeral(),
                citations: vec![],
            }],
            vec![],
            vec![],
        );
        let out = BedrockWriter.write_request(&req);
        assert_eq!(
            out.pointer("/system/0/text").and_then(|v| v.as_str()),
            Some("long static preamble"),
        );
        assert_eq!(
            out.pointer("/system/1/cachePoint"),
            Some(&serde_json::json!({"type": "default"})),
            "a system cache_control block must emit a trailing cachePoint; got {out}"
        );
    }

    /// H3 (write): a tool definition carrying `cache_control` emits a `cachePoint` element in the
    /// `toolConfig.tools` array right after the tool (caching the tool-schema prefix).
    #[test]
    fn test_cache_control_on_tool_emits_cache_point() {
        let req = cache_ctrl_req(
            vec![],
            vec![],
            vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: None,
                input_schema: serde_json::json!({"type": "object"}),
                cache_control: ephemeral(),
            }],
        );
        let out = BedrockWriter.write_request(&req);
        assert_eq!(
            out.pointer("/toolConfig/tools/0/toolSpec/name")
                .and_then(|v| v.as_str()),
            Some("get_weather"),
        );
        assert_eq!(
            out.pointer("/toolConfig/tools/1/cachePoint"),
            Some(&serde_json::json!({"type": "default"})),
            "a tool cache_control must emit a trailing cachePoint in toolConfig.tools; got {out}"
        );
    }

    /// H3 (read): a Bedrock `cachePoint` following a content block must map onto the preceding IR
    /// block's first-class `cache_control` (so a Bedrock->Anthropic hop, where the positional stash is
    /// dropped, still preserves the boundary). The adjacency targets the immediately-preceding block.
    #[test]
    fn test_cache_point_maps_onto_preceding_block_cache_control() {
        let reader = BedrockReader;
        let wire = serde_json::json!({
            "system": [
                {"text": "preamble"},
                {"cachePoint": {"type": "default"}}
            ],
            "messages": [
                {"role": "user", "content": [
                    {"text": "doc"},
                    {"cachePoint": {"type": "default"}},
                    {"text": "tail"}
                ]}
            ],
            "toolConfig": {
                "tools": [
                    {"toolSpec": {"name": "t", "inputSchema": {"json": {}}}},
                    {"cachePoint": {"type": "default"}}
                ]
            }
        });
        let ir = reader.read_request(&wire).expect("read_request");
        // System: the first (and only) text block carries cache_control.
        match &ir.system[0] {
            crate::ir::IrBlock::Text { cache_control, .. } => {
                assert!(
                    cache_control.is_some(),
                    "system block must carry cache_control"
                );
            }
            other => panic!("expected Text, got {other:?}"),
        }
        // Message: the FIRST text ("doc") carries cache_control; the second ("tail") does not.
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text {
                text,
                cache_control,
                ..
            } => {
                assert_eq!(text, "doc");
                assert!(
                    cache_control.is_some(),
                    "preceding block must carry cache_control"
                );
            }
            other => panic!("expected Text, got {other:?}"),
        }
        match &ir.messages[0].content[1] {
            crate::ir::IrBlock::Text {
                text,
                cache_control,
                ..
            } => {
                assert_eq!(text, "tail");
                assert!(
                    cache_control.is_none(),
                    "trailing block must NOT carry cache_control"
                );
            }
            other => panic!("expected Text, got {other:?}"),
        }
        // Tool: the preceding tool carries cache_control.
        assert!(
            ir.tools[0].cache_control.is_some(),
            "the tool preceding a tools-array cachePoint must carry cache_control"
        );
    }

    /// H3 (round-trip, cross-protocol shape): reading a cachePoint-bearing body into the IR and then
    /// writing it back with `extra` CLEARED (the cross-protocol seam) re-derives the cachePoint purely
    /// from the first-class `cache_control` field — the boundary survives even when the positional
    /// stash is gone.
    #[test]
    fn test_cache_control_round_trip_via_field_only() {
        let reader = BedrockReader;
        let wire = serde_json::json!({
            "messages": [
                {"role": "user", "content": [
                    {"text": "doc"},
                    {"cachePoint": {"type": "default"}}
                ]}
            ]
        });
        let mut ir = reader.read_request(&wire).expect("read_request");
        // Simulate the cross-protocol seam: drop the busbar-internal positional stash so only the
        // first-class `cache_control` field remains to drive emission.
        ir.extra.clear();
        let out = BedrockWriter.write_request(&ir);
        assert_eq!(
            out.pointer("/messages/0/content/0/text")
                .and_then(|v| v.as_str()),
            Some("doc"),
        );
        assert_eq!(
            out.pointer("/messages/0/content/1/cachePoint"),
            Some(&serde_json::json!({"type": "default"})),
            "the cachePoint must be re-derived from cache_control after the stash is cleared; got {out}"
        );
    }

    /// H3 (no double-emit): on the SAME-protocol path the positional stash AND the first-class
    /// `cache_control` field are both populated by the reader, but the writer must emit EXACTLY ONE
    /// cachePoint (the stash drives placement; the inline field emission is suppressed). Guards against
    /// a regression that would double-bill the cache boundary.
    #[test]
    fn test_same_protocol_cache_point_no_double_emit() {
        let reader = BedrockReader;
        let wire = serde_json::json!({
            "messages": [
                {"role": "user", "content": [
                    {"text": "doc"},
                    {"cachePoint": {"type": "default"}},
                    {"text": "tail"}
                ]}
            ]
        });
        let ir = reader.read_request(&wire).expect("read_request");
        let out = BedrockWriter.write_request(&ir);
        let count = out
            .pointer("/messages/0/content")
            .and_then(|c| c.as_array())
            .map(|a| a.iter().filter(|b| b.get("cachePoint").is_some()).count())
            .unwrap_or(0);
        assert_eq!(
            count, 1,
            "same-protocol path must emit exactly one cachePoint; got {out}"
        );
        assert_eq!(
            out, wire,
            "same-protocol body must round-trip byte-identically; got {out}"
        );
    }

    // --- L4: degradations are now observable (warn paths) --------------------------------------

    /// L4 (warn path): `tool_choice = None` has no native Converse directive, so it degrades to an
    /// omitted `toolChoice` and a `tracing::warn!`. The observable degradation (no `toolChoice` key,
    /// tools still emitted) is asserted here; the warn fires on the same branch.
    #[test]
    fn test_tool_choice_none_warns_and_omits() {
        let req = tool_choice_req(Some(crate::ir::IrToolChoice::None));
        let out = BedrockWriter.write_request(&req);
        let tool_config = out.get("toolConfig").expect("toolConfig emitted");
        assert!(
            tool_config.get("toolChoice").is_none(),
            "tool_choice=None must omit toolChoice (warn-and-degrade); got {tool_config:?}"
        );
        assert!(
            tool_config.get("tools").is_some(),
            "the tools array must still be emitted; got {tool_config:?}"
        );
    }

    /// L4 (warn path): a malformed image media_type (an empty subtype) is coerced to `format: "png"`
    /// and a `tracing::warn!` fires. The observable coercion is asserted here; the warn rides the same
    /// fallback branch.
    #[test]
    fn test_malformed_media_type_warns_and_falls_back_to_png() {
        // Empty subtype (`image/`) takes the fallback branch that warns.
        let block = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
            media_type: "image/".to_string(),
            data: ("QQ==").to_string(),
        })
        .expect("base64 image must emit a block");
        assert_eq!(
            block.pointer("/format").and_then(|v| v.as_str()),
            Some("png"),
            "an empty subtype must coerce to png (warn-and-degrade); got {block}"
        );
        // A bare, unprefixed media_type also takes the warning fallback.
        let bare = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
            media_type: "garbage".to_string(),
            data: ("QQ==").to_string(),
        })
        .expect("bare media_type must emit a block");
        assert_eq!(
            bare.pointer("/format").and_then(|v| v.as_str()),
            Some("png"),
        );
        // A well-formed subtype does NOT take the fallback (no coercion, no warn).
        let jpeg = bedrock_image_block(&crate::ir::IrImageSource::Base64 {
            media_type: "image/jpeg".to_string(),
            data: ("QQ==").to_string(),
        })
        .expect("jpeg must emit a block");
        assert_eq!(
            jpeg.pointer("/format").and_then(|v| v.as_str()),
            Some("jpeg")
        );
    }

    /// D3: a cross-protocol IR carrying `response_format` reaching the Bedrock egress must be DROPPED
    /// (Converse has no native response_format field) — and the wire must contain NO `response_format`
    /// key (it would 400 the upstream). Mirrors the Anthropic-egress drop. The `warn!` itself is not
    /// asserted here (tracing capture is out of scope); the contract is "emits nothing".
    #[test]
    fn test_write_request_response_format_dropped() {
        let writer = BedrockWriter;
        let req = crate::ir::IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: vec![],
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            tool_choice: None,
            stream: false,
            frequency_penalty: None,
            presence_penalty: None,
            seed: None,
            n: None,
            response_format: Some(crate::ir::IrResponseFormat {
                json: true,
                schema: Some(serde_json::json!({"type": "object"})),
                name: Some("s".to_string()),
                strict: None,
                description: None,
            }),
            extra: serde_json::Map::new(),
        };
        let out = writer.write_request(&req);
        let wire = serde_json::to_string(&out).unwrap();
        assert!(
            !wire.contains("response_format") && !wire.contains("json_schema"),
            "response_format must not be emitted on the Bedrock wire; got {wire}"
        );
        assert!(
            out.get("response_format").is_none(),
            "no top-level response_format key may be present; got {out}"
        );
    }

    #[test]
    fn bedrock_stream_framing_emits_one_metadata_delta_then_guards_duplicate() {
        // GUARD: `BedrockStreamFraming::on_combined_stop_delta` must enforce the exactly-one-`metadata`
        // invariant against a (malformed/adversarial) egress that emits a SECOND combined stop-delta
        // carrying usage. The FIRST call (with non-zero usage) emits the stop-only delta PLUS one
        // usage-only `MessageDelta{stop_reason:None}` (the metadata frame); the SECOND call — `emitted`
        // is now set — emits ONLY the stop-only delta, so NO second metadata frame is produced.
        use super::StreamFraming;
        let usage = crate::ir::IrUsage {
            input_tokens: 5,
            output_tokens: 2,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };
        let mut framing = BedrockStreamFraming::default();

        // Helper: count the usage-only metadata deltas (`MessageDelta{stop_reason: None, ..}`).
        fn metadata_delta_count(events: &[crate::ir::IrStreamEvent]) -> usize {
            events
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        crate::ir::IrStreamEvent::MessageDelta {
                            stop_reason: None,
                            ..
                        }
                    )
                })
                .count()
        }

        let first = framing
            .on_combined_stop_delta(crate::ir::IrStopReason::EndTurn, None, &usage)
            .expect("first stop-delta returns events");
        assert_eq!(
            metadata_delta_count(&first),
            1,
            "first call must emit exactly ONE usage-only metadata delta; got {first:?}"
        );

        let second = framing
            .on_combined_stop_delta(crate::ir::IrStopReason::EndTurn, None, &usage)
            .expect("second stop-delta returns events");
        assert_eq!(
            metadata_delta_count(&second),
            0,
            "second call must emit ZERO metadata deltas (the !emitted guard suppresses the duplicate); got {second:?}"
        );
    }

    /// REGRESSION (audit c2r4): a CACHE-ONLY stop-delta (`input_tokens == 0 && output_tokens == 0`
    /// but non-zero cache tokens — a full cache hit) must emit its `metadata` frame INLINE with the
    /// real cache tokens, not defer it and later flush a zero-usage frame. `has_usage` now includes
    /// the cache fields.
    #[test]
    fn cache_only_usage_emits_metadata_inline() {
        fn metadata_delta_count(events: &[crate::ir::IrStreamEvent]) -> usize {
            events
                .iter()
                .filter(|e| {
                    matches!(
                        e,
                        crate::ir::IrStreamEvent::MessageDelta {
                            stop_reason: None,
                            ..
                        }
                    )
                })
                .count()
        }
        let usage = crate::ir::IrUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: Some(4096), // full cache hit
        };
        let mut framing = BedrockStreamFraming::default();
        let evs = framing
            .on_combined_stop_delta(crate::ir::IrStopReason::EndTurn, None, &usage)
            .expect("stop-delta returns events");
        assert_eq!(
            metadata_delta_count(&evs),
            1,
            "a cache-only stop-delta must emit ONE metadata frame inline with the real cache tokens, not defer a zero-usage frame; got {evs:?}"
        );
    }

    /// F4 coalescing (headline Bedrock behavior): Converse requires STRICTLY ALTERNATING
    /// user/assistant turns — two consecutive same-role messages are a 400 ValidationException. An IR
    /// with `[Assistant(tool_use), Tool(result1), Tool(result2)]` maps the two Tool turns to "user"
    /// role and MUST coalesce them into ONE user message so the wire alternates assistant,user.
    #[test]
    fn consecutive_tool_result_turns_coalesce_into_single_user_message() {
        let req = crate::ir::IrRequest {
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "run both tools".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::ToolUse {
                        id: "t1".to_string(),
                        name: "a".to_string(),
                        input: serde_json::json!({}),
                        cache_control: None,
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "t1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "r1".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                        cache_control: None,
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "t2".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "r2".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                        cache_control: None,
                    }],
                },
            ],
            ..Default::default()
        };
        let out = BedrockWriter.write_request(&req);
        let msgs = out
            .get("messages")
            .and_then(|m| m.as_array())
            .expect("messages array");
        // user, assistant, user — the two Tool turns coalesced into ONE trailing user message.
        let roles: Vec<&str> = msgs
            .iter()
            .filter_map(|m| m.get("role").and_then(|r| r.as_str()))
            .collect();
        assert_eq!(
            roles,
            vec!["user", "assistant", "user"],
            "consecutive same-role (tool→user) turns must coalesce to keep strict alternation: {out}"
        );
        // The coalesced final user message carries BOTH tool results.
        let last_content = msgs
            .last()
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_array())
            .expect("last content array");
        assert_eq!(
            last_content.len(),
            2,
            "both tool_result blocks must land in the single coalesced user turn: {out}"
        );
    }

    /// An UNKNOWN native `stopReason` maps to `IrStopReason::Other` on read (ir.rs:186), and `Other`
    /// degrades to the safe `end_turn` on egress — a foreign token is never carried into Converse's
    /// closed `stopReason` enum. Pins the full read_response→write_response degradation.
    #[test]
    fn unknown_stop_reason_maps_to_other_and_degrades_to_end_turn() {
        assert_eq!(
            stop_reason_map("some_future_reason"),
            crate::ir::IrStopReason::Other
        );
        let body = serde_json::json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": "some_future_reason",
            "usage": {"inputTokens": 3, "outputTokens": 1, "totalTokens": 4}
        });
        let resp = BedrockReader.read_response(&body).expect("read_response");
        assert_eq!(resp.stop_reason, Some(crate::ir::IrStopReason::Other));
        let out = BedrockWriter.write_response(&resp);
        assert_eq!(
            out.get("stopReason").and_then(|v| v.as_str()),
            Some("end_turn"),
            "Other must degrade to end_turn, never leak the foreign token into Converse's enum"
        );
    }

    /// Bedrock cache tokens are ALREADY ADDITIVE (ir.rs:457): unlike OpenAI/Gemini (which subtract the
    /// cached prefix out of the input total), the Bedrock reader stores `cacheReadInputTokens` /
    /// `cacheWriteInputTokens` AS-IS and does NOT reduce `inputTokens` by them. This pins that
    /// `input_tokens` is the raw wire value and `billable_tokens` sums all four additively.
    #[test]
    fn cache_usage_is_additive_input_not_reduced() {
        let body = serde_json::json!({
            "output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 10,
                "outputTokens": 5,
                "totalTokens": 15,
                "cacheReadInputTokens": 1000,
                "cacheWriteInputTokens": 200
            }
        });
        let resp = BedrockReader.read_response(&body).expect("read_response");
        assert_eq!(
            resp.usage.input_tokens, 10,
            "Bedrock inputTokens stored AS-IS (additive convention), NOT reduced by cache reads"
        );
        assert_eq!(resp.usage.cache_read_input_tokens, Some(1000));
        assert_eq!(resp.usage.cache_creation_input_tokens, Some(200));
        // Additive sum: 10 + 5 + 1000 + 200.
        assert_eq!(resp.usage.billable_tokens(), 1215);

        // Round-trip: write re-emits the native additive fields under AWS's spellings.
        let out = BedrockWriter.write_response(&resp);
        assert_eq!(
            out.pointer("/usage/cacheReadInputTokens")
                .and_then(|v| v.as_u64()),
            Some(1000)
        );
        assert_eq!(
            out.pointer("/usage/cacheWriteInputTokens")
                .and_then(|v| v.as_u64()),
            Some(200)
        );
        assert_eq!(
            out.pointer("/usage/inputTokens").and_then(|v| v.as_u64()),
            Some(10)
        );
    }

    /// `write_response_exception` (the Bedrock-INGRESS stream error path) must fold every error class
    /// onto ONE of the FIVE legal ConverseStream exception-union members, never a request-level name a
    /// native AWS stream decoder can't match. Pins the class→member mapping so a mid-stream error
    /// reaches a Bedrock client as a typed, decodable exception.
    #[test]
    fn write_response_exception_folds_to_stream_union_members() {
        let mk = |class| crate::proto::IrError {
            class,
            provider_signal: None,
            retry_after: None,
        };
        let cases = [
            (StatusClass::RateLimit, "ThrottlingException"),
            (StatusClass::Overloaded, "ServiceUnavailableException"),
            (StatusClass::ClientError, "ValidationException"),
            (StatusClass::ContextLength, "ValidationException"),
            (StatusClass::Timeout, "ModelStreamErrorException"),
            (StatusClass::Auth, "InternalServerException"),
            (StatusClass::Billing, "InternalServerException"),
            (StatusClass::ServerError, "InternalServerException"),
            (StatusClass::Network, "InternalServerException"),
        ];
        for (class, expect) in cases {
            let (name, _msg) = BedrockWriter
                .write_response_exception(&mk(class))
                .expect("Bedrock always returns Some for a stream exception");
            assert_eq!(name, expect, "class {class:?} must fold to {expect}");
        }
        // The message prefers the upstream provider_signal when present.
        let err = crate::proto::IrError {
            class: StatusClass::RateLimit,
            provider_signal: Some("slow down".to_string()),
            retry_after: None,
        };
        let (name, msg) = BedrockWriter.write_response_exception(&err).unwrap();
        assert_eq!(name, "ThrottlingException");
        assert_eq!(
            msg, "slow down",
            "message prefers the upstream provider_signal"
        );
    }
}
