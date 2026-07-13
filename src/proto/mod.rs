// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The protocol seam: a protocol-agnostic core, with each wire dialect's specifics confined to a
//! `Reader` (wire → signal/IR) and a `Writer` (IR/intent → wire). `Protocol` bundles a Reader and
//! Writer; a string-keyed registry maps a provider's protocol name to its `Protocol`.

use axum::http::{header::HeaderValue, HeaderName, StatusCode};
use std::sync::Arc;

// StatusClass and CanonicalSignal are defined in breaker.rs and re-exported here for compatibility.
// The `CanonicalSignal` re-export is consumed only by the per-protocol `classify` test helpers (which
// are themselves `#[cfg(test)]`), so it is gated to test builds to avoid an unused-import warning in
// the 1.0 binary; production code refers to the canonical `crate::breaker::CanonicalSignal` directly.
#[cfg(test)]
pub(crate) use crate::breaker::CanonicalSignal;
pub(crate) use crate::breaker::StatusClass;

// Import types needed for response/stream IR
use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent, IrUsage};

/// Busbar-internal `provider_signal` label for an IR-parse failure (the LANE label the breaker/metrics
/// layer reads to classify a translation/parse error). A busbar-internal signal, NOT a wire shape, so
/// it lives in the agnostic proto layer; the per-protocol readers reference it rather than re-spelling
/// the literal.
pub(crate) const SIGNAL_IR_PARSE: &str = "ir_parse";

/// The OpenAI-style SSE stream terminator sentinel (`data: [DONE]`). The bare token is matched by the
/// cross-protocol streaming core and several readers; the full framed bytes are emitted on egress.
/// Shared here so no reader/writer re-spells either form.
pub(crate) const SSE_DONE_SENTINEL: &str = "[DONE]";
pub(crate) const SSE_DONE_FRAME: &[u8] = b"data: [DONE]\n\n";

/// The HTTP `Authorization` header name (lowercase, canonical). Emitted by the bearer/SigV4 auth-header
/// builders across protocols; named once so no builder re-spells it.
pub(crate) const HDR_AUTHORIZATION: &str = "authorization";

/// An IR-level error, currently an alias for `CanonicalSignal` (the normalized error signal).
pub(crate) type IrError = crate::breaker::CanonicalSignal;

/// Build the `Authorization: Bearer <key>` header pair for the pure-Bearer protocol writers
/// (OpenAI, `/v1/responses`, Gemini's `x-goog`… aside, Cohere). Shared so the warn+OMIT policy lives
/// in ONE place rather than being copy-pasted (and drifting) per writer.
///
/// `HeaderValue::from_str` rejects ASCII control bytes (a stray CR/LF/NUL a config system may have
/// injected). The previous per-writer `unwrap_or_else(HeaderValue::from_static(""))` SILENTLY emitted
/// a syntactically empty `Authorization: ` header — the upstream then 401s every request on the lane
/// with no proxy-side signal, and the empty-Bearer form is itself a fingerprinting tell a backend can
/// compare against well-formed tokens. Instead we surface a `tracing::warn!` (naming the protocol so
/// the operator can locate the misconfigured lane) and OMIT the header entirely (empty Vec). The
/// request is still sent (the trait can't refuse it here) and the upstream answers 401, but the warn
/// line tells the operator the lane's credential bytes are invalid. The key is NEVER logged (it is the
/// secret); only the protocol name and the fact that the bytes are malformed.
pub(crate) fn bearer_auth_headers(proto: &str, key: &str) -> Vec<(HeaderName, HeaderValue)> {
    match HeaderValue::from_str(&format!("Bearer {key}")) {
        Ok(value) => vec![(HeaderName::from_static(HDR_AUTHORIZATION), value)],
        Err(_) => {
            tracing::warn!(
                protocol = proto,
                "authorization credential contains invalid header bytes (ASCII control character); \
                 omitting auth header — upstream will reject with 401"
            );
            Vec::new()
        }
    }
}

/// Decompose an OpenAI/Responses `image_url` string into the IR `(media_type, data)` pair. Shared
/// verbatim by `openai_chat.rs` and `openai_responses.rs` (both surfaces use the same `image_url` wire shape).
///
/// A `data:<mime>;base64,<payload>` URI is decomposed into its real MIME type ("image/png") and raw
/// base64 payload, matching the IR contract the Anthropic reader/writer use for base64 images. Any
/// other URL (an https reference, or a data URI we cannot confidently split) is preserved verbatim in
/// `data` with an "image_url" media_type sentinel so the writer can reconstruct the exact original
/// `image_url` on a same-protocol round-trip rather than mangling it.
pub(crate) fn parse_image_url(url: &str) -> crate::ir::IrImageSource {
    if let Some(rest) = url.strip_prefix("data:") {
        if let Some((meta, payload)) = rest.split_once(',') {
            // meta is e.g. "image/png;base64" or "image/png" — keep only the MIME type.
            let media_type = meta.split(';').next().unwrap_or("").to_string();
            if meta.contains("base64") && !media_type.is_empty() {
                return crate::ir::IrImageSource::Base64 {
                    media_type,
                    data: payload.to_string(),
                };
            }
        }
    }
    // Non-data URL (https://...) or an unrecognized data URI: keep it verbatim as a URL reference so
    // the writer round-trips it as-is rather than mangling it.
    crate::ir::IrImageSource::Url(url.to_string())
}

/// Reconstruct an OpenAI/Responses `image_url` string from an [`crate::ir::IrImageSource`] — the
/// inverse of [`parse_image_url`]. A `Url` is emitted verbatim; a `Base64` is re-wrapped into a
/// `data:<mime>;base64,<payload>` URI. A `Vendor` reference has no `image_url` projection, so
/// returns `None` and the caller drops the block with a warn. Shared by `openai_chat.rs` and `openai_responses.rs`.
pub(crate) fn image_url_from_ir(source: &crate::ir::IrImageSource) -> Option<String> {
    match source {
        crate::ir::IrImageSource::Url(url) => Some(url.clone()),
        crate::ir::IrImageSource::Base64 { media_type, data } => {
            Some(format!("data:{media_type};base64,{data}"))
        }
        // An opaque vendor reference has no neutral `image_url` projection.
        crate::ir::IrImageSource::Vendor { .. } => None,
    }
}

/// True when an image source is a vendor-scoped reference with no neutral form — a foreign writer
/// that sees one must skip the image with a `tracing::warn!` instead of emitting a corrupt block. The
/// PRODUCING protocol re-emits its own `Vendor` reference same-protocol and does NOT route through
/// here (it matches its own `vendor` tag first).
pub(crate) fn is_unresolvable_image_ref(source: &crate::ir::IrImageSource) -> bool {
    matches!(source, crate::ir::IrImageSource::Vendor { .. })
}

/// True when an IR block is a structured-json tool-result content block ([`crate::ir::IrBlock::Json`])
/// rather than text/image — used by NON-Bedrock ToolResult writers to drop-with-warn it (there is no
/// lossless cross-protocol projection of a Bedrock `{"json":…}` tool-result).
pub(crate) fn is_json_tool_result_block(block: &crate::ir::IrBlock) -> bool {
    matches!(block, crate::ir::IrBlock::Json(_))
}

/// Conservative fallback for the `max_tokens` injected at a translation boundary when the source
/// protocol omitted it (legal for OpenAI) but the target REQUIRES it (Anthropic, Bedrock — see
/// `ProtocolWriter::requires_max_tokens`). Used only when the lane has no configured
/// `default_max_tokens`. 4096 is a safe output ceiling across current chat models — large enough
/// not to truncate typical completions, small enough not to be refused.
pub(crate) const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Mixed-case base62 alphabet (digits + lowercase + uppercase, no `-`/`_`) and the rejection-sampling
/// threshold used when synthesizing opaque ids for protocols whose native ids are flat random tokens
/// (Gemini `responseId`, Responses `msg_`/`fc_`/`resp_` suffixes). Hoisted here as the single source
/// of truth so the two id generators cannot drift on the character set or the bias-elimination cutoff
/// — `REJECT_THRESHOLD` is the largest multiple of 62 that fits in a `u8` (62 × 4 = 248); a draw in
/// `0..248` maps uniformly via `% 62`, a draw `>= 248` is rejected and redrawn.
pub(crate) const BASE62_ALPHABET: &[u8; 62] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub(crate) const BASE62_REJECT_THRESHOLD: u8 = 248;

/// Client-visible detail string for a mid-stream abort (the upstream connection dropped or a
/// translate step failed after first byte). Lives in the proto layer — the lowest common ancestor —
/// because BOTH `forward.rs` (SSE/forward abort path) and the Bedrock-eventstream reassembler in this
/// module emit it, and `forward.rs → proto` is the only legal dependency direction. Single source of
/// truth so the abort text a client sees is identical on every framing.
pub(crate) const STREAM_ABORT_DETAIL: &str = "The response stream was interrupted.";

/// The CANONICAL ingress-protocol classifier: infer the wire protocol a request targets from its
/// path prefix. This is the single source of truth shared by every site that must shape an error
/// (or otherwise reason about protocol) from a path alone — `auth.rs::unauthorized_response`,
/// `main.rs`'s fallback/405 handlers — so the auth-time and routing-time classifiers CANNOT drift
/// (a divergence here means the same `/model/foo/bar` path gets a Bedrock-shaped error from one
/// handler and an OpenAI-shaped error from another — an indistinguishability tell). Check order is
/// significant: the more specific Gemini/Bedrock surfaces are tested before the generic
/// `/v1/messages` / `/v1/chat/completions` suffixes.
///
/// The `/model/...` arm REQUIRES the `/converse` or `/converse-stream` suffix before classifying as
/// bedrock: Bedrock's Converse API is `/model/<id>/converse[-stream]`, so a non-Converse `/model/...`
/// path (e.g. `/model/foo/bar`, or a pool literally named "model" hitting `/model/v1/messages`) must
/// NOT be handed a Bedrock-shaped envelope — it falls through to the `/v1/messages` (anthropic) arm
/// or the OpenAI default, matching what a real client speaking that protocol expects.
pub(crate) fn proto_for_path(path: &str) -> &'static str {
    if path.starts_with("/v1beta/models") {
        // `/v1beta/models/...` is a Gemini-only surface (OpenAI has no v1beta), so always Gemini.
        PROTO_GEMINI
    } else if path.starts_with("/v1/models/") {
        // `/v1/models/...` is ambiguous: Gemini packs a `:<action>` into the LAST path segment
        // (`/v1/models/gemini-pro:generateContent`), whereas the OpenAI SDK's `model.retrieve`
        // issues `GET /v1/models/{id}`. A naive `contains(':')` mis-classifies OpenAI model ids that
        // legitimately contain colons (fine-tuned `ft:gpt-3.5-turbo:my-org::abc123`, deployment-style
        // `gpt-4o:deployment`) as Gemini, handing a real OpenAI `model.retrieve` an undecodable Gemini
        // error envelope. Distinguish the Gemini `:<action>` form by matching ONLY the known Gemini
        // method suffixes; anything else (including colon-bearing OpenAI model ids) → OpenAI.
        let last_segment = path.rsplit('/').next().unwrap_or("");
        const GEMINI_ACTIONS: [&str; 7] = [
            ":generateContent",
            ":streamGenerateContent",
            ":countTokens",
            ":embedContent",
            ":batchGenerateContent",
            ":generateAnswer",
            ":batchEmbedContents",
        ];
        if GEMINI_ACTIONS.iter().any(|a| last_segment.ends_with(a)) {
            PROTO_GEMINI
        } else {
            PROTO_OPENAI
        }
    } else if path.starts_with("/model/")
        && (path.ends_with("/converse") || path.ends_with("/converse-stream"))
    {
        PROTO_BEDROCK
    } else if path == "/v1/messages" || path.ends_with("/v1/messages") {
        PROTO_ANTHROPIC
    } else if path == "/v1/chat/completions" {
        PROTO_OPENAI
    } else if path == "/v2/chat" {
        PROTO_COHERE
    } else if path == "/v1/responses" {
        PROTO_RESPONSES
    } else {
        // Unknown ingress: fall back to the widely-understood OpenAI envelope.
        PROTO_OPENAI
    }
}

/// The vendor-plausible auth-failure wire MESSAGE for an ingress protocol. This string lands verbatim
/// in the native error body (`error.message` for anthropic/openai/gemini/responses, the bare
/// top-level `message` for cohere, the `message` beside `__type` for bedrock). It MUST read like the
/// copy the REAL vendor returns for a bad/missing credential and carry NO busbar-internal vocabulary
/// ("lane", "virtual key", "passthrough", …): any such word is a deterministic protocol tell that
/// also discloses busbar's auth model. Canonical source of truth; `auth.rs::vendor_auth_failure_message`
/// is a thin delegation wrapper to this, not a copy. Strings sampled from real 401/403 bodies:
///   anthropic → "invalid x-api-key"; openai/responses → "Incorrect API key provided.";
///   gemini → "API key not valid. Please pass a valid API key."; cohere → "invalid api token";
///   bedrock → "" (AWS conveys AccessDenied via __type / x-amzn-errortype, not message prose).
///
/// Thin wrapper: dispatches through `ProtocolWriter::auth_failure_message` so the per-vendor copy
/// lives in the writer vtable, not in this agnostic function. An unknown future proto falls back to
/// the default generic copy.
pub(crate) fn vendor_auth_failure_message(proto: &str) -> &'static str {
    protocol_for(proto)
        .map(|p| p.writer().auth_failure_message())
        .unwrap_or("authentication failed")
}

/// ProtocolReader extracts signals from wire responses (Stage 1a + 1b).
/// Methods are provider-specific normalizers that feed the breaker's Stage 2 classifier.
pub(crate) trait ProtocolReader: Send + Sync {
    /// Extract raw error info from HTTP response without classifying.
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError;

    /// Classify a response into a canonical signal in one call (convenience over
    /// `extract_error` + `normalize_raw_error`). The release path runs those two stages explicitly
    /// (so it can apply the lane's `error_map`); this all-in-one form has no production caller and
    /// exists solely to back the per-protocol classification unit tests, so it is compiled only
    /// under `#[cfg(test)]` and kept out of the 1.0 binary.
    #[cfg(test)]
    fn classify(&self, status: StatusCode, body: &[u8]) -> CanonicalSignal;

    /// Read an IR request from wire JSON.
    fn read_request(&self, body: &serde_json::Value) -> Result<crate::ir::IrRequest, IrError>;

    /// Read a single response/stream event from already-de-framed SSE data.
    ///
    /// Default: delegate to the canonical fan-out [`read_response_events`] over a fresh decode
    /// state and surface its FIRST IR event. Every protocol whose live translation path is the
    /// plural fan-out (OpenAI, Gemini, Cohere, Responses, Bedrock) inherits this default — the
    /// singular form exists only to satisfy the trait and has no production caller on those
    /// protocols. Delegating (rather than a dead `None` stub) guarantees that if the call-path
    /// invariant is ever broken, an event degrades to 1:1 rather than being SILENTLY swallowed — a
    /// silent drop is both a correctness failure and hard to diagnose. A chunk that maps to several
    /// IR events loses the trailing ones through this 1:1 adapter (exactly why production uses the
    /// plural path), but nothing is dropped wholesale. Never panics on the request path:
    /// `StreamDecodeState::default()` is infallible and the fan-out is total. Anthropic overrides
    /// this with its native 1:1 singular implementation (its plural form wraps the singular).
    fn read_response_event(
        &self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        let mut state = crate::ir::StreamDecodeState::default();
        self.read_response_events(event_type, data, &mut state)
            .into_iter()
            .next()
    }

    /// Fan-out variant: one wire event/chunk → 0..n IR stream events, threading
    /// per-request decode state. Anthropic is 1:1 (wraps the singular, ignores state); OpenAI's
    /// flat stream synthesizes block boundaries via the state. This is the general translation
    /// API the live response-translation path calls.
    fn read_response_events(
        &self,
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent>;

    /// Read a whole (non-streaming) response from wire JSON.
    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError>;

    /// True when THIS protocol authenticates INBOUND requests with AWS SigV4 (an access-key-id +
    /// secret signature) rather than a bearer / api-key token — the Bedrock ingress shape. The
    /// front-door auth middleware consults this through the reader vtable to decide whether to run
    /// the SigV4 verification path for a request, instead of branching on the protocol NAME. The
    /// SigV4 verification itself stays in the auth layer (it needs the governance key lookup and the
    /// shared signing helpers, exactly like the bearer path) — only the "which protocol uses SigV4"
    /// metadata lives here. Default `false` (bearer / api-key protocols); BedrockReader overrides.
    fn uses_sigv4_ingress_auth(&self) -> bool {
        false
    }

    /// Clone this reader as a trait object.
    fn clone_box(&self) -> Box<dyn ProtocolReader>;
}

/// Per-request signing context. Most protocols' `auth_headers` ignore this; protocols that
/// sign the whole request (AWS SigV4 for Bedrock) need the method/host/path/body/time.
pub(crate) struct SigningContext<'a> {
    /// Upstream host (no scheme), e.g. `bedrock-runtime.us-east-1.amazonaws.com`.
    pub(crate) host: String,
    /// URI-encoded request path (no query), e.g. `/model/anthropic.claude%3A0/converse`.
    pub(crate) canonical_uri: String,
    /// The exact request body bytes that will be sent.
    pub(crate) body: &'a [u8],
    /// Unix epoch seconds at signing time.
    pub(crate) timestamp_epoch: u64,
    /// The UPSTREAM-credential mode for this request. Lets a writer resolve a credential whose scheme
    /// is otherwise ambiguous (e.g. Anthropic's API-key-vs-Bearer choice) to the single native header
    /// the mode implies — `Passthrough` forwards the caller's Bearer token; `Own` presents the
    /// configured-key shape. Without it, an ambiguous credential must emit BOTH headers, which is an
    /// upstream-distinguishability tell no native client produces. (The upstream-credential concern,
    /// split out of the front-door auth mode in slice 2d.)
    pub(crate) upstream_creds: crate::auth::UpstreamCreds,
}

/// ProtocolWriter rewrites intents for the upstream wire format.
pub(crate) trait ProtocolWriter: Send + Sync {
    /// Returns the upstream path suffix (e.g., "/v1/messages").
    fn upstream_path(&self) -> &str;

    /// the upstream path for a specific model. Most protocols ignore the model and
    /// return a fixed path (the default); Gemini's path embeds the model
    /// (`/v1beta/models/{model}:generateContent`). `forward` uses this to build the URL.
    fn upstream_path_for(&self, _model: &str) -> String {
        self.upstream_path().to_string()
    }

    /// Per-request upstream path that also knows whether the caller wants a streamed response.
    /// Defaults to `upstream_path_for` (most protocols use one path for both stream and non-stream).
    /// Gemini overrides it: streaming uses `:streamGenerateContent?alt=sse`, non-streaming
    /// `:generateContent`.
    fn upstream_path_for_stream(&self, model: &str, _stream: bool) -> String {
        self.upstream_path_for(model)
    }

    /// Returns auth headers given an API key.
    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)>;

    /// Per-request auth, given the signing context. Defaults to the static `auth_headers` (bearer /
    /// api-key protocols ignore `ctx`). Bedrock overrides this to compute AWS SigV4 headers,
    /// which depend on the method/host/path/body/timestamp.
    fn sign_request(&self, key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        self.auth_headers(key)
    }

    /// Rewrites the model field in the request body, returning whether the body actually CHANGED.
    ///
    /// The default inserts/overwrites a top-level `"model"` string — the shape every JSON-body
    /// protocol (Anthropic, Cohere, OpenAI, Gemini, Responses) needs. `BedrockWriter` overrides
    /// this with a no-op (returns `false`) because the target model is carried in the request URL,
    /// not the body.
    ///
    /// The return value is the structural coupling that drives request pristine-tracking (Change B):
    /// it reports `true` ONLY when the value truly changes (the existing `model` differs from the
    /// authoritative lane model, or no `model` was present), so a same-protocol passthrough whose
    /// client already sent the canonical model name stays pristine and can short-circuit.
    fn rewrite_model_if_needed(&self, body: &mut serde_json::Value, model: &str) -> bool {
        if let Some(obj) = body.as_object_mut() {
            // Only an ACTUAL change counts: if the body already carries exactly this model string,
            // the insert is a no-op and the body is unchanged (stays pristine).
            if obj.get("model").and_then(|m| m.as_str()) == Some(model) {
                return false;
            }
            obj.insert("model".to_string(), serde_json::json!(model));
            return true;
        }
        false
    }

    /// Write an IR request to wire JSON.
    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value;

    /// Whether this protocol REQUIRES `max_tokens` on every request. The Anthropic Messages API
    /// hard-rejects (400 `max_tokens: Field required`) a request without it, whereas OpenAI Chat
    /// Completions treats it as optional (the server applies a default) — and Bedrock Converse
    /// likewise defaults it. When this returns `true` and a cross-protocol-translated request
    /// carries no `max_tokens`, the forward path injects the lane's `default_max_tokens` (or
    /// `DEFAULT_MAX_TOKENS`) so source-optional clients keep working across the translation
    /// boundary. Default: `false` (source-optional == target-optional).
    fn requires_max_tokens(&self) -> bool {
        false
    }

    /// Whether this writer projects the IR's `cache_control` breakpoints into a native wire
    /// marker that is MODEL-GATED — a schema key some deployed models hard-reject with a 400
    /// (Bedrock's `cachePoint`: Claude accepts it, Amazon Nova rejects it as "extraneous key
    /// [cachePoint] is not permitted"). When true, the cross-protocol seam clears the cache ask
    /// unless the lane declares the `prompt_caching` capability — the same operator-asserted
    /// posture as `reasoning`, so a translation can never 400 a model over a marker the caller's
    /// dialect allowed. Writers whose cache form is universally accepted by their API (Anthropic
    /// `cache_control`), or who emit no cache marker at all, keep the default `false` and need no
    /// capability flag. Same-protocol passthrough never consults this (byte-identical proxying:
    /// a caller speaking the egress dialect natively gets exactly what a direct call would).
    fn cache_markers_model_gated(&self) -> bool {
        false
    }

    /// Write a response/stream event to wire (event_type, data).
    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)>;

    /// Map a mid-stream `IrError` to a MODELED-EXCEPTION pair `(exception_name, message)` for
    /// protocols whose native stream signals errors with an out-of-band exception frame rather than a
    /// normal event. Only the AWS Bedrock event-stream wire distinguishes this: a native AWS SDK
    /// dispatches errors off the `:message-type: exception` / `:exception-type` headers, which can only
    /// be produced by `eventstream::encode_exception_frame` — NOT by `write_response_event`, whose
    /// `(event_type, json)` pair is always framed `:message-type: event`. `StreamTranslate` calls this
    /// for a Bedrock-INGRESS stream when the IR event is `IrStreamEvent::Error`, so the client receives
    /// the typed Converse exception it expects instead of a silently-dropped `event`-typed frame.
    ///
    /// Returns `None` by default: every SSE-framed protocol (openai/anthropic/gemini/cohere/responses)
    /// carries its error in-band via `write_response_event`, so the StreamTranslate caller falls back
    /// to the normal event path for them. Only `BedrockWriter` overrides this.
    fn write_response_exception(&self, _err: &IrError) -> Option<(String, String)> {
        None
    }

    /// Write a whole (non-streaming) response to wire JSON.
    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value;

    /// Render a router/forward/auth-layer error as this protocol's NATIVE error envelope, so a
    /// client on the vendor's official SDK gets the typed exception it expects instead of a
    /// plain-text body it cannot decode (the §8.1 / Unit I transparency gap). `status` is the HTTP
    /// status to be sent (informational; the envelope body may also embed it, e.g. Gemini's
    /// `error.code`); `kind` is a protocol-appropriate error type/category string (e.g.
    /// `"invalid_request_error"`, `"not_found"`); `message` is the human-readable detail.
    ///
    /// Regardless of protocol, the returned JSON MUST be served with
    /// `content-type: application/json` (every vendor's error envelope is JSON — OpenAI, Anthropic,
    /// Gemini, Cohere, Responses, and the Bedrock Converse error shape alike).
    ///
    /// All six registered protocols (OpenAI `{"error":{"message","type","code"}}`, Anthropic
    /// `{"type":"error","error":{"type","message"}}`, Gemini `{"error":{"code","message","status"}}`,
    /// Cohere, Responses, Bedrock `{"__type","message"}`) OVERRIDE this default with their native
    /// envelope. The default returns a generic `{"error":{"message":message,"type":kind}}` and is the
    /// catch-all only for a future 7th protocol that omits an override (a maintainer adding one should
    /// supply a native envelope, or a client on that protocol gets this generic — non-native — shape).
    ///
    /// This method IS on the live request path: it is dispatched via the writer vtable from the
    /// router/auth/forward error sites (`ingress::ingress_error`, `auth`, `proxy::ingress_error`).
    /// Only the default *body* is unreachable in release (every concrete writer overrides it), so no
    /// dead-code suppression is needed here.
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        serde_json::json!({
            "error": {
                "message": message,
                "type": kind,
            }
        })
    }

    /// Native HTTP status a quota/budget-exhaustion rejection maps to for THIS protocol. Most vendors
    /// surface over-quota as `429 Too Many Requests` (the default); Bedrock's
    /// `ServiceQuotaExceededException` is a `400`-class error. The agnostic governance guard calls
    /// this through the writer vtable instead of branching on the protocol name, so a 7th protocol
    /// gets the default until it overrides. The wrong status here is a vendor-indistinguishability
    /// tell on an over-budget rejection.
    fn quota_exceeded_status(&self) -> StatusCode {
        StatusCode::TOO_MANY_REQUESTS
    }

    /// Attach any protocol-specific RESPONSE HEADERS a native endpoint always carries on an error
    /// response, given the already-built error `envelope` and canonical `kind`. Default no-op (most
    /// protocols carry the error entirely in the body). Bedrock attaches `x-amzn-RequestId` +
    /// `x-amzn-errortype`; Anthropic mirrors the body `request_id` into the `request-id` header. The
    /// agnostic error path (`proxy::ingress_error`) calls this through the writer vtable instead of
    /// branching on the protocol name, so the main/degraded/auth/route error paths cannot drift.
    fn attach_error_response_headers(
        &self,
        _headers: &mut axum::http::HeaderMap,
        _kind: &str,
        _envelope: &serde_json::Value,
    ) {
    }

    /// True when this protocol's INGRESS client decodes a binary `application/vnd.amazon.eventstream`
    /// body (a native AWS SDK Bedrock client). A mid-stream error must then be a BINARY exception
    /// frame, not an SSE `event: error` text frame — writing SSE text into a binary eventstream body
    /// yields an undecodable prelude/CRC for the SDK's decoder. The agnostic `FirstByteBody`
    /// constructor calls this through the writer vtable instead of `ingress_protocol == "bedrock"`,
    /// so the eventstream path is gated by the protocol itself, not by its name.
    ///
    /// Default: `false` (every SSE-framed protocol). Only `BedrockWriter` overrides to `true`.
    fn ingress_is_eventstream(&self) -> bool {
        false
    }

    /// True when THIS protocol's streamed (SSE) response ends with the literal `data: [DONE]`
    /// terminator — the OpenAI Chat Completions convention. busbar reproduces it when emitting an
    /// openai-format stream back to an openai-ingress client on a cross-protocol hop. Default `false`
    /// (Responses uses typed terminal events; Anthropic/Gemini/Cohere have their own framing; Bedrock
    /// is binary eventstream); OpenAiWriter overrides → true. Consulted via the vtable by
    /// `StreamTranslate::new` so that constructor carries no `ingress == "openai"` name-branch.
    fn emits_sse_done_terminator(&self) -> bool {
        false
    }

    /// The MAXIMUM number of citations this protocol's streamed `citations_delta`-equivalent wire
    /// event may carry, or `None` for no limit. Anthropic frames EXACTLY ONE `citation` per
    /// `citations_delta` SSE event (a native SDK `JSON.parse`s one object per `data:` line and crashes
    /// on an array), so `AnthropicWriter` overrides → `Some(1)`; `StreamTranslate` then fans a multi-
    /// citation `CitationsDelta` into N single-citation deltas at the framing seam. Default `None`
    /// (Gemini legitimately coalesces N sources into one candidate-level `citationMetadata` chunk; the
    /// others have no per-event citation limit). Consulted via the vtable so the translator carries no
    /// `ingress == "anthropic"` name-branch for this wire constraint.
    fn max_citations_per_delta(&self) -> Option<usize> {
        None
    }

    /// The streaming `Content-Type` this protocol's INGRESS client expects when receiving a
    /// cross-protocol reframed stream. On a cross-protocol reframe the streamed body is re-encoded
    /// into the client's framing, so the response header must describe the CLIENT's wire format —
    /// copying the upstream CT verbatim would mislabel the body (e.g. a Bedrock-egress
    /// `application/vnd.amazon.eventstream` reaching an SSE client, or vice versa).
    ///
    /// Default: `"text/event-stream"` (openai/anthropic/gemini/cohere/responses). `BedrockWriter`
    /// overrides to `"application/vnd.amazon.eventstream"`. The agnostic forward path calls this
    /// through the writer vtable so `ingress_stream_content_type` carries no `"bedrock"` branch.
    fn streaming_content_type(&self) -> &'static str {
        crate::proxy::TEXT_EVENT_STREAM
    }

    /// Plausible native-SDK `User-Agent` for THIS EGRESS protocol. reqwest sends NO default
    /// User-Agent unless one is set, so without this every proxied upstream request reaches the
    /// backend with no UA at all — a trivial backend-side fingerprint distinguishing busbar-proxied
    /// traffic from a native vendor SDK (which always sends a recognizable UA). Each writer returns
    /// the string its real first-party SDK emits. The agnostic forward path calls this through the
    /// writer vtable instead of the name-match in `egress_user_agent`, so adding a 7th protocol
    /// only requires an override here, not a new branch in the core.
    ///
    /// Default: `EGRESS_UA_DEFAULT` from forward.rs — a generic-but-present UA for unknown egress
    /// (better than none). Each registered writer overrides with its own pinned SDK UA string (see
    /// `EGRESS_UA_*` in forward.rs for the per-protocol UA strings that must be kept current).
    fn egress_user_agent(&self) -> &'static str {
        crate::proxy::EGRESS_UA_DEFAULT
    }

    /// Native-SDK `Accept` header for THIS EGRESS protocol, given the caller's stream intent.
    /// A native SDK always sends one; omitting it is a backend-side proxy fingerprint, especially on
    /// the Bedrock egress where botocore sends `application/vnd.amazon.eventstream` on a
    /// ConverseStream call. The agnostic forward path calls this through the writer vtable instead of
    /// the name-match in `egress_accept`, so the core never branches on `"bedrock"`.
    ///
    /// Default: `text/event-stream` when streaming, `application/json` otherwise (the shape shared
    /// by anthropic/openai/responses/gemini/cohere). `BedrockWriter` overrides: eventstream when
    /// streaming, `application/json` otherwise.
    fn egress_accept(&self, wants_stream: bool) -> &'static str {
        if wants_stream {
            crate::proxy::TEXT_EVENT_STREAM
        } else {
            crate::proxy::APPLICATION_JSON
        }
    }

    /// True when this protocol carries the model identifier IN THE URL PATH rather than in the
    /// request body. Gemini encodes it as `/v1beta/models/{model}:generateContent` and Bedrock as
    /// `/model/{id}/converse`; for both, the body `model` field must be STRIPPED on the same-protocol
    /// passthrough path (the native backend rejects an unexpected body field and the model is already
    /// encoded in the signed/constructed URL). Body-model protocols (anthropic/openai/responses/cohere)
    /// return `false` (the default) and keep the field untouched. The agnostic
    /// `strip_same_protocol_model_shim` calls this through the writer vtable instead of
    /// `matches!(ingress_protocol, "gemini" | "bedrock")`, so a 7th url-model protocol only needs an
    /// override here, not a new arm in the core.
    ///
    /// Default: `false` (body-model protocols). Only `GeminiWriter` and `BedrockWriter` override to
    /// `true`.
    fn has_model_in_url(&self) -> bool {
        false
    }

    /// The HTTP status and protocol-agnostic error `kind` a bad/missing credential yields for THIS
    /// protocol. The pair is chosen to match what the genuine vendor returns for a bad API key,
    /// because the status code and the writer-mapped `error.type`/`error.status` are both deterministic
    /// protocol tells a native SDK keys its typed exception off:
    ///   - bedrock → HTTP 403 + "auth": a real SigV4 rejection is 403 AccessDenied (NOT 401).
    ///   - gemini  → HTTP 400 + "invalid_request_error": the Generative Language API does NOT return
    ///     401/UNAUTHENTICATED for a bad API key; it returns HTTP 400 with `error.status:
    ///     "INVALID_ARGUMENT"` (google.rpc.Code; the gemini writer maps `invalid_request_error` →
    ///     INVALID_ARGUMENT and echoes `code: 400`). A 401/UNAUTHENTICATED body would be a tell.
    ///   - openai / responses → HTTP 401 + "authentication_error": the genuine OpenAI/Responses
    ///     bad-key 401 body carries `error.code: "invalid_api_key"`. We pass `authentication_error`
    ///     so the wire body carries the real `code: "invalid_api_key"` pairing.
    ///   - anthropic / cohere / unknown → HTTP 401 + "authentication_error": the standard
    ///     bad-credential shape for those vendors.
    ///
    /// `BedrockWriter` and `GeminiWriter` override; all other writers use the default. The agnostic
    /// `auth::auth_failure_status_and_kind` dispatches through this vtable instead of a match on the
    /// protocol name, so the core never branches on `"bedrock"` or `"gemini"` for auth-failure shaping.
    ///
    /// Default: `(StatusCode::UNAUTHORIZED, "authentication_error")` (openai/responses/anthropic/
    /// cohere/unknown).
    fn auth_failure_status_and_kind(&self) -> (StatusCode, &'static str) {
        (StatusCode::UNAUTHORIZED, crate::proxy::KIND_AUTHENTICATION)
    }

    /// When a Bedrock-ingress client requested a STREAMING response (`wants_stream`) but the upstream
    /// answered with a BUFFERED (non-SSE) 2xx body, the single translated `IrResponse` must be
    /// re-emitted as native binary eventstream frames rather than `application/json` — a Bedrock SDK's
    /// `ConverseStream` decoder expects binary-framed events and cannot parse a bare JSON body (hard
    /// SDK decode failure and a deterministic proxy tell).
    ///
    /// Returns `Some(bytes)` when this writer needs the buffered-to-stream synthesis path, `None` when
    /// the plain translated JSON body is correct (all non-Bedrock ingress protocols). The returned bytes
    /// are the complete binary eventstream payload; the caller emits them under
    /// `writer.streaming_content_type()` so the Content-Type header matches the framing.
    ///
    /// Default: `None` (every SSE-framed protocol — a plain JSON body is acceptable).
    /// `BedrockWriter` overrides: returns `Some(bedrock_response_to_eventstream(ir, elapsed_ms))`.
    fn wrap_buffered_as_stream(
        &self,
        _ir: &crate::ir::IrResponse,
        _elapsed_ms: Option<u64>,
    ) -> Option<Vec<u8>> {
        None
    }

    /// Inject any protocol-required per-response metrics into a translated buffered response body
    /// (a `serde_json::Value` produced by `write_response`), if timing is available.
    ///
    /// Bedrock's non-stream `Converse` response ALWAYS carries `metrics.latencyMs` (the AWS SDK
    /// surfaces it via `ConverseOutput::metrics().latency_ms()`). The bedrock writer's `write_response`
    /// deliberately omits it (the writer is unaware of wall-clock time); the agnostic forward path
    /// injects it here — matching the live streaming path which injects it into the `metadata` frame.
    /// OMIT rather than fabricate a tell-tale `0` when timing is unavailable.
    ///
    /// Default: no-op (all non-Bedrock protocols carry no timing field in the response body).
    /// `BedrockWriter` overrides: inserts `metrics: { latencyMs: ms }` when both `elapsed_ms` is
    /// `Some` AND `value` is a JSON object (same double-`Some` guard the original inline branches use).
    fn inject_response_metrics(&self, _value: &mut serde_json::Value, _elapsed_ms: Option<u64>) {}

    /// True when this protocol's INGRESS client expects `x-amzn-RequestId` (and, on error paths,
    /// `x-amzn-errortype`) on every response — 2xx, stream, and error. A real AWS Bedrock endpoint
    /// always sends these headers; their absence is a detectable proxy tell and leaves the AWS SDK's
    /// `request_id()` returning `None`.
    ///
    /// Used as the predicate at the four category-3 sites in `forward.rs` (header capture before body
    /// consumption, 2xx buffered attach, streaming 2xx attach, degraded error attach). The header-attach
    /// bodies remain inline; only the name-branch `if ingress_protocol == "bedrock"` is replaced with
    /// `if writer.ingress_relays_amzn_headers()`, removing the provider-name string from the
    /// agnostic core while keeping the intricate `Builder`-move header flow untouched.
    ///
    /// Default: `false` (all non-Bedrock protocols never emit `x-amzn-*` headers).
    /// `BedrockWriter` overrides: `true`.
    fn ingress_relays_amzn_headers(&self) -> bool {
        false
    }

    /// The request-id RESPONSE HEADER (name + value) to ATTACH to a 2xx/relay response on THIS
    /// protocol's INGRESS path, or `None` when no header is attached. This is the SUCCESS-path analog
    /// of `attach_error_response_headers`, dispatched through the writer vtable so the agnostic forward
    /// path (`maybe_attach_response_request_id`) names no protocol module for request-id synthesis.
    ///
    /// Both bedrock and anthropic do `upstream_request_id.map(String::from).or_else(synth)`: the
    /// captured UPSTREAM id is preferred (so a same-protocol passthrough forwards the real native id),
    /// else a shape-correct one is synthesized (the cross-protocol case, where the caller passes `None`).
    /// - `BedrockWriter` → `(HDR_AMZN_REQUEST_ID, upstream-or-synth UUID)` — a real ConverseStream
    ///   always carries `x-amzn-RequestId`.
    /// - `AnthropicWriter` → `(HDR_REQUEST_ID, upstream-or-synth req_…)` — a real Anthropic response
    ///   always carries `request-id` (the SDK reads it into `APIError.request_id`).
    ///
    /// Default: `None` (no other protocol attaches a request-id header on the success path).
    fn ingress_response_request_id(
        &self,
        _upstream_request_id: Option<&str>,
    ) -> Option<(&'static str, String)> {
        None
    }

    /// The UPSTREAM response header NAMES this protocol's same-protocol passthrough forwards VERBATIM
    /// on a relay (read from the upstream response, re-emitted on the client response). Exposed through
    /// the vtable so the agnostic forward path reads/forwards them by iterating this list, naming no
    /// protocol module.
    ///
    /// - `BedrockWriter` → `["x-amzn-requestid", "x-amzn-errortype"]` (a native Bedrock response carries
    ///   both; AWS SDKs dispatch the typed exception from `x-amzn-errortype` BEFORE the body `__type`).
    /// - `AnthropicWriter` → `["request-id"]`.
    ///
    /// Default: `&[]` (no relayed headers).
    fn ingress_relayed_response_header_names(&self) -> &'static [&'static str] {
        &[]
    }

    /// The vendor-plausible auth-failure wire MESSAGE for THIS protocol — the per-vendor prose that
    /// lands verbatim in the native error body on a bad/missing credential. Dispatched through the
    /// vtable so `auth.rs` names no protocol string for this decision. Strings sampled from real
    /// 401/403 bodies (see the former `vendor_auth_failure_message` doc). Default: a generic
    /// `"authentication failed"`; each vendor writer overrides with its sampled copy.
    fn auth_failure_message(&self) -> &'static str {
        "authentication failed"
    }

    /// True when this protocol's INGRESS client expects a STREAMING response body in the JSON-array
    /// streaming format (NOT SSE). Gemini clients that send a `:streamGenerateContent` request
    /// WITHOUT `?alt=sse` expect an array-framed JSON stream; the route layer signals this via the
    /// `GEMINI_JSON_ARRAY_SHIM_KEY` in the request body, and the forward path gates on this predicate
    /// (AND the shim key) to enable `GeminiJsonArrayFramer`. Gating on the vtable — not the name
    /// string — prevents a body-model client from smuggling the shim key to force JSON-array reframing
    /// of its own SSE stream (that would be undecodable and a router behaviour no native backend
    /// exhibits).
    ///
    /// Default: `false` (openai/anthropic/bedrock/cohere/responses all use SSE or binary framing).
    /// `GeminiWriter` overrides: `true`.
    fn uses_array_stream_shim(&self) -> bool {
        false
    }

    /// True when this protocol has a NATIVE path-not-found error envelope with a protocol-specific
    /// message format, as opposed to the canonical `not_found_error` OpenAI-shape used by all other
    /// protocols. Gemini native NOT_FOUND responses carry a structured message naming the resource
    /// path and API version; for all other protocols the generic envelope is correct.
    ///
    /// Used at two sites in `route.rs` (no-colon path and unsupported-action path) to gate the
    /// Gemini-native NOT_FOUND envelope without branching on the name string `"gemini"`.
    ///
    /// Default: `false` (all non-Gemini protocols use the canonical OpenAI-shape NOT_FOUND).
    /// `GeminiWriter` overrides: `true`.
    fn has_native_path_not_found(&self) -> bool {
        false
    }

    /// Build a minimal, protocol-correct request body for an active health probe of `model`.
    /// Serializes a one-token "ping" through this protocol's own `write_request`, so every protocol
    /// gets a valid probe body for free — no per-protocol probe code, no extra dependency.
    fn probe_body(&self, model: &str) -> Vec<u8> {
        use crate::ir::{IrBlock, IrMessage, IrRequest, IrRole};
        let ir = IrRequest {
            reasoning: None,
            reasoning_budgets: None,
            logprobs: None,
            top_logprobs: None,
            user: None,
            parallel_tool_calls: None,
            system: vec![],
            messages: vec![IrMessage {
                role: IrRole::User,
                content: vec![IrBlock::Text {
                    text: "ping".to_string(),
                    cache_control: None,
                    citations: vec![],
                }],
            }],
            tools: vec![],
            max_tokens: Some(1),
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
        let mut body = self.write_request(&ir);
        let _ = self.rewrite_model_if_needed(&mut body, model);
        serde_json::to_vec(&body).unwrap_or_default()
    }

    /// Build the per-stream framing state for THIS protocol as an INGRESS (client-facing) writer.
    ///
    /// `StreamTranslate` calls this ONCE per stream on its ingress writer and holds the result as a
    /// `Box<dyn StreamFraming>`, then routes every protocol-specific stream-shape decision through it
    /// — so the translator names NO protocol's wire quirk. The framing is keyed to the
    /// INGRESS writer because it is what produces the client-facing bytes: the OpenAI per-chunk
    /// identity replay + include_usage trailing-usage un-fold is OpenAI-INGRESS only; the Bedrock
    /// messageStop/metadata two-frame deferral (and its finish-time flush) is Bedrock-INGRESS only.
    ///
    /// Default: a no-op [`PassthroughFraming`] (every SSE-framed protocol with no per-stream framing
    /// quirk). `OpenAiWriter` and `BedrockWriter` override it with their stateful impls (defined in
    /// their own modules), so deleting `proto/openai_chat.rs` or `proto/bedrock.rs` needs ZERO changes to
    /// the translator here.
    fn new_stream_framing(&self) -> Box<dyn StreamFraming> {
        Box::new(PassthroughFraming)
    }

    /// Build this protocol's array-stream framer (the JSON-array reframer engaged for a streaming
    /// response that must be delivered as a `[{...},{...}]` document instead of SSE), as a
    /// `Box<dyn JsonArrayFramer>`, or `None` when this protocol has no such framing. The agnostic
    /// forward path constructs the framer through this vtable method — gated by `uses_array_stream_shim()`
    /// — so it never names the gemini framer type. Default `None`; `GeminiWriter` overrides → `Some`.
    fn make_array_stream_framer(&self) -> Option<Box<dyn JsonArrayFramer>> {
        None
    }

    /// True when THIS ingress writer's client wants its streamed response reframed as a JSON array
    /// (rather than SSE) for the given request `body`. The forward path consults this — together with
    /// `uses_array_stream_shim()` — instead of reading any protocol-specific body key itself, so the
    /// core names no shim key. Default `false`; `GeminiWriter` overrides to read its router shim key
    /// from the body.
    fn wants_array_stream(&self, _body: &serde_json::Value) -> bool {
        false
    }

    /// The router-internal array-stream shim key this protocol injects into a request body (the key
    /// `wants_array_stream` reads), or `None` for protocols with no such shim. It is never native to
    /// any backend wire, so the forward path strips it from every outbound body; iterating the registry
    /// and removing each protocol's key lets the agnostic strip name no shim-key literal. Default
    /// `None`; `GeminiWriter` overrides → `Some(GEMINI_JSON_ARRAY_SHIM_KEY)`.
    fn array_stream_shim_key(&self) -> Option<&'static str> {
        None
    }

    /// Clone this writer as a trait object.
    fn clone_box(&self) -> Box<dyn ProtocolWriter>;
}

/// A streaming JSON-array reframer: consumes a protocol's SSE response bytes and re-emits them as one
/// streaming JSON array (`[{...},{...}]`), the body shape a non-SSE streaming request expects. The
/// agnostic forward path holds one `Box<dyn JsonArrayFramer>` (built via
/// [`ProtocolWriter::make_array_stream_framer`]) and drives it, so it names no protocol's framer type.
/// The sole implementor is `gemini::GeminiJsonArrayFramer` (Gemini `:streamGenerateContent` without
/// `?alt=sse`). The trait exposes only the SUBSET of that type's API the agnostic core needs (`feed`,
/// `finish_for_translate`, `finish_with_server_error`); the type's raw `finish` and its low-level
/// `finish_with_error(code, status, …)` are absent, since the core never passes a wire status code.
pub(crate) trait JsonArrayFramer: Send {
    /// Feed a chunk of SSE bytes; return JSON-array bytes for whatever complete frames are now
    /// available (empty if only a partial frame is buffered).
    fn feed(&mut self, chunk: &[u8]) -> Vec<u8>;

    /// Close the array at end-of-stream when this framer sits DOWNSTREAM of a cross-protocol
    /// `StreamTranslate`; pass `translate_aborted = StreamTranslate::aborted()` so a translate-side
    /// abort surfaces as a trailing error element instead of a silent truncation. Idempotent.
    fn finish_for_translate(&mut self, translate_aborted: bool) -> Vec<u8>;

    /// Terminate the array with a trailing protocol-shaped SERVER-ERROR element, then the closing `]`.
    /// Used on a mid-stream upstream transport failure (and on internal abort). The agnostic caller
    /// supplies only the human-readable `message`; the implementor owns the wire status/code shape (e.g.
    /// Gemini emits a `google.rpc.Status` with HTTP 500 / gRPC `INTERNAL`), so the core names no
    /// protocol wire value. Idempotent.
    fn finish_with_server_error(&mut self, message: &str) -> Vec<u8>;
}

/// Per-stream, INGRESS-keyed framing state for the shared [`StreamTranslate`] translator. This is the
/// vtable seam that keeps the agnostic-core translator from naming any protocol's wire shape:
/// every protocol-specific streaming decision the translator used to make inline — the OpenAI per-chunk
/// identity replay + include_usage trailing-usage un-fold, and the Bedrock messageStop/metadata
/// two-frame deferral with its finish-time flush — lives BEHIND this trait, implemented in the owning
/// protocol's module. The translator holds ONE `Box<dyn StreamFraming>` (built via
/// [`ProtocolWriter::new_stream_framing`] from the ingress writer) and consults it; it never branches
/// on a protocol name. The default [`PassthroughFraming`] impl is inert, so a protocol with no
/// per-stream framing quirk needs no override.
///
/// The translator keeps `emit_ir_event` as the emission primitive: the framing methods return WHAT to
/// emit (mutating a chunk in place, or returning the IR events / trailing chunk to frame), and the
/// translator does the actual framing. This preserves the exact byte-level emission order.
pub(crate) trait StreamFraming: Send {
    /// EGRESS-CHUNK seam (OpenAI ingress). Called for every reframed SSE `chat.completion.chunk` body
    /// the ingress writer produced, just before it is framed. Does two things, BOTH byte-shape-critical:
    /// (a) replays the latched stream identity (`id`/`created`/`model`) onto `chunk` in place — the
    /// opening chunk latches them, every later chunk (which the writer emits without them) gets them
    /// injected, so the whole stream shares ONE id like a genuine OpenAI stream; and (b) returns
    /// `Some(trailing)` when `chunk` is a usage-bearing finish chunk, having REMOVED the folded `usage`
    /// from `chunk` and re-homed it onto a separate trailing usage-only chunk (the include_usage
    /// un-fold). The translator then frames `chunk` and, if `Some`, the trailing chunk after it.
    ///
    /// Default ([`PassthroughFraming`]): no mutation, returns `None`.
    fn on_egress_chunk(&mut self, _chunk: &mut serde_json::Value) -> Option<serde_json::Value> {
        None
    }

    /// COMBINED-STOP-DELTA seam (Bedrock ingress). Called when the translator sees a combined
    /// `MessageDelta{stop_reason: Some, usage}`. Returns the IR events the translator must emit (via
    /// `emit_ir_event`) IN ORDER to reproduce a native ConverseStream's two-frame stop/metadata split,
    /// while updating internal state so EXACTLY ONE `metadata` frame is ever emitted for the stream. The
    /// returned vec is: always a stop-only delta (→ `messageStop`); plus a usage-only delta (→
    /// `metadata`) IFF real usage rode with the stop (else the metadata is DEFERRED to a trailing
    /// usage-only delta, or to `on_finish`). When this returns `Some`, the translator emits each event
    /// and consumes the original event (the inline path `continue`s).
    ///
    /// Default ([`PassthroughFraming`]): `None` — the translator falls through to its normal path.
    fn on_combined_stop_delta(
        &mut self,
        _stop_reason: crate::ir::IrStopReason,
        _stop_sequence: Option<String>,
        _usage: &crate::ir::IrUsage,
    ) -> Option<Vec<crate::ir::IrStreamEvent>> {
        None
    }

    /// USAGE-ONLY-DELTA seam (Bedrock ingress). Called for a trailing `MessageDelta{stop_reason: None}`
    /// (the OpenAI include_usage usage chunk, or a native usage frame). Returns `true` if the translator
    /// should EMIT this delta as the stream's single `metadata` frame, or `false` to SUPPRESS it (a
    /// `metadata` already rode with the stop). Updates internal state so the one-metadata invariant
    /// holds and resolves any pending deferral.
    ///
    /// Default ([`PassthroughFraming`]): returns `None` — the translator falls through to its normal
    /// path (this delta is not special-cased).
    fn on_usage_only_delta(&mut self) -> Option<bool> {
        None
    }

    /// FINISH seam (Bedrock ingress). Called once at end-of-stream. Returns `Some(event)` when a
    /// `metadata` frame was DEFERRED (a zero-usage stop with no trailing usage delta — the default
    /// OpenAI streaming case) and never resolved, so the translator must flush a single best-effort
    /// zero-usage `metadata` frame to honor the always-one-metadata invariant. Returns `None` when no
    /// flush is owed.
    ///
    /// Default ([`PassthroughFraming`]): `None`.
    fn on_finish(&mut self) -> Option<crate::ir::IrStreamEvent> {
        None
    }

    /// METADATA-METRICS seam (Bedrock ingress). Called in the eventstream-framing branch for each
    /// emitted frame with the frame's event-type, its just-built data object, and the stream's start
    /// instant. A native ConverseStream `metadata` frame carries `metrics.latencyMs`; the Bedrock impl
    /// injects the elapsed wall-clock into that one frame (omitting `metrics` entirely if timing is
    /// unavailable, rather than emitting a tell-tale `0`), mutating `data` in place. Keeps the wire
    /// event-type literal and the latency shape in the Bedrock module, out of the agnostic translator.
    ///
    /// Default ([`PassthroughFraming`]): no-op (no event-type is special).
    fn inject_streaming_metrics(
        &self,
        _event_type: &str,
        _data: &mut serde_json::Value,
        _started_at: Option<std::time::Instant>,
    ) {
    }

    /// STREAM-ABORT seam (eventstream ingress). The protocol-shaped error TYPE NAME this ingress emits
    /// as the terminal frame on an ABORTED stream (reassembly-buffer overflow / malformed prelude).
    /// `Some(name)` means "this ingress frames aborts as an eventstream exception of this type"
    /// (Bedrock → `InternalServerException`); the agnostic translator then emits a well-formed
    /// exception frame WITHOUT naming the wire type itself. `None` (default / every SSE protocol) →
    /// the translator takes its SSE-abort path instead. Keeps the wire exception name in the owning
    /// protocol module, out of the agnostic translator.
    fn abort_exception_type(&self) -> Option<&'static str> {
        None
    }
}

/// Inert default [`StreamFraming`]: every method takes the trait's no-op default. Used by every
/// protocol whose INGRESS stream carries no per-stream framing quirk (Anthropic/Gemini/Cohere/
/// Responses). Holds no state.
struct PassthroughFraming;

impl StreamFraming for PassthroughFraming {}

/// Bundled Protocol with name + reader + writer.
pub(crate) struct Protocol {
    name: &'static str,
    reader: Box<dyn ProtocolReader>,
    writer: Box<dyn ProtocolWriter>,
}

impl Clone for Box<dyn ProtocolReader> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl Clone for Box<dyn ProtocolWriter> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl Clone for Protocol {
    fn clone(&self) -> Self {
        Protocol {
            name: self.name,
            reader: self.reader.clone(),
            writer: self.writer.clone(),
        }
    }
}

impl Protocol {
    pub(crate) fn new<R, W>(name: &'static str, reader: R, writer: W) -> Self
    where
        R: ProtocolReader + 'static,
        W: ProtocolWriter + 'static,
    {
        Self {
            name,
            reader: Box::new(reader),
            writer: Box::new(writer),
        }
    }

    /// Returns the protocol name ("anthropic", "openai", etc.).
    pub(crate) fn name(&self) -> &str {
        self.name
    }

    /// Returns the reader for this protocol.
    pub(crate) fn reader(&self) -> &dyn ProtocolReader {
        self.reader.as_ref()
    }

    /// Returns the writer for this protocol.
    pub(crate) fn writer(&self) -> &dyn ProtocolWriter {
        self.writer.as_ref()
    }

    /// Construct an Anthropic protocol instance.
    pub(crate) fn anthropic() -> Self {
        Self::new(PROTO_ANTHROPIC, AnthropicReader, AnthropicWriter)
    }

    /// Construct an OpenAI protocol instance.
    pub(crate) fn openai() -> Self {
        Self::new(PROTO_OPENAI, OpenAiReader, OpenAiWriter)
    }

    /// Construct a Gemini protocol instance.
    pub(crate) fn gemini() -> Self {
        Self::new(PROTO_GEMINI, GeminiReader, GeminiWriter)
    }

    /// Construct an OpenAI Responses protocol instance.
    pub(crate) fn responses() -> Self {
        Self::new(PROTO_RESPONSES, ResponsesReader, ResponsesWriter)
    }

    /// Construct a Bedrock protocol instance.
    pub(crate) fn bedrock() -> Self {
        Self::new(PROTO_BEDROCK, BedrockReader, BedrockWriter)
    }

    /// Construct a Cohere (v2 chat) protocol instance.
    pub(crate) fn cohere() -> Self {
        Self::new(PROTO_COHERE, CohereReader, CohereWriter)
    }
}

/// Resolve a built-in Protocol by name (for ingress translation). Each call allocates two vtable
/// boxes (`Box<dyn ProtocolReader>` + `Box<dyn ProtocolWriter>`). Most reader/writer structs are
/// zero-sized, but a fresh instance is REQUIRED per request regardless: `GeminiWriter`,
/// `CohereWriter`, and `ResponsesWriter` carry per-STREAM mutable state (e.g. `Mutex<Vec<…>>`,
/// `AtomicU64`) seeded from their const constructors, so they must not be shared/cached across
/// concurrent requests. The allocations are small (empty collections) and confined to per-request
/// setup paths — never per-chunk loops. Registry SWEEPS that only need pure-by-name vtable facts
/// (`streaming_content_types`, `array_stream_shim_keys`) memoize their results to avoid repeating
/// these allocations on the hot path.
pub(crate) fn protocol_for(name: &str) -> Option<Protocol> {
    match name {
        PROTO_ANTHROPIC => Some(Protocol::anthropic()),
        PROTO_BEDROCK => Some(Protocol::bedrock()),
        PROTO_COHERE => Some(Protocol::cohere()),
        PROTO_GEMINI => Some(Protocol::gemini()),
        PROTO_OPENAI => Some(Protocol::openai()),
        PROTO_RESPONSES => Some(Protocol::responses()),
        _ => None,
    }
}

/// The set of streaming `Content-Type` values across all registered protocols' writers, cached once.
///
/// Sweeps `KNOWN_PROTOCOLS`, reading each writer's `streaming_content_type()` from the vtable (this is
/// the registry layer aggregating the writers — it names no MIME literal of its own), then sorts and
/// dedups into a stable `&'static [&'static str]`. The one-time `OnceLock` init pays the
/// `protocol_for` Box allocations; callers (e.g. `proxy::is_streaming_content_type`) then read the
/// cached slice with zero per-request allocation. The aggregated set is IDENTICAL to what the
/// per-request sweep produced — the cache only memoizes it.
pub(crate) fn streaming_content_types() -> &'static [&'static str] {
    static CACHE: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let mut v: Vec<&'static str> = KNOWN_PROTOCOLS
                .iter()
                .filter_map(|n| protocol_for(n).map(|p| p.writer().streaming_content_type()))
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        })
        .as_slice()
}

/// The set of array-stream shim keys across all registered protocols' writers, cached once.
///
/// Sweeps `KNOWN_PROTOCOLS`, reading each writer's `array_stream_shim_key()` (most return `None`;
/// only Gemini overrides → `GEMINI_JSON_ARRAY_SHIM_KEY`). Like `streaming_content_types`, the
/// `OnceLock` init pays the one-time `protocol_for` allocations so callers (e.g.
/// `proxy::strip_router_shim_keys`) iterate the cached slice with zero per-request allocation, and
/// the collected slice is sorted + deduped (mirroring `streaming_content_types`) so the set is stable
/// and unique regardless of registry order even if a second protocol ever overrides this key. The
/// collected set is IDENTICAL to the per-request sweep — the cache only memoizes it.
pub(crate) fn array_stream_shim_keys() -> &'static [&'static str] {
    static CACHE: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let mut v: Vec<&'static str> = KNOWN_PROTOCOLS
                .iter()
                .filter_map(|n| protocol_for(n).and_then(|p| p.writer().array_stream_shim_key()))
                .collect();
            v.sort_unstable();
            v.dedup();
            v
        })
        .as_slice()
}

/// The array-stream shim key for the NAMED protocol's writer, or `None` if that protocol has no
/// shim key (most don't) or is not registered. Routes through the writer vtable so the INJECTION
/// site (`ingress::ingress_path_model`, which sets the marker on a non-`alt=sse` Gemini request body)
/// names no protocol submodule — preserving "delete proto/X → app is X-free": if `proto/gemini.rs`
/// were removed, this returns `None` and the marker is simply never injected, with no compile-time
/// dependency on the submodule. Dispatch by protocol NAME string is the sanctioned registry boundary.
pub(crate) fn array_stream_shim_key_for(protocol_name: &str) -> Option<&'static str> {
    protocol_for(protocol_name).and_then(|p| p.writer().array_stream_shim_key())
}

/// The INGRESS protocol's NATIVE tool-call id prefix, used by [`ToolIdRemap`] to reshape a foreign
/// egress tool id into the ingress client's expected form. `None` means the protocol either carries
/// no tool id on the wire (Gemini correlates `functionCall`s by name; its writer ignores the IR
/// `ToolUse.id`) so no remap is meaningful, OR uses a free-form id with NO canonical prefix — for the
/// latter the foreign egress id passes through verbatim (no reshape on the response, no decode on the
/// request), the correct no-op.
fn native_tool_id_prefix(protocol_name: &str) -> Option<&'static str> {
    match protocol_name {
        // Anthropic `toolu_…`, OpenAI/Responses `call_…`, Bedrock `tooluse_…` are the documented
        // native shapes — each is a stable prefix the encode can prepend and the decode can gate on.
        PROTO_ANTHROPIC => Some("toolu_"),
        PROTO_OPENAI | PROTO_RESPONSES => Some("call_"),
        PROTO_BEDROCK => Some("tooluse_"),
        // Cohere tool ids are free-form with NO canonical prefix. An empty prefix would make the
        // reversibility marker (`bb1`) itself the only distinguishing signal, which collides with a
        // legitimate client-authored id of shape `bb1<even-len-hex-UTF8>` (e.g. `bb161626364` → the
        // decode silently rewrites it to `abcd`) — corrupting tool_use/tool_result correlation on a
        // Cohere-ingress cross-protocol hop. Return `None` (like Gemini) so Cohere ids pass through
        // verbatim: the egress id is never reshaped, so there is nothing to mis-decode on the echo.
        PROTO_COHERE => None,
        // Gemini carries no tool id on the wire — its writer drops `ToolUse.id` entirely — so there is
        // nothing to reshape and no risk of a foreign id leaking to a Gemini client.
        _ => None,
    }
}

/// Marker segment embedded in a busbar-minted tool id so the reverse (request) translation can tell a
/// busbar-reshaped id from one the client itself authored, and recover the original egress id without
/// any cross-request state. Chosen to be alphanumeric (valid inside every native id shape) and
/// vanishingly unlikely to prefix a genuine client tool id. The original egress id follows as lower
/// hex, making the whole transform a pure, deterministic bijection: the SAME egress id always maps to
/// the SAME native id, so a `tool_use` and the `tool_result` that later references it stay consistent
/// WITHIN a request AND across rounds (the client echoes the native id back; the request path decodes
/// it to the original before the egress backend sees it).
const TOOL_ID_REMAP_MARKER: &str = "bb1";

/// Per-request / per-stream tool-id remap applied ONLY at the cross-protocol seam (ingress != egress).
/// Same-protocol passthrough never constructs one, so native ids pass through verbatim there.
///
/// Forward (egress → ingress, on a response): each foreign egress tool id is reshaped to the ingress
/// protocol's native form — `<prefix><MARKER><hex(egress_id)>` — so e.g. an OpenAI backend's `call_…`
/// never reaches an Anthropic client as a foreign `call_…` (an immediate proxy tell), it arrives as a
/// native `toolu_…`. The in-request map memoizes so a repeated egress id maps stably (and the encoding
/// is deterministic regardless, so the map is an optimization, not a correctness crutch).
///
/// Reverse (ingress → egress, on the next request): the client echoes the native id back inside a
/// `tool_result`; [`decode_native_tool_id`] strips the marker and hex-decodes it to the ORIGINAL
/// egress id so the backend sees the id it actually issued. An id WITHOUT the marker is client-authored
/// (or same-protocol) and passes through untouched.
#[derive(Default)]
pub(crate) struct ToolIdRemap {
    map: std::collections::HashMap<String, String>,
}

impl ToolIdRemap {
    /// Reshape one egress tool id into the ingress protocol's native form. Deterministic + memoized.
    /// A `None` ingress prefix (Gemini, Cohere) returns the id unchanged — Gemini drops tool ids
    /// outright, and Cohere ids are free-form (no canonical prefix to make the reshape reversible
    /// without colliding with client-authored ids), so both pass through verbatim.
    fn native_for(&mut self, ingress_protocol: &str, egress_id: &str) -> String {
        let Some(prefix) = native_tool_id_prefix(ingress_protocol) else {
            return egress_id.to_string();
        };
        if let Some(existing) = self.map.get(egress_id) {
            return existing.clone();
        }
        let native = format!("{prefix}{TOOL_ID_REMAP_MARKER}{}", hex::encode(egress_id));
        self.map.insert(egress_id.to_string(), native.clone());
        native
    }

    /// Rewrite every tool id in a non-stream `IrResponse` to the ingress-native form (in place).
    pub(crate) fn remap_response(
        &mut self,
        ingress_protocol: &str,
        ir: &mut crate::ir::IrResponse,
    ) {
        for block in &mut ir.content {
            self.remap_block(ingress_protocol, block);
        }
    }

    /// Rewrite every tool id in a streaming `IrStreamEvent` to the ingress-native form (in place).
    fn remap_event(&mut self, ingress_protocol: &str, event: &mut crate::ir::IrStreamEvent) {
        if let crate::ir::IrStreamEvent::BlockStart {
            block: crate::ir::IrBlockMeta::ToolUse { id, .. },
            ..
        } = event
        {
            *id = self.native_for(ingress_protocol, id);
        }
    }

    fn remap_block(&mut self, ingress_protocol: &str, block: &mut crate::ir::IrBlock) {
        match block {
            crate::ir::IrBlock::ToolUse { id, .. } => {
                *id = self.native_for(ingress_protocol, id);
            }
            crate::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                *tool_use_id = self.native_for(ingress_protocol, tool_use_id);
                for inner in content {
                    self.remap_block(ingress_protocol, inner);
                }
            }
            crate::ir::IrBlock::Text { .. }
            | crate::ir::IrBlock::Thinking { .. }
            | crate::ir::IrBlock::Image { .. }
            | crate::ir::IrBlock::Json(_) => {}
        }
    }
}

/// Recover the ORIGINAL egress tool id from a busbar-reshaped native id (the EXACT reverse of
/// [`ToolIdRemap::native_for`]). Returns `Some(original)` when `id` carries the busbar marker after
/// the INGRESS protocol's OWN native prefix AND the hex tail decodes to valid UTF-8; otherwise `None`
/// (a client-authored id — pass it through verbatim). Pure and stateless, so the reverse needs no
/// shared map across rounds.
///
/// The decode is gated on the SAME `native_tool_id_prefix(ingress_protocol)` the encode used — NOT a
/// best-effort scan over every known prefix. Trying foreign prefixes would mis-detect a genuine
/// CLIENT-authored id of the colliding shape (`<any-known-prefix>bb1<even-len-hex>`) as
/// busbar-reshaped and silently hex-decode it, corrupting the tool_use/tool_result correlation for
/// that turn. Restricting to the ingress's own prefix makes this the precise inverse of the encode.
/// A prefix-less ingress (Cohere, Gemini) returns `None` here, so its ids are never decoded — the
/// matching no-op for a protocol whose ids are never reshaped on the response.
fn decode_native_tool_id(ingress_protocol: &str, id: &str) -> Option<String> {
    // The ingress protocol's own native prefix — exactly what `native_for` prepended on encode.
    // Gemini (and any protocol without a prefix) never has ids reshaped, so nothing to decode.
    let prefix = native_tool_id_prefix(ingress_protocol)?;
    let rest = id.strip_prefix(prefix)?;
    let hexpart = rest.strip_prefix(TOOL_ID_REMAP_MARKER)?;
    // A marker-only id (empty hex tail) is NOT a busbar id — `native_for` always hex-encodes the
    // egress id, so an empty tail can only come from a client-authored `<prefix>bb1`. Decoding it
    // would yield an empty string and break the exact-inverse round-trip, so pass it through verbatim.
    if hexpart.is_empty() {
        return None;
    }
    // A valid busbar id has an even-length lowercase-hex tail; reject anything else so a genuine
    // client id that merely happens to start with `<prefix>bb1` is not mangled.
    let bytes = hex::decode(hexpart).ok()?;
    String::from_utf8(bytes).ok()
}

/// Walk a request-body IR (messages → blocks, recursing into `ToolResult.content`) and decode any
/// busbar-reshaped tool id back to the original egress id, so a `tool_result` the client echoes after a
/// cross-protocol response references the id the egress backend actually issued. A no-op for ids that
/// carry no busbar marker (client-authored / same-protocol). Applied at the request seam (ingress !=
/// egress) AFTER `read_request`, BEFORE the egress `write_request`.
pub(crate) fn decode_request_tool_ids(
    ingress_protocol: &str,
    messages: &mut [crate::ir::IrMessage],
) {
    fn walk(ingress_protocol: &str, block: &mut crate::ir::IrBlock) {
        match block {
            crate::ir::IrBlock::ToolUse { id, .. } => {
                if let Some(orig) = decode_native_tool_id(ingress_protocol, id) {
                    *id = orig;
                }
            }
            crate::ir::IrBlock::ToolResult {
                tool_use_id,
                content,
                ..
            } => {
                if let Some(orig) = decode_native_tool_id(ingress_protocol, tool_use_id) {
                    *tool_use_id = orig;
                }
                for inner in content {
                    walk(ingress_protocol, inner);
                }
            }
            crate::ir::IrBlock::Text { .. }
            | crate::ir::IrBlock::Thinking { .. }
            | crate::ir::IrBlock::Image { .. }
            | crate::ir::IrBlock::Json(_) => {}
        }
    }
    for msg in messages {
        for block in &mut msg.content {
            walk(ingress_protocol, block);
        }
    }
}

pub(crate) mod stream;
pub(crate) use stream::StreamTranslate;

/// Find the first SSE frame terminator (a blank line) in `buf`, returning `(offset, terminator_len)`
/// where `offset` is the byte index of the first terminator byte. Recognizes both the LF-LF (`\n\n`,
/// 2 bytes) and the spec-legal CRLF (`\r\n\r\n`, 4 bytes) blank-line terminators per WHATWG SSE.
/// Returns `None` if no complete terminator is present yet.
pub(crate) fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            // LF-LF: `\n\n` — the blank-line terminator begins at this `\n` and is 2 bytes long.
            if buf.get(i + 1) == Some(&b'\n') {
                return Some((i, 2));
            }
            // CRLF-CRLF: `\r\n\r\n` — the full spec-legal terminator is 4 bytes. We anchor the scan
            // on the `\n` that ENDS the preceding line's CRLF, then confirm the blank line's own
            // `\r\n` follows (`...\n` + `\r\n`). The terminator proper begins at the trailing `\r`
            // of the preceding line (one byte BEFORE this `\n`), so report `offset = i - 1` and
            // `len = 4`. (`i >= 1` is guaranteed here: a leading `\n` at index 0 cannot match this
            // arm, since the preceding `\r` it requires would have to sit at index -1.)
            if i >= 1
                && buf[i - 1] == b'\r'
                && buf.get(i + 1) == Some(&b'\r')
                && buf.get(i + 2) == Some(&b'\n')
            {
                return Some((i - 1, 4));
            }
        }
        i += 1;
    }
    None
}

/// Parse one SSE frame into `(event_type, data_payload)`. `event_type` is "" when the frame has
/// no `event:` line (OpenAI style). Multiple `data:` lines in a single frame are concatenated with
/// `\n` per the SSE spec (§9.2.6). Returns `None` if the frame carries no `data:` line (including a
/// frame with only an `event:` line) or is invalid UTF-8.
pub(crate) fn parse_sse_frame(frame: &[u8]) -> Option<(String, String)> {
    let text = std::str::from_utf8(frame).ok()?;
    let mut event_type = String::new();
    let mut data_lines: Vec<&str> = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("event:") {
            event_type = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("data:") {
            // Per the SSE spec a single leading space after the colon is stripped; the rest of the
            // value is preserved verbatim so multi-line JSON payloads survive intact.
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    if data_lines.is_empty() {
        // No `data:` line at all (e.g. an `event:`-only frame) — nothing to translate.
        return None;
    }
    Some((event_type, data_lines.join("\n")))
}

/// Re-frame an IR-derived `(event_type, data)` as INGRESS SSE bytes. A non-empty `event_type`
/// yields Anthropic-style `event:`/`data:` frames; an empty one yields OpenAI-style bare `data:`.
fn reframe_sse(event_type: &str, data: &serde_json::Value) -> String {
    if event_type.is_empty() {
        format!("data: {data}\n\n")
    } else {
        format!("event: {event_type}\ndata: {data}\n\n")
    }
}

/// Anthropic reader implementation.
pub(crate) mod anthropic;
pub(crate) mod bedrock;
pub(crate) mod cohere;
/// Wire-dialect detection: `protocol_id(path, headers)` sniffs which protocol a request speaks.
pub(crate) mod detect;
pub(crate) mod gemini;
pub(crate) mod openai_chat;
pub(crate) mod openai_family;
pub(crate) mod openai_responses;

// Private imports (NOT re-exports) for the symbols mod.rs references by bare name: the registry
// constructs each Reader/Writer below, and a test synthesizes an Anthropic request id. Every other
// caller references these at their owning module path (e.g. `crate::proto::bedrock::...`).
use anthropic::{AnthropicReader, AnthropicWriter};
// `synth_anthropic_request_id` lives in `anthropic.rs`; mod.rs references it only from its own test
// module (production callers use `crate::proto::anthropic::synth_anthropic_request_id`). Private,
// test-gated import — NOT a re-export.
#[cfg(test)]
use anthropic::synth_anthropic_request_id;
use bedrock::{BedrockReader, BedrockWriter};
use cohere::{CohereReader, CohereWriter};
use gemini::{GeminiReader, GeminiWriter};
// `GeminiJsonArrayFramer` lives in `gemini.rs`; mod.rs references it only from its own test module
// (production callers use `crate::proto::gemini::GeminiJsonArrayFramer`). Private, test-gated import
// — NOT a re-export.
#[cfg(test)]
use gemini::GeminiJsonArrayFramer;
use openai_chat::{OpenAiReader, OpenAiWriter};
use openai_responses::{ResponsesReader, ResponsesWriter};

/// Canonical protocol-id vocabulary. Every PRODUCTION comparison / match arm / registry insertion on
/// a protocol name goes through these consts so the router, dispatch, projections, and registry
/// cannot drift on a typo'd literal. Tests keep raw literals by convention (golden-value checks).
pub(crate) const PROTO_ANTHROPIC: &str = "anthropic";
pub(crate) const PROTO_OPENAI: &str = "openai";
pub(crate) const PROTO_GEMINI: &str = "gemini";
pub(crate) const PROTO_BEDROCK: &str = "bedrock";
pub(crate) const PROTO_COHERE: &str = "cohere";
pub(crate) const PROTO_RESPONSES: &str = "responses";

/// Every protocol name busbar ships a built-in `Protocol` for. SINGLE SOURCE OF TRUTH shared by
/// `ProtocolRegistry::with_builtins` (which builds its map from these names) and the config validator
/// (`config_validate.rs`, which rejects a provider whose `protocol` is not in this set so an unknown
/// protocol is COLLECTED with every other config error rather than escaping to a lone `die()` at lane
/// construction in `main.rs`). Keeping the list here, co-located with `with_builtins` and
/// `debug_assert`-checked against the registry it builds, guarantees the registry and validator cannot
/// drift: adding a protocol to `with_builtins` without listing it here (or vice versa) trips the
/// assertion in any debug/test build.
pub(crate) const KNOWN_PROTOCOLS: &[&str] = &[
    "anthropic",
    PROTO_OPENAI,
    PROTO_GEMINI,
    PROTO_BEDROCK,
    PROTO_RESPONSES,
    PROTO_COHERE,
];

/// String-keyed registry mapping a provider's protocol name to its `Protocol`.
/// `with_builtins` registers every protocol busbar ships with.
#[derive(Default)]
pub(crate) struct ProtocolRegistry {
    map: std::collections::HashMap<String, Arc<Protocol>>,
}

impl ProtocolRegistry {
    /// Create a new registry with built-in protocols.
    pub(crate) fn with_builtins() -> Self {
        let mut map = std::collections::HashMap::new();
        for &name in KNOWN_PROTOCOLS {
            // Build the registry from the single-source-of-truth name list so the registry and the
            // config validator (which validates against `KNOWN_PROTOCOLS`) cannot drift.
            let protocol = match name {
                PROTO_ANTHROPIC => Protocol::anthropic(),
                PROTO_OPENAI => Protocol::openai(),
                PROTO_GEMINI => Protocol::gemini(),
                PROTO_BEDROCK => Protocol::bedrock(),
                PROTO_RESPONSES => Protocol::responses(),
                PROTO_COHERE => Protocol::cohere(),
                // Startup-only construction: if a name is added to `KNOWN_PROTOCOLS` without a
                // matching constructor arm here, fail loud in debug/test builds. In release this
                // skips the unmapped name (it simply will not be registered), and the lane-build
                // `die()` in main.rs remains the defensive backstop.
                other => {
                    debug_assert!(
                        false,
                        "KNOWN_PROTOCOLS lists '{other}' but with_builtins has no constructor for it"
                    );
                    continue;
                }
            };
            map.insert(name.to_string(), Arc::new(protocol));
        }
        // Belt-and-suspenders: the registry must contain exactly the KNOWN_PROTOCOLS set, so a
        // constructor arm added WITHOUT listing the name in KNOWN_PROTOCOLS (or vice versa) is caught.
        debug_assert_eq!(
            map.len(),
            KNOWN_PROTOCOLS.len(),
            "ProtocolRegistry built {} protocols but KNOWN_PROTOCOLS lists {}",
            map.len(),
            KNOWN_PROTOCOLS.len()
        );
        Self { map }
    }

    /// Get a protocol by name.
    pub(crate) fn get(&self, name: &str) -> Option<Arc<Protocol>> {
        self.map.get(name).cloned()
    }
}

pub(crate) fn convert_headers(
    headers: Vec<(HeaderName, HeaderValue)>,
) -> reqwest::header::HeaderMap {
    let mut map = reqwest::header::HeaderMap::new();
    for (name, value) in headers {
        map.insert(name, value);
    }
    map
}

#[cfg(test)]
#[path = "tests/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/stream_fanout_tests.rs"]
mod stream_fanout_tests;

#[cfg(test)]
#[path = "tests/stream_translate_tests.rs"]
mod stream_translate_tests;

/// Change B step 2 — SAME-PROTOCOL FIDELITY PROOF. For each of the 6 protocols, replay captured
/// native streaming frames through a `StreamTranslate::new_same_proto` translator and assert the
/// concatenated `feed` + `finish` output is BYTE-FOR-BYTE identical to the input frames (the verbatim
/// short-circuit must never re-serialize). Also asserts the IR-derived `usage()` (the A-tap billing
/// value) matches the token counts embedded in the captured frames. The three HIGHEST-RISK paths
/// (bedrock binary eventstream, gemini non-`?alt=sse` JSON-array source frames, openai bare `data:`)
/// get dedicated frame-for-frame assertions.
#[cfg(test)]
#[path = "tests/same_proto_fidelity_tests.rs"]
mod same_proto_fidelity_tests;

#[cfg(test)]
#[path = "tests/gemini_tests.rs"]
mod gemini_tests;

#[cfg(test)]
#[path = "tests/context_length_tests.rs"]
mod context_length_tests;

#[cfg(test)]
#[path = "tests/gemini_integration_tests.rs"]
mod gemini_integration_tests;

#[cfg(test)]
#[path = "tests/response_format_matrix_tests.rs"]
mod response_format_matrix_tests;

#[cfg(test)]
#[path = "tests/stop_reason_matrix_tests.rs"]
mod stop_reason_matrix_tests;

#[cfg(test)]
#[path = "tests/image_source_matrix_tests.rs"]
mod image_source_matrix_tests;
