// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

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

/// An IR-level error, currently an alias for `CanonicalSignal` (the normalized error signal).
pub(crate) type IrError = crate::breaker::CanonicalSignal;

/// Conservative fallback for the `max_tokens` injected at a translation boundary when the source
/// protocol omitted it (legal for OpenAI) but the target REQUIRES it (Anthropic, Bedrock — see
/// `ProtocolWriter::requires_max_tokens`). Used only when the lane has no configured
/// `default_max_tokens`. 4096 is a safe output ceiling across current chat models — large enough
/// not to truncate typical completions, small enough not to be refused.
pub(crate) const DEFAULT_MAX_TOKENS: u32 = 4096;

/// Mint a UUID-v4-shaped request id (`8-4-4-4-12` lowercase hex) for the `x-amzn-RequestId` header a
/// native AWS Bedrock response always carries — on EVERY response, success and error, stream and
/// non-stream (the AWS SDK exposes it via `*Output::request_id()`; an absent header makes that return
/// `None`, which is impossible with a real endpoint and a deterministic proxy tell). Uses the OS
/// CSPRNG; returns `None` (so the caller simply OMITS the header) if entropy is unavailable — this is
/// on the request path and must never panic. Shared by the success paths (`forward.rs`) and the error
/// paths (`route.rs`/`auth.rs` keep wire-identical private copies pending a wider refactor).
pub(crate) fn synth_amzn_request_id() -> Option<String> {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).ok()?;
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

/// Mint a protocol-correct Anthropic request id (`req_01<token>`) for the `request-id` RESPONSE HEADER
/// a native Anthropic response always carries. The official SDK reads this header into
/// `APIError.request_id` / `Message._request_id` (NOT the body), so a busbar anthropic response that
/// omitted it left `request_id == None` — impossible against the real API and a deterministic proxy
/// tell. Used by `forward.rs` on anthropic-ingress success/relay 2xx responses that have NO upstream
/// `request-id` to forward (the error path mirrors the writer's own body `request_id` into the header
/// instead; the same-protocol passthrough forwards the UPSTREAM `request-id` verbatim and never calls
/// this). The shape mirrors a native id: the `req_` prefix, the `01` version marker, then a fixed-width
/// lowercase-base62 token from the OS CSPRNG. Returns `None` (caller OMITS the header) only if entropy
/// is unavailable — on the request path, must never panic.
pub(crate) fn synth_anthropic_request_id() -> Option<String> {
    // 96 bits of CSPRNG entropy → 16 base62 chars (collision-free in practice), matching the
    // fixed-width base62 token shape of a native `req_01…` id.
    let mut buf = [0u8; 12];
    getrandom::getrandom(&mut buf).ok()?;
    const ALPHABET: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    // Accumulate the 12 bytes as a u128 and emit 16 base62 digits (62^16 > 2^95, so 12 bytes fit).
    let mut n = buf.iter().fold(0u128, |acc, &b| (acc << 8) | b as u128);
    let mut token = [0u8; 16];
    for slot in token.iter_mut().rev() {
        *slot = ALPHABET[(n % 62) as usize];
        n /= 62;
    }
    // token is ASCII base62, always valid UTF-8.
    let token = std::str::from_utf8(&token).unwrap_or("0000000000000000");
    Some(format!("req_01{token}"))
}

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
        "gemini"
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
            "gemini"
        } else {
            "openai"
        }
    } else if path.starts_with("/model/")
        && (path.ends_with("/converse") || path.ends_with("/converse-stream"))
    {
        "bedrock"
    } else if path == "/v1/messages" || path.ends_with("/v1/messages") {
        "anthropic"
    } else if path == "/v1/chat/completions" {
        "openai"
    } else if path == "/v2/chat" {
        "cohere"
    } else if path == "/v1/responses" {
        "responses"
    } else {
        // Unknown ingress: fall back to the widely-understood OpenAI envelope.
        "openai"
    }
}

/// The vendor-plausible auth-failure wire MESSAGE for an ingress protocol. This string lands verbatim
/// in the native error body (`error.message` for anthropic/openai/gemini/responses, the bare
/// top-level `message` for cohere, the `message` beside `__type` for bedrock). It MUST read like the
/// copy the REAL vendor returns for a bad/missing credential and carry NO busbar-internal vocabulary
/// ("lane", "virtual key", "passthrough", …): any such word is a deterministic protocol tell that
/// also discloses busbar's auth model. Canonical source of truth; `auth.rs` keeps a wire-identical
/// private copy pending migration. Strings sampled from real 401/403 bodies:
///   anthropic → "invalid x-api-key"; openai/responses → "Incorrect API key provided.";
///   gemini → "API key not valid. Please pass a valid API key."; cohere → "invalid api token";
///   bedrock → "" (AWS conveys AccessDenied via __type / x-amzn-errortype, not message prose).
pub(crate) fn vendor_auth_failure_message(proto: &str) -> &'static str {
    match proto {
        "anthropic" => "invalid x-api-key",
        "gemini" => "API key not valid. Please pass a valid API key.",
        "cohere" => "invalid api token",
        "bedrock" => "",
        "openai" | "responses" => "Incorrect API key provided.",
        _ => "authentication failed",
    }
}

/// Attach the `x-amzn-RequestId` and `x-amzn-errortype` headers a native AWS Bedrock error response
/// ALWAYS carries to an already-built response. `x-amzn-errortype` mirrors the body `__type` (via
/// `error_kind_to_bedrock_type`, the single source of truth) so header and body agree; the request
/// id is the only request-id surface the AWS SDK exposes via `*Output::request_id()`. This is the
/// canonical helper so `forward.rs::ingress_error`, `route.rs`, and `auth.rs` cannot drift on which
/// headers a Bedrock error must carry. Best-effort: if entropy or header encoding fails we skip that
/// header rather than panic — this runs on the request path. No-op caller responsibility: only call
/// when the ingress protocol is bedrock.
pub(crate) fn attach_bedrock_error_headers(headers: &mut axum::http::HeaderMap, kind: &str) {
    if let Some(id) = synth_amzn_request_id() {
        if let Ok(hv) = HeaderValue::from_str(&id) {
            headers.insert(HeaderName::from_static("x-amzn-requestid"), hv);
        }
    }
    let errortype = error_kind_to_bedrock_type(kind);
    if let Ok(hv) = HeaderValue::from_str(errortype) {
        headers.insert(HeaderName::from_static("x-amzn-errortype"), hv);
    }
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

    /// Read a response/stream event from already-de-framed SSE data.
    fn read_response_event(
        &self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Option<IrStreamEvent>;

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

    /// Clone this reader as a trait object.
    fn clone_box(&self) -> Box<dyn ProtocolReader>;
}

/// Per-request signing context. Most protocols' `auth_headers` ignore this; protocols that
/// sign the whole request (AWS SigV4 for Bedrock) need the method/host/path/body/time.
pub(crate) struct SigningContext<'a> {
    /// Upstream host (no scheme), e.g. `bedrock-runtime.us-east-1.amazonaws.com`.
    pub host: String,
    /// URI-encoded request path (no query), e.g. `/model/anthropic.claude%3A0/converse`.
    pub canonical_uri: String,
    /// The exact request body bytes that will be sent.
    pub body: &'a [u8],
    /// Unix epoch seconds at signing time.
    pub timestamp_epoch: u64,
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

    /// Rewrites the model field in the request body.
    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str);

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
    /// router/auth/forward error sites (`route::ingress_error`, `auth`, `forward::ingress_error`).
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

    /// Build a minimal, protocol-correct request body for an active health probe of `model`.
    /// Serializes a one-token "ping" through this protocol's own `write_request`, so every protocol
    /// gets a valid probe body for free — no per-protocol probe code, no extra dependency.
    fn probe_body(&self, model: &str) -> Vec<u8> {
        use crate::ir::{IrBlock, IrMessage, IrRequest, IrRole};
        let ir = IrRequest {
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
            stream: false,
            extra: serde_json::Map::new(),
        };
        let mut body = self.write_request(&ir);
        self.rewrite_model(&mut body, model);
        serde_json::to_vec(&body).unwrap_or_default()
    }

    /// Clone this writer as a trait object.
    fn clone_box(&self) -> Box<dyn ProtocolWriter>;
}

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
        Self::new("anthropic", AnthropicReader, AnthropicWriter)
    }

    /// Construct an OpenAI protocol instance.
    pub(crate) fn openai() -> Self {
        Self::new("openai", OpenAiReader, OpenAiWriter)
    }

    /// Construct a Gemini protocol instance.
    pub(crate) fn gemini() -> Self {
        Self::new("gemini", GeminiReader, GeminiWriter)
    }

    /// Construct an OpenAI Responses protocol instance.
    pub(crate) fn responses() -> Self {
        Self::new("responses", ResponsesReader, ResponsesWriter)
    }

    /// Construct a Bedrock protocol instance.
    pub(crate) fn bedrock() -> Self {
        Self::new("bedrock", BedrockReader, BedrockWriter)
    }

    /// Construct a Cohere (v2 chat) protocol instance.
    pub(crate) fn cohere() -> Self {
        Self::new("cohere", CohereReader, CohereWriter)
    }
}

/// Resolve a built-in Protocol by name (for ingress translation). Cheap (unit structs).
pub(crate) fn protocol_for(name: &str) -> Option<Protocol> {
    match name {
        "anthropic" => Some(Protocol::anthropic()),
        "bedrock" => Some(Protocol::bedrock()),
        "cohere" => Some(Protocol::cohere()),
        "gemini" => Some(Protocol::gemini()),
        "openai" => Some(Protocol::openai()),
        "responses" => Some(Protocol::responses()),
        _ => None,
    }
}

/// pure cross-protocol response-stream translator. Feed EGRESS-protocol SSE bytes,
/// get the equivalent INGRESS-protocol SSE bytes — composing `egress.reader().read_response_events`
/// (wire → IR, stateful fan-out) with `ingress.writer().write_response_event` (IR → wire). Holds
/// a reassembly buffer for frames split across chunks and the IR decode state across the stream.
/// It is driven from the live streaming response path (see `FirstByteBody` in `forward`).
pub(crate) struct StreamTranslate {
    ingress: Protocol,
    egress: Protocol,
    decode: crate::ir::StreamDecodeState,
    buf: Vec<u8>,
    /// How far into `buf` we have already scanned for an SSE frame terminator. Searching only the
    /// unscanned tail keeps `feed()` linear even when a single large frame arrives as many small
    /// chunks (otherwise the whole accumulated prefix is re-scanned on every call → O(n^2)).
    scanned: usize,
    /// Set once the reassembly buffer exceeds `MAX_BUF` with no complete frame: the stream is
    /// abandoned (an untrusted upstream that never emits a terminator must not grow `buf`
    /// without bound — that is a memory-exhaustion DoS).
    aborted: bool,
    /// ingress == "openai" → the stream must terminate with `data: [DONE]\n\n`.
    emit_done: bool,
    /// egress == "bedrock" → frames are binary `application/vnd.amazon.eventstream`, not SSE.
    egress_eventstream: bool,
    /// ingress == "bedrock" → the CLIENT is a native AWS SDK, so each translated event must be
    /// packed into a binary `application/vnd.amazon.eventstream` frame (with valid CRC32) instead of
    /// reframed as SSE. The stream's terminator is the `messageStop`/`metadata` frames themselves
    /// (Bedrock has no `[DONE]`), so `finish()` stays empty. See `docs/architecture.md`.
    ingress_eventstream: bool,
    /// Wall-clock instant the first byte was fed, used to report a real `metrics.latencyMs` on a
    /// Bedrock-INGRESS `metadata` frame (finding: a native ConverseStream reports actual latency; a
    /// hard-coded `0` was a detectable tell). Set lazily on the first `feed`. `None` until then (and
    /// for non-Bedrock ingress, where it is never read).
    started_at: Option<std::time::Instant>,
    /// ingress == "openai" → the stream-start identity (`id`/`created`/`model`) captured from the
    /// first translated `MessageStart`, replayed onto EVERY subsequent `chat.completion.chunk`. The
    /// real OpenAI API repeats these top-level fields on every chunk; the writer emits them only on
    /// the opening (role) chunk, so without this replay the later content/finish chunks omit them — a
    /// shape divergence from a genuine OpenAI stream. Reuses the stream's id (never mints a fresh one
    /// per chunk). `None` until the first MessageStart is translated.
    openai_chunk_identity: Option<OpenAiChunkIdentity>,
    /// ingress == "bedrock" → whether a `metadata` (usage) frame has ALREADY been emitted for this
    /// stream. A native ConverseStream emits EXACTLY ONE `metadata` frame. But an OpenAI backend
    /// using `stream_options.include_usage` splits its terminal information across TWO chunks: a
    /// `finish_reason` chunk that carries NO usage (→ IR `MessageDelta{stop_reason:Some, usage=0}`)
    /// followed by a usage-only chunk (→ `MessageDelta{stop_reason:None, usage=real}`). Without this
    /// guard the fan-out emitted a zero-usage `metadata` for the first AND a real `metadata` for the
    /// second — TWO metadata frames (one reporting 0 tokens), a deterministic tell and corrupt token
    /// accounting. This flag lets us emit the metadata exactly once: defer it when the stop chunk
    /// carries no usage, and suppress a duplicate if usage already rode with the stop.
    bedrock_metadata_emitted: bool,
    /// ingress == "bedrock" → set when a combined stop-delta arrived with all-zero usage and the
    /// `metadata` frame was therefore DEFERRED (awaiting a trailing usage-only delta). In the OpenAI
    /// `include_usage` case that trailing delta arrives and emits the metadata; but in the DEFAULT
    /// OpenAI streaming case (no `include_usage`) there is NO trailing usage delta, so the metadata
    /// would never be emitted and the ConverseStream would end with messageStop but NO `metadata`
    /// frame — a genuine Bedrock ConverseStream ALWAYS terminates with one. This flag lets `finish()`
    /// flush a single best-effort (zero-usage) `metadata` frame at end-of-stream when the deferral was
    /// never resolved, so the stream is never missing its terminal metadata frame.
    bedrock_metadata_pending: bool,
    /// ingress == "bedrock" → a side-channel carrying the JSON payload of EVERY frame emitted on this
    /// stream, BEFORE it is packed into binary `application/vnd.amazon.eventstream` framing. The
    /// forward-layer `UsageTap` extracts token usage by brace-scanning JSON text, which is correct for
    /// the five SSE ingress protocols (whose `feed` output IS the JSON-bearing SSE text) but WRONG for
    /// bedrock ingress (whose output is binary frames whose length-prefixes/CRC32s/`{`-containing
    /// preludes mislead the scanner, so token accounting is unreliable or zeroed). The tap reads this
    /// pre-encode JSON instead, decoupling its input from the `ingress_eventstream` framing. Empty for
    /// non-bedrock ingress (the tap reads the SSE output directly there). Drained by `take_tap_json`.
    tap_json: Vec<u8>,
    /// Input-token usage captured at stream start (`MessageStart.usage`), carried forward so the
    /// terminal `MessageDelta` reports the prompt-token count.
    ///
    /// Anthropic's SSE puts `usage.input_tokens` (and the cache-token splits) ONLY on `message_start`;
    /// its `message_delta` carries `output_tokens` alone. Every other protocol bundles input+output
    /// into the terminal usage event. So on a cross-protocol hop OUT of an Anthropic backend the IR's
    /// terminal `MessageDelta.usage.input_tokens` is 0 and the prompt-token count is lost — the ingress
    /// writer (and the forward-layer `UsageTap` scanning its output) under-reports usage. Latch the
    /// start-usage input/cache fields here and backfill them onto the terminal delta when the delta
    /// itself carries none, so input tokens survive the seam regardless of how the egress protocol
    /// split start-vs-terminal usage. `None` until the first `MessageStart` carrying usage is seen.
    start_usage: Option<crate::ir::IrUsage>,
}

/// The OpenAI stream-start identity replayed onto every `chat.completion.chunk` (see
/// `StreamTranslate::openai_chunk_identity`). Captured from the opening chunk the OpenAI writer
/// emits for the IR `MessageStart` (which already synthesizes a stable `id`/`created` when the
/// cross-protocol backend supplied none), so the whole stream shares ONE identity.
#[derive(Clone)]
struct OpenAiChunkIdentity {
    id: serde_json::Value,
    created: serde_json::Value,
    model: Option<serde_json::Value>,
}

impl StreamTranslate {
    /// Build a translator for an ingress→egress pair. `None` if either protocol is unknown OR
    /// ingress == egress (no translation needed — the caller does native passthrough).
    pub(crate) fn new(ingress: &str, egress: &str) -> Option<Self> {
        if ingress == egress {
            return None;
        }
        Some(Self {
            ingress: protocol_for(ingress)?,
            egress: protocol_for(egress)?,
            decode: crate::ir::StreamDecodeState::default(),
            buf: Vec::new(),
            scanned: 0,
            aborted: false,
            emit_done: ingress == "openai",
            egress_eventstream: egress == "bedrock",
            ingress_eventstream: ingress == "bedrock",
            started_at: None,
            openai_chunk_identity: None,
            bedrock_metadata_emitted: false,
            bedrock_metadata_pending: false,
            tap_json: Vec::new(),
            start_usage: None,
        })
    }

    /// Translate one egress event `(event_type, payload)` into ingress wire bytes, advancing the
    /// decode state. Shared by the SSE and event-stream feed paths.
    fn translate_event(&mut self, event_type: &str, data: &serde_json::Value, out: &mut Vec<u8>) {
        for mut ev in self
            .egress
            .reader()
            .read_response_events(event_type, data, &mut self.decode)
        {
            // Cross-protocol stream identity strip: a `StreamTranslate` only exists when
            // ingress != egress (`new` returns None otherwise), so every event here crosses a
            // protocol boundary. Clear the foreign-format `MessageStart` `id`/`created` so the INGRESS
            // writer synthesizes NATIVE-format stream identity rather than leaking the backend's
            // `chatcmpl-…`/`msg_…` id to a different-protocol client — mirrors the non-stream strip in
            // forward.rs (`ir.id = None`). `model` is DELIBERATELY LEFT INTACT: it is the lane's model
            // name (format-neutral, like `created`), and ingress writers use a populated `model` as
            // the anchor for synthesizing the full native stream-start skeleton — clearing it
            // suppressed that synthesis (the Anthropic writer emitted a degenerate `message_start`
            // missing `id`/`type`/`content`/`stop_reason`/`stop_sequence`; the Gemini writer omitted
            // `modelVersion`). The non-stream path in forward.rs also does NOT clear `model`. Same-
            // protocol byte-exact round-trips never reach here, so they are untouched.
            if let crate::ir::IrStreamEvent::MessageStart {
                id, created, usage, ..
            } = &mut ev
            {
                // Latch the start-usage input/cache token counts (before stripping identity). Anthropic
                // carries input tokens ONLY here, never on `message_delta`; backfilling the terminal
                // delta below keeps the prompt-token count from vanishing across the cross-protocol seam.
                if let Some(u) = usage {
                    self.start_usage = Some(u.clone());
                }
                *id = None;
                *created = None;
            }
            // Backfill the terminal usage: if the egress protocol reported input/cache tokens only at
            // stream start (Anthropic), the `MessageDelta` arrives with `input_tokens == 0` and no cache
            // splits. Restore them from the latched start-usage so the ingress writer emits — and the
            // forward-layer UsageTap reads — the real prompt-token count. Only fills fields the delta
            // itself left empty, so a protocol that DOES carry input on its terminal delta (OpenAI
            // include_usage, Gemini, Bedrock, Cohere) is never overwritten.
            if let crate::ir::IrStreamEvent::MessageDelta { usage, .. } = &mut ev {
                if let Some(start) = &self.start_usage {
                    if usage.input_tokens == 0 {
                        usage.input_tokens = start.input_tokens;
                    }
                    if usage.cache_creation_input_tokens.is_none() {
                        usage.cache_creation_input_tokens = start.cache_creation_input_tokens;
                    }
                    if usage.cache_read_input_tokens.is_none() {
                        usage.cache_read_input_tokens = start.cache_read_input_tokens;
                    }
                }
            }
            // Bedrock-INGRESS error path: a native AWS SDK dispatches mid-stream errors off the
            // `:message-type: exception` / `:exception-type` headers, which ONLY
            // `encode_exception_frame` produces. A normal `write_response_event` pair would be framed
            // `:message-type: event` and silently dropped by a strict decoder. So when the ingress is
            // an event-stream client and the IR event is an Error, emit a real modeled-exception frame
            // via the writer's `write_response_exception` mapping instead of the event encoder.
            if self.ingress_eventstream {
                if let crate::ir::IrStreamEvent::Error(err) = &ev {
                    if let Some((exc_name, message)) =
                        self.ingress.writer().write_response_exception(err)
                    {
                        out.extend_from_slice(&crate::eventstream::encode_exception_frame(
                            &exc_name, &message,
                        ));
                        continue;
                    }
                }
            }

            // Bedrock-INGRESS combined-delta fan-out: the IR carries ONE combined
            // `MessageDelta{stop_reason: Some, usage}` (the egress reader collapses Bedrock's native
            // two-frame stop/usage split — or any other protocol's single message_delta — into one).
            // A native AWS SDK Bedrock client, however, expects the real TWO-frame sequence: a
            // `messageStop` frame carrying the stop reason FOLLOWED by a `metadata` frame carrying the
            // token usage (and a `metrics` object). The single-`(String,Value)`-return writer trait
            // cannot emit two frames, so we fan the combined delta into two synthetic single-purpose
            // deltas here — a stop-only delta → `messageStop`, then a usage-only delta → `metadata` —
            // and inject the real `metrics.latencyMs` onto the metadata frame (see below). This
            // reproduces exactly what `BedrockReader::read_response_events` consumed, so a
            // bedrock->bedrock stream still round-trips frame-for-frame.
            if self.ingress_eventstream {
                if let crate::ir::IrStreamEvent::MessageDelta {
                    stop_reason: Some(reason),
                    usage,
                    stop_sequence,
                } = &ev
                {
                    // Frame 1: stop-only delta → `messageStop` (usage, if any, rides frame 2).
                    let stop_only = crate::ir::IrStreamEvent::MessageDelta {
                        stop_reason: Some(reason.clone()),
                        stop_sequence: stop_sequence.clone(),
                        usage: crate::ir::IrUsage {
                            input_tokens: 0,
                            output_tokens: 0,
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        },
                    };
                    self.emit_ir_event(&stop_only, out);
                    // Frame 2: `metadata` carrying the token usage — but a native ConverseStream emits
                    // EXACTLY ONE `metadata`. Emit it here ONLY if real usage rode WITH the stop (the
                    // native Bedrock→Bedrock case AND any egress that bundles usage into the stop
                    // delta). If usage is all-zero, this is an OpenAI `include_usage` stop chunk whose
                    // tokens arrive in a SEPARATE trailing usage-only delta — DEFER the metadata to
                    // that delta so we emit it once with the REAL tokens, never a zero-usage frame.
                    let has_usage = usage.input_tokens != 0 || usage.output_tokens != 0;
                    if has_usage {
                        let usage_only = crate::ir::IrStreamEvent::MessageDelta {
                            stop_reason: None,
                            stop_sequence: stop_sequence.clone(),
                            usage: usage.clone(),
                        };
                        self.emit_ir_event(&usage_only, out);
                        self.bedrock_metadata_emitted = true;
                    } else {
                        // Deferred: the stop carried no usage. The trailing usage-only delta (OpenAI
                        // `include_usage`) will emit the metadata if it arrives — but in DEFAULT
                        // OpenAI streaming (no `include_usage`) it never does, so mark the metadata
                        // pending and let `finish()` flush a single zero-usage `metadata` frame at
                        // end-of-stream. A native ConverseStream ALWAYS ends with a metadata frame;
                        // its total absence is a proxy tell and loses token accounting.
                        self.bedrock_metadata_pending = true;
                    }
                    continue;
                }
                // A usage-only delta (`stop_reason: None`) → a `metadata` frame. This is the trailing
                // OpenAI `include_usage` chunk (or a native usage frame). Emit at most once: suppress
                // it if a `metadata` already rode with the stop above, so the stream carries exactly
                // one metadata frame regardless of how the egress backend split stop vs usage.
                if let crate::ir::IrStreamEvent::MessageDelta {
                    stop_reason: None, ..
                } = &ev
                {
                    if self.bedrock_metadata_emitted {
                        continue;
                    }
                    self.bedrock_metadata_emitted = true;
                    self.bedrock_metadata_pending = false; // the deferral is now resolved
                    self.emit_ir_event(&ev, out);
                    continue;
                }
            }

            self.emit_ir_event(&ev, out);
        }
    }

    /// Write a single IR event through the ingress writer and append its framed bytes to `out`.
    /// Handles the eventstream-vs-SSE framing split, the Bedrock-INGRESS `metadata`-frame
    /// `metrics.latencyMs` injection (finding: a native ConverseStream reports real latency), and the
    /// OpenAI-INGRESS per-chunk identity replay (finding: the real OpenAI API repeats
    /// `id`/`created`/`model` on EVERY `chat.completion.chunk`, not just the opening one).
    fn emit_ir_event(&mut self, ev: &crate::ir::IrStreamEvent, out: &mut Vec<u8>) {
        let Some((out_et, mut out_data)) = self.ingress.writer().write_response_event(ev) else {
            return;
        };
        if self.ingress_eventstream {
            // ingress is a native AWS SDK Bedrock client: pack the logical event into a
            // binary `application/vnd.amazon.eventstream` frame with valid CRC32.
            if out_et == "metadata" {
                // A native ConverseStream `metadata` frame carries a `metrics` object with the
                // stream's real `latencyMs`. Inject the elapsed wall-clock since the first byte was
                // fed; if timing is somehow unavailable, OMIT `metrics` entirely rather than emit a
                // tell-tale `0`. The writer leaves `metrics` off so this is the single source of it.
                if let Some(start) = self.started_at {
                    let elapsed_ms = start.elapsed().as_millis();
                    // u128 → u64 for JSON; saturate (elapsed never realistically exceeds u64 ms).
                    let elapsed_ms = u64::try_from(elapsed_ms).unwrap_or(u64::MAX);
                    if let Some(obj) = out_data.as_object_mut() {
                        obj.insert(
                            "metrics".to_string(),
                            serde_json::json!({ "latencyMs": elapsed_ms }),
                        );
                    }
                }
            }
            let payload = serde_json::to_vec(&out_data).unwrap_or_default();
            // Tap side-channel: record the pre-encode JSON payload (with its `type` event name folded
            // in, so the tap's `message_delta`/`message_stop`/`metadata`-keyed extractors fire) so the
            // forward-layer `UsageTap` can scan JSON text rather than the binary frame bytes below.
            // This is the bedrock-ingress token-accounting fix: brace-scanning the encoded binary
            // frame (length prefix / CRC32 / header block) mis-parses or zeroes usage.
            // Splice the `type` key into the ALREADY-serialized `payload` bytes instead of deep-cloning
            // the whole `out_data` Value (which can be kilobytes for a metadata/tool-result frame) just
            // to insert one key. `payload` is the serialization of `out_data`; when `out_data` is a JSON
            // object it begins with `{`, so `{"type":<enc>,` + payload[1..] yields the same object with
            // `type` prepended — zero Value clone, one small format alloc. Guard on the object shape (a
            // non-object out_data would not serialize to a leading `{`); fall back to the explicit
            // build only in that (unexpected) case so the tap is never fed malformed JSON.
            if out_data.is_object() {
                if let Ok(enc_et) = serde_json::to_string(&out_et) {
                    // payload is `{...}`; replace the leading `{` with `{"type":<enc_et>,` (or
                    // `{"type":<enc_et>}` for the empty-object `{}` case, which has no trailing field).
                    self.tap_json.extend_from_slice(b"{\"type\":");
                    self.tap_json.extend_from_slice(enc_et.as_bytes());
                    if payload.len() > 2 {
                        // non-empty object: `{` + rest → `,` + rest-after-`{`
                        self.tap_json.push(b',');
                        self.tap_json.extend_from_slice(&payload[1..]);
                    } else {
                        // `{}` → close immediately
                        self.tap_json.push(b'}');
                    }
                }
            }
            out.extend_from_slice(&crate::eventstream::encode_frame(&out_et, &payload));
        } else {
            if self.emit_done {
                // ingress == "openai" (the only ingress that emits a `[DONE]` terminator): every
                // `chat.completion.chunk` repeats the stream's top-level `id`/`created`/`model`.
                // Capture them from the opening chunk (the MessageStart the writer rendered, which
                // already synthesized stable values when the cross-protocol backend supplied none)
                // and replay them onto every later chunk so the stream is shape-faithful to a genuine
                // OpenAI stream (and the chunks share ONE id — never a freshly minted per-chunk id).
                self.apply_openai_chunk_identity(&mut out_data);
            }
            out.extend_from_slice(reframe_sse(&out_et, &out_data).as_bytes());
        }
    }

    /// Capture-or-replay the OpenAI stream identity on a `chat.completion.chunk` body. On the first
    /// chunk that carries an `id` (the opening role chunk), latch `id`/`created`/`model`; on every
    /// subsequent chunk (which the writer emits WITHOUT them), inject the latched values. Only called
    /// for OpenAI ingress. The `[DONE]` sentinel is a separate `finish()` literal, not routed here.
    fn apply_openai_chunk_identity(&mut self, chunk: &mut serde_json::Value) {
        let Some(obj) = chunk.as_object_mut() else {
            return;
        };
        // Only `chat.completion.chunk` bodies carry stream identity. An in-band error envelope
        // (`{"error":{...}}`) the writer may emit has no `object` field — leave it untouched.
        if obj.get("object").and_then(|v| v.as_str()) != Some("chat.completion.chunk") {
            return;
        }
        match &self.openai_chunk_identity {
            None => {
                // First chunk: latch its identity (the writer put id/created on the role chunk, and
                // model when the lane supplied one).
                if obj.contains_key("id") {
                    self.openai_chunk_identity = Some(OpenAiChunkIdentity {
                        id: obj.get("id").cloned().unwrap_or(serde_json::Value::Null),
                        created: obj
                            .get("created")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        model: obj.get("model").cloned(),
                    });
                }
            }
            Some(identity) => {
                // Subsequent chunk: replay the latched identity (the writer omitted it).
                obj.entry("id".to_string())
                    .or_insert_with(|| identity.id.clone());
                obj.entry("created".to_string())
                    .or_insert_with(|| identity.created.clone());
                if let Some(model) = &identity.model {
                    obj.entry("model".to_string())
                        .or_insert_with(|| model.clone());
                }
            }
        }
    }

    /// Hard cap on the reassembly buffer. An upstream that streams bytes without ever emitting a
    /// frame terminator must not grow `buf` indefinitely (memory-exhaustion DoS). DEFINED as
    /// `eventstream::MAX_FRAME_BYTES` (a single source of truth) so any single frame the binary
    /// decoder is willing to assemble can be buffered to completion here — a smaller cap would
    /// silently abort an oversized-but-decoder-legal frame before `drain_frames` ever saw it, and a
    /// divergence between the two literals (the previous hand-copied `16 * 1024 * 1024`) would
    /// reintroduce that bug with no compile-time signal. Far larger than any legitimate single SSE /
    /// event-stream frame from a chat completion.
    const MAX_BUF: usize = crate::eventstream::MAX_FRAME_BYTES;

    /// Feed a chunk of EGRESS SSE bytes; return translated INGRESS SSE bytes for whatever
    /// COMPLETE frames are now available (empty if only a partial frame is buffered). Once the
    /// reassembly buffer exceeds [`Self::MAX_BUF`] with no complete frame the stream is abandoned
    /// and all further input is ignored.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.aborted {
            return Vec::new();
        }
        // Stamp the stream's wall-clock start on the first byte fed, so a Bedrock-INGRESS `metadata`
        // frame can report a real `metrics.latencyMs` (elapsed since the stream began) instead of a
        // tell-tale hard-coded 0. Cheap monotonic clock read; only read on the bedrock-ingress path.
        if self.started_at.is_none() {
            self.started_at = Some(std::time::Instant::now());
        }
        self.buf.extend_from_slice(chunk);
        let mut out: Vec<u8> = Vec::new();

        if self.egress_eventstream {
            // egress is binary AWS event-stream framing (Bedrock ConverseStream). The event
            // name lives in the frame's `:event-type` header, not the JSON payload; the Bedrock
            // reader keys off a `type` field, so fold the header into the payload.
            for (event_type, payload) in crate::eventstream::drain_frames(&mut self.buf) {
                let Ok(mut data) = serde_json::from_slice::<serde_json::Value>(&payload) else {
                    continue; // non-JSON payload — skip the frame
                };
                if let Some(obj) = data.as_object_mut() {
                    obj.insert(
                        "type".to_string(),
                        serde_json::Value::String(event_type.clone()),
                    );
                }
                self.translate_event(&event_type, &data, &mut out);
            }
            if self.buf.len() > Self::MAX_BUF {
                self.abort_overflow();
            }
            return out;
        }

        // Drain every complete blank-line-delimited SSE frame currently buffered. Both the LF-LF
        // (`\n\n`) and the spec-legal CRLF (`\r\n\r\n`) terminators are recognized — some gateways /
        // CDNs in front of model APIs emit CRLF SSE, which contains no `\n\n` adjacency, so an
        // LF-only scanner would buffer the whole stream until MAX_BUF and silently abort it. We back
        // up to cover a terminator straddling the previous chunk boundary (3 bytes, enough for the
        // 4-byte CRLF terminator) and only rescan the unsearched tail, keeping `feed()` linear.
        loop {
            let search_from = self.scanned.saturating_sub(3).min(self.buf.len());
            match find_frame_terminator(&self.buf[search_from..]) {
                Some((rel, term_len)) => {
                    let end = search_from + rel + term_len;
                    let frame: Vec<u8> = self.buf.drain(..end).collect();
                    self.scanned = 0;

                    let Some((event_type, data_str)) = parse_sse_frame(&frame) else {
                        continue; // no data: line, or non-utf8 — skip
                    };
                    if data_str.is_empty() || data_str == "[DONE]" {
                        continue; // egress terminator/keepalive — ingress terminator is finish()'s
                    }
                    let Ok(data) = serde_json::from_str::<serde_json::Value>(&data_str) else {
                        continue; // malformed data JSON — skip the frame rather than abort
                    };
                    self.translate_event(&event_type, &data, &mut out);
                }
                None => {
                    // No complete frame: everything currently buffered has been scanned.
                    self.scanned = self.buf.len();
                    break;
                }
            }
        }
        if self.buf.len() > Self::MAX_BUF {
            self.abort_overflow();
        }
        out
    }

    /// Drain the pre-encode JSON the most recent `feed`/`finish` emitted for the forward-layer
    /// `UsageTap` (bedrock ingress only — see `tap_json`). Returns the accumulated JSON-payload bytes
    /// and clears the buffer so each chunk is tapped exactly once. Always empty for non-bedrock
    /// ingress (there the tap reads the SSE output directly). The caller feeds this into the tap
    /// INSTEAD of the binary frame output on the bedrock-ingress path.
    pub(crate) fn take_tap_json(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.tap_json)
    }

    /// True when this translator's ingress is a binary event-stream client (bedrock), i.e. its
    /// `feed`/`finish` OUTPUT is binary frames and the `UsageTap` must read `take_tap_json` instead.
    pub(crate) fn ingress_is_eventstream(&self) -> bool {
        self.ingress_eventstream
    }

    /// Abandon a stream whose reassembly buffer grew past [`Self::MAX_BUF`] without a frame
    /// terminator. The buffer is released and all subsequent `feed()` calls become no-ops.
    fn abort_overflow(&mut self) {
        self.aborted = true;
        self.buf.clear();
        self.buf.shrink_to_fit();
        self.scanned = 0;
    }

    /// Call once at end-of-stream. Returns the INGRESS terminator (OpenAI → `data: [DONE]\n\n`,
    /// Anthropic → empty: its `message_stop` event already carries termination).
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        // Bedrock-INGRESS: if a combined stop-delta deferred the `metadata` frame (zero usage,
        // expecting a trailing usage-only delta) and that delta never arrived — the DEFAULT OpenAI
        // streaming case (no `stream_options.include_usage`) — flush a single best-effort zero-usage
        // `metadata` frame now. A genuine Bedrock ConverseStream ALWAYS ends with a `metadata` frame;
        // emitting a zero-usage one is far closer to native than omitting it entirely (which loses
        // the AWS SDK's `ConverseStreamMetadataEvent` callback and is a deterministic proxy tell).
        if self.ingress_eventstream
            && self.bedrock_metadata_pending
            && !self.bedrock_metadata_emitted
        {
            self.bedrock_metadata_emitted = true;
            self.bedrock_metadata_pending = false;
            let usage_only = crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: None,
                stop_sequence: None,
                usage: crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            self.emit_ir_event(&usage_only, &mut out);
        }
        if self.emit_done {
            out.extend_from_slice(b"data: [DONE]\n\n");
        }
        out
    }
}

/// Find the first SSE frame terminator (a blank line) in `buf`, returning `(offset, terminator_len)`
/// where `offset` is the byte index of the first terminator byte. Recognizes both the LF-LF (`\n\n`,
/// 2 bytes) and the spec-legal CRLF (`\r\n\r\n`, 4 bytes) blank-line terminators per WHATWG SSE.
/// Returns `None` if no complete terminator is present yet.
pub(crate) fn find_frame_terminator(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0;
    while i < buf.len() {
        if buf[i] == b'\n' {
            // LF-LF: `\n\n`.
            if buf.get(i + 1) == Some(&b'\n') {
                return Some((i, 2));
            }
            // CRLF-CRLF: a `\n` followed by `\r\n` (the leading `\r` of this line was already
            // consumed by the previous line's CRLF), i.e. `\n\r\n`.
            if buf.get(i + 1) == Some(&b'\r') && buf.get(i + 2) == Some(&b'\n') {
                return Some((i, 3));
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

/// Re-frame a Gemini SSE response stream as the JSON-ARRAY streaming format a native
/// `:streamGenerateContent` request WITHOUT `?alt=sse` expects: a leading `[`, the per-chunk
/// `GenerateContentResponse` JSON objects separated by `,`, and a trailing `]`. (The SSE variant —
/// `?alt=sse` — emits `data:`-framed chunks instead; busbar always requests `?alt=sse` UPSTREAM, so
/// the bytes reaching this framer are Gemini SSE frames either way, whether the egress is gemini
/// same-protocol passthrough or a cross-protocol `StreamTranslate` whose ingress writer is gemini.)
///
/// This framer is the JSON-array sibling of [`StreamTranslate`]'s SSE path: it consumes the SSE
/// bytes (already in the gemini ingress wire shape), strips the `data:` framing, and re-emits the
/// payloads as one streaming JSON array. The output is ALWAYS a syntactically valid JSON array
/// (`finish` emits `]`, or `[]` when no chunk was seen) so a client that buffers and `JSON.parse`s
/// the whole body still succeeds.
/// Router-internal shim key the gemini ingress route injects into the request body when the client
/// sent a streaming `:streamGenerateContent` request WITHOUT `?alt=sse` (so the response must be the
/// JSON-array streaming format, not SSE). It rides alongside the `model`/`stream` shims. Single
/// source of truth shared by the route injection (`route.rs`), the forward-layer strip
/// (`forward::strip_router_shim_keys`), and the Gemini reader's `modeled_keys` exclusion so it never
/// reaches a backend on any path. A leading `__busbar` makes a collision with a real provider field
/// impossible.
pub(crate) const GEMINI_JSON_ARRAY_SHIM_KEY: &str = "__busbar_gemini_json_array";

pub(crate) struct GeminiJsonArrayFramer {
    buf: Vec<u8>,
    /// How far into `buf` the SSE terminator scan has already advanced (keeps `feed` linear; mirrors
    /// `StreamTranslate::scanned`).
    scanned: usize,
    /// Whether the opening `[` (and, for every object after the first, the separating `,`) has been
    /// emitted yet.
    started: bool,
    /// Set once `finish` has emitted the closing `]`, so a second `finish` is a no-op.
    finished: bool,
    /// Abandon the stream if the reassembly buffer grows past the cap with no complete frame.
    aborted: bool,
}

impl GeminiJsonArrayFramer {
    const MAX_BUF: usize = crate::eventstream::MAX_FRAME_BYTES;

    pub(crate) fn new() -> Self {
        Self {
            buf: Vec::new(),
            scanned: 0,
            started: false,
            finished: false,
            aborted: false,
        }
    }

    /// Feed a chunk of GEMINI SSE bytes; return JSON-array bytes for whatever complete SSE frames are
    /// now available (empty if only a partial frame is buffered, or if the buffered frames carried no
    /// data payload yet). Each emitted object is preceded by `[` (first) or `,` (subsequent).
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.aborted || self.finished {
            return Vec::new();
        }
        self.buf.extend_from_slice(chunk);
        let mut out: Vec<u8> = Vec::new();
        loop {
            let search_from = self.scanned.saturating_sub(3).min(self.buf.len());
            match find_frame_terminator(&self.buf[search_from..]) {
                Some((rel, term_len)) => {
                    let end = search_from + rel + term_len;
                    let frame: Vec<u8> = self.buf.drain(..end).collect();
                    self.scanned = 0;
                    let Some((_event_type, data_str)) = parse_sse_frame(&frame) else {
                        continue; // no data: line — keepalive/comment frame
                    };
                    if data_str.is_empty() || data_str == "[DONE]" {
                        continue; // egress terminator/keepalive — the array close is finish()'s job
                    }
                    // Validate the payload is JSON before forwarding so a malformed frame cannot
                    // corrupt the array; re-serialize from the parsed Value to normalize whitespace.
                    let Ok(data) = serde_json::from_str::<serde_json::Value>(&data_str) else {
                        continue;
                    };
                    if self.started {
                        out.push(b',');
                    } else {
                        out.push(b'[');
                        self.started = true;
                    }
                    out.extend_from_slice(data.to_string().as_bytes());
                }
                None => {
                    self.scanned = self.buf.len();
                    break;
                }
            }
        }
        if self.buf.len() > Self::MAX_BUF {
            self.aborted = true;
            self.buf.clear();
            self.buf.shrink_to_fit();
            self.scanned = 0;
        }
        out
    }

    /// Call once at end-of-stream. Emits the closing `]` (and the opening `[` too, as `[]`, when the
    /// stream carried no chunk) so the body is always a complete, parseable JSON array. When the
    /// framer ABORTED (the reassembly buffer overran `MAX_BUF` without a frame terminator), the
    /// stream was silently truncated — so instead of a bare `]` that would make the partial array
    /// look complete, append a Gemini-shaped `google.rpc.Status` error element so a parsing client
    /// can see the stream ended abnormally (then close the array).
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        if self.aborted {
            return self.finish_with_error(
                500,
                "INTERNAL",
                // Client-facing wire body: must carry NO product/internal vocabulary (the
                // protocol-indistinguishability promise). "upstream" is busbar-internal routing
                // vocabulary no real Gemini API ever emits — a fingerprintable tell. Mirror Gemini's
                // own canonical 500 status message text instead (the `google.rpc.Status.message` a
                // real Generative Language API 500 carries), so substring-matching clients can't
                // distinguish the proxy.
                "Internal error encountered.",
            );
        }
        self.finished = true;
        if self.started {
            b"]".to_vec()
        } else {
            b"[]".to_vec()
        }
    }

    /// Terminate the array with a trailing Gemini-shaped error element, then the closing `]`. Used on
    /// a mid-stream upstream transport failure (and on internal abort): a native Gemini JSON-array
    /// body is `application/json`, so the in-band error MUST itself be a valid array element — a
    /// `{"error":{"code","message","status"}}` object matching Gemini's `google.rpc.Status` envelope
    /// (the same shape `GeminiWriter::write_error` emits). Emitting raw SSE `event:`/`data:` text here
    /// (the bug this replaces) spliced non-JSON into the array, yielding an unparseable body and a
    /// protocol tell (a native Gemini JSON-array stream never contains SSE framing). Idempotent.
    pub(crate) fn finish_with_error(&mut self, code: u16, status: &str, message: &str) -> Vec<u8> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let err = serde_json::json!({
            "error": { "code": code, "message": message, "status": status }
        });
        let mut out: Vec<u8> = Vec::new();
        if self.started {
            out.push(b',');
        } else {
            out.push(b'[');
            self.started = true;
        }
        out.extend_from_slice(err.to_string().as_bytes());
        out.push(b']');
        out
    }
}

/// Anthropic reader implementation.
mod anthropic;
mod bedrock;
mod cohere;
mod gemini;
mod openai;
mod responses;

pub(crate) use anthropic::{AnthropicReader, AnthropicWriter};
pub(crate) use bedrock::{error_kind_to_bedrock_type, BedrockReader, BedrockWriter};
pub(crate) use cohere::{CohereReader, CohereWriter};
pub(crate) use gemini::{GeminiReader, GeminiWriter};
pub(crate) use openai::{OpenAiReader, OpenAiWriter};
pub(crate) use responses::{ResponsesReader, ResponsesWriter};

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
        map.insert("anthropic".to_string(), Arc::new(Protocol::anthropic()));
        map.insert("openai".to_string(), Arc::new(Protocol::openai()));
        map.insert("gemini".to_string(), Arc::new(Protocol::gemini()));
        map.insert("bedrock".to_string(), Arc::new(Protocol::bedrock()));
        map.insert("responses".to_string(), Arc::new(Protocol::responses()));
        map.insert("cohere".to_string(), Arc::new(Protocol::cohere()));
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
mod tests {
    use super::*;

    /// The default `ProtocolWriter::write_error` (the only impl in this wave — no per-protocol
    /// overrides yet) must produce valid JSON carrying the message and the `kind` as `error.type`,
    /// so the §8.1 / Unit I plumbing exists before per-protocol envelopes land. (Content-type is a
    /// caller concern; the doc contract says `application/json` for all protocols.)
    #[test]
    fn test_write_error_default_envelope_is_valid_json() {
        // Any writer exercises the default impl since none override it yet.
        let writer: Box<dyn ProtocolWriter> = Box::new(OpenAiWriter);
        let v = writer.write_error(404, "not_found", "model 'x' not found");
        // Round-trips as JSON (no panic) and has the generic envelope shape.
        let serialized = serde_json::to_string(&v).expect("write_error output must serialize");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("write_error output must be valid JSON");
        assert_eq!(
            reparsed["error"]["message"],
            serde_json::json!("model 'x' not found")
        );
        assert_eq!(reparsed["error"]["type"], serde_json::json!("not_found"));
    }

    /// MEDIUM/conformance (proto_for_path:75-86): a `GET /v1/models/<id>` whose id legitimately
    /// CONTAINS a colon (OpenAI fine-tuned `ft:...`, deployment-style `gpt-4o:deployment`) must
    /// classify as OpenAI — NOT Gemini — so `model.retrieve` gets an OpenAI-decodable error envelope.
    /// Only the known Gemini ACTION suffixes (`:generateContent`, …) are Gemini.
    #[test]
    fn test_proto_for_path_colon_model_id_is_openai_not_gemini() {
        // OpenAI fine-tuned model id (multiple colons) on the model.retrieve path → OpenAI.
        assert_eq!(
            proto_for_path("/v1/models/ft:gpt-3.5-turbo:my-org::abc123"),
            "openai",
            "a colon-bearing OpenAI fine-tuned model id must stay OpenAI"
        );
        // Azure-style deployment id with a colon → OpenAI.
        assert_eq!(proto_for_path("/v1/models/gpt-4o:deployment"), "openai");
        // Plain model id (no colon) → OpenAI.
        assert_eq!(proto_for_path("/v1/models/gpt-4o"), "openai");
        // A genuine Gemini action suffix → Gemini.
        assert_eq!(
            proto_for_path("/v1/models/gemini-pro:generateContent"),
            "gemini",
            "the Gemini :generateContent action suffix still classifies as Gemini"
        );
        assert_eq!(
            proto_for_path("/v1/models/gemini-pro:streamGenerateContent"),
            "gemini"
        );
        assert_eq!(
            proto_for_path("/v1/models/text-embedding-004:embedContent"),
            "gemini"
        );
        assert_eq!(
            proto_for_path("/v1/models/gemini-pro:countTokens"),
            "gemini"
        );
    }

    /// MEDIUM/conformance (synth_anthropic_request_id): the synthesized `request-id` header value must
    /// carry the native Anthropic shape (`req_01` prefix + non-empty token) so the official SDK reads
    /// a well-formed `Message._request_id` / `APIError.request_id`.
    #[test]
    fn test_synth_anthropic_request_id_is_well_formed() {
        let id = synth_anthropic_request_id().expect("entropy available in test");
        assert!(
            id.starts_with("req_01"),
            "anthropic request-id must carry the native req_01 prefix; got {id}"
        );
        assert!(
            id.len() > "req_01".len(),
            "anthropic request-id must have a token suffix; got {id}"
        );
        // ASCII base62 token (no padding/special chars that a native id never carries).
        let token = &id["req_01".len()..];
        assert!(
            token.bytes().all(|b| b.is_ascii_alphanumeric()),
            "the token must be base62 (alphanumeric); got {token}"
        );
        // Distinct across calls (CSPRNG-backed) — no fixed/predictable id.
        let id2 = synth_anthropic_request_id().expect("entropy available in test");
        assert_ne!(id, id2, "successive ids must differ");
    }

    /// MEDIUM/conformance (GeminiJsonArrayFramer::finish_with_error): the truncation error element must
    /// carry NO busbar-internal vocabulary ("upstream"). A real Gemini API never emits that word, so it
    /// is a fingerprintable tell. The message must read like Gemini's own canonical 500 body.
    #[test]
    fn test_gemini_truncation_error_carries_no_internal_vocabulary() {
        let mut f = GeminiJsonArrayFramer::new();
        // Force the truncation/abort path: a frame with NO terminator that overruns MAX_BUF, mirroring
        // `test_gemini_json_array_framer_finish_signals_abort`.
        let huge = vec![b'x'; GeminiJsonArrayFramer::MAX_BUF + 16];
        let mut pre = Vec::from(&b"data: {\"k\":\""[..]);
        pre.extend_from_slice(&huge);
        let _ = f.feed(&pre);
        let tail = f.finish();
        let body = String::from_utf8_lossy(&tail);
        assert!(
            !body.to_lowercase().contains("upstream"),
            "the truncation error must NOT contain the busbar-internal word 'upstream': {body}"
        );
        assert!(
            body.contains("Internal error encountered."),
            "the truncation error must mirror Gemini's own 500 body text: {body}"
        );
    }

    /// A fresh `IrResponse` constructed with the new identity fields left at their documented
    /// default (`None`) must read back as `None` — guards the foundation that later waves populate.
    #[test]
    fn test_ir_response_identity_fields_default_none() {
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![],
            stop_reason: None,
            usage: crate::ir::IrUsage {
                input_tokens: 0,
                output_tokens: 0,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: None,
            created: None,
            system_fingerprint: None,
            stop_sequence: None,
        };
        assert_eq!(resp.id, None);
        assert_eq!(resp.created, None);
        assert_eq!(resp.system_fingerprint, None);
        assert_eq!(resp.stop_sequence, None);
    }

    /// The streaming-start IR event carries the new identity metadata, defaulting to `None`.
    #[test]
    fn test_ir_message_start_identity_fields_default_none() {
        let ev = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        match ev {
            crate::ir::IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                assert_eq!(id, None);
                assert_eq!(created, None);
                assert_eq!(model, None);
            }
            _ => panic!("constructed a MessageStart"),
        }
    }

    /// Every protocol's writer must produce a non-empty, valid-JSON probe body that carries the
    /// requested model (or, for path-model protocols like Gemini/Bedrock, at least valid JSON) —
    /// this is what the active health prober sends.
    #[test]
    fn test_probe_body_valid_for_all_protocols() {
        for name in [
            "anthropic",
            "openai",
            "gemini",
            "bedrock",
            "responses",
            "cohere",
        ] {
            let proto = protocol_for(name).unwrap();
            let body = proto.writer().probe_body("my-model");
            assert!(!body.is_empty(), "{name}: probe body must be non-empty");
            let v: serde_json::Value = serde_json::from_slice(&body)
                .unwrap_or_else(|e| panic!("{name}: invalid JSON: {e}"));
            assert!(v.is_object(), "{name}: probe body must be a JSON object");
        }
    }

    /// `requires_max_tokens()` must be true exactly for the protocols whose APIs hard-reject a
    /// request lacking `max_tokens` (Anthropic Messages) and false for the rest — including Bedrock,
    /// which defaults maxTokens when omitted. This flag gates the translation-seam injection in
    /// `forward`; a false positive would silently cap a backend's output.
    #[test]
    fn test_requires_max_tokens_per_protocol() {
        for (name, want) in [
            ("anthropic", true),
            ("bedrock", false),
            ("openai", false),
            ("gemini", false),
            ("responses", false),
            ("cohere", false),
        ] {
            let proto = protocol_for(name).unwrap();
            assert_eq!(
                proto.writer().requires_max_tokens(),
                want,
                "{name}: requires_max_tokens() mismatch"
            );
        }
    }

    /// OpenAI-compatible reasoning models put the chain-of-thought in `reasoning_content`; it must
    /// map to a Thinking block (ahead of the answer) so it survives translation to Anthropic.
    #[test]
    fn test_openai_reasoning_content_maps_to_thinking() {
        let body = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "reasoning_content": "step 1: think; step 2: answer",
                    "content": "the answer"
                },
                "finish_reason": "stop"
            }],
            "usage": {"prompt_tokens": 5, "completion_tokens": 7}
        });
        let ir = OpenAiReader.read_response(&body).expect("read_response");
        assert!(
            matches!(ir.content.first(), Some(crate::ir::IrBlock::Thinking { text, .. }) if text == "step 1: think; step 2: answer"),
            "first block should be the reasoning as a Thinking block"
        );
        assert!(
            ir.content.iter().any(
                |b| matches!(b, crate::ir::IrBlock::Text { text, .. } if text == "the answer")
            ),
            "the answer text should follow"
        );
        // And it should render as an Anthropic thinking block on write.
        let wire = AnthropicWriter.write_response(&ir);
        let blocks = wire.get("content").and_then(|c| c.as_array()).unwrap();
        assert!(
            blocks
                .iter()
                .any(|b| b.get("type").and_then(|t| t.as_str()) == Some("thinking")),
            "Anthropic output should contain a thinking block"
        );
    }

    /// Streaming reasoning: `delta.reasoning_content` must open a Thinking block at index 0 and
    /// close it before the text block (which shifts to index 1).
    #[test]
    fn test_openai_streaming_reasoning_blocks() {
        use crate::ir::{IrBlockMeta, IrDelta, IrStreamEvent};
        let reader = OpenAiReader;
        let mut st = crate::ir::StreamDecodeState::default();
        let mut ev = Vec::new();
        ev.extend(reader.read_response_events(
            "",
            &serde_json::json!({"choices":[{"delta":{"reasoning_content":"mulling"}}]}),
            &mut st,
        ));
        ev.extend(reader.read_response_events(
            "",
            &serde_json::json!({"choices":[{"delta":{"content":"answer"}}]}),
            &mut st,
        ));
        ev.extend(reader.read_response_events(
            "",
            &serde_json::json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}),
            &mut st,
        ));

        let think_start = ev.iter().position(|e| {
            matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Thinking
                }
            )
        });
        let think_delta = ev.iter().any(|e| matches!(e, IrStreamEvent::BlockDelta { index: 0, delta: IrDelta::ThinkingDelta(t) } if t == "mulling"));
        let think_stop = ev
            .iter()
            .position(|e| matches!(e, IrStreamEvent::BlockStop { index: 0 }));
        let text_start = ev.iter().position(|e| {
            matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 1,
                    block: IrBlockMeta::Text
                }
            )
        });
        let text_delta = ev.iter().any(|e| matches!(e, IrStreamEvent::BlockDelta { index: 1, delta: IrDelta::TextDelta(t) } if t == "answer"));

        assert!(
            think_start.is_some() && think_delta,
            "reasoning opens a Thinking block at index 0"
        );
        assert!(
            text_start.is_some() && text_delta,
            "text opens at index 1 after reasoning"
        );
        assert!(
            think_stop < text_start,
            "the thinking block must close before the text block opens"
        );
    }

    /// Regression: a normal (no-reasoning) OpenAI stream keeps text at index 0 (offset unchanged).
    #[test]
    fn test_openai_streaming_no_reasoning_text_index_zero() {
        use crate::ir::{IrBlockMeta, IrStreamEvent};
        let reader = OpenAiReader;
        let mut st = crate::ir::StreamDecodeState::default();
        let ev = reader.read_response_events(
            "",
            &serde_json::json!({"choices":[{"delta":{"content":"hi"}}]}),
            &mut st,
        );
        assert!(
            ev.iter().any(|e| matches!(
                e,
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Text
                }
            )),
            "without reasoning, text stays at index 0"
        );
    }

    fn rich_fixture() -> serde_json::Value {
        // temperature is a natural 0.7 — IrRequest.temperature is f64 so it round-trips exactly.
        serde_json::json!({
            "system": [{"type": "text", "text": "You are a helpful assistant.", "cache_control": {"type": "ephemeral"}}],
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "What is the weather?"}, {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="}}]},
                {"role": "assistant", "content": [{"type": "thinking", "thinking": "I need to analyze the weather...", "signature": "sig_abc123xyz"}, {"type": "tool_use", "id": "tool_1", "name": "get_weather", "input": {"location": "San Francisco"}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tool_1", "content": [{"type": "text", "text": "Sunny, 72°F"}]}]}
            ],
            "tools": [{"name": "get_weather", "description": "Get weather for a location", "input_schema": {"type": "object", "properties": {"location": {"type": "string"}}, "required": ["location"]}}],
            "max_tokens": 4096,
            "temperature": 0.7,
            "stream": true,
            "top_p": 0.95
        })
    }

    #[test]
    fn test_openai_tool_schema_translates_to_anthropic() {
        // Regression: OpenAI nests name/description/parameters under `function`. The reader must
        // descend into it so the JSON schema reaches Anthropic's `input_schema` — otherwise the
        // translated tool has `input_schema: null` and the Anthropic backend 422s.
        let openai_body = serde_json::json!({
            "model": "x",
            "max_tokens": 200,
            "messages": [{"role": "user", "content": "weather in Paris?"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get weather",
                    "parameters": {
                        "type": "object",
                        "properties": {"city": {"type": "string"}},
                        "required": ["city"]
                    }
                }
            }]
        });
        let ir = OpenAiReader
            .read_request(&openai_body)
            .expect("openai read_request");
        assert_eq!(ir.tools.len(), 1);
        assert_eq!(
            ir.tools[0].name, "get_weather",
            "tool name (nested under function)"
        );
        assert_eq!(
            ir.tools[0].input_schema["properties"]["city"]["type"], "string",
            "parameters schema must be read into IrTool.input_schema"
        );

        let anthropic = AnthropicWriter.write_request(&ir);
        let tools = anthropic.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools[0]["name"], "get_weather");
        assert!(
            !tools[0]["input_schema"].is_null(),
            "Anthropic tool input_schema must not be null (caused the 422)"
        );
        assert_eq!(
            tools[0]["input_schema"]["properties"]["city"]["type"], "string",
            "the full JSON schema must survive OpenAI → Anthropic translation"
        );
    }

    #[test]
    fn test_roundtrip_identity() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        let roundtrip = writer.write_request(&ir);
        assert_eq!(
            roundtrip, j,
            "round-trip must be byte-identical on representable subset"
        );
    }

    #[test]
    fn test_signature_verbatim() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        let mut found_thinking = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::Assistant {
                for block in &msg.content {
                    if let crate::ir::IrBlock::Thinking { text: _, signature } = block {
                        found_thinking = true;
                        assert_eq!(signature.as_deref(), Some("sig_abc123xyz"));
                    }
                }
            }
        }
        assert!(found_thinking);
        let roundtrip = writer.write_request(&ir);
        if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
            for msg_val in msgs {
                if let Some(content_arr) = msg_val.get("content").and_then(|v| v.as_array()) {
                    for block_val in content_arr {
                        if let Some(block_obj) = block_val.as_object() {
                            if block_obj.get("type").and_then(|t| t.as_str()) == Some("thinking") {
                                assert_eq!(
                                    block_obj.get("signature").and_then(|s| s.as_str()),
                                    Some("sig_abc123xyz")
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_cache_control_preserved() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        assert!(!ir.system.is_empty());
        if let crate::ir::IrBlock::Text {
            text: _,
            cache_control,
            citations: _,
        } = &ir.system[0]
        {
            assert!(cache_control.is_some());
            match cache_control.as_ref().unwrap().kind {
                crate::ir::CacheKind::Ephemeral => {}
            };
        }
        let roundtrip = writer.write_request(&ir);
        if let Some(system_arr) = roundtrip.get("system").and_then(|v| v.as_array()) {
            if let Some(first_block) = system_arr.first() {
                assert!(first_block
                    .as_object()
                    .unwrap()
                    .contains_key("cache_control"));
            }
        }
    }

    #[test]
    fn test_extra_passthrough() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();
        let j = rich_fixture();
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        // top_p is now a first-class IR sampling control (promoted out of `extra` so it survives the
        // cross-protocol seam); it must NOT linger in `extra` but MUST still round-trip via the typed
        // field into the written body.
        assert!(!ir.extra.contains_key("top_p"));
        assert!(ir.top_p.is_some());
        let roundtrip = writer.write_request(&ir);
        assert!(roundtrip.as_object().unwrap().contains_key("top_p"));
    }

    // Finding 2 (native control fields dropped on cross-protocol hops). The universally-modeled
    // sampling controls (top_p, top_k, stop) are now first-class IR fields, so they survive the
    // cross-protocol seam (which CLEARS `ir.extra` to stop source-only key leakage). Each test reads
    // a native request, CLEARS `extra` to simulate the seam (forward.rs `ir.extra.clear()`), then
    // writes through a DIFFERENT protocol and asserts the control reappears in that protocol's native
    // shape. Were these still extra-only, the clear would drop them.

    #[test]
    fn test_cross_protocol_openai_top_p_to_anthropic() {
        let body = serde_json::json!({
            "model":"gpt-x",
            "messages":[{"role":"user","content":"hi"}],
            "top_p":0.81
        });
        let mut ir = OpenAiReader.read_request(&body).expect("openai parses");
        assert_eq!(ir.top_p, Some(0.81));
        ir.extra.clear(); // simulate the cross-protocol seam
        let out = AnthropicWriter.write_request(&ir);
        assert_eq!(
            out.get("top_p").and_then(|v| v.as_f64()),
            Some(0.81),
            "openai top_p must translate to anthropic top_p across the seam; got {out}"
        );
    }

    #[test]
    fn test_cross_protocol_gemini_stop_sequences_to_openai_stop() {
        let body = serde_json::json!({
            "model":"gemini-x",
            "contents":[{"role":"user","parts":[{"text":"hi"}]}],
            "generationConfig":{"stopSequences":["STOP","END"]}
        });
        let mut ir = GeminiReader.read_request(&body).expect("gemini parses");
        assert_eq!(ir.stop, vec!["STOP".to_string(), "END".to_string()]);
        ir.extra.clear(); // simulate the cross-protocol seam
        let out = OpenAiWriter.write_request(&ir);
        assert_eq!(
            out.get("stop"),
            Some(&serde_json::json!(["STOP", "END"])),
            "gemini stopSequences must translate to openai stop across the seam; got {out}"
        );
    }

    #[test]
    fn test_cross_protocol_anthropic_top_k_to_gemini() {
        let body = serde_json::json!({
            "model":"claude-x",
            "messages":[{"role":"user","content":"hi"}],
            "max_tokens":16,
            "top_k":40
        });
        let mut ir = AnthropicReader
            .read_request(&body)
            .expect("anthropic parses");
        assert_eq!(ir.top_k, Some(40));
        ir.extra.clear(); // simulate the cross-protocol seam
        let writer = GeminiWriter;
        let out = writer.write_request(&ir);
        assert_eq!(
            out.pointer("/generationConfig/topK")
                .and_then(|v| v.as_u64()),
            Some(40),
            "anthropic top_k must translate to gemini generationConfig.topK; got {out}"
        );
    }

    // top_k has NO OpenAI target: the OpenAI writer must NOT invent one (lossy-by-target, not a leak).
    #[test]
    fn test_cross_protocol_top_k_dropped_for_openai_target() {
        let body = serde_json::json!({
            "model":"claude-x",
            "messages":[{"role":"user","content":"hi"}],
            "max_tokens":16,
            "top_k":40
        });
        let mut ir = AnthropicReader
            .read_request(&body)
            .expect("anthropic parses");
        ir.extra.clear();
        let out = OpenAiWriter.write_request(&ir);
        assert!(
            out.get("top_k").is_none() && out.get("k").is_none(),
            "OpenAI has no top_k knob; the writer must not synthesize one; got {out}"
        );
    }

    #[test]
    fn test_registry_resolves_anthropic() {
        let registry = ProtocolRegistry::with_builtins();

        // Anthropic should be present
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        assert_eq!(protocol.name(), "anthropic");
        assert_eq!(protocol.writer().upstream_path(), "/v1/messages");

        // Non-existent should return None
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_reader_classify_behavior() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let reader = protocol.reader();

        // Test 429 → RateLimit
        let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
        assert_eq!(signal.class, StatusClass::RateLimit);

        // Test 401 → Auth
        let signal = reader.classify(StatusCode::UNAUTHORIZED, b"{}");
        assert_eq!(signal.class, StatusClass::Auth);

        // Test 503 → ServerError
        let signal = reader.classify(StatusCode::SERVICE_UNAVAILABLE, b"{}");
        assert_eq!(signal.class, StatusClass::ServerError);
    }

    #[test]
    fn test_writer_auth_headers() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("anthropic").expect("anthropic should exist");
        let writer = protocol.writer();

        let headers = writer.auth_headers("k");
        let header_names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).collect();

        assert!(header_names.contains(&"x-api-key"));
        assert!(header_names.contains(&"anthropic-version"));
    }

    #[test]
    fn test_irerror_bridge() {
        // IrError IS CanonicalSignal - construct and verify
        let ir_error: IrError = IrError {
            class: StatusClass::Billing,
            provider_signal: Some("test".to_string()),
            retry_after: None,
        };

        assert_eq!(ir_error.class, StatusClass::Billing);
    }

    #[test]
    fn test_stream_roundtrip_identity() {
        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        // message_start with usage. `write_response_event` runs ONLY on the cross-protocol
        // StreamTranslate path (same-protocol streams pass raw bytes through), so the writer ALWAYS
        // emits the full native skeleton — `id` (synthesized when absent), `type`, `content[]`,
        // `stop_reason`, `stop_sequence` — that every native Anthropic message_start carries. Assert
        // those structural fields (the synthesized `id` is non-deterministic) plus the round-tripped
        // usage, rather than byte-identity to the bare input.
        let data = serde_json::json!({
            "message": {
                "role": "assistant",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_creation_input_tokens": 5,
                    "cache_read_input_tokens": 15
                }
            }
        });
        let ev = reader.read_response_event("message_start", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            let (et, out) = writer
                .write_response_event(&e)
                .expect("writes message_start");
            assert_eq!(et, "message_start");
            let msg = out.get("message").expect("message object");
            assert!(
                msg.get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .starts_with("msg_"),
                "synthesized id must be msg_-prefixed: {out}"
            );
            assert_eq!(msg.get("type").and_then(|v| v.as_str()), Some("message"));
            assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
            assert!(msg.get("content").and_then(|c| c.as_array()).is_some());
            assert!(msg.get("stop_reason").map(|v| v.is_null()).unwrap_or(false));
            assert!(msg
                .get("stop_sequence")
                .map(|v| v.is_null())
                .unwrap_or(false));
            assert_eq!(
                msg.get("usage").and_then(|u| u.get("input_tokens")),
                Some(&serde_json::json!(10))
            );
        }

        // content_block_start for tool_use. Fixtures carry the top-level `type` field that native
        // Anthropic SSE data bodies include and that `AnthropicWriter::write_response_event` now emits
        // (the reader dispatches on the SSE `event:` header, not `data.type`, so the field is dropped
        // on read and re-synthesized by the writer — exact-equality holds with `type` present in the
        // fixture).
        let data = serde_json::json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "tool_use",
                "id": "tool_123",
                "name": "get_weather"
            }
        });
        let ev = reader.read_response_event("content_block_start", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_start".to_string(), data))
            );
        }

        // content_block_delta - text_delta
        let data = serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {
                "type": "text_delta",
                "text": "hello"
            }
        });
        let ev = reader.read_response_event("content_block_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), data))
            );
        }

        // content_block_delta - thinking_delta
        let data = serde_json::json!({
            "type": "content_block_delta",
            "index": 1,
            "delta": {
                "type": "thinking_delta",
                "thinking": "I need to think"
            }
        });
        let ev = reader.read_response_event("content_block_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), data))
            );
        }

        // content_block_delta - input_json_delta
        let data = serde_json::json!({
            "type": "content_block_delta",
            "index": 2,
            "delta": {
                "type": "input_json_delta",
                "partial_json": "{\"loc"
            }
        });
        let ev = reader.read_response_event("content_block_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), data))
            );
        }

        // content_block_delta - signature_delta
        let data = serde_json::json!({
            "type": "content_block_delta",
            "index": 1,
            "delta": {
                "type": "signature_delta",
                "signature": "sig_abc123xyz"
            }
        });
        let ev = reader.read_response_event("content_block_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_delta".to_string(), data))
            );
        }

        // content_block_stop
        let data = serde_json::json!({ "type": "content_block_stop", "index": 0 });
        let ev = reader.read_response_event("content_block_stop", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("content_block_stop".to_string(), data))
            );
        }

        // message_delta with usage. Native Anthropic ALWAYS carries `delta.stop_sequence` (explicit
        // `null` when no stop sequence fired), so the round-tripped frame includes it.
        let data = serde_json::json!({
            "type": "message_delta",
            "delta": { "stop_reason": "end_turn", "stop_sequence": null },
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_creation_input_tokens": 5,
                "cache_read_input_tokens": 15
            }
        });
        let ev = reader.read_response_event("message_delta", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("message_delta".to_string(), data))
            );
        }

        // message_stop
        let data = serde_json::json!({ "type": "message_stop" });
        let ev = reader.read_response_event("message_stop", &data);
        assert!(ev.is_some());
        if let Some(e) = ev {
            assert_eq!(
                writer.write_response_event(&e),
                Some(("message_stop".to_string(), data))
            );
        }
    }

    #[test]
    fn test_split_usage_never_collapses() {
        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        // message_delta with all four usage fields distinct
        let data = serde_json::json!({
            "delta": { "stop_reason": "end_turn" },
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50,
                "cache_creation_input_tokens": 30,
                "cache_read_input_tokens": 200
            }
        });

        let ev = reader
            .read_response_event("message_delta", &data)
            .expect("should parse");
        if let crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: _,
            usage,
            ..
        } = ev
        {
            assert_eq!(usage.input_tokens, 100);
            assert_eq!(usage.output_tokens, 50);
            assert_eq!(usage.cache_creation_input_tokens, Some(30));
            assert_eq!(usage.cache_read_input_tokens, Some(200));
            // Verify they weren't collapsed: input_tokens != sum of cache tokens
            assert_ne!(100, 30 + 200);
        } else {
            panic!("expected MessageDelta");
        }

        let roundtrip = writer.write_response_event(&crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 100,
                output_tokens: 50,
                cache_creation_input_tokens: Some(30),
                cache_read_input_tokens: Some(200),
            },
        });
        assert!(roundtrip.is_some());
        let (_, rt_data) = roundtrip.unwrap();
        assert_eq!(
            rt_data
                .get("usage")
                .and_then(|u| u.get("input_tokens"))
                .and_then(|v| v.as_u64()),
            Some(100)
        );
        assert_eq!(
            rt_data
                .get("usage")
                .and_then(|u| u.get("output_tokens"))
                .and_then(|v| v.as_u64()),
            Some(50)
        );
        assert_eq!(
            rt_data
                .get("usage")
                .and_then(|u| u.get("cache_creation_input_tokens"))
                .and_then(|v| v.as_u64()),
            Some(30)
        );
        assert_eq!(
            rt_data
                .get("usage")
                .and_then(|u| u.get("cache_read_input_tokens"))
                .and_then(|v| v.as_u64()),
            Some(200)
        );
    }

    #[test]
    fn test_signature_delta_verbatim() {
        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        // Signature delta with byte-identical string
        let sig = "sig_abc123xyz_signature_for_thinking";
        let data = serde_json::json!({
            "index": 0,
            "delta": {
                "type": "signature_delta",
                "signature": sig
            }
        });

        let ev = reader
            .read_response_event("content_block_delta", &data)
            .expect("should parse");
        if let crate::ir::IrStreamEvent::BlockDelta { index: _, delta } = ev {
            if let crate::ir::IrDelta::SignatureDelta(s) = delta {
                assert_eq!(s, sig);
            } else {
                panic!("expected SignatureDelta");
            }
        } else {
            panic!("expected BlockDelta");
        }

        let roundtrip = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::SignatureDelta(sig.to_string()),
        });
        assert!(roundtrip.is_some());
        let (_, rt_data) = roundtrip.unwrap();
        let rt_sig = rt_data
            .get("delta")
            .and_then(|d| d.get("signature"))
            .and_then(|s| s.as_str())
            .unwrap();
        assert_eq!(rt_sig, sig);
    }

    #[test]
    fn test_ping_returns_none() {
        let reader = AnthropicReader;
        let data = serde_json::json!({});
        let result = reader.read_response_event("ping", &data);
        assert!(result.is_none());

        // Unknown event type also returns None
        let result = reader.read_response_event("unknown_event_type", &data);
        assert!(result.is_none());
    }

    #[test]
    fn test_openai_request_roundtrip_identity() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();

        // Canonical OpenAI request with system message, user+image, assistant tool_call, tool_result, tools array, max_tokens, temperature:0.7, stream:true, top_p→extra
        let j = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": [{"type": "text", "text": "hello"}, {"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}]},
                {"role": "assistant", "tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\":\"San Francisco\"}"}}]},
                {"role": "tool", "tool_call_id": "call_123", "content": "Sunny, 72°F"}
            ],
            "tools": [{"type": "function", "name": "get_weather", "description": "Get weather for a location", "parameters": {"type": "object", "properties": {"location": {"type": "string"}}, "required": ["location"]}}],
            "max_tokens": 100,
            "temperature": 0.7,
            "stream": true,
            "top_p": 0.95
        });

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        let roundtrip = writer.write_request(&ir);

        // Compare structurally rather than byte-identical since IR doesn't preserve model field and tool_call ids are regenerated
        assert_eq!(
            roundtrip
                .as_object()
                .unwrap()
                .get("messages")
                .and_then(|v| v.as_array())
                .map(|a| a.len()),
            j.get("messages")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
        );
        assert_eq!(
            roundtrip.as_object().unwrap().get("max_tokens"),
            j.as_object().unwrap().get("max_tokens")
        );
        assert_eq!(
            roundtrip.as_object().unwrap().get("temperature"),
            j.as_object().unwrap().get("temperature")
        );
        assert_eq!(
            roundtrip.as_object().unwrap().get("stream"),
            j.as_object().unwrap().get("stream")
        );
        assert_eq!(
            roundtrip.as_object().unwrap().get("top_p"),
            j.as_object().unwrap().get("top_p")
        );

        // Correctness-critical: the tool_call id must round-trip VERBATIM (not be regenerated),
        // so the assistant tool_call still correlates with the tool-result `tool_call_id`.
        let msgs = roundtrip
            .get("messages")
            .and_then(|v| v.as_array())
            .unwrap();
        let written_id = msgs
            .iter()
            .find_map(|m| m.get("tool_calls").and_then(|tc| tc.as_array()))
            .and_then(|tc| tc.first())
            .and_then(|c| c.get("id"))
            .and_then(|i| i.as_str());
        assert_eq!(
            written_id,
            Some("call_123"),
            "tool_call id must round-trip verbatim, not be regenerated"
        );
        // And the tool-result must still reference that same id (correlation preserved).
        let result_ref = msgs
            .iter()
            .find(|m| m.get("role").and_then(|r| r.as_str()) == Some("tool"))
            .and_then(|m| m.get("tool_call_id"))
            .and_then(|i| i.as_str());
        assert_eq!(
            result_ref,
            Some("call_123"),
            "tool-result correlation must survive round-trip"
        );
    }

    #[test]
    fn test_openai_tool_call_arguments_string_to_value() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();
        let writer = protocol.writer();

        // Test with arguments that parse to a JSON object
        let j = serde_json::json!({
            "model": "gpt-4",
            "messages": [
                {"role": "assistant", "tool_calls": [{"id": "call_123", "type": "function", "function": {"name": "get_weather", "arguments": "{\"location\":\"San Francisco\"}"}}]}
            ]
        });

        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        // Find the ToolUse block and verify arguments parsed to Value
        let mut found_tool_use = false;
        for msg in &ir.messages {
            if msg.role == crate::ir::IrRole::Assistant {
                for block in &msg.content {
                    if let crate::ir::IrBlock::ToolUse { id, name, input } = block {
                        found_tool_use = true;
                        assert_eq!(id, "call_123");
                        assert_eq!(name, "get_weather");
                        // Verify arguments parsed to an object Value
                        match input {
                            serde_json::Value::Object(_) => {}
                            _ => panic!("arguments should parse to Object"),
                        }
                    }
                }
            }
        }
        assert!(found_tool_use);

        let roundtrip = writer.write_request(&ir);

        // Re-parse the arguments from roundtrip and compare parsed values
        if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
            for msg_val in msgs {
                if let Some(tc_arr) = msg_val.get("tool_calls").and_then(|v| v.as_array()) {
                    for tc_val in tc_arr {
                        if let Some(func) = tc_val.get("function") {
                            let args_str =
                                func.get("arguments").and_then(|a| a.as_str()).unwrap_or("");
                            let roundtrip_args: serde_json::Value =
                                serde_json::from_str(args_str).expect("args should parse");

                            // Original parsed value
                            let orig_input = &ir.messages[0].content[0];
                            if let crate::ir::IrBlock::ToolUse { input, .. } = orig_input {
                                assert_eq!(roundtrip_args, *input, "parsed arguments must match");
                            } else {
                                panic!("expected ToolUse block");
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_registry_has_both_protocols() {
        let registry = ProtocolRegistry::with_builtins();

        // Both should exist
        assert!(
            registry.get("anthropic").is_some(),
            "anthropic should exist"
        );
        assert!(registry.get("openai").is_some(), "openai should exist");

        // Verify openai writer path
        let openai = registry.get("openai").expect("openai should exist");
        assert_eq!(openai.writer().upstream_path(), "/v1/chat/completions");

        // Verify anthropic writer path
        let anthropic = registry.get("anthropic").expect("anthropic should exist");
        assert_eq!(anthropic.writer().upstream_path(), "/v1/messages");
    }

    #[test]
    fn test_protocol_clone_works() {
        // Test OpenAI protocol clone doesn't panic
        let openai_proto = Protocol::openai();
        let cloned_openai = openai_proto.clone();

        assert_eq!(openai_proto.name(), cloned_openai.name());
        assert_eq!(
            openai_proto.writer().upstream_path(),
            cloned_openai.writer().upstream_path()
        );

        // Test Anthropic protocol clone doesn't panic
        let anthropic_proto = Protocol::anthropic();
        let cloned_anthropic = anthropic_proto.clone();

        assert_eq!(anthropic_proto.name(), cloned_anthropic.name());
        assert_eq!(
            anthropic_proto.writer().upstream_path(),
            cloned_anthropic.writer().upstream_path()
        );

        // Verify clone_box works for trait objects (just check it doesn't panic and returns same type)
        let openai_reader: Box<dyn ProtocolReader> = Box::new(OpenAiReader);
        let _cloned_reader = openai_reader.clone();

        let openai_writer: Box<dyn ProtocolWriter> = Box::new(OpenAiWriter);
        let _cloned_writer = openai_writer.clone();
    }

    #[test]
    fn test_openai_classify() {
        let registry = ProtocolRegistry::with_builtins();
        let protocol = registry.get("openai").expect("openai should exist");
        let reader = protocol.reader();

        // Test 429 → RateLimit
        let signal = reader.classify(StatusCode::TOO_MANY_REQUESTS, b"{}");
        assert_eq!(signal.class, StatusClass::RateLimit);

        // Test 401 → Auth
        let signal = reader.classify(StatusCode::UNAUTHORIZED, b"{}");
        assert_eq!(signal.class, StatusClass::Auth);

        // Test 503 → ServerError
        let signal = reader.classify(StatusCode::SERVICE_UNAVAILABLE, b"{}");
        assert_eq!(signal.class, StatusClass::ServerError);

        // Test 403 → Auth
        let signal = reader.classify(StatusCode::FORBIDDEN, b"{}");
        assert_eq!(signal.class, StatusClass::Auth);
    }

    #[cfg(test)]
    mod ir_property_tests {
        use super::*;

        // ============================================================================
        // A. Anthropic REQUEST property tests (decode assertions + round-trip)
        // ============================================================================

        /// Rich canonical Anthropic fixture with natural values only (0.7, "hello", 10, "call_123").
        fn anthropic_rich_fixture() -> serde_json::Value {
            serde_json::json!({
                "system": [
                    {
                        "type": "text",
                        "text": "You are a helpful assistant.",
                        "cache_control": {"type": "ephemeral"}
                    }
                ],
                "messages": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "hello"},
                            {
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": "image/png",
                                    "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"
                                }
                            }
                        ]
                    },
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "thinking",
                                "thinking": "I need to analyze this request carefully...",
                                "signature": "sig_thinking_abc123"
                            },
                            {
                                "type": "tool_use",
                                "id": "call_123",
                                "name": "get_weather",
                                "input": {"location": "San Francisco"}
                            }
                        ]
                    },
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "call_123",
                                "content": [{"type": "text", "text": "Sunny, 72°F"}],
                                "is_error": false
                            }
                        ]
                    }
                ],
                "tools": [
                    {
                        "name": "get_weather",
                        "description": "Get weather for a location",
                        "input_schema": {
                            "type": "object",
                            "properties": {"location": {"type": "string"}},
                            "required": ["location"]
                        }
                    }
                ],
                "max_tokens": 10,
                "temperature": 0.7,
                "stream": true,
                "top_p": 0.95
            })
        }

        #[test]
        fn test_anthropic_request_decode_assertions() {
            // DECODE assertions on rich canonical fixture - exact field values that a doctored
            // fixture cannot fake (anti-fab / + #10)
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("anthropic").expect("anthropic should exist");
            let reader = protocol.reader();
            let j = anthropic_rich_fixture();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Assert system[0] has cache_control Some(Ephemeral) & text
            assert!(!ir.system.is_empty());
            if let crate::ir::IrBlock::Text {
                ref text,
                ref cache_control,
                ref citations,
            } = ir.system[0]
            {
                assert_eq!(text, "You are a helpful assistant.");
                assert!(cache_control.is_some());
                match cache_control.as_ref().unwrap().kind {
                    crate::ir::CacheKind::Ephemeral => {}
                }
                assert!(citations.is_empty());
            } else {
                panic!("system[0] should be Text block");
            }

            // Assert the Thinking signature String == "sig_thinking_abc123"
            let mut found_assistant = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Assistant {
                    found_assistant = true;
                    let mut found_thinking = false;
                    for block in &msg.content {
                        if let crate::ir::IrBlock::Thinking {
                            text: _,
                            ref signature,
                        } = block
                        {
                            found_thinking = true;
                            assert_eq!(signature.as_deref(), Some("sig_thinking_abc123"));
                        }
                    }
                    assert!(found_thinking);
                }
            }
            assert!(found_assistant);

            // Assert ToolUse id/name/input
            let mut found_tool_use = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Assistant {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolUse { id, name, input } = block {
                            found_tool_use = true;
                            assert_eq!(id, "call_123");
                            assert_eq!(name, "get_weather");
                            match input {
                                serde_json::Value::Object(obj) => {
                                    assert_eq!(
                                        obj.get("location"),
                                        Some(&serde_json::json!("San Francisco"))
                                    );
                                }
                                _ => panic!("input should be Object"),
                            }
                        }
                    }
                }
            }
            assert!(found_tool_use);

            // Assert Image media_type+data in user message
            let mut found_image = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::User {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::Image {
                            ref media_type,
                            ref data,
                        } = block
                        {
                            found_image = true;
                            assert_eq!(media_type, "image/png");
                            assert_eq!(data, "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ");
                        }
                    }
                }
            }
            assert!(found_image);

            // Assert tool_result tool_use_id == "call_123" (correlation)
            let mut found_tool_result = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::User {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolResult {
                            ref tool_use_id,
                            ref content,
                            ref is_error,
                        } = block
                        {
                            found_tool_result = true;
                            assert_eq!(tool_use_id, "call_123");
                            assert!(!content.is_empty());
                            assert!(!*is_error);
                        }
                    }
                }
            }
            assert!(found_tool_result);

            // Assert temperature == Some(0.7) (f64, exact - natural value not 0.699999988)
            assert_eq!(ir.temperature, Some(0.7_f64));

            // top_p is now promoted to a first-class IR field (so it survives the cross-protocol
            // seam): it must be carried in `ir.top_p`, NOT left in `extra`.
            assert!(!ir.extra.contains_key("top_p"));
            assert_eq!(ir.top_p, Some(0.95_f64));
        }

        #[test]
        fn test_anthropic_request_roundtrip_identity() {
            // Round-trip identity: semantic equivalence via decoded IR (NOT byte-identical) because
            // serializer adds is_error:false for tool_result blocks that had no is_error field in input.
            // This is documented semantic equivalence per anti-fab spec - assert on DECODED IR directly
            // which is the ground truth that a doctored fixture cannot fake (+ #10).
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("anthropic").expect("anthropic should exist");
            let reader = protocol.reader();
            let writer = protocol.writer();
            let j = anthropic_rich_fixture();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Round-trip the JSON through write + read and verify DECODED IR is identical
            let roundtrip_json = writer.write_request(&ir);
            let rt_ir = reader
                .read_request(&roundtrip_json)
                .expect("read round-trip should succeed");

            // Assert decoded IR is byte-identical (ground truth for anti-fab)
            assert_eq!(ir, rt_ir, "decoded IR must be identical after round-trip");
        }

        #[test]
        fn test_anthropic_request_empty_minimal() {
            // Empty/minimal: a bare {"messages":[{"role":"user","content":"hi"}]} round-trips and decodes
            let j = serde_json::json!({
                "messages": [{"role": "user", "content": "hi"}]
            });

            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("anthropic").expect("anthropic should exist");
            let reader = protocol.reader();
            let writer = protocol.writer();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Assert empty/minimal properties
            assert!(ir.system.is_empty());
            assert_eq!(ir.messages.len(), 1);
            assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
            if let crate::ir::IrBlock::Text { ref text, .. } = ir.messages[0].content[0] {
                assert_eq!(text, "hi");
            } else {
                panic!("expected Text block");
            }
            assert!(ir.tools.is_empty());
            assert_eq!(ir.max_tokens, None);
            assert_eq!(ir.temperature, None);
            assert!(!ir.stream);

            // Round-trip: semantic equivalence (NOT byte-identical) because serializer always outputs
            // content as array even for single text block - this is a known serialization difference
            let roundtrip = writer.write_request(&ir);

            // Verify semantic equivalence via decoded IR
            let rt_ir = reader
                .read_request(&roundtrip)
                .expect("read round-trip should succeed");
            assert_eq!(ir, rt_ir);
        }

        // ============================================================================
        // B. OpenAI REQUEST property tests (decode assertions + correlation)
        // ============================================================================

        /// Canonical OpenAI fixture with natural values only.
        fn openai_rich_fixture() -> serde_json::Value {
            serde_json::json!({
                "model": "gpt-4",
                "messages": [
                    {"role": "system", "content": "You are a helpful assistant."},
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "hello"},
                            {"type": "image_url", "image_url": {"url": "https://example.com/image.png"}}
                        ]
                    },
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "get_weather",
                                    "arguments": "{\"location\":\"San Francisco\"}"
                                }
                            }
                        ]
                    },
                    {"role": "tool", "tool_call_id": "call_123", "content": "Sunny, 72°F"}
                ],
                "tools": [
                    {
                        "type": "function",
                        "name": "get_weather",
                        "description": "Get weather for a location",
                        "parameters": {
                            "type": "object",
                            "properties": {"location": {"type": "string"}},
                            "required": ["location"]
                        }
                    }
                ],
                "max_tokens": 100,
                "temperature": 0.7,
                "stream": true,
                "top_p": 0.95
            })
        }

        #[test]
        fn test_openai_request_decode_assertions() {
            // DECODE assertions on canonical OpenAI fixture - exact field values that a doctored
            // fixture cannot fake (anti-fab / + #10)
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("openai").expect("openai should exist");
            let reader = protocol.reader();
            let j = openai_rich_fixture();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Assert system decoded from messages[0] (OpenAI convention)
            assert!(!ir.system.is_empty());
            if let crate::ir::IrBlock::Text { ref text, .. } = ir.system[0] {
                assert_eq!(text, "You are a helpful assistant.");
            } else {
                panic!("system[0] should be Text block");
            }

            // Assert ToolUse id == "call_123" (NOT regenerated)
            let mut found_tool_use = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Assistant {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolUse { id, name, .. } = block {
                            found_tool_use = true;
                            assert_eq!(id, "call_123", "ToolUse id must be verbatim from input");
                            assert_eq!(name, "get_weather");
                        }
                    }
                }
            }
            assert!(found_tool_use);

            // Assert the tool_result tool_use_id == "call_123" (correlation)
            let mut found_tool_result = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Tool {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolResult {
                            ref tool_use_id, ..
                        } = block
                        {
                            found_tool_result = true;
                            assert_eq!(
                                tool_use_id, "call_123",
                                "tool_result correlation must survive"
                            );
                        }
                    }
                }
            }
            assert!(found_tool_result);

            // Assert image url preserved in Image.data
            let mut found_image = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::User {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::Image {
                            media_type: _,
                            ref data,
                        } = block
                        {
                            found_image = true;
                            assert_eq!(data, "https://example.com/image.png");
                        }
                    }
                }
            }
            assert!(found_image);

            // Assert temperature Some(0.7) (f64, exact natural value)
            assert_eq!(ir.temperature, Some(0.7_f64));
        }

        #[test]
        fn test_openai_tool_call_id_correlation_survives_write() {
            // tool_call id correlation survives write: after write_request, the assistant
            // tool_calls[0].id == "call_123" AND the tool message tool_call_id == "call_123" (same id)
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("openai").expect("openai should exist");
            let reader = protocol.reader();
            let writer = protocol.writer();
            let j = openai_rich_fixture();

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");
            let roundtrip = writer.write_request(&ir);

            // Verify assistant tool_calls[0].id == "call_123"
            if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
                for msg_val in msgs {
                    if let Some(tc_arr) = msg_val.get("tool_calls").and_then(|v| v.as_array()) {
                        for tc_val in tc_arr {
                            if let Some(id) = tc_val.get("id").and_then(|i| i.as_str()) {
                                assert_eq!(
                                    id, "call_123",
                                    "assistant tool_call id must survive write"
                                );
                            }
                        }
                    }
                }
            }

            // Verify tool message tool_call_id == "call_123" (same id)
            if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
                for msg_val in msgs {
                    if msg_val.get("role").and_then(|r| r.as_str()) == Some("tool") {
                        if let Some(tool_call_id) =
                            msg_val.get("tool_call_id").and_then(|i| i.as_str())
                        {
                            assert_eq!(
                                tool_call_id, "call_123",
                                "tool message correlation must survive"
                            );
                        } else {
                            panic!("tool message should have tool_call_id");
                        }
                    }
                }
            }
        }

        #[test]
        fn test_openai_arguments_string_to_value_roundtrip() {
            // arguments string↔Value: OpenAI function `arguments` (JSON string) → ToolUse.input
            // (Value/Object) on read, re-serialized to a string on write that re-parses equal
            let registry = ProtocolRegistry::with_builtins();
            let protocol = registry.get("openai").expect("openai should exist");
            let reader = protocol.reader();
            let writer = protocol.writer();

            let j = serde_json::json!({
                "model": "gpt-4",
                "messages": [
                    {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "id": "call_123",
                                "type": "function",
                                "function": {
                                    "name": "get_weather",
                                    "arguments": "{\"location\":\"San Francisco\",\"unit\":\"celsius\"}"
                                }
                            }
                        ]
                    }
                ]
            });

            let ir = reader
                .read_request(&j)
                .expect("read_request should succeed");

            // Find ToolUse and verify arguments parsed to Value/Object on read
            let mut found_tool_use = false;
            for msg in &ir.messages {
                if msg.role == crate::ir::IrRole::Assistant {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolUse { id, name, input } = block {
                            found_tool_use = true;
                            assert_eq!(id, "call_123");
                            assert_eq!(name, "get_weather");
                            match input {
                                serde_json::Value::Object(obj) => {
                                    assert_eq!(
                                        obj.get("location"),
                                        Some(&serde_json::json!("San Francisco"))
                                    );
                                    assert_eq!(
                                        obj.get("unit"),
                                        Some(&serde_json::json!("celsius"))
                                    );
                                }
                                _ => panic!("arguments should parse to Object Value"),
                            }
                        }
                    }
                }
            }
            assert!(found_tool_use);

            // Write and re-parse arguments from roundtrip
            let roundtrip = writer.write_request(&ir);
            if let Some(msgs) = roundtrip.get("messages").and_then(|v| v.as_array()) {
                for msg_val in msgs {
                    if let Some(tc_arr) = msg_val.get("tool_calls").and_then(|v| v.as_array()) {
                        for tc_val in tc_arr {
                            if let Some(func) = tc_val.get("function") {
                                let args_str =
                                    func.get("arguments").and_then(|a| a.as_str()).unwrap_or("");

                                // Re-parse the serialized string and compare parsed values
                                let roundtrip_args: serde_json::Value =
                                    serde_json::from_str(args_str).expect("args should parse");

                                // Compare with original parsed value
                                if let crate::ir::IrBlock::ToolUse { input, .. } =
                                    &ir.messages[0].content[0]
                                {
                                    assert_eq!(
                                        roundtrip_args, *input,
                                        "re-serialized arguments must equal original parsed Value"
                                    );
                                } else {
                                    panic!("expected ToolUse block");
                                }
                            }
                        }
                    }
                }
            }
        }

        // ============================================================================
        // C. Anthropic RESPONSE/STREAM per-event property tests (read_response_event/write_response_event)
        // ============================================================================

        #[test]
        fn test_anthropic_stream_per_event_roundtrip() {
            // Per-event round-trip for each event type with natural values
            let reader = AnthropicReader;
            let writer = AnthropicWriter;

            // 1. message_start w/ usage incl. cache tokens. The writer (cross-protocol-only path)
            // always emits the full native skeleton with a synthesized `id`, so assert the structural
            // fields + round-tripped usage rather than byte-identity to the bare input.
            let data = serde_json::json!({
                "message": {
                    "role": "assistant",
                    "usage": {
                        "input_tokens": 10,
                        "output_tokens": 20,
                        "cache_creation_input_tokens": 5,
                        "cache_read_input_tokens": 15
                    }
                }
            });
            let ev = reader.read_response_event("message_start", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                let (et, out) = writer
                    .write_response_event(&e)
                    .expect("writes message_start");
                assert_eq!(et, "message_start");
                let msg = out.get("message").expect("message object");
                assert!(
                    msg.get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .starts_with("msg_"),
                    "synthesized id must be msg_-prefixed: {out}"
                );
                assert_eq!(msg.get("type").and_then(|v| v.as_str()), Some("message"));
                assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
                assert!(msg.get("content").and_then(|c| c.as_array()).is_some());
                assert!(msg.get("stop_reason").map(|v| v.is_null()).unwrap_or(false));
                assert!(msg
                    .get("stop_sequence")
                    .map(|v| v.is_null())
                    .unwrap_or(false));
                assert_eq!(
                    msg.get("usage")
                        .and_then(|u| u.get("cache_read_input_tokens")),
                    Some(&serde_json::json!(15))
                );
            }

            // 2. content_block_start tool_use. Fixtures carry the native top-level `type` field
            // (matching the SSE `event:` header) that `AnthropicWriter` now emits; the reader drops it
            // (it dispatches on the header, not `data.type`) and the writer re-synthesizes it, so the
            // same-protocol round-trip stays byte-identical with `type` present in the fixture.
            let data = serde_json::json!({
                "type": "content_block_start",
                "index": 0,
                "content_block": {
                    "type": "tool_use",
                    "id": "call_123",
                    "name": "get_weather"
                }
            });
            let ev = reader.read_response_event("content_block_start", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_start".to_string(), data))
                );
            }

            // 3. content_block_delta ×4 delta kinds (text, thinking, input_json, signature)
            let text_data = serde_json::json!({
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "hello"}
            });
            let ev = reader.read_response_event("content_block_delta", &text_data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_delta".to_string(), text_data))
                );
            }

            let thinking_data = serde_json::json!({
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "thinking_delta", "thinking": "I need to think"}
            });
            let ev = reader.read_response_event("content_block_delta", &thinking_data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_delta".to_string(), thinking_data))
                );
            }

            let json_data = serde_json::json!({
                "type": "content_block_delta",
                "index": 2,
                "delta": {"type": "input_json_delta", "partial_json": "{\"loc"}
            });
            let ev = reader.read_response_event("content_block_delta", &json_data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_delta".to_string(), json_data))
                );
            }

            let sig_data = serde_json::json!({
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "signature_delta", "signature": "sig_thinking_xyz"}
            });
            let ev = reader.read_response_event("content_block_delta", &sig_data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_delta".to_string(), sig_data))
                );
            }

            // 4. content_block_stop
            let data = serde_json::json!({"type": "content_block_stop", "index": 0});
            let ev = reader.read_response_event("content_block_stop", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("content_block_stop".to_string(), data))
                );
            }

            // 5. message_delta w/ usage, no matched stop_sequence (the common case). The source
            // carried no matched `stop_sequence`, so the IR's `stop_sequence` is `None`. Native
            // Anthropic ALWAYS carries `delta.stop_sequence` (explicit `null` when none fired), so
            // the writer emits it as `null` and the round-trip preserves that native shape.
            let data = serde_json::json!({
                "type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_creation_input_tokens": 5,
                    "cache_read_input_tokens": 15
                }
            });
            let ev = reader.read_response_event("message_delta", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                // The IR must carry stop_sequence = None for a delta whose wire had none.
                if let crate::ir::IrStreamEvent::MessageDelta { stop_sequence, .. } = &e {
                    assert_eq!(*stop_sequence, None);
                } else {
                    panic!("expected MessageDelta");
                }
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("message_delta".to_string(), data))
                );
            }

            // 5b. message_delta WHERE a stop_sequence matched (`stop_reason: "stop_sequence"` carries
            // the matched string). The reader now captures `stop_sequence` and the writer re-emits it,
            // so this same-protocol round-trip is byte-faithful — previously the field was dropped.
            let data = serde_json::json!({
                "type": "message_delta",
                "delta": {"stop_reason": "stop_sequence", "stop_sequence": "\n\nHuman:"},
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 20,
                    "cache_creation_input_tokens": 5,
                    "cache_read_input_tokens": 15
                }
            });
            let ev = reader.read_response_event("message_delta", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                if let crate::ir::IrStreamEvent::MessageDelta { stop_sequence, .. } = &e {
                    assert_eq!(stop_sequence.as_deref(), Some("\n\nHuman:"));
                } else {
                    panic!("expected MessageDelta");
                }
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("message_delta".to_string(), data))
                );
            }

            // 6. message_stop
            let data = serde_json::json!({"type": "message_stop"});
            let ev = reader.read_response_event("message_stop", &data);
            assert!(ev.is_some());
            if let Some(e) = ev {
                assert_eq!(
                    writer.write_response_event(&e),
                    Some(("message_stop".to_string(), data))
                );
            }

            // 7. error event
            let data = serde_json::json!({
                "error": {"type": "invalid_request_error"}
            });
            let ev = reader.read_response_event("error", &data);
            assert!(ev.is_some());
        }

        #[test]
        fn test_split_usage_decode_all_fields_distinct() {
            // Split usage decode: a message_delta usage {input 100, output 50, cache_creation 30,
            // cache_read 200} decodes to IrUsage with all four DISTINCT (assert each ==, and input != sum)
            let reader = AnthropicReader;

            let data = serde_json::json!({
                "delta": {"stop_reason": "end_turn"},
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "cache_creation_input_tokens": 30,
                    "cache_read_input_tokens": 200
                }
            });

            let ev = reader
                .read_response_event("message_delta", &data)
                .expect("should parse message_delta");

            if let crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: _,
                usage,
                ..
            } = ev
            {
                // Assert each field == exact value (natural values only)
                assert_eq!(usage.input_tokens, 100);
                assert_eq!(usage.output_tokens, 50);
                assert_eq!(usage.cache_creation_input_tokens, Some(30));
                assert_eq!(usage.cache_read_input_tokens, Some(200));

                // Verify they weren't collapsed: input != sum of cache tokens (anti-fab)
                let cache_sum = 30 + 200;
                assert_ne!(
                    100, cache_sum,
                    "input_tokens must not be collapsed into cache token sum"
                );
            } else {
                panic!("expected MessageDelta event");
            }
        }

        #[test]
        fn test_signature_delta_verbatim_roundtrip() {
            // signature_delta decodes to IrDelta::SignatureDelta(s) with s == input, round-trips
            let reader = AnthropicReader;
            let writer = AnthropicWriter;

            let sig = "sig_thinking_abc123xyz";
            let data = serde_json::json!({
                "index": 0,
                "delta": {
                    "type": "signature_delta",
                    "signature": sig
                }
            });

            // Decode assertion: signature decodes to SignatureDelta(s) with s == input
            let ev = reader
                .read_response_event("content_block_delta", &data)
                .expect("should parse");

            if let crate::ir::IrStreamEvent::BlockDelta { index: _, delta } = ev {
                if let crate::ir::IrDelta::SignatureDelta(s) = delta {
                    assert_eq!(s, sig);
                } else {
                    panic!("expected SignatureDelta variant");
                }
            } else {
                panic!("expected BlockDelta event");
            }

            // Round-trip: write back and verify signature preserved verbatim
            let roundtrip = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::SignatureDelta(sig.to_string()),
            });
            assert!(roundtrip.is_some());
            let (_, rt_data) = roundtrip.unwrap();

            let rt_sig = rt_data
                .get("delta")
                .and_then(|d| d.get("signature"))
                .and_then(|s| s.as_str())
                .unwrap();
            assert_eq!(rt_sig, sig);
        }

        #[test]
        fn test_openai_write_response_event_text_delta() {
            let writer = OpenAiWriter;
            let ev = crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("hello".to_string()),
            };
            let result = writer.write_response_event(&ev);
            assert!(result.is_some());
            let (_, chunk) = result.unwrap();
            assert_eq!(
                chunk.get("object").and_then(|v| v.as_str()),
                Some("chat.completion.chunk")
            );
            let choices = chunk.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(choices.len(), 1);
            let choice = &choices[0];
            assert_eq!(choice.get("index").and_then(|v| v.as_u64()), Some(0));
            assert_eq!(
                choice
                    .get("delta")
                    .and_then(|d| d.get("content").and_then(|c| c.as_str())),
                Some("hello")
            );
        }

        #[test]
        fn test_openai_write_response_event_message_start() {
            let writer = OpenAiWriter;
            let ev = crate::ir::IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            };
            let result = writer.write_response_event(&ev);
            assert!(result.is_some());
            let (_, chunk) = result.unwrap();
            assert_eq!(
                chunk.get("object").and_then(|v| v.as_str()),
                Some("chat.completion.chunk")
            );
            let choices = chunk.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(choices.len(), 1);
            let choice = &choices[0];
            assert_eq!(
                choice
                    .get("delta")
                    .and_then(|d| d.get("role").and_then(|r| r.as_str())),
                Some("assistant")
            );
        }

        #[test]
        fn test_openai_write_response_event_finish_reason_mapping() {
            let writer = OpenAiWriter;

            // end_turn -> stop
            let ev1 = crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            let result1 = writer.write_response_event(&ev1);
            assert!(result1.is_some());
            let (_, chunk1) = result1.unwrap();
            let choices1 = chunk1.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(
                choices1[0].get("finish_reason").and_then(|v| v.as_str()),
                Some("stop")
            );

            // max_tokens -> length
            let ev2 = crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: Some("max_tokens".to_string()),
                stop_sequence: None,
                usage: crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            let result2 = writer.write_response_event(&ev2);
            assert!(result2.is_some());
            let (_, chunk2) = result2.unwrap();
            let choices2 = chunk2.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(
                choices2[0].get("finish_reason").and_then(|v| v.as_str()),
                Some("length")
            );

            // tool_use -> tool_calls
            let ev3 = crate::ir::IrStreamEvent::MessageDelta {
                stop_reason: Some("tool_use".to_string()),
                stop_sequence: None,
                usage: crate::ir::IrUsage {
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_creation_input_tokens: None,
                    cache_read_input_tokens: None,
                },
            };
            let result3 = writer.write_response_event(&ev3);
            assert!(result3.is_some());
            let (_, chunk3) = result3.unwrap();
            let choices3 = chunk3.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(
                choices3[0].get("finish_reason").and_then(|v| v.as_str()),
                Some("tool_calls")
            );
        }

        #[test]
        fn test_openai_write_response_event_tool_call_args() {
            let writer = OpenAiWriter;
            let ev = crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta(r#"{"x":1}"#.to_string()),
            };
            let result = writer.write_response_event(&ev);
            assert!(result.is_some());
            let (_, chunk) = result.unwrap();
            let choices = chunk.get("choices").and_then(|c| c.as_array()).unwrap();
            assert_eq!(choices.len(), 1);
            let choice = &choices[0];
            let tool_calls = choice
                .get("delta")
                .and_then(|d| d.get("tool_calls"))
                .and_then(|tc| tc.as_array())
                .unwrap();
            assert_eq!(tool_calls.len(), 1);
            let func_args = tool_calls[0]
                .get("function")
                .and_then(|f| f.get("arguments"))
                .and_then(|a| a.as_str())
                .unwrap();
            assert_eq!(func_args, r#"{"x":1}"#);
        }

        #[test]
        fn test_openai_write_response_event_lossy_drops() {
            let writer = OpenAiWriter;

            // ThinkingDelta -> None
            let ev1 = crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::ThinkingDelta("thinking...".to_string()),
            };
            assert!(writer.write_response_event(&ev1).is_none());

            // SignatureDelta -> None
            let ev2 = crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::SignatureDelta("sig...".to_string()),
            };
            assert!(writer.write_response_event(&ev2).is_none());

            // BlockStop -> None
            let ev3 = crate::ir::IrStreamEvent::BlockStop { index: 0 };
            assert!(writer.write_response_event(&ev3).is_none());

            // MessageStop -> None
            let ev4 = crate::ir::IrStreamEvent::MessageStop;
            assert!(writer.write_response_event(&ev4).is_none());
        }

        #[test]
        fn test_openai_write_response_event_error() {
            let writer = OpenAiWriter;
            let err = crate::proto::IrError {
                class: crate::breaker::StatusClass::ClientError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            };
            let ev = crate::ir::IrStreamEvent::Error(err);
            let result = writer.write_response_event(&ev);
            assert!(result.is_some());
            let (_, chunk) = result.unwrap();
            assert_eq!(
                chunk
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(|m| m.as_str()),
                Some("boom")
            );
        }
    }
}

#[cfg(test)]
mod stream_fanout_tests {
    use super::*;
    use crate::ir::{IrBlockMeta, IrDelta, IrRole, IrStreamEvent, IrUsage, StreamDecodeState};
    use serde_json::json;

    // OpenAI flat stream → Anthropic-shaped IR events. Exact-sequence decode asserts
    // (ungameable: the expected Vec is derived from the state-machine spec, not from output).
    #[test]
    fn test_openai_read_fanout_text() {
        let reader = OpenAiReader;
        let mut st = StreamDecodeState::default();
        let mut events: Vec<IrStreamEvent> = Vec::new();
        for chunk in [
            json!({"choices":[{"delta":{"role":"assistant"}}]}),
            json!({"choices":[{"delta":{"content":"Hel"}}]}),
            json!({"choices":[{"delta":{"content":"lo"}}]}),
            json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}),
        ] {
            events.extend(reader.read_response_events("", &chunk, &mut st));
        }
        assert_eq!(
            events,
            vec![
                IrStreamEvent::MessageStart {
                    role: IrRole::Assistant,
                    usage: None,
                    id: None,
                    created: None,
                    model: None
                },
                IrStreamEvent::BlockStart {
                    index: 0,
                    block: IrBlockMeta::Text
                },
                IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: IrDelta::TextDelta("Hel".to_string())
                },
                IrStreamEvent::BlockDelta {
                    index: 0,
                    delta: IrDelta::TextDelta("lo".to_string())
                },
                IrStreamEvent::BlockStop { index: 0 },
                IrStreamEvent::MessageDelta {
                    stop_reason: Some("end_turn".to_string()),
                    stop_sequence: None,
                    usage: IrUsage {
                        input_tokens: 10,
                        output_tokens: 5,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None
                    },
                },
                IrStreamEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn test_openai_read_fanout_tool_call() {
        let reader = OpenAiReader;
        let mut st = StreamDecodeState::default();
        let mut events: Vec<IrStreamEvent> = Vec::new();
        for chunk in [
            json!({"choices":[{"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"get_weather","arguments":""}}]}}]}),
            json!({"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"loc\":\"SF\"}"}}]}}]}),
            json!({"choices":[{"delta":{},"finish_reason":"tool_calls"}]}),
        ] {
            events.extend(reader.read_response_events("", &chunk, &mut st));
        }
        assert_eq!(
            events,
            vec![
                IrStreamEvent::MessageStart {
                    role: IrRole::Assistant,
                    usage: None,
                    id: None,
                    created: None,
                    model: None
                },
                IrStreamEvent::BlockStart {
                    index: 1,
                    block: IrBlockMeta::ToolUse {
                        id: "call_1".to_string(),
                        name: "get_weather".to_string()
                    }
                },
                IrStreamEvent::BlockDelta {
                    index: 1,
                    delta: IrDelta::InputJsonDelta(String::new())
                },
                IrStreamEvent::BlockDelta {
                    index: 1,
                    delta: IrDelta::InputJsonDelta("{\"loc\":\"SF\"}".to_string())
                },
                IrStreamEvent::BlockStop { index: 1 },
                IrStreamEvent::MessageDelta {
                    stop_reason: Some("tool_use".to_string()),
                    stop_sequence: None,
                    usage: IrUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None
                    },
                },
                IrStreamEvent::MessageStop,
            ]
        );
    }

    #[test]
    fn test_openai_read_fanout_cached_tokens() {
        let reader = OpenAiReader;
        let mut st = StreamDecodeState::default();
        let mut events: Vec<IrStreamEvent> = Vec::new();
        events.extend(reader.read_response_events(
            "",
            &json!({"choices":[{"delta":{"content":"hi"}}]}),
            &mut st,
        ));
        events.extend(reader.read_response_events(
            "",
            &json!({"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":50,"prompt_tokens_details":{"cached_tokens":7}}}),
            &mut st,
        ));
        let usage = events
            .iter()
            .find_map(|e| match e {
                IrStreamEvent::MessageDelta { usage, .. } => Some(usage.clone()),
                _ => None,
            })
            .expect("MessageDelta present");
        assert_eq!(
            usage.cache_read_input_tokens,
            Some(7),
            "cached_tokens → cache_read"
        );
        assert_eq!(
            usage.cache_creation_input_tokens, None,
            "OpenAI has no cache-creation split"
        );
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
    }

    #[test]
    fn test_anthropic_read_events_wraps_singular() {
        let reader = AnthropicReader;
        let mut st = StreamDecodeState::default();
        let data = json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}});
        let single = reader.read_response_event("content_block_delta", &data);
        let plural = reader.read_response_events("content_block_delta", &data, &mut st);
        assert_eq!(
            plural,
            single.into_iter().collect::<Vec<_>>(),
            "Anthropic plural wraps singular 1:1"
        );
        assert_eq!(plural.len(), 1);
        // ping → empty
        assert_eq!(
            reader.read_response_events("ping", &json!({}), &mut st),
            Vec::<IrStreamEvent>::new()
        );
    }
}

#[cfg(test)]
mod stream_translate_tests {
    use super::*;

    /// The gemini JSON-array framer turns gemini SSE `data:` frames into one streaming JSON array
    /// (`[obj,obj,...]`). The concatenated output must be a syntactically valid JSON array whose
    /// elements are the per-chunk payloads, in order.
    #[test]
    fn test_gemini_json_array_framer_basic() {
        let mut f = GeminiJsonArrayFramer::new();
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&f.feed(b"data: {\"candidates\":[{\"index\":0}]}\n\n"));
        // A split frame yields nothing until the terminator arrives.
        out.extend_from_slice(&f.feed(b"data: {\"candi"));
        out.extend_from_slice(&f.feed(b"dates\":[{\"index\":1}]}\n\n"));
        out.extend_from_slice(&f.finish());
        let parsed: serde_json::Value =
            serde_json::from_slice(&out).expect("framer output must be a valid JSON array");
        let arr = parsed.as_array().expect("must be an array");
        assert_eq!(arr.len(), 2, "two chunks → two array elements");
        assert_eq!(arr[0]["candidates"][0]["index"], 0);
        assert_eq!(arr[1]["candidates"][0]["index"], 1);
    }

    /// An empty stream (no data frame) still finishes as a valid empty JSON array `[]`, and the
    /// `[DONE]`/keepalive SSE sentinels are dropped (the array close is `finish`'s job).
    #[test]
    fn test_gemini_json_array_framer_empty_and_done() {
        let mut f = GeminiJsonArrayFramer::new();
        let mid = f.feed(b"data: [DONE]\n\n");
        let end = f.finish();
        let mut out = mid;
        out.extend_from_slice(&end);
        assert_eq!(out, b"[]", "empty stream → empty JSON array");
    }

    /// Round-4: `finish_with_error` after real chunks appends a gemini-shaped error element + `]`, so
    /// the body stays a valid JSON array (used on a mid-stream transport failure).
    #[test]
    fn test_gemini_json_array_framer_finish_with_error_closes_array() {
        let mut f = GeminiJsonArrayFramer::new();
        let mut out = f.feed(b"data: {\"candidates\":[{\"index\":0}]}\n\n");
        out.extend_from_slice(&f.finish_with_error(500, "INTERNAL", "boom"));
        let parsed: serde_json::Value =
            serde_json::from_slice(&out).expect("error-terminated body must parse as JSON array");
        let arr = parsed.as_array().expect("array");
        assert_eq!(arr.len(), 2, "one chunk + one trailing error element");
        assert_eq!(arr[1]["error"]["code"], 500);
        assert_eq!(arr[1]["error"]["status"], "INTERNAL");
        // A finish_with_error on an EMPTY stream still yields a valid single-element array.
        let mut g = GeminiJsonArrayFramer::new();
        let only = g.finish_with_error(503, "UNAVAILABLE", "x");
        let pv: serde_json::Value = serde_json::from_slice(&only).expect("parses");
        assert_eq!(pv.as_array().expect("array").len(), 1);
    }

    /// Round-4: when the framer ABORTS (reassembly buffer overran `MAX_BUF` without a terminator),
    /// `finish` must emit a gemini error element instead of a bare `]` that would make the silently
    /// truncated stream look complete.
    #[test]
    fn test_gemini_json_array_framer_finish_signals_abort() {
        let mut f = GeminiJsonArrayFramer::new();
        // Feed a frame with no terminator that overruns MAX_BUF → aborts.
        let huge = vec![b'x'; GeminiJsonArrayFramer::MAX_BUF + 16];
        let mut pre = Vec::from(&b"data: {\"k\":\""[..]);
        pre.extend_from_slice(&huge);
        let _ = f.feed(&pre);
        let out = f.finish();
        let parsed: serde_json::Value =
            serde_json::from_slice(&out).expect("aborted finish must still parse as JSON array");
        let arr = parsed.as_array().expect("array");
        assert!(
            arr.iter().any(|el| el.get("error").is_some()),
            "aborted stream must surface an error element, not a silent bare close; got {parsed}"
        );
    }

    /// Encode one AWS event-stream frame (`:event-type` string header + JSON payload) for tests.
    fn es_frame(event_type: &str, payload: &[u8]) -> Vec<u8> {
        let name = b":event-type";
        let mut headers = vec![name.len() as u8];
        headers.extend_from_slice(name);
        headers.push(7);
        headers.extend_from_slice(&(event_type.len() as u16).to_be_bytes());
        headers.extend_from_slice(event_type.as_bytes());
        let total = 12 + headers.len() + payload.len() + 4;
        let mut f = Vec::new();
        f.extend_from_slice(&(total as u32).to_be_bytes());
        f.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]);
        f.extend_from_slice(&headers);
        f.extend_from_slice(payload);
        f.extend_from_slice(&[0, 0, 0, 0]);
        f
    }

    /// HIGH/conformance regression (eventstream.rs:64): a Bedrock EGRESS that sends a mid-stream
    /// MODELED-EXCEPTION frame (`:message-type: exception` + `:exception-type`, NO `:event-type`)
    /// must surface as a translated ERROR event on the ingress stream, not be silently dropped. Before
    /// the fix, `drain_frames` returned `("", payload)` for the exception frame, the folded `type:""`
    /// fell into the reader's no-op arm, and the ingress client saw an abrupt EOF with no error.
    #[test]
    fn test_translate_bedrock_egress_exception_frame_surfaces_error_to_ingress() {
        let mut st =
            StreamTranslate::new("anthropic", "bedrock").expect("bedrock egress translator");
        let mut bytes = es_frame("messageStart", br#"{"role":"assistant"}"#);
        // A real AWS modeled-exception frame built by the production encoder: ThrottlingException
        // carries `:message-type: exception` + `:exception-type: ThrottlingException` and no
        // `:event-type`. `drain_frames` must normalize it to `throttlingException` so the reader's
        // exception arm fires and emits an IR Error → the Anthropic ingress writes an error event.
        bytes.extend(crate::eventstream::encode_exception_frame(
            "ThrottlingException",
            "rate exceeded mid-stream",
        ));

        let out = String::from_utf8(st.feed(&bytes)).unwrap();
        // The mid-stream exception must reach the client as an Anthropic-native error event, NOT be
        // dropped (which would leave the client on a hanging / EOF-without-terminator stream).
        assert!(
            out.contains("event: error") || out.contains("\"type\":\"error\""),
            "bedrock-egress mid-stream exception must translate to an ingress error event; got:\n{out}"
        );
        // The human message rides through.
        assert!(
            out.contains("rate exceeded mid-stream"),
            "the exception message must reach the ingress error body; got:\n{out}"
        );
    }

    /// a Bedrock ConverseStream (binary event-stream egress) translates to Anthropic SSE for
    /// the caller — proving the eventstream decoder → IR → ingress-writer path end to end.
    #[test]
    fn test_translate_bedrock_eventstream_egress_to_anthropic_ingress() {
        let mut st =
            StreamTranslate::new("anthropic", "bedrock").expect("bedrock egress translator");
        let mut bytes = es_frame("messageStart", br#"{"role":"assistant"}"#);
        bytes.extend(es_frame(
            "contentBlockDelta",
            br#"{"contentBlockIndex":0,"delta":{"text":"Hi"}}"#,
        ));
        bytes.extend(es_frame("contentBlockStop", br#"{"contentBlockIndex":0}"#));
        bytes.extend(es_frame("messageStop", br#"{"stopReason":"end_turn"}"#));
        bytes.extend(es_frame(
            "metadata",
            br#"{"usage":{"inputTokens":5,"outputTokens":2}}"#,
        ));

        let out = String::from_utf8(st.feed(&bytes)).unwrap();
        // Anthropic SSE framing with the translated content.
        assert!(out.contains("event: message_start"), "got:\n{out}");
        assert!(
            out.contains("\"text\":\"Hi\"") || out.contains("Hi"),
            "text delta; got:\n{out}"
        );
        assert!(out.contains("message_stop"), "terminator; got:\n{out}");

        // Finding 1 (delta-before-stop): Bedrock splits stop_reason (`messageStop`) from usage
        // (`metadata`); the egress reader collapses them into ONE combined IR `MessageDelta` emitted
        // BEFORE the terminal `MessageStop`. The Anthropic ingress writer must therefore emit
        // `message_delta` BEFORE `message_stop` — the native non-eventstream order. (Before the fix
        // the IR order was MessageStop-then-MessageDelta, so the writer emitted them reversed.)
        let delta_pos = out.find("event: message_delta");
        let stop_pos = out.find("event: message_stop");
        assert!(
            delta_pos.is_some() && stop_pos.is_some() && delta_pos < stop_pos,
            "message_delta must precede message_stop (native order); got:\n{out}"
        );

        // Finding 2: each translated Anthropic SSE data body carries the native top-level `type`
        // field matching its `event:` header. Assert it for the delta and the terminal stop produced
        // on this cross-protocol path.
        assert!(
            out.contains("\"type\":\"message_delta\""),
            "message_delta data body must carry top-level type; got:\n{out}"
        );
        assert!(
            out.contains("\"type\":\"message_stop\""),
            "message_stop data body must carry top-level type; got:\n{out}"
        );
        // The combined delta carries the usage that arrived in the Bedrock `metadata` frame.
        assert!(
            out.contains("\"input_tokens\":5") && out.contains("\"output_tokens\":2"),
            "combined message_delta must carry the Bedrock metadata usage; got:\n{out}"
        );
    }

    /// Finding 1 regression at the reader→writer level (independent of eventstream framing): the
    /// Bedrock reader must emit the combined `MessageDelta` BEFORE the terminal `MessageStop`, so the
    /// Anthropic writer maps them to `message_delta` then `message_stop` — the native order. Guards
    /// against a reorder regressing back to MessageStop-then-MessageDelta (which made the Anthropic
    /// ingress write `message_stop` first).
    #[test]
    fn test_bedrock_reader_emits_delta_before_stop_for_anthropic_ingress() {
        use crate::ir::IrStreamEvent;
        let reader = BedrockReader;
        let writer = AnthropicWriter;
        let mut state = crate::ir::StreamDecodeState::default();

        // The terminal pair of the Bedrock wire: `messageStop` (stop_reason) then `metadata` (usage).
        let mut events: Vec<IrStreamEvent> = Vec::new();
        events.extend(reader.read_response_events(
            "",
            &serde_json::json!({"type": "messageStop", "stopReason": "end_turn"}),
            &mut state,
        ));
        events.extend(reader.read_response_events(
            "",
            &serde_json::json!({"type": "metadata", "usage": {"inputTokens": 5, "outputTokens": 2}}),
            &mut state,
        ));

        // IR order: combined MessageDelta first, terminal MessageStop second.
        assert!(
            matches!(events.first(), Some(IrStreamEvent::MessageDelta { .. })),
            "combined MessageDelta must come first; got {events:?}"
        );
        assert!(
            matches!(events.last(), Some(IrStreamEvent::MessageStop)),
            "terminal MessageStop must come last; got {events:?}"
        );

        // The Anthropic writer maps that order to `message_delta` then `message_stop`.
        let wire: Vec<String> = events
            .iter()
            .filter_map(|e| writer.write_response_event(e).map(|(et, _)| et))
            .collect();
        let delta_pos = wire.iter().position(|t| t == "message_delta");
        let stop_pos = wire.iter().position(|t| t == "message_stop");
        assert!(
            delta_pos.is_some() && stop_pos.is_some() && delta_pos < stop_pos,
            "Anthropic writer must emit message_delta before message_stop; got {wire:?}"
        );
    }

    /// Bedrock *ingress* streaming: an Anthropic SSE backend stream → a native AWS SDK Bedrock
    /// client. `StreamTranslate("bedrock", "anthropic")` must emit BINARY
    /// `application/vnd.amazon.eventstream` frames (not SSE) that `drain_frames` decodes back into
    /// the expected Converse event sequence. This is the encoder's cross-protocol acceptance test:
    /// it exercises encode_frame on the live streaming path and round-trips through the production
    /// decoder, proving CRC + framing validity end to end. No `data: [DONE]` terminator.
    #[test]
    fn test_translate_anthropic_egress_to_bedrock_ingress_binary_frames() {
        let mut t =
            StreamTranslate::new("bedrock", "anthropic").expect("bedrock ingress translator");
        let mut raw: Vec<u8> = Vec::new();
        for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_backend\",\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }
        // Bedrock has no `[DONE]`: the messageStop frame is the terminator, so finish() is empty.
        assert!(
            t.finish().is_empty(),
            "bedrock ingress emits no terminator frame in finish()"
        );

        // The output must NOT be SSE text — it must be binary frames the decoder can parse.
        assert!(
            !raw.starts_with(b"event:") && !raw.starts_with(b"data:"),
            "bedrock ingress output must be binary frames, not SSE"
        );

        let mut buf = raw.clone();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(
            buf.is_empty(),
            "all emitted frames must decode cleanly (valid CRC + lengths); {} bytes left",
            buf.len()
        );
        let types: Vec<&str> = frames.iter().map(|(et, _)| et.as_str()).collect();
        assert_eq!(
            types.first().copied(),
            Some("messageStart"),
            "stream opens with messageStart; got {types:?}"
        );
        assert!(
            types.contains(&"contentBlockDelta"),
            "must carry a contentBlockDelta; got {types:?}"
        );
        assert!(
            types.contains(&"messageStop"),
            "must carry messageStop terminator; got {types:?}"
        );
        // The combined IR MessageDelta (stop_reason + usage) must FAN OUT into BOTH a `messageStop`
        // frame AND a following `metadata` frame carrying the real usage — the native two-frame
        // ConverseStream sequence (finding: messageStop+metadata fan-out). A single Anthropic
        // `message_delta` thus reproduces the genuine Bedrock pair.
        assert!(
            types.contains(&"metadata"),
            "combined delta must fan out a `metadata` usage frame; got {types:?}"
        );
        // messageStop must precede metadata (native order).
        let stop_pos = types.iter().position(|t| *t == "messageStop");
        let meta_pos = types.iter().position(|t| *t == "metadata");
        assert!(
            stop_pos < meta_pos,
            "messageStop must precede metadata (native order); got {types:?}"
        );
        // The metadata frame carries the real token usage from the Anthropic message_delta.
        let meta = frames
            .iter()
            .find(|(et, _)| et == "metadata")
            .expect("a metadata frame");
        let mv: serde_json::Value =
            serde_json::from_slice(&meta.1).expect("valid metadata JSON payload");
        assert_eq!(
            mv.pointer("/usage/inputTokens").and_then(|x| x.as_u64()),
            Some(5),
            "metadata usage inputTokens round-trips; got {mv}"
        );
        assert_eq!(
            mv.pointer("/usage/outputTokens").and_then(|x| x.as_u64()),
            Some(2),
            "metadata usage outputTokens round-trips; got {mv}"
        );
        // The metadata frame carries a real `metrics.latencyMs` (a u64), never the tell-tale absent /
        // fabricated-0 of the old writer; it is injected by StreamTranslate from the stream wall-clock.
        assert!(
            mv.pointer("/metrics/latencyMs")
                .and_then(|x| x.as_u64())
                .is_some(),
            "metadata must carry a real metrics.latencyMs; got {mv}"
        );

        // The contentBlockDelta payload must round-trip the translated text.
        let delta = frames
            .iter()
            .find(|(et, _)| et == "contentBlockDelta")
            .expect("a contentBlockDelta frame");
        let v: serde_json::Value = serde_json::from_slice(&delta.1).expect("valid JSON payload");
        assert_eq!(
            v.pointer("/delta/text").and_then(|x| x.as_str()),
            Some("Hi"),
            "delta text round-trips; got {v}"
        );

        // The foreign Anthropic `msg_backend` id must NOT appear anywhere in the binary stream
        // (cross-protocol MessageStart identity strip). Bedrock's messageStart carries no id anyway,
        // so this also guards against a regression that would leak it.
        assert!(
            !raw.windows(b"msg_backend".len())
                .any(|w| w == b"msg_backend"),
            "foreign backend stream id must be stripped on cross-protocol ingress"
        );
    }

    /// Bedrock *ingress* streaming, TOOL-CALL path: an Anthropic SSE `content_block_start` with a
    /// `tool_use` block + `input_json_delta` + `content_block_stop` must translate through the binary
    /// Bedrock encoder into a `contentBlockStart` frame carrying a `toolUse` start, a
    /// `contentBlockDelta` carrying the tool input, and a `contentBlockStop`. Exercises
    /// `BedrockWriter::write_response_event`'s `BlockStart(ToolUse)`/`InputJsonDelta` arms on the live
    /// `StreamTranslate` path (previously only covered by the unit `test_write_response_event`).
    #[test]
    fn test_translate_anthropic_egress_to_bedrock_ingress_tool_call() {
        let mut t =
            StreamTranslate::new("bedrock", "anthropic").expect("bedrock ingress translator");
        let mut raw: Vec<u8> = Vec::new();
        for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_abc\",\"name\":\"get_weather\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"city\\\":\\\"SF\\\"}\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }

        let mut buf = raw.clone();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(
            buf.is_empty(),
            "all emitted frames decode cleanly; {} bytes left",
            buf.len()
        );
        let types: Vec<&str> = frames.iter().map(|(et, _)| et.as_str()).collect();
        assert!(
            types.contains(&"contentBlockStart"),
            "tool_use must emit a contentBlockStart frame; got {types:?}"
        );
        assert!(
            types.contains(&"contentBlockStop"),
            "must emit a contentBlockStop frame; got {types:?}"
        );

        // The contentBlockStart frame must carry the toolUse start payload.
        let start = frames
            .iter()
            .find(|(et, _)| et == "contentBlockStart")
            .expect("a contentBlockStart frame");
        let v: serde_json::Value = serde_json::from_slice(&start.1).expect("valid JSON payload");
        assert_eq!(
            v.pointer("/start/toolUse/name").and_then(|x| x.as_str()),
            Some("get_weather"),
            "toolUse name round-trips; got {v}"
        );
        assert_eq!(
            v.pointer("/start/toolUse/toolUseId")
                .and_then(|x| x.as_str()),
            Some("toolu_abc"),
            "toolUse id round-trips; got {v}"
        );

        // The contentBlockDelta frame must carry the tool input JSON.
        let delta = frames
            .iter()
            .find(|(et, _)| et == "contentBlockDelta")
            .expect("a contentBlockDelta frame");
        let dv: serde_json::Value = serde_json::from_slice(&delta.1).expect("valid JSON payload");
        assert!(
            dv.pointer("/delta/toolUse/input").is_some(),
            "tool input delta round-trips through the binary encoder; got {dv}"
        );
    }

    /// HIGH/conformance regression: a mid-stream upstream ERROR on a Bedrock-INGRESS cross-protocol
    /// stream must be framed as a MODELED EXCEPTION (`:message-type: exception` + `:exception-type`),
    /// NOT a normal `:message-type: event` frame. An AWS SDK dispatches errors off `:message-type`;
    /// an `event`-typed frame naming a Converse exception is silently dropped, so the client never
    /// surfaces the error and the stream appears to truncate. This drives an Anthropic egress
    /// `event: error` frame (decoded to `IrStreamEvent::Error`) through the bedrock-ingress translator
    /// and asserts the emitted frame is a real exception frame.
    #[test]
    fn test_translate_error_to_bedrock_ingress_is_exception_frame() {
        let mut t =
            StreamTranslate::new("bedrock", "anthropic").expect("bedrock ingress translator");
        // Anthropic native mid-stream error envelope → IrStreamEvent::Error (the Anthropic reader
        // classifies all stream errors as ClientError → ValidationException).
        let err_frame = "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"upstream is overloaded\"}}\n\n";
        let raw = t.feed(err_frame.as_bytes());
        assert!(!raw.is_empty(), "an error event must emit a frame");
        // Must be binary framing, not SSE text.
        assert!(
            !raw.starts_with(b"event:") && !raw.starts_with(b"data:"),
            "bedrock ingress error must be a binary frame, not SSE text"
        );
        // The frame must be a valid event-stream message carrying the exception headers.
        let headers_len = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
        let headers = String::from_utf8_lossy(&raw[12..12 + headers_len]);
        assert!(
            headers.contains(":message-type"),
            "frame carries a :message-type header; headers: {headers}"
        );
        assert!(
            headers.contains("exception"),
            ":message-type must be `exception`, not `event`; headers: {headers}"
        );
        assert!(
            headers.contains(":exception-type"),
            "frame carries an :exception-type header; headers: {headers}"
        );
        // The exception-type is a real Converse exception name (ClientError → ValidationException).
        assert!(
            headers.contains("ValidationException"),
            ":exception-type names a real Converse exception; headers: {headers}"
        );
        // The whole frame must decode without trailing bytes (valid CRC + lengths).
        let total_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        assert_eq!(total_len, raw.len(), "total_len matches the bytes emitted");
        // Payload is the JSON `{"message": ...}` the SDK surfaces. The Anthropic stream-error reader
        // carries the upstream error `type` as the IR `provider_signal`, which becomes the message.
        let payload = &raw[12 + headers_len..total_len - 4];
        let v: serde_json::Value = serde_json::from_slice(payload).expect("valid JSON payload");
        assert!(
            v.get("message").and_then(|m| m.as_str()).is_some(),
            "exception frame carries a JSON message body; got {v}"
        );
    }

    /// MEDIUM/conformance regression: on a cross-protocol Gemini-INGRESS stream, the MessageStart
    /// frame must still carry a `responseId` even though `StreamTranslate` strips the foreign id/model
    /// to `None` — a native google-genai SDK reads `chunk.response_id` off the first chunk. Previously
    /// the Gemini writer emitted NO frame when both id and model were `None`, leaving the client with
    /// no responseId on any cross-protocol Gemini stream.
    #[test]
    fn test_translate_to_gemini_ingress_synthesizes_response_id() {
        let mut t = StreamTranslate::new("gemini", "openai").expect("gemini ingress translator");
        // OpenAI chunk with a top-level id/model that the cross-protocol strip will clear.
        let chunk = "data: {\"id\":\"chatcmpl-abc\",\"created\":1,\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n";
        let out = String::from_utf8(t.feed(chunk.as_bytes())).unwrap();
        assert!(
            out.contains("responseId"),
            "gemini cross-protocol stream must carry a synthesized responseId; got:\n{out}"
        );
        // The foreign OpenAI id must NOT leak through.
        assert!(
            !out.contains("chatcmpl-abc"),
            "foreign backend id must be stripped, not leaked; got:\n{out}"
        );
    }

    /// Round-10 HIGH/conformance regression: a CROSS-PROTOCOL tool call streamed to a Gemini client
    /// must surface as a SINGLE native `functionCall` part `{name, args}` — not a `{name, args:{}}`
    /// opening frame followed by a separate nameless `{args}` part. An OpenAI backend emits the tool
    /// NAME on the first tool-call chunk and the arguments as later `arguments` fragments; the IR
    /// preserves that split (BlockStart{ToolUse{name}} then InputJsonDelta). Before the GeminiWriter
    /// per-stream buffer, the writer emitted two parts: an empty-args part carrying the name and an
    /// args part carrying NO name — a shape a native google-genai client never produces (and where a
    /// strict client reading `function_call.name` off the args part sees an empty string). The
    /// per-stream buffer re-attaches the name to the args part so exactly one `{name, args}` part is
    /// written.
    #[test]
    fn test_translate_to_gemini_tool_call_single_functioncall_part() {
        let mut t = StreamTranslate::new("gemini", "openai").expect("gemini ingress translator");
        let mut out = String::new();
        for frame in [
            // role chunk
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            // first tool-call chunk: id + name, no args yet
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"get_weather\"}}]}}]}\n\n",
            // argument fragments
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"city\\\":\\\"SF\\\"}\"}}]}}]}\n\n",
            // finish
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        out.push_str(&String::from_utf8(t.finish()).unwrap());

        // Collect every `functionCall` part across all emitted Gemini chunks.
        let payloads = data_payloads(&out);
        let func_parts: Vec<&serde_json::Value> = payloads
            .iter()
            .filter_map(|p| {
                p.pointer("/candidates/0/content/parts")
                    .and_then(|parts| parts.as_array())
            })
            .flatten()
            .filter_map(|part| part.get("functionCall"))
            .collect();

        assert_eq!(
            func_parts.len(),
            1,
            "exactly one native functionCall part expected (no empty-args-then-args split); got:\n{out}"
        );
        let func = func_parts[0];
        assert_eq!(
            func.pointer("/name").and_then(|n| n.as_str()),
            Some("get_weather"),
            "the single functionCall part must carry the name; got:\n{out}"
        );
        assert_eq!(
            func.pointer("/args/city").and_then(|c| c.as_str()),
            Some("SF"),
            "the single functionCall part must carry the args; got:\n{out}"
        );
        // No nameless functionCall part anywhere (the old split's second part).
        assert!(
            !func_parts.iter().any(|f| f
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .is_empty()),
            "no nameless functionCall part may be emitted; got:\n{out}"
        );
    }

    /// A CRLF-delimited SSE upstream (`\r\n\r\n` frame terminators — spec-legal, emitted by some
    /// gateways/CDNs) must reassemble and translate correctly. An LF-only scanner would never detect
    /// a terminator and buffer the whole stream until MAX_BUF, then abort — stalling the client.
    #[test]
    fn test_translate_crlf_sse_frames() {
        let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
        // OpenAI-style bare `data:` frames with CRLF line endings and `\r\n\r\n` terminators.
        let chunk = "data: {\"choices\":[{\"delta\":{\"content\":\"He\"}}]}\r\n\r\ndata: {\"choices\":[{\"delta\":{\"content\":\"llo\"}}]}\r\n\r\n";
        let out = String::from_utf8(t.feed(chunk.as_bytes())).unwrap();
        assert!(
            !out.is_empty(),
            "CRLF SSE must produce translated output, not stall"
        );
        assert!(
            out.contains("He") && out.contains("llo"),
            "both CRLF-delimited deltas must translate; got:\n{out}"
        );
        assert!(!t.aborted, "CRLF stream must not be abandoned");
    }

    /// Decoder also works when the binary frames arrive split across feed() calls (partial frame
    /// buffered, then completed) — the realistic chunked-transport case.
    #[test]
    fn test_translate_bedrock_eventstream_split_chunks() {
        let mut st = StreamTranslate::new("anthropic", "bedrock").expect("translator");
        let mut bytes = es_frame("messageStart", br#"{"role":"assistant"}"#);
        bytes.extend(es_frame(
            "contentBlockDelta",
            br#"{"contentBlockIndex":0,"delta":{"text":"Yo"}}"#,
        ));
        let split = bytes.len() - 6; // mid-second-frame
        let mut out = st.feed(&bytes[..split]);
        out.extend(st.feed(&bytes[split..]));
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains("Yo"),
            "text survives a frame split across chunks; got:\n{s}"
        );
    }

    /// Collect the JSON payloads of all `data:` lines (excluding `[DONE]`).
    fn data_payloads(out: &str) -> Vec<serde_json::Value> {
        out.lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(|s| s.trim())
            .filter(|s| *s != "[DONE]")
            .filter_map(|s| serde_json::from_str(s).ok())
            .collect()
    }

    // anthropic egress stream → openai ingress: client receives OpenAI chat.completion.chunks.
    #[test]
    fn test_translate_anthropic_egress_to_openai_ingress() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
        let mut out = String::new();
        for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        out.push_str(&String::from_utf8(t.finish()).unwrap());

        assert!(
            !out.contains("event:"),
            "OpenAI output must have no event: lines; got {out}"
        );
        let payloads = data_payloads(&out);
        assert!(
            payloads.iter().any(|p| p
                .pointer("/choices/0/delta/content")
                .and_then(|v| v.as_str())
                == Some("hi")),
            "translated content 'hi' missing; got {out}"
        );
        assert!(
            payloads.iter().any(|p| p
                .pointer("/choices/0/finish_reason")
                .and_then(|v| v.as_str())
                == Some("stop")),
            "finish_reason 'stop' missing; got {out}"
        );
        assert!(
            out.trim_end().ends_with("data: [DONE]"),
            "OpenAI stream must end with data: [DONE]; got {out}"
        );
    }

    // openai egress stream → anthropic ingress: client receives Anthropic event: frames.
    #[test]
    fn test_translate_openai_egress_to_anthropic_ingress() {
        let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
        let mut out = String::new();
        for frame in [
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n",
            "data: [DONE]\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        assert!(
            t.finish().is_empty(),
            "Anthropic ingress has no [DONE] terminator"
        );
        assert!(
            out.contains("event: message_start"),
            "missing message_start; got {out}"
        );
        assert!(
            out.contains("event: content_block_delta"),
            "missing content_block_delta; got {out}"
        );
        assert!(
            out.contains("text_delta") && out.contains("hi"),
            "missing text_delta 'hi'; got {out}"
        );
        assert!(
            out.contains("event: message_stop"),
            "missing message_stop; got {out}"
        );
    }

    // Finding 1 (input-token loss across the IR on streaming). Anthropic's SSE carries
    // `usage.input_tokens` ONLY on `message_start`; its `message_delta` carries `output_tokens`
    // alone. On a cross-protocol hop OUT of an Anthropic backend the terminal `MessageDelta.usage`
    // therefore had `input_tokens == 0` and the prompt-token count vanished. `StreamTranslate` now
    // latches the start-usage input/cache tokens and backfills the terminal delta. Gemini ingress is
    // the cleanest observer: its writer renders the terminal usage as `usageMetadata.promptTokenCount`
    // (Anthropic→Gemini), so a non-zero promptTokenCount proves the input count survived the seam.
    #[test]
    fn test_translate_anthropic_egress_to_gemini_ingress_preserves_input_tokens() {
        let mut t = StreamTranslate::new("gemini", "anthropic").expect("gemini ingress translator");
        let mut out = String::new();
        for frame in [
            // input_tokens live ONLY here (message_start), per the native Anthropic shape.
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\",\"usage\":{\"input_tokens\":42,\"output_tokens\":0}}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            // message_delta carries output_tokens but NO input_tokens (native Anthropic).
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        out.push_str(&String::from_utf8(t.finish()).unwrap());
        let payloads = data_payloads(&out);
        // The terminal Gemini chunk's usageMetadata must report BOTH the input (prompt) tokens
        // latched at stream start AND the output (candidates) tokens from the delta.
        let usage = payloads
            .iter()
            .find_map(|p| p.pointer("/usageMetadata"))
            .unwrap_or_else(|| panic!("no usageMetadata in translated stream; got {out}"));
        assert_eq!(
            usage.get("promptTokenCount").and_then(|v| v.as_u64()),
            Some(42),
            "input tokens captured at message_start must survive to the terminal usage; got {out}"
        );
        assert_eq!(
            usage.get("candidatesTokenCount").and_then(|v| v.as_u64()),
            Some(7),
            "output tokens from message_delta must be reported; got {out}"
        );
    }

    // Finding 1, same-protocol round-trip: an Anthropic stream read into IR events and written back
    // out by the Anthropic writer must carry input tokens (message_start) AND output tokens
    // (message_delta) — neither half lost. (Same-protocol forwarding is byte-passthrough in prod and
    // never hits StreamTranslate; this asserts the reader+writer IR contract underneath that.)
    #[test]
    fn test_anthropic_stream_usage_roundtrips_input_and_output_tokens() {
        let reader = AnthropicReader;
        let writer = AnthropicWriter;
        let mut state = crate::ir::StreamDecodeState::default();

        // message_start → MessageStart carrying input_tokens.
        let start_in = serde_json::json!({
            "type":"message_start",
            "message":{"role":"assistant","usage":{"input_tokens":42,"output_tokens":0}}
        });
        let start_evs = reader.read_response_events("message_start", &start_in, &mut state);
        let (_et, start_out) = writer
            .write_response_event(&start_evs[0])
            .expect("message_start writes");
        assert_eq!(
            start_out
                .pointer("/message/usage/input_tokens")
                .and_then(|v| v.as_u64()),
            Some(42),
            "message_start must round-trip input_tokens"
        );

        // message_delta → MessageDelta carrying output_tokens.
        let delta_in = serde_json::json!({
            "type":"message_delta",
            "delta":{"stop_reason":"end_turn"},
            "usage":{"output_tokens":7}
        });
        let delta_evs = reader.read_response_events("message_delta", &delta_in, &mut state);
        let (_et, delta_out) = writer
            .write_response_event(&delta_evs[0])
            .expect("message_delta writes");
        assert_eq!(
            delta_out
                .pointer("/usage/output_tokens")
                .and_then(|v| v.as_u64()),
            Some(7),
            "message_delta must round-trip output_tokens"
        );
    }

    // HIGH/test-coverage (proto/mod.rs:368): StreamTranslate with COHERE as the ingress side. Cohere
    // uses a bare `data:` envelope keyed on `type` and must NEVER emit a `[DONE]` sentinel
    // (`emit_done` is false for cohere). Exercises CohereWriter::write_delta/write_stop through the
    // translator end-to-end.
    #[test]
    fn test_translate_anthropic_egress_to_cohere_ingress() {
        let mut t = StreamTranslate::new("cohere", "anthropic").expect("cohere ingress translator");
        let mut out = String::new();
        for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        out.push_str(&String::from_utf8(t.finish()).unwrap());

        // Cohere v2 native stream: bare `data:` frames, no `event:` lines.
        assert!(
            !out.contains("event:"),
            "Cohere output must have no event: lines; got {out}"
        );
        // Cohere must NEVER emit a `[DONE]` sentinel (emit_done is false for cohere ingress).
        assert!(
            !out.contains("[DONE]"),
            "Cohere stream must NOT emit a [DONE] sentinel; got {out}"
        );
        let payloads = data_payloads(&out);
        // The translated text rides at delta.message.content.text in a `content-delta` frame.
        assert!(
            payloads.iter().any(|p| p["type"] == "content-delta"
                && p.pointer("/delta/message/content/text")
                    .and_then(|v| v.as_str())
                    == Some("hi")),
            "missing cohere content-delta carrying 'hi'; got {out}"
        );
        // The terminal `message-end` carries the finish reason and usage.
        assert!(
            payloads.iter().any(|p| p["type"] == "message-end"
                && p.pointer("/delta/finish_reason").and_then(|v| v.as_str()) == Some("COMPLETE")),
            "missing cohere message-end COMPLETE; got {out}"
        );
    }

    // HIGH/test-coverage (proto/mod.rs:368): StreamTranslate with RESPONSES as the ingress side.
    // The Responses API uses NAMED SSE events (`event: response.created` ... `response.completed`),
    // not bare `data:` frames, and never a `[DONE]`. Exercises ResponsesWriter::write_delta/write_stop
    // through the translator end-to-end.
    #[test]
    fn test_translate_anthropic_egress_to_responses_ingress() {
        let mut t =
            StreamTranslate::new("responses", "anthropic").expect("responses ingress translator");
        let mut out = String::new();
        for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        out.push_str(&String::from_utf8(t.finish()).unwrap());

        // Responses uses named events for the stream boundaries.
        assert!(
            out.contains("event: response.created"),
            "missing Responses event: response.created; got {out}"
        );
        assert!(
            out.contains("event: response.completed"),
            "missing Responses event: response.completed; got {out}"
        );
        // Never a `[DONE]` (emit_done is only true for openai ingress).
        assert!(
            !out.contains("[DONE]"),
            "Responses stream must NOT emit a [DONE] sentinel; got {out}"
        );
    }

    // MEDIUM/conformance (proto/mod.rs:441 fan-out): OpenAI egress with `stream_options.include_usage`
    // splits its terminal info across TWO chunks — a finish_reason chunk with NO usage, then a
    // usage-only chunk. A native ConverseStream emits EXACTLY ONE `metadata` frame; the pre-fix
    // fan-out emitted a zero-usage metadata for the first AND a real metadata for the second. Assert
    // exactly one `metadata` frame, carrying the REAL tokens.
    #[test]
    fn test_translate_openai_include_usage_egress_to_bedrock_ingress_single_metadata() {
        let mut t = StreamTranslate::new("bedrock", "openai").expect("bedrock ingress translator");
        let mut raw: Vec<u8> = Vec::new();
        for frame in [
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            // include_usage: terminal finish chunk carries NO usage...
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            // ...usage rides a SEPARATE trailing chunk (empty choices).
            "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":11}}\n\n",
            "data: [DONE]\n\n",
        ] {
            raw.extend_from_slice(&t.feed(frame.as_bytes()));
        }
        raw.extend_from_slice(&t.finish());

        // Decode the binary eventstream frames.
        let mut buf = raw.clone();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(buf.is_empty(), "all frames must decode cleanly");

        // Exactly ONE `metadata` frame (a native ConverseStream emits exactly one), carrying the
        // REAL tokens — NOT the pre-fix pair (a zero-usage frame + a real frame).
        let metadata: Vec<&(String, Vec<u8>)> =
            frames.iter().filter(|(et, _)| et == "metadata").collect();
        assert_eq!(
            metadata.len(),
            1,
            "a native ConverseStream emits exactly ONE metadata frame; got {}",
            metadata.len()
        );
        let md: serde_json::Value =
            serde_json::from_slice(&metadata[0].1).expect("metadata payload is JSON");
        assert_eq!(
            md["usage"]["inputTokens"], 7,
            "metadata must carry the REAL input tokens, not a zero frame; got {md}"
        );
        assert_eq!(
            md["usage"]["outputTokens"], 11,
            "metadata must carry the REAL output tokens; got {md}"
        );
        // And exactly one messageStop frame (the stop discriminant).
        let stops = frames.iter().filter(|(et, _)| et == "messageStop").count();
        assert_eq!(stops, 1, "exactly one messageStop frame");
    }

    // MEDIUM/conformance (proto/mod.rs fan-out): DEFAULT OpenAI streaming — NO
    // `stream_options.include_usage` — the finish chunk carries no usage AND there is NO trailing
    // usage-only chunk. The pre-fix fan-out DEFERRED the `metadata` frame to a trailing delta that
    // never arrived, so the ConverseStream ended with messageStop but NO `metadata` frame at all (a
    // deterministic proxy tell + lost token accounting). `finish()` must now flush exactly one
    // (zero-usage) `metadata` frame so the stream is never missing its terminal metadata.
    #[test]
    fn test_translate_openai_no_include_usage_egress_to_bedrock_ingress_emits_metadata() {
        let mut t = StreamTranslate::new("bedrock", "openai").expect("bedrock ingress translator");
        let mut raw: Vec<u8> = Vec::new();
        for frame in [
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n",
            // Default streaming: terminal finish chunk carries NO usage, and NO trailing usage chunk.
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        ] {
            raw.extend_from_slice(&t.feed(frame.as_bytes()));
        }
        // finish() must flush the deferred metadata frame.
        raw.extend_from_slice(&t.finish());

        let mut buf = raw.clone();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(buf.is_empty(), "all frames must decode cleanly");

        // EXACTLY ONE metadata frame — present (the fix), never the pre-fix total absence.
        let metadata: Vec<&(String, Vec<u8>)> =
            frames.iter().filter(|(et, _)| et == "metadata").collect();
        assert_eq!(
            metadata.len(),
            1,
            "default OpenAI stream (no include_usage) must STILL terminate with exactly one \
             metadata frame; got {} frames: {:?}",
            metadata.len(),
            frames.iter().map(|(et, _)| et.as_str()).collect::<Vec<_>>()
        );
        // It carries zero tokens (no usage was reported) — far closer to native than no frame.
        let md: serde_json::Value =
            serde_json::from_slice(&metadata[0].1).expect("metadata payload is JSON");
        assert_eq!(md["usage"]["inputTokens"], 0);
        assert_eq!(md["usage"]["outputTokens"], 0);

        // messageStop must precede the flushed metadata (native order).
        let types: Vec<&str> = frames.iter().map(|(et, _)| et.as_str()).collect();
        let stop_pos = types.iter().position(|t| *t == "messageStop");
        let meta_pos = types.iter().position(|t| *t == "metadata");
        assert!(
            stop_pos.is_some() && meta_pos.is_some() && stop_pos < meta_pos,
            "messageStop must precede metadata (native order); got {types:?}"
        );
        // Exactly one messageStop.
        assert_eq!(
            frames.iter().filter(|(et, _)| et == "messageStop").count(),
            1,
            "exactly one messageStop frame"
        );
    }

    // A frame split across two feeds yields no output until complete, then translates.
    #[test]
    fn test_translate_split_frame_reassembly() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
        let frame = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n";
        let (a, b) = frame.as_bytes().split_at(20);
        assert!(t.feed(a).is_empty(), "partial frame must yield no output");
        let s = String::from_utf8(t.feed(b)).unwrap();
        assert!(
            s.contains("\"content\":\"hi\""),
            "completed frame must translate to openai content; got {s}"
        );
    }

    // Cross-protocol tool-calling fidelity: openai tool_calls → anthropic tool_use survives.
    #[test]
    fn test_translate_tool_call_fidelity() {
        let mut t = StreamTranslate::new("anthropic", "openai").expect("translator");
        let mut out = String::new();
        for frame in [
            "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"loc\\\":\\\"SF\\\"}\"}}]}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        ] {
            out.push_str(&String::from_utf8(t.feed(frame.as_bytes())).unwrap());
        }
        assert!(
            out.contains("content_block_start"),
            "missing content_block_start; got {out}"
        );
        assert!(
            out.contains("tool_use"),
            "tool_use block type missing; got {out}"
        );
        assert!(
            out.contains("get_weather") && out.contains("call_1"),
            "tool name/id must survive cross-protocol; got {out}"
        );
        assert!(
            out.contains("input_json_delta"),
            "missing input_json_delta; got {out}"
        );
    }

    #[test]
    fn test_translate_same_protocol_is_none() {
        assert!(StreamTranslate::new("openai", "openai").is_none());
        assert!(StreamTranslate::new("anthropic", "anthropic").is_none());
    }

    /// Multiple `data:` lines in one SSE frame must be concatenated with `\n` (SSE spec §9.2.6),
    /// not collapsed to the last line. A leading space after the colon is stripped exactly once.
    #[test]
    fn test_parse_sse_frame_concatenates_multiple_data_lines() {
        let frame = b"event: e\ndata: {\"a\":1,\ndata: \"b\":2}\n\n";
        let (et, data) = parse_sse_frame(frame).expect("frame has data");
        assert_eq!(et, "e");
        assert_eq!(data, "{\"a\":1,\n\"b\":2}");
        // and the joined payload is valid JSON
        let v: serde_json::Value = serde_json::from_str(&data).expect("joined data parses");
        assert_eq!(v.get("a"), Some(&serde_json::json!(1)));
        assert_eq!(v.get("b"), Some(&serde_json::json!(2)));
    }

    /// A frame carrying only an `event:` line (no `data:`) must return None.
    #[test]
    fn test_parse_sse_frame_event_only_is_none() {
        assert!(parse_sse_frame(b"event: ping\n\n").is_none());
        assert!(parse_sse_frame(b"\n\n").is_none());
    }

    /// A `data:` line with empty value still yields Some (caller treats empty payload as a
    /// terminator/keepalive); the OpenAI `[DONE]` sentinel survives leading-space stripping.
    #[test]
    fn test_parse_sse_frame_done_sentinel() {
        let (et, data) = parse_sse_frame(b"data: [DONE]\n\n").expect("data line present");
        assert_eq!(et, "");
        assert_eq!(data, "[DONE]");
    }

    /// An upstream that splits a single JSON event across two `data:` lines must still translate
    /// correctly end-to-end (the payload is rejoined before JSON parsing).
    #[test]
    fn test_translate_multiline_data_payload() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
        let frame = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\ndata: \"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n";
        let s = String::from_utf8(t.feed(frame.as_bytes())).unwrap();
        assert!(
            s.contains("\"content\":\"hi\""),
            "multi-line data payload must reassemble and translate; got {s}"
        );
    }

    /// An upstream that streams bytes without ever emitting a frame terminator must not grow the
    /// reassembly buffer without bound: once past the cap the stream is abandoned and the buffer
    /// is released.
    #[test]
    fn test_feed_aborts_on_unbounded_buffer() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
        let chunk = vec![b'x'; 1024 * 1024]; // 1 MiB of garbage, no `\n\n`
        let mut total = 0usize;
        // Feed past MAX_BUF (16 MiB) — the +1 iteration crosses the cap and triggers the abort.
        for _ in 0..18 {
            let out = t.feed(&chunk);
            assert!(out.is_empty(), "garbage stream must produce no output");
            total += chunk.len();
            if t.aborted {
                break;
            }
            assert!(
                t.buf.len() <= StreamTranslate::MAX_BUF,
                "buffer must stay within MAX_BUF while accumulating"
            );
        }
        assert!(
            t.aborted,
            "stream must abort after exceeding MAX_BUF (fed {total} bytes)"
        );
        assert!(t.buf.is_empty(), "aborted stream must release its buffer");
        // Further feeds are no-ops, including a now-complete frame.
        assert!(
            t.feed(b"data: {\"choices\":[]}\n\n").is_empty(),
            "feeds after abort must be ignored"
        );
    }

    /// The scanned-offset optimization must not break terminator detection when `\n\n` straddles a
    /// chunk boundary (one `\n` at the end of chunk A, the next at the start of chunk B).
    #[test]
    fn test_feed_terminator_straddles_chunk_boundary() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
        let frame = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n";
        // First chunk ends right after the first '\n'; the second '\n' opens the next chunk.
        assert!(t.feed(frame.as_bytes()).is_empty(), "no terminator yet");
        let s = String::from_utf8(t.feed(b"\n")).unwrap();
        assert!(
            s.contains("\"content\":\"hi\""),
            "terminator split across chunks must still complete the frame; got {s}"
        );
    }

    /// Many tiny chunks comprising a single large frame must reassemble and translate exactly once.
    #[test]
    fn test_feed_large_frame_many_chunks() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("translator");
        let big = "x".repeat(200_000);
        let frame = format!(
            "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{big}\"}}}}\n\n"
        );
        let bytes = frame.as_bytes();
        let mut out = Vec::new();
        for chunk in bytes.chunks(64) {
            out.extend(t.feed(chunk));
        }
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.contains(&big),
            "large frame split across many chunks must reassemble"
        );
    }

    // ============================================================
    // Whole-response (non-streaming) R/W tests
    // ============================================================

    #[test]
    fn test_anthropic_read_response_decode() {
        // Anthropic message → IrResponse with exact fields
        let data = serde_json::json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 5,
                "output_tokens": 3,
                "cache_creation_input_tokens": null,
                "cache_read_input_tokens": null
            }
        });

        let reader = AnthropicReader;
        let resp = reader.read_response(&data).expect("should parse");

        assert_eq!(resp.role, crate::ir::IrRole::Assistant);
        assert_eq!(resp.content.len(), 1);
        if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
            assert_eq!(text, "hi");
        } else {
            panic!("expected Text block");
        }
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(resp.usage.input_tokens, 5);
    }

    #[test]
    fn test_openai_read_response_decode() {
        // OpenAI chat.completion → IrResponse with exact fields and stop_reason mapping
        let data = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": 3
            }
        });

        let reader = OpenAiReader;
        let resp = reader.read_response(&data).expect("should parse");

        assert_eq!(resp.role, crate::ir::IrRole::Assistant);
        assert_eq!(resp.content.len(), 1);
        if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
            assert_eq!(text, "hi");
        } else {
            panic!("expected Text block");
        }
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn")); // mapped from "stop"
        assert_eq!(resp.usage.input_tokens, 5);
    }

    #[test]
    fn test_cross_protocol_openai_to_anthropic() {
        // OpenAI → IR → Anthropic: verify output is Anthropic-shaped
        let openai_data = serde_json::json!({
            "choices": [{
                "message": {"role": "assistant", "content": "hi"},
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": 3
            }
        });

        let ir_resp = OpenAiReader
            .read_response(&openai_data)
            .expect("OpenAI read");
        let anthropic_json = AnthropicWriter.write_response(&ir_resp);

        // Assert Anthropic-shaped output
        assert_eq!(
            anthropic_json.get("type").and_then(|v| v.as_str()),
            Some("message")
        );
        if let Some(content_arr) = anthropic_json.get("content").and_then(|c| c.as_array()) {
            assert!(!content_arr.is_empty());
            let first_block = &content_arr[0];
            assert_eq!(
                first_block.get("type").and_then(|v| v.as_str()),
                Some("text")
            );
            assert_eq!(first_block.get("text").and_then(|v| v.as_str()), Some("hi"));
        } else {
            panic!("missing content array");
        }
        assert_eq!(
            anthropic_json.get("stop_reason").and_then(|v| v.as_str()),
            Some("end_turn")
        );
    }

    #[test]
    fn test_cross_protocol_anthropic_to_openai() {
        // Anthropic → IR → OpenAI: verify output is OpenAI-shaped
        let anthropic_data = serde_json::json!({
            "role": "assistant",
            "content": [{"type": "text", "text": "hi"}],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 5,
                "output_tokens": 3,
                "cache_creation_input_tokens": null,
                "cache_read_input_tokens": null
            }
        });

        let ir_resp = AnthropicReader
            .read_response(&anthropic_data)
            .expect("Anthropic read");
        let openai_json = OpenAiWriter.write_response(&ir_resp);

        // Assert OpenAI-shaped output
        assert_eq!(
            openai_json.get("object").and_then(|v| v.as_str()),
            Some("chat.completion")
        );
        if let Some(choices_arr) = openai_json.get("choices").and_then(|c| c.as_array()) {
            assert!(!choices_arr.is_empty());
            let choice = &choices_arr[0];
            if let Some(msg) = choice.get("message") {
                assert_eq!(msg.get("role").and_then(|v| v.as_str()), Some("assistant"));
                assert_eq!(msg.get("content").and_then(|v| v.as_str()), Some("hi"));
            } else {
                panic!("missing message");
            }
            assert_eq!(
                choice.get("finish_reason").and_then(|v| v.as_str()),
                Some("stop")
            );
        } else {
            panic!("missing choices array");
        }
    }

    #[test]
    fn test_cross_protocol_tool_use_response() {
        // OpenAI tool_calls response → IR → Anthropic: verify tool_use block round-trips
        let openai_data = serde_json::json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "f", "arguments": "{\"x\":1}"}
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {
                "prompt_tokens": 5,
                "completion_tokens": 3
            }
        });

        let ir_resp = OpenAiReader
            .read_response(&openai_data)
            .expect("OpenAI read");

        // Verify IR has ToolUse block
        assert_eq!(ir_resp.content.len(), 1);
        if let crate::ir::IrBlock::ToolUse { id, name, input } = &ir_resp.content[0] {
            assert_eq!(id, "call_1");
            assert_eq!(name, "f");
            match input {
                serde_json::Value::Object(obj) => {
                    assert_eq!(obj.get("x"), Some(&serde_json::json!(1)));
                }
                _ => panic!("input should be Object"),
            }
        } else {
            panic!("expected ToolUse block");
        }

        let anthropic_json = AnthropicWriter.write_response(&ir_resp);

        // Assert Anthropic output has tool_use block with correct fields
        if let Some(content_arr) = anthropic_json.get("content").and_then(|c| c.as_array()) {
            assert!(!content_arr.is_empty());
            let first_block = &content_arr[0];
            assert_eq!(
                first_block.get("type").and_then(|v| v.as_str()),
                Some("tool_use")
            );
            assert_eq!(
                first_block.get("id").and_then(|v| v.as_str()),
                Some("call_1")
            );
            assert_eq!(first_block.get("name").and_then(|v| v.as_str()), Some("f"));
            // input should be an object with x: 1
            if let Some(input_val) = first_block.get("input") {
                match input_val {
                    serde_json::Value::Object(obj) => {
                        assert_eq!(obj.get("x"), Some(&serde_json::json!(1)));
                    }
                    _ => panic!("input should be Object"),
                }
            } else {
                panic!("missing input");
            }
        } else {
            panic!("missing content array");
        }

        // stop_reason should be "tool_use" (passthrough from Anthropic canonical form)
        assert_eq!(
            anthropic_json.get("stop_reason").and_then(|v| v.as_str()),
            Some("tool_use")
        );
    }

    #[test]
    fn test_same_protocol_roundtrip_idempotence() {
        // Anthropic read → write → read yields equal IrResponse.
        // `id` is seeded because a native Anthropic Message always carries one and the writer
        // (correctly) synthesizes an `id` when absent — so idempotence is only meaningful with a
        // real id present (an id-less fixture is not a shape a native client ever sends).
        let original_data = serde_json::json!({
            "id": "msg_01TestRoundtripIdempotence",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "hello"},
                {"type": "tool_use", "id": "tool_1", "name": "get_weather", "input": {"loc": "SF"}}
            ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_creation_input_tokens": null,
                "cache_read_input_tokens": null
            }
        });

        let reader = AnthropicReader;
        let writer = AnthropicWriter;

        // First read
        let ir1 = reader.read_response(&original_data).expect("first read");

        // Write to JSON
        let written_json = writer.write_response(&ir1);

        // Read again
        let ir2 = reader.read_response(&written_json).expect("second read");

        // Decode IR must be identical (ground truth for anti-fab)
        assert_eq!(ir1, ir2, "decoded IR must be identical after round-trip");
    }

    // Gemini decode test - systemInstruction + contents with mixed blocks + tools
    #[test]
    fn test_gemini_decode() {
        let j = serde_json::json!({
            "systemInstruction": {
                "parts": [{"text": "You are a helpful assistant."}]
            },
            "contents": [
                {"role": "user", "parts": [
                    {"text": "What is the weather?"},
                    {"inlineData": {"mimeType": "image/png", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"}}
                ]},
                {"role": "model", "parts": [
                    {"functionCall": {"name": "get_weather", "args": {"location": "San Francisco"}}}
                ]},
                {"role": "user", "parts": [
                    {"functionResponse": {"name": "get_weather", "response": {"temperature": 72, "units": "F"}}}
                ]}
            ],
            "tools": [{
                "functionDeclarations": [
                    {
                        "name": "get_weather",
                        "description": "Get weather for a location",
                        "parameters": {
                            "type": "object",
                            "properties": {"location": {"type": "string"}},
                            "required": ["location"]
                        }
                    }
                ]
            }],
            "generationConfig": {
                "maxOutputTokens": 4096,
                "temperature": 0.7
            },
            "stream": true
        });

        let reader = GeminiReader;
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");

        // Assert system Text block
        assert_eq!(ir.system.len(), 1);
        if let crate::ir::IrBlock::Text {
            text,
            cache_control: _,
            citations: _,
        } = &ir.system[0]
        {
            assert_eq!(text, "You are a helpful assistant.");
        } else {
            panic!("expected Text block in system");
        }

        // Assert messages roles and content
        assert_eq!(ir.messages.len(), 3);

        // First message: User with text + image
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        assert_eq!(ir.messages[0].content.len(), 2);
        if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
            assert_eq!(text, "What is the weather?");
        } else {
            panic!("expected Text block in first message");
        }
        if let crate::ir::IrBlock::Image { media_type, data } = &ir.messages[0].content[1] {
            assert_eq!(media_type, "image/png");
            assert_eq!(data, "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ");
        } else {
            panic!("expected Image block in first message");
        }

        // Second message: Assistant with functionCall (ToolUse)
        assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
        assert_eq!(ir.messages[1].content.len(), 1);
        if let crate::ir::IrBlock::ToolUse { id: _, name, input } = &ir.messages[1].content[0] {
            assert_eq!(name, "get_weather");
            assert_eq!(
                input.get("location").and_then(|v| v.as_str()),
                Some("San Francisco")
            );
        } else {
            panic!("expected ToolUse block in second message");
        }

        // Third message: User with functionResponse (ToolResult)
        assert_eq!(ir.messages[2].role, crate::ir::IrRole::User);
        assert_eq!(ir.messages[2].content.len(), 1);
        if let crate::ir::IrBlock::ToolResult {
            tool_use_id,
            content,
            is_error,
        } = &ir.messages[2].content[0]
        {
            assert_eq!(tool_use_id, "get_weather");
            assert!(!is_error);
            assert_eq!(content.len(), 1);
            if let crate::ir::IrBlock::Text { text, .. } = &content[0] {
                // Response serialized as JSON string
                assert!(text.contains("72") || text.contains("temperature"));
            } else {
                panic!("expected Text block in tool result");
            }
        } else {
            panic!("expected ToolResult block in third message");
        }

        // Assert tools
        assert_eq!(ir.tools.len(), 1);
        let crate::ir::IrTool {
            name,
            description,
            input_schema,
        } = &ir.tools[0];
        {
            assert_eq!(name, "get_weather");
            assert_eq!(description.as_deref(), Some("Get weather for a location"));
            assert!(!input_schema.is_null());
        }

        // Assert generationConfig fields
        assert_eq!(ir.max_tokens, Some(4096));
        assert_eq!(ir.temperature, Some(0.7));
        assert!(ir.stream);
    }

    // Gemini round-trip test - write_request(read_request(j)) == j for canonical fixture
    #[test]
    fn test_gemini_roundtrip_identity() {
        let j = serde_json::json!({
            "model": "gemini-pro",
            "systemInstruction": {"parts": [{"text": "You are a helpful assistant."}]},
            "contents": [
                {"role": "user", "parts": [{"text": "Hello"}]},
                {"role": "model", "parts": [{"text": "Hi there!"}]}
            ],
            "generationConfig": {"maxOutputTokens": 100, "temperature": 0.5},
            "stream": false
        });

        let reader = GeminiReader;
        let writer = GeminiWriter;

        // Canonical form: minimal fixture that round-trips exactly
        let ir = reader
            .read_request(&j)
            .expect("read_request should succeed");
        let roundtrip = writer.write_request(&ir);

        // Compare as Value - exact identity on representable subset
        assert_eq!(roundtrip, j, "round-trip must be byte-identical");
    }

    // Protocol::gemini resolves correctly with working reader/writer
    #[test]
    fn test_gemini_protocol_resolves() {
        let proto = Protocol::gemini();
        assert_eq!(proto.name(), "gemini");

        let reader = proto.reader();
        let writer = proto.writer();

        // Verify reader methods work
        let j = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "test"}]}]
        });
        let ir = reader.read_request(&j).expect("reader should parse");
        assert_eq!(ir.messages.len(), 1);

        // Verify writer methods work
        let output = writer.write_request(&ir);
        assert!(output.as_object().unwrap().contains_key("contents"));

        // Verify other protocol methods.: the real per-request path embeds the model via
        // upstream_path_for(); upstream_path() is just the model-independent base.
        assert_eq!(writer.upstream_path(), "/v1beta/models");
        assert_eq!(
            writer.upstream_path_for("gemini-pro"),
            "/v1beta/models/gemini-pro:generateContent"
        );
        let headers = writer.auth_headers("test-key");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "x-goog-api-key");

        // Verify error handling methods
        let status_code = StatusCode::TOO_MANY_REQUESTS;
        let signal = reader.classify(status_code, b"{}");
        assert_eq!(signal.class, StatusClass::RateLimit);

        let raw_error = reader.extract_error(status_code, b"{}");
        assert_eq!(raw_error.http_status, 429);
    }

    #[test]
    fn test_bedrock_and_responses_register() {
        // Both 0.10 protocols resolve via the registry and the ingress resolver.
        let registry = ProtocolRegistry::with_builtins();
        assert!(registry.get("bedrock").is_some(), "bedrock in registry");
        assert!(registry.get("responses").is_some(), "responses in registry");
        assert!(
            protocol_for("bedrock").is_some(),
            "bedrock resolves for ingress"
        );
        assert!(
            protocol_for("responses").is_some(),
            "responses resolves for ingress"
        );

        // Responses: bearer auth + the /v1/responses egress path (fully usable).
        let responses = Protocol::responses();
        assert_eq!(responses.name(), "responses");
        assert_eq!(responses.writer().upstream_path(), "/v1/responses");
        let headers = responses.writer().auth_headers("sk-test");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "authorization");
        assert_eq!(headers[0].1.to_str().unwrap(), "Bearer sk-test");

        // Gemini selects the streaming vs non-streaming endpoint by request intent.
        let gemini = Protocol::gemini();
        assert_eq!(
            gemini
                .writer()
                .upstream_path_for_stream("gemini-pro", false),
            "/v1beta/models/gemini-pro:generateContent"
        );
        assert_eq!(
            gemini.writer().upstream_path_for_stream("gemini-pro", true),
            "/v1beta/models/gemini-pro:streamGenerateContent?alt=sse"
        );
        // Non-Gemini protocols ignore the stream flag (single path).
        assert_eq!(
            Protocol::openai()
                .writer()
                .upstream_path_for_stream("x", true),
            Protocol::openai().writer().upstream_path_for("x")
        );

        // Bedrock: model-in-path Converse URL + native SigV4 auth + ConverseStream
        // event-stream decoding. Fully first-class.
        let bedrock = Protocol::bedrock();
        assert_eq!(bedrock.name(), "bedrock");
        assert_eq!(
            bedrock.writer().upstream_path_for("anthropic.claude-3"),
            "/model/anthropic.claude-3/converse"
        );
    }
}

#[cfg(test)]
mod gemini_tests {
    use super::*;
    use crate::ir::{IrBlockMeta, IrDelta, IrRole, IrStreamEvent};

    // read_response decode - Gemini generateContent response with text + functionCall
    #[test]
    fn test_gemini_read_response_decode() {
        let j = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": "The weather in San Francisco is sunny."},
                        {"functionCall": {"name": "get_weather", "args": {"location": "San Francisco"}}}
                    ]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 15,
                "candidatesTokenCount": 8
            }
        });

        let reader = GeminiReader;
        let resp = reader.read_response(&j).expect("should parse");

        // Assert content: Text + ToolUse
        assert_eq!(resp.content.len(), 2);

        if let crate::ir::IrBlock::Text { text, .. } = &resp.content[0] {
            assert_eq!(text, "The weather in San Francisco is sunny.");
        } else {
            panic!("expected Text block");
        }

        if let crate::ir::IrBlock::ToolUse { id: _, name, input } = &resp.content[1] {
            assert_eq!(name, "get_weather");
            match input {
                serde_json::Value::Object(obj) => {
                    assert_eq!(
                        obj.get("location"),
                        Some(&serde_json::json!("San Francisco"))
                    );
                }
                _ => panic!("input should be Object"),
            }
        } else {
            panic!("expected ToolUse block");
        }

        // Assert stop_reason: "STOP" → "end_turn"
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));

        // Assert usage: promptTokenCount→input_tokens, candidatesTokenCount→output_tokens
        assert_eq!(resp.usage.input_tokens, 15);
        assert_eq!(resp.usage.output_tokens, 8);
    }

    // whole-response round-trip - write_response(read_response(j)) == j
    #[test]
    fn test_gemini_read_write_response_roundtrip() {
        let j = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"text": "Hello, world!"}]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 5,
                "candidatesTokenCount": 3
            }
        });

        let reader = GeminiReader;
        let writer = GeminiWriter;

        let ir = reader.read_response(&j).expect("should parse");
        let roundtrip = writer.write_response(&ir);

        // Round-trip must be byte-identical for canonical text-only fixture
        assert_eq!(roundtrip, j, "whole-response round-trip must be identical");
    }

    // stream fan-out - feed Gemini chunk sequence through StreamDecodeState
    #[test]
    fn test_gemini_read_response_events_stream_fanout() {
        let reader = GeminiReader;
        let mut state = crate::ir::StreamDecodeState::default();

        // Chunk 1: text delta (role+text)
        let chunk1 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Hello"}]},
                "finishReason": null
            }]
        });

        // Chunk 2: more text delta
        let chunk2 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": ", world!"}]},
                "finishReason": null
            }]
        });

        // Chunk 3: finish with STOP + usageMetadata
        let chunk3 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 5
            }
        });

        let mut events: Vec<IrStreamEvent> = Vec::new();

        for chunk in [chunk1.clone(), chunk2.clone(), chunk3.clone()] {
            events.extend(reader.read_response_events("", &chunk, &mut state));
        }

        // Assert exact event sequence: MessageStart, BlockStart{0,Text}, BlockDelta×2, BlockStop{0}, MessageDelta{end_turn,usage}, MessageStop
        assert_eq!(events.len(), 7);

        assert!(matches!(
            events[0],
            IrStreamEvent::MessageStart {
                role: IrRole::Assistant,
                usage: None,
                ..
            }
        ));

        assert!(matches!(
            events[1],
            IrStreamEvent::BlockStart {
                index: 0,
                block: IrBlockMeta::Text
            }
        ));

        if let IrStreamEvent::BlockDelta { index: idx, delta } = &events[2] {
            assert_eq!(*idx, 0);
            if let IrDelta::TextDelta(text) = delta {
                assert_eq!(text, "Hello");
            } else {
                panic!("expected TextDelta");
            }
        } else {
            panic!("expected BlockDelta");
        }

        if let IrStreamEvent::BlockDelta { index: idx, delta } = &events[3] {
            assert_eq!(*idx, 0);
            if let IrDelta::TextDelta(text) = delta {
                assert_eq!(text, ", world!");
            } else {
                panic!("expected TextDelta");
            }
        } else {
            panic!("expected BlockDelta");
        }

        assert!(matches!(events[4], IrStreamEvent::BlockStop { index: 0 }));

        if let IrStreamEvent::MessageDelta {
            stop_reason, usage, ..
        } = &events[5]
        {
            assert_eq!(stop_reason.as_deref(), Some("end_turn"));
            assert_eq!(usage.input_tokens, 10);
            assert_eq!(usage.output_tokens, 5);
        } else {
            panic!("expected MessageDelta");
        }

        assert!(matches!(events[6], IrStreamEvent::MessageStop));
    }

    // write_response_event - BlockDelta TextDelta → candidates[0].content.parts[0].text
    #[test]
    fn test_gemini_write_response_event_text_delta() {
        let writer = GeminiWriter;

        let ev = IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        };

        let result = writer.write_response_event(&ev);
        assert!(result.is_some());

        let (_, chunk) = result.unwrap();

        // Assert structure: candidates[0].content.parts[0].text == "hi"
        let candidates = chunk.get("candidates").and_then(|c| c.as_array()).unwrap();
        assert_eq!(candidates.len(), 1);

        let candidate = &candidates[0];
        let content = candidate.get("content").unwrap();

        assert_eq!(content.get("role").and_then(|r| r.as_str()), Some("model"));

        let parts_arr = content.get("parts").and_then(|p| p.as_array()).unwrap();
        assert_eq!(parts_arr.len(), 1);

        let part = &parts_arr[0];
        assert_eq!(part.get("text").and_then(|t| t.as_str()), Some("hi"));
    }

    // write_response_event - MessageDelta{end_turn} → finishReason "STOP"
    #[test]
    fn test_gemini_write_response_event_message_delta() {
        let writer = GeminiWriter;

        let ev = IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };

        let result = writer.write_response_event(&ev);
        assert!(result.is_some());

        let (_, chunk) = result.unwrap();

        // Assert finishReason == "STOP"
        let candidates = chunk.get("candidates").and_then(|c| c.as_array()).unwrap();
        assert_eq!(candidates.len(), 1);

        let candidate = &candidates[0];
        assert_eq!(
            candidate.get("finishReason").and_then(|r| r.as_str()),
            Some("STOP")
        );

        // Assert usageMetadata present
        assert!(chunk.get("usageMetadata").is_some());
    }

    // stream fan-out with functionCall - ToolUse via functionCall
    #[test]
    fn test_gemini_read_response_events_function_call() {
        let reader = GeminiReader;
        let mut state = crate::ir::StreamDecodeState::default();

        // Chunk with text delta
        let chunk1 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": [{"text": "Let me check"}]},
                "finishReason": null
            }]
        });

        // Chunk with functionCall (Gemini sends whole args, not streamed)
        let chunk2 = serde_json::json!({
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        {"text": ""},
                        {"functionCall": {"name": "get_weather", "args": {"location": "SF"}}}
                    ]
                },
                "finishReason": null
            }]
        });

        // Chunk with finishReason STOP
        let chunk3 = serde_json::json!({
            "candidates": [{
                "content": {"role": "model", "parts": []},
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 20,
                "candidatesTokenCount": 10
            }
        });

        let mut events: Vec<IrStreamEvent> = Vec::new();

        for chunk in [chunk1.clone(), chunk2.clone(), chunk3.clone()] {
            events.extend(reader.read_response_events("", &chunk, &mut state));
        }

        // Verify we have MessageStart + BlockStart{Text} + text delta + ToolUse block + tool args delta + blocks stop + MessageDelta + MessageStop
        assert!(events.len() >= 6);

        // Find the ToolUse-related events
        let mut found_tool_block_start = false;
        let mut found_tool_args_delta = false;

        for event in &events {
            match event {
                IrStreamEvent::BlockStart {
                    index: _,
                    block: crate::ir::IrBlockMeta::ToolUse { id: _, name },
                    ..
                } => {
                    if *name == "get_weather" {
                        found_tool_block_start = true;
                    }
                }

                IrStreamEvent::BlockDelta {
                    delta: IrDelta::InputJsonDelta(json_str),
                    ..
                } => {
                    // Parse and check args contain location
                    if let Ok(args) = serde_json::from_str::<serde_json::Value>(json_str) {
                        if args.get("location").is_some() {
                            found_tool_args_delta = true;
                        }
                    }
                }
                _ => {}
            }
        }

        assert!(found_tool_block_start, "should have ToolUse BlockStart");
        assert!(
            found_tool_args_delta,
            "should have InputJsonDelta with args"
        );
    }

    // --- 1.0 streaming-conformance regression tests (cross-protocol seam) ----------------------

    /// Helper: split a concatenated OpenAI SSE byte stream into its per-frame JSON chunk objects
    /// (skipping the `[DONE]` sentinel and any keepalive). Mirrors `parse_sse_frame`'s framing.
    fn openai_sse_chunks(bytes: &[u8]) -> Vec<serde_json::Value> {
        let text = std::str::from_utf8(bytes).expect("openai SSE is utf-8");
        let mut chunks = Vec::new();
        for frame in text.split("\n\n") {
            let Some(rest) = frame.lines().find_map(|l| l.strip_prefix("data:")) else {
                continue;
            };
            let payload = rest.strip_prefix(' ').unwrap_or(rest).trim();
            if payload.is_empty() || payload == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(payload) {
                chunks.push(v);
            }
        }
        chunks
    }

    /// Finding (OpenAI per-chunk identity): the real OpenAI API repeats the top-level
    /// `id`/`created`/`model` on EVERY `chat.completion.chunk`, not just the opening role chunk. An
    /// Anthropic egress stream translated to an OpenAI ingress must therefore carry the SAME
    /// `id`/`created`/`model` on every emitted chunk — a single stream identity, never a fresh id per
    /// chunk and never an identity-less later chunk (a detectable shape divergence).
    #[test]
    fn test_openai_ingress_per_chunk_identity_repeated() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("openai ingress translator");
        let mut raw: Vec<u8> = Vec::new();
        for frame in [
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_backend\",\"role\":\"assistant\",\"model\":\"claude-x\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" there\"}}\n\n",
            "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
            "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"input_tokens\":5,\"output_tokens\":2}}\n\n",
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }
        raw.extend(t.finish());

        let chunks = openai_sse_chunks(&raw);
        assert!(
            chunks.len() >= 2,
            "expected multiple chunks; got {}",
            chunks.len()
        );
        // Every chunk is a chat.completion.chunk carrying the SAME id/created/model.
        let first_id = chunks[0]
            .get("id")
            .and_then(|v| v.as_str())
            .expect("first chunk has an id")
            .to_string();
        // Synthesized (cross-protocol) id must be a native chatcmpl- shape, NOT the foreign msg_.
        assert!(
            first_id.starts_with("chatcmpl-"),
            "cross-protocol id must be a native chatcmpl- id; got {first_id}"
        );
        let first_created = chunks[0].get("created").and_then(|v| v.as_u64());
        assert!(first_created.is_some(), "first chunk has a created");
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(
                c.get("object").and_then(|v| v.as_str()),
                Some("chat.completion.chunk"),
                "chunk {i} object; got {c}"
            );
            assert_eq!(
                c.get("id").and_then(|v| v.as_str()),
                Some(first_id.as_str()),
                "chunk {i} must repeat the SAME stream id; got {c}"
            );
            assert_eq!(
                c.get("created").and_then(|v| v.as_u64()),
                first_created,
                "chunk {i} must repeat the SAME created; got {c}"
            );
            assert_eq!(
                c.get("model").and_then(|v| v.as_str()),
                Some("claude-x"),
                "chunk {i} must repeat the stream model; got {c}"
            );
        }
        // The foreign backend id must never leak to the OpenAI client.
        assert!(
            !raw.windows(b"msg_backend".len())
                .any(|w| w == b"msg_backend"),
            "foreign backend id must be stripped on cross-protocol ingress"
        );
    }

    /// MEDIUM/test-coverage (proto/mod.rs:754-763): the `apply_openai_chunk_identity` guard skips any
    /// frame that is not a `chat.completion.chunk` (no `object` field). The in-band ERROR envelope the
    /// OpenAI writer emits mid-stream (`{"error":{...}}`, no `object`) must therefore pass through
    /// UNCHANGED — no synthetic `id`/`created` injected, which would corrupt the error JSON shape a
    /// strict SDK rejects. Drive an anthropic egress → OpenAI ingress stream with a real opening chunk
    /// (to LATCH the stream identity) followed by a mid-stream error event, then assert the resulting
    /// error frame carries neither `id` nor `created`.
    #[test]
    fn test_openai_ingress_mid_stream_error_envelope_unchanged_by_identity() {
        let mut t = StreamTranslate::new("openai", "anthropic").expect("openai ingress translator");
        let mut raw: Vec<u8> = Vec::new();
        for frame in [
            // Opening chunk: latches id/created/model in apply_openai_chunk_identity.
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_x\",\"role\":\"assistant\",\"model\":\"claude-x\"}}\n\n",
            "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n",
            "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            // Mid-stream error: the writer emits an in-band `{"error":{...}}` envelope (no `object`).
            "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"upstream overloaded\"}}\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }
        raw.extend(t.finish());

        let chunks = openai_sse_chunks(&raw);
        // There must be at least one error envelope; locate it.
        let error_frame = chunks
            .iter()
            .find(|c| c.get("error").is_some())
            .expect("a mid-stream error envelope must be emitted to the OpenAI client");
        // The guard must have left it untouched: NO synthetic id/created injected onto the error.
        assert!(
            error_frame.get("id").is_none(),
            "error envelope must NOT receive an injected `id` (would corrupt the shape); got {error_frame}"
        );
        assert!(
            error_frame.get("created").is_none(),
            "error envelope must NOT receive an injected `created`; got {error_frame}"
        );
        assert!(
            error_frame.get("object").is_none(),
            "error envelope is not a chat.completion.chunk and carries no `object`; got {error_frame}"
        );
        // And the error body itself is well-formed (the writer's standard in-band shape).
        assert!(
            error_frame
                .get("error")
                .and_then(|e| e.get("type"))
                .and_then(|v| v.as_str())
                .is_some(),
            "error envelope must carry an `error.type`; got {error_frame}"
        );
        // The chat.completion.chunk frames before the error still carry a latched identity (proving
        // identity injection IS active on real chunks — the guard is selective, not globally off).
        let had_identity_chunk = chunks.iter().any(|c| {
            c.get("object").and_then(|v| v.as_str()) == Some("chat.completion.chunk")
                && c.get("id").is_some()
        });
        assert!(
            had_identity_chunk,
            "real chat.completion.chunk frames must still carry the latched id (guard is selective)"
        );
    }

    /// Finding (bedrock messageStop+metadata fan-out, real latencyMs): a bedrock->bedrock stream must
    /// round-trip — the egress reader collapses the native two-frame stop/usage split into ONE
    /// combined IR MessageDelta, and the ingress writer fan-out RE-SPLITS it back into the native
    /// `messageStop` + `metadata` frame pair (metadata carrying the real usage AND a real
    /// `metrics.latencyMs`). This proves the reader collapse and writer fan-out are exact inverses.
    #[test]
    fn test_bedrock_to_bedrock_stream_roundtrips_stop_and_metadata() {
        // Same-protocol returns None (native passthrough), so drive the cross-protocol seam with a
        // foreign egress that still produces the combined delta. Use openai egress → bedrock ingress:
        // a single OpenAI final chunk carries finish_reason + usage, the reader emits ONE combined
        // MessageDelta, and the bedrock-ingress fan-out must produce messageStop + metadata.
        assert!(
            StreamTranslate::new("bedrock", "bedrock").is_none(),
            "bedrock->bedrock needs no translator (native passthrough)"
        );

        let mut t = StreamTranslate::new("bedrock", "openai").expect("bedrock ingress translator");
        let mut raw: Vec<u8> = Vec::new();
        for frame in [
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3}}\n\n",
            "data: [DONE]\n\n",
        ] {
            raw.extend(t.feed(frame.as_bytes()));
        }
        raw.extend(t.finish());

        let mut buf = raw.clone();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(
            buf.is_empty(),
            "all frames decode cleanly; {} left",
            buf.len()
        );
        let types: Vec<&str> = frames.iter().map(|(et, _)| et.as_str()).collect();
        // The combined delta fans out to a messageStop FOLLOWED by a metadata frame.
        let stop_pos = types
            .iter()
            .position(|t| *t == "messageStop")
            .expect("messageStop frame present");
        let meta_pos = types
            .iter()
            .position(|t| *t == "metadata")
            .expect("metadata frame present");
        assert!(
            stop_pos < meta_pos,
            "messageStop must precede metadata (native order); got {types:?}"
        );
        // The metadata frame carries the real usage and a real latencyMs (not a fabricated 0-tell).
        let meta = frames
            .iter()
            .find(|(et, _)| et == "metadata")
            .expect("metadata frame");
        let mv: serde_json::Value = serde_json::from_slice(&meta.1).expect("valid metadata JSON");
        assert_eq!(
            mv.pointer("/usage/inputTokens").and_then(|x| x.as_u64()),
            Some(7),
            "usage inputTokens; got {mv}"
        );
        assert_eq!(
            mv.pointer("/usage/outputTokens").and_then(|x| x.as_u64()),
            Some(3),
            "usage outputTokens; got {mv}"
        );
        assert!(
            mv.pointer("/metrics/latencyMs")
                .and_then(|x| x.as_u64())
                .is_some(),
            "metadata must carry a real metrics.latencyMs; got {mv}"
        );
        // The messageStop frame carries the mapped stop reason.
        let stop = frames
            .iter()
            .find(|(et, _)| et == "messageStop")
            .expect("messageStop frame");
        let sv: serde_json::Value =
            serde_json::from_slice(&stop.1).expect("valid messageStop JSON");
        assert_eq!(
            sv.get("stopReason").and_then(|x| x.as_str()),
            Some("end_turn"),
            "stop reason maps to end_turn; got {sv}"
        );
    }

    /// REGRESSION (R7 MEDIUM, forward.rs tap on bedrock ingress): on a BEDROCK-ingress cross-protocol
    /// stream the translator's OUTPUT is binary eventstream framing, so the forward-layer `UsageTap`
    /// (a JSON `{`-scanner) would mis-parse the length-prefixes/CRC32s and zero token accounting.
    /// `take_tap_json` exposes the PRE-ENCODE JSON instead. This asserts that JSON (a) is text the tap
    /// can parse, (b) carries the real usage, and (c) the tap reads `inputTokens`/`outputTokens` from
    /// it — while the binary `feed`/`finish` OUTPUT does NOT (the bug it fixes).
    #[test]
    fn test_bedrock_ingress_tap_json_carries_usage_not_binary() {
        let mut t = StreamTranslate::new("bedrock", "openai").expect("bedrock ingress translator");
        let mut binary_out: Vec<u8> = Vec::new();
        let mut tap_json: Vec<u8> = Vec::new();
        for frame in [
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hi\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-x\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4}}\n\n",
            "data: [DONE]\n\n",
        ] {
            binary_out.extend(t.feed(frame.as_bytes()));
            tap_json.extend(t.take_tap_json());
        }
        binary_out.extend(t.finish());
        tap_json.extend(t.take_tap_json());

        assert!(t.ingress_is_eventstream(), "bedrock ingress is eventstream");

        // The tap-JSON side-channel parses with the forward-layer UsageTap and yields the real usage.
        let mut tap = crate::forward::UsageTap::new();
        tap.feed(&bytes::Bytes::from(tap_json));
        assert_eq!(
            tap.input_tokens,
            Some(11),
            "tap reads inputTokens from the pre-encode JSON"
        );
        assert_eq!(
            tap.output_tokens,
            Some(4),
            "tap reads outputTokens from the pre-encode JSON"
        );

        // The translator OUTPUT really is binary eventstream framing (NOT the JSON text the tap is
        // built for): it carries the AWS frame prelude/CRC bytes, so it is not parseable as a whole
        // JSON document. The point of the side-channel is that token accounting reads the clean JSON
        // above instead of brace-scanning these binary frames (where stray `{` bytes in the
        // prelude/CRC/length fields mislead the scanner — the unreliability the finding describes).
        assert!(!binary_out.is_empty(), "binary frames were emitted");
        assert!(
            serde_json::from_slice::<serde_json::Value>(&binary_out).is_err(),
            "translator output is binary eventstream framing, not a JSON document"
        );
        // The frames decode as real AWS eventstream frames (proving they are binary-framed, not SSE).
        let mut buf = binary_out.clone();
        let frames = crate::eventstream::drain_frames(&mut buf);
        assert!(
            frames.iter().any(|(et, _)| et == "metadata"),
            "binary output contains the eventstream metadata frame"
        );
    }
}

#[cfg(test)]
mod context_length_tests {
    use super::*;
    use crate::breaker::{classify, Disposition};
    use axum::http::StatusCode;

    #[test]
    fn test_classify_context_length_both_protocols() {
        // OpenAI: error.code == context_length_exceeded
        let o = OpenAiReader.classify(
            StatusCode::BAD_REQUEST,
            br#"{"error":{"code":"context_length_exceeded","message":"maximum context length is 8192 tokens"}}"#,
        );
        assert_eq!(
            o.class,
            StatusClass::ContextLength,
            "openai code → ContextLength"
        );

        // Anthropic: "prompt is too long"
        let a = AnthropicReader.classify(
            StatusCode::BAD_REQUEST,
            br#"{"error":{"type":"invalid_request_error","message":"prompt is too long: 250000 tokens > 200000 maximum"}}"#,
        );
        assert_eq!(
            a.class,
            StatusClass::ContextLength,
            "anthropic message → ContextLength"
        );

        // A plain 400 client error is NOT context-length (must still be ClientError).
        let c = AnthropicReader.classify(
            StatusCode::BAD_REQUEST,
            br#"{"error":{"type":"invalid_request_error","message":"unexpected field 'foo'"}}"#,
        );
        assert_eq!(
            c.class,
            StatusClass::ClientError,
            "generic 400 stays ClientError"
        );
    }

    #[test]
    fn test_context_length_disposition() {
        let sig = CanonicalSignal {
            class: StatusClass::ContextLength,
            provider_signal: Some("context_length".to_string()),
            retry_after: None,
        };
        assert_eq!(classify(&sig), Disposition::ContextLength);
    }
}

#[cfg(test)]
mod gemini_integration_tests {
    use super::*;

    // Gemini's URL embeds the model; non-Gemini protocols keep their fixed path.
    #[test]
    fn test_gemini_upstream_path_for_embeds_model() {
        let gemini_writer = GeminiWriter;
        assert_eq!(
            gemini_writer.upstream_path_for("gemini-1.5-pro"),
            "/v1beta/models/gemini-1.5-pro:generateContent"
        );
        // Default (non-Gemini) ignores the model.
        assert_eq!(
            AnthropicWriter.upstream_path_for("anything"),
            "/v1/messages"
        );
        assert_eq!(
            OpenAiWriter.upstream_path_for("anything"),
            "/v1/chat/completions"
        );
    }

    // gemini is now a registered, buildable protocol.
    #[test]
    fn test_gemini_registered_in_builtins() {
        let reg = ProtocolRegistry::with_builtins();
        let g = reg.get("gemini").expect("gemini should be registered");
        assert_eq!(g.name(), "gemini");
        assert_eq!(
            g.writer().upstream_path_for("m"),
            "/v1beta/models/m:generateContent"
        );
        // x-goog-api-key auth header.
        let headers = g.writer().auth_headers("k");
        assert!(headers.iter().any(|(n, _)| n.as_str() == "x-goog-api-key"));
    }
}
