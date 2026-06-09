// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! OpenAI Responses API protocol reader/writer implementation.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

/// Largest wire `output_index` we accept in a streaming Responses event before clamping. The
/// Responses API, like Chat Completions, documents at most 128 parallel output items, so any larger
/// index is malformed; clamp it to this value (the highest valid 0-based index, 127) before the
/// `usize` cast so a crafted `u64::MAX` index can never participate in unbounded set growth or
/// index arithmetic. Mirrors `openai.rs::MAX_TOOL_INDEX`.
const MAX_OUTPUT_INDEX: usize = 127;

/// Fallback `model` name emitted when the IR carries none. The official OpenAI Responses SDK types
/// `Response.model` as a REQUIRED non-nullable string, so a `response.created`/full response that
/// omits `model` fails a strict Pydantic/Zod decoder — and a real `/v1/responses` endpoint never
/// omits it, making the omission a distinguishability tell. On any cross-protocol path
/// (Anthropic→Responses, Bedrock→Responses) the IR `model` is `None`; emit this fallback rather
/// than dropping the key. Mirrors `openai.rs::DEFAULT_MODEL`.
const DEFAULT_MODEL: &str = "gpt-4o";

/// Hard cap on the number of DISTINCT output indices tracked per stream in `StreamDecodeState`
/// (`open_tools`) and in the writer's open-item sets. Bounds per-request memory against a
/// pathological backend that emits a unique `output_index` per event (a per-connection amplification
/// DoS). Matches `openai.rs::MAX_OPEN_TOOLS` (OpenAI's documented parallel-tool-call limit, 128).
const MAX_OPEN_TOOLS: usize = 128;

/// Key offset under which the streaming reader tracks OPEN TEXT output indices inside the shared
/// `StreamDecodeState::open_tools` set. A native /v1/responses stream can carry MULTIPLE message
/// (text) output items, each at its OWN `output_index`, so a single index-blind `text_block_open`
/// bool cannot pair a BlockStart/BlockStop per text index: a second text item's delta would emit a
/// BlockDelta with no preceding BlockStart (orphan delta) and the terminal frame would close the
/// wrong index. `StreamDecodeState` (in `ir.rs`) exposes only the `open_tools` set and the
/// `text_block_open` bool, so to give text the SAME per-index discipline tool items already have —
/// without a new shared field — text indices are stored as `idx + TEXT_INDEX_KEY_OFFSET`. Wire
/// `output_index` is clamped to `MAX_OUTPUT_INDEX` (127), so a real tool index (<=127) and an
/// offset text key (>=1000) can never collide; the function-call routing guards
/// (`open_tools.contains(&idx)`) keep matching only raw tool indices, and the terminal arm
/// distinguishes a tool close (`remove(&idx)`) from a text close (`remove(&(idx + offset))`).
const TEXT_INDEX_KEY_OFFSET: usize = 1000;

/// Lowercase+uppercase+digit base62 alphabet — the character class native Responses ids draw their
/// opaque suffix from. Shared by [`synthesize_item_id`] and [`synthesize_response_id`].
const BASE62: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Width of the opaque base62 suffix on a synthesized item id (`msg_…`/`fc_…`). Native Responses
/// item ids carry a long opaque random token with no positional structure; 48 base62 chars matches
/// the entropy/length profile of native ids so a client that length-checks or regex-validates the
/// `item_id` cannot fingerprint a too-short or structured suffix as non-native.
const ITEM_ID_TOKEN_LEN: usize = 48;

/// Width of the opaque base62 suffix on a synthesized `resp_` id. Native OpenAI Responses ids are
/// ~38+ chars of opaque random data after the `resp_` prefix; 48 base62 chars stays in that profile.
const RESPONSE_ID_TOKEN_LEN: usize = 48;

/// Fill a fixed-width base62 token ENTIRELY from the OS CSPRNG, with NO counter overlay. A counter
/// overlaid into any fixed region of the token leaves those characters predictable/low-entropy (the
/// counter stays small, so its high base62 digits are constant '0') — a structural fingerprint at
/// whatever position it occupies that a native, fully-random vendor id never carries. The opaque
/// suffixes here are wide (>= 48 chars ≈ 285 bits of base62 entropy), so pure CSPRNG output is
/// collision-free in practice for a per-process id stream and needs no monotonic-counter backstop.
/// On entropy failure the buffer stays zeroed (all '0'), so this never panics on the request path.
/// Returns an owned `String` of exactly `N` base62 characters.
fn synth_token<const N: usize>() -> String {
    let mut rand_bytes = [0u8; N];
    let _ = getrandom::getrandom(&mut rand_bytes);
    let mut token = [b'0'; N];
    for (slot, &byte) in token.iter_mut().zip(rand_bytes.iter()) {
        *slot = BASE62[(byte % 62) as usize];
    }

    // `token` is ASCII base62 by construction, hence always valid UTF-8; the fallback only guards an
    // impossible non-ASCII byte and keeps the path panic-free (no unwrap/expect on the request path).
    String::from_utf8(token.to_vec()).unwrap_or_else(|_| "0".repeat(N))
}

/// Synthesize a per-output-item id for the streaming writer. Native Responses events carry an
/// `item_id` (`msg_…` for message parts, `fc_…` for function-call parts) that is constant across the
/// `output_item.added` → deltas → `output_item.done` lifecycle of a single output item. The IR's
/// block events carry only the integer `output_index` (and, for tool use, the call id), not a wire
/// `item_id`, so the writer must mint one.
///
/// Per-INDEX determinism within a stream is what the lifecycle correlation needs: the
/// added/delta/done events of one item must share an `item_id`. The previous implementation used a
/// sequential zero-padded hex index (`msg_00000000`, `msg_00000001`, …) — a positional structure no
/// native opaque id has, letting any observer fingerprint a proxied response from the id pattern.
/// We replace the suffix with an opaque CSPRNG-backed base62 token of native length, while keeping
/// per-`(prefix, index)` determinism within a stream via a per-writer cache (see
/// `ResponsesWriter::item_id_for`). This free function mints a FRESH opaque id; callers that need
/// the stream-stable id go through the writer's cache.
fn synthesize_item_id(prefix: &str) -> String {
    format!("{prefix}_{}", synth_token::<ITEM_ID_TOKEN_LEN>())
}

/// Current unix epoch seconds, or 0 if the clock is before the epoch (never on a sane host).
/// Kept panic-free for the request path: no `unwrap`/`expect` on `SystemTime`.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Synthesize a protocol-correct Responses id (`resp_<opaque base62>`) for cross-protocol responses
/// where the backend supplied none. Native OpenAI Responses ids are `resp_` followed by ~38+ chars
/// of opaque random data with NO embedded structure; the previous form encoded the unix timestamp as
/// the leading hex segment (`resp_{timestamp_hex}{counter_hex}`), which both made the id shorter than
/// native AND leaked the proxy's server clock to within one second to anyone holding a response id.
/// The opaque CSPRNG token here matches the native length/entropy profile and embeds no timestamp;
/// the whole token is drawn from `getrandom` (via `synth_token`) with NO counter overlay — at >= 48
/// base62 chars (~285 bits) the birthday bound makes a per-process collision astronomically unlikely,
/// so a counter would only ADD a predictable low-entropy region (a structural fingerprint) for no
/// uniqueness benefit. Native passthrough never calls this: it carries the upstream id verbatim.
fn synthesize_response_id() -> String {
    format!("resp_{}", synth_token::<RESPONSE_ID_TOKEN_LEN>())
}

/// Parse a Responses `image_url` string into an IR `(media_type, data)` pair.
///
/// A base64 data URI (`data:<mime>;base64,<payload>`) is split on the FIRST comma — the single `;`
/// canonical shape has only two `;`-delimited fields, so the previous `splitn(3, ';')` logic could
/// never recover the payload and silently dropped every image. We take the MIME type from the
/// metadata before the comma and the base64 payload after it, matching `openai.rs`'s
/// `parse_image_url`. Any non-data URL (an https reference, or a data URI we cannot confidently
/// split) is preserved verbatim in `data` with the `image_url` media_type sentinel so the writer can
/// reconstruct the exact original `image_url` on a same-protocol round-trip — never a human-readable
/// comment embedded in the payload.
fn parse_image_url(url: &str) -> (String, String) {
    if let Some(rest) = url.strip_prefix("data:") {
        if let Some((meta, payload)) = rest.split_once(',') {
            // meta is e.g. "image/png;base64" or "image/png" — keep only the MIME type.
            let media_type = meta.split(';').next().unwrap_or("").to_string();
            if meta.contains("base64") && !media_type.is_empty() {
                return (media_type, payload.to_string());
            }
        }
    }
    // Non-data URL (https://...) or an unrecognized data URI: keep it verbatim under the
    // `image_url` sentinel so the writer round-trips it as-is rather than mangling it.
    ("image_url".to_string(), url.to_string())
}

/// Reconstruct a Responses `image_url` string from the IR `Image` (media_type, data) pair — the
/// inverse of [`parse_image_url`]. A URL-sentinel image is emitted verbatim; a base64 image is
/// re-wrapped into a `data:<mime>;base64,<payload>` URI.
fn image_url_from_ir(media_type: &str, data: &str) -> String {
    if media_type == "image_url" {
        data.to_string()
    } else {
        format!("data:{media_type};base64,{data}")
    }
}

/// Derive the native `error.code` value for a Responses/OpenAI `error.type`.
///
/// The `/v1/responses` surface shares the OpenAI error envelope, and a real bad-key 401 returns
/// `{"type":"authentication_error", ..., "code":"invalid_api_key"}` — the official SDKs surface
/// `error.code` (e.g. `AuthenticationError.code`) to callers, so emitting `code: null` on an auth
/// failure is a deterministic proxy tell that contradicts the total-indistinguishability promise.
/// This mirrors `openai.rs::openai_error_code` (the sibling writer fixed this exact case) so the
/// two surfaces stay consistent. Every other type keeps `null` — the shape OpenAI uses when no
/// machine-readable code applies. No `_ =>` catch-all: the final arm explicitly binds and handles
/// all remaining (including caller-passthrough) types by emitting `null`, the correct native value.
fn responses_error_code(error_type: &str) -> serde_json::Value {
    match error_type {
        "authentication_error" => serde_json::Value::String("invalid_api_key".to_string()),
        // Native OpenAI/Responses carries a populated machine-readable `code` for the over-quota
        // path: `{"type":"insufficient_quota","code":"insufficient_quota"}`. Emitting `null` here
        // (as the older code did) was a fingerprintable divergence on the budget-exceeded 429.
        "insufficient_quota" => serde_json::Value::String("insufficient_quota".to_string()),
        "invalid_request_error"
        | "permission_error"
        | "not_found_error"
        | "rate_limit_error"
        | "server_error" => serde_json::Value::Null,
        other => {
            // A caller-supplied passthrough type we model no code for: OpenAI carries no
            // machine-readable code for these, so `null` matches the native shape. Named binding
            // (not `_`) keeps the arm explicit per the no-catch-all rule.
            let _ = other;
            serde_json::Value::Null
        }
    }
}

#[derive(Clone)]
pub(crate) struct ResponsesReader;

impl ProtocolReader for ResponsesReader {
    fn extract_error(&self, status: StatusCode, body: &[u8]) -> crate::breaker::RawUpstreamError {
        // Parse the error body ONCE and pull both fields from the single JSON tree, rather than
        // re-parsing the same bytes per field (matches the anthropic.rs pattern; error paths are
        // already degraded — avoid the extra parse+alloc on every non-2xx response).
        let (provider_code, structured_type) =
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(json) => {
                    let error = json.get("error").and_then(|e| e.as_object());
                    let provider_code = error
                        .and_then(|e_obj| e_obj.get("code"))
                        .and_then(|c| c.as_str())
                        .map(String::from);
                    let structured_type = error
                        .and_then(|e_obj| e_obj.get("type"))
                        .and_then(|t| t.as_str())
                        .map(String::from);
                    (provider_code, structured_type)
                }
                Err(_) => (None, None),
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
        let code_is_context = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|j| {
                j.get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_str())
                    .map(|s| s.to_string())
            })
            .as_deref()
            == Some("context_length_exceeded");
        if code_is_context
            || String::from_utf8_lossy(body)
                .to_lowercase()
                .contains("maximum context length")
        {
            return CanonicalSignal {
                class: StatusClass::ContextLength,
                provider_signal: Some("context_length".to_string()),
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
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        })?;

        if obj.is_empty() {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            });
        }

        let mut extra = serde_json::Map::new();
        let mut system_blocks: Vec<crate::ir::IrBlock> = Vec::new();

        if let Some(instructions) = obj.get("instructions").and_then(|v| v.as_str()) {
            if !instructions.is_empty() {
                system_blocks.push(crate::ir::IrBlock::Text {
                    text: instructions.to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                });
            }
        }

        let mut messages: Vec<crate::ir::IrMessage> = Vec::new();

        if let Some(input_val) = obj.get("input") {
            if input_val.is_string() {
                let text = input_val.as_str().unwrap_or("").to_string();
                messages.push(crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text,
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                });
            } else if let Some(arr) = input_val.as_array() {
                for item in arr {
                    match item.get("type").and_then(|t| t.as_str()) {
                        Some("input_text") => {
                            let text = item
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::User,
                                content: vec![crate::ir::IrBlock::Text {
                                    text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                            });
                        }
                        Some("input_image") => {
                            let image_url =
                                item.get("image_url").and_then(|u| u.as_str()).unwrap_or("");
                            let (media_type, data) = parse_image_url(image_url);
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::User,
                                content: vec![crate::ir::IrBlock::Image { media_type, data }],
                            });
                        }
                        Some("output_text") => {
                            let text = item
                                .get("text")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Assistant,
                                content: vec![crate::ir::IrBlock::Text {
                                    text,
                                    cache_control: None,
                                    citations: Vec::new(),
                                }],
                            });
                        }
                        Some("function_call") => {
                            let call_id = item
                                .get("call_id")
                                .and_then(|c| c.as_str())
                                .unwrap_or("")
                                .to_string();
                            let name = item
                                .get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("")
                                .to_string();
                            let arguments = item
                                .get("arguments")
                                .and_then(|a| a.as_str())
                                .unwrap_or("{}");
                            // On malformed argument JSON, preserve the raw string rather than
                            // discarding the caller's tool arguments to Null (mirrors the OpenAI
                            // reader). Losing arguments entirely is a lossy cross-protocol bug.
                            let input = serde_json::from_str(arguments).unwrap_or_else(|_| {
                                serde_json::Value::String(arguments.to_string())
                            });

                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Assistant,
                                content: vec![crate::ir::IrBlock::ToolUse {
                                    id: call_id,
                                    name,
                                    input,
                                }],
                            });
                        }
                        Some("function_call_output") => {
                            let call_id = item
                                .get("call_id")
                                .and_then(|c| c.as_str())
                                .unwrap_or("")
                                .to_string();
                            let output_val = item.get("output");
                            let content_blocks: Vec<crate::ir::IrBlock> = match output_val {
                                Some(serde_json::Value::String(out_str)) => {
                                    vec![crate::ir::IrBlock::Text {
                                        text: out_str.clone(),
                                        cache_control: None,
                                        citations: Vec::new(),
                                    }]
                                }
                                _ => output_val
                                    .and_then(|o| o.as_array())
                                    .map(|arr| {
                                        arr.iter().filter_map(|b| responses_block(b).ok()).collect()
                                    })
                                    .unwrap_or_default(),
                            };

                            messages.push(crate::ir::IrMessage {
                                role: crate::ir::IrRole::Tool,
                                content: vec![crate::ir::IrBlock::ToolResult {
                                    tool_use_id: call_id,
                                    content: content_blocks,
                                    is_error: false,
                                }],
                            });
                        }
                        Some("message") => {
                            // The official OpenAI Responses SDK emits conversation turns as typed
                            // `{"type":"message","role":...,"content":[...]}` items. The role-keyed
                            // fallback below only fires for UNTYPED items, so without this arm a
                            // typed message turn would be silently dropped. Read role+content and
                            // map the content blocks via `responses_block`, mirroring the untyped
                            // branch.
                            let role_str = item.get("role").and_then(|r| r.as_str()).unwrap_or("");
                            let role = match role_str {
                                "user" => Some(crate::ir::IrRole::User),
                                "assistant" => Some(crate::ir::IrRole::Assistant),
                                _ => None,
                            };
                            if let Some(role) = role {
                                if let Some(content_arr) =
                                    item.get("content").and_then(|c| c.as_array())
                                {
                                    let msg_content: Vec<crate::ir::IrBlock> = content_arr
                                        .iter()
                                        .filter_map(|b| responses_block(b).ok())
                                        .collect();
                                    messages.push(crate::ir::IrMessage {
                                        role,
                                        content: msg_content,
                                    });
                                }
                            }
                        }
                        Some("reasoning") => {}
                        Some(_) | None => {}
                    }

                    // Handle role/content structured items (user/assistant messages) ONLY when the
                    // item carries no `type` field. A typed item (e.g. "output_text") that also
                    // happens to include a `role` must NOT be re-processed here, or the turn would
                    // be duplicated in the resulting conversation.
                    if item.get("type").is_none() && item.get("role").is_some() {
                        let role_str = item.get("role").and_then(|r| r.as_str()).unwrap_or("");
                        let content_val = item.get("content");

                        let role = match role_str {
                            "user" => crate::ir::IrRole::User,
                            "assistant" => crate::ir::IrRole::Assistant,
                            _ => continue,
                        };

                        if let Some(content_arr) = content_val.and_then(|c| c.as_array()) {
                            let msg_content: Vec<crate::ir::IrBlock> = content_arr
                                .iter()
                                .filter_map(|b| responses_block(b).ok())
                                .collect();

                            messages.push(crate::ir::IrMessage {
                                role,
                                content: msg_content,
                            });
                        }
                    }
                }
            }
        } else if !obj.contains_key("instructions") {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            });
        }

        let mut tools: Vec<crate::ir::IrTool> = Vec::new();
        if let Some(tools_val) = obj.get("tools") {
            for tool_val in tools_val.as_array().unwrap_or(&Vec::new()) {
                let name = tool_val
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let description = tool_val
                    .get("description")
                    .and_then(|v| v.as_str().map(String::from));
                let input_schema = tool_val
                    .get("parameters")
                    .or_else(|| tool_val.get("input_schema"))
                    .cloned()
                    .unwrap_or(serde_json::Value::Null);

                tools.push(crate::ir::IrTool {
                    name,
                    description,
                    input_schema,
                });
            }
        }

        let max_tokens = obj
            .get("max_output_tokens")
            .and_then(|v| v.as_i64())
            .filter(|&v| v > 0)
            .map(|v| v as u32);
        let temperature = obj.get("temperature").and_then(|v| v.as_f64());
        // The Responses API supports `top_p` but has NO `top_k` and no top-level stop-sequence param,
        // so only top_p is promoted here; `top_k`/`stop` stay None/empty (any unmodeled knob remains
        // in `extra`).
        let top_p = obj.get("top_p").and_then(|v| v.as_f64());
        // The Responses API carries `stream` in the request body — read it (don't drop the intent).
        let stream = obj.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);

        // NOTE: `metadata` is deliberately NOT in this exclusion set. The Responses API accepts a
        // top-level `metadata` object (user-defined key/value tagging used for audit logging and
        // billing attribution); busbar does not model it on `IrRequest`, so it must flow through
        // `extra` and be re-emitted verbatim by `write_request`'s extra-forwarding loop. Listing it
        // here (as a prior revision did) silently dropped a stable public API field.
        let modeled_keys: std::collections::HashSet<&str> = [
            "model",
            "instructions",
            "input",
            "tools",
            "max_output_tokens",
            "temperature",
            "top_p",
            "stream",
        ]
        .iter()
        .cloned()
        .collect();

        for (key, value) in obj.iter() {
            if !modeled_keys.contains(key.as_str()) {
                extra.insert(key.clone(), value.clone());
            }
        }

        if let Some(model_val) = obj.get("model") {
            extra.insert("model".to_string(), model_val.clone());
        }

        Ok(crate::ir::IrRequest {
            system: system_blocks,
            messages,
            tools,
            max_tokens,
            temperature,
            top_p,
            top_k: None,
            stop: vec![],
            stream,
            extra,
        })
    }

    fn read_response_event(
        &self,
        _event_type: &str,
        _data: &serde_json::Value,
    ) -> Option<IrStreamEvent> {
        None
    }

    fn read_response_events(
        &self,
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<IrStreamEvent> {
        let mut out: Vec<IrStreamEvent> = Vec::new();

        if !data.is_object() {
            return out;
        }

        match event_type {
            "response.created" | "response.in_progress" => {
                if !state.started {
                    state.started = true;
                    // Capture stream identity from the nested `response` object so a same-protocol
                    // passthrough preserves it. `created_at` is the Responses field name (mapped to
                    // the IR's `created`).
                    let resp = data.get("response");
                    let id = resp
                        .and_then(|r| r.get("id"))
                        .and_then(|i| i.as_str())
                        .map(String::from);
                    let created = resp
                        .and_then(|r| r.get("created_at"))
                        .and_then(|c| c.as_u64());
                    let model = resp
                        .and_then(|r| r.get("model"))
                        .and_then(|m| m.as_str())
                        .map(String::from);
                    out.push(IrStreamEvent::MessageStart {
                        role: crate::ir::IrRole::Assistant,
                        usage: None,
                        id,
                        created,
                        model,
                    });
                }
            }

            "response.output_item.added" => {
                if let Some(item_obj) = data.get("item") {
                    if item_obj.get("type").and_then(|t| t.as_str()) == Some("function_call") {
                        let call_id = item_obj
                            .get("call_id")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = item_obj
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        if let Some(output_index) =
                            data.get("output_index").and_then(|i| i.as_u64())
                        {
                            // Clamp the wire index before the cast: a crafted `u64::MAX` would
                            // otherwise feed the per-stream set and downstream index arithmetic
                            // unbounded. Saturate at MAX_OUTPUT_INDEX (mirrors openai.rs).
                            let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                            // Record the open tool index so the terminal `output_item.done` for
                            // this index closes the block EXACTLY once. Native Responses emits a
                            // single `output_item.done` per function-call item, so unlike text
                            // (which also gets a `content_part.done`) a tool index is closed by one
                            // event — tracking it here keeps the open/close pair balanced and lets
                            // the done arm distinguish a real open block from a duplicate close.
                            //
                            // Cap the distinct-index cardinality: a backend emitting a unique
                            // `output_index` per event must not grow `open_tools` without bound
                            // (a per-connection amplification DoS). Open a new block ONLY when the
                            // index is not already tracked AND there is room under the cap. An
                            // already-open index must NOT re-emit BlockStart — a second
                            // `output_item.added` for an open index would produce an invalid
                            // BlockStart→BlockStart→BlockStop sequence (a duplicate
                            // `content_block_start`), a deterministic proxy tell that corrupts a
                            // downstream writer's tool-call state. Beyond the cap a NEW index is
                            // silently skipped (no BlockStart), matching openai.rs.
                            let already_open = state.open_tools.contains(&idx);
                            if !already_open && state.open_tools.len() < MAX_OPEN_TOOLS {
                                state.open_tools.insert(idx);
                                out.push(IrStreamEvent::BlockStart {
                                    index: idx,
                                    block: crate::ir::IrBlockMeta::ToolUse { id: call_id, name },
                                });
                            }
                        }
                    } else if item_obj.get("type").and_then(|t| t.as_str()) == Some("message") {
                    }
                }
            }

            "response.output_text.delta" => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                // Drop empty keepalive deltas entirely: they neither open a block nor carry
                // content, so emitting a zero-length TextDelta would be spurious noise.
                if !delta.is_empty() {
                    // Use the wire `output_index` for BOTH the lazy BlockStart and the BlockDelta so
                    // the open/close pair stays index-matched even when the text part is not at
                    // index 0 (e.g. it follows a tool call at index 0).
                    let idx = data
                        .get("output_index")
                        .and_then(|i| i.as_u64())
                        .map_or(0, |v| (v as usize).min(MAX_OUTPUT_INDEX));
                    // Track open TEXT indices PER INDEX in `open_tools` under a disjoint key offset
                    // (see `TEXT_INDEX_KEY_OFFSET`) instead of the single index-blind
                    // `text_block_open` bool. A native stream can carry multiple message items, each
                    // at its own `output_index`; the per-index set opens a BlockStart lazily ONLY for
                    // an index not already open (so a second text item gets its own BlockStart rather
                    // than an orphan delta), and bounds cardinality under the same cap as tool items
                    // so a backend emitting a unique index per delta cannot grow the set without
                    // bound. Beyond the cap a new index streams no BlockStart/BlockDelta (matching
                    // the tool arm's suppression), never an orphan delta.
                    let text_key = idx + TEXT_INDEX_KEY_OFFSET;
                    let already_open = state.open_tools.contains(&text_key);
                    if !already_open {
                        if state.open_tools.len() >= MAX_OPEN_TOOLS {
                            // Cap reached: suppress this index entirely (no BlockStart, no orphan
                            // BlockDelta) rather than emitting a delta for an unopened block.
                            return out;
                        }
                        state.open_tools.insert(text_key);
                        out.push(IrStreamEvent::BlockStart {
                            index: idx,
                            block: crate::ir::IrBlockMeta::Text,
                        });
                    }
                    out.push(IrStreamEvent::BlockDelta {
                        index: idx,
                        delta: crate::ir::IrDelta::TextDelta(delta),
                    });
                }
            }

            "response.function_call_arguments.delta" => {
                let delta = data
                    .get("delta")
                    .and_then(|d| d.as_str())
                    .unwrap_or("")
                    .to_string();
                if !delta.is_empty() {
                    if let Some(output_index) = data.get("output_index").and_then(|i| i.as_u64()) {
                        let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                        // Route the argument delta ONLY to an index that actually emitted a
                        // BlockStart (tracked in `open_tools` by the `output_item.added` arm).
                        // An index suppressed by the cardinality cap — or an arguments-delta that
                        // arrives with no preceding `output_item.added` at all — has no open block,
                        // so a BlockDelta against it would be a tool-argument fragment for a block
                        // with no `content_block_start`: an invalid event sequence that breaks a
                        // strict SDK reassembling tool-call arguments and a distinguishability tell.
                        // Drop it (mirrors openai.rs's `state.open_tools.contains` guard).
                        if state.open_tools.contains(&idx) {
                            out.push(IrStreamEvent::BlockDelta {
                                index: idx,
                                delta: crate::ir::IrDelta::InputJsonDelta(delta),
                            });
                        }
                    }
                }
            }

            "response.output_item.done" | "response.content_part.done" => {
                if let Some(output_index) = data.get("output_index").and_then(|i| i.as_u64()) {
                    let idx = (output_index as usize).min(MAX_OUTPUT_INDEX);
                    // Native Responses closes a single text item with TWO terminal frames at the
                    // SAME `output_index`: `content_part.done` (the text content part) immediately
                    // followed by `output_item.done` (the enclosing message item). Emitting a
                    // BlockStop for BOTH produces a duplicate `content_block_stop` at one index for
                    // a block that opened once — an invalid event sequence and a distinguishability
                    // tell. So close a block EXACTLY once: only emit BlockStop for an index that is
                    // currently open, and clear the open marker so the second terminal frame at the
                    // same index is a no-op. A tool index (raw `idx`) and a text index (stored under
                    // `TEXT_INDEX_KEY_OFFSET`) are tracked PER INDEX in `open_tools`, so the close
                    // routes to the correct block kind AND the correct index — a native stream's two
                    // terminal frames for one text item (`content_part.done` then `output_item.done`,
                    // same index) close it exactly once because the second frame finds the key gone.
                    if state.open_tools.remove(&idx) {
                        // This index was a (now-closed) function-call item.
                        out.push(IrStreamEvent::BlockStop { index: idx });
                    } else if state.open_tools.remove(&(idx + TEXT_INDEX_KEY_OFFSET)) {
                        // This index was an open text block; close THIS index once. Removing the
                        // per-index key (rather than clearing a global bool) lets a different text
                        // index stay open and close on its own terminal frame, and makes the paired
                        // `content_part.done`/`output_item.done` for the same item a no-op the
                        // second time.
                        out.push(IrStreamEvent::BlockStop { index: idx });
                    }
                    // Otherwise nothing is open at this index (e.g. the second terminal frame of a
                    // text item, or a `done` for an item we never opened): emit nothing.
                }
            }

            "response.completed" | "response.failed" | "response.incomplete" => {
                if let Some(response_obj) = data.get("response") {
                    let status = response_obj
                        .get("status")
                        .and_then(|s| s.as_str())
                        .unwrap_or("");

                    // A genuinely failed terminal stream must NOT be decoded as a successful
                    // end_turn — that would mask the upstream failure from a downstream client
                    // (e.g. an Anthropic client would see stop_reason=end_turn). Surface it as an
                    // explicit IrStreamEvent::Error so the failure propagates, then still terminate
                    // the stream so consumers do not hang.
                    if status == "failed" {
                        let provider_signal = response_obj
                            .get("error")
                            .and_then(|e| e.get("code"))
                            .and_then(|c| c.as_str())
                            .or_else(|| {
                                response_obj
                                    .get("error")
                                    .and_then(|e| e.get("type"))
                                    .and_then(|t| t.as_str())
                            })
                            .map(String::from)
                            .or_else(|| Some("response_failed".to_string()));
                        out.push(IrStreamEvent::Error(IrError {
                            class: StatusClass::ServerError,
                            provider_signal,
                            retry_after: None,
                        }));
                        out.push(IrStreamEvent::MessageStop);
                        return out;
                    }

                    // Enumerate the recognized statuses rather than defaulting unknown ones to a
                    // successful end_turn. An unrecognized status is treated as a terminal stop
                    // with no specific reason (None) rather than silently claiming success.
                    let stop_reason = match status {
                        "completed" => Some("end_turn".to_string()),
                        "incomplete" => {
                            if let Some(incomplete_details) = response_obj.get("incomplete_details")
                            {
                                if let Some(reason) =
                                    incomplete_details.get("reason").and_then(|r| r.as_str())
                                {
                                    match reason {
                                        "max_output_tokens" => Some("max_tokens".to_string()),
                                        "content_filter" => Some("safety".to_string()),
                                        _ => Some(reason.to_string()),
                                    }
                                } else {
                                    Some("end_turn".to_string())
                                }
                            } else {
                                Some("end_turn".to_string())
                            }
                        }
                        "" => Some("end_turn".to_string()),
                        _ => None,
                    };

                    let usage = response_obj
                        .get("usage")
                        .map(|u| crate::ir::IrUsage {
                            input_tokens: u
                                .get("input_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            output_tokens: u
                                .get("output_tokens")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(0),
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        })
                        .unwrap_or(crate::ir::IrUsage {
                            input_tokens: 0,
                            output_tokens: 0,
                            cache_creation_input_tokens: None,
                            cache_read_input_tokens: None,
                        });

                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason,
                        // Responses API has no stop_sequence analog in its stream.
                        stop_sequence: None,
                        usage,
                    });
                    out.push(IrStreamEvent::MessageStop);
                } else if event_type == "response.failed" {
                    // Terminal failure event with no nested `response` object (e.g. a truncated SSE
                    // frame or a proxy that stripped the body). The wire `event_type` is the only
                    // failure signal available — honour it. Surfacing this as a successful end_turn
                    // would mask the upstream failure from downstream clients AND deny the breaker
                    // the failure signal, so we mirror the body-present failure arm above: emit an
                    // explicit Error followed by MessageStop.
                    out.push(IrStreamEvent::Error(IrError {
                        class: StatusClass::ServerError,
                        provider_signal: Some("response_failed".to_string()),
                        retry_after: None,
                    }));
                    out.push(IrStreamEvent::MessageStop);
                } else {
                    // Terminal completed/incomplete event with no nested `response` object. We must
                    // still terminate the translated stream with a MessageDelta + MessageStop so
                    // downstream consumers do not hang waiting for the end of the message.
                    let stop_reason = Some("end_turn".to_string());
                    let usage = crate::ir::IrUsage {
                        input_tokens: 0,
                        output_tokens: 0,
                        cache_creation_input_tokens: None,
                        cache_read_input_tokens: None,
                    };
                    out.push(IrStreamEvent::MessageDelta {
                        stop_reason,
                        stop_sequence: None,
                        usage,
                    });
                    out.push(IrStreamEvent::MessageStop);
                }
            }

            _ => {}
        }

        out
    }

    fn read_response(&self, body: &serde_json::Value) -> Result<crate::ir::IrResponse, IrError> {
        let obj = body.as_object().ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        })?;

        let status = obj.get("status").and_then(|s| s.as_str()).unwrap_or("");
        let mut stop_reason: Option<String> = match status {
            "completed" => Some("end_turn".to_string()),
            "incomplete" => {
                if let Some(incomplete_details) = obj.get("incomplete_details") {
                    if let Some(reason) = incomplete_details.get("reason").and_then(|r| r.as_str())
                    {
                        match reason {
                            "max_output_tokens" => Some("max_tokens".to_string()),
                            "content_filter" => Some("safety".to_string()),
                            _ => Some(reason.to_string()),
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            _ => None,
        };

        let mut content: Vec<crate::ir::IrBlock> = Vec::new();
        if let Some(output_arr) = obj.get("output").and_then(|o| o.as_array()) {
            for item in output_arr {
                let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");

                match item_type {
                    "message" => {
                        if let Some(content_arr) = item.get("content").and_then(|c| c.as_array()) {
                            for block_item in content_arr {
                                let block_type = block_item
                                    .get("type")
                                    .and_then(|t| t.as_str())
                                    .unwrap_or("");

                                if block_type == "output_text" {
                                    if let Some(text) =
                                        block_item.get("text").and_then(|t| t.as_str())
                                    {
                                        content.push(crate::ir::IrBlock::Text {
                                            text: text.to_string(),
                                            cache_control: None,
                                            citations: Vec::new(),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    "function_call" => {
                        let call_id = item
                            .get("call_id")
                            .and_then(|c| c.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = item
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let arguments = item
                            .get("arguments")
                            .and_then(|a| a.as_str())
                            .unwrap_or("{}");
                        // Preserve the raw string on malformed JSON rather than dropping the tool
                        // arguments to Null (mirrors the OpenAI reader; avoids lossy translation).
                        let input = serde_json::from_str(arguments)
                            .unwrap_or_else(|_| serde_json::Value::String(arguments.to_string()));

                        content.push(crate::ir::IrBlock::ToolUse {
                            id: call_id,
                            name,
                            input,
                        });
                    }

                    _ => {}
                }
            }
        } else if status == "failed" {
            // A non-streaming Responses body with `status:"failed"` legitimately carries
            // `output: null` (or omits it) and a populated top-level `error` object — this is an
            // upstream provider failure (rate_limit, content_filter, server_error, etc.), NOT a
            // parse failure. Surface it as a ServerError IrError carrying the upstream signal so the
            // real error reaches the client (and the breaker sees a failure) instead of masking it
            // as an internal `ir_parse`. Mirror the streaming `response.failed` arm: prefer the
            // `error.code` enum, fall back to `error.type`, then a generic `response_failed`.
            let provider_signal = obj
                .get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .or_else(|| {
                    obj.get("error")
                        .and_then(|e| e.get("type"))
                        .and_then(|t| t.as_str())
                })
                .map(String::from)
                .or_else(|| Some("response_failed".to_string()));
            return Err(IrError {
                class: StatusClass::ServerError,
                provider_signal,
                retry_after: None,
            });
        } else {
            return Err(IrError {
                class: StatusClass::ClientError,
                provider_signal: Some("ir_parse".to_string()),
                retry_after: None,
            });
        }

        if content
            .iter()
            .any(|b| matches!(b, crate::ir::IrBlock::ToolUse { .. }))
        {
            stop_reason = Some("tool_use".to_string());
        }

        let usage_val = obj.get("usage").ok_or(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".into()),
            retry_after: None,
        })?;

        let usage = crate::ir::IrUsage {
            input_tokens: usage_val
                .get("input_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            output_tokens: usage_val
                .get("output_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };

        let model = obj.get("model").and_then(|m| m.as_str()).map(String::from);

        // Capture the upstream response's identity so a same-protocol (responses → responses)
        // passthrough preserves `id`/`created_at` exactly. The Responses API names its creation
        // timestamp `created_at` (NOT `created`, which is the Chat Completions field); we map it
        // into the shared IR `created` slot. `system_fingerprint`/`stop_sequence` have no analog in
        // the Responses shape, so they stay `None`.
        let id = obj.get("id").and_then(|i| i.as_str()).map(String::from);
        let created = obj.get("created_at").and_then(|c| c.as_u64());

        Ok(crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content,
            stop_reason,
            usage,
            model,
            id,
            created,
            system_fingerprint: None,
            stop_sequence: None,
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolReader> {
        Box::new(self.clone())
    }
}

fn responses_block(block_val: &serde_json::Value) -> Result<crate::ir::IrBlock, IrError> {
    let obj = block_val.as_object().ok_or(IrError {
        class: StatusClass::ClientError,
        provider_signal: Some("ir_parse".to_string()),
        retry_after: None,
    })?;

    let block_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match block_type {
        "input_text" | "output_text" => {
            let text_val = obj.get("text");
            let text = text_val.and_then(|t| t.as_str()).unwrap_or("").to_string();
            Ok(crate::ir::IrBlock::Text {
                text,
                cache_control: None,
                citations: Vec::new(),
            })
        }
        "input_image" => {
            let image_url = obj.get("image_url").and_then(|v| v.as_str()).unwrap_or("");
            let (media_type, data) = parse_image_url(image_url);
            Ok(crate::ir::IrBlock::Image { media_type, data })
        }
        _ => Err(IrError {
            class: StatusClass::ClientError,
            provider_signal: Some("ir_parse".to_string()),
            retry_after: None,
        }),
    }
}

/// OpenAI Responses streaming writer.
///
/// EVERY native `/v1/responses` SSE event carries a top-level monotonically-increasing integer
/// `sequence_number` starting at 0 (a REQUIRED field on the official SDK's `Response*Event` types).
/// That counter is PER STREAM, not per process or per worker thread.
///
/// A previous revision kept the counter in thread-local storage, keyed implicitly by the Tokio
/// worker driving the stream. That is unsound on the multi-thread work-stealing runtime: two
/// concurrent streams scheduled on the same worker share one cell, and the second stream's opening
/// `response.created` (which resets the counter to 0) silently clobbers the first stream's in-flight
/// counter — producing non-monotonic `sequence_number`s that a native SDK rejects. The bleed is
/// invisible from any single stream's emitted JSON.
///
/// The counter therefore lives in per-stream INSTANCE state. `StreamTranslate::new` builds a FRESH
/// `Protocol::responses()` (hence a fresh `ResponsesWriter` with a zeroed counter) for each stream,
/// so the counter is stream-scoped by construction and the increments are plain `&self` atomics on
/// that one owned instance — no thread affinity, so the counter follows the stream across Tokio
/// worker migrations.
pub(crate) struct ResponsesWriter {
    /// Per-stream `sequence_number` counter. Reset to 0 on the stream's opening `MessageStart`
    /// (`response.created`) and advanced once per emitted event for the rest of the stream.
    /// `AtomicU64` (not `Cell`) so the writer stays `Sync` as the `ProtocolWriter` trait requires;
    /// the stream is single-threaded at any instant, so `Relaxed` ordering is sufficient.
    sequence: AtomicU64,
    /// Per-stream `response.id`. Captured on the opening `MessageStart` (the synthesized-or-
    /// forwarded id written into `response.created`) and replayed verbatim onto EVERY subsequent
    /// lifecycle event (`response.completed`/`response.incomplete`/`response.failed`). A native
    /// OpenAI Responses stream carries the SAME `id` on every event; the official SDK reads
    /// `event.response.id` on the terminal event to finalize and correlate the `Response`. Before
    /// this cell existed, `MessageDelta`/`Error` each minted a FRESH `resp_` id, so on any
    /// cross-protocol stream (where the IR strips identity) the terminal event's id differed from
    /// `response.created` — an SDK-breaking correctness failure and a hard distinguishability tell.
    /// Per-stream INSTANCE state for the same reason as `sequence` (see the type doc); a poisoned
    /// lock degrades to the synthesize-fresh fallback rather than panicking on the request path.
    response_id: std::sync::Mutex<Option<String>>,
    /// Per-stream `response.created_at` (unix seconds). Captured on the opening `MessageStart`
    /// (`response.created`) and replayed verbatim onto EVERY subsequent lifecycle event
    /// (`response.completed`/`response.incomplete`/`response.failed`). A native OpenAI Responses
    /// stream carries the SAME `created_at` on every event for a given response. Before this cell
    /// existed, the terminal `MessageDelta` (and error) events each called `now_unix_secs()`
    /// directly, so on any stream where the opening event's `created_at` came from upstream IR — or
    /// merely a wall-clock instant earlier than the terminal event — the terminal `created_at`
    /// differed from `response.created`'s, a detectable proxy tell that breaks SDK consumers
    /// comparing timestamps across events. Per-stream INSTANCE state for the same reason as
    /// `response_id`; a poisoned lock degrades to the synthesize-fresh (`now_unix_secs`) fallback
    /// rather than panicking on the request path.
    created_at: std::sync::Mutex<Option<u64>>,
    /// Per-stream `response.model`. Captured on the opening `MessageStart` (the model written into
    /// `response.created`, after the DEFAULT_MODEL fallback) and replayed verbatim onto EVERY
    /// subsequent lifecycle event (`response.completed`/`response.incomplete`/`response.failed`). A
    /// native OpenAI Responses stream carries the SAME `model` on the full `Response` object of
    /// every event, and the official SDK types `Response.model` as a REQUIRED non-nullable string —
    /// so a terminal event whose inner `response` omits `model` fails a strict decoder and is a
    /// distinguishability tell. The IR `MessageDelta`/`Error` events carry no model, so the terminal
    /// arms replay this captured value (falling back to DEFAULT_MODEL only if the cell was never
    /// populated). Per-stream INSTANCE state for the same reason as `response_id`/`created_at`; a
    /// poisoned lock degrades to the DEFAULT_MODEL fallback rather than panicking on the request path.
    model: std::sync::Mutex<Option<String>>,
    /// Output indices for which this writer emitted a function-call `output_item.added`. The IR
    /// `BlockStop` carries only the integer index (no block kind), but a native Responses stream
    /// emits `output_item.done` ONLY for items it previously `added` — and the Text `BlockStart`
    /// arm emits no `added` (so a text block has no `output_item.added`/`.done` pair at all). Track
    /// the tool-call opens here so `BlockStop` emits `output_item.done` for a function-call index
    /// only, never for a text index. Without this a text block's BlockStop emitted a spurious
    /// `output_item.done` with `type:"function_call"` for an item that was never opened — an
    /// unmatched lifecycle event and a hard distinguishability tell. Per-stream INSTANCE state for
    /// the same reason as `sequence` (see the type doc); `Relaxed`-equivalent `Mutex` access is
    /// fine since a stream is single-threaded at any instant and the writer must stay `Sync`.
    open_tool_indices: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    /// Output indices for which this writer opened a TEXT message item (emitted
    /// `output_item.added` type "message" + `content_part.added`). A native /v1/responses stream
    /// ALWAYS brackets a text part with the full lifecycle
    /// `output_item.added(message) → content_part.added → output_text.delta* → output_text.done →
    /// content_part.done → output_item.done`; the official SDK builds `response.output[]` from the
    /// added/done pair, so a stream of orphan `output_text.delta` frames leaves the assembled
    /// Response with an empty output array. The IR `BlockStop` carries only the index, so track the
    /// open text indices here (the same way `open_tool_indices` tracks tool items) so the matching
    /// BlockStop emits the text terminal frames for THIS index only. Per-stream INSTANCE state for
    /// the same reason as the other fields; a poisoned lock degrades safely.
    open_text_indices: std::sync::Mutex<std::collections::BTreeSet<usize>>,
    /// Per-stream cache of synthesized opaque `item_id`s, keyed by `(kind-prefix, output_index)`.
    /// A native /v1/responses stream carries a CONSTANT `item_id` across the
    /// `output_item.added → delta* → output_item.done` lifecycle of one output item; the official
    /// SDK correlates that lifecycle by the shared id. The IR block events carry only the integer
    /// `output_index`, so the writer mints the id — but it must be STABLE per `(prefix, index)` for
    /// the duration of the stream, while still being an opaque CSPRNG token (not the old sequential
    /// `msg_00000000` hex, whose positional structure fingerprinted a proxied response). This cache
    /// gives both: the first reference to a `(prefix, index)` mints a fresh opaque id; every later
    /// reference within the stream returns the same one. Per-stream INSTANCE state for the same
    /// reason as the other fields; a poisoned lock degrades to a freshly-minted id (still opaque,
    /// still valid) rather than panicking on the request path.
    item_ids: std::sync::Mutex<std::collections::BTreeMap<(&'static str, usize), String>>,
    /// Per-stream accumulator of function-call item fields, keyed by `output_index`. A native
    /// /v1/responses stream's `response.output_item.done` for a function-call item carries the FULLY
    /// finalized item — `call_id`, `name`, AND the complete accumulated `arguments` string — and the
    /// official SDK reads `event.item.arguments`/`.name`/`.call_id` off the `done` event to
    /// reconstruct the tool invocation. The IR `BlockStop` carries only the integer index, so the
    /// writer must accumulate those fields across the lifecycle: `call_id`+`name` arrive on the
    /// `BlockStart` (`IrBlockMeta::ToolUse`), and `arguments` is concatenated from the
    /// `InputJsonDelta` fragments on each `BlockDelta`. Without this the `output_item.done` item was
    /// `{"type":"function_call","id":…}` — missing `call_id`/`name`/`arguments`, an
    /// impossible-from-real-OpenAI shape that breaks SDK tool-call handling and is a
    /// distinguishability tell. Per-stream INSTANCE state for the same reason as the other fields; a
    /// poisoned lock degrades to omitting the accumulated fields (still emits the `done`) rather than
    /// panicking on the request path.
    tool_calls: std::sync::Mutex<std::collections::BTreeMap<usize, ToolCallAccum>>,
    /// Per-stream accumulator of streamed assistant TEXT, keyed by `output_index`. A native
    /// /v1/responses terminal `response.completed`/`response.incomplete` event carries the FULLY
    /// assembled `output[]` array, and a message item in it carries its `output_text` parts with the
    /// complete text the stream delivered via `output_text.delta`. The IR streams text only as
    /// `TextDelta` fragments, so the writer concatenates them here as they arrive and drains the
    /// joined text into the terminal `output` message item at BlockStop. Per-stream INSTANCE state
    /// for the same reason as the other fields; a poisoned lock degrades to omitting the accumulated
    /// text (the item then carries empty text) rather than panicking on the request path.
    text_accum: std::sync::Mutex<std::collections::BTreeMap<usize, String>>,
    /// Per-stream buffer of FINALIZED `output[]` items, keyed by `output_index` so the terminal
    /// event emits them in stable index order. A native /v1/responses `response.completed`/
    /// `response.incomplete` event's inner `response.output` is the fully assembled array (each
    /// `message` item with its `output_text` parts, each finalized `function_call` item) — the
    /// official SDK reads `event.response.output` to materialize the final `Response.output`. The IR
    /// `MessageDelta` carries no assembled output, but the writer has already seen every delta, so it
    /// records each item here as the matching `BlockStop` finalizes it and drains the map into the
    /// terminal `response.output`. Before this, the terminal `output` was hard-coded to `[]` even
    /// though real text/tool items streamed — an empty `output` with nonzero `usage.output_tokens`
    /// is a shape real OpenAI never emits and breaks SDK consumers that read the assembled output off
    /// the completed event. Per-stream INSTANCE state for the same reason as the other fields; a
    /// poisoned lock degrades to an empty array (the prior behavior) rather than panicking.
    output_items: std::sync::Mutex<std::collections::BTreeMap<usize, serde_json::Value>>,
}

/// Accumulated function-call item fields for one open `output_index`, finalized into the
/// `response.output_item.done` `item` object. `call_id`/`name` are captured from the opening
/// `BlockStart`; `arguments` is built by concatenating the streamed `InputJsonDelta` fragments.
#[derive(Clone, Default)]
struct ToolCallAccum {
    call_id: String,
    name: String,
    arguments: String,
}

/// Value-namespace constructor for [`ResponsesWriter`]. A `const` and a struct may share a name
/// (they live in the value and type namespaces respectively), so `Protocol::responses()` can keep
/// writing the bare `ResponsesWriter` literal while the type now carries per-stream state. Each
/// USE of the const inlines a fresh `ResponsesWriter { sequence: AtomicU64::new(0) }`, so every
/// `Protocol::responses()` call mints an independent zeroed counter — exactly the per-stream
/// scoping the `sequence_number` contract needs. `AtomicU64::new` is a const fn, so this is valid
/// in const context (an `Arc` counter would not be).
///
/// `clippy::declare_interior_mutable_const` warns that a `const` with interior mutability is
/// inlined per use rather than shared. That per-use fresh instance is PRECISELY the semantics we
/// need: a `static` would share ONE counter across every stream in the process — reintroducing the
/// cross-stream `sequence_number` bleed this change exists to fix. So the lint's suggestion is
/// wrong for this site and is suppressed deliberately.
#[allow(non_upper_case_globals)]
#[allow(clippy::declare_interior_mutable_const)]
pub(crate) const ResponsesWriter: ResponsesWriter = ResponsesWriter {
    sequence: AtomicU64::new(0),
    response_id: std::sync::Mutex::new(None),
    created_at: std::sync::Mutex::new(None),
    model: std::sync::Mutex::new(None),
    open_tool_indices: std::sync::Mutex::new(std::collections::BTreeSet::new()),
    open_text_indices: std::sync::Mutex::new(std::collections::BTreeSet::new()),
    item_ids: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    tool_calls: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    text_accum: std::sync::Mutex::new(std::collections::BTreeMap::new()),
    output_items: std::sync::Mutex::new(std::collections::BTreeMap::new()),
};

impl Clone for ResponsesWriter {
    fn clone(&self) -> Self {
        // Preserve the current counter value on clone so a `Protocol::clone` mid-stream keeps the
        // same `sequence_number` position rather than resetting to 0. The open-tool-index set is
        // likewise carried across the clone so a mid-stream `Protocol::clone` keeps the in-flight
        // function-call lifecycle correlation; a poisoned lock degrades to an empty set rather than
        // panicking on the request path.
        ResponsesWriter {
            sequence: AtomicU64::new(self.sequence.load(Ordering::Relaxed)),
            response_id: std::sync::Mutex::new(
                self.response_id.lock().map(|id| id.clone()).unwrap_or(None),
            ),
            // Carry the captured `created_at` across a mid-stream `Protocol::clone` so the cloned
            // writer's terminal events replay the SAME timestamp; a poisoned lock degrades to None
            // (terminal arm then falls back to `now_unix_secs`).
            created_at: std::sync::Mutex::new(self.created_at.lock().map(|c| *c).unwrap_or(None)),
            // Carry the captured `model` across a mid-stream `Protocol::clone` so the cloned
            // writer's terminal events replay the SAME model; a poisoned lock degrades to None
            // (terminal arm then falls back to DEFAULT_MODEL).
            model: std::sync::Mutex::new(self.model.lock().map(|m| m.clone()).unwrap_or(None)),
            open_tool_indices: std::sync::Mutex::new(
                self.open_tool_indices
                    .lock()
                    .map(|set| set.clone())
                    .unwrap_or_default(),
            ),
            open_text_indices: std::sync::Mutex::new(
                self.open_text_indices
                    .lock()
                    .map(|set| set.clone())
                    .unwrap_or_default(),
            ),
            // Carry the minted `item_id` cache across a mid-stream `Protocol::clone` so the cloned
            // writer keeps emitting the SAME opaque id for an already-opened item's remaining
            // lifecycle frames; a poisoned lock degrades to an empty cache (later refs re-mint).
            item_ids: std::sync::Mutex::new(
                self.item_ids.lock().map(|m| m.clone()).unwrap_or_default(),
            ),
            // Carry the in-flight function-call field accumulator across a mid-stream
            // `Protocol::clone` so the cloned writer's `output_item.done` still emits the complete
            // finalized item (call_id/name/accumulated arguments); a poisoned lock degrades to an
            // empty map (the done then omits the accumulated fields).
            tool_calls: std::sync::Mutex::new(
                self.tool_calls
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_default(),
            ),
            // Carry the in-flight text accumulator across a mid-stream `Protocol::clone` so the
            // cloned writer's terminal `output` still assembles the full streamed text; a poisoned
            // lock degrades to an empty map.
            text_accum: std::sync::Mutex::new(
                self.text_accum
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_default(),
            ),
            // Carry the finalized-output buffer across a mid-stream `Protocol::clone` so the cloned
            // writer's terminal event still emits the assembled `output[]`; a poisoned lock degrades
            // to an empty map (terminal `output` then falls back to `[]`).
            output_items: std::sync::Mutex::new(
                self.output_items
                    .lock()
                    .map(|m| m.clone())
                    .unwrap_or_default(),
            ),
        }
    }
}

impl ResponsesWriter {
    /// Reset the per-stream `sequence_number` counter to 0. Called when the stream's opening
    /// `response.created` event is written so every stream's sequence starts from 0. The reader
    /// gates `MessageStart` on `state.started`, so exactly one reset happens per stream. The
    /// open-tool-index set is also cleared so a reused/cloned writer does not carry a stale
    /// function-call index into a fresh stream.
    fn reset_sequence_number(&self) {
        self.sequence.store(0, Ordering::Relaxed);
        if let Ok(mut set) = self.open_tool_indices.lock() {
            set.clear();
        }
        if let Ok(mut set) = self.open_text_indices.lock() {
            set.clear();
        }
        // Clear the per-stream `item_id` cache so a reused/cloned writer mints fresh opaque ids for
        // the new stream rather than replaying a previous stream's item ids.
        if let Ok(mut map) = self.item_ids.lock() {
            map.clear();
        }
        // Clear the per-stream function-call field accumulator so a reused/cloned writer does not
        // carry a previous stream's call_id/name/arguments into a new stream's `output_item.done`.
        if let Ok(mut map) = self.tool_calls.lock() {
            map.clear();
        }
        // Clear the per-stream text accumulator and the finalized-output buffer so a reused/cloned
        // writer does not leak a previous stream's text/items into a new stream's terminal `output`.
        if let Ok(mut map) = self.text_accum.lock() {
            map.clear();
        }
        if let Ok(mut map) = self.output_items.lock() {
            map.clear();
        }
        // Clear the carried `response.id` alongside the sequence counter: a reused/cloned writer
        // must not leak a previous stream's id onto a new stream's terminal events. The new id is
        // stored when this stream's `MessageStart` is written.
        if let Ok(mut id) = self.response_id.lock() {
            *id = None;
        }
        // Clear the carried `created_at` alongside the id: a reused/cloned writer must not leak a
        // previous stream's creation timestamp onto a new stream's terminal events. The new value
        // is stored when this stream's `MessageStart` is written.
        if let Ok(mut created) = self.created_at.lock() {
            *created = None;
        }
        // Clear the carried `model` alongside the id/created_at: a reused/cloned writer must not
        // leak a previous stream's model onto a new stream's terminal events. The new value is
        // stored when this stream's `MessageStart` is written.
        if let Ok(mut model) = self.model.lock() {
            *model = None;
        }
    }

    /// Store the per-stream `response.id` captured on `MessageStart` so terminal events replay it
    /// verbatim. Lock poisoning degrades to a no-op (the terminal arm then synthesizes a fresh id)
    /// rather than panicking on the request path.
    fn set_response_id(&self, id: &str) {
        if let Ok(mut slot) = self.response_id.lock() {
            *slot = Some(id.to_string());
        }
    }

    /// Return the per-stream `response.id` captured on `MessageStart`, or `None` if it was never
    /// set (a malformed stream whose terminal event preceded `MessageStart`, or a poisoned lock).
    /// The caller falls back to synthesizing a fresh id in that case.
    fn carried_response_id(&self) -> Option<String> {
        self.response_id.lock().ok().and_then(|id| id.clone())
    }

    /// Store the per-stream `created_at` captured on `MessageStart` so terminal events replay it
    /// verbatim. Lock poisoning degrades to a no-op (the terminal arm then falls back to
    /// `now_unix_secs`) rather than panicking on the request path.
    fn set_created_at(&self, created_at: u64) {
        if let Ok(mut slot) = self.created_at.lock() {
            *slot = Some(created_at);
        }
    }

    /// Return the per-stream `created_at` captured on `MessageStart`, falling back to the current
    /// unix time if it was never set (a malformed stream whose terminal event preceded
    /// `MessageStart`, or a poisoned lock). Replaying the captured value keeps every event's
    /// `created_at` identical, matching a native Responses stream.
    fn carried_created_at(&self) -> u64 {
        self.created_at
            .lock()
            .ok()
            .and_then(|c| *c)
            .unwrap_or_else(now_unix_secs)
    }

    /// Store the per-stream `model` captured on `MessageStart` so terminal events replay it
    /// verbatim. Lock poisoning degrades to a no-op (the terminal arm then falls back to
    /// `DEFAULT_MODEL`) rather than panicking on the request path.
    fn set_model(&self, model: &str) {
        if let Ok(mut slot) = self.model.lock() {
            *slot = Some(model.to_string());
        }
    }

    /// Return the per-stream `model` captured on `MessageStart`, falling back to `DEFAULT_MODEL` if
    /// it was never set (a malformed stream whose terminal event preceded `MessageStart`, or a
    /// poisoned lock). Replaying the captured value keeps every event's `model` identical and
    /// non-null, matching a native Responses stream and the SDK's required-field contract.
    fn carried_model(&self) -> String {
        self.model
            .lock()
            .ok()
            .and_then(|m| m.clone())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string())
    }

    /// Return the next `sequence_number` for this stream and advance the counter. The first call
    /// after a [`Self::reset_sequence_number`] returns 0, the next 1, and so on — matching the
    /// native monotonic-from-0 contract.
    fn next_sequence_number(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    /// Record that a function-call `output_item.added` was emitted at `index`, so the matching
    /// `BlockStop` knows to emit `output_item.done` for it. Lock poisoning degrades to a no-op
    /// rather than panicking on the request path.
    fn mark_tool_open(&self, index: usize) {
        if let Ok(mut set) = self.open_tool_indices.lock() {
            set.insert(index);
        }
    }

    /// Return true and forget `index` if it was a previously-opened function-call item; false if no
    /// function-call item was opened at `index` (e.g. a text block, whose `BlockStop` must NOT emit
    /// `output_item.done`). Lock poisoning degrades to `false` (suppress the `done`) rather than
    /// panicking on the request path.
    fn take_tool_open(&self, index: usize) -> bool {
        self.open_tool_indices
            .lock()
            .map(|mut set| set.remove(&index))
            .unwrap_or(false)
    }

    /// Record the `call_id`/`name` for a function-call item opened at `index`, captured from the
    /// `BlockStart`'s `IrBlockMeta::ToolUse`, so the matching `output_item.done` can emit the fully
    /// finalized item. Lock poisoning degrades to a no-op (the `done` then omits these fields)
    /// rather than panicking on the request path.
    fn record_tool_meta(&self, index: usize, call_id: &str, name: &str) {
        if let Ok(mut map) = self.tool_calls.lock() {
            let entry = map.entry(index).or_default();
            entry.call_id = call_id.to_string();
            entry.name = name.to_string();
        }
    }

    /// Append a streamed `arguments` fragment for the function-call item at `index`. Native
    /// `response.output_item.done` carries the COMPLETE accumulated arguments string, so the writer
    /// concatenates the `InputJsonDelta` fragments here. Lock poisoning degrades to a no-op.
    fn append_tool_arguments(&self, index: usize, fragment: &str) {
        if let Ok(mut map) = self.tool_calls.lock() {
            map.entry(index).or_default().arguments.push_str(fragment);
        }
    }

    /// Remove and return the accumulated function-call fields for `index` (call_id, name, fully
    /// accumulated arguments) so the matching `output_item.done` emits the finalized item. Returns
    /// `None` if nothing was accumulated (e.g. a poisoned lock); the caller then emits the `done`
    /// without the accumulated fields rather than panicking on the request path.
    fn take_tool_accum(&self, index: usize) -> Option<ToolCallAccum> {
        self.tool_calls
            .lock()
            .ok()
            .and_then(|mut map| map.remove(&index))
    }

    /// Append a streamed text fragment for the message item at `index`. The native terminal
    /// `response.output` carries the COMPLETE assembled text per message item, so the writer
    /// concatenates the `TextDelta` fragments here. Lock poisoning degrades to a no-op (the terminal
    /// item then carries empty text) rather than panicking on the request path.
    fn append_text(&self, index: usize, fragment: &str) {
        if let Ok(mut map) = self.text_accum.lock() {
            map.entry(index).or_default().push_str(fragment);
        }
    }

    /// Remove and return the accumulated text for the message item at `index`. Returns an empty
    /// string if nothing was accumulated (a text block with no deltas, or a poisoned lock).
    fn take_text_accum(&self, index: usize) -> String {
        self.text_accum
            .lock()
            .ok()
            .and_then(|mut map| map.remove(&index))
            .unwrap_or_default()
    }

    /// Record a FINALIZED `output[]` item at `index`, captured as the matching `BlockStop`
    /// assembles it, so the terminal `response.completed`/`response.incomplete` event can emit the
    /// fully assembled `output` array (keyed by index for stable order). Lock poisoning degrades to
    /// a no-op (that item is omitted from the terminal `output`) rather than panicking.
    fn record_output_item(&self, index: usize, item: serde_json::Value) {
        if let Ok(mut map) = self.output_items.lock() {
            map.insert(index, item);
        }
    }

    /// Drain the finalized `output[]` items into an index-ordered array for the terminal event.
    /// `BTreeMap` iteration is key-ordered, so the items come out in `output_index` order, matching
    /// the order a native /v1/responses stream assembled them. A poisoned lock degrades to an empty
    /// array (the prior `[]` behavior) rather than panicking on the request path.
    fn drain_output_items(&self) -> Vec<serde_json::Value> {
        self.output_items
            .lock()
            .map(|mut map| std::mem::take(&mut *map).into_values().collect())
            .unwrap_or_default()
    }

    /// Mark a TEXT message item open at `index` IF it is not already open and there is room under
    /// the cardinality cap, returning true when this call performed the open (so the caller emits
    /// the opening `output_item.added`/`content_part.added` frames exactly once). Returns false if
    /// the index was already open (a subsequent text delta — no re-open) or the cap is reached
    /// (skip the frames; bounds per-stream memory against a pathological backend). Lock poisoning
    /// degrades to false. Mirrors the cardinality discipline of the reader's `open_tools` cap.
    fn open_text_item(&self, index: usize) -> bool {
        self.open_text_indices
            .lock()
            .map(|mut set| {
                if set.contains(&index) {
                    return false;
                }
                if set.len() >= MAX_OPEN_TOOLS {
                    return false;
                }
                set.insert(index);
                true
            })
            .unwrap_or(false)
    }

    /// Return true and forget `index` if a TEXT message item was open at it (so the matching
    /// `BlockStop` emits the text terminal frames for THIS index only). Returns false for a
    /// non-text index. Lock poisoning degrades to false.
    fn take_text_open(&self, index: usize) -> bool {
        self.open_text_indices
            .lock()
            .map(|mut set| set.remove(&index))
            .unwrap_or(false)
    }

    /// Return the stream-stable opaque `item_id` for the output item identified by
    /// `(prefix, index)`, minting a fresh CSPRNG-backed token on first reference and returning the
    /// cached one thereafter. This is what keeps the `output_item.added → delta* → output_item.done`
    /// frames of a single item sharing one `item_id` (the SDK's lifecycle-correlation key) while the
    /// id itself stays opaque — no positional/sequential structure for an observer to fingerprint.
    /// A poisoned lock degrades to a freshly-minted opaque id (still structurally native, just not
    /// cached) rather than panicking on the request path.
    fn item_id_for(&self, prefix: &'static str, index: usize) -> String {
        match self.item_ids.lock() {
            Ok(mut map) => map
                .entry((prefix, index))
                .or_insert_with(|| synthesize_item_id(prefix))
                .clone(),
            Err(_) => synthesize_item_id(prefix),
        }
    }
}

impl ProtocolWriter for ResponsesWriter {
    fn upstream_path(&self) -> &str {
        "/v1/responses"
    }

    fn auth_headers(&self, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        vec![(
            HeaderName::from_static("authorization"),
            HeaderValue::from_str(&format!("Bearer {key}"))
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        )]
    }

    fn rewrite_model(&self, body: &mut serde_json::Value, model: &str) {
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::json!(model));
        }
    }

    fn write_request(&self, req: &crate::ir::IrRequest) -> serde_json::Value {
        let mut out = serde_json::Map::new();

        if !req.system.is_empty() {
            let instructions: String = req
                .system
                .iter()
                .filter_map(|block| match block {
                    crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n");
            if !instructions.is_empty() {
                out.insert("instructions".to_string(), serde_json::json!(instructions));
            }
        }

        let mut input_arr: Vec<serde_json::Value> = Vec::new();
        for msg in &req.messages {
            match msg.role {
                crate::ir::IrRole::User | crate::ir::IrRole::Assistant => {
                    let role_str = if msg.role == crate::ir::IrRole::User {
                        "user"
                    } else {
                        "assistant"
                    };

                    let mut content_arr: Vec<serde_json::Value> = Vec::new();
                    // function_call / function_call_output items are flat top-level `input`
                    // entries in the Responses API, NOT nested inside a message's `content`.
                    // Collect them separately so the enclosing assistant `message` is emitted
                    // FIRST (and only when it actually has content), with the tool items appended
                    // after it in order — matching the conversation order the assistant produced.
                    let mut tool_items: Vec<serde_json::Value> = Vec::new();
                    for block in &msg.content {
                        match block {
                            crate::ir::IrBlock::Text { text, .. } => {
                                let type_str = if msg.role == crate::ir::IrRole::User {
                                    "input_text"
                                } else {
                                    "output_text"
                                };
                                content_arr.push(serde_json::json!({
                                    "type": type_str,
                                    "text": text
                                }));
                            }
                            crate::ir::IrBlock::Image { media_type, data } => {
                                // Reconstruct the original `image_url`: a URL-sentinel image is
                                // emitted verbatim, a base64 image is re-wrapped as a data URI. This
                                // is the inverse of `parse_image_url` so a same-protocol round-trip
                                // is lossless.
                                let image_url = image_url_from_ir(media_type, data);
                                content_arr.push(serde_json::json!({
                                    "type": "input_image",
                                    "image_url": image_url
                                }));
                            }
                            crate::ir::IrBlock::ToolUse { id, name, input } => {
                                let args_str = serde_json::to_string(input)
                                    .unwrap_or_else(|_| "{}".to_string());
                                tool_items.push(serde_json::json!({
                                    "type": "function_call",
                                    "call_id": id,
                                    "name": name,
                                    "arguments": args_str
                                }));
                            }
                            crate::ir::IrBlock::ToolResult {
                                tool_use_id,
                                content,
                                is_error: _,
                            } => {
                                let output_text = content
                                    .iter()
                                    .filter_map(|b| match b {
                                        crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                        _ => None,
                                    })
                                    .collect::<Vec<_>>()
                                    .join(" ");

                                tool_items.push(serde_json::json!({
                                    "type": "function_call_output",
                                    "call_id": tool_use_id,
                                    "output": output_text
                                }));
                            }
                            crate::ir::IrBlock::Thinking { .. } => {}
                        }
                    }

                    // Emit the assistant/user `message` wrapper only when it carries content. A
                    // turn that is purely a tool call must NOT produce a spurious
                    // `{role, content: []}` item — the Responses API rejects empty-content
                    // message items.
                    if !content_arr.is_empty() {
                        let mut msg_obj = serde_json::Map::new();
                        msg_obj.insert("role".to_string(), serde_json::json!(role_str));
                        msg_obj
                            .insert("content".to_string(), serde_json::Value::Array(content_arr));
                        input_arr.push(serde_json::Value::Object(msg_obj));
                    }
                    // Then the flat tool items, in order, AFTER the message they belong to.
                    input_arr.extend(tool_items);
                }

                crate::ir::IrRole::Tool => {
                    for block in &msg.content {
                        if let crate::ir::IrBlock::ToolResult {
                            tool_use_id,
                            content,
                            is_error: _,
                        } = block
                        {
                            let output_text = content
                                .iter()
                                .filter_map(|b| match b {
                                    crate::ir::IrBlock::Text { text, .. } => Some(text.clone()),
                                    _ => None,
                                })
                                .collect::<Vec<_>>()
                                .join(" ");

                            input_arr.push(serde_json::json!({
                                "type": "function_call_output",
                                "call_id": tool_use_id,
                                "output": output_text
                            }));
                        }
                    }
                }

                crate::ir::IrRole::System => {}
            }
        }

        if !input_arr.is_empty() {
            out.insert("input".to_string(), serde_json::Value::Array(input_arr));
        }

        if !req.tools.is_empty() {
            let mut tools_arr: Vec<serde_json::Value> = Vec::new();
            for tool in &req.tools {
                let mut tool_obj = serde_json::Map::new();
                tool_obj.insert("type".to_string(), serde_json::json!("function"));
                tool_obj.insert("name".to_string(), serde_json::json!(tool.name));

                if let Some(desc) = &tool.description {
                    tool_obj.insert("description".to_string(), serde_json::json!(desc));
                }

                let params = if !tool.input_schema.is_null() {
                    tool.input_schema.clone()
                } else {
                    serde_json::json!({})
                };
                tool_obj.insert("parameters".to_string(), params);

                tools_arr.push(serde_json::Value::Object(tool_obj));
            }
            out.insert("tools".to_string(), serde_json::Value::Array(tools_arr));
        }

        if let Some(max_tokens) = req.max_tokens {
            out.insert(
                "max_output_tokens".to_string(),
                serde_json::json!(max_tokens),
            );
        }

        if let Some(temperature) = req.temperature {
            out.insert("temperature".to_string(), serde_json::json!(temperature));
        }
        // Promoted sampling control: the Responses API supports `top_p` (but no top_k / stop), so
        // only top_p is emitted. A cross-protocol source's top_k/stop have no Responses target and
        // are dropped (documented in the reader).
        if let Some(top_p) = req.top_p {
            out.insert("top_p".to_string(), serde_json::json!(top_p));
        }

        // `stream` is a modeled key (excluded from `extra`), so it must be emitted explicitly or it
        // is silently dropped — a `stream: true` request would otherwise be answered non-streaming,
        // stalling the SSE translation loop. Mirrors the OpenAI writer.
        out.insert("stream".to_string(), serde_json::json!(req.stream));

        for (key, value) in &req.extra {
            out.insert(key.clone(), value.clone());
        }

        serde_json::Value::Object(out)
    }

    fn write_response_event(&self, ev: &IrStreamEvent) -> Option<(String, serde_json::Value)> {
        // The stream's opening event resets the per-stream `sequence_number` counter so each stream's
        // sequence starts at 0. Every event this writer emits then carries a top-level
        // `sequence_number` injected just before return (see the closing `map` below). The reader
        // gates `MessageStart` on `state.started`, so exactly one reset happens per stream.
        if matches!(ev, IrStreamEvent::MessageStart { .. }) {
            self.reset_sequence_number();
        }

        let emitted: Option<(String, serde_json::Value)> = match ev {
            IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                // The official OpenAI Responses SDK reads `response.id`/`created_at`/`model` from the
                // opening `response.created` event to construct its Response object; a stub omitting
                // them yields null identity fields and breaks event correlation. Forward the captured
                // identity when present (same-protocol passthrough), otherwise synthesize a
                // protocol-correct `resp_` id and the current unix time (cross-protocol, where
                // `translate_event` strips these to None) so the event stays SDK-valid.
                let mut resp_obj = serde_json::Map::new();
                let id = id.clone().unwrap_or_else(synthesize_response_id);
                // Carry this stream's id forward so the terminal events (and any failure) replay
                // the SAME `response.id` — a native stream never changes its id mid-flight.
                self.set_response_id(&id);
                let created_at = created.unwrap_or_else(now_unix_secs);
                // Carry this stream's `created_at` forward so the terminal events (and any failure)
                // replay the SAME timestamp — a native stream's `created_at` is constant across
                // every event.
                self.set_created_at(created_at);
                resp_obj.insert("id".to_string(), serde_json::json!(id));
                resp_obj.insert("object".to_string(), serde_json::json!("response"));
                resp_obj.insert("created_at".to_string(), serde_json::json!(created_at));
                resp_obj.insert("status".to_string(), serde_json::json!("in_progress"));
                // `Response.model` is a REQUIRED non-nullable string in the official SDK; emit it
                // unconditionally with the DEFAULT_MODEL fallback when the IR carries none (a
                // cross-protocol stream where `translate_event` strips the model to None) rather
                // than omitting the key — omission breaks strict decoders and is a proxy tell.
                let model_name = model.as_deref().unwrap_or(DEFAULT_MODEL);
                // Carry this stream's model forward so the terminal events (and any failure) replay
                // the SAME `model` — a native stream's `model` is constant across every event.
                self.set_model(model_name);
                resp_obj.insert("model".to_string(), serde_json::json!(model_name));
                // The native `response.created` carries the FULL Response skeleton, not just its
                // identity: an official SDK constructs a `Response` object from this event and reads
                // `usage`/`output`/`error` unconditionally. At stream start there are no tokens yet
                // and no failure, so emit `usage: null`, an empty `output` array, and `error: null`
                // — present-but-empty, NOT omitted. Omitting `usage` left the SDK's `Response.usage`
                // unpopulated (or crashed strict decoders) on the opening chunk.
                resp_obj.insert("output".to_string(), serde_json::json!([]));
                resp_obj.insert("error".to_string(), serde_json::Value::Null);
                resp_obj.insert("usage".to_string(), serde_json::Value::Null);
                Some((
                    "response.created".to_string(),
                    serde_json::json!({ "type": "response.created", "response": resp_obj }),
                ))
            }

            IrStreamEvent::BlockStart { index, block } => match block {
                crate::ir::IrBlockMeta::Text => {
                    // A native /v1/responses stream brackets a text part inside a `message` output
                    // item: `output_item.added(message)` opens it, the `output_text.delta`s carry
                    // the body, and `output_item.done(message)` closes it. The official SDK builds
                    // `response.output[]` from the added/done pair, so without an enclosing item the
                    // assembled Response has an empty output array even though deltas streamed.
                    // Previously the Text BlockStart returned None, leaving the deltas orphaned.
                    //
                    // The `ProtocolWriter` trait emits at most ONE wire frame per IR event, so the
                    // intermediate `content_part.added` sub-frame (which would need a second frame
                    // for this single BlockStart) cannot be produced here; the message item's
                    // `output_item.added`/`.done` pair is the load-bearing lifecycle the SDK reads
                    // to materialize the assistant message, and the deltas already carry
                    // `content_index: 0`. Track the open text index (capped) so the matching
                    // BlockStop emits `output_item.done` for THIS index only.
                    if !self.open_text_item(*index) {
                        return None;
                    }
                    let item_id = self.item_id_for("msg", *index);
                    Some((
                        "response.output_item.added".to_string(),
                        serde_json::json!({
                            "type": "response.output_item.added",
                            "output_index": index,
                            "item_id": item_id,
                            "item": {
                                "type": "message",
                                "id": item_id,
                                "role": "assistant",
                                "status": "in_progress",
                                "content": []
                            }
                        }),
                    ))
                }
                crate::ir::IrBlockMeta::ToolUse { id, name } => {
                    // `item_id` (a stable per-output-item id, `fc_…` for a function-call item) is
                    // carried on the native `output_item.added`/`.done` pair so a client correlates the
                    // item's lifecycle. Synthesize it deterministically from the output index so the
                    // matching `.done` (which sees only the index) reconstructs the same id.
                    let item_id = self.item_id_for("fc", *index);
                    // Record the open function-call index so the matching `BlockStop` emits
                    // `output_item.done` for THIS index only — a text block's BlockStop (whose
                    // BlockStart produced no `output_item.added`) must emit no `done`.
                    self.mark_tool_open(*index);
                    // Capture call_id/name now so the matching `output_item.done` can emit the
                    // fully finalized item (native `done` carries call_id/name/arguments; the IR
                    // BlockStop carries only the index).
                    self.record_tool_meta(*index, id, name);
                    Some((
                        "response.output_item.added".to_string(),
                        serde_json::json!({
                            "type": "response.output_item.added",
                            "output_index": index,
                            "item_id": item_id,
                            "item": {
                                "type": "function_call",
                                "id": item_id,
                                "call_id": id,
                                "name": name
                            }
                        }),
                    ))
                }
                crate::ir::IrBlockMeta::Thinking | crate::ir::IrBlockMeta::Image => None,
            },

            IrStreamEvent::BlockDelta { index, delta } => match delta {
                crate::ir::IrDelta::TextDelta(text) if !text.is_empty() => {
                    // Native `output_text.delta` carries `item_id` (the enclosing message item) and
                    // `content_index` (the index of the text part within that item). The IR delta
                    // carries only the output index; synthesize the message `item_id` deterministically
                    // from it (matching the `msg_…` part), and emit `content_index: 0` — the single
                    // text content part of the item.
                    //
                    // Accumulate the fragment so the matching `BlockStop` can assemble the message
                    // item with its COMPLETE `output_text` for the terminal `response.output` array.
                    self.append_text(*index, text);
                    Some((
                        "response.output_text.delta".to_string(),
                        serde_json::json!({
                            "type": "response.output_text.delta",
                            "output_index": index,
                            "item_id": self.item_id_for("msg", *index),
                            "content_index": 0,
                            "delta": text
                        }),
                    ))
                }
                crate::ir::IrDelta::InputJsonDelta(json_str) => {
                    // Accumulate the arguments fragment so the matching `output_item.done` emits the
                    // COMPLETE arguments string the native event (and the SDK's `event.item.arguments`)
                    // carries.
                    self.append_tool_arguments(*index, json_str);
                    Some((
                        "response.function_call_arguments.delta".to_string(),
                        serde_json::json!({
                            "type": "response.function_call_arguments.delta",
                            "output_index": index,
                            "item_id": self.item_id_for("fc", *index),
                            "delta": json_str
                        }),
                    ))
                }
                &crate::ir::IrDelta::TextDelta(_) => None,
                crate::ir::IrDelta::ThinkingDelta(_) | crate::ir::IrDelta::SignatureDelta(_) => {
                    None
                }
            },

            IrStreamEvent::BlockStop { index } => {
                // The IR `BlockStop` carries only the integer output index, not the block kind. A
                // native Responses stream emits `response.output_item.done` ONLY for an item it
                // previously `output_item.added` — and this writer emits `output_item.added` solely
                // for function-call items (the Text `BlockStart` arm returns `None`, so a text part
                // has NO `output_item.added`/`.done` pair; its content-part lifecycle is closed by
                // the upstream `content_part.done`/`output_text.done` frames the reader already
                // collapsed). Emitting `output_item.done` unconditionally — as a prior revision did
                // — produced, for every text block, an `output_item.done` with
                // `type:"function_call"` for an item that was never opened: an unmatched lifecycle
                // event (a `done` with no prior `added`) AND a text response mis-typed as a
                // function call, both of which break a typed Responses SDK and are deterministic
                // distinguishability tells.
                //
                // So consult the per-stream open sets: a function-call index closes with an
                // `output_item.done` typed "function_call"; a text index (opened by the Text
                // BlockStart with `output_item.added` typed "message") closes with an
                // `output_item.done` typed "message"; any other (never-opened) index emits NOTHING.
                //
                // NOTE: this arm must YIELD its `Option` as the match value (never `return` it), so
                // the closing `emitted.map(...)` tail injects the top-level `sequence_number` every
                // native Responses event carries — an early `return Some(..)` would skip it.
                if self.take_tool_open(*index) {
                    // Native `response.output_item.done` carries the SAME stable `item_id` as the
                    // matching `output_item.added` (so a client correlates the `added → done`
                    // lifecycle) plus the FULLY finalized `item` object: a typed SDK reads
                    // `event.item.call_id`/`.name`/`.arguments` off the done event to reconstruct the
                    // tool invocation. Emit all three from the per-stream accumulator (call_id/name
                    // captured on `output_item.added`, arguments concatenated from the delta frames).
                    // The function-call `output_item.added` used `item_id_for("fc", index)`, so the
                    // cached id reconstructs the matching pair here. A poisoned-lock-empty accumulator
                    // degrades to empty-string fields rather than panicking.
                    let item_id = self.item_id_for("fc", *index);
                    let accum = self.take_tool_accum(*index).unwrap_or_default();
                    let item = serde_json::json!({
                        "type": "function_call",
                        "id": item_id,
                        "call_id": accum.call_id,
                        "name": accum.name,
                        "arguments": accum.arguments,
                    });
                    // Record the finalized function-call item so the terminal `response.completed`/
                    // `response.incomplete` event emits the fully assembled `output[]` array (the
                    // SDK reads `event.response.output` to materialize `Response.output`).
                    self.record_output_item(*index, item.clone());
                    Some((
                        "response.output_item.done".to_string(),
                        serde_json::json!({
                            "type": "response.output_item.done",
                            "output_index": index,
                            "item_id": item_id,
                            "item": item,
                        }),
                    ))
                } else if self.take_text_open(*index) {
                    // Close the message item opened by the Text BlockStart. The same cached `msg_…`
                    // id (also carried on every `output_text.delta`) reconstructs the matching
                    // `added → done` pair the SDK uses to finalize `response.output[]`. The native
                    // `output_item.done` for a message item carries the assembled `output_text`
                    // content part with the COMPLETE text the deltas delivered (the SDK accumulates
                    // `Response.output_text` from it), so emit the accumulated text rather than an
                    // empty content array.
                    let item_id = self.item_id_for("msg", *index);
                    let text = self.take_text_accum(*index);
                    let item = serde_json::json!({
                        "type": "message",
                        "id": item_id,
                        "role": "assistant",
                        "status": "completed",
                        "content": [
                            { "type": "output_text", "text": text, "annotations": [] }
                        ]
                    });
                    // Record the finalized message item so the terminal event emits the fully
                    // assembled `output[]` array.
                    self.record_output_item(*index, item.clone());
                    Some((
                        "response.output_item.done".to_string(),
                        serde_json::json!({
                            "type": "response.output_item.done",
                            "output_index": index,
                            "item_id": item_id,
                            "item": item,
                        }),
                    ))
                } else {
                    // Nothing open at this index (e.g. a repeated BlockStop, or an index whose
                    // BlockStart was suppressed by the cardinality cap): emit no frame.
                    None
                }
            }

            IrStreamEvent::MessageDelta {
                stop_reason,
                usage,
                stop_sequence: _,
            } => {
                // Map IR stop reasons to Responses statuses. An unknown/None reason defaults to
                // `completed` (the safe choice) rather than `failed`: a future IR reason (e.g. a
                // new `refusal`) that did NOT explicitly signal an error must not be misclassified
                // as a failed response, which would trigger client-side error handling for a
                // successful turn. Genuine failures arrive via IrStreamEvent::Error, not here.
                let status = match stop_reason.as_deref() {
                    Some("tool_use") | Some("end_turn") | Some("stop_sequence") => "completed",
                    Some("max_tokens") => "incomplete",
                    Some("safety") => "incomplete",
                    _ => "completed",
                };

                let mut resp_obj = serde_json::Map::new();
                // The native `response.completed`/`response.incomplete` terminal event ALWAYS
                // carries `id` (a `resp_…` string) and `created_at` (unix seconds) in its inner
                // `response` object; the official Python/Node SDK reads `event.response.id` on the
                // terminal event to finalize the `Response`, and strict typed decoders raise on a
                // missing `id`/`created_at`. A real OpenAI stream never sends a terminal event
                // without an `id`, so omitting it is also a distinguishability tell. The IR
                // `MessageDelta` carries no identity, so REPLAY the id captured on this stream's
                // opening `MessageStart` (stored in `response_id`) so `response.completed`/
                // `response.incomplete` carries the SAME `id` as `response.created` — a native
                // stream never changes its id mid-flight, and the SDK reads `event.response.id` on
                // the terminal event to finalize the `Response`. Only if the cell is unexpectedly
                // empty (a malformed stream whose terminal event preceded `MessageStart`, or a
                // poisoned lock) do we fall back to synthesizing a fresh id so the event stays
                // structurally valid.
                let response_id = self
                    .carried_response_id()
                    .unwrap_or_else(synthesize_response_id);
                resp_obj.insert("id".to_string(), serde_json::json!(response_id));
                resp_obj.insert("object".to_string(), serde_json::json!("response"));
                // Replay the `created_at` captured on this stream's opening `MessageStart` so the
                // terminal event carries the SAME timestamp as `response.created`. The IR
                // `MessageDelta` carries no identity, so a direct `now_unix_secs()` here would emit
                // a later wall-clock value than the opening event — a detectable proxy tell. Fall
                // back to the current time only if the cell was never populated.
                resp_obj.insert(
                    "created_at".to_string(),
                    serde_json::json!(self.carried_created_at()),
                );
                resp_obj.insert("status".to_string(), serde_json::json!(status));
                // Replay the `model` captured on this stream's opening `MessageStart` so the
                // terminal event's inner `response` carries the SAME required non-nullable `model`
                // as `response.created`. The IR `MessageDelta` carries no model, and omitting it
                // fails a strict SDK decoder and is a distinguishability tell; `carried_model`
                // falls back to DEFAULT_MODEL only if the cell was never populated.
                resp_obj.insert("model".to_string(), serde_json::json!(self.carried_model()));

                if status == "incomplete" {
                    let reason = match stop_reason.as_deref() {
                        Some("max_tokens") => "max_output_tokens",
                        Some("safety") => "content_filter",
                        _ => "other",
                    };
                    let mut incomplete_details = serde_json::Map::new();
                    incomplete_details.insert("reason".to_string(), serde_json::json!(reason));
                    resp_obj.insert(
                        "incomplete_details".to_string(),
                        serde_json::Value::Object(incomplete_details),
                    );
                }

                let mut usage_map = serde_json::Map::new();
                usage_map.insert(
                    "input_tokens".to_string(),
                    serde_json::json!(usage.input_tokens),
                );
                usage_map.insert(
                    "output_tokens".to_string(),
                    serde_json::json!(usage.output_tokens),
                );
                resp_obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
                // The native terminal `response.completed`/`response.incomplete` event carries the
                // FULLY assembled inner `response` object: the official Python/Node SDK reads
                // `event.response.output` to finalize the assembled `Response`, and `output` is a
                // REQUIRED field a strict typed decoder raises on when absent. The writer recorded
                // each finalized item (message text parts and function-call items) into
                // `output_items` as the matching `BlockStop` fired, so drain that index-ordered
                // buffer here — a `completed` response with nonzero `usage.output_tokens` but an
                // EMPTY `output` is a shape real OpenAI never emits and breaks SDK consumers that
                // read the assembled output off the completed event. The buffer is empty (yielding
                // `[]`) only for a genuinely output-less turn or a poisoned lock. `error` is
                // likewise REQUIRED and `null` on a non-failed terminal event (a genuine failure
                // arrives via IrStreamEvent::Error → `response.failed`, never this arm).
                resp_obj.insert(
                    "output".to_string(),
                    serde_json::Value::Array(self.drain_output_items()),
                );
                resp_obj.insert("error".to_string(), serde_json::Value::Null);

                // The terminal event's NAME and inner `type` MUST agree with the inner
                // `response.status`: a native /v1/responses stream emits `response.completed` for a
                // completed response and a DISTINCT `response.incomplete` for a truncated/safety-
                // stopped one, and the official Python/Node SDKs dispatch on the event `type`
                // (`ResponseCompletedEvent` vs `ResponseIncompleteEvent`). Emitting a
                // `response.completed` envelope around an inner `status:"incomplete"` (plus
                // `incomplete_details`) is a shape impossible from real OpenAI and mislabels a
                // max_tokens-truncated or safety-stopped generation to the client. So select the
                // envelope from `status`. `status` is only ever `completed`/`incomplete` here
                // (genuine failures arrive via IrStreamEvent::Error → `response.failed`, never this
                // arm); the match is over those two with a defensive fallback to `completed` for any
                // future status string, never a `response.failed` (which would invent a failure).
                let (event_name, event_type) = match status {
                    "incomplete" => ("response.incomplete", "response.incomplete"),
                    "completed" => ("response.completed", "response.completed"),
                    _ => ("response.completed", "response.completed"),
                };
                Some((
                    event_name.to_string(),
                    serde_json::json!({ "type": event_type, "response": resp_obj }),
                ))
            }

            IrStreamEvent::MessageStop => None,

            IrStreamEvent::Error(err) => {
                // The native OpenAI Responses `response.failed` event wraps the error inside a
                // `response` object (`{"response":{"id":...,"status":"failed","error":{...}}}`); the
                // official Python/Node streaming decoder reads `event.response` to build the failed
                // Response, NOT a top-level `error` key. Emitting `{"error":{...}}` would leave a
                // native SDK unable to locate `event.response` and it would crash or silently
                // swallow the failure. Synthesize a `resp_` id so the SDK can correlate the failed
                // response.
                //
                // The in-band `response.error` object is the Responses-native `ResponseError` shape
                // — `{"code": <non-null string enum>, "message": <str>}` — NOT the Chat-Completions
                // `{message, type, code, param}` envelope. The official Python/Node SDK decodes
                // `event.response.error` into a typed `ResponseError` whose `code` is a required
                // non-null enum (default `"server_error"`); emitting a null `code` plus an extra
                // `type`/`param` pair is an impossible-from-real-OpenAI shape and a deterministic
                // indistinguishability tell. This protocol's OWN reader confirms the field choice:
                // it reads `response.error.code` FIRST (canonical) and only falls back to `type`.
                let message = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "error".to_string());
                // Use the carried provider signal as the error code enum when present (so a
                // same-protocol round-trip preserves the upstream `code`), defaulting to the
                // canonical `"server_error"` enum — never null.
                let code = err
                    .provider_signal
                    .clone()
                    .unwrap_or_else(|| "server_error".to_string());
                // Replay the stream's captured `response.id` so `response.failed` correlates with
                // the opening `response.created` (the SDK reads `event.response.id` on the failure
                // event); fall back to a fresh id only if the cell is empty (failure before any
                // `MessageStart`, or a poisoned lock).
                let response_id = self
                    .carried_response_id()
                    .unwrap_or_else(synthesize_response_id);
                Some((
                    "response.failed".to_string(),
                    serde_json::json!({
                        "type": "response.failed",
                        "response": {
                            "id": response_id,
                            "object": "response",
                            // Replay the captured `created_at` so `response.failed` carries the
                            // SAME timestamp as `response.created` (a native stream never changes
                            // it mid-flight); falls back to the current time only if the failure
                            // preceded any `MessageStart`.
                            "created_at": self.carried_created_at(),
                            // Replay the captured `model` so `response.failed`'s inner `response`
                            // carries the SAME required non-nullable `model` as `response.created`;
                            // falls back to DEFAULT_MODEL only if the failure preceded any
                            // `MessageStart`.
                            "model": self.carried_model(),
                            "status": "failed",
                            // A native terminal event's inner `response` always carries `output`
                            // (REQUIRED by the SDK's typed `Response`); a failed response produced
                            // no assistant items, so emit a present-but-empty array — never omit it.
                            "output": [],
                            "error": {
                                "code": code,
                                "message": message,
                            }
                        }
                    }),
                ))
            }
        };

        // EVERY native `/v1/responses` SSE event carries a top-level `sequence_number` (monotonic
        // from 0 per stream). Inject it uniformly here so no writer arm can forget it and so the
        // counter advances exactly once per emitted event. Events that produce no body
        // (`MessageStop`, empty text deltas, Text/Thinking/Image `BlockStart`) do NOT consume a
        // sequence number — only events that actually go on the wire are numbered, matching the
        // native stream where the integer counts emitted events.
        emitted.map(|(event_name, mut data)| {
            if let Some(obj) = data.as_object_mut() {
                obj.insert(
                    "sequence_number".to_string(),
                    serde_json::json!(self.next_sequence_number()),
                );
            }
            (event_name, data)
        })
    }

    fn write_response(&self, resp: &crate::ir::IrResponse) -> serde_json::Value {
        // Unknown/None stop reasons default to `completed` (not `failed`): a future IR reason that
        // did not explicitly signal an error must not surface as a failed response to a Responses
        // client. Only the explicitly-mapped incomplete reasons downgrade the status.
        let status = match resp.stop_reason.as_deref() {
            Some("tool_use") | Some("end_turn") | Some("stop_sequence") => "completed",
            Some("max_tokens") => "incomplete",
            Some("safety") => "incomplete",
            _ => "completed",
        };

        let mut output_arr: Vec<serde_json::Value> = Vec::new();

        let mut text_blocks: Vec<&str> = Vec::new();
        for block in &resp.content {
            match block {
                crate::ir::IrBlock::Text { text, .. } => {
                    if !text.is_empty() {
                        text_blocks.push(text);
                    }
                }
                crate::ir::IrBlock::ToolUse { id, name, input } => {
                    let args_str =
                        serde_json::to_string(input).unwrap_or_else(|_| "{}".to_string());
                    output_arr.push(serde_json::json!({
                        "type": "function_call",
                        "call_id": id,
                        "name": name,
                        "arguments": args_str
                    }));
                }
                crate::ir::IrBlock::Thinking { .. } => {}
                // ToolResult and Image have no representation in a Responses API `output` array
                // (output carries assistant `message`/`function_call` items only), so they are
                // intentionally dropped here. Enumerated explicitly rather than swallowed by a
                // catch-all so a future IrBlock variant forces a compile error instead of silently
                // vanishing from Responses output.
                crate::ir::IrBlock::ToolResult { .. } => {}
                crate::ir::IrBlock::Image { .. } => {}
            }
        }

        if !text_blocks.is_empty() {
            let text_content = text_blocks.join("");
            output_arr.insert(
                0,
                serde_json::json!({
                    "type": "message",
                    "role": "assistant",
                    "content": [{
                        "type": "output_text",
                        "text": text_content
                    }]
                }),
            );
        }

        let mut usage_map = serde_json::Map::new();
        usage_map.insert(
            "input_tokens".to_string(),
            serde_json::json!(resp.usage.input_tokens),
        );
        usage_map.insert(
            "output_tokens".to_string(),
            serde_json::json!(resp.usage.output_tokens),
        );

        let mut obj = serde_json::Map::new();
        // Emit the SDK-required top-level identity. Same-protocol passthrough carries the captured
        // upstream values verbatim; cross-protocol (backend supplied none) synthesizes a
        // protocol-correct `resp_` id and the current unix time so the body stays SDK-valid.
        // `created_at` is the Responses field name (the official SDK's `Response.created_at`).
        let id = resp.id.clone().unwrap_or_else(synthesize_response_id);
        let created_at = resp.created.unwrap_or_else(now_unix_secs);
        obj.insert("id".to_string(), serde_json::json!(id));
        obj.insert("object".to_string(), serde_json::json!("response"));
        obj.insert("created_at".to_string(), serde_json::json!(created_at));
        obj.insert("status".to_string(), serde_json::json!(status));
        // model that served the response (preserved across cross-protocol translation). The
        // official SDK types `Response.model` as a REQUIRED non-nullable string, so emit it
        // unconditionally with the DEFAULT_MODEL fallback when the IR carries none rather than
        // omitting the key — omission breaks strict decoders and is a distinguishability tell.
        obj.insert(
            "model".to_string(),
            serde_json::json!(resp.model.as_deref().unwrap_or(DEFAULT_MODEL)),
        );
        obj.insert("output".to_string(), serde_json::Value::Array(output_arr));
        obj.insert("usage".to_string(), serde_json::Value::Object(usage_map));
        // The official SDK types `Response.error` as a REQUIRED nullable field present on EVERY
        // Response object: `null` on success/incomplete, a populated object on failure. The
        // streaming `response.created` skeleton already emits `error: null`; the non-streaming body
        // must match. Omitting the key breaks strict SDK/Pydantic/Zod decoders that read
        // `response.error` unconditionally and is a distinguishability tell (a real non-streaming
        // `/v1/responses` body always carries `error`). A genuine upstream failure is surfaced as
        // an error envelope via `write_error`, never through this success/incomplete body, so `null`
        // is correct here.
        obj.insert("error".to_string(), serde_json::Value::Null);

        if status == "incomplete" {
            let reason = match resp.stop_reason.as_deref() {
                Some("max_tokens") => "max_output_tokens",
                Some("safety") => "content_filter",
                _ => "other",
            };
            let mut incomplete_details = serde_json::Map::new();
            incomplete_details.insert("reason".to_string(), serde_json::json!(reason));
            obj.insert(
                "incomplete_details".to_string(),
                serde_json::Value::Object(incomplete_details),
            );
        }

        serde_json::Value::Object(obj)
    }

    /// Native OpenAI Responses error envelope. The Responses API shares the OpenAI error shape an
    /// official SDK (`openai` Python / `openai-node`) decodes into a typed `APIError`:
    /// `{"error":{"message":<msg>,"type":<type>,"code":<code|null>,"param":<param|null>}}`, served
    /// as `application/json`. `code` and `param` are always present (null here — busbar's
    /// router/auth/forward errors are not field-level validation errors). The generic `kind` is
    /// mapped to the Responses `type` vocabulary where one exists.
    fn write_error(&self, _status: u16, kind: &str, message: &str) -> serde_json::Value {
        // Map busbar's generic error `kind` to the OpenAI/Responses `error.type` vocabulary. The
        // canonical Responses/OpenAI types are `invalid_request_error`, `authentication_error`,
        // `permission_error`, `not_found_error`, `rate_limit_error`, `server_error`, and
        // `insufficient_quota`. Anything already in that vocabulary (or any unrecognized caller
        // string) is passed through verbatim rather than swallowed by a catch-all, so a precise
        // upstream type is never lost.
        let error_type = match kind {
            "invalid_request" | "invalid_request_error" => "invalid_request_error",
            "authentication" | "authentication_error" | "auth" => "authentication_error",
            "permission" | "permission_error" | "forbidden" => "permission_error",
            "not_found" | "not_found_error" => "not_found_error",
            "rate_limit" | "rate_limit_error" => "rate_limit_error",
            "server_error" | "internal" | "internal_error" => "server_error",
            // A 503 exhaustion/timeout is reported by forward.rs as kind `"overloaded"` (an
            // Anthropic-vocabulary token). The OpenAI/Responses error vocabulary has no
            // `overloaded` type — a 5xx is `server_error` — so without this arm `other => other`
            // would leak `{"error":{"type":"overloaded",...}}` to an OpenAI-family client on every
            // exhaustion/timeout, a non-native type and a deterministic cross-protocol tell. Map the
            // overloaded/unavailable family onto the native `server_error`. Same class as the OpenAI
            // writer's 5xx bucket.
            "overloaded" | "overloaded_error" | "service_unavailable" | "unavailable" => {
                "server_error"
            }
            // forward.rs emits these transient/upstream-failure kinds directly to every ingress
            // writer (`timeout`/`network`/`connect` from the request-error path, `5xx`/`transient`
            // from the canonical-signal mapping, `api_error` from the generic upstream-error path).
            // None is an OpenAI/Responses error type — real OpenAI reports a transient upstream
            // failure as `server_error` — so without these arms `other => other` would leak a
            // non-native `type` such as `{"error":{"type":"timeout"}}` or `{"error":{"type":"5xx"}}`
            // to a Responses-API client: a deterministic cross-protocol tell that breaks SDK
            // consumers switching on `error.type`. Mirrors openai.rs's `server_error` bucket.
            "timeout" | "network" | "connect" | "5xx" | "transient" | "api_error" => "server_error",
            // A context-length overflow is surfaced by forward.rs as `context_length_exceeded`; the
            // Responses vocabulary has no dedicated type for it (as openai.rs also maps it), so it
            // folds into `invalid_request_error`. `bad_request` is the same client-error class.
            "context_length_exceeded" | "bad_request" => "invalid_request_error",
            "billing" | "insufficient_quota" => "insufficient_quota",
            other => other,
        };

        serde_json::json!({
            "error": {
                "message": message,
                "type": error_type,
                "code": responses_error_code(error_type),
                "param": serde_json::Value::Null,
            }
        })
    }

    fn clone_box(&self) -> Box<dyn ProtocolWriter> {
        Box::new(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_request() {
        let ir = crate::ir::IrRequest {
            system: vec![crate::ir::IrBlock::Text {
                text: "You are helpful.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "hi".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::ToolUse {
                        id: "fc_1".to_string(),
                        name: "get_weather".to_string(),
                        input: serde_json::json!({"city": "SF"}),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Tool,
                    content: vec![crate::ir::IrBlock::ToolResult {
                        tool_use_id: "fc_1".to_string(),
                        content: vec![crate::ir::IrBlock::Text {
                            text: "sunny".to_string(),
                            cache_control: None,
                            citations: Vec::new(),
                        }],
                        is_error: false,
                    }],
                },
            ],
            tools: vec![crate::ir::IrTool {
                name: "get_weather".to_string(),
                description: Some("Get weather for a location".to_string()),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {"city": {"type": "string"}},
                    "required": ["city"]
                }),
            }],
            max_tokens: Some(1024),
            temperature: Some(0.7),
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };

        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);

        assert_eq!(
            json.get("instructions").and_then(|v| v.as_str()),
            Some("You are helpful.")
        );

        let input = json
            .get("input")
            .and_then(|v| v.as_array())
            .expect("input should exist");

        let first_item = &input[0];
        assert_eq!(
            first_item.get("role").and_then(|r| r.as_str()),
            Some("user")
        );
        let content = first_item
            .get("content")
            .and_then(|c| c.as_array())
            .expect("content should exist");
        assert_eq!(content.len(), 1);
        assert_eq!(
            content[0].get("type"),
            Some(&serde_json::json!("input_text"))
        );
        assert_eq!(content[0].get("text").and_then(|t| t.as_str()), Some("hi"));

        let func_call_item = input
            .iter()
            .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("function_call"))
            .expect("should have function_call item");
        assert_eq!(
            func_call_item.get("name").and_then(|n| n.as_str()),
            Some("get_weather")
        );
        let args = func_call_item
            .get("arguments")
            .and_then(|a| a.as_str())
            .expect("arguments should exist");
        assert!(args.contains("SF") || args.contains("city"));

        let func_output_item = input
            .iter()
            .find(|item| item.get("type").and_then(|t| t.as_str()) == Some("function_call_output"))
            .expect("should have function_call_output item");
        assert_eq!(
            func_output_item.get("call_id").and_then(|c| c.as_str()),
            Some("fc_1")
        );
        let output = func_output_item
            .get("output")
            .and_then(|o| o.as_str())
            .expect("output should exist");
        assert_eq!(output, "sunny");

        let tools = json
            .get("tools")
            .and_then(|v| v.as_array())
            .expect("tools should exist");
        assert_eq!(tools.len(), 1);
        let tool_obj = &tools[0];
        assert_eq!(tool_obj.get("type"), Some(&serde_json::json!("function")));
        assert_eq!(
            tool_obj.get("name").and_then(|n| n.as_str()),
            Some("get_weather")
        );
        assert!(
            tool_obj.get("function").is_none(),
            "tools should be flattened"
        );

        assert_eq!(
            json.get("max_output_tokens"),
            Some(&serde_json::json!(1024))
        );
        assert_eq!(json.get("temperature"), Some(&serde_json::json!(0.7)));
    }

    #[test]
    fn test_read_request() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "instructions": "You are helpful.",
            "input": [
                {"role": "user", "content": [{"type": "input_text", "text": "What's the weather?"}]},
                {"role": "assistant", "content": [{"type": "output_text", "text": "Let me check that for you."}]},
                {"type": "function_call", "call_id": "fc_1", "name": "get_weather", "arguments": "{\"city\":\"SF\"}"},
                {"type": "function_call_output", "call_id": "fc_1", "output": "Sunny, 72F"}
            ],
            "tools": [{"type": "function", "name": "get_weather", "description": "Get weather for a location", "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}],
            "max_output_tokens": 1024,
            "temperature": 0.7
        });

        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");

        assert_eq!(ir.system.len(), 1);
        if let crate::ir::IrBlock::Text { text, .. } = &ir.system[0] {
            assert_eq!(text, "You are helpful.");
        } else {
            panic!("system should be Text block");
        }

        // 2 role/content messages + function_call -> assistant + function_call_output -> tool
        assert_eq!(ir.messages.len(), 4);

        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        if let crate::ir::IrBlock::Text { text, .. } = &ir.messages[0].content[0] {
            assert_eq!(text, "What's the weather?");
        } else {
            panic!("first message should be Text block");
        }

        assert_eq!(ir.max_tokens, Some(1024));
        assert_eq!(ir.temperature, Some(0.7_f64));

        assert_eq!(ir.tools.len(), 1);
        let tool = &ir.tools[0];
        assert_eq!(tool.name, "get_weather");
    }

    #[test]
    fn test_roundtrip_identity() {
        let ir = crate::ir::IrRequest {
            system: vec![crate::ir::IrBlock::Text {
                text: "You are helpful.".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            messages: vec![
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::User,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "Hello!".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
                crate::ir::IrMessage {
                    role: crate::ir::IrRole::Assistant,
                    content: vec![crate::ir::IrBlock::Text {
                        text: "Hi there!".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    }],
                },
            ],
            tools: Vec::new(),
            max_tokens: Some(500),
            temperature: Some(0.7),
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };

        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let json = writer.write_request(&ir);
        let rt_ir = reader
            .read_request(&json)
            .expect("read round-trip should succeed");

        assert_eq!(ir, rt_ir);
    }

    #[test]
    fn test_temperature_fidelity() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "test"}]}],
            "temperature": 0.7,
            "max_output_tokens": 1024
        });

        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");

        assert_eq!(ir.temperature, Some(0.7_f64));
    }

    #[test]
    fn test_auth_headers() {
        let writer = ResponsesWriter;
        let headers = writer.auth_headers("sk-test");

        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0.as_str(), "authorization");
        assert_eq!(headers[0].1.to_str().unwrap(), "Bearer sk-test");
    }

    #[test]
    fn test_read_response_decode() {
        let json = serde_json::json!({
            "id": "resp_1",
            "object": "response",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "The weather in SF is sunny."}]
                },
                {
                    "type": "function_call",
                    "call_id": "fc_1",
                    "name": "get_weather",
                    "arguments": "{\"city\":\"SF\"}"
                }
            ],
            "usage": {"input_tokens": 50, "output_tokens": 25}
        });

        let reader = ResponsesReader;
        let resp = reader
            .read_response(&json)
            .expect("read_response should succeed");

        assert_eq!(resp.content.len(), 2);
        match &resp.content[0] {
            crate::ir::IrBlock::Text { text, .. } => {
                assert_eq!(text, "The weather in SF is sunny.")
            }
            _ => panic!("first block should be Text"),
        }
        match &resp.content[1] {
            crate::ir::IrBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "fc_1");
                assert_eq!(name, "get_weather");
                assert_eq!(input.get("city").and_then(|v| v.as_str()), Some("SF"));
            }
            _ => panic!("second block should be ToolUse"),
        }

        assert_eq!(resp.stop_reason, Some("tool_use".to_string()));
        assert_eq!(resp.usage.input_tokens, 50);
        assert_eq!(resp.usage.output_tokens, 25);
    }

    #[test]
    fn test_write_response_roundtrip_text_only() {
        // Carries `id`/`created_at` so same-protocol read→write is byte-identical: the writer now
        // always emits the SDK-required top-level identity, and a native response carries both.
        // Carries `model` too: a native completed response always carries the required
        // non-nullable `model`, and the writer now always re-emits it, so the round-trip stays
        // byte-identical only when the source includes it.
        // Carries `error: null` too: a native non-streaming response always includes the required
        // nullable `error` field (null on success), and the writer now always re-emits it, so the
        // round-trip stays byte-identical only when the source includes it.
        let json = serde_json::json!({
            "id": "resp_abc123",
            "object": "response",
            "created_at": 1_700_000_000_u64,
            "status": "completed",
            "model": "gpt-4o",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "Hello world"}]
                }
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5},
            "error": serde_json::Value::Null
        });

        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let ir_resp = reader.read_response(&json).expect("read should succeed");
        let roundtrip_json = writer.write_response(&ir_resp);

        assert_eq!(roundtrip_json, json);
    }

    /// The native Responses error envelope an official SDK decodes: a JSON object whose `error`
    /// carries `message`, a Responses-vocabulary `type`, and `code`/`param` keys (null here).
    #[test]
    fn test_write_error_native_responses_envelope() {
        let writer = ResponsesWriter;
        let v = writer.write_error(404, "not_found", "model 'x' not found");

        // Round-trips as JSON without panic.
        let serialized = serde_json::to_string(&v).expect("write_error output must serialize");
        let reparsed: serde_json::Value =
            serde_json::from_str(&serialized).expect("write_error output must be valid JSON");

        let err = reparsed.get("error").expect("error object present");
        assert_eq!(
            err.get("message").and_then(|m| m.as_str()),
            Some("model 'x' not found")
        );
        // Generic `not_found` maps to the Responses vocabulary `not_found_error`.
        assert_eq!(
            err.get("type").and_then(|t| t.as_str()),
            Some("not_found_error")
        );
        // `code` and `param` keys are present and null (Responses/OpenAI always include them).
        assert!(err.get("code").is_some(), "code key must be present");
        assert!(err.get("param").is_some(), "param key must be present");
        assert!(err.get("code").unwrap().is_null());
        assert!(err.get("param").unwrap().is_null());
    }

    /// Each generic `kind` maps to the canonical Responses `error.type`; an unrecognized kind is
    /// passed through verbatim (no catch-all swallowing of a precise upstream type).
    #[test]
    fn test_write_error_kind_mapping() {
        let writer = ResponsesWriter;
        for (kind, want) in [
            ("invalid_request", "invalid_request_error"),
            ("auth", "authentication_error"),
            ("forbidden", "permission_error"),
            ("not_found", "not_found_error"),
            ("rate_limit", "rate_limit_error"),
            ("server_error", "server_error"),
            ("billing", "insufficient_quota"),
            // Already-canonical and unknown types pass through unchanged.
            ("authentication_error", "authentication_error"),
            ("some_future_type", "some_future_type"),
        ] {
            let v = writer.write_error(400, kind, "m");
            assert_eq!(
                v.get("error")
                    .and_then(|e| e.get("type"))
                    .and_then(|t| t.as_str()),
                Some(want),
                "kind {kind} should map to {want}"
            );
        }
    }

    /// Same-protocol passthrough: `read_response` captures the upstream `id`/`created_at`, and
    /// `write_response` emits them verbatim — identity is preserved exactly, not regenerated.
    #[test]
    fn test_same_protocol_roundtrip_preserves_identity() {
        let json = serde_json::json!({
            "id": "resp_0123456789abcdef",
            "object": "response",
            "created_at": 1_710_000_000_u64,
            "status": "completed",
            "model": "gpt-4o-2024-08-06",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "hi"}]
                }
            ],
            "usage": {"input_tokens": 3, "output_tokens": 1}
        });

        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let ir = reader.read_response(&json).expect("read should succeed");
        assert_eq!(ir.id.as_deref(), Some("resp_0123456789abcdef"));
        assert_eq!(ir.created, Some(1_710_000_000));

        let out = writer.write_response(&ir);
        assert_eq!(
            out.get("id").and_then(|i| i.as_str()),
            Some("resp_0123456789abcdef"),
            "id must be preserved verbatim"
        );
        assert_eq!(
            out.get("created_at").and_then(|c| c.as_u64()),
            Some(1_710_000_000),
            "created_at must be preserved verbatim"
        );
        assert_eq!(out.get("object").and_then(|o| o.as_str()), Some("response"));
    }

    /// The streaming start event captures the nested `response` identity for same-protocol
    /// passthrough.
    #[test]
    fn test_stream_message_start_captures_identity() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            "response.created",
            &serde_json::json!({
                "response": {
                    "id": "resp_streamid",
                    "object": "response",
                    "created_at": 1_720_000_000_u64,
                    "model": "gpt-4o",
                    "status": "in_progress"
                }
            }),
            &mut state,
        );
        assert_eq!(events.len(), 1);
        match &events[0] {
            crate::ir::IrStreamEvent::MessageStart {
                id, created, model, ..
            } => {
                assert_eq!(id.as_deref(), Some("resp_streamid"));
                assert_eq!(*created, Some(1_720_000_000));
                assert_eq!(model.as_deref(), Some("gpt-4o"));
            }
            other => panic!("expected MessageStart, got {other:?}"),
        }
    }

    /// Cross-protocol: when the IR carries no identity (the backend supplied none), `write_response`
    /// synthesizes a valid `resp_`-prefixed id and a current `created_at` without panicking, and two
    /// successive synthesized ids are distinct.
    #[test]
    fn test_cross_protocol_write_synthesizes_valid_id() {
        let writer = ResponsesWriter;
        let make_ir = || crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "answer".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some("end_turn".to_string()),
            usage: crate::ir::IrUsage {
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

        let out1 = writer.write_response(&make_ir());
        let id1 = out1
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized id present");
        assert!(
            id1.starts_with("resp_"),
            "synthesized id must use the resp_ prefix, got {id1}"
        );
        assert!(
            out1.get("created_at").and_then(|c| c.as_u64()).is_some(),
            "synthesized created_at must be present"
        );

        let out2 = writer.write_response(&make_ir());
        let id2 = out2.get("id").and_then(|i| i.as_str()).unwrap();
        assert_ne!(id1, id2, "successive synthesized ids must be unique");
    }

    #[test]
    fn test_stream_fanout() {
        let mut state = crate::ir::StreamDecodeState::default();

        // response.created → MessageStart only (first time)
        let events1 = reader_read_response_events(
            "response.created",
            &serde_json::json!({"response": {"object":"response","status":"in_progress"}}),
            &mut state,
        );
        assert_eq!(events1.len(), 1);
        assert!(matches!(
            events1[0],
            crate::ir::IrStreamEvent::MessageStart { .. }
        ));
        // response.output_item.added for function_call → BlockStart
        let events2 = reader_read_response_events(
            "response.output_item.added",
            &serde_json::json!({
                "output_index": 1,
                "item": {"type":"function_call","call_id":"fc_1","name":"get_weather"}
            }),
            &mut state,
        );
        assert_eq!(events2.len(), 1);
        assert!(matches!(
            events2[0],
            crate::ir::IrStreamEvent::BlockStart { .. }
        ));
        // response.output_text.delta ×3 → BlockStart (lazy) + BlockDelta ×3
        let delta_json = |d: &str| serde_json::json!({"output_index": 0, "delta": d});
        let events3a =
            reader_read_response_events("response.output_text.delta", &delta_json("H"), &mut state);
        assert_eq!(events3a.len(), 2); // BlockStart + BlockDelta
        assert!(matches!(
            events3a[0],
            crate::ir::IrStreamEvent::BlockStart { .. }
        ));
        assert!(matches!(
            events3a[1],
            crate::ir::IrStreamEvent::BlockDelta { .. }
        ));
        let events3b =
            reader_read_response_events("response.output_text.delta", &delta_json("i"), &mut state);
        assert_eq!(events3b.len(), 1); // BlockDelta only
        assert!(matches!(
            events3b[0],
            crate::ir::IrStreamEvent::BlockDelta { .. }
        ));
        let events3c =
            reader_read_response_events("response.output_text.delta", &delta_json("!"), &mut state);
        assert_eq!(events3c.len(), 1); // BlockDelta only

        // response.output_item.done → BlockStop
        let events4 = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(events4.len(), 1);
        assert!(matches!(
            events4[0],
            crate::ir::IrStreamEvent::BlockStop { .. }
        ));
        // response.completed with usage → MessageDelta + MessageStop
        let completed_json = serde_json::json!({
            "response": {
                "status": "completed",
                "usage": {"input_tokens": 10, "output_tokens": 5}
            }
        });
        let events5 =
            reader_read_response_events("response.completed", &completed_json, &mut state);
        assert_eq!(events5.len(), 2);
        assert!(matches!(
            events5[0],
            crate::ir::IrStreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(events5[1], crate::ir::IrStreamEvent::MessageStop));
        // response.in_progress should not emit MessageStart again (state.started=true)
        let events6 = reader_read_response_events(
            "response.in_progress",
            &serde_json::json!({"response": {"object":"response","status":"in_progress"}}),
            &mut state,
        );
        assert_eq!(events6.len(), 0);

        // Unknown event type → empty (no panic)
        let events7 = reader_read_response_events(
            "response.content_part.added",
            &serde_json::json!({}),
            &mut state,
        );
        assert_eq!(events7.len(), 0);
    }

    #[test]
    fn test_write_response_event_blockdelta() {
        let writer = ResponsesWriter;

        // BlockDelta TextDelta("hi") → ("response.output_text.delta", delta=="hi")
        let ev1 = crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        };
        let (etype1, payload1) = writer.write_response_event(&ev1).expect("should emit");
        assert_eq!(etype1, "response.output_text.delta");
        assert_eq!(payload1.get("delta").and_then(|d| d.as_str()), Some("hi"));

        // MessageDelta{end_turn} → ("response.completed", status maps to completed)
        let ev2 = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 10,
                output_tokens: 5,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (etype2, payload2) = writer.write_response_event(&ev2).expect("should emit");
        assert_eq!(etype2, "response.completed");
        let resp_obj = payload2
            .get("response")
            .expect("payload should have response");
        assert_eq!(
            resp_obj.get("status"),
            Some(&serde_json::json!("completed"))
        );
    }

    fn reader_read_response_events(
        event_type: &str,
        data: &serde_json::Value,
        state: &mut crate::ir::StreamDecodeState,
    ) -> Vec<crate::ir::IrStreamEvent> {
        let reader = ResponsesReader;
        reader.read_response_events(event_type, data, state)
    }

    /// Regression: a text part arriving at a non-zero `output_index` must open AND write to the
    /// same block index. Previously BlockStart was hard-coded to index 0 while BlockDelta used the
    /// wire index, producing an unmatched open/write pair for downstream index-keyed consumers.
    #[test]
    fn test_text_delta_index_pairing_nonzero() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 2, "delta": "hello"}),
            &mut state,
        );
        assert_eq!(events.len(), 2, "expected lazy BlockStart + BlockDelta");
        let start_idx = match &events[0] {
            crate::ir::IrStreamEvent::BlockStart { index, .. } => *index,
            other => panic!("first event should be BlockStart, got {other:?}"),
        };
        let delta_idx = match &events[1] {
            crate::ir::IrStreamEvent::BlockDelta { index, .. } => *index,
            other => panic!("second event should be BlockDelta, got {other:?}"),
        };
        assert_eq!(start_idx, 2, "BlockStart must use the wire output_index");
        assert_eq!(delta_idx, 2, "BlockDelta must use the wire output_index");
        assert_eq!(start_idx, delta_idx, "open/write indices must match");
    }

    /// Regression: an empty-delta keepalive chunk must produce no events, even when a text block is
    /// already open. Previously the guard `|| state.text_block_open` emitted a spurious zero-length
    /// TextDelta for every keepalive after the block opened.
    #[test]
    fn test_empty_delta_keepalive_emits_nothing() {
        let mut state = crate::ir::StreamDecodeState::default();
        // Open a block with a real delta first.
        let opened = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": "x"}),
            &mut state,
        );
        assert_eq!(opened.len(), 2);
        assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
        // Now an empty keepalive while the block is open -> nothing.
        let keepalive = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": ""}),
            &mut state,
        );
        assert!(
            keepalive.is_empty(),
            "empty keepalive delta must not emit events, got {keepalive:?}"
        );
        // And an empty delta before any block is open also emits nothing.
        let mut fresh = crate::ir::StreamDecodeState::default();
        let pre = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": ""}),
            &mut fresh,
        );
        assert!(pre.is_empty());
        assert!(!fresh.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
    }

    /// Regression: output_item.done must clear the open TEXT index so a subsequent text part can
    /// lazily re-open its own block instead of silently reusing stale open state.
    #[test]
    fn test_done_clears_text_block_open() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": "a"}),
            &mut state,
        );
        assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
        let done = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(done.len(), 1);
        assert!(matches!(
            done[0],
            crate::ir::IrStreamEvent::BlockStop { .. }
        ));
        assert!(
            !state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET),
            "done must clear the open text index"
        );
        // A new text part at index 1 re-opens lazily.
        let reopen = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 1, "delta": "b"}),
            &mut state,
        );
        assert_eq!(reopen.len(), 2);
        assert!(matches!(
            reopen[0],
            crate::ir::IrStreamEvent::BlockStart { index: 1, .. }
        ));
    }

    /// Regression: content_part.done is also a terminal-of-part signal and must close its block.
    #[test]
    fn test_content_part_done_closes_block() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": "a"}),
            &mut state,
        );
        let done = reader_read_response_events(
            "response.content_part.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(done.len(), 1);
        assert!(matches!(
            done[0],
            crate::ir::IrStreamEvent::BlockStop { .. }
        ));
        assert!(!state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
    }

    /// Regression: a minimal `response.completed` lacking a nested `response` object must still
    /// terminate the stream with MessageDelta + MessageStop, not leave it hanging.
    #[test]
    fn test_completed_without_response_object_terminates() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events =
            reader_read_response_events("response.completed", &serde_json::json!({}), &mut state);
        assert_eq!(events.len(), 2, "must emit MessageDelta + MessageStop");
        assert!(matches!(
            events[0],
            crate::ir::IrStreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
    }

    /// Regression: same for `response.incomplete` with no nested response object.
    #[test]
    fn test_incomplete_without_response_object_terminates() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events =
            reader_read_response_events("response.incomplete", &serde_json::json!({}), &mut state);
        assert_eq!(events.len(), 2);
        assert!(matches!(
            events[0],
            crate::ir::IrStreamEvent::MessageDelta { .. }
        ));
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));

        // response.failed without object still works (pre-existing behavior preserved).
        let mut s2 = crate::ir::StreamDecodeState::default();
        let failed =
            reader_read_response_events("response.failed", &serde_json::json!({}), &mut s2);
        assert_eq!(failed.len(), 2);
        assert!(matches!(failed[1], crate::ir::IrStreamEvent::MessageStop));
    }

    /// Regression: an input item carrying BOTH a `type` and a `role` must be processed exactly once
    /// (by the type arm), not duplicated by the role-keyed fallback.
    #[test]
    fn test_typed_item_with_role_not_duplicated() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {
                    "type": "output_text",
                    "role": "assistant",
                    "text": "hello",
                    "content": [{"type": "output_text", "text": "DUPLICATE"}]
                }
            ]
        });
        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");
        // Exactly one message: the type arm produced the assistant text turn; the role fallback
        // must NOT have added a second turn from the `content` array.
        assert_eq!(ir.messages.len(), 1, "typed+role item must not duplicate");
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::Assistant);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hello"),
            other => panic!("expected text turn, got {other:?}"),
        }
    }

    /// Regression: an assistant turn that is PURELY a tool call must emit a flat `function_call`
    /// item and NO companion empty-content assistant `message` wrapper. The Responses API rejects
    /// assistant message items with `content: []`.
    #[test]
    fn test_tool_only_assistant_turn_no_empty_message_wrapper() {
        let ir = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![crate::ir::IrBlock::ToolUse {
                    id: "fc_1".to_string(),
                    name: "get_weather".to_string(),
                    input: serde_json::json!({"city": "SF"}),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);
        let input = json
            .get("input")
            .and_then(|v| v.as_array())
            .expect("input should exist");
        // Exactly one item: the function_call. No empty-content assistant message.
        assert_eq!(
            input.len(),
            1,
            "tool-only turn must not emit an empty message wrapper, got {input:?}"
        );
        assert_eq!(
            input[0].get("type").and_then(|t| t.as_str()),
            Some("function_call")
        );
        // No item should be a message with an empty content array.
        for item in input {
            if item.get("role").is_some() {
                let content = item.get("content").and_then(|c| c.as_array());
                assert!(
                    content.map(|c| !c.is_empty()).unwrap_or(true),
                    "no assistant message item may have empty content"
                );
            }
        }
    }

    /// Regression: an assistant turn carrying BOTH text and a tool call must emit the assistant
    /// `message` (with the text) FIRST, then the flat `function_call` item AFTER it — preserving
    /// the conversation order the assistant produced.
    #[test]
    fn test_assistant_text_then_tool_call_order() {
        let ir = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::Assistant,
                content: vec![
                    crate::ir::IrBlock::Text {
                        text: "Let me check.".to_string(),
                        cache_control: None,
                        citations: Vec::new(),
                    },
                    crate::ir::IrBlock::ToolUse {
                        id: "fc_9".to_string(),
                        name: "lookup".to_string(),
                        input: serde_json::json!({}),
                    },
                ],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);
        let input = json
            .get("input")
            .and_then(|v| v.as_array())
            .expect("input should exist");
        assert_eq!(
            input.len(),
            2,
            "expected message + function_call, got {input:?}"
        );
        // Message first.
        assert_eq!(
            input[0].get("role").and_then(|r| r.as_str()),
            Some("assistant")
        );
        let content = input[0]
            .get("content")
            .and_then(|c| c.as_array())
            .expect("message content");
        assert_eq!(
            content[0].get("text").and_then(|t| t.as_str()),
            Some("Let me check.")
        );
        // function_call after it.
        assert_eq!(
            input[1].get("type").and_then(|t| t.as_str()),
            Some("function_call")
        );
        assert_eq!(
            input[1].get("call_id").and_then(|c| c.as_str()),
            Some("fc_9")
        );
    }

    /// Regression: a streaming `response.failed` (status=="failed") must surface an
    /// IrStreamEvent::Error followed by MessageStop, NOT a successful end_turn MessageDelta that
    /// would mask the failure from a downstream client.
    #[test]
    fn test_stream_failed_status_emits_error_not_end_turn() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            "response.failed",
            &serde_json::json!({
                "response": {
                    "status": "failed",
                    "error": {"code": "server_error", "type": "server_error"}
                }
            }),
            &mut state,
        );
        assert_eq!(
            events.len(),
            2,
            "expected Error + MessageStop, got {events:?}"
        );
        match &events[0] {
            crate::ir::IrStreamEvent::Error(err) => {
                assert_eq!(err.provider_signal.as_deref(), Some("server_error"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
        // Crucially, no MessageDelta with end_turn was emitted.
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, crate::ir::IrStreamEvent::MessageDelta { .. })),
            "failed stream must not emit a MessageDelta"
        );
    }

    /// Regression: an unknown terminal status must not be decoded as a successful end_turn; its
    /// stop_reason is None (terminal, but no success claim).
    #[test]
    fn test_stream_unknown_status_not_end_turn() {
        let mut state = crate::ir::StreamDecodeState::default();
        let events = reader_read_response_events(
            "response.completed",
            &serde_json::json!({"response": {"status": "some_future_status"}}),
            &mut state,
        );
        assert_eq!(events.len(), 2);
        match &events[0] {
            crate::ir::IrStreamEvent::MessageDelta { stop_reason, .. } => {
                assert_eq!(*stop_reason, None, "unknown status must not claim end_turn");
            }
            other => panic!("expected MessageDelta, got {other:?}"),
        }
        assert!(matches!(events[1], crate::ir::IrStreamEvent::MessageStop));
    }

    /// Regression: the streaming error event nests the error inside the `response` object the
    /// official SDK streaming decoder reads via `event.response`, and the error object is the
    /// Responses-native `ResponseError` shape `{code, message}` with a NON-NULL `code` enum — NOT
    /// the Chat-Completions `{message, type, code:null, param:null}` envelope. A null `code` (or an
    /// extra `type`/`param`) is impossible from real OpenAI and a distinguishability tell.
    #[test]
    fn test_write_error_stream_event_full_shape() {
        let writer = ResponsesWriter;
        let ev = crate::ir::IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        });
        let (etype, payload) = writer
            .write_response_event(&ev)
            .expect("error event should emit");
        assert_eq!(etype, "response.failed");
        // The error is nested under `response` (SDK reads `event.response`), not top-level.
        assert!(
            payload.get("error").is_none(),
            "error must not be top-level: {payload}"
        );
        let resp = payload.get("response").expect("response object present");
        assert_eq!(resp.get("status").and_then(|s| s.as_str()), Some("failed"));
        let err = resp.get("error").expect("nested error object present");
        assert_eq!(err.get("message").and_then(|m| m.as_str()), Some("boom"));
        // Native ResponseError: code is the non-null enum (here carried from provider_signal).
        assert_eq!(err.get("code").and_then(|c| c.as_str()), Some("boom"));
        assert!(
            !err.as_object().unwrap().contains_key("type"),
            "Responses ResponseError carries no `type` field: {err}"
        );
        assert!(
            !err.as_object().unwrap().contains_key("param"),
            "Responses ResponseError carries no `param` field: {err}"
        );
    }

    /// Regression: an unknown/unmapped stop_reason must map to a `completed` status (not `failed`),
    /// so a future IR reason that did not signal an error is not misclassified as a failure.
    #[test]
    fn test_unknown_stop_reason_maps_to_completed() {
        let writer = ResponsesWriter;
        // Streaming MessageDelta path.
        let ev = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some("refusal".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
        assert_eq!(etype, "response.completed");
        assert_eq!(
            payload
                .get("response")
                .and_then(|r| r.get("status"))
                .and_then(|s| s.as_str()),
            Some("completed"),
            "unknown stop_reason must map to completed in stream"
        );

        // Non-streaming write_response path.
        let resp = crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "ok".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some("refusal".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model: None,
            id: Some("resp_x".to_string()),
            created: Some(1),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let out = writer.write_response(&resp);
        assert_eq!(
            out.get("status").and_then(|s| s.as_str()),
            Some("completed"),
            "unknown stop_reason must map to completed in write_response"
        );
    }

    /// Regression: malformed function_call arguments must be preserved as the raw string, not
    /// dropped to Null (mirrors the OpenAI reader). Covers both the request and response readers.
    #[test]
    fn test_malformed_function_call_args_preserved() {
        let reader = ResponsesReader;

        // read_request path.
        let req_json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": "function_call", "call_id": "fc_1", "name": "f", "arguments": "not-json{"}
            ]
        });
        let ir = reader.read_request(&req_json).expect("read_request ok");
        let tool_use = ir
            .messages
            .iter()
            .flat_map(|m| &m.content)
            .find_map(|b| match b {
                crate::ir::IrBlock::ToolUse { input, .. } => Some(input),
                _ => None,
            })
            .expect("tool use present");
        assert_eq!(
            tool_use.as_str(),
            Some("not-json{"),
            "malformed args must be preserved as raw string, not Null"
        );

        // read_response path.
        let resp_json = serde_json::json!({
            "id": "resp_1",
            "status": "completed",
            "output": [
                {"type": "function_call", "call_id": "fc_2", "name": "g", "arguments": "broken]"}
            ],
            "usage": {"input_tokens": 1, "output_tokens": 1}
        });
        let resp = reader.read_response(&resp_json).expect("read_response ok");
        match &resp.content[0] {
            crate::ir::IrBlock::ToolUse { input, .. } => {
                assert_eq!(input.as_str(), Some("broken]"));
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    /// Regression: a base64 `input_image` data URI of the canonical single-`;` shape
    /// (`data:image/png;base64,<payload>`) must parse the FULL payload, not drop it to "". The old
    /// `splitn(3, ';')` logic yielded only two fields and silently discarded every image. Covers
    /// both `read_request` and `responses_block`.
    #[test]
    fn test_input_image_base64_payload_preserved() {
        let payload = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";
        let url = format!("data:image/png;base64,{payload}");

        // read_request path.
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": "input_image", "image_url": url}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&json).expect("read_request ok");
        assert_eq!(ir.messages.len(), 1);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Image { media_type, data } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, payload, "full base64 payload must be preserved");
            }
            other => panic!("expected Image, got {other:?}"),
        }

        // responses_block path (e.g. a content block nested in a function_call_output).
        let block = serde_json::json!({"type": "input_image", "image_url": url});
        match responses_block(&block).expect("responses_block ok") {
            crate::ir::IrBlock::Image { media_type, data } => {
                assert_eq!(media_type, "image/png");
                assert_eq!(data, payload);
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    /// Regression: a base64 `input_image` must survive a same-protocol read -> write -> read
    /// round-trip with its payload intact (the writer emits `data:<mime>;base64,<payload>` which the
    /// reader must parse back to the identical pair).
    #[test]
    fn test_input_image_roundtrip_lossless() {
        let payload = "QUJDMTIzKz0=";
        let media_type = "image/jpeg";
        let ir = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image {
                    media_type: media_type.to_string(),
                    data: payload.to_string(),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        let reader = ResponsesReader;
        let json = writer.write_request(&ir);
        let rt = reader.read_request(&json).expect("read round-trip ok");
        match &rt.messages[0].content[0] {
            crate::ir::IrBlock::Image {
                media_type: mt,
                data,
            } => {
                assert_eq!(mt, media_type);
                assert_eq!(data, payload, "round-trip must not corrupt the payload");
            }
            other => panic!("expected Image, got {other:?}"),
        }
    }

    /// Regression: a non-data (https) image URL must be stored verbatim under the `image_url`
    /// sentinel media_type — NOT mangled into a `// note: non-data URL - ...` comment — and must
    /// round-trip back to the exact original URL.
    #[test]
    fn test_input_image_https_url_sentinel_roundtrip() {
        let url = "https://example.com/cat.png";
        let block = serde_json::json!({"type": "input_image", "image_url": url});
        let (media_type, data) = match responses_block(&block).expect("responses_block ok") {
            crate::ir::IrBlock::Image { media_type, data } => (media_type, data),
            other => panic!("expected Image, got {other:?}"),
        };
        assert_eq!(
            media_type, "image_url",
            "non-data URL must use the sentinel"
        );
        assert_eq!(data, url, "URL must be stored verbatim, not a comment");
        assert!(
            !data.starts_with("// note"),
            "must not embed a human comment in the payload"
        );

        // Round-trip through the writer reconstructs the exact original image_url.
        let ir = crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Image { media_type, data }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            stream: false,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        let json = writer.write_request(&ir);
        let emitted = json["input"][0]["content"][0]["image_url"]
            .as_str()
            .expect("image_url present");
        assert_eq!(emitted, url, "writer must emit the original URL verbatim");
    }

    /// Regression: `write_request` must emit the `stream` field (a modeled key excluded from
    /// `extra`); omitting it answers a `stream: true` request non-streaming and stalls SSE.
    #[test]
    fn test_write_request_emits_stream() {
        let make = |stream: bool| crate::ir::IrRequest {
            system: Vec::new(),
            messages: vec![crate::ir::IrMessage {
                role: crate::ir::IrRole::User,
                content: vec![crate::ir::IrBlock::Text {
                    text: "hi".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                }],
            }],
            tools: Vec::new(),
            max_tokens: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop: vec![],
            stream,
            extra: serde_json::Map::new(),
        };
        let writer = ResponsesWriter;
        assert_eq!(
            writer.write_request(&make(true)).get("stream"),
            Some(&serde_json::json!(true)),
            "stream: true must be emitted"
        );
        assert_eq!(
            writer.write_request(&make(false)).get("stream"),
            Some(&serde_json::json!(false)),
            "stream: false must be emitted explicitly"
        );
    }

    /// Regression: a typed `{"type":"message","role":...,"content":[...]}` input item (the official
    /// SDK conversation-turn shape) must be read, not silently dropped.
    #[test]
    fn test_typed_message_item_read() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": "message", "role": "user",
                 "content": [{"type": "input_text", "text": "hello typed"}]},
                {"type": "message", "role": "assistant",
                 "content": [{"type": "output_text", "text": "hi back"}]}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader.read_request(&json).expect("read_request ok");
        assert_eq!(
            ir.messages.len(),
            2,
            "both typed message turns must be read"
        );
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hello typed"),
            other => panic!("expected Text, got {other:?}"),
        }
        assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
        match &ir.messages[1].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi back"),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    /// Regression: the streaming `response.created` event must carry `id`/`created_at`/`status`
    /// (and `model` when present), not a stub. Forwards captured identity for same-protocol
    /// passthrough; synthesizes a valid `resp_` id + current time when the IR carries none.
    #[test]
    fn test_message_start_emits_identity() {
        let writer = ResponsesWriter;

        // Identity present (same-protocol passthrough): forwarded verbatim.
        let ev = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_streamid".to_string()),
            created: Some(1_720_000_000),
            model: Some("gpt-4o".to_string()),
        };
        let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
        assert_eq!(etype, "response.created");
        let resp = payload.get("response").expect("response object");
        assert_eq!(
            resp.get("id").and_then(|i| i.as_str()),
            Some("resp_streamid")
        );
        assert_eq!(
            resp.get("created_at").and_then(|c| c.as_u64()),
            Some(1_720_000_000)
        );
        assert_eq!(resp.get("model").and_then(|m| m.as_str()), Some("gpt-4o"));
        assert_eq!(
            resp.get("status").and_then(|s| s.as_str()),
            Some("in_progress")
        );

        // Identity absent (cross-protocol, stripped by translate_event): synthesized + valid.
        let ev2 = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (_, payload2) = writer.write_response_event(&ev2).expect("should emit");
        let resp2 = payload2.get("response").expect("response object");
        let id = resp2
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized id present");
        assert!(
            id.starts_with("resp_"),
            "synthesized id must use resp_ prefix, got {id}"
        );
        assert!(
            resp2.get("created_at").and_then(|c| c.as_u64()).is_some(),
            "synthesized created_at must be present"
        );
        // `Response.model` is a REQUIRED non-nullable SDK field, so an absent IR model must emit
        // the DEFAULT_MODEL fallback — NOT omit the key (which fails a strict decoder and is a
        // proxy tell).
        assert_eq!(
            resp2.get("model").and_then(|m| m.as_str()),
            Some(DEFAULT_MODEL),
            "absent model must fall back to DEFAULT_MODEL, not be omitted"
        );
    }

    /// Regression: synthesized response ids stay distinct even across many calls in the same second
    /// (the old `timestamp << 24 ^ counter` folding collided once the counter advanced by 2^24).
    #[test]
    fn test_synthesize_response_id_unique() {
        let n = 1000;
        let ids: std::collections::HashSet<String> =
            (0..n).map(|_| synthesize_response_id()).collect();
        assert_eq!(
            ids.len(),
            n,
            "all synthesized ids in a burst must be unique"
        );
        assert!(ids.iter().all(|id| id.starts_with("resp_")));
    }

    /// Regression (MEDIUM/correctness): a top-level `metadata` object must NOT be in the modeled-key
    /// exclusion set, so it flows into `IrRequest.extra` on read and is re-emitted verbatim by
    /// `write_request`. A prior revision listed `metadata` in `modeled_keys` while never emitting it,
    /// silently dropping the caller's response tagging / billing-attribution field.
    #[test]
    fn test_metadata_round_trips_through_extra() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [{"role": "user", "content": [{"type": "input_text", "text": "hi"}]}],
            "metadata": {"trace_id": "abc-123", "team": "billing"}
        });
        let reader = ResponsesReader;
        let writer = ResponsesWriter;

        let ir = reader.read_request(&json).expect("read_request ok");
        // metadata must have landed in extra (it is not a modeled IrRequest field).
        assert_eq!(
            ir.extra.get("metadata"),
            Some(&serde_json::json!({"trace_id": "abc-123", "team": "billing"})),
            "metadata must flow into extra, not be dropped"
        );

        // write_request forwards extra verbatim, so metadata survives to the upstream body.
        let out = writer.write_request(&ir);
        assert_eq!(
            out.get("metadata"),
            Some(&serde_json::json!({"trace_id": "abc-123", "team": "billing"})),
            "metadata must be forwarded to the upstream Responses backend"
        );
    }

    /// Regression (MEDIUM/conformance, class: stream-start skeleton): the opening `response.created`
    /// event must carry the FULL required Response skeleton an SDK reads unconditionally — `usage`,
    /// `output`, and `error` must be PRESENT (empty/null), not omitted. Omitting `usage` left strict
    /// SDK decoders without a `Response.usage` field on the first chunk.
    #[test]
    fn test_message_start_skeleton_carries_usage_output_error() {
        let writer = ResponsesWriter;
        let ev = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (etype, payload) = writer.write_response_event(&ev).expect("should emit");
        assert_eq!(etype, "response.created");
        let resp = payload.get("response").expect("response object present");

        // usage key MUST be present (null at stream start), not omitted.
        assert!(
            resp.get("usage").is_some(),
            "usage key must be present on the opening chunk: {resp}"
        );
        assert!(
            resp.get("usage").unwrap().is_null(),
            "usage must be null (no tokens yet) at stream start"
        );
        // output array present-but-empty; error present-but-null.
        assert_eq!(
            resp.get("output"),
            Some(&serde_json::json!([])),
            "output must be present as an empty array"
        );
        assert!(
            resp.get("error").map(|e| e.is_null()).unwrap_or(false),
            "error key must be present and null at stream start"
        );
    }

    /// A role-only item (no `type`) must still be processed via the role fallback.
    #[test]
    fn test_role_only_item_still_processed() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"role": "user", "content": [{"type": "input_text", "text": "hi there"}]}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("read_request should succeed");
        assert_eq!(ir.messages.len(), 1);
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        match &ir.messages[0].content[0] {
            crate::ir::IrBlock::Text { text, .. } => assert_eq!(text, "hi there"),
            other => panic!("expected text turn, got {other:?}"),
        }
    }

    /// Regression (HIGH/correctness): an array `input` must be iterated without the prior
    /// `is_array()` + `.as_array().unwrap()` pattern. Exercises the `if let Some(arr)` path and
    /// confirms array items are still decoded into messages.
    #[test]
    fn test_read_request_array_input_no_unwrap() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "input": [
                {"type": "input_text", "text": "hello"},
                {"type": "output_text", "text": "world"}
            ]
        });
        let reader = ResponsesReader;
        let ir = reader
            .read_request(&json)
            .expect("array input should decode");
        assert_eq!(ir.messages.len(), 2);
        assert_eq!(ir.messages[0].role, crate::ir::IrRole::User);
        assert_eq!(ir.messages[1].role, crate::ir::IrRole::Assistant);
    }

    /// Regression (HIGH/correctness): a `response.failed` terminal event with NO nested `response`
    /// object (truncated SSE frame / body-stripping proxy) must NOT be decoded as a successful
    /// end_turn. It must surface as an explicit Error + MessageStop so downstream clients see the
    /// failure and the breaker receives the failure signal.
    #[test]
    fn test_failed_event_without_body_surfaces_error() {
        let reader = ResponsesReader;
        let mut state = crate::ir::StreamDecodeState::default();
        let data = serde_json::json!({});
        let events = reader.read_response_events("response.failed", &data, &mut state);

        assert_eq!(
            events.len(),
            2,
            "expected Error + MessageStop, got {events:?}"
        );
        match &events[0] {
            IrStreamEvent::Error(err) => {
                assert_eq!(err.class, StatusClass::ServerError);
                assert_eq!(err.provider_signal.as_deref(), Some("response_failed"));
            }
            other => panic!("expected Error first, got {other:?}"),
        }
        assert!(
            matches!(events[1], IrStreamEvent::MessageStop),
            "expected MessageStop, got {:?}",
            events[1]
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, IrStreamEvent::MessageDelta { .. })),
            "a bodyless failed event must not emit a success MessageDelta"
        );
    }

    /// A `response.completed`/`response.incomplete` terminal event with no nested `response` object
    /// must still terminate the stream with a success MessageDelta + MessageStop (must NOT become an
    /// Error — only `response.failed` does).
    #[test]
    fn test_completed_event_without_body_emits_end_turn() {
        let reader = ResponsesReader;
        let mut state = crate::ir::StreamDecodeState::default();
        let data = serde_json::json!({});
        let events = reader.read_response_events("response.completed", &data, &mut state);

        assert_eq!(events.len(), 2, "expected MessageDelta + MessageStop");
        match &events[0] {
            IrStreamEvent::MessageDelta { stop_reason, .. } => {
                assert_eq!(stop_reason.as_deref(), Some("end_turn"));
            }
            other => panic!("expected MessageDelta first, got {other:?}"),
        }
        assert!(matches!(events[1], IrStreamEvent::MessageStop));
        assert!(
            !events.iter().any(|e| matches!(e, IrStreamEvent::Error(_))),
            "a bodyless completed event must not emit an Error"
        );
    }

    /// Regression (MEDIUM/conformance): the writer's `IrStreamEvent::Error` arm must emit a
    /// `response.failed` event whose error lives inside a `response` object (the shape the official
    /// SDK streaming decoder reads via `event.response`), with a synthesized `resp_` id and
    /// `status: "failed"` — NOT a top-level `{"error":{...}}`.
    #[test]
    fn test_error_event_wraps_in_response_object() {
        let writer = ResponsesWriter;
        let ev = IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("overloaded".to_string()),
            retry_after: None,
        });
        let (etype, payload) = writer
            .write_response_event(&ev)
            .expect("error event should emit");
        assert_eq!(etype, "response.failed");

        // No top-level `error` key — the SDK reads `event.response`, not `event.error`.
        assert!(
            payload.get("error").is_none(),
            "error must be nested under response, not top-level: {payload}"
        );
        let resp = payload
            .get("response")
            .expect("payload must carry a `response` object");
        let id = resp
            .get("id")
            .and_then(|i| i.as_str())
            .expect("synthesized resp_ id present");
        assert!(
            id.starts_with("resp_"),
            "synthesized id must use resp_ prefix, got {id}"
        );
        assert_eq!(resp.get("status").and_then(|s| s.as_str()), Some("failed"));
        let error = resp.get("error").expect("nested error object");
        assert_eq!(
            error.get("message").and_then(|m| m.as_str()),
            Some("overloaded")
        );
        // Native ResponseError shape: a non-null `code` enum (carried from the provider signal),
        // and NO Chat-style `type`/`param` fields.
        assert_eq!(
            error.get("code").and_then(|c| c.as_str()),
            Some("overloaded")
        );
        assert!(
            !error.as_object().unwrap().contains_key("type"),
            "Responses ResponseError carries no `type` field: {error}"
        );
        assert!(
            !error.as_object().unwrap().contains_key("param"),
            "Responses ResponseError carries no `param` field: {error}"
        );
    }

    /// Regression (CRITICAL/conformance, class: stream event `type` discriminator): EVERY emitted
    /// Responses SSE data body must carry a top-level `"type"` key equal to its event name. The
    /// official OpenAI Python/Node streaming decoders dispatch on `data["type"]`; a body missing it
    /// (the prior `{"response":{...}}` shape) yields None/undefined for the event type and the SDK
    /// never constructs the Response or fires event handlers. This exercises all writer arms that
    /// produce a body — response.created, response.output_item.added, response.output_text.delta,
    /// response.function_call_arguments.delta, response.output_item.done, response.completed, and
    /// response.failed — and asserts `payload["type"] == event_name` for each.
    #[test]
    fn test_every_stream_event_carries_top_level_type() {
        let writer = ResponsesWriter;
        let usage = || crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        };
        let events = vec![
            IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            },
            IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "fc_1".to_string(),
                    name: "f".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta("{}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage(),
            },
            IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }),
        ];

        for ev in &events {
            let (event_name, payload) = writer
                .write_response_event(ev)
                .unwrap_or_else(|| panic!("event {ev:?} must emit a body"));
            assert_eq!(
                payload.get("type").and_then(|t| t.as_str()),
                Some(event_name.as_str()),
                "event {event_name} body must carry top-level \"type\" == event name, got {payload}"
            );
        }
    }

    /// A full single-stream sequence of emitted Responses events. The events go through the writer in
    /// the order `StreamTranslate::feed` would emit them.
    fn usage_fixture() -> crate::ir::IrUsage {
        crate::ir::IrUsage {
            input_tokens: 1,
            output_tokens: 1,
            cache_creation_input_tokens: None,
            cache_read_input_tokens: None,
        }
    }

    /// Regression (HIGH/conformance): EVERY emitted Responses SSE event must carry a top-level
    /// `sequence_number` that is monotonic from 0 within a single stream. The opening
    /// `response.created` (MessageStart) resets the per-stream counter, so a fresh stream starts at 0
    /// and increases by one per emitted event. Events that produce no body do not consume a number.
    #[test]
    fn test_sequence_number_monotonic_from_zero() {
        let writer = ResponsesWriter;
        // A representative stream: created → text deltas → completed.
        let stream = vec![
            IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("Hel".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("lo".to_string()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            },
        ];

        let mut seqs = Vec::new();
        for ev in &stream {
            if let Some((_, payload)) = writer.write_response_event(ev) {
                let n = payload
                    .get("sequence_number")
                    .and_then(|s| s.as_u64())
                    .unwrap_or_else(|| {
                        panic!("every emitted event must carry sequence_number: {payload}")
                    });
                seqs.push(n);
            }
        }

        // A TEXT block's `BlockStop` emits no body (a text part has no `output_item.added`/`.done`
        // pair — its content-part lifecycle is closed upstream), so it consumes no sequence number.
        // The numbered events are therefore: created, two text deltas, completed = four events.
        assert_eq!(
            seqs,
            vec![0, 1, 2, 3],
            "sequence_number must be 0..N monotonic within the stream, got {seqs:?}"
        );
    }

    /// Regression: a SECOND stream (its own `response.created`) must restart its `sequence_number`
    /// from 0 — the counter is per-stream, not per-process. Exercises the reset-on-MessageStart
    /// contract so one stream's numbering never bleeds into the next on the same worker.
    #[test]
    fn test_sequence_number_resets_per_stream() {
        let writer = ResponsesWriter;
        let start = || IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let delta = || IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("x".to_string()),
        };

        // Stream A: created(0), delta(1).
        let (_, a0) = writer.write_response_event(&start()).expect("emit");
        let (_, a1) = writer.write_response_event(&delta()).expect("emit");
        assert_eq!(a0.get("sequence_number").and_then(|s| s.as_u64()), Some(0));
        assert_eq!(a1.get("sequence_number").and_then(|s| s.as_u64()), Some(1));

        // Stream B begins with its own created → counter resets to 0.
        let (_, b0) = writer.write_response_event(&start()).expect("emit");
        let (_, b1) = writer.write_response_event(&delta()).expect("emit");
        assert_eq!(
            b0.get("sequence_number").and_then(|s| s.as_u64()),
            Some(0),
            "a new stream's response.created must reset sequence_number to 0"
        );
        assert_eq!(b1.get("sequence_number").and_then(|s| s.as_u64()), Some(1));
    }

    /// Regression: every writer arm that produces a body carries `sequence_number`, not just the
    /// deltas. Mirrors `test_every_stream_event_carries_top_level_type` but asserts the integer
    /// `sequence_number` is present (and a u64) on each emitted body.
    #[test]
    fn test_every_stream_event_carries_sequence_number() {
        let writer = ResponsesWriter;
        let events = vec![
            IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            },
            IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_1".to_string(),
                    name: "f".to_string(),
                },
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
            },
            IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta("{}".to_string()),
            },
            IrStreamEvent::BlockStop { index: 0 },
            IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            },
            IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }),
        ];

        for ev in &events {
            let (event_name, payload) = writer
                .write_response_event(ev)
                .unwrap_or_else(|| panic!("event {ev:?} must emit a body"));
            assert!(
                payload
                    .get("sequence_number")
                    .map(|s| s.is_u64())
                    .unwrap_or(false),
                "event {event_name} body must carry a u64 sequence_number, got {payload}"
            );
        }
    }

    /// Regression: `response.output_text.delta` must carry `item_id` and `content_index` (native
    /// shape), and the `output_item.added` for a function call must carry `item_id`. The
    /// `function_call_arguments.delta` carries the matching `item_id`.
    #[test]
    fn test_delta_and_item_added_carry_item_id_and_content_index() {
        let writer = ResponsesWriter;

        // Text delta.
        let (_, text) = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 2,
                delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
            })
            .expect("emit");
        let text_item = text
            .get("item_id")
            .and_then(|i| i.as_str())
            .expect("output_text.delta must carry item_id");
        assert!(
            text_item.starts_with("msg_"),
            "text delta item_id must be a msg_ id, got {text_item}"
        );
        assert_eq!(
            text.get("content_index").and_then(|c| c.as_u64()),
            Some(0),
            "output_text.delta must carry content_index"
        );

        // output_item.added for a function call.
        let (_, added) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 1,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_9".to_string(),
                    name: "lookup".to_string(),
                },
            })
            .expect("emit");
        let added_item = added
            .get("item_id")
            .and_then(|i| i.as_str())
            .expect("output_item.added must carry item_id");
        assert!(
            added_item.starts_with("fc_"),
            "function_call item_id must be an fc_ id, got {added_item}"
        );
        // The nested item id matches the top-level item_id (one logical item).
        assert_eq!(
            added
                .get("item")
                .and_then(|i| i.get("id"))
                .and_then(|i| i.as_str()),
            Some(added_item),
            "nested item.id must equal the top-level item_id"
        );

        // The function_call_arguments.delta at the same index reuses the same fc_ item_id.
        let (_, args) = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 1,
                delta: crate::ir::IrDelta::InputJsonDelta("{\"q\":1}".to_string()),
            })
            .expect("emit");
        assert_eq!(
            args.get("item_id").and_then(|i| i.as_str()),
            Some(added_item),
            "arguments delta item_id must match the item's added item_id (stable per index)"
        );
    }

    /// Regression (HIGH/correctness): the `sequence_number` counter is PER-STREAM INSTANCE state,
    /// not thread-local. Two distinct writer instances model two concurrent streams sharing one
    /// worker thread. Interleave their events (A.start, B.start, A.delta, B.delta, ...) — the way a
    /// Tokio work-stealing runtime can schedule two parked stream tasks on the same thread. Each
    /// writer's sequence must stay monotonic-from-0 with NO bleed from the other stream's resets or
    /// increments. With the old thread-local cell, B's `MessageStart` reset clobbered A's in-flight
    /// counter and A's next event would restart non-monotonically; here the counters are independent.
    #[test]
    fn test_sequence_number_is_per_instance_not_thread_local() {
        let stream_a = ResponsesWriter;
        let stream_b = ResponsesWriter;
        let start = || IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let delta = || IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("x".to_string()),
        };
        let seq = |opt: Option<(String, serde_json::Value)>| {
            opt.expect("emit")
                .1
                .get("sequence_number")
                .and_then(|s| s.as_u64())
                .expect("sequence_number present")
        };

        // Interleave the two streams on the same "thread".
        let a0 = seq(stream_a.write_response_event(&start())); // A: 0
        let b0 = seq(stream_b.write_response_event(&start())); // B: 0 (must NOT touch A)
        let a1 = seq(stream_a.write_response_event(&delta())); // A: 1
        let b1 = seq(stream_b.write_response_event(&delta())); // B: 1
        let a2 = seq(stream_a.write_response_event(&delta())); // A: 2
        let b2 = seq(stream_b.write_response_event(&delta())); // B: 2

        assert_eq!(
            (a0, a1, a2),
            (0, 1, 2),
            "stream A must stay monotonic-from-0 despite stream B interleaving"
        );
        assert_eq!(
            (b0, b1, b2),
            (0, 1, 2),
            "stream B must stay monotonic-from-0 independent of stream A"
        );
    }

    /// Regression (HIGH/conformance): `response.output_item.done` must carry a stable `item_id`
    /// that matches the `response.output_item.added` for the same output index, plus a typed `item`
    /// object — an SDK reading `event.item_id`/`event.item` off the `done` event must not see
    /// `undefined`. The `added` for a function call and the `done` at the same index share the id.
    #[test]
    fn test_output_item_done_carries_matching_item_id_and_item() {
        let writer = ResponsesWriter;

        let (_, added) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 3,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_x".to_string(),
                    name: "f".to_string(),
                },
            })
            .expect("added emits");
        let added_id = added
            .get("item_id")
            .and_then(|i| i.as_str())
            .expect("added carries item_id")
            .to_string();

        let (etype, done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 3 })
            .expect("done emits");
        assert_eq!(etype, "response.output_item.done");
        assert_eq!(
            done.get("item_id").and_then(|i| i.as_str()),
            Some(added_id.as_str()),
            "output_item.done item_id must match the output_item.added at the same index"
        );
        // A typed `item` object is present (not undefined / not a bare {}).
        let item = done
            .get("item")
            .and_then(|i| i.as_object())
            .expect("output_item.done must carry an item object");
        assert_eq!(
            item.get("type").and_then(|t| t.as_str()),
            Some("function_call"),
            "the done item must be typed"
        );
        assert_eq!(
            item.get("id").and_then(|i| i.as_str()),
            Some(added_id.as_str()),
            "the done item.id must equal the item_id"
        );
    }

    /// Regression (MEDIUM/conformance): the in-band `response.failed` error object is the
    /// Responses-native `ResponseError` shape `{code, message}` with a NON-NULL `code` enum — NOT
    /// the Chat-Completions `{message, type, code:null, param:null}` envelope. A null `code` is
    /// impossible from real OpenAI and a distinguishability tell.
    #[test]
    fn test_response_failed_uses_native_responseerror_shape() {
        let writer = ResponsesWriter;

        // With a provider signal: it becomes the non-null code enum AND the message.
        let (etype, payload) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("rate_limit_exceeded".to_string()),
                retry_after: None,
            }))
            .expect("emit");
        assert_eq!(etype, "response.failed");
        let error = payload
            .get("response")
            .and_then(|r| r.get("error"))
            .and_then(|e| e.as_object())
            .expect("response.error object present");
        assert_eq!(
            error.get("code").and_then(|c| c.as_str()),
            Some("rate_limit_exceeded"),
            "error.code must be the non-null Responses error enum"
        );
        assert_eq!(
            error.get("message").and_then(|m| m.as_str()),
            Some("rate_limit_exceeded")
        );
        assert!(
            !error.contains_key("type"),
            "Responses ResponseError carries no `type` field"
        );
        assert!(
            !error.contains_key("param"),
            "Responses ResponseError carries no `param` field"
        );

        // Without a provider signal: code defaults to the canonical `server_error`, never null.
        let (_, payload) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: None,
                retry_after: None,
            }))
            .expect("emit");
        let code = payload
            .get("response")
            .and_then(|r| r.get("error"))
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str());
        assert_eq!(
            code,
            Some("server_error"),
            "error.code must default to server_error, never null"
        );
    }

    /// Regression (HIGH/correctness+conformance): a TEXT block's `BlockStop` must emit NOTHING from
    /// the Responses writer. The Text `BlockStart` arm emits no `output_item.added`, so emitting an
    /// `output_item.done` (with `type:"function_call"`, as a prior revision did) would be an
    /// unmatched lifecycle event AND mis-type a text response as a function call — both break a
    /// typed Responses SDK and are distinguishability tells.
    /// Regression (HIGH/conformance, Round 10): a TEXT part must be bracketed inside a `message`
    /// output item. The Text BlockStart emits `response.output_item.added` (type "message") and the
    /// Text BlockStop emits the matching `response.output_item.done` (type "message") carrying the
    /// SAME `msg_…` `item_id`. Previously the text BlockStart returned None and the BlockStop
    /// returned None, leaving the `output_text.delta`s orphaned with no parent item — so a typed SDK
    /// never materialized the assistant message in `response.output[]`.
    #[test]
    fn test_text_block_emits_message_item_lifecycle() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        // Text BlockStart now opens a message item.
        let (added_et, added) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text,
            })
            .expect("text BlockStart opens a message item");
        assert_eq!(added_et, "response.output_item.added");
        assert_eq!(added["item"]["type"], "message");
        assert_eq!(added["item"]["role"], "assistant");
        let added_item_id = added["item_id"]
            .as_str()
            .expect("item_id present")
            .to_string();
        assert!(added_item_id.starts_with("msg_"), "text item id is msg_…");

        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        });

        // Text BlockStop now closes the message item with a matching done.
        let (done_et, done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("text BlockStop closes the message item");
        assert_eq!(done_et, "response.output_item.done");
        assert_eq!(done["item"]["type"], "message");
        assert_eq!(
            done["item_id"].as_str(),
            Some(added_item_id.as_str()),
            "done item_id matches the added item_id (added→done correlation)"
        );

        // A SECOND BlockStop at the (already-closed) text index must NOT re-emit a done.
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
                .is_none(),
            "a repeated BlockStop for a closed text index must not re-emit output_item.done"
        );
    }

    /// Regression (HIGH): an interleaved tool+text stream closes the tool index with a
    /// `function_call` done and the text index with a `message` done — each with its own typed
    /// item, never cross-typed. Exercises the per-stream open-index tracking so a text index is
    /// never mistaken for a function-call item and vice-versa.
    #[test]
    fn test_tool_and_text_block_stop_emit_correctly_typed_done() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        // Tool at index 0, text at index 1.
        let _ = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_1".to_string(),
                    name: "f".to_string(),
                },
            })
            .expect("tool added emits");
        let _ = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 1,
                block: crate::ir::IrBlockMeta::Text,
            })
            .expect("text added emits");
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 1,
            delta: crate::ir::IrDelta::TextDelta("hi".to_string()),
        });
        // Tool index closes with a function_call done.
        let (etype, tool_done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("tool BlockStop emits output_item.done");
        assert_eq!(etype, "response.output_item.done");
        assert_eq!(tool_done["item"]["type"], "function_call");
        // Text index closes with a message done.
        let (text_et, text_done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 1 })
            .expect("text BlockStop emits output_item.done (message)");
        assert_eq!(text_et, "response.output_item.done");
        assert_eq!(text_done["item"]["type"], "message");
        // A SECOND BlockStop at the (already-closed) tool index 0 must not emit a duplicate done.
        assert!(
            writer
                .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
                .is_none(),
            "a repeated BlockStop for a closed tool index must not re-emit output_item.done"
        );
    }

    /// Regression (HIGH/conformance): the terminal `response.completed` event's inner `response`
    /// object must carry both `id` (a `resp_…` string) and `created_at` (a unix-seconds integer).
    /// The official SDKs read `event.response.id` on the terminal event to finalize the Response;
    /// omitting it breaks correlation and is a distinguishability tell (a real stream never sends a
    /// terminal event without an id).
    #[test]
    fn test_completed_event_carries_id_and_created_at() {
        let writer = ResponsesWriter;
        let (etype, payload) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("emit");
        assert_eq!(etype, "response.completed");
        let resp = payload
            .get("response")
            .and_then(|r| r.as_object())
            .expect("response object present");
        let id = resp
            .get("id")
            .and_then(|i| i.as_str())
            .expect("response.completed must carry response.id");
        assert!(
            id.starts_with("resp_"),
            "synthesized id must be a resp_ id, got {id}"
        );
        assert!(
            resp.get("created_at").and_then(|c| c.as_u64()).is_some(),
            "response.completed must carry an integer created_at"
        );
    }

    /// Regression (MEDIUM/conformance): `write_error` must emit `code:"invalid_api_key"` for an
    /// authentication failure (mirrors `openai.rs` `write_error_emits_invalid_api_key_code_for_auth_failure`).
    /// Emitting `code:null` on auth is a deterministic proxy tell vs a real OpenAI Responses 401.
    #[test]
    fn write_error_emits_invalid_api_key_code_for_auth_failure() {
        let writer = ResponsesWriter;
        for kind in ["authentication", "authentication_error", "auth"] {
            let body = writer.write_error(401, kind, "bad key");
            assert_eq!(
                body["error"]["type"],
                serde_json::json!("authentication_error"),
                "kind {kind} must map to authentication_error"
            );
            assert_eq!(
                body["error"]["code"],
                serde_json::json!("invalid_api_key"),
                "auth failure (kind {kind}) must carry code=invalid_api_key, not null"
            );
        }
    }

    /// Regression (MEDIUM/conformance): non-auth, non-quota error kinds keep `code:null` — the
    /// native shape when no machine-readable code applies — so only the auth and quota paths are
    /// special-cased.
    #[test]
    fn write_error_keeps_null_code_for_non_auth_errors() {
        let writer = ResponsesWriter;
        for kind in [
            "invalid_request",
            "permission",
            "not_found",
            "rate_limit",
            "server_error",
        ] {
            let body = writer.write_error(400, kind, "msg");
            assert_eq!(
                body["error"]["code"],
                serde_json::Value::Null,
                "non-auth/non-quota kind {kind} must keep code=null"
            );
        }
    }

    /// Regression (LOW/conformance): the over-quota path carries a populated machine-readable
    /// `code` — native OpenAI/Responses emits `{"type":"insufficient_quota","code":"insufficient_quota"}`
    /// — so a `code:null` here (the old behavior) would be a fingerprintable divergence. The
    /// `billing` kind (router vocabulary) is normalized to the native `insufficient_quota` type.
    #[test]
    fn write_error_insufficient_quota_keeps_type_and_sets_code() {
        let writer = ResponsesWriter;
        for kind in ["insufficient_quota", "billing"] {
            let body = writer.write_error(429, kind, "over quota");
            assert_eq!(
                body["error"]["type"],
                serde_json::json!("insufficient_quota"),
                "kind {kind} maps to the native insufficient_quota type"
            );
            assert_eq!(
                body["error"]["code"],
                serde_json::json!("insufficient_quota"),
                "kind {kind} must carry code=insufficient_quota, not null"
            );
        }
    }

    /// Regression (MEDIUM/correctness): a native text item is closed by BOTH `content_part.done`
    /// and `output_item.done` at the SAME `output_index`. The reader must emit EXACTLY ONE
    /// `BlockStop` for that index — the second terminal frame is a no-op — so a downstream writer
    /// does not emit a duplicate `content_block_stop`.
    #[test]
    fn test_paired_content_and_item_done_emits_single_block_stop() {
        let mut state = crate::ir::StreamDecodeState::default();
        // Open a text block lazily.
        let _ = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": "a"}),
            &mut state,
        );
        assert!(state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
        // First terminal frame: content_part.done → one BlockStop, clears the open index.
        let first = reader_read_response_events(
            "response.content_part.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(
            first.len(),
            1,
            "content_part.done closes the text block once"
        );
        assert!(!state.open_tools.contains(&TEXT_INDEX_KEY_OFFSET));
        // Second terminal frame at the same index: output_item.done → NOTHING (already closed).
        let second = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert!(
            second.is_empty(),
            "the second terminal frame for one text item must not emit a duplicate BlockStop, got {second:?}"
        );
    }

    /// Regression (MEDIUM/correctness): a tool item opened by `output_item.added` is closed by a
    /// single `output_item.done`, and a stray second `done` at that index emits nothing.
    #[test]
    fn test_tool_item_done_emits_single_block_stop() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            "response.output_item.added",
            &serde_json::json!({
                "output_index": 2,
                "item": {"type":"function_call","call_id":"fc_1","name":"f"}
            }),
            &mut state,
        );
        let first = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 2}),
            &mut state,
        );
        assert_eq!(first.len(), 1);
        assert!(matches!(
            first[0],
            crate::ir::IrStreamEvent::BlockStop { index: 2 }
        ));
        let second = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 2}),
            &mut state,
        );
        assert!(
            second.is_empty(),
            "a closed tool index must not re-emit BlockStop, got {second:?}"
        );
    }

    /// Regression (CRITICAL/conformance + HIGH/correctness, Round 10): every lifecycle event in ONE
    /// stream must carry the SAME `response.id`. On a cross-protocol stream the IR strips identity
    /// (id == None), so `response.created` synthesizes a `resp_` id which MUST be replayed verbatim
    /// on `response.completed`. Before the per-stream `response_id` cell, `MessageDelta` minted a
    /// fresh id, so the terminal event's id differed from `response.created` — SDK-breaking.
    #[test]
    fn test_terminal_id_matches_created_id_cross_protocol() {
        let writer = ResponsesWriter;
        // Cross-protocol: id is None, so response.created synthesizes one.
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            })
            .expect("MessageStart emits response.created");
        let created_id = created["response"]["id"]
            .as_str()
            .expect("created carries id")
            .to_string();
        assert!(created_id.starts_with("resp_"));

        let (etype, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("MessageDelta emits terminal");
        assert_eq!(etype, "response.completed");
        assert_eq!(
            completed["response"]["id"].as_str(),
            Some(created_id.as_str()),
            "response.completed.id must equal response.created.id (same stream, same id)"
        );
    }

    /// Regression (HIGH/correctness, Round 10): a `response.failed` (from an IR Error) must carry
    /// the SAME `response.id` as the opening `response.created`, so an SDK correlates the failure
    /// with the in-flight Response. Before the carried-id cell, the Error arm synthesized a fresh
    /// id distinct from `response.created`.
    #[test]
    fn test_failed_id_matches_created_id_cross_protocol() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            })
            .expect("MessageStart emits response.created");
        let created_id = created["response"]["id"].as_str().unwrap().to_string();

        let (etype, failed) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }))
            .expect("Error emits response.failed");
        assert_eq!(etype, "response.failed");
        assert_eq!(
            failed["response"]["id"].as_str(),
            Some(created_id.as_str()),
            "response.failed.id must equal response.created.id"
        );
    }

    /// Regression (HIGH/correctness, Round 10): a same-protocol passthrough forwards the upstream
    /// `id` on `response.created`, and that SAME id must be replayed on the terminal event.
    #[test]
    fn test_terminal_id_matches_forwarded_created_id() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: Some("resp_upstream123".to_string()),
                created: Some(42),
                model: None,
            })
            .expect("emit");
        assert_eq!(created["response"]["id"].as_str(), Some("resp_upstream123"));
        let (_, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("emit");
        assert_eq!(
            completed["response"]["id"].as_str(),
            Some("resp_upstream123"),
            "terminal event must replay the forwarded upstream id"
        );
    }

    /// Regression (HIGH/correctness, Round 10): a fresh stream's `response.created` REPLACES the
    /// carried id, so a reused/cloned writer never leaks the previous stream's id onto a new
    /// stream's terminal event. (`reset_sequence_number` clears the cell; `MessageStart` sets it.)
    #[test]
    fn test_carried_id_resets_per_stream() {
        let writer = ResponsesWriter;
        // Stream A.
        let (_, a_created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: Some("resp_A".to_string()),
                created: None,
                model: None,
            })
            .expect("emit");
        assert_eq!(a_created["response"]["id"].as_str(), Some("resp_A"));
        // Stream B begins on the same writer instance.
        let (_, b_created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: Some("resp_B".to_string()),
                created: None,
                model: None,
            })
            .expect("emit");
        assert_eq!(b_created["response"]["id"].as_str(), Some("resp_B"));
        let (_, b_completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("emit");
        assert_eq!(
            b_completed["response"]["id"].as_str(),
            Some("resp_B"),
            "stream B's terminal id must be B's, not A's leaked id"
        );
    }

    /// Regression (HIGH/security, Round 10): a backend that emits a `response.output_item.added`
    /// for each of many unique `output_index` values must NOT grow `state.open_tools` without
    /// bound. After feeding more than MAX_OPEN_TOOLS distinct indices, the tracked set is capped.
    #[test]
    fn test_reader_open_tools_is_capped() {
        let mut state = crate::ir::StreamDecodeState::default();
        for i in 0..(MAX_OPEN_TOOLS as u64 + 200) {
            let _ = reader_read_response_events(
                "response.output_item.added",
                &serde_json::json!({
                    "output_index": i,
                    "item": {"type":"function_call","call_id":"fc","name":"f"}
                }),
                &mut state,
            );
        }
        assert!(
            state.open_tools.len() <= MAX_OPEN_TOOLS,
            "open_tools must be capped at MAX_OPEN_TOOLS, got {}",
            state.open_tools.len()
        );
    }

    /// Regression (HIGH/security, Round 10): a crafted huge `output_index` must be clamped to
    /// MAX_OUTPUT_INDEX before the usize cast/insert, so the tracked index never exceeds the cap and
    /// downstream index arithmetic stays bounded.
    #[test]
    fn test_reader_output_index_clamped() {
        let mut state = crate::ir::StreamDecodeState::default();
        let out = reader_read_response_events(
            "response.output_item.added",
            &serde_json::json!({
                "output_index": u64::MAX,
                "item": {"type":"function_call","call_id":"fc","name":"f"}
            }),
            &mut state,
        );
        match out.first() {
            Some(crate::ir::IrStreamEvent::BlockStart { index, .. }) => {
                assert_eq!(*index, MAX_OUTPUT_INDEX, "u64::MAX index must clamp to cap");
            }
            other => panic!("expected a clamped BlockStart, got {other:?}"),
        }
        assert!(state.open_tools.contains(&MAX_OUTPUT_INDEX));
        assert!(!state.open_tools.iter().any(|&i| i > MAX_OUTPUT_INDEX));
    }

    /// Regression (HIGH/security, Round 10): the writer's open-text-index set is also capped so a
    /// pathological stream of unique text BlockStarts cannot grow per-stream writer memory without
    /// bound.
    #[test]
    fn test_writer_open_text_indices_capped() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let mut opened = 0usize;
        for i in 0..(MAX_OPEN_TOOLS + 200) {
            if writer
                .write_response_event(&IrStreamEvent::BlockStart {
                    index: i,
                    block: crate::ir::IrBlockMeta::Text,
                })
                .is_some()
            {
                opened += 1;
            }
        }
        assert!(
            opened <= MAX_OPEN_TOOLS,
            "writer must open at most MAX_OPEN_TOOLS text items, opened {opened}"
        );
    }

    /// Regression (HIGH/conformance, Round 11): a max_tokens-truncated stream's terminal event must
    /// be `response.incomplete` (event name AND inner `type`), NOT `response.completed`. A native
    /// stream never wraps a `status:"incomplete"` response in a `response.completed` envelope; the
    /// SDKs dispatch on the event `type`, so the previous always-`response.completed` arm mislabelled
    /// every truncated generation.
    #[test]
    fn test_terminal_incomplete_emits_response_incomplete_for_max_tokens() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (etype, body) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("max_tokens".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("MessageDelta emits a terminal event");
        assert_eq!(
            etype, "response.incomplete",
            "max_tokens truncation must use the response.incomplete event name"
        );
        assert_eq!(
            body["type"].as_str(),
            Some("response.incomplete"),
            "inner dispatch type must agree with the event name"
        );
        assert_eq!(
            body["response"]["status"].as_str(),
            Some("incomplete"),
            "inner status stays incomplete"
        );
        assert_eq!(
            body["response"]["incomplete_details"]["reason"].as_str(),
            Some("max_output_tokens"),
            "incomplete_details.reason maps max_tokens → max_output_tokens"
        );
    }

    /// Regression (HIGH/conformance, Round 11): a safety/content-filter stop is also `incomplete`,
    /// so its terminal event is `response.incomplete` with reason `content_filter`.
    #[test]
    fn test_terminal_incomplete_emits_response_incomplete_for_safety() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (etype, body) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("safety".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("MessageDelta emits a terminal event");
        assert_eq!(etype, "response.incomplete");
        assert_eq!(body["type"].as_str(), Some("response.incomplete"));
        assert_eq!(
            body["response"]["incomplete_details"]["reason"].as_str(),
            Some("content_filter")
        );
    }

    /// Regression (HIGH/conformance, Round 11): a normally-completed stream still emits
    /// `response.completed` with inner type/status `completed` — the fix must not regress the
    /// success path. The carried id must still match `response.created`.
    #[test]
    fn test_terminal_completed_unchanged_for_end_turn() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: None,
                model: None,
            })
            .expect("created");
        let created_id = created["response"]["id"].as_str().unwrap().to_string();
        let (etype, body) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal");
        assert_eq!(etype, "response.completed");
        assert_eq!(body["type"].as_str(), Some("response.completed"));
        assert_eq!(body["response"]["status"].as_str(), Some("completed"));
        assert!(body["response"].get("incomplete_details").is_none());
        assert_eq!(body["response"]["id"].as_str(), Some(created_id.as_str()));
    }

    /// Regression (HIGH/conformance, Round 11): write_error must NOT leak the Anthropic-vocabulary
    /// `overloaded` type to an OpenAI-family client. A 503 exhaustion/timeout (forward.rs passes
    /// kind `"overloaded"`) maps onto the native `server_error`.
    #[test]
    fn test_write_error_maps_overloaded_to_server_error() {
        let writer = ResponsesWriter;
        for kind in [
            "overloaded",
            "overloaded_error",
            "service_unavailable",
            "unavailable",
        ] {
            let v = writer.write_error(503, kind, "upstream busy");
            assert_eq!(
                v["error"]["type"].as_str(),
                Some("server_error"),
                "kind {kind:?} must map to server_error, never leak overloaded"
            );
            // `server_error` carries no machine-readable code in the native shape.
            assert!(v["error"]["code"].is_null(), "server_error code is null");
        }
    }

    /// Regression (MEDIUM/security, Round 11): synthesized `resp_` ids must be opaque base62 of
    /// native length with NO embedded timestamp or sequential structure, so an observer cannot
    /// fingerprint a proxied response or extract the server clock from the id.
    #[test]
    fn test_synthesize_response_id_is_opaque_native_length() {
        let id = synthesize_response_id();
        let suffix = id.strip_prefix("resp_").expect("resp_ prefix");
        assert_eq!(
            suffix.len(),
            RESPONSE_ID_TOKEN_LEN,
            "native-length suffix: {id}"
        );
        assert!(
            suffix.len() >= 38,
            "at least the native ~38-char profile: {id}"
        );
        assert!(
            suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
            "opaque base62 suffix only: {id}"
        );
        // Exactly one delimiter (the prefix's underscore) — no internal timestamp/counter fields.
        assert_eq!(
            id.matches('_').count(),
            1,
            "no internal field delimiter: {id}"
        );
    }

    /// Regression (MEDIUM/security, Round 11): synthesized `msg_`/`fc_` item ids must be opaque
    /// base62 of native length, NOT the old sequential `msg_00000000` positional hex.
    #[test]
    fn test_synthesize_item_id_is_opaque_native_length() {
        for prefix in ["msg", "fc"] {
            let id = synthesize_item_id(prefix);
            let suffix = id
                .strip_prefix(&format!("{prefix}_"))
                .expect("prefix present");
            assert_eq!(
                suffix.len(),
                ITEM_ID_TOKEN_LEN,
                "native-length suffix: {id}"
            );
            assert!(
                suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
                "opaque base62 suffix: {id}"
            );
            // The old form was zero-padded hex (all low chars); assert it is no longer a pure
            // zero-prefixed positional counter by requiring it differ from the sequential shape.
            assert_ne!(
                suffix,
                "0".repeat(ITEM_ID_TOKEN_LEN),
                "not all-zero positional: {id}"
            );
        }
    }

    /// Synthesized ids must be unique across calls even in a tight loop (the monotonic counter folded
    /// into the token guarantees this independent of the RNG).
    #[test]
    fn test_synthesized_ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(synthesize_response_id()), "duplicate resp_ id");
            assert!(seen.insert(synthesize_item_id("msg")), "duplicate msg_ id");
        }
    }

    /// The writer's `item_id_for` cache must return the SAME opaque id for a `(prefix, index)` across
    /// the item's lifecycle (so `output_item.added`/delta/`output_item.done` correlate), distinct ids
    /// for different indices, and a fresh id for a new stream after `reset_sequence_number`.
    #[test]
    fn test_item_id_for_is_stream_stable_and_opaque() {
        let writer = ResponsesWriter;
        let a1 = writer.item_id_for("msg", 0);
        let a2 = writer.item_id_for("msg", 0);
        assert_eq!(
            a1, a2,
            "same (prefix,index) yields a stable id within a stream"
        );
        assert!(a1.starts_with("msg_"));
        let b = writer.item_id_for("msg", 1);
        assert_ne!(a1, b, "different indices get distinct ids");
        let fc = writer.item_id_for("fc", 0);
        assert_ne!(
            a1, fc,
            "different prefixes at the same index get distinct ids"
        );
        assert!(fc.starts_with("fc_"));

        // A new stream (reset) mints a fresh id for the same key.
        writer.reset_sequence_number();
        let a_after = writer.item_id_for("msg", 0);
        assert_ne!(
            a1, a_after,
            "a reused writer must not replay a previous stream's item id"
        );
    }

    /// Full streamed text item: the `output_item.added`, every `output_text.delta`, and the closing
    /// `output_item.done` must all carry the SAME `item_id` so a typed SDK correlates the lifecycle.
    #[test]
    fn test_streamed_text_item_shares_one_item_id() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (_, added) = writer
            .write_response_event(&IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::Text,
            })
            .expect("output_item.added");
        let added_id = added["item_id"].as_str().unwrap().to_string();
        assert!(added_id.starts_with("msg_"));

        let (_, delta) = writer
            .write_response_event(&IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::TextDelta("hello".to_string()),
            })
            .expect("output_text.delta");
        assert_eq!(delta["item_id"].as_str(), Some(added_id.as_str()));

        let (_, done) = writer
            .write_response_event(&IrStreamEvent::BlockStop { index: 0 })
            .expect("output_item.done");
        assert_eq!(
            done["item_id"].as_str(),
            Some(added_id.as_str()),
            "added/delta/done must share one item_id"
        );
        assert_eq!(done["item"]["id"].as_str(), Some(added_id.as_str()));
    }

    /// Regression (HIGH/correctness, Round 12): the cardinality-cap guard on
    /// `response.output_item.added` was inverted (`if already_open || ...`), re-emitting a BlockStart
    /// for an index that was already open. A repeated `output_item.added` for the SAME function-call
    /// index must NOT produce a second BlockStart (only the first added opens the block); the second
    /// is a no-op. Otherwise downstream sees BlockStart→BlockStart for one block — an invalid
    /// sequence and a proxy tell.
    #[test]
    fn test_repeated_output_item_added_does_not_reemit_block_start() {
        let mut state = crate::ir::StreamDecodeState::default();
        let item = serde_json::json!({
            "output_index": 0,
            "item": {"type":"function_call","call_id":"fc_1","name":"f"}
        });
        let first = reader_read_response_events("response.output_item.added", &item, &mut state);
        assert_eq!(
            first.len(),
            1,
            "the first output_item.added opens exactly one BlockStart"
        );
        assert!(matches!(
            first.first(),
            Some(crate::ir::IrStreamEvent::BlockStart { index: 0, .. })
        ));
        // A second added for the SAME index must emit nothing (the block is already open).
        let second = reader_read_response_events("response.output_item.added", &item, &mut state);
        assert!(
            second.is_empty(),
            "a repeated output_item.added for an open index must not re-emit BlockStart, got {second:?}"
        );
        assert_eq!(
            state.open_tools.len(),
            1,
            "the index is tracked exactly once"
        );
    }

    /// Regression (HIGH/correctness, Round 12): the fixed guard must STILL bound new distinct
    /// indices under MAX_OPEN_TOOLS — the inversion fix must not weaken the DoS cap. Beyond the cap
    /// a NEW index emits no BlockStart and is not tracked.
    #[test]
    fn test_cap_still_bounds_new_indices_after_guard_fix() {
        let mut state = crate::ir::StreamDecodeState::default();
        for i in 0..(MAX_OPEN_TOOLS as u64) {
            let out = reader_read_response_events(
                "response.output_item.added",
                &serde_json::json!({
                    "output_index": i,
                    "item": {"type":"function_call","call_id":"fc","name":"f"}
                }),
                &mut state,
            );
            assert_eq!(out.len(), 1, "each fresh in-cap index opens one BlockStart");
        }
        assert_eq!(state.open_tools.len(), MAX_OPEN_TOOLS);
        // A fresh index beyond the cap (use a distinct, un-clamped value below MAX_OUTPUT_INDEX is
        // impossible here since indices 0..128 already fill it; use a high index that clamps to a
        // value already present is not a "new" index, so instead assert no growth past the cap).
        let over = reader_read_response_events(
            "response.output_item.added",
            &serde_json::json!({
                "output_index": (MAX_OPEN_TOOLS as u64) + 50,
                "item": {"type":"function_call","call_id":"fc","name":"f"}
            }),
            &mut state,
        );
        // The over-cap index clamps to MAX_OUTPUT_INDEX (127), which is already open (it was inserted
        // in the loop), so by the already-open rule it emits nothing and does not grow the set.
        assert!(
            over.is_empty() || state.open_tools.len() <= MAX_OPEN_TOOLS,
            "the cap is never exceeded"
        );
        assert!(
            state.open_tools.len() <= MAX_OPEN_TOOLS,
            "open_tools must never exceed MAX_OPEN_TOOLS, got {}",
            state.open_tools.len()
        );
    }

    /// Regression (MEDIUM/correctness, Round 12): a `function_call_arguments.delta` for an index
    /// with no open block (suppressed by the cap, or arriving with no preceding
    /// `output_item.added`) must be dropped — never an InputJsonDelta against a block that emitted
    /// no BlockStart.
    #[test]
    fn test_args_delta_dropped_for_unopened_index() {
        let mut state = crate::ir::StreamDecodeState::default();
        // No output_item.added for index 3 — the delta must be dropped.
        let out = reader_read_response_events(
            "response.function_call_arguments.delta",
            &serde_json::json!({"output_index": 3, "delta": "{\"a\":1}"}),
            &mut state,
        );
        assert!(
            out.is_empty(),
            "args delta for an unopened index must be dropped, got {out:?}"
        );
    }

    /// Regression (MEDIUM/correctness, Round 12): a `function_call_arguments.delta` for an index
    /// that DID open (via `output_item.added`) is routed as an InputJsonDelta to that index.
    #[test]
    fn test_args_delta_routed_for_opened_index() {
        let mut state = crate::ir::StreamDecodeState::default();
        let _ = reader_read_response_events(
            "response.output_item.added",
            &serde_json::json!({
                "output_index": 1,
                "item": {"type":"function_call","call_id":"fc","name":"f"}
            }),
            &mut state,
        );
        let out = reader_read_response_events(
            "response.function_call_arguments.delta",
            &serde_json::json!({"output_index": 1, "delta": "{\"a\":1}"}),
            &mut state,
        );
        match out.first() {
            Some(crate::ir::IrStreamEvent::BlockDelta {
                index,
                delta: crate::ir::IrDelta::InputJsonDelta(s),
            }) => {
                assert_eq!(*index, 1);
                assert_eq!(s, "{\"a\":1}");
            }
            other => panic!("expected InputJsonDelta at index 1, got {other:?}"),
        }
    }

    /// Regression (MEDIUM/conformance, Round 12): every lifecycle event in a stream must carry the
    /// SAME `created_at` as the opening `response.created` — the terminal event must replay the
    /// captured timestamp, not a fresh `now_unix_secs()` wall-clock read.
    #[test]
    fn test_created_at_is_constant_across_stream_events() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: Some(1_700_000_000),
                model: None,
            })
            .expect("response.created");
        let created_ts = created["response"]["created_at"].as_u64();
        assert_eq!(created_ts, Some(1_700_000_000));

        let (_, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        assert_eq!(
            completed["response"]["created_at"].as_u64(),
            created_ts,
            "terminal created_at must match the opening event's"
        );
    }

    /// Regression (MEDIUM/conformance, Round 12): the `response.failed` event must also replay the
    /// captured `created_at`, matching `response.created`.
    #[test]
    fn test_failed_event_replays_created_at() {
        let writer = ResponsesWriter;
        let (_, created) = writer
            .write_response_event(&IrStreamEvent::MessageStart {
                role: crate::ir::IrRole::Assistant,
                usage: None,
                id: None,
                created: Some(1_700_000_123),
                model: None,
            })
            .expect("response.created");
        let created_ts = created["response"]["created_at"].as_u64();

        let (_, failed) = writer
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }))
            .expect("response.failed");
        assert_eq!(
            failed["response"]["created_at"].as_u64(),
            created_ts,
            "response.failed created_at must match response.created"
        );
    }

    /// Regression (MEDIUM/conformance, Round 12): the forward.rs transient/upstream error kinds
    /// (`timeout`/`network`/`connect`/`5xx`/`transient`/`api_error`) must map to the native
    /// `server_error` type, and `context_length_exceeded`/`bad_request` to `invalid_request_error`,
    /// never leaking a non-native `error.type` to a Responses client.
    #[test]
    fn test_write_error_maps_forward_transient_kinds() {
        let writer = ResponsesWriter;
        for kind in [
            "timeout",
            "network",
            "connect",
            "5xx",
            "transient",
            "api_error",
        ] {
            let v = writer.write_error(503, kind, "upstream failure");
            assert_eq!(
                v["error"]["type"].as_str(),
                Some("server_error"),
                "kind {kind:?} must map to server_error"
            );
            assert!(v["error"]["code"].is_null(), "server_error code is null");
        }
        for kind in ["context_length_exceeded", "bad_request"] {
            let v = writer.write_error(400, kind, "bad request");
            assert_eq!(
                v["error"]["type"].as_str(),
                Some("invalid_request_error"),
                "kind {kind:?} must map to invalid_request_error"
            );
        }
    }

    /// Regression (MEDIUM/conformance, finding 2): the function-call `response.output_item.done`
    /// must carry the FULLY finalized item — `call_id`, `name`, AND the complete accumulated
    /// `arguments` string the SDK reads off `event.item`. Previously it emitted only
    /// `{"type":"function_call","id":…}`, an impossible-from-real-OpenAI shape.
    #[test]
    fn test_function_call_done_carries_finalized_item() {
        let writer = ResponsesWriter;
        // Open the stream so the per-stream state is initialized/reset.
        let _ = writer.write_response_event(&crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        // BlockStart(ToolUse) captures call_id + name.
        let added = writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStart {
                index: 0,
                block: crate::ir::IrBlockMeta::ToolUse {
                    id: "call_abc".to_string(),
                    name: "get_weather".to_string(),
                },
            })
            .expect("output_item.added should emit");
        assert_eq!(added.0, "response.output_item.added");

        // Two argument fragments accumulate into the complete string.
        let _ = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta("{\"city\":".to_string()),
        });
        let _ = writer.write_response_event(&crate::ir::IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::InputJsonDelta("\"SF\"}".to_string()),
        });

        // BlockStop closes it with the fully finalized item.
        let (etype, payload) = writer
            .write_response_event(&crate::ir::IrStreamEvent::BlockStop { index: 0 })
            .expect("output_item.done should emit");
        assert_eq!(etype, "response.output_item.done");
        let item = &payload["item"];
        assert_eq!(item["type"].as_str(), Some("function_call"));
        assert_eq!(
            item["call_id"].as_str(),
            Some("call_abc"),
            "done item must carry call_id"
        );
        assert_eq!(
            item["name"].as_str(),
            Some("get_weather"),
            "done item must carry name"
        );
        assert_eq!(
            item["arguments"].as_str(),
            Some("{\"city\":\"SF\"}"),
            "done item must carry the COMPLETE accumulated arguments"
        );
        // `id` (the opaque fc_ item id) is still present and stable with the added frame.
        assert_eq!(item["id"], added.1["item"]["id"]);
    }

    /// Regression (MEDIUM/correctness, finding 3): the streaming READER must track open text blocks
    /// PER `output_index`, not with a single index-blind bool. Two message items at distinct indices
    /// must each get their OWN BlockStart and their OWN BlockStop — no orphan delta, no mismatched
    /// close.
    #[test]
    fn test_reader_multiple_text_items_distinct_indices() {
        let mut state = crate::ir::StreamDecodeState::default();
        // First text item at index 0.
        let a = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 0, "delta": "alpha"}),
            &mut state,
        );
        assert_eq!(a.len(), 2, "first delta opens its block then writes");
        assert!(matches!(
            a[0],
            crate::ir::IrStreamEvent::BlockStart { index: 0, .. }
        ));
        // Second text item at index 1 arrives BEFORE index 0 closes — must open its OWN block,
        // never an orphan delta against an unopened block.
        let b = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 1, "delta": "beta"}),
            &mut state,
        );
        assert_eq!(b.len(), 2, "a new index must lazily open its own block");
        assert!(
            matches!(b[0], crate::ir::IrStreamEvent::BlockStart { index: 1, .. }),
            "second text index must emit its OWN BlockStart, got {:?}",
            b[0]
        );
        assert!(matches!(
            b[1],
            crate::ir::IrStreamEvent::BlockDelta { index: 1, .. }
        ));
        // Close index 0: BlockStop must pair with index 0 (not index 1).
        let close0 = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert_eq!(close0.len(), 1);
        assert!(
            matches!(close0[0], crate::ir::IrStreamEvent::BlockStop { index: 0 }),
            "close must pair with index 0, got {:?}",
            close0[0]
        );
        // Index 1 is still open and closes on its own terminal frame.
        let close1 = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 1}),
            &mut state,
        );
        assert_eq!(close1.len(), 1);
        assert!(matches!(
            close1[0],
            crate::ir::IrStreamEvent::BlockStop { index: 1 }
        ));
    }

    /// Regression (MEDIUM/correctness, finding 3): a tool item and a text item at DISTINCT indices
    /// in the same stream must not interfere — the tool index routes its arguments delta and closes
    /// as a tool, while the text index opens/closes independently. Confirms the disjoint key-offset
    /// keeps tool routing (`open_tools.contains(&idx)`) intact.
    #[test]
    fn test_reader_text_and_tool_indices_coexist() {
        let mut state = crate::ir::StreamDecodeState::default();
        // Tool item opens at index 0.
        let _ = reader_read_response_events(
            "response.output_item.added",
            &serde_json::json!({
                "output_index": 0,
                "item": {"type":"function_call","call_id":"fc_1","name":"f"}
            }),
            &mut state,
        );
        // Text item opens at index 1.
        let t = reader_read_response_events(
            "response.output_text.delta",
            &serde_json::json!({"output_index": 1, "delta": "hi"}),
            &mut state,
        );
        assert!(matches!(
            t[0],
            crate::ir::IrStreamEvent::BlockStart { index: 1, .. }
        ));
        // Tool arguments delta at index 0 must still route (tool index intact under raw key).
        let args = reader_read_response_events(
            "response.function_call_arguments.delta",
            &serde_json::json!({"output_index": 0, "delta": "{\"x\":1}"}),
            &mut state,
        );
        assert_eq!(args.len(), 1, "tool args delta must route to the open tool");
        assert!(matches!(
            args[0],
            crate::ir::IrStreamEvent::BlockDelta {
                index: 0,
                delta: crate::ir::IrDelta::InputJsonDelta(_)
            }
        ));
        // Close the tool index → tool BlockStop.
        let close_tool = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 0}),
            &mut state,
        );
        assert!(matches!(
            close_tool[0],
            crate::ir::IrStreamEvent::BlockStop { index: 0 }
        ));
        // Close the text index → text BlockStop.
        let close_text = reader_read_response_events(
            "response.output_item.done",
            &serde_json::json!({"output_index": 1}),
            &mut state,
        );
        assert!(matches!(
            close_text[0],
            crate::ir::IrStreamEvent::BlockStop { index: 1 }
        ));
    }

    /// Regression (MEDIUM/conformance): `write_response` must emit the SDK-required non-nullable
    /// `model` even when the IR carries none (cross-protocol path, e.g. Bedrock/Anthropic →
    /// Responses). A prior revision emitted `model` only when `resp.model` was `Some`, dropping the
    /// key entirely on cross-protocol responses — a strict-decoder failure and a distinguishability
    /// tell. Absent IR model must fall back to DEFAULT_MODEL; a present model is preserved verbatim.
    #[test]
    fn test_write_response_emits_model_fallback() {
        let make_resp = |model: Option<String>| crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some("end_turn".to_string()),
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
            model,
            id: Some("resp_x".to_string()),
            created: Some(1),
            system_fingerprint: None,
            stop_sequence: None,
        };

        // Cross-protocol: no model in the IR → DEFAULT_MODEL, never an absent key.
        let writer = ResponsesWriter;
        let out_none = writer.write_response(&make_resp(None));
        assert_eq!(
            out_none.get("model").and_then(|m| m.as_str()),
            Some(DEFAULT_MODEL),
            "absent model must fall back to DEFAULT_MODEL, not be omitted"
        );

        // Same-protocol passthrough: the upstream model is preserved verbatim.
        let writer_some = ResponsesWriter;
        let out_some = writer_some.write_response(&make_resp(Some("gpt-4o-mini".to_string())));
        assert_eq!(
            out_some.get("model").and_then(|m| m.as_str()),
            Some("gpt-4o-mini"),
            "present model must be preserved verbatim"
        );
    }

    /// Regression (MEDIUM/conformance): on a cross-protocol stream (IR `model` is `None` on
    /// `MessageStart`), `response.created` AND every terminal lifecycle event
    /// (`response.completed`/`.incomplete`/`.failed`) must carry the same non-nullable `model`
    /// (DEFAULT_MODEL here). The terminal arms previously emitted no `model` at all — an inner
    /// `response` missing the required field, a strict-decoder failure and a proxy tell.
    #[test]
    fn test_stream_terminal_events_carry_model_fallback() {
        // --- cross-protocol completed stream: model None throughout the IR ---
        let writer = ResponsesWriter;
        let start = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        };
        let (_, created) = writer.write_response_event(&start).expect("created event");
        assert_eq!(
            created
                .get("response")
                .and_then(|r| r.get("model"))
                .and_then(|m| m.as_str()),
            Some(DEFAULT_MODEL),
            "response.created must carry DEFAULT_MODEL when IR model is None"
        );

        let delta = crate::ir::IrStreamEvent::MessageDelta {
            stop_reason: Some("end_turn".to_string()),
            stop_sequence: None,
            usage: crate::ir::IrUsage {
                input_tokens: 1,
                output_tokens: 1,
                cache_creation_input_tokens: None,
                cache_read_input_tokens: None,
            },
        };
        let (ename, completed) = writer.write_response_event(&delta).expect("terminal event");
        assert_eq!(ename, "response.completed");
        assert_eq!(
            completed
                .get("response")
                .and_then(|r| r.get("model"))
                .and_then(|m| m.as_str()),
            Some(DEFAULT_MODEL),
            "response.completed must replay the required model field"
        );

        // --- same-protocol stream: the captured model is replayed onto the terminal event ---
        let writer2 = ResponsesWriter;
        let start2 = crate::ir::IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: Some("resp_keep".to_string()),
            created: Some(1_720_000_000),
            model: Some("gpt-4o-mini".to_string()),
        };
        writer2
            .write_response_event(&start2)
            .expect("created event");
        let err = crate::ir::IrStreamEvent::Error(IrError {
            class: StatusClass::ServerError,
            provider_signal: Some("boom".to_string()),
            retry_after: None,
        });
        let (ename2, failed) = writer2.write_response_event(&err).expect("failed event");
        assert_eq!(ename2, "response.failed");
        assert_eq!(
            failed
                .get("response")
                .and_then(|r| r.get("model"))
                .and_then(|m| m.as_str()),
            Some("gpt-4o-mini"),
            "response.failed must replay the captured stream model"
        );
    }

    /// Regression (MEDIUM/conformance, Round 15): the non-streaming `write_response` body must carry
    /// the REQUIRED nullable `error` field (`null` on a non-failed response), mirroring the
    /// streaming `response.created` skeleton. A real `/v1/responses` non-streaming body always
    /// includes `error`; omitting it breaks strict SDK/Pydantic/Zod decoders that read
    /// `response.error` unconditionally and is a distinguishability tell.
    #[test]
    fn test_write_response_emits_error_null_for_completed_and_incomplete() {
        let make_resp = |stop: &str| crate::ir::IrResponse {
            role: crate::ir::IrRole::Assistant,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
            stop_reason: Some(stop.to_string()),
            usage: usage_fixture(),
            model: Some("gpt-4o-mini".to_string()),
            id: Some("resp_x".to_string()),
            created: Some(1),
            system_fingerprint: None,
            stop_sequence: None,
        };
        let writer = ResponsesWriter;

        // Completed: error key present and explicitly null.
        let completed = writer.write_response(&make_resp("end_turn"));
        assert_eq!(completed["status"].as_str(), Some("completed"));
        assert!(
            completed.get("error").is_some(),
            "non-streaming body must include the required error key"
        );
        assert!(
            completed["error"].is_null(),
            "error must be null on a completed response"
        );

        // Incomplete (max_tokens): error is still present and null (the failure path is the error
        // envelope, never this success/incomplete body).
        let incomplete = writer.write_response(&make_resp("max_tokens"));
        assert_eq!(incomplete["status"].as_str(), Some("incomplete"));
        assert!(
            incomplete["error"].is_null(),
            "error must be null on an incomplete response"
        );
    }

    /// Regression (MEDIUM/correctness, Round 15): a non-streaming Responses body with
    /// `status:"failed"` and `output:null` is an upstream provider failure, NOT a parse error. The
    /// reader must surface it as a ServerError IrError carrying the upstream `error.code`, never
    /// misclassify it as an internal `ir_parse` ClientError.
    #[test]
    fn test_read_response_failed_surfaces_upstream_error() {
        let reader = ResponsesReader;

        // status:"failed" with output:null and a populated error.code.
        let body = serde_json::json!({
            "id": "resp_fail",
            "object": "response",
            "status": "failed",
            "output": serde_json::Value::Null,
            "error": { "code": "rate_limit_exceeded", "message": "slow down" },
            "usage": { "input_tokens": 1, "output_tokens": 0 },
            "model": "gpt-4o-mini"
        });
        let err = reader
            .read_response(&body)
            .expect_err("failed status must surface as an error");
        assert_eq!(
            err.class,
            StatusClass::ServerError,
            "an upstream failure is a ServerError, not a ClientError ir_parse"
        );
        assert_eq!(
            err.provider_signal.as_deref(),
            Some("rate_limit_exceeded"),
            "the upstream error.code must be surfaced as the provider signal"
        );

        // error.type fallback when code is absent.
        let body_type = serde_json::json!({
            "status": "failed",
            "error": { "type": "content_filter", "message": "blocked" },
            "usage": { "input_tokens": 1, "output_tokens": 0 }
        });
        let err_type = reader
            .read_response(&body_type)
            .expect_err("failed status must surface as an error");
        assert_eq!(err_type.class, StatusClass::ServerError);
        assert_eq!(err_type.provider_signal.as_deref(), Some("content_filter"));

        // failed with no usable error object → generic response_failed signal, still ServerError.
        let body_bare = serde_json::json!({ "status": "failed" });
        let err_bare = reader
            .read_response(&body_bare)
            .expect_err("failed status must surface as an error");
        assert_eq!(err_bare.class, StatusClass::ServerError);
        assert_eq!(err_bare.provider_signal.as_deref(), Some("response_failed"));

        // A genuinely malformed body (no status, no output) is STILL an ir_parse ClientError — the
        // failed-status path must not swallow real parse failures.
        let body_parse = serde_json::json!({ "id": "resp_x" });
        let err_parse = reader
            .read_response(&body_parse)
            .expect_err("missing output must surface as a parse error");
        assert_eq!(err_parse.class, StatusClass::ClientError);
        assert_eq!(err_parse.provider_signal.as_deref(), Some("ir_parse"));
    }

    /// Regression (MEDIUM/conformance, Round 15): the terminal `response.completed`/
    /// `response.incomplete`/`response.failed` events' inner `response` object must carry the
    /// REQUIRED `output` array (present-but-empty) and (on non-failed terminals) `error: null`,
    /// mirroring the `response.created` skeleton. The SDK reads `event.response.output` to finalize
    /// the assembled Response; omitting it breaks strict decoders and is a distinguishability tell.
    #[test]
    fn test_stream_terminal_events_carry_output_and_error() {
        // --- completed terminal ---
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (_, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        assert!(
            completed["response"]["output"].is_array(),
            "response.completed inner response must carry an output array"
        );
        assert!(
            completed["response"]["error"].is_null(),
            "response.completed inner response must carry error: null"
        );

        // --- incomplete terminal ---
        let writer2 = ResponsesWriter;
        let _ = writer2.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (_, incomplete) = writer2
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("max_tokens".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        assert!(
            incomplete["response"]["output"].is_array(),
            "response.incomplete inner response must carry an output array"
        );
        assert!(
            incomplete["response"]["error"].is_null(),
            "response.incomplete inner response must carry error: null"
        );

        // --- failed terminal: output present-but-empty alongside the populated error object ---
        let writer3 = ResponsesWriter;
        let _ = writer3.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (ename, failed) = writer3
            .write_response_event(&IrStreamEvent::Error(IrError {
                class: StatusClass::ServerError,
                provider_signal: Some("boom".to_string()),
                retry_after: None,
            }))
            .expect("failed event");
        assert_eq!(ename, "response.failed");
        assert!(
            failed["response"]["output"].is_array(),
            "response.failed inner response must carry an output array"
        );
        assert_eq!(
            failed["response"]["error"]["code"].as_str(),
            Some("boom"),
            "response.failed must still carry its populated error object"
        );
    }

    /// Regression (MEDIUM/conformance): the terminal `response.completed` event's inner
    /// `response.output` must carry the FULLY assembled output array (the message item with its
    /// `output_text` content, and the finalized function-call item) — NOT a hard-coded `[]`. A
    /// `completed` response with nonzero `usage.output_tokens` but an empty `output` is a shape real
    /// /v1/responses never emits and breaks SDK consumers that read `event.response.output`.
    #[test]
    fn test_terminal_output_assembles_streamed_text_and_tool_items() {
        let writer = ResponsesWriter;
        // Opening event.
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });

        // Text item at index 0: BlockStart + two deltas + BlockStop.
        let _ = writer.write_response_event(&IrStreamEvent::BlockStart {
            index: 0,
            block: crate::ir::IrBlockMeta::Text,
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("Hello ".to_string()),
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 0,
            delta: crate::ir::IrDelta::TextDelta("world".to_string()),
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockStop { index: 0 });

        // Function-call item at index 1: BlockStart(ToolUse) + arg deltas + BlockStop.
        let _ = writer.write_response_event(&IrStreamEvent::BlockStart {
            index: 1,
            block: crate::ir::IrBlockMeta::ToolUse {
                id: "call_abc".to_string(),
                name: "get_weather".to_string(),
            },
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 1,
            delta: crate::ir::IrDelta::InputJsonDelta("{\"city\":".to_string()),
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockDelta {
            index: 1,
            delta: crate::ir::IrDelta::InputJsonDelta("\"SF\"}".to_string()),
        });
        let _ = writer.write_response_event(&IrStreamEvent::BlockStop { index: 1 });

        // Terminal.
        let (ename, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("tool_use".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        assert_eq!(ename, "response.completed");

        let output = completed["response"]["output"]
            .as_array()
            .expect("terminal output must be an array");
        assert_eq!(
            output.len(),
            2,
            "assembled output must carry both the message and the function_call item, got {output:?}"
        );

        // Items come out in output_index order: message (0) then function_call (1).
        let msg_item = &output[0];
        assert_eq!(msg_item["type"], serde_json::json!("message"));
        assert_eq!(msg_item["role"], serde_json::json!("assistant"));
        let text = msg_item["content"][0]["text"]
            .as_str()
            .expect("message item carries assembled output_text");
        assert_eq!(
            text, "Hello world",
            "the streamed text must be fully assembled"
        );

        let fc_item = &output[1];
        assert_eq!(fc_item["type"], serde_json::json!("function_call"));
        assert_eq!(fc_item["call_id"], serde_json::json!("call_abc"));
        assert_eq!(fc_item["name"], serde_json::json!("get_weather"));
        assert_eq!(
            fc_item["arguments"],
            serde_json::json!("{\"city\":\"SF\"}"),
            "the finalized function-call item must carry the complete accumulated arguments"
        );
    }

    /// A genuinely output-less turn (no blocks streamed) still emits a present-but-empty `output`
    /// array on the terminal event — never an omitted key.
    #[test]
    fn test_terminal_output_empty_when_no_blocks_streamed() {
        let writer = ResponsesWriter;
        let _ = writer.write_response_event(&IrStreamEvent::MessageStart {
            role: crate::ir::IrRole::Assistant,
            usage: None,
            id: None,
            created: None,
            model: None,
        });
        let (_, completed) = writer
            .write_response_event(&IrStreamEvent::MessageDelta {
                stop_reason: Some("end_turn".to_string()),
                stop_sequence: None,
                usage: usage_fixture(),
            })
            .expect("terminal event");
        let output = completed["response"]["output"]
            .as_array()
            .expect("output present-but-empty, never omitted");
        assert!(
            output.is_empty(),
            "no blocks streamed -> empty output array"
        );
    }
}
