use super::{
    client_fault_kind, extract_error_message, is_streaming_content_type, mid_stream_error_bytes,
    strip_router_shim_keys, strip_same_protocol_model_shim, MID_STREAM_GENERIC_DETAIL,
};
use crate::proto::gemini::GEMINI_JSON_ARRAY_SHIM_KEY;
use crate::proto::StatusClass;
use serde_json::{json, Value};

/// HIGH (proxy engine gemini JSON-array path, + the SSE/eventstream + pre-first-byte twins):
/// the client-facing mid-stream transport-error detail MUST be a static, vendor-neutral string —
/// NEVER the raw `reqwest::Error` Display, which embeds hyper/reqwest internals and the egress
/// backend URL (a protocol tell + infrastructure leak). All three call sites pass the single
/// `MID_STREAM_GENERIC_DETAIL` const; pin that the const itself carries no leak markers, and that
/// both error-framing helpers it feeds emit a body free of them.
#[test]
fn test_mid_stream_generic_detail_has_no_leak_markers() {
    // Markers: transport/infrastructure tells (URLs, hyper/reqwest internals) AND busbar-internal
    // reverse-proxy VOCABULARY ("upstream"/"proxy"/"gateway"/"backend"/"lane"/"translate"). A
    // native vendor SDK never emits the latter in an error body or stream exception frame, so the
    // word "upstream" was itself a protocol-indistinguishability tell — pin it out here so it
    // cannot creep back into any client-facing fallback constant.
    const LEAK_MARKERS: &[&str] = &[
        "http://",
        "https://",
        "reqwest",
        "hyper",
        "tcp",
        "dns",
        "connect",
        "amazonaws",
        "url",
        "error sending request",
        "upstream",
        "proxy",
        "gateway",
        "backend",
        "lane",
        "translat", // matches "translate" / "translation" / "untranslatable"
    ];
    // Every client-facing fallback string, not just the mid-stream detail: all are rendered into
    // a native error envelope / stream frame and must read like a real single-vendor API.
    for detail in [
        MID_STREAM_GENERIC_DETAIL,
        super::GENERIC_REJECTED_DETAIL,
        super::GENERIC_RESPONSE_ERROR_DETAIL,
    ] {
        for marker in LEAK_MARKERS {
            assert!(
                !detail.to_ascii_lowercase().contains(marker),
                "client-facing fallback must not contain leak marker {marker:?}: {detail:?}"
            );
        }
    }
    // The Gemini JSON-array path: a `google.rpc.Status` element whose message
    // is exactly the generic detail, with no transport/URL markers spliced in.
    let mut framer = crate::proto::gemini::GeminiJsonArrayFramer::new();
    let arr = framer.finish_with_error(500, "INTERNAL", MID_STREAM_GENERIC_DETAIL);
    let arr_text = String::from_utf8_lossy(&arr);
    assert!(arr_text.contains(MID_STREAM_GENERIC_DETAIL));
    for marker in ["https://", "reqwest", "hyper", "amazonaws"] {
        assert!(
            !arr_text.contains(marker),
            "gemini json-array error body leaked {marker:?}: {arr_text}"
        );
    }
    // The SSE ingress twins carry the same generic detail in their native error envelope.
    // (Cohere is excluded: its native v2 mid-stream error is a `message-end` frame with
    // `delta.finish_reason: "ERROR"` and NO free-text field — a native client never sees a
    // detail string, so the cause is logged server-side instead of placed on the wire.)
    for proto in ["openai", "anthropic", "gemini", "responses"] {
        let bytes = mid_stream_error_bytes(proto, false, MID_STREAM_GENERIC_DETAIL);
        let text = String::from_utf8_lossy(&bytes);
        assert!(
            text.contains(MID_STREAM_GENERIC_DETAIL),
            "{proto} mid-stream error must carry the generic detail; got {text}"
        );
    }
    // Cohere: native `message-end` with ERROR finish_reason, and NO leaked detail on the wire.
    let cohere_bytes = mid_stream_error_bytes("cohere", false, MID_STREAM_GENERIC_DETAIL);
    let cohere_text = String::from_utf8_lossy(&cohere_bytes);
    assert!(
        cohere_text.contains("message-end") && cohere_text.contains("ERROR"),
        "cohere mid-stream error is a native message-end ERROR frame; got {cohere_text}"
    );
    assert!(
        !cohere_text.contains(MID_STREAM_GENERIC_DETAIL),
        "cohere native message-end must not carry a free-text detail; got {cohere_text}"
    );
}

/// HIGH (proxy engine / 372-380): a mid-stream upstream failure on a BEDROCK-ingress stream
/// (the client decodes binary `application/vnd.amazon.eventstream`) MUST be emitted as a valid
/// binary exception frame — never an SSE `event: error` text frame, which would inject ASCII into
/// a binary body and produce an undecodable prelude/CRC for the AWS SDK's eventstream decoder.
#[test]
fn test_bedrock_ingress_mid_stream_error_is_binary_exception_frame() {
    let bytes = mid_stream_error_bytes("bedrock", true, "connection reset by peer");
    // Must NOT be SSE text.
    assert!(
        !bytes.starts_with(b"event:") && !bytes.starts_with(b"data:"),
        "bedrock ingress error must be a binary frame, not SSE text"
    );
    // Must decode as a valid event-stream message with the AWS exception markers + JSON payload.
    let total_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    assert_eq!(total_len, bytes.len(), "valid total_len (CRC-framed)");
    let prelude_crc = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    assert_eq!(
        prelude_crc,
        crc32fast::hash(&bytes[..8]),
        "real prelude CRC"
    );
    let len = bytes.len();
    let msg_crc = u32::from_be_bytes([
        bytes[len - 4],
        bytes[len - 3],
        bytes[len - 2],
        bytes[len - 1],
    ]);
    assert_eq!(
        msg_crc,
        crc32fast::hash(&bytes[..len - 4]),
        "real message CRC"
    );
    let headers_len = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as usize;
    let headers = String::from_utf8_lossy(&bytes[12..12 + headers_len]);
    assert!(headers.contains(":message-type"));
    assert!(headers.contains("exception"));
    assert!(headers.contains(":exception-type"));
    // Generic transient failure maps to a real AWS Converse exception name.
    assert!(headers.contains("InternalServerException"));
    let payload = &bytes[12 + headers_len..len - 4];
    let v: Value = serde_json::from_slice(payload).expect("valid JSON payload");
    assert_eq!(v["message"], "connection reset by peer");
}

/// HIGH/conformance (proxy engine): the SSE mid-stream error frame must be the ingress
/// writer's OWN STREAMING error event (`write_response_event(&Error)`), framed exactly as the
/// happy path — NOT the non-stream `write_error()` HTTP envelope. Bare-`data:` protocols
/// (openai/cohere/gemini, whose native streams emit `data:`-only frames) get NO `event:` line;
/// anthropic gets `event: error`; responses gets `event: response.failed` with the SDK-required
/// `{"response":{...,"error":{...}}}` STREAM shape.
#[test]
fn test_sse_ingress_mid_stream_error_uses_native_framing() {
    // openai / cohere / gemini: bare `data:`, NO event line, native JSON envelope. (Gemini's
    // native streaming error is a bare `data:` frame — its writer returns an empty event name —
    // NOT `event: error`; emitting an event line for gemini was the pre-fix bug.)
    for proto in ["openai", "cohere", "gemini"] {
        let bytes = mid_stream_error_bytes(proto, false, "boom");
        let text = String::from_utf8(bytes).expect("SSE error is utf-8 text");
        assert!(
            text.starts_with("data: "),
            "{proto}: bare data: frame (no event: line); got: {text}"
        );
        assert!(
            !text.contains("event:"),
            "{proto}: native stream never emits an event: line mid-stream; got: {text}"
        );
        let data = text
            .lines()
            .find_map(|l| l.strip_prefix("data: "))
            .expect("a data: line");
        let v: Value = serde_json::from_str(data).expect("native JSON envelope");
        // OpenAI/Gemini wrap in `error`; Cohere's native mid-stream error is its `message-end`
        // frame with `delta.finish_reason: "ERROR"` (no top-level `message`/`error` — a native
        // v2 client never sees a proxy-detail string; the cause is logged server-side).
        let cohere_message_end = v.get("type").and_then(|t| t.as_str()) == Some("message-end")
            && v.pointer("/delta/finish_reason")
                .and_then(|f| f.as_str())
                .is_some_and(|f| f.starts_with("ERROR"));
        let has_native_shape =
            v.get("error").is_some() || v.get("message").is_some() || cohere_message_end;
        assert!(has_native_shape, "{proto} native envelope: {v}");
    }

    // anthropic: named `event: error`, payload `{"type":"error","error":{"type","message"}}`.
    let bytes = mid_stream_error_bytes("anthropic", false, "boom");
    let text = String::from_utf8(bytes).expect("SSE error is utf-8 text");
    assert!(
        text.starts_with("event: error\n"),
        "anthropic: named event: error frame; got: {text}"
    );
    let data = text
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("a data: line");
    let v: Value = serde_json::from_str(data).expect("native JSON envelope");
    // The `error` discriminant is the SSE event NAME (`event: error`); the data payload is
    // `{"error":{"type","message"}}` (the native Anthropic in-stream error event body).
    assert!(
        v["error"]["message"].is_string(),
        "anthropic error.message present: {v}"
    );

    // responses: terminal error event is `response.failed`, and the payload MUST be the STREAM
    // shape `{"response":{...,"error":{...}}}` (the SDK reads `event.response`), NOT the
    // non-stream `{"error":{...}}` HTTP envelope. This is the core of the finding.
    let bytes = mid_stream_error_bytes("responses", false, "boom");
    let text = String::from_utf8(bytes).expect("SSE error is utf-8 text");
    assert!(
        text.starts_with("event: response.failed\n"),
        "responses: event: response.failed frame; got: {text}"
    );
    let data = text
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .expect("a data: line");
    let v: Value = serde_json::from_str(data).expect("native JSON envelope");
    assert!(
        v.get("response").is_some(),
        "responses stream error MUST wrap in a `response` object (SDK reads event.response), \
             not a top-level `error`; got: {v}"
    );
    assert_eq!(
        v["response"]["status"], "failed",
        "responses failed-event status: {v}"
    );
    assert!(
        v["response"]["error"]["message"].is_string(),
        "responses error.message present inside response object: {v}"
    );
    assert!(
        v.get("error").is_none(),
        "responses stream error must NOT carry a top-level `error` (that is the HTTP envelope, \
             which the stream decoder cannot locate): {v}"
    );
}

/// `client_fault_kind` maps the classified 4xx to a protocol-agnostic kind, exhaustively.
#[test]
fn test_client_fault_kind_mapping() {
    assert_eq!(
        client_fault_kind(StatusClass::ContextLength),
        "context_length_exceeded" // golden wire-contract literal (kept bare on purpose)
    );
    assert_eq!(
        client_fault_kind(StatusClass::ClientError),
        "invalid_request_error" // golden wire-contract literal (kept bare on purpose)
    );
}

/// `extract_error_message` pulls the human message across vendor shapes, and returns None for a
/// non-JSON / message-less body so the caller substitutes a generic detail (no foreign leak).
#[test]
fn test_extract_error_message() {
    assert_eq!(
        extract_error_message(br#"{"error":{"message":"bad param"}}"#).as_deref(),
        Some("bad param")
    );
    assert_eq!(
        extract_error_message(br#"{"message":"flat"}"#).as_deref(),
        Some("flat")
    );
    assert_eq!(extract_error_message(b"not json"), None);
    assert_eq!(extract_error_message(br#"{"foo":1}"#), None);
}

/// `is_streaming_content_type` recognizes exactly the registry's streaming CTs (SSE +
/// AWS-event-stream) via prefix match, so a parameterized SSE CT (`; charset=utf-8`) still
/// engages the streaming path, while non-streaming/empty CTs do not.
#[test]
fn test_is_streaming_content_type() {
    assert!(is_streaming_content_type("text/event-stream")); // golden wire-contract literal (kept bare on purpose)
    assert!(is_streaming_content_type(
        "application/vnd.amazon.eventstream"
    ));
    assert!(is_streaming_content_type(
        "text/event-stream; charset=utf-8"
    ));
    assert!(!is_streaming_content_type("application/json"));
    assert!(!is_streaming_content_type(""));
}

/// `strip_router_shim_keys` removes the NEVER-NATIVE shim keys on every branch: the gemini
/// JSON-array key for ALL egress, and `stream` for path-model gemini/bedrock EGRESS (R9 HIGH: gated
/// on egress, not ingress, so the writer-authored `stream` survives for a body-model backend). It
/// does NOT remove `model` (that is `strip_same_protocol_model_shim`'s job, on the same-protocol
/// branch only) so a cross-protocol hop keeps the authoritative model `rewrite_model` installs.
#[test]
fn test_strip_router_shim_keys() {
    let mut v =
        json!({"model": "p", "stream": true, GEMINI_JSON_ARRAY_SHIM_KEY: true, "messages": []});
    strip_router_shim_keys(&mut v, "bedrock");
    assert_eq!(
        v["model"], "p",
        "model NOT stripped here (rewrite_model owns it)"
    );
    assert!(v.get("stream").is_none(), "bedrock: stream shim stripped");
    assert!(
        v.get(GEMINI_JSON_ARRAY_SHIM_KEY).is_none(),
        "gemini array shim key stripped on every protocol"
    );
    assert!(v.get("messages").is_some(), "real fields retained");

    let mut v = json!({"stream": true, GEMINI_JSON_ARRAY_SHIM_KEY: true});
    strip_router_shim_keys(&mut v, "gemini");
    assert!(v.get("stream").is_none() && v.get(GEMINI_JSON_ARRAY_SHIM_KEY).is_none());

    // OpenAI is a BODY-MODEL protocol: model/stream are genuine caller fields, never stripped —
    // but the gemini array key is never native to ANY protocol, so a client-smuggled copy is
    // still removed (closes the body-model framing-smuggle leak).
    let mut v = json!({"model": "gpt-4o", "stream": true, GEMINI_JSON_ARRAY_SHIM_KEY: true});
    strip_router_shim_keys(&mut v, "openai");
    assert_eq!(
        v["model"], "gpt-4o",
        "openai model is genuine, not stripped"
    );
    assert_eq!(v["stream"], true, "openai stream is genuine, not stripped");
    assert!(
        v.get(GEMINI_JSON_ARRAY_SHIM_KEY).is_none(),
        "gemini array key stripped even for body-model ingress"
    );
}

/// `strip_same_protocol_model_shim` removes the body `model` for same-protocol gemini/bedrock
/// passthrough (model rides the URL there), and is a no-op for body-model ingress.
#[test]
fn test_strip_same_protocol_model_shim() {
    let mut v = json!({"model": "p", "messages": []});
    strip_same_protocol_model_shim(&mut v, "gemini");
    assert!(
        v.get("model").is_none(),
        "gemini same-protocol: model stripped"
    );
    assert!(v.get("messages").is_some());

    let mut v = json!({"model": "gpt-4o"});
    strip_same_protocol_model_shim(&mut v, "openai");
    assert_eq!(v["model"], "gpt-4o", "openai model never stripped");
}

/// REGRESSION (R7 CRITICAL, proxy engine shim-strip ordering): a PATH-MODEL ingress (gemini/bedrock)
/// crossing to a BODY-MODEL egress (openai/anthropic/cohere/responses) must reach the backend WITH
/// the authoritative egress `model`. The bug: `rewrite_model` ran, then an UNCONDITIONAL strip
/// removed `model`, so the cross-protocol body hit the backend with no `model` (a guaranteed 400).
/// This exercises the exact strip→rewrite ordering on a value, asserting the cross-protocol body
/// keeps `model` and (R9 HIGH) keeps the writer-authored `stream` for a BODY-MODEL egress, while
/// the array key is gone; and the same-protocol path drops `model` and (path-model egress) `stream`.
#[test]
fn test_shim_strip_ordering_cross_protocol_keeps_model() {
    // Cross-protocol gemini→openai: strip (never-native keys, gated on EGRESS) → rewrite_model
    // installs the lane model → NO same-protocol model strip. Body must carry the egress model AND
    // keep the writer-authored `stream` (R9 HIGH: openai is a body-model egress, so the backend
    // reads `stream` from the body — stripping it made it answer non-streaming).
    let mut v =
        json!({"model": "router-placeholder", "stream": true, GEMINI_JSON_ARRAY_SHIM_KEY: true});
    let ingress = "gemini";
    let egress = "openai";
    strip_router_shim_keys(&mut v, egress);
    crate::proto::Protocol::openai()
        .writer()
        .rewrite_model_if_needed(&mut v, "gpt-4o");
    if ingress == egress {
        strip_same_protocol_model_shim(&mut v, ingress);
    }
    assert_eq!(
        v["model"], "gpt-4o",
        "cross-protocol egress body MUST carry the authoritative model (the critical fix)"
    );
    assert_eq!(
        v["stream"], true,
        "R9 HIGH: writer-authored `stream` MUST survive for a body-model egress (gated on egress)"
    );
    assert!(
        v.get(GEMINI_JSON_ARRAY_SHIM_KEY).is_none(),
        "gemini array key stripped cross-protocol"
    );

    // Same-protocol gemini→gemini: model rides the URL, so the body must NOT carry `model` even
    // though the gemini writer's rewrite_model re-inserts one — the same-protocol strip runs after.
    // `stream` IS stripped here because the EGRESS is gemini (path-model: stream rides the URL).
    let mut v = json!({"model": "router-placeholder", "stream": true, "contents": []});
    let ingress = "gemini";
    let egress = "gemini";
    strip_router_shim_keys(&mut v, egress);
    crate::proto::Protocol::gemini()
        .writer()
        .rewrite_model_if_needed(&mut v, "gemini-1.5-pro");
    if ingress == egress {
        strip_same_protocol_model_shim(&mut v, ingress);
    }
    assert!(
        v.get("model").is_none(),
        "same-protocol gemini passthrough must NOT leak a body model (rides the URL)"
    );
    assert!(
        v.get("stream").is_none(),
        "shim stream stripped for path-model (gemini) egress"
    );
}
