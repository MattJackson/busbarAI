
use super::*;
use crate::breaker::{classify, Disposition};
use crate::proto::openai_family::PROVIDER_SIGNAL_CONTEXT_LENGTH;
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
        provider_signal: Some(PROVIDER_SIGNAL_CONTEXT_LENGTH.to_string()),
        retry_after: None,
    };
    assert_eq!(classify(&sig), Disposition::ContextLength);
}
