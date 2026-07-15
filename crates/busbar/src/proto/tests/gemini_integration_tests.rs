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
