//! THE REGRESSION NET for the `response_format` bug class. Before the typed `IrResponseFormat`
//! layer, the same "writer echoes a foreign shape cross-protocol → backend 400" bug surfaced once
//! per writer (openai → cohere → gemini → responses). Now the IR is typed, so a writer physically
//! cannot hold or echo a foreign shape — and this matrix proves every projection lands native.
use super::*;
use crate::ir::{IrBlock, IrMessage, IrResponseFormat, IrRole};

fn req_with_format(rf: IrResponseFormat) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        response_format: Some(rf),
        ..Default::default()
    }
}

/// ONE typed directive, projected by EVERY native-structured-output writer, must land in THAT
/// writer's own wire shape — never a foreign one — with the schema preserved.
#[test]
fn every_writer_emits_its_native_shape() {
    let schema = serde_json::json!({"type":"object","properties":{"x":{"type":"string"}}});
    let req = req_with_format(IrResponseFormat {
        json: true,
        schema: Some(schema),
        name: Some("out".to_string()),
        strict: None,
        description: None,
    });

    // OpenAI: {type:"json_schema", json_schema:{name, schema}} — schema NESTED under .schema.
    let o = OpenAiWriter.write_request(&req);
    assert_eq!(
        o.pointer("/response_format/type"),
        Some(&serde_json::json!("json_schema"))
    );
    assert_eq!(
        o.pointer("/response_format/json_schema/schema/properties/x/type"),
        Some(&serde_json::json!("string"))
    );
    assert!(o.pointer("/response_format/json_schema/name").is_some());
    assert!(
        o.pointer("/response_format/responseMimeType").is_none(),
        "no Gemini-shaped key may leak into OpenAI: {o}"
    );

    // Cohere: {type:"json_object", json_schema:<schema DIRECTLY>}.
    let cohere_writer = CohereWriter;
    let c = cohere_writer.write_request(&req);
    assert_eq!(
        c.pointer("/response_format/type"),
        Some(&serde_json::json!("json_object"))
    );
    assert_eq!(
        c.pointer("/response_format/json_schema/properties/x/type"),
        Some(&serde_json::json!("string"))
    );
    assert!(
        c.pointer("/response_format/json_schema/schema").is_none(),
        "Cohere does NOT nest under .schema (that's OpenAI's shape): {c}"
    );

    // Gemini: generationConfig.responseMimeType + responseSchema; no top-level response_format.
    let gemini_writer = GeminiWriter;
    let g = gemini_writer.write_request(&req);
    assert_eq!(
        g.pointer("/generationConfig/responseMimeType"),
        Some(&serde_json::json!("application/json"))
    );
    assert_eq!(
        g.pointer("/generationConfig/responseSchema/properties/x/type"),
        Some(&serde_json::json!("string"))
    );
    assert!(
        g.pointer("/response_format").is_none(),
        "Gemini has no top-level response_format: {g}"
    );

    // Responses: text.format FLAT json_schema (name/schema beside type, not nested).
    let responses_writer = ResponsesWriter;
    let r = responses_writer.write_request(&req);
    assert_eq!(
        r.pointer("/text/format/type"),
        Some(&serde_json::json!("json_schema"))
    );
    assert_eq!(
        r.pointer("/text/format/schema/properties/x/type"),
        Some(&serde_json::json!("string"))
    );
    assert!(
        r.pointer("/text/format/json_schema").is_none(),
        "Responses text.format is FLAT, not nested under json_schema: {r}"
    );
}

/// And the read side: each protocol's NATIVE structured-output request canonicalizes into the
/// same typed directive — proving readers feed the agnostic IR, not a protocol-shaped blob.
#[test]
fn every_reader_canonicalizes_to_typed_ir() {
    let oi = OpenAiReader
            .read_request(&serde_json::json!({
                "messages":[{"role":"user","content":"hi"}],
                "response_format":{"type":"json_schema","json_schema":{"name":"out","schema":{"type":"object"}}}
            }))
            .unwrap();
    let rf = oi.response_format.unwrap();
    assert!(rf.json && rf.name.as_deref() == Some("out") && rf.schema.is_some());

    let co = CohereReader
        .read_request(&serde_json::json!({
            "model":"command-r",
            "messages":[{"role":"user","content":"hi"}],
            "response_format":{"type":"json_object","json_schema":{"type":"object"}}
        }))
        .unwrap();
    let rf = co.response_format.unwrap();
    assert!(rf.json && rf.schema.is_some());

    let ge = GeminiReader
            .read_request(&serde_json::json!({
                "contents":[{"role":"user","parts":[{"text":"hi"}]}],
                "generationConfig":{"responseMimeType":"application/json","responseSchema":{"type":"object"}}
            }))
            .unwrap();
    let rf = ge.response_format.unwrap();
    assert!(rf.json && rf.schema.is_some());

    let re = ResponsesReader
        .read_request(&serde_json::json!({
            "input":"hi",
            "text":{"format":{"type":"json_schema","name":"out","schema":{"type":"object"}}}
        }))
        .unwrap();
    let rf = re.response_format.unwrap();
    assert!(rf.json && rf.name.as_deref() == Some("out") && rf.schema.is_some());
}
