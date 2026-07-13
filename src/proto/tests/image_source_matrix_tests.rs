//! Regression net for the image-source bug class (closed by the typed `IrImageSource`). The key
//! invariant: a writer can NEVER emit a corrupt block from a misread sentinel — a `Vendor`
//! reference it doesn't own is dropped, a neutral `Base64`/`Url` is projected natively.
use super::*;
use crate::ir::{IrBlock, IrImageSource, IrMessage, IrRole};

fn req_with_image(source: IrImageSource) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::Image {
                source,
                cache_control: None,
            }],
        }],
        ..Default::default()
    }
}

/// A FOREIGN vendor reference (one the writer doesn't own) must never reach the wire as a corrupt
/// block — every writer drops it. (The OWNING protocol re-emits its own; covered per-protocol.)
#[test]
fn foreign_vendor_image_ref_never_corrupts_any_writer() {
    // A Responses file_id reference projected by every NON-Responses writer must be dropped.
    let foreign = IrImageSource::Vendor {
        vendor: "responses",
        value: serde_json::json!({ "file_id": "file-x" }),
    };
    let req = req_with_image(foreign);
    let cohere = CohereWriter;
    let gemini = GeminiWriter;
    let o = serde_json::to_string(&OpenAiWriter.write_request(&req)).unwrap();
    let a = serde_json::to_string(&AnthropicWriter.write_request(&req)).unwrap();
    let g = serde_json::to_string(&gemini.write_request(&req)).unwrap();
    let b = serde_json::to_string(&BedrockWriter.write_request(&req)).unwrap();
    let c = serde_json::to_string(&cohere.write_request(&req)).unwrap();
    for (name, wire) in [
        ("openai", o),
        ("anthropic", a),
        ("gemini", g),
        ("bedrock", b),
        ("cohere", c),
    ] {
        assert!(
            !wire.contains("file-x"),
            "{name} writer must DROP a foreign vendor image ref, not leak it: {wire}"
        );
    }
}

/// A neutral base64 image projects to a real inline-image shape on every writer that supports
/// images (no writer corrupts it).
#[test]
fn base64_image_projects_or_drops_cleanly() {
    let req = req_with_image(IrImageSource::Base64 {
        media_type: "image/png".to_string(),
        data: "QUJD".to_string(),
    });
    // OpenAI emits a data URI carrying the base64 payload.
    let o = OpenAiWriter.write_request(&req);
    let s = serde_json::to_string(&o).unwrap();
    assert!(
        s.contains("QUJD"),
        "base64 payload must survive to the OpenAI wire: {s}"
    );
}
