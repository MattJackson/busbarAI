// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Bedrock `RequestHandler` + cells (design §6/§7). Embeddings first (Titan, via InvokeModel).
#![allow(dead_code)]

use crate::handlers::{
    CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler, WireBody,
};
use crate::ir::embeddings::{EmbInput, EmbeddingItem, EmbeddingsResp, EncFmt, VectorData};
use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;
use bytes::Bytes;
use serde_json::{json, Value};

pub(crate) struct BedrockRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: crate::handlers::chat::ChatOperation = crate::handlers::chat::ChatOperation("bedrock");
static EMB: BedrockEmbeddings = BedrockEmbeddings;
static IMG: BedrockImage = BedrockImage;
static RERANK: BedrockRerank = BedrockRerank;

impl RequestHandler for BedrockRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "bedrock"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Embeddings => Some(&EMB),
            Operation::Image => Some(&IMG),
            Operation::Rerank => Some(&RERANK),
            Operation::Chat => Some(&CHAT),
            // Enumerated (not `_`) so adding an operation is a compile error here — the documented
            // removability/symmetry gate. These are genuine gaps → no-handler 404.
            Operation::Moderation | Operation::Transcription | Operation::Speech => None,
        }
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        match ctx.operation {
            // Chat uses the Converse API (stream-aware); embeddings/images use InvokeModel.
            Operation::Chat => {
                let verb = if ctx.stream {
                    "converse-stream"
                } else {
                    "converse"
                };
                format!("/model/{}/{verb}", ctx.model)
            }
            _ => format!("/model/{}/invoke", ctx.model),
        }
    }
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<Operation> {
        // Converse is chat; InvokeModel multiplexes — the BODY names the op (Titan image vs Titan
        // embeddings). Unknown invoke bodies resolve to None (a clean 400 at the route layer).
        if path.ends_with("/converse") || path.ends_with("/converse-stream") {
            return Some(Operation::Chat);
        }
        if path.ends_with("/invoke") {
            // Anchor every scan to the QUOTED JSON key (`"key"`), not the bare token: an unanchored
            // `inputText` matched the substring inside a rerank query/document VALUE and misrouted the
            // whole request to embeddings. Check rerank (the two-key body) FIRST so a document that
            // merely mentions "inputText"/"textToImageParams" can't steal it.
            let has = |n: &[u8]| body.windows(n.len()).any(|w| w == n);
            // Rerank models (cohere.rerank-*, amazon.rerank-*) take {query, documents} — no
            // other InvokeModel body carries both keys.
            if has(b"\"query\"") && has(b"\"documents\"") {
                return Some(Operation::Rerank);
            }
            if has(b"\"textToImageParams\"") {
                return Some(Operation::Image);
            }
            if has(b"\"inputText\"") {
                return Some(Operation::Embeddings);
            }
        }
        None
    }
    fn path_model(&self, path: &str) -> Option<String> {
        // `/model/{model}/{converse|converse-stream|invoke}` — the middle segment.
        let rest = path.strip_prefix("/model/")?;
        let (model, _verb) = rest.rsplit_once('/')?;
        (!model.is_empty()).then(|| model.to_string())
    }
}

/// Amazon Titan Image Generator via `/model/{id}/invoke`. prompt in → `images[]` (b64) out.
struct BedrockImage;

impl OperationHandler for BedrockImage {
    /// Titan image `InvokeModel` wire → IR (bedrock as INGRESS). Model rides the PATH, not the body —
    /// the route layer resolves it; the IR's `model` is filled by routing (`IrReq::set_model`).
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let params = wire.get("textToImageParams").cloned().unwrap_or_default();
        let cfg = wire
            .get("imageGenerationConfig")
            .cloned()
            .unwrap_or_default();
        Ok(IrReq::Image(crate::ir::image::ImageReq {
            prompt: params
                .get("text")
                .and_then(Value::as_str)
                .map(str::to_string),
            negative_prompt: params
                .get("negativeText")
                .and_then(Value::as_str)
                .map(str::to_string),
            n: cfg
                .get("numberOfImages")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()),
            seed: cfg.get("seed").and_then(Value::as_u64),
            guidance_scale: cfg
                .get("cfgScale")
                .and_then(Value::as_f64)
                .map(|f| f as f32),
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Image(r) = ir else {
            return Bytes::new();
        };
        let body = json!({
            "taskType": "TEXT_IMAGE",
            "textToImageParams": { "text": r.prompt.clone().unwrap_or_default() },
            "imageGenerationConfig": { "numberOfImages": r.n.unwrap_or(1) },
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let images = v
            .get("images")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|b| b.as_str())
                    .map(|b| crate::media::ImageOutput {
                        b64: Some(b.to_string()),
                        ..Default::default()
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(IrResp::Image(crate::ir::image::ImageResp {
            images,
            ..Default::default()
        }))
    }
    /// IR → Titan image response (bedrock as INGRESS): `{"images": ["<b64>", …]}`.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Image(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let images: Vec<&str> = r.images.iter().filter_map(|i| i.b64.as_deref()).collect();
        WireBody::json(Bytes::from(
            serde_json::to_vec(&json!({ "images": images })).unwrap_or_default(),
        ))
    }
}

/// Amazon Titan Embeddings via `/model/{id}/invoke`.
struct BedrockEmbeddings;

impl OperationHandler for BedrockEmbeddings {
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
    /// Titan `InvokeModel` wire → IR (bedrock as INGRESS): `inputText` (+ v2 dims/normalize). Model
    /// rides the PATH; routing fills it via `IrReq::set_model`.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let Some(text) = wire.get("inputText").and_then(Value::as_str) else {
            return Err(IngressReject::BadRequest(
                "invoke embeddings requires `inputText`".into(),
            ));
        };
        Ok(IrReq::Embeddings(crate::ir::embeddings::EmbeddingsReq {
            input: EmbInput::Text(vec![text.to_string()]),
            dimensions: wire
                .get("dimensions")
                .and_then(Value::as_u64)
                .and_then(|d| u32::try_from(d).ok()),
            normalize: wire.get("normalize").and_then(Value::as_bool),
            encoding_formats: vec![EncFmt::Float],
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Embeddings(r) = ir else {
            return Bytes::new();
        };
        let text = match &r.input {
            EmbInput::Text(v) => {
                // Titan's InvokeModel embeddings takes a SINGLE `inputText`; a multi-input request
                // (OpenAI allows an array) can only embed the first here. Warn rather than silently
                // drop the rest — true multi-input fan-out to single-input backends is a 1.3 item.
                if v.len() > 1 {
                    tracing::warn!(
                        dropped = v.len() - 1,
                        "Titan embeddings takes one input; embedding only the first of a \
                         multi-input request (the rest are not sent)"
                    );
                }
                v.first().cloned().unwrap_or_default()
            }
            _ => String::new(),
        };
        let mut body = json!({ "inputText": text });
        if let Some(d) = r.dimensions {
            body["dimensions"] = json!(d);
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let mut item = EmbeddingItem::default();
        if let Some(f) = v.get("embedding").and_then(Value::as_array) {
            item.vectors.insert(
                EncFmt::Float,
                VectorData::Float(
                    f.iter()
                        .filter_map(|x| x.as_f64().map(|n| n as f32))
                        .collect(),
                ),
            );
        }
        let usage = v
            .get("inputTextTokenCount")
            .and_then(Value::as_u64)
            .map(|n| crate::billing::TokenUsage {
                input: n,
                ..Default::default()
            });
        Ok(IrResp::Embeddings(EmbeddingsResp {
            embeddings: vec![item],
            usage,
            ..Default::default()
        }))
    }
    /// IR → Titan embeddings response (bedrock as INGRESS): `embedding` + `inputTextTokenCount`.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Embeddings(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let floats: Vec<f32> = r
            .embeddings
            .first()
            .and_then(|item| match item.vectors.get(&EncFmt::Float) {
                Some(VectorData::Float(v)) => Some(v.clone()),
                _ => None,
            })
            .unwrap_or_default();
        let mut body = json!({ "embedding": floats });
        if let Some(u) = &r.usage {
            body["inputTextTokenCount"] = json!(u.input);
        }
        WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
    }
}

/// Bedrock rerank models (`cohere.rerank-*`, `amazon.rerank-*`) via `/model/{id}/invoke`:
/// `{query, documents[], top_n?, api_version}` → `{results: [{index, relevance_score}]}` — the
/// same result shape as Cohere's own `/v2/rerank`, so translation between the two is exact. The
/// model rides the URL (path-model protocol); `api_version: 2` is required by the cohere.rerank
/// models and harmless to amazon.rerank.
struct BedrockRerank;

impl OperationHandler for BedrockRerank {
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let query = wire
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let documents = crate::handlers::cohere::rerank_documents_pub(wire.get("documents"));
        if query.is_empty() || documents.is_empty() {
            return Err(IngressReject::BadRequest(
                "rerank request requires `query` and `documents`".into(),
            ));
        }
        Ok(IrReq::Rerank(crate::ir::rerank::RerankReq {
            // Path-model protocol: the model arrives via the URL and routing calls `set_model`.
            model: String::new(),
            query,
            documents,
            top_n: wire
                .get("top_n")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()),
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Rerank(r) = ir else {
            return Bytes::new();
        };
        let mut body = json!({
            "query": r.query,
            "documents": r.documents,
            "api_version": 2,
        });
        if let Some(n) = r.top_n {
            body["top_n"] = json!(n);
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        Ok(IrResp::Rerank(crate::ir::rerank::RerankResp {
            id: v.get("id").and_then(Value::as_str).map(str::to_string),
            results: crate::handlers::cohere::read_rerank_results(v.get("results")),
            ..Default::default()
        }))
    }
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Rerank(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let results: Vec<Value> = r
            .results
            .iter()
            .map(|x| json!({"index": x.index, "relevance_score": x.relevance_score}))
            .collect();
        let mut body = json!({ "results": results });
        if let Some(id) = &r.id {
            body["id"] = json!(id);
        }
        WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invoke_rerank_not_misclassified_by_inputtext_substring() {
        // A rerank body whose query/document text merely MENTIONS "inputText" must resolve to
        // Rerank (checked first, key-anchored), not be stolen by the embeddings substring scan.
        let h = BedrockRequestHandler;
        let body = br#"{"query":"how does inputText work?","documents":["textToImageParams too"]}"#;
        assert_eq!(
            h.resolve_operation("/model/cohere.rerank-v3-5:0/invoke", body),
            Some(Operation::Rerank),
        );
        // Real Titan embeddings (top-level inputText key) still resolves to Embeddings.
        assert_eq!(
            h.resolve_operation(
                "/model/amazon.titan-embed-text-v2:0/invoke",
                br#"{"inputText":"hello"}"#,
            ),
            Some(Operation::Embeddings),
        );
        // Real Titan image (top-level textToImageParams key) still resolves to Image.
        assert_eq!(
            h.resolve_operation(
                "/model/amazon.titan-image-generator-v1/invoke",
                br#"{"textToImageParams":{"text":"a cat"}}"#,
            ),
            Some(Operation::Image),
        );
        // Converse remains chat.
        assert_eq!(
            h.resolve_operation("/model/anthropic.claude/converse", b"{}"),
            Some(Operation::Chat),
        );
    }

    #[test]
    fn image_read_request_captures_prompt_and_count() {
        // Titan image InvokeModel body → IR Image with the prompt from textToImageParams.text and
        // n from imageGenerationConfig.numberOfImages.
        let body = br#"{"textToImageParams":{"text":"a cat"},"imageGenerationConfig":{"numberOfImages":2}}"#;
        let ir = BedrockImage
            .read_request(body, "application/json")
            .expect("valid titan image body");
        let IrReq::Image(r) = ir else {
            panic!("expected IrReq::Image");
        };
        assert_eq!(r.prompt.as_deref(), Some("a cat"));
        assert_eq!(r.n, Some(2));
    }

    #[test]
    fn embeddings_read_request_captures_input_text() {
        // Titan embeddings InvokeModel body → IR Embeddings carrying the inputText string.
        let ir = BedrockEmbeddings
            .read_request(br#"{"inputText":"hello"}"#, "application/json")
            .expect("valid titan embeddings body");
        let IrReq::Embeddings(r) = ir else {
            panic!("expected IrReq::Embeddings");
        };
        assert_eq!(r.input, EmbInput::Text(vec!["hello".to_string()]));
    }

    #[test]
    fn embeddings_read_request_without_input_text_is_bad_request() {
        // A Titan embeddings body missing the required inputText key must 400 at the trust
        // boundary, not resolve to an empty embed input.
        let err = BedrockEmbeddings
            .read_request(br#"{"dimensions":256}"#, "application/json")
            .expect_err("missing inputText must reject");
        assert!(matches!(err, IngressReject::BadRequest(_)));
    }

    #[test]
    fn embeddings_write_read_roundtrip_preserves_input_text() {
        // write_request emits `inputText`; read_request must recover the same input string.
        let req = IrReq::Embeddings(crate::ir::embeddings::EmbeddingsReq {
            input: EmbInput::Text(vec!["roundtrip".to_string()]),
            encoding_formats: vec![EncFmt::Float],
            ..Default::default()
        });
        let wire = BedrockEmbeddings.write_request(&req);
        let back = BedrockEmbeddings
            .read_request(&wire, "application/json")
            .expect("emitted body reparses");
        let IrReq::Embeddings(r) = back else {
            panic!("expected IrReq::Embeddings");
        };
        assert_eq!(r.input, EmbInput::Text(vec!["roundtrip".to_string()]));
    }
}
