// SPDX-License-Identifier: AGPL-3.0-or-later
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
static EMB: BedrockEmbeddings = BedrockEmbeddings;
static IMG: BedrockImage = BedrockImage;

impl RequestHandler for BedrockRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "bedrock"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Embeddings => Some(&EMB),
            Operation::Image => Some(&IMG),
            Operation::Chat => Some(&crate::handlers::chat::CHAT_HANDLER),
            _ => None, // genuine gaps stay None → no-handler 404
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
            let has = |n: &[u8]| body.windows(n.len()).any(|w| w == n);
            if has(b"textToImageParams") {
                return Some(Operation::Image);
            }
            if has(b"inputText") {
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
                .map(|n| n as u32),
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
                .map(|d| d as u32),
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
            EmbInput::Text(v) => v.first().cloned().unwrap_or_default(), // Titan takes a single inputText
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
