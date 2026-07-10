// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Bedrock `RequestHandler` + cells (design §6/§7). Embeddings first (Titan, via InvokeModel).
#![allow(dead_code)]

use crate::handler::{CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler, WireBody};
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
            Operation::Chat => Some(&crate::cells::chat::CHAT_HANDLER),
            _ => None, // genuine gaps stay None → no-cell 404
        }
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        match ctx.operation {
            // Chat uses the Converse API (stream-aware); embeddings/images use InvokeModel.
            Operation::Chat => {
                let verb = if ctx.stream { "converse-stream" } else { "converse" };
                format!("/model/{}/{verb}", ctx.model)
            }
            _ => format!("/model/{}/invoke", ctx.model),
        }
    }
}

/// Amazon Titan Image Generator via `/model/{id}/invoke`. prompt in → `images[]` (b64) out.
struct BedrockImage;

impl OperationHandler for BedrockImage {
    fn read_request(&self, _body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        Err(IngressReject::BadRequest("bedrock image is egress-only".into()))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Image(r) = ir else { return Bytes::new() };
        let body = json!({
            "taskType": "TEXT_IMAGE",
            "textToImageParams": { "text": r.prompt.clone().unwrap_or_default() },
            "imageGenerationConfig": { "numberOfImages": r.n.unwrap_or(1) },
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value = serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let images = v
            .get("images")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|b| b.as_str())
                    .map(|b| crate::media::ImageOutput { b64: Some(b.to_string()), ..Default::default() })
                    .collect()
            })
            .unwrap_or_default();
        Ok(IrResp::Image(crate::ir::image::ImageResp { images, ..Default::default() }))
    }
    fn write_response(&self, _ir: &IrResp) -> WireBody {
        WireBody::json(Bytes::new())
    }
}

/// Amazon Titan Embeddings via `/model/{id}/invoke`. Egress-only in the harness (openai→bedrock).
struct BedrockEmbeddings;

impl OperationHandler for BedrockEmbeddings {
    fn read_request(&self, _body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        Err(IngressReject::BadRequest("bedrock embeddings is egress-only".into()))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Embeddings(r) = ir else { return Bytes::new() };
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
        let v: Value = serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let mut item = EmbeddingItem::default();
        if let Some(f) = v.get("embedding").and_then(Value::as_array) {
            item.vectors.insert(
                EncFmt::Float,
                VectorData::Float(f.iter().filter_map(|x| x.as_f64().map(|n| n as f32)).collect()),
            );
        }
        let usage = v
            .get("inputTextTokenCount")
            .and_then(Value::as_u64)
            .map(|n| crate::billing::TokenUsage { input: n, ..Default::default() });
        Ok(IrResp::Embeddings(EmbeddingsResp { embeddings: vec![item], usage, ..Default::default() }))
    }
    fn write_response(&self, _ir: &IrResp) -> WireBody {
        WireBody::json(Bytes::new())
    }
}
