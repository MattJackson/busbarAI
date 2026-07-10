// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Gemini `RequestHandler` + cells (design §6/§7). Embeddings via `models/{id}:embedContent`.
#![allow(dead_code)]

use crate::handler::{CodecError, IngressReject, OperationHandler, RequestHandler};
use crate::ir::embeddings::{EmbInput, EmbeddingItem, EmbeddingsResp, EncFmt, VectorData};
use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;
use crate::state::Lane;
use bytes::Bytes;
use serde_json::{json, Value};

pub(crate) struct GeminiRequestHandler;
static EMB: GeminiEmbeddings = GeminiEmbeddings;
static IMG: GeminiImage = GeminiImage;

impl RequestHandler for GeminiRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "gemini"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Embeddings => Some(&EMB),
            Operation::Image => Some(&IMG),
            _ => None,
        }
    }
}

/// Gemini/Imagen image generation (`models/{id}:predict`). prompt in → `predictions[].bytesBase64Encoded` out.
struct GeminiImage;

impl OperationHandler for GeminiImage {
    fn upstream_path(&self, lane: &Lane, _wants_stream: bool) -> String {
        lane.path
            .clone()
            .unwrap_or_else(|| format!("/v1beta/models/{}:predict", lane.wire_model()))
    }
    fn read_request(&self, _wire: &Value) -> Result<IrReq, IngressReject> {
        Err(IngressReject::BadRequest("gemini image is egress-only".into()))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Image(r) = ir else { return Bytes::new() };
        let body = json!({
            "instances": [{ "prompt": r.prompt.clone().unwrap_or_default() }],
            "parameters": { "sampleCount": r.n.unwrap_or(1) },
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value = serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let images = v
            .get("predictions")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|p| crate::media::ImageOutput {
                        b64: p.get("bytesBase64Encoded").and_then(Value::as_str).map(str::to_string),
                        mime_type: p.get("mimeType").and_then(Value::as_str).map(str::to_string),
                        ..Default::default()
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(IrResp::Image(crate::ir::image::ImageResp { images, ..Default::default() }))
    }
    fn write_response(&self, _ir: &IrResp) -> Bytes {
        Bytes::new()
    }
}

/// Gemini embeddings (`models/{id}:embedContent`). Single content in, `embedding.values` out.
struct GeminiEmbeddings;

impl OperationHandler for GeminiEmbeddings {
    fn upstream_path(&self, lane: &Lane, _wants_stream: bool) -> String {
        lane.path
            .clone()
            .unwrap_or_else(|| format!("/v1beta/models/{}:embedContent", lane.wire_model()))
    }
    fn read_request(&self, _wire: &Value) -> Result<IrReq, IngressReject> {
        Err(IngressReject::BadRequest("gemini embeddings is egress-only".into()))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Embeddings(r) = ir else { return Bytes::new() };
        let text = match &r.input {
            EmbInput::Text(v) => v.first().cloned().unwrap_or_default(),
            _ => String::new(),
        };
        let body = json!({ "content": { "parts": [{ "text": text }] } });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value = serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let mut item = EmbeddingItem::default();
        if let Some(f) = v.get("embedding").and_then(|e| e.get("values")).and_then(Value::as_array) {
            item.vectors.insert(
                EncFmt::Float,
                VectorData::Float(f.iter().filter_map(|x| x.as_f64().map(|n| n as f32)).collect()),
            );
        }
        let usage = v
            .get("usageMetadata")
            .and_then(|u| u.get("promptTokenCount"))
            .and_then(Value::as_u64)
            .map(|n| crate::billing::TokenUsage { input: n, ..Default::default() });
        Ok(IrResp::Embeddings(EmbeddingsResp { embeddings: vec![item], usage, ..Default::default() }))
    }
    fn write_response(&self, _ir: &IrResp) -> Bytes {
        Bytes::new()
    }
}
