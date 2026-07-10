// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Cohere `RequestHandler` + cells (design §6/§7). Embeddings via `/v2/embed`.
#![allow(dead_code)]

use crate::handlers::{
    CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler, WireBody,
};
use crate::ir::embeddings::{EmbInput, EmbeddingItem, EmbeddingsResp, EncFmt, VectorData};
use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;
use bytes::Bytes;
use serde_json::{json, Value};

pub(crate) struct CohereRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: crate::handlers::chat::ChatOperation = crate::handlers::chat::ChatOperation("cohere");
static EMB: CohereEmbeddings = CohereEmbeddings;

impl RequestHandler for CohereRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "cohere"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Embeddings => Some(&EMB),
            Operation::Chat => Some(&CHAT),
            _ => None,
        }
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        match ctx.operation {
            Operation::Chat => "/v2/chat".into(),
            _ => "/v2/embed".into(),
        }
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        if path.ends_with("/v2/chat") {
            Some(Operation::Chat)
        } else if path.ends_with("/v2/embed") {
            Some(Operation::Embeddings)
        } else {
            None
        }
    }
}

/// Cohere v2 embeddings (`/v2/embed`). `input_type` is required by Cohere; default to a document role.
struct CohereEmbeddings;

impl OperationHandler for CohereEmbeddings {
    /// cohere `/v2/embed` wire → IR (cohere as INGRESS): `texts[]` + required `input_type`.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let texts = wire
            .get("texts")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if texts.is_empty() {
            return Err(IngressReject::BadRequest(
                "embed request requires `texts`".into(),
            ));
        }
        let encoding_formats = wire
            .get("embedding_types")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str())
                    .map(|s| {
                        if s == "base64" {
                            EncFmt::Base64
                        } else {
                            EncFmt::Float
                        }
                    })
                    .collect()
            })
            .unwrap_or_else(|| vec![EncFmt::Float]);
        Ok(IrReq::Embeddings(crate::ir::embeddings::EmbeddingsReq {
            model: wire
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            input: EmbInput::Text(texts),
            input_type: wire
                .get("input_type")
                .and_then(Value::as_str)
                .map(str::to_string),
            dimensions: wire
                .get("output_dimension")
                .and_then(Value::as_u64)
                .map(|d| d as u32),
            truncate: wire
                .get("truncate")
                .and_then(Value::as_str)
                .map(str::to_string),
            encoding_formats,
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Embeddings(r) = ir else {
            return Bytes::new();
        };
        let texts = match &r.input {
            EmbInput::Text(v) => v.clone(),
            _ => Vec::new(),
        };
        let input_type = r
            .input_type
            .clone()
            .unwrap_or_else(|| "search_document".to_string());
        let body = json!({
            "model": r.model,
            "texts": texts,
            "input_type": input_type,
            "embedding_types": ["float"],
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let embeddings = v
            .get("embeddings")
            .and_then(|e| e.get("float"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .enumerate()
                    .map(|(idx, row)| {
                        let mut item = EmbeddingItem {
                            index: idx,
                            ..Default::default()
                        };
                        if let Some(f) = row.as_array() {
                            item.vectors.insert(
                                EncFmt::Float,
                                VectorData::Float(
                                    f.iter()
                                        .filter_map(|x| x.as_f64().map(|n| n as f32))
                                        .collect(),
                                ),
                            );
                        }
                        item
                    })
                    .collect()
            })
            .unwrap_or_default();
        let usage = v
            .get("meta")
            .and_then(|m| m.get("billed_units"))
            .and_then(|b| b.get("input_tokens"))
            .and_then(Value::as_u64)
            .map(|n| crate::billing::TokenUsage {
                input: n,
                ..Default::default()
            });
        Ok(IrResp::Embeddings(EmbeddingsResp {
            id: v.get("id").and_then(Value::as_str).map(str::to_string),
            embeddings,
            usage,
            ..Default::default()
        }))
    }
    /// IR → cohere v2 embed response (cohere as INGRESS): `embeddings.float[[..]]` + billed_units.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Embeddings(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let floats: Vec<Vec<f32>> = r
            .embeddings
            .iter()
            .filter_map(|item| match item.vectors.get(&EncFmt::Float) {
                Some(VectorData::Float(v)) => Some(v.clone()),
                _ => None,
            })
            .collect();
        let mut body = json!({
            "response_type": "embeddings_by_type",
            "embeddings": { "float": floats },
        });
        if let Some(id) = &r.id {
            body["id"] = json!(id);
        }
        if let Some(texts) = &r.input_echo {
            body["texts"] = json!(texts);
        }
        if let Some(u) = &r.usage {
            body["meta"] = json!({ "billed_units": { "input_tokens": u.input } });
        }
        WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
    }
}
