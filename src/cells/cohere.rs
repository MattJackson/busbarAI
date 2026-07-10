// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Cohere `RequestHandler` + cells (design §6/§7). Embeddings via `/v2/embed`.
#![allow(dead_code)]

use crate::handler::{CodecError, IngressReject, OperationHandler, RequestHandler};
use crate::ir::embeddings::{EmbInput, EmbeddingItem, EmbeddingsResp, EncFmt, VectorData};
use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;
use crate::state::Lane;
use bytes::Bytes;
use serde_json::{json, Value};

pub(crate) struct CohereRequestHandler;
static EMB: CohereEmbeddings = CohereEmbeddings;

impl RequestHandler for CohereRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "cohere"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Embeddings => Some(&EMB),
            _ => None,
        }
    }
}

/// Cohere v2 embeddings (`/v2/embed`). `input_type` is required by Cohere; default to a document role.
struct CohereEmbeddings;

impl OperationHandler for CohereEmbeddings {
    fn upstream_path(&self, lane: &Lane, _wants_stream: bool) -> String {
        lane.path.clone().unwrap_or_else(|| "/v2/embed".to_string())
    }
    fn read_request(&self, _wire: &Value) -> Result<IrReq, IngressReject> {
        Err(IngressReject::BadRequest("cohere embeddings is egress-only".into()))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Embeddings(r) = ir else { return Bytes::new() };
        let texts = match &r.input {
            EmbInput::Text(v) => v.clone(),
            _ => Vec::new(),
        };
        let input_type = r.input_type.clone().unwrap_or_else(|| "search_document".to_string());
        let body = json!({
            "model": r.model,
            "texts": texts,
            "input_type": input_type,
            "embedding_types": ["float"],
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value = serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let embeddings = v
            .get("embeddings")
            .and_then(|e| e.get("float"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .enumerate()
                    .map(|(idx, row)| {
                        let mut item = EmbeddingItem { index: idx, ..Default::default() };
                        if let Some(f) = row.as_array() {
                            item.vectors.insert(
                                EncFmt::Float,
                                VectorData::Float(f.iter().filter_map(|x| x.as_f64().map(|n| n as f32)).collect()),
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
            .map(|n| crate::billing::TokenUsage { input: n, ..Default::default() });
        Ok(IrResp::Embeddings(EmbeddingsResp {
            id: v.get("id").and_then(Value::as_str).map(str::to_string),
            embeddings,
            usage,
            ..Default::default()
        }))
    }
    fn write_response(&self, _ir: &IrResp) -> Bytes {
        Bytes::new()
    }
}
