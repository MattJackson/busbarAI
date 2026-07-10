// SPDX-License-Identifier: Apache-2.0
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
static RERANK: CohereRerank = CohereRerank;

impl RequestHandler for CohereRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "cohere"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Embeddings => Some(&EMB),
            Operation::Rerank => Some(&RERANK),
            Operation::Chat => Some(&CHAT),
            _ => None,
        }
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        match ctx.operation {
            Operation::Chat => "/v2/chat".into(),
            Operation::Rerank => "/v2/rerank".into(),
            _ => "/v2/embed".into(),
        }
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        if path.ends_with("/v2/chat") {
            Some(Operation::Chat)
        } else if path.ends_with("/v2/embed") {
            Some(Operation::Embeddings)
        } else if path.ends_with("/v2/rerank") {
            Some(Operation::Rerank)
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
                .and_then(|d| u32::try_from(d).ok()),
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

/// Cohere v2 rerank (`/v2/rerank`): `{model, query, documents[], top_n?}` →
/// `{results: [{index, relevance_score}], meta.billed_units.search_units}`. Documents arrive as
/// bare strings or `{text}` objects; both normalize to strings.
struct CohereRerank;

pub(crate) fn rerank_documents_pub(v: Option<&Value>) -> Vec<String> {
    rerank_documents(v)
}

fn rerank_documents(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|d| {
                    d.as_str()
                        .map(str::to_string)
                        .or_else(|| d.get("text").and_then(Value::as_str).map(str::to_string))
                })
                .collect()
        })
        .unwrap_or_default()
}

impl OperationHandler for CohereRerank {
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let query = wire
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let documents = rerank_documents(wire.get("documents"));
        if query.is_empty() || documents.is_empty() {
            return Err(IngressReject::BadRequest(
                "rerank request requires `query` and `documents`".into(),
            ));
        }
        Ok(IrReq::Rerank(crate::ir::rerank::RerankReq {
            model: wire
                .get("model")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            query,
            documents,
            top_n: wire
                .get("top_n")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()),
            max_tokens_per_doc: wire
                .get("max_tokens_per_doc")
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
            "model": r.model,
            "query": r.query,
            "documents": r.documents,
        });
        if let Some(n) = r.top_n {
            body["top_n"] = json!(n);
        }
        if let Some(m) = r.max_tokens_per_doc {
            body["max_tokens_per_doc"] = json!(m);
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        Ok(IrResp::Rerank(crate::ir::rerank::RerankResp {
            id: v.get("id").and_then(Value::as_str).map(str::to_string),
            results: read_rerank_results(v.get("results")),
            search_units: v
                .get("meta")
                .and_then(|m| m.get("billed_units"))
                .and_then(|b| b.get("search_units"))
                .and_then(Value::as_u64),
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
        if let Some(su) = r.search_units {
            body["meta"] = json!({ "billed_units": { "search_units": su } });
        }
        WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
    }
}

/// `results[] -> [{index, relevance_score}]` — shared by the Cohere and Bedrock rerank readers
/// (the two wires use the same result shape).
pub(crate) fn read_rerank_results(v: Option<&Value>) -> Vec<crate::ir::rerank::RerankResult> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    Some(crate::ir::rerank::RerankResult {
                        index: x.get("index").and_then(Value::as_u64)? as usize,
                        relevance_score: x.get("relevance_score").and_then(Value::as_f64)?,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod rerank_tests {
    //! The seventh operation, round-tripped through the IR: cohere <-> bedrock are the two rerank
    //! wires, and their result shapes are identical, so translation must be exact both ways.
    use super::*;
    use crate::handlers::bedrock::BedrockRequestHandler;

    fn cohere_wire() -> Vec<u8> {
        serde_json::to_vec(&json!({
            "model": "rerank-v3.5",
            "query": "what is a busbar",
            "documents": ["a metal bar", {"text": "a fish"}, "a conductor"],
            "top_n": 2
        }))
        .unwrap()
    }

    /// cohere ingress -> bedrock egress: query/documents/top_n cross; api_version added; the
    /// {text} object form normalizes to a bare string.
    #[test]
    fn cohere_request_reaches_bedrock() {
        let rh = CohereRequestHandler;
        assert_eq!(
            rh.resolve_operation("/v2/rerank", b"{}"),
            Some(Operation::Rerank)
        );
        let ir = rh
            .operation_handler(Operation::Rerank)
            .unwrap()
            .read_request(&cohere_wire(), "application/json")
            .expect("parses");
        let bh = BedrockRequestHandler;
        let out = bh
            .operation_handler(Operation::Rerank)
            .unwrap()
            .write_request(&ir);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["query"], "what is a busbar");
        assert_eq!(v["documents"][1], "a fish");
        assert_eq!(v["top_n"], 2);
        assert_eq!(v["api_version"], 2);
    }

    /// bedrock ingress (invoke body-detect) -> cohere egress; and the response comes back exact.
    #[test]
    fn bedrock_request_and_response_round_trip() {
        let bh = BedrockRequestHandler;
        let body = serde_json::to_vec(&json!({
            "query": "q", "documents": ["a", "b"], "top_n": 1
        }))
        .unwrap();
        assert_eq!(
            bh.resolve_operation("/model/cohere.rerank-v3-5:0/invoke", &body),
            Some(Operation::Rerank)
        );
        let ir = bh
            .operation_handler(Operation::Rerank)
            .unwrap()
            .read_request(&body, "application/json")
            .expect("parses");
        let ch = CohereRequestHandler;
        let out = ch
            .operation_handler(Operation::Rerank)
            .unwrap()
            .write_request(&ir);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["query"], "q");
        assert_eq!(v["documents"], json!(["a", "b"]));

        // Response: cohere wire -> IR -> bedrock wire preserves index + relevance_score exactly.
        let resp = serde_json::to_vec(&json!({
            "id": "r1",
            "results": [
                {"index": 2, "relevance_score": 0.98},
                {"index": 0, "relevance_score": 0.11}
            ],
            "meta": {"billed_units": {"search_units": 1}}
        }))
        .unwrap();
        let ir_resp = ch
            .operation_handler(Operation::Rerank)
            .unwrap()
            .read_response(&resp)
            .expect("parses");
        let wire = bh
            .operation_handler(Operation::Rerank)
            .unwrap()
            .write_response(&ir_resp);
        let v: Value = serde_json::from_slice(&wire.bytes).unwrap();
        assert_eq!(v["results"][0]["index"], 2);
        assert_eq!(v["results"][0]["relevance_score"], 0.98);
        assert_eq!(v["results"][1]["index"], 0);
    }

    /// A client top_n larger than u32::MAX must DROP to None (omitted), never silently wrap to a
    /// bogus small value — the checked-narrowing contract for all client-supplied counts.
    #[test]
    fn oversized_top_n_drops_to_none_not_wrapped() {
        let body = serde_json::to_vec(&json!({
            "model": "rerank-v3.5", "query": "q", "documents": ["a", "b"],
            "top_n": u64::from(u32::MAX) + 1
        }))
        .unwrap();
        let ir = CohereRequestHandler
            .operation_handler(Operation::Rerank)
            .unwrap()
            .read_request(&body, "application/json")
            .expect("parses");
        let IrReq::Rerank(r) = ir else {
            panic!("expected rerank")
        };
        assert_eq!(
            r.top_n, None,
            "an out-of-range top_n must be omitted, not wrapped"
        );
    }

    /// Protocols without a rerank surface have NO handler: the universal no-handler 404 covers
    /// ingress and egress alike (the deletion-switch symmetry).
    #[test]
    fn no_rerank_handler_on_the_other_four() {
        for proto in ["openai", "anthropic", "gemini", "responses"] {
            let rh = crate::handlers::request_handler(proto).expect(proto);
            assert!(
                rh.operation_handler(Operation::Rerank).is_none(),
                "{proto} must have no rerank handler"
            );
        }
    }
}
