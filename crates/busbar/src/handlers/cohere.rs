// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

/// Endpoint paths — each appears on BOTH the egress side (`upstream_path`) and the ingress match
/// (`resolve_operation`); single-sourced so the two sides cannot drift.
const PATH_CHAT: &str = "/v2/chat";
const PATH_EMBED: &str = "/v2/embed";
const PATH_RERANK: &str = "/v2/rerank";

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
            // Enumerated (not `_`) so adding an operation is a compile error here — the documented
            // removability/symmetry gate. Cohere has no moderation/image/audio surface.
            Operation::Moderation
            | Operation::Image
            | Operation::Transcription
            | Operation::Speech => None,
        }
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        match ctx.operation {
            Operation::Chat => PATH_CHAT.into(),
            Operation::Rerank => PATH_RERANK.into(),
            Operation::Embeddings => PATH_EMBED.into(),
            // Enumerated (not `_`) so adding an operation is a compile error here — the same
            // removability/symmetry gate operation_handler enforces. Unreachable: operation_handler
            // returns None for these, so egress path resolution is never reached.
            Operation::Moderation
            | Operation::Image
            | Operation::Transcription
            | Operation::Speech => PATH_EMBED.into(),
        }
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        if path.ends_with(PATH_CHAT) {
            Some(Operation::Chat)
        } else if path.ends_with(PATH_EMBED) {
            Some(Operation::Embeddings)
        } else if path.ends_with(PATH_RERANK) {
            Some(Operation::Rerank)
        } else {
            None
        }
    }
}

/// Cohere `embedding_types` name for an IR encoding — a 1:1 mapping (Cohere v2 supports exactly
/// these six), so a requested encoding is served natively instead of downgraded to float.
fn cohere_embedding_type(f: &EncFmt) -> &'static str {
    match f {
        EncFmt::Float => "float",
        EncFmt::Base64 => "base64",
        EncFmt::Int8 => "int8",
        EncFmt::Uint8 => "uint8",
        EncFmt::Binary => "binary",
        EncFmt::Ubinary => "ubinary",
    }
}

/// Every IR encoding Cohere's `/v2/embed` supports, for iterating the response keys.
const ALL_ENCODINGS: [EncFmt; 6] = [
    EncFmt::Float,
    EncFmt::Base64,
    EncFmt::Int8,
    EncFmt::Uint8,
    EncFmt::Binary,
    EncFmt::Ubinary,
];

/// Inverse of [`cohere_embedding_type`]: a Cohere `embedding_types` wire string → IR encoding. The
/// full 1:1 map (not just base64), so an `int8`/`uint8`/`binary`/`ubinary` ask is not silently
/// collapsed to float on the read side. Unknown strings fall back to float.
fn cohere_encoding_format(s: &str) -> EncFmt {
    match s {
        "base64" => EncFmt::Base64,
        "int8" => EncFmt::Int8,
        "uint8" => EncFmt::Uint8,
        "binary" => EncFmt::Binary,
        "ubinary" => EncFmt::Ubinary,
        _ => EncFmt::Float,
    }
}

/// Cohere v2 embeddings (`/v2/embed`). `input_type` is required by Cohere; default to a document role.
struct CohereEmbeddings;

impl OperationHandler for CohereEmbeddings {
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
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
                    .map(cohere_encoding_format)
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
        // Honor the caller's requested encoding(s): Cohere's `embedding_types` map 1:1 to the IR
        // `EncFmt` variants, so a base64 ask is served natively rather than silently downgraded to
        // float (the same drop that was fixed for the OpenAI egress writer). Default to float.
        let embedding_types: Vec<&str> = if r.encoding_formats.is_empty() {
            vec!["float"]
        } else {
            r.encoding_formats
                .iter()
                .map(cohere_embedding_type)
                .collect()
        };
        let mut body = json!({
            "model": r.model,
            "texts": texts,
            "input_type": input_type,
            "embedding_types": embedding_types,
        });
        // Carry the shape/truncation controls the reader captures (Cohere is the lone embeddings
        // writer that was dropping these): `output_dimension` (Matryoshka on embed-v4) and `truncate`.
        if let Some(d) = r.dimensions {
            body["output_dimension"] = json!(d);
        }
        if let Some(t) = &r.truncate {
            body["truncate"] = json!(t);
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        // Cohere returns each requested encoding under its own key (`embeddings.float`,
        // `embeddings.base64`, `embeddings.int8`, ...), positionally aligned. Read EVERY encoding the
        // request leg can ask for — float, base64, and the four integer forms — so an int8/uint8/
        // binary/ubinary response is not silently dropped (its `float` key is absent when only that
        // encoding was requested). Float -> Float, base64 -> Base64, the int forms -> Int.
        let emb = v.get("embeddings");
        let arrays: Vec<(EncFmt, &Vec<Value>)> = ALL_ENCODINGS
            .iter()
            .filter_map(|&e| {
                emb.and_then(|o| o.get(cohere_embedding_type(&e)))
                    .and_then(Value::as_array)
                    .map(|a| (e, a))
            })
            .collect();
        let count = arrays.iter().map(|(_, a)| a.len()).max().unwrap_or(0);
        let embeddings: Vec<EmbeddingItem> = (0..count)
            .map(|idx| {
                let mut item = EmbeddingItem {
                    index: idx,
                    ..Default::default()
                };
                for (enc, arr) in &arrays {
                    let Some(cell) = arr.get(idx) else { continue };
                    let vd = match enc {
                        EncFmt::Float => cell.as_array().map(|f| {
                            VectorData::Float(
                                f.iter()
                                    .filter_map(|x| x.as_f64().map(|n| n as f32))
                                    .collect(),
                            )
                        }),
                        EncFmt::Base64 => cell.as_str().map(|s| VectorData::Base64(s.to_string())),
                        // int8/uint8/binary/ubinary all arrive as JSON integer arrays.
                        _ => cell.as_array().map(|f| {
                            VectorData::Int(
                                f.iter()
                                    .filter_map(|x| x.as_i64().map(|n| n as i32))
                                    .collect(),
                            )
                        }),
                    };
                    if let Some(vd) = vd {
                        item.vectors.insert(*enc, vd);
                    }
                }
                item
            })
            .collect();
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
        // Emit every encoding the IR carries under its own Cohere key (`float`, `base64`, `int8`,
        // ...), so an int8/base64/etc. response (e.g. from a cross-protocol backend) is not silently
        // dropped — the write twin of the six-encoding read. Cohere's `embeddings_by_type` shape
        // holds multiple keys, each a per-item array in candidate order.
        let mut by_enc: std::collections::BTreeMap<EncFmt, Vec<Value>> =
            std::collections::BTreeMap::new();
        for item in &r.embeddings {
            for (enc, vd) in &item.vectors {
                let cell = match vd {
                    VectorData::Float(v) => json!(v),
                    VectorData::Base64(s) => json!(s),
                    VectorData::Int(v) => json!(v),
                };
                by_enc.entry(*enc).or_default().push(cell);
            }
        }
        let mut emb = serde_json::Map::new();
        for (enc, vals) in &by_enc {
            emb.insert(cohere_embedding_type(enc).to_string(), json!(vals));
        }
        // Emit an empty `float` key when the IR carried no vectors, for response-shape stability.
        if emb.is_empty() {
            emb.insert("float".to_string(), json!(Vec::<Vec<f32>>::new()));
        }
        let mut body = json!({
            "response_type": "embeddings_by_type",
            "embeddings": emb,
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

    #[test]
    fn embeddings_write_request_emits_base64_encoding_type() {
        use crate::ir::embeddings::EmbeddingsReq;
        let ir = IrReq::Embeddings(EmbeddingsReq {
            model: "embed-v4".into(),
            input: EmbInput::Text(vec!["a".into()]),
            encoding_formats: vec![EncFmt::Base64],
            ..Default::default()
        });
        let out = CohereEmbeddings.write_request(&ir);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["embedding_types"], json!(["base64"]));
    }

    #[test]
    fn embeddings_write_request_defaults_to_float_when_empty() {
        use crate::ir::embeddings::EmbeddingsReq;
        let ir = IrReq::Embeddings(EmbeddingsReq {
            model: "embed-v4".into(),
            input: EmbInput::Text(vec!["a".into()]),
            encoding_formats: vec![],
            ..Default::default()
        });
        let out = CohereEmbeddings.write_request(&ir);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["embedding_types"], json!(["float"]));
    }

    #[test]
    fn embeddings_write_request_preserves_multiple_encoding_types_in_order() {
        use crate::ir::embeddings::EmbeddingsReq;
        let ir = IrReq::Embeddings(EmbeddingsReq {
            model: "embed-v4".into(),
            input: EmbInput::Text(vec!["a".into()]),
            encoding_formats: vec![EncFmt::Float, EncFmt::Base64],
            ..Default::default()
        });
        let out = CohereEmbeddings.write_request(&ir);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["embedding_types"], json!(["float", "base64"]));
    }

    #[test]
    fn embeddings_read_response_reads_base64_vectors() {
        let body = serde_json::to_vec(&json!({
            "id": "x",
            "embeddings": {"base64": ["AAAA", "BBBB"]}
        }))
        .unwrap();
        let ir = CohereEmbeddings.read_response(&body).expect("parses");
        let IrResp::Embeddings(r) = ir else {
            panic!("expected embeddings")
        };
        assert_eq!(r.embeddings.len(), 2);
        assert_eq!(
            r.embeddings[0].vectors[&EncFmt::Base64],
            VectorData::Base64("AAAA".into())
        );
        assert_eq!(
            r.embeddings[1].vectors[&EncFmt::Base64],
            VectorData::Base64("BBBB".into())
        );
    }

    #[test]
    fn embeddings_response_roundtrips_int8_not_dropped() {
        // int8/uint8/binary/ubinary arrive as integer arrays and must NOT be dropped on the
        // response leg (they used to yield count=0 -> empty embeddings).
        let body = serde_json::to_vec(&json!({
            "id": "x",
            "embeddings": {"int8": [[1, 2, 3], [4, 5, 6]]}
        }))
        .unwrap();
        let ir = CohereEmbeddings.read_response(&body).expect("parses");
        let IrResp::Embeddings(r) = &ir else {
            panic!("expected embeddings")
        };
        assert_eq!(r.embeddings.len(), 2, "int8 response must not be empty");
        assert!(matches!(
            r.embeddings[0].vectors.get(&EncFmt::Int8),
            Some(VectorData::Int(_))
        ));
        // write_response re-emits the int8 key, not an empty float array.
        let out = CohereEmbeddings.write_response(&ir);
        let v: Value = serde_json::from_slice(&out.bytes).unwrap();
        assert!(v["embeddings"]["int8"].is_array(), "int8 key emitted: {v}");
        assert!(
            v["embeddings"].get("float").is_none(),
            "no spurious float key: {v}"
        );
        let _ = EmbeddingsResp::default();
    }

    #[test]
    fn embeddings_read_response_reads_float_vectors() {
        let body = serde_json::to_vec(&json!({
            "embeddings": {"float": [[0.1, 0.2]]}
        }))
        .unwrap();
        let ir = CohereEmbeddings.read_response(&body).expect("parses");
        let IrResp::Embeddings(r) = ir else {
            panic!("expected embeddings")
        };
        assert_eq!(r.embeddings.len(), 1);
        assert!(matches!(
            r.embeddings[0].vectors[&EncFmt::Float],
            VectorData::Float(_)
        ));
    }

    #[test]
    fn embeddings_write_response_emits_base64_key_not_swallowed_by_empty_float() {
        use crate::ir::embeddings::EmbeddingsResp;
        let mut item = EmbeddingItem {
            index: 0,
            ..Default::default()
        };
        item.vectors
            .insert(EncFmt::Base64, VectorData::Base64("AAAA".into()));
        let ir = IrResp::Embeddings(EmbeddingsResp {
            embeddings: vec![item],
            ..Default::default()
        });
        let out = CohereEmbeddings.write_response(&ir);
        let v: Value = serde_json::from_slice(&out.bytes).unwrap();
        assert_eq!(v["embeddings"]["base64"], json!(["AAAA"]));
        // A base64-only response must NOT emit an empty `float` array that swallows it.
        assert!(v["embeddings"].get("float").is_none());
    }

    #[test]
    fn embeddings_write_response_emits_float_key() {
        use crate::ir::embeddings::EmbeddingsResp;
        let mut item = EmbeddingItem {
            index: 0,
            ..Default::default()
        };
        item.vectors
            .insert(EncFmt::Float, VectorData::Float(vec![0.1, 0.2]));
        let ir = IrResp::Embeddings(EmbeddingsResp {
            embeddings: vec![item],
            ..Default::default()
        });
        let out = CohereEmbeddings.write_response(&ir);
        let v: Value = serde_json::from_slice(&out.bytes).unwrap();
        assert!(v["embeddings"].get("float").is_some());
        let row = v["embeddings"]["float"][0].as_array().expect("float row");
        assert_eq!(row.len(), 2);
        // f32 round-trip: compare with tolerance rather than exact f64 literals.
        assert!((row[0].as_f64().unwrap() - 0.1).abs() < 1e-6);
        assert!((row[1].as_f64().unwrap() - 0.2).abs() < 1e-6);
    }

    #[test]
    fn embeddings_read_request_parses_texts() {
        let body = serde_json::to_vec(&json!({
            "model": "m",
            "texts": ["a", "b"],
            "input_type": "search_query"
        }))
        .unwrap();
        let ir = CohereEmbeddings
            .read_request(&body, "application/json")
            .expect("parses");
        let IrReq::Embeddings(r) = ir else {
            panic!("expected embeddings")
        };
        assert_eq!(r.input, EmbInput::Text(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn embeddings_read_request_rejects_missing_texts() {
        let body = serde_json::to_vec(&json!({"model": "m"})).unwrap();
        let err = CohereEmbeddings
            .read_request(&body, "application/json")
            .expect_err("missing texts must reject");
        assert!(matches!(err, IngressReject::BadRequest(_)));
    }

    #[test]
    fn embeddings_read_request_maps_all_encoding_types_not_just_base64() {
        // Every Cohere embedding_type must map to its IR variant, not collapse to Float. int8/
        // uint8/binary/ubinary were silently downgraded before (only base64 was handled).
        for (wire, want) in [
            ("float", EncFmt::Float),
            ("base64", EncFmt::Base64),
            ("int8", EncFmt::Int8),
            ("uint8", EncFmt::Uint8),
            ("binary", EncFmt::Binary),
            ("ubinary", EncFmt::Ubinary),
        ] {
            let body = serde_json::to_vec(&json!({
                "model": "m", "texts": ["x"], "input_type": "search_query",
                "embedding_types": [wire]
            }))
            .unwrap();
            let IrReq::Embeddings(r) = CohereEmbeddings
                .read_request(&body, "application/json")
                .expect("parses")
            else {
                panic!("expected embeddings")
            };
            assert_eq!(r.encoding_formats, vec![want], "encoding_type {wire}");
        }
    }

    #[test]
    fn embeddings_write_request_carries_output_dimension_and_truncate() {
        // Cohere was the lone embeddings writer dropping these; they must reach the wire so a
        // Matryoshka (output_dimension) or explicit truncate request is honored.
        use crate::ir::embeddings::{EmbeddingsReq, EncFmt};
        let ir = IrReq::Embeddings(EmbeddingsReq {
            model: "embed-v4.0".into(),
            input: EmbInput::Text(vec!["x".into()]),
            dimensions: Some(256),
            truncate: Some("NONE".into()),
            encoding_formats: vec![EncFmt::Int8],
            ..Default::default()
        });
        let out = CohereEmbeddings.write_request(&ir);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["output_dimension"], 256);
        assert_eq!(v["truncate"], "NONE");
        assert_eq!(v["embedding_types"], json!(["int8"]));
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
