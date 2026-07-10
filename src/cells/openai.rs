// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! OpenAI `RequestHandler` and its operation cells (design §6/§7). Per the design these live under
//! `handlers/request/openai/operations/`; the flat `cells/openai.rs` layout is a deferred cosmetic
//! move. Cells are pure codecs — wire ↔ IR, both directions, nothing else.
//!
//! First cell: moderation (openai-only, K=1). More openai cells (embeddings/images/audio/chat) are
//! added here as they're built.
#![allow(dead_code)]

use crate::handler::{CodecError, IngressReject, OperationHandler, RequestHandler};
use crate::ir::moderation::{ModerationInput, ModerationReq, ModerationResp, ModerationResult};
use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;
use crate::state::Lane;
use bytes::Bytes;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) struct OpenAiRequestHandler;

static MODERATION: OpenAiModeration = OpenAiModeration;
static EMBEDDINGS: OpenAiEmbeddings = OpenAiEmbeddings;
static IMAGE: OpenAiImage = OpenAiImage;
static TRANSCRIPTION: OpenAiTranscription = OpenAiTranscription;
static SPEECH: OpenAiSpeech = OpenAiSpeech;

impl RequestHandler for OpenAiRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "openai"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Moderation => Some(&MODERATION),
            Operation::Embeddings => Some(&EMBEDDINGS),
            Operation::Image => Some(&IMAGE),
            Operation::Transcription => Some(&TRANSCRIPTION),
            Operation::Speech => Some(&SPEECH),
            // chat re-homes onto a cell in the final P4 step (OpSpec removal).
            Operation::Chat => None,
        }
    }
}

// The embeddings/image/audio cells below are registered so their SAME-protocol (openai→openai) rows go
// green now (v1 `forward_operation` relays the body verbatim same-proto and uses only `upstream_path`).
// Their wire↔IR codecs are exercised on the CROSS-protocol path; until that bridge lands they fail LOUD
// (a clear error, never a silent mistranslation). Same-proto correctness is proven by the harness now.

macro_rules! passthrough_cell {
    ($ty:ident, $path:literal, $op:literal) => {
        struct $ty;
        impl OperationHandler for $ty {
            fn upstream_path(&self, lane: &Lane, _wants_stream: bool) -> String {
                lane.path.clone().unwrap_or_else(|| $path.to_string())
            }
            fn read_request(&self, _wire: &Value) -> Result<IrReq, IngressReject> {
                Err(IngressReject::BadRequest(concat!($op, " cross-protocol codec not yet implemented").into()))
            }
            fn write_request(&self, _ir: &IrReq) -> Bytes {
                Bytes::new()
            }
            fn read_response(&self, _wire: &[u8]) -> Result<IrResp, CodecError> {
                Err(CodecError::Malformed(concat!($op, " cross-protocol codec not yet implemented").into()))
            }
            fn write_response(&self, _ir: &IrResp) -> Bytes {
                Bytes::new()
            }
        }
    };
}

passthrough_cell!(OpenAiTranscription, "/v1/audio/transcriptions", "transcription");
passthrough_cell!(OpenAiSpeech, "/v1/audio/speech", "speech");

// -------------------------------------------------- embeddings cell (real codec, cross-protocol)

use crate::ir::embeddings::{EmbInput, EmbeddingItem, EmbeddingsReq, EmbeddingsResp, EncFmt, VectorData};

struct OpenAiEmbeddings;

impl OperationHandler for OpenAiEmbeddings {
    fn upstream_path(&self, lane: &Lane, _wants_stream: bool) -> String {
        lane.path.clone().unwrap_or_else(|| "/v1/embeddings".to_string())
    }

    /// openai embeddings wire → IR (used when openai is the INGRESS of a cross-protocol call).
    fn read_request(&self, wire: &Value) -> Result<IrReq, IngressReject> {
        let model = wire.get("model").and_then(Value::as_str).unwrap_or_default().to_string();
        let input = match wire.get("input") {
            Some(Value::String(s)) => EmbInput::Text(vec![s.clone()]),
            Some(Value::Array(a)) => {
                EmbInput::Text(a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            }
            _ => return Err(IngressReject::BadRequest("embeddings request missing `input`".into())),
        };
        let dimensions = wire.get("dimensions").and_then(Value::as_u64).map(|d| d as u32);
        let encoding_formats = match wire.get("encoding_format").and_then(Value::as_str) {
            Some("base64") => vec![EncFmt::Base64],
            _ => vec![EncFmt::Float],
        };
        Ok(IrReq::Embeddings(EmbeddingsReq {
            model,
            input,
            dimensions,
            encoding_formats,
            user: wire.get("user").and_then(Value::as_str).map(str::to_string),
            ..Default::default()
        }))
    }

    /// IR → openai embeddings wire (used when openai is the EGRESS).
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Embeddings(r) = ir else { return Bytes::new() };
        let input = match &r.input {
            EmbInput::Text(v) if v.len() == 1 => json!(v[0]),
            EmbInput::Text(v) => json!(v),
            _ => json!([]),
        };
        let mut body = json!({ "model": r.model, "input": input });
        if let Some(d) = r.dimensions {
            body["dimensions"] = json!(d);
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }

    /// openai embeddings response wire → IR (used when openai is the EGRESS).
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value = serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let embeddings = v
            .get("data")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .enumerate()
                    .map(|(idx, d)| {
                        let index = d.get("index").and_then(Value::as_u64).unwrap_or(idx as u64) as usize;
                        let mut item = EmbeddingItem { index, ..Default::default() };
                        if let Some(f) = d.get("embedding").and_then(Value::as_array) {
                            item.vectors.insert(
                                EncFmt::Float,
                                VectorData::Float(f.iter().filter_map(|x| x.as_f64().map(|n| n as f32)).collect()),
                            );
                        } else if let Some(b) = d.get("embedding").and_then(Value::as_str) {
                            item.vectors.insert(EncFmt::Base64, VectorData::Base64(b.to_string()));
                        }
                        item
                    })
                    .collect()
            })
            .unwrap_or_default();
        let usage = v.get("usage").map(|u| crate::billing::TokenUsage {
            input: u.get("prompt_tokens").and_then(Value::as_u64).unwrap_or(0),
            ..Default::default()
        });
        Ok(IrResp::Embeddings(EmbeddingsResp {
            model: v.get("model").and_then(Value::as_str).map(str::to_string),
            object_kind: Some("list".into()),
            embeddings,
            usage,
            ..Default::default()
        }))
    }

    /// IR → openai embeddings response wire (used when openai is the INGRESS — the caller's dialect).
    fn write_response(&self, ir: &IrResp) -> Bytes {
        let IrResp::Embeddings(r) = ir else { return Bytes::new() };
        let data: Vec<Value> = r
            .embeddings
            .iter()
            .map(|item| {
                let emb = match item.vectors.get(&EncFmt::Float) {
                    Some(VectorData::Float(f)) => json!(f),
                    _ => match item.vectors.values().next() {
                        Some(VectorData::Base64(b)) => json!(b),
                        Some(VectorData::Int(v)) => json!(v),
                        _ => json!([]),
                    },
                };
                json!({ "object": "embedding", "index": item.index, "embedding": emb })
            })
            .collect();
        let mut body = json!({ "object": "list", "data": data });
        if let Some(m) = &r.model {
            body["model"] = json!(m);
        }
        if let Some(u) = &r.usage {
            body["usage"] = json!({ "prompt_tokens": u.input, "total_tokens": u.input + u.output });
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
}

// ---------------------------------------------------------------- image cell (real, cross-protocol)

use crate::ir::image::{ImageOp, ImageReq, ImageResp, ImageSize};
use crate::media::ImageOutput;

struct OpenAiImage;

impl OperationHandler for OpenAiImage {
    fn upstream_path(&self, lane: &Lane, _wants_stream: bool) -> String {
        lane.path.clone().unwrap_or_else(|| "/v1/images/generations".to_string())
    }
    fn read_request(&self, wire: &Value) -> Result<IrReq, IngressReject> {
        let size = wire.get("size").and_then(Value::as_str).and_then(|s| {
            if s == "auto" {
                Some(ImageSize::Auto)
            } else {
                s.split_once('x')
                    .and_then(|(w, h)| Some(ImageSize::Wh { width: w.parse().ok()?, height: h.parse().ok()? }))
            }
        });
        Ok(IrReq::Image(ImageReq {
            op: ImageOp::Generate,
            model: wire.get("model").and_then(Value::as_str).unwrap_or_default().to_string(),
            prompt: wire.get("prompt").and_then(Value::as_str).map(str::to_string),
            n: wire.get("n").and_then(Value::as_u64).map(|n| n as u32),
            size,
            quality: wire.get("quality").and_then(Value::as_str).map(str::to_string),
            style: wire.get("style").and_then(Value::as_str).map(str::to_string),
            response_format: wire.get("response_format").and_then(Value::as_str).map(str::to_string),
            user: wire.get("user").and_then(Value::as_str).map(str::to_string),
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Image(r) = ir else { return Bytes::new() };
        let mut body = json!({ "model": r.model });
        if let Some(p) = &r.prompt {
            body["prompt"] = json!(p);
        }
        if let Some(n) = r.n {
            body["n"] = json!(n);
        }
        if let Some(ImageSize::Wh { width, height }) = r.size {
            body["size"] = json!(format!("{width}x{height}"));
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value = serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let images = v
            .get("data")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|d| ImageOutput {
                        b64: d.get("b64_json").and_then(Value::as_str).map(str::to_string),
                        url: d.get("url").and_then(Value::as_str).map(str::to_string),
                        revised_prompt: d.get("revised_prompt").and_then(Value::as_str).map(str::to_string),
                        ..Default::default()
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(IrResp::Image(ImageResp {
            created: v.get("created").and_then(Value::as_u64),
            images,
            ..Default::default()
        }))
    }
    fn write_response(&self, ir: &IrResp) -> Bytes {
        let IrResp::Image(r) = ir else { return Bytes::new() };
        let data: Vec<Value> = r
            .images
            .iter()
            .map(|img| {
                let mut o = serde_json::Map::new();
                if let Some(b) = &img.b64 {
                    o.insert("b64_json".into(), json!(b));
                }
                if let Some(u) = &img.url {
                    o.insert("url".into(), json!(u));
                }
                if let Some(rp) = &img.revised_prompt {
                    o.insert("revised_prompt".into(), json!(rp));
                }
                Value::Object(o)
            })
            .collect();
        Bytes::from(serde_json::to_vec(&json!({ "created": r.created.unwrap_or(0), "data": data })).unwrap_or_default())
    }
}

// ---------------------------------------------------------------- moderation cell

struct OpenAiModeration;

impl OperationHandler for OpenAiModeration {
    fn upstream_path(&self, lane: &Lane, _wants_stream: bool) -> String {
        lane.path.clone().unwrap_or_else(|| "/v1/moderations".to_string())
    }

    fn read_request(&self, wire: &Value) -> Result<IrReq, IngressReject> {
        let model = wire
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let input = parse_input(wire.get("input"))?;
        Ok(IrReq::Moderation(ModerationReq { model, input, extra: BTreeMap::new() }))
    }

    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Moderation(r) = ir else {
            // A cell only ever receives its own variant; anything else is a programming error, not a
            // runtime path. Emit an empty body rather than panic.
            return Bytes::new();
        };
        let body = json!({ "model": r.model, "input": input_to_value(&r.input) });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }

    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let results = v
            .get("results")
            .and_then(Value::as_array)
            .map(|arr| arr.iter().map(parse_result).collect())
            .unwrap_or_default();
        Ok(IrResp::Moderation(ModerationResp {
            id: v.get("id").and_then(Value::as_str).map(str::to_string),
            model: v.get("model").and_then(Value::as_str).map(str::to_string),
            results,
            extra: BTreeMap::new(),
        }))
    }

    fn write_response(&self, ir: &IrResp) -> Bytes {
        let IrResp::Moderation(r) = ir else {
            return Bytes::new();
        };
        let results: Vec<Value> = r
            .results
            .iter()
            .map(|res| {
                json!({
                    "flagged": res.flagged,
                    "categories": map_bool(&res.categories),
                    "category_scores": map_f64(&res.category_scores),
                    "category_applied_input_types": map_strs(&res.applied_input_types),
                })
            })
            .collect();
        let mut body = json!({ "results": results });
        if let Some(id) = &r.id {
            body["id"] = json!(id);
        }
        if let Some(m) = &r.model {
            body["model"] = json!(m);
        }
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
}

// ---- helpers ----

fn parse_input(v: Option<&Value>) -> Result<Vec<ModerationInput>, IngressReject> {
    match v {
        Some(Value::String(s)) => Ok(vec![ModerationInput::Text(s.clone())]),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|item| match item {
                Value::String(s) => Ok(ModerationInput::Text(s.clone())),
                Value::Object(o) => match o.get("type").and_then(Value::as_str) {
                    Some("image_url") => o
                        .get("image_url")
                        .and_then(|iu| iu.get("url"))
                        .and_then(Value::as_str)
                        .map(|u| ModerationInput::ImageUrl(u.to_string()))
                        .ok_or_else(|| IngressReject::BadRequest("image_url missing url".into())),
                    _ => o
                        .get("text")
                        .and_then(Value::as_str)
                        .map(|t| ModerationInput::Text(t.to_string()))
                        .ok_or_else(|| IngressReject::BadRequest("input item missing text".into())),
                },
                _ => Err(IngressReject::BadRequest("invalid input item".into())),
            })
            .collect(),
        _ => Err(IngressReject::BadRequest("moderation request missing `input`".into())),
    }
}

fn input_to_value(input: &[ModerationInput]) -> Value {
    // Round-trip: a single text input emits the bare string (OpenAI's common form); otherwise an array.
    if let [ModerationInput::Text(s)] = input {
        return json!(s);
    }
    Value::Array(
        input
            .iter()
            .map(|i| match i {
                ModerationInput::Text(t) => json!({ "type": "text", "text": t }),
                ModerationInput::ImageUrl(u) => json!({ "type": "image_url", "image_url": { "url": u } }),
            })
            .collect(),
    )
}

fn parse_result(v: &Value) -> ModerationResult {
    ModerationResult {
        flagged: v.get("flagged").and_then(Value::as_bool).unwrap_or(false),
        categories: obj_map(v.get("categories"), |x| x.as_bool()),
        category_scores: obj_map(v.get("category_scores"), |x| x.as_f64()),
        applied_input_types: obj_map(v.get("category_applied_input_types"), |x| {
            x.as_array()
                .map(|a| a.iter().filter_map(|s| s.as_str().map(str::to_string)).collect())
        }),
    }
}

fn obj_map<T>(v: Option<&Value>, f: impl Fn(&Value) -> Option<T>) -> BTreeMap<String, T> {
    v.and_then(Value::as_object)
        .map(|o| o.iter().filter_map(|(k, val)| f(val).map(|t| (k.clone(), t))).collect())
        .unwrap_or_default()
}

fn map_bool(m: &BTreeMap<String, bool>) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
}
fn map_f64(m: &BTreeMap<String, f64>) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
}
fn map_strs(m: &BTreeMap<String, Vec<String>>) -> Value {
    Value::Object(m.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cell_lookup() {
        let h = OpenAiRequestHandler;
        assert!(h.operation_handler(Operation::Moderation).is_some());
        assert!(h.operation_handler(Operation::Chat).is_none());
    }

    #[test]
    fn moderation_request_round_trips_openai_shape() {
        let cell = OpenAiModeration;
        let wire = json!({ "model": "omni-moderation-latest", "input": "hello" });
        let ir = cell.read_request(&wire).unwrap();
        let back: Value = serde_json::from_slice(&cell.write_request(&ir)).unwrap();
        assert_eq!(back["model"], "omni-moderation-latest");
        assert_eq!(back["input"], "hello"); // single text → bare string, round-tripped
    }

    #[test]
    fn moderation_response_round_trips() {
        let cell = OpenAiModeration;
        let wire = br#"{"id":"modr-1","model":"m","results":[{"flagged":true,
            "categories":{"violence":true},"category_scores":{"violence":0.9},
            "category_applied_input_types":{"violence":["text"]}}]}"#;
        let ir = cell.read_response(wire).unwrap();
        let back: Value = serde_json::from_slice(&cell.write_response(&ir)).unwrap();
        assert_eq!(back["results"][0]["flagged"], true);
        assert_eq!(back["results"][0]["categories"]["violence"], true);
        assert_eq!(back["results"][0]["category_scores"]["violence"], 0.9);
        assert_eq!(back["id"], "modr-1");
    }
}
