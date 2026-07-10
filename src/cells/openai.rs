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

impl RequestHandler for OpenAiRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "openai"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Moderation => Some(&MODERATION),
            // embeddings/images/audio/chat cells land here as built.
            _ => None,
        }
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
