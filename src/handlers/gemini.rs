// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! Gemini `RequestHandler` + cells (design §6/§7). Embeddings via `models/{id}:embedContent`.
#![allow(dead_code)]

use crate::handlers::{
    CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler, WireBody,
};
use crate::ir::audio::{SpeechResp, TranscriptionResp};
use crate::ir::embeddings::{EmbInput, EmbeddingItem, EmbeddingsResp, EncFmt, VectorData};
use crate::ir::variant::{IrReq, IrResp};
use crate::media::{base64_encode, MediaBlob, MediaPayload};
use crate::operation::Operation;
use bytes::Bytes;
use serde_json::{json, Value};

pub(crate) struct GeminiRequestHandler;
/// This protocol's OWN chat instance — delete this line (and the registry arm) and this
/// protocol's chat 404s via the standard no-handler path; everything else keeps working.
static CHAT: crate::handlers::chat::ChatOperation = crate::handlers::chat::ChatOperation("gemini");
static EMB: GeminiEmbeddings = GeminiEmbeddings;
static IMG: GeminiImage = GeminiImage;
static TRANSCRIPTION: GeminiTranscription = GeminiTranscription;
static SPEECH: GeminiSpeech = GeminiSpeech;

impl RequestHandler for GeminiRequestHandler {
    fn protocol_name(&self) -> &'static str {
        "gemini"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        match op {
            Operation::Embeddings => Some(&EMB),
            Operation::Image => Some(&IMG),
            Operation::Transcription => Some(&TRANSCRIPTION),
            Operation::Speech => Some(&SPEECH),
            Operation::Chat => Some(&CHAT),
            _ => None,
        }
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        let m = ctx.model;
        match ctx.operation {
            Operation::Embeddings => format!("/v1beta/models/{m}:embedContent"),
            Operation::Image => format!("/v1beta/models/{m}:predict"),
            // Chat + audio understanding/TTS all ride generateContent (stream-aware for chat/audio).
            Operation::Chat | Operation::Transcription | Operation::Speech => {
                let verb = if ctx.stream {
                    "streamGenerateContent"
                } else {
                    "generateContent"
                };
                format!("/v1beta/models/{m}:{verb}")
            }
            Operation::Moderation => format!("/v1beta/models/{m}:generateContent"),
            // Unreachable in practice: gemini has no rerank handler, so Rerank never reaches here.
            Operation::Rerank => format!("/v1beta/models/{m}:generateContent"),
        }
    }
    fn resolve_operation(&self, path: &str, body: &[u8]) -> Option<Operation> {
        // Gemini multiplexes: the ACTION names embeddings/image; `generateContent` serves chat AND
        // audio, split by BODY — `responseModalities:["AUDIO"]` ⇒ speech, an `inline_data` part with
        // an audio mime ⇒ transcription, an inline IMAGE part is multimodal CHAT. The byte-scan is a
        // cheap pre-filter so plain chat never pays the JSON parse.
        if path.contains(":embedContent") || path.contains(":batchEmbedContents") {
            return Some(Operation::Embeddings);
        }
        if path.contains(":predict") {
            return Some(Operation::Image);
        }
        if !(path.contains(":generateContent") || path.contains(":streamGenerateContent")) {
            return None;
        }
        let has = |n: &[u8]| body.windows(n.len()).any(|w| w == n);
        if has(b"responseModalities") || has(b"inline_data") || has(b"inlineData") {
            if let Ok(v) = serde_json::from_slice::<Value>(body) {
                let audio_out = v
                    .pointer("/generationConfig/responseModalities")
                    .and_then(Value::as_array)
                    .is_some_and(|m| m.iter().any(|x| x.as_str() == Some("AUDIO")));
                if audio_out {
                    return Some(Operation::Speech);
                }
                let audio_in = v
                    .pointer("/contents/0/parts")
                    .and_then(Value::as_array)
                    .is_some_and(|parts| {
                        parts.iter().any(|p| {
                            p.get("inline_data")
                                .or_else(|| p.get("inlineData"))
                                .and_then(|d| d.get("mime_type").or_else(|| d.get("mimeType")))
                                .and_then(Value::as_str)
                                .is_some_and(|m| m.starts_with("audio/"))
                        })
                    });
                if audio_in {
                    return Some(Operation::Transcription);
                }
            }
        }
        Some(Operation::Chat)
    }
    fn path_model(&self, path: &str) -> Option<String> {
        // `/{v1,v1beta}/models/{model}:{action}` — model is the last segment up to the LAST colon.
        let rest = path.split("/models/").nth(1)?;
        let (model, _action) = rest.rsplit_once(':')?;
        (!model.is_empty()).then(|| model.to_string())
    }
}

/// Gemini transcription — audio understood via `models/{id}:generateContent` with inline audio data.
/// Egress-only (openai→gemini): audio IR → generateContent request; candidates text → transcription.
struct GeminiTranscription;

impl OperationHandler for GeminiTranscription {
    /// gemini `generateContent`-with-audio wire → IR (gemini as INGRESS): `inline_data` part is the
    /// audio, a text part (if any) is the instruction/prompt. Model rides the PATH.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let mut audio = None;
        let mut prompt = None;
        if let Some(parts) = wire.pointer("/contents/0/parts").and_then(Value::as_array) {
            for p in parts {
                let inline = p.get("inline_data").or_else(|| p.get("inlineData"));
                if let Some(d) = inline {
                    audio = Some(MediaBlob {
                        payload: MediaPayload::B64(
                            d.get("data")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_string(),
                        ),
                        mime_type: d
                            .get("mime_type")
                            .or_else(|| d.get("mimeType"))
                            .and_then(Value::as_str)
                            .unwrap_or("application/octet-stream")
                            .to_string(),
                        pcm: None,
                    });
                } else if let Some(t) = p.get("text").and_then(Value::as_str) {
                    prompt = Some(t.to_string());
                }
            }
        }
        let Some(audio) = audio else {
            return Err(IngressReject::BadRequest(
                "transcription requires an inline_data audio part".into(),
            ));
        };
        Ok(IrReq::Transcription(crate::ir::audio::TranscriptionReq {
            audio: Some(audio),
            prompt,
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Transcription(r) = ir else {
            return Bytes::new();
        };
        let (mime, data) = match &r.audio {
            Some(blob) => {
                let d = match &blob.payload {
                    MediaPayload::B64(s) => s.clone(),
                    MediaPayload::Bytes(b) => base64_encode(b),
                    MediaPayload::Uri(_) => String::new(),
                };
                (blob.mime_type.clone(), d)
            }
            None => (String::new(), String::new()),
        };
        // `target_language` set ⇒ translate (folds /audio/translations, §1b); else transcribe.
        let instruction = if r.target_language.is_some() {
            "Translate the following audio to text."
        } else {
            "Transcribe the following audio verbatim."
        };
        let body = json!({
            "contents": [{ "role": "user", "parts": [
                { "text": instruction },
                { "inline_data": { "mime_type": mime, "data": data } },
            ]}],
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let text = v
            .pointer("/candidates/0/content/parts")
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        let usage = v.get("usageMetadata").map(|u| {
            crate::billing::Billing::Tokens(crate::billing::TokenUsage {
                input: u
                    .get("promptTokenCount")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                output: u
                    .get("candidatesTokenCount")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                ..Default::default()
            })
        });
        Ok(IrResp::Transcription(TranscriptionResp {
            text,
            usage,
            ..Default::default()
        }))
    }
    /// IR → gemini candidates response (gemini as INGRESS): transcript text as the model turn.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Transcription(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let mut body = json!({
            "candidates": [{
                "content": { "parts": [{ "text": r.text }], "role": "model" },
                "finishReason": "STOP",
            }],
        });
        if let Some(crate::billing::Billing::Tokens(t)) = &r.usage {
            body["usageMetadata"] = json!({
                "promptTokenCount": t.input,
                "candidatesTokenCount": t.output,
                "totalTokenCount": t.input.saturating_add(t.output),
            });
        }
        WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
    }
}

/// Gemini speech (TTS) — `models/{id}:generateContent` with `responseModalities: [AUDIO]`.
/// Gemini returns inline base64 PCM; a raw-binary body (mock/other) is wrapped verbatim.
struct GeminiSpeech;

impl OperationHandler for GeminiSpeech {
    /// gemini TTS wire → IR (gemini as INGRESS): text part is the input; voice from speechConfig.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let input = wire
            .pointer("/contents/0/parts")
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        if input.is_empty() {
            return Err(IngressReject::BadRequest(
                "speech requires a text part".into(),
            ));
        }
        let voice = wire
            .pointer("/generationConfig/speechConfig/voiceConfig/prebuiltVoiceConfig/voiceName")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        Ok(IrReq::Speech(crate::ir::audio::SpeechReq {
            input,
            voice,
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Speech(r) = ir else {
            return Bytes::new();
        };
        let mut speech_config = json!({
            "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": r.voice } }
        });
        if let Some(instr) = &r.instructions {
            speech_config["languageCode"] = json!(instr);
        }
        let body = json!({
            "contents": [{ "role": "user", "parts": [{ "text": r.input }]}],
            "generationConfig": { "responseModalities": ["AUDIO"], "speechConfig": speech_config },
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        // Real Gemini → JSON with inline base64 audio; mock/raw → binary body. Try JSON, fall back.
        if let Ok(v) = serde_json::from_slice::<Value>(wire) {
            if let Some(data) = v
                .pointer("/candidates/0/content/parts/0/inlineData/data")
                .and_then(Value::as_str)
            {
                let mime = v
                    .pointer("/candidates/0/content/parts/0/inlineData/mimeType")
                    .and_then(Value::as_str)
                    .unwrap_or("audio/L16;codec=pcm;rate=24000")
                    .to_string();
                let pcm = mime.contains("pcm").then_some(crate::media::PcmParams {
                    sample_rate: 24000,
                    channels: 1,
                    bit_depth: 16,
                });
                return Ok(IrResp::Speech(SpeechResp {
                    audio: Some(MediaBlob {
                        payload: MediaPayload::B64(data.to_string()),
                        mime_type: mime,
                        pcm,
                    }),
                    ..Default::default()
                }));
            }
        }
        Ok(IrResp::Speech(SpeechResp {
            audio: Some(MediaBlob {
                payload: MediaPayload::Bytes(Bytes::copy_from_slice(wire)),
                mime_type: "audio/mpeg".into(),
                pcm: None,
            }),
            ..Default::default()
        }))
    }
    /// IR → gemini TTS response (gemini as INGRESS): inline base64 audio as the model turn. Real
    /// Gemini answers TTS in JSON (`inlineData`), never raw binary — the caller's dialect rules.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Speech(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let (data, mime) = match &r.audio {
            Some(blob) => {
                let d = match &blob.payload {
                    MediaPayload::B64(s) => s.clone(),
                    MediaPayload::Bytes(b) => base64_encode(b),
                    MediaPayload::Uri(_) => String::new(),
                };
                (d, blob.mime_type.clone())
            }
            None => (String::new(), "audio/mpeg".into()),
        };
        let body = json!({
            "candidates": [{
                "content": { "parts": [{ "inlineData": { "mimeType": mime, "data": data } }], "role": "model" },
                "finishReason": "STOP",
            }],
        });
        WireBody::json(Bytes::from(serde_json::to_vec(&body).unwrap_or_default()))
    }
}

/// Gemini/Imagen image generation (`models/{id}:predict`). prompt in → `predictions[].bytesBase64Encoded` out.
struct GeminiImage;

impl OperationHandler for GeminiImage {
    /// Imagen `:predict` wire → IR (gemini as INGRESS): `instances[].prompt` + `parameters`.
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let params = wire.get("parameters").cloned().unwrap_or_default();
        Ok(IrReq::Image(crate::ir::image::ImageReq {
            prompt: wire
                .pointer("/instances/0/prompt")
                .and_then(Value::as_str)
                .map(str::to_string),
            n: params
                .get("sampleCount")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()),
            aspect_ratio: params
                .get("aspectRatio")
                .and_then(Value::as_str)
                .map(str::to_string),
            person_generation: params
                .get("personGeneration")
                .and_then(Value::as_str)
                .map(str::to_string),
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Image(r) = ir else {
            return Bytes::new();
        };
        let body = json!({
            "instances": [{ "prompt": r.prompt.clone().unwrap_or_default() }],
            "parameters": { "sampleCount": r.n.unwrap_or(1) },
        });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let images = v
            .get("predictions")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .map(|p| crate::media::ImageOutput {
                        b64: p
                            .get("bytesBase64Encoded")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        mime_type: p
                            .get("mimeType")
                            .and_then(Value::as_str)
                            .map(str::to_string),
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
    /// IR → Imagen `:predict` response (gemini as INGRESS): `predictions[].bytesBase64Encoded`.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Image(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let predictions: Vec<Value> = r
            .images
            .iter()
            .map(|img| {
                let mut p = json!({});
                if let Some(b64) = &img.b64 {
                    p["bytesBase64Encoded"] = json!(b64);
                }
                p["mimeType"] = json!(img.mime_type.clone().unwrap_or_else(|| "image/png".into()));
                p
            })
            .collect();
        WireBody::json(Bytes::from(
            serde_json::to_vec(&json!({ "predictions": predictions })).unwrap_or_default(),
        ))
    }
}

/// Gemini embeddings (`models/{id}:embedContent`). Single content in, `embedding.values` out.
struct GeminiEmbeddings;

impl OperationHandler for GeminiEmbeddings {
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        // gemini `:embedContent` wire → IR (gemini as INGRESS). Model rides the PATH (routing fills
        // it via `IrReq::set_model`); the body carries `content.parts[].text`.
        let wire: Value =
            serde_json::from_slice(body).map_err(|e| IngressReject::BadRequest(e.to_string()))?;
        let text = wire
            .pointer("/content/parts")
            .and_then(Value::as_array)
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        if text.is_empty() {
            return Err(IngressReject::BadRequest(
                "embedContent requires `content.parts[].text`".into(),
            ));
        }
        Ok(IrReq::Embeddings(crate::ir::embeddings::EmbeddingsReq {
            input: EmbInput::Text(vec![text]),
            task_type: wire
                .get("taskType")
                .and_then(Value::as_str)
                .map(str::to_string),
            title: wire
                .get("title")
                .and_then(Value::as_str)
                .map(str::to_string),
            dimensions: wire
                .get("outputDimensionality")
                .and_then(Value::as_u64)
                .and_then(|d| u32::try_from(d).ok()),
            encoding_formats: vec![EncFmt::Float],
            ..Default::default()
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Embeddings(r) = ir else {
            return Bytes::new();
        };
        let text = match &r.input {
            EmbInput::Text(v) => v.first().cloned().unwrap_or_default(),
            _ => String::new(),
        };
        let body = json!({ "content": { "parts": [{ "text": text }] } });
        Bytes::from(serde_json::to_vec(&body).unwrap_or_default())
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let v: Value =
            serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
        let mut item = EmbeddingItem::default();
        if let Some(f) = v
            .get("embedding")
            .and_then(|e| e.get("values"))
            .and_then(Value::as_array)
        {
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
            .get("usageMetadata")
            .and_then(|u| u.get("promptTokenCount"))
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
    /// IR → gemini `:embedContent` response (gemini as INGRESS): `{"embedding":{"values":[..]}}`.
    fn write_response(&self, ir: &IrResp) -> WireBody {
        let IrResp::Embeddings(r) = ir else {
            return WireBody::json(Bytes::new());
        };
        let values: Vec<f32> = r
            .embeddings
            .first()
            .and_then(|item| match item.vectors.get(&EncFmt::Float) {
                Some(VectorData::Float(v)) => Some(v.clone()),
                _ => None,
            })
            .unwrap_or_default();
        WireBody::json(Bytes::from(
            serde_json::to_vec(&json!({ "embedding": { "values": values } })).unwrap_or_default(),
        ))
    }
}
