// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! Gemini `RequestHandler` + cells (design §6/§7). Embeddings via `models/{id}:embedContent`.
#![allow(dead_code)]

use crate::handler::{CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler, WireBody};
use crate::ir::audio::{SpeechResp, TranscriptionResp};
use crate::ir::embeddings::{EmbInput, EmbeddingItem, EmbeddingsResp, EncFmt, VectorData};
use crate::ir::variant::{IrReq, IrResp};
use crate::media::{base64_encode, MediaBlob, MediaPayload};
use crate::operation::Operation;
use bytes::Bytes;
use serde_json::{json, Value};

pub(crate) struct GeminiRequestHandler;
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
            Operation::Chat => Some(&crate::cells::chat::CHAT_HANDLER),
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
                let verb = if ctx.stream { "streamGenerateContent" } else { "generateContent" };
                format!("/v1beta/models/{m}:{verb}")
            }
            Operation::Moderation => format!("/v1beta/models/{m}:generateContent"),
        }
    }
}

/// Gemini transcription — audio understood via `models/{id}:generateContent` with inline audio data.
/// Egress-only (openai→gemini): audio IR → generateContent request; candidates text → transcription.
struct GeminiTranscription;

impl OperationHandler for GeminiTranscription {
    fn read_request(&self, _body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        Err(IngressReject::BadRequest("gemini transcription is egress-only".into()))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Transcription(r) = ir else { return Bytes::new() };
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
        let v: Value = serde_json::from_slice(wire).map_err(|e| CodecError::Malformed(e.to_string()))?;
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
                input: u.get("promptTokenCount").and_then(Value::as_u64).unwrap_or(0),
                output: u.get("candidatesTokenCount").and_then(Value::as_u64).unwrap_or(0),
                ..Default::default()
            })
        });
        Ok(IrResp::Transcription(TranscriptionResp { text, usage, ..Default::default() }))
    }
    fn write_response(&self, _ir: &IrResp) -> WireBody {
        WireBody::json(Bytes::new())
    }
}

/// Gemini speech (TTS) — `models/{id}:generateContent` with `responseModalities: [AUDIO]`. Egress-only.
/// Gemini returns inline base64 PCM; a raw-binary body (mock/other) is wrapped verbatim.
struct GeminiSpeech;

impl OperationHandler for GeminiSpeech {
    fn read_request(&self, _body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        Err(IngressReject::BadRequest("gemini speech is egress-only".into()))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        let IrReq::Speech(r) = ir else { return Bytes::new() };
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
                    audio: Some(MediaBlob { payload: MediaPayload::B64(data.to_string()), mime_type: mime, pcm }),
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
    fn write_response(&self, _ir: &IrResp) -> WireBody {
        WireBody::json(Bytes::new())
    }
}

/// Gemini/Imagen image generation (`models/{id}:predict`). prompt in → `predictions[].bytesBase64Encoded` out.
struct GeminiImage;

impl OperationHandler for GeminiImage {
    fn read_request(&self, _body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
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
    fn write_response(&self, _ir: &IrResp) -> WireBody {
        WireBody::json(Bytes::new())
    }
}

/// Gemini embeddings (`models/{id}:embedContent`). Single content in, `embedding.values` out.
struct GeminiEmbeddings;

impl OperationHandler for GeminiEmbeddings {
    fn read_request(&self, _body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
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
    fn write_response(&self, _ir: &IrResp) -> WireBody {
        WireBody::json(Bytes::new())
    }
}
