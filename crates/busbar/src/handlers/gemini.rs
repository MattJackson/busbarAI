// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
            // Enumerated (not `_`) so adding an operation is a compile error here — the documented
            // removability/symmetry gate. Gemini has no moderation/rerank surface.
            Operation::Moderation | Operation::Rerank => None,
        }
    }
    fn upstream_path(&self, ctx: &EgressCtx) -> String {
        let m = ctx.model;
        // The base segment before `/{model}:verb`. Native Gemini is `/v1beta/models`; a provider may
        // override it via `path_base` (e.g. Vertex AI's `/v1/projects/{p}/locations/{l}/publishers/
        // google/models`). The `:verb` suffix and streaming selection are unchanged.
        let base = ctx.path_base.unwrap_or("/v1beta/models");
        match ctx.operation {
            Operation::Embeddings => format!("{base}/{m}:embedContent"),
            Operation::Image => format!("{base}/{m}:predict"),
            // Chat + audio understanding/TTS all ride generateContent (stream-aware for chat/audio).
            Operation::Chat | Operation::Transcription | Operation::Speech => {
                let verb = if ctx.stream {
                    "streamGenerateContent"
                } else {
                    "generateContent"
                };
                format!("{base}/{m}:{verb}")
            }
            // Unreachable in practice: gemini has no moderation/rerank handler (operation_handler
            // returns None), so these never reach egress path resolution.
            Operation::Moderation => format!("{base}/{m}:generateContent"),
            Operation::Rerank => format!("{base}/{m}:generateContent"),
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
                    // Validate the client-supplied base64 at this trust boundary: a malformed
                    // payload must 400 here, not silently become an empty audio body downstream
                    // (the egress writer decodes it and any `unwrap_or_default` would truncate).
                    let data = d
                        .get("data")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    if crate::media::base64_decode(&data).is_none() {
                        return Err(IngressReject::BadRequest(
                            "inline_data.data is not valid base64".into(),
                        ));
                    }
                    audio = Some(MediaBlob {
                        payload: MediaPayload::B64(data),
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
        let speech_config = json!({
            "voiceConfig": { "prebuiltVoiceConfig": { "voiceName": r.voice } }
        });
        // OpenAI's `instructions` is FREE-TEXT style guidance ("speak cheerfully"), not a locale.
        // The old code put it into `speechConfig.languageCode` (a BCP-47 field), producing an
        // invalid Gemini request. Gemini steers TTS style through the PROMPT itself, so prefix the
        // text (its documented style-control mechanism) instead of corrupting languageCode.
        let text = match &r.instructions {
            Some(instr) if !instr.trim().is_empty() => format!("{}: {}", instr.trim(), r.input),
            _ => r.input.clone(),
        };
        let body = json!({
            "contents": [{ "role": "user", "parts": [{ "text": text }]}],
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
                // Validate the backend's base64 at this trust boundary: a corrupt payload must fail
                // loud here (CodecError) rather than reach the egress writer, where a decode failure
                // would silently become an empty 200 audio body. This is the response-side twin of
                // the ingress inline_data validation.
                if crate::media::base64_decode(data).is_none() {
                    return Err(CodecError::Malformed(
                        "gemini speech inlineData.data is not valid base64".into(),
                    ));
                }
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
        let mut params = json!({ "sampleCount": r.n.unwrap_or(1) });
        // Carry the Imagen generation controls the reader captures; dropping them fell back to
        // Imagen's defaults (1:1 aspect, default person-generation policy) instead of the request.
        if let Some(a) = &r.aspect_ratio {
            params["aspectRatio"] = json!(a);
        }
        if let Some(p) = &r.person_generation {
            params["personGeneration"] = json!(p);
        }
        let body = json!({
            "instances": [{ "prompt": r.prompt.clone().unwrap_or_default() }],
            "parameters": params,
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
    // Token-metered: buffer the same-protocol non-stream 2xx body so the default
    // `extract_usage` can read the `usage` object and bill the virtual key's TPM/spend
    // (the cross-protocol path already bills; this closes the same-protocol gap).
    fn taps_usage(&self) -> bool {
        true
    }
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
            EmbInput::Text(v) => {
                // Gemini `:embedContent` embeds a SINGLE content; a multi-input request can only
                // embed the first here (batch would need `:batchEmbedContents`, a 1.3 item). Warn
                // rather than silently drop the rest.
                if v.len() > 1 {
                    tracing::warn!(
                        dropped = v.len() - 1,
                        "Gemini :embedContent takes one input; embedding only the first of a \
                         multi-input request (the rest are not sent)"
                    );
                }
                v.first().cloned().unwrap_or_default()
            }
            _ => String::new(),
        };
        // Carry the retrieval/shape controls the reader captures — Gemini `:embedContent` supports
        // them natively. Dropping `outputDimensionality` returned full-width vectors instead of the
        // requested size (a wrong-length response); `taskType`/`title` steer retrieval quality.
        let mut body = json!({ "content": { "parts": [{ "text": text }] } });
        if let Some(d) = r.dimensions {
            body["outputDimensionality"] = json!(d);
        }
        if let Some(t) = &r.task_type {
            body["taskType"] = json!(t);
        }
        if let Some(t) = &r.title {
            body["title"] = json!(t);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_base_reshapes_the_gemini_url_for_vertex() {
        let h = GeminiRequestHandler;
        let model = "gemini-2.0-flash";
        let ctx = |path_base| EgressCtx {
            operation: Operation::Chat,
            model,
            stream: false,
            path_base,
        };
        // Default (no override): the native Generative Language layout is unchanged.
        assert_eq!(
            h.upstream_path(&ctx(None)),
            "/v1beta/models/gemini-2.0-flash:generateContent"
        );
        // With a Vertex path_base: the base segment is replaced; the `/{model}:verb` suffix survives,
        // so a `gemini`-protocol provider reaches the Vertex URL by config alone.
        let vbase = "/v1/projects/my-proj/locations/us-central1/publishers/google/models";
        assert_eq!(
            h.upstream_path(&ctx(Some(vbase))),
            "/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.0-flash:generateContent"
        );
        // Embeddings keep their verb on the overridden base too.
        assert_eq!(
            h.upstream_path(&EgressCtx {
                operation: Operation::Embeddings,
                model,
                stream: false,
                path_base: Some(vbase),
            }),
            "/v1/projects/my-proj/locations/us-central1/publishers/google/models/gemini-2.0-flash:embedContent"
        );
    }

    #[test]
    fn transcription_read_request_captures_inline_audio() {
        // A generateContent body with a valid-base64 inline_data audio part → IR Transcription
        // carrying the audio blob (and any text part as the prompt).
        let audio_b64 = base64_encode(b"pretend-audio-bytes");
        let body = serde_json::to_vec(&json!({
            "contents": [{ "role": "user", "parts": [
                { "text": "please transcribe" },
                { "inline_data": { "mime_type": "audio/wav", "data": audio_b64 } },
            ]}],
        }))
        .unwrap();
        let ir = TRANSCRIPTION
            .read_request(&body, "application/json")
            .expect("valid inline audio body");
        let IrReq::Transcription(r) = ir else {
            panic!("expected IrReq::Transcription");
        };
        let blob = r.audio.expect("audio captured");
        assert_eq!(blob.mime_type, "audio/wav");
        assert_eq!(r.prompt.as_deref(), Some("please transcribe"));
        match blob.payload {
            MediaPayload::B64(s) => assert_eq!(s, base64_encode(b"pretend-audio-bytes")),
            _ => panic!("expected B64 payload"),
        }
    }

    #[test]
    fn transcription_read_request_invalid_base64_is_bad_request() {
        // Malformed base64 in inline_data.data must 400 at this trust boundary rather than
        // silently truncate to an empty audio body downstream.
        let body = serde_json::to_vec(&json!({
            "contents": [{ "role": "user", "parts": [
                { "inline_data": { "mime_type": "audio/wav", "data": "!!!not base64!!!" } },
            ]}],
        }))
        .unwrap();
        let err = TRANSCRIPTION
            .read_request(&body, "application/json")
            .expect_err("invalid base64 must reject");
        assert!(matches!(err, IngressReject::BadRequest(_)));
    }

    #[test]
    fn transcription_read_request_without_inline_data_is_bad_request() {
        // No inline_data audio part → the specific "requires an inline_data audio part" 400.
        let body = serde_json::to_vec(&json!({
            "contents": [{ "role": "user", "parts": [{ "text": "just text" }]}],
        }))
        .unwrap();
        let err = TRANSCRIPTION
            .read_request(&body, "application/json")
            .expect_err("no audio part must reject");
        match err {
            IngressReject::BadRequest(m) => {
                assert!(m.contains("inline_data audio part"), "message was: {m}");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn resolve_operation_audio_out_is_speech() {
        // responseModalities:["AUDIO"] on generateContent ⇒ Speech (TTS).
        let h = GeminiRequestHandler;
        let body = serde_json::to_vec(&json!({
            "contents": [{ "role": "user", "parts": [{ "text": "say hi" }]}],
            "generationConfig": { "responseModalities": ["AUDIO"] },
        }))
        .unwrap();
        assert_eq!(
            h.resolve_operation("/v1beta/models/gemini-x:generateContent", &body),
            Some(Operation::Speech),
        );
    }

    #[test]
    fn resolve_operation_audio_in_is_transcription() {
        // An inline_data part with an audio/* mime ⇒ Transcription.
        let body = serde_json::to_vec(&json!({
            "contents": [{ "role": "user", "parts": [
                { "inline_data": { "mime_type": "audio/wav", "data": "AAAA" } },
            ]}],
        }))
        .unwrap();
        let h = GeminiRequestHandler;
        assert_eq!(
            h.resolve_operation("/v1beta/models/gemini-x:generateContent", &body),
            Some(Operation::Transcription),
        );
    }

    #[test]
    fn resolve_operation_plain_text_is_chat() {
        // A plain text chat body (no audio modalities, no inline_data) ⇒ Chat.
        let body = serde_json::to_vec(&json!({
            "contents": [{ "role": "user", "parts": [{ "text": "hello" }]}],
        }))
        .unwrap();
        let h = GeminiRequestHandler;
        assert_eq!(
            h.resolve_operation("/v1beta/models/gemini-x:generateContent", &body),
            Some(Operation::Chat),
        );
    }

    #[test]
    fn embeddings_read_request_captures_content_text() {
        // embedContent body → IR Embeddings carrying content.parts[].text.
        let body = serde_json::to_vec(&json!({
            "content": { "parts": [{ "text": "embed me" }] },
        }))
        .unwrap();
        let ir = EMB
            .read_request(&body, "application/json")
            .expect("valid embedContent body");
        let IrReq::Embeddings(r) = ir else {
            panic!("expected IrReq::Embeddings");
        };
        assert_eq!(r.input, EmbInput::Text(vec!["embed me".to_string()]));
    }

    #[test]
    fn embeddings_read_request_without_text_is_bad_request() {
        // No content.parts text ⇒ 400.
        let body = serde_json::to_vec(&json!({ "content": { "parts": [] } })).unwrap();
        let err = EMB
            .read_request(&body, "application/json")
            .expect_err("empty content must reject");
        assert!(matches!(err, IngressReject::BadRequest(_)));
    }

    #[test]
    fn image_read_request_captures_prompt_and_count() {
        // Imagen :predict body → IR Image with instances[0].prompt and parameters.sampleCount.
        let body = serde_json::to_vec(&json!({
            "instances": [{ "prompt": "a fox" }],
            "parameters": { "sampleCount": 3 },
        }))
        .unwrap();
        let ir = IMG
            .read_request(&body, "application/json")
            .expect("valid predict body");
        let IrReq::Image(r) = ir else {
            panic!("expected IrReq::Image");
        };
        assert_eq!(r.prompt.as_deref(), Some("a fox"));
        assert_eq!(r.n, Some(3));
    }

    #[test]
    fn image_write_read_roundtrip_preserves_prompt() {
        // write_request emits instances[].prompt + parameters.sampleCount; read_request recovers.
        let req = IrReq::Image(crate::ir::image::ImageReq {
            prompt: Some("roundtrip fox".to_string()),
            n: Some(2),
            ..Default::default()
        });
        let wire = IMG.write_request(&req);
        let back = IMG
            .read_request(&wire, "application/json")
            .expect("emitted body reparses");
        let IrReq::Image(r) = back else {
            panic!("expected IrReq::Image");
        };
        assert_eq!(r.prompt.as_deref(), Some("roundtrip fox"));
        assert_eq!(r.n, Some(2));
    }

    #[test]
    fn embeddings_write_request_carries_dimensions_task_type_and_title() {
        // Gemini `:embedContent` supports these natively; dropping `outputDimensionality` returned
        // full-width vectors, and taskType/title steer retrieval quality.
        let ir = IrReq::Embeddings(crate::ir::embeddings::EmbeddingsReq {
            input: EmbInput::Text(vec!["hi".into()]),
            dimensions: Some(256),
            task_type: Some("RETRIEVAL_DOCUMENT".into()),
            title: Some("doc".into()),
            ..Default::default()
        });
        let out = EMB.write_request(&ir);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["outputDimensionality"], 256);
        assert_eq!(v["taskType"], "RETRIEVAL_DOCUMENT");
        assert_eq!(v["title"], "doc");
    }

    #[test]
    fn image_write_request_carries_aspect_ratio_and_person_generation() {
        // Imagen generation controls must ride under `parameters`; dropping them fell back to
        // Imagen's defaults (1:1 aspect, default person-generation policy).
        let ir = IrReq::Image(crate::ir::image::ImageReq {
            prompt: Some("a fox".into()),
            aspect_ratio: Some("16:9".into()),
            person_generation: Some("allow_adult".into()),
            ..Default::default()
        });
        let out = IMG.write_request(&ir);
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(v["parameters"]["aspectRatio"], "16:9");
        assert_eq!(v["parameters"]["personGeneration"], "allow_adult");
    }

    #[test]
    fn speech_read_response_invalid_base64_is_malformed() {
        // A corrupt inline base64 audio payload must fail LOUD (CodecError) at this trust boundary
        // rather than reach the egress writer, where a decode failure would silently become an
        // empty 200 audio body.
        let body = br#"{"candidates":[{"content":{"parts":[{"inlineData":{"data":"!!!not-base64!!!","mimeType":"audio/L16;codec=pcm;rate=24000"}}]}}]}"#;
        let res = SPEECH.read_response(body);
        assert!(matches!(res, Err(CodecError::Malformed(_))));
    }

    #[test]
    fn speech_read_response_valid_base64_returns_audio_blob() {
        // The valid-base64 case returns Ok with the audio blob carried as a B64 payload.
        let data = base64_encode(b"pretend-pcm-audio");
        let body = serde_json::to_vec(&json!({
            "candidates": [{ "content": { "parts": [{ "inlineData": {
                "data": data, "mimeType": "audio/L16;codec=pcm;rate=24000",
            } }] } }],
        }))
        .unwrap();
        let ir = SPEECH
            .read_response(&body)
            .expect("valid base64 must decode");
        let IrResp::Speech(r) = ir else {
            panic!("expected speech IR");
        };
        let blob = r.audio.expect("audio blob present");
        match blob.payload {
            MediaPayload::B64(s) => assert_eq!(s, base64_encode(b"pretend-pcm-audio")),
            _ => panic!("expected B64 payload"),
        }
    }

    #[test]
    fn speech_read_request_captures_prompt_text() {
        // A generateContent TTS body → IR Speech carrying the joined parts[].text as `input`.
        let body = serde_json::to_vec(&json!({
            "contents": [{ "parts": [{ "text": "hello" }] }],
            "generationConfig": { "responseModalities": ["AUDIO"] },
        }))
        .unwrap();
        let ir = SPEECH
            .read_request(&body, "application/json")
            .expect("valid speech body");
        let IrReq::Speech(r) = ir else {
            panic!("expected speech IR");
        };
        assert_eq!(r.input, "hello");
    }

    #[test]
    fn speech_write_request_prefixes_instructions_to_prompt_not_language_code() {
        // OpenAI-style free-text `instructions` steer Gemini TTS through the PROMPT, not the BCP-47
        // `speechConfig.languageCode` (the old, request-corrupting behavior). Assert the prefix lands
        // in parts[0].text as "<instr>: <input>" and no languageCode key is emitted.
        let ir = IrReq::Speech(crate::ir::audio::SpeechReq {
            input: "hello".into(),
            voice: "Kore".into(),
            instructions: Some("speak cheerfully".into()),
            ..Default::default()
        });
        let out = SPEECH.write_request(&ir);
        let v: Value = serde_json::from_slice(&out).unwrap();
        let text = v
            .pointer("/contents/0/parts/0/text")
            .and_then(Value::as_str)
            .expect("prompt text present");
        assert_eq!(text, "speak cheerfully: hello");
        assert!(
            !serde_json::to_string(&v).unwrap().contains("languageCode"),
            "instructions must not corrupt speechConfig.languageCode: {v}"
        );
    }
}
