//! Opaque media payload value types for the operations rebuild (design-operations-oop.md §5b).
//!
//! Two distinct value types, deliberately NOT unified (the re-verification, finding C3, showed a
//! single one-of type is lossy for image output):
//!
//! - [`MediaBlob`] — AUDIO. A single representation (bytes OR base64 OR uri), enforced by a one-of
//!   enum. Carries optional PCM parameters because headerless raw PCM (`audio/L16`, OpenAI `pcm`)
//!   keeps sample-rate / channels / bit-depth in the model contract, not the bytes.
//! - [`ImageOutput`] — IMAGE. ADDITIVE: a single image may legitimately return base64 AND a url/uri
//!   at once (dall-e URL, Vertex `gcsUri`, everyone-else base64), and losslessness requires keeping
//!   every form present — so optionals, never a one-of.
//!
//! Foundation types; `dead_code` allowed until the IR wiring lands.
#![allow(dead_code)]

use bytes::Bytes;

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 (RFC 4648 §4, with `=` padding). Audio cells cross the JSON/binary boundary
/// (Gemini inline_data is base64; OpenAI speech is raw bytes), so encode/decode live with the blob
/// types rather than pulling in a `base64` crate.
pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(B64_ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64_ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Decode standard base64 (padding optional; whitespace ignored). Returns `None` on any invalid byte
/// so a malformed provider payload fails loud rather than silently truncating audio.
pub(crate) fn base64_decode(input: &str) -> Option<Bytes> {
    let mut val = [255u8; 256];
    for (i, &c) in B64_ALPHABET.iter().enumerate() {
        val[c as usize] = i as u8;
    }
    let mut bits: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for &b in input.as_bytes() {
        if b == b'=' || b.is_ascii_whitespace() {
            continue;
        }
        let v = val[b as usize];
        if v == 255 {
            return None;
        }
        bits = (bits << 6) | v as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    Some(Bytes::from(out))
}

/// Audio payload — exactly ONE representation, enforced. `B64` is the lossless common denominator
/// across providers; `Bytes` is the raw OpenAI binary response; `Uri` covers reference forms.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum MediaPayload {
    Bytes(Bytes),
    B64(String),
    Uri(String),
}

/// Sample parameters for headerless raw PCM (`audio/L16;codec=pcm;rate=24000`, OpenAI `pcm`), where
/// the wire bytes carry no container header. `None` on `MediaBlob.pcm` for self-describing formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PcmParams {
    pub(crate) sample_rate: u32,
    pub(crate) channels: u8,
    pub(crate) bit_depth: u8,
}

/// A single audio payload (transcription input / speech output). One representation + its MIME type,
/// plus PCM parameters iff the MIME type is headerless raw PCM.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MediaBlob {
    pub(crate) payload: MediaPayload,
    pub(crate) mime_type: String,
    pub(crate) pcm: Option<PcmParams>,
}

impl MediaBlob {
    /// Well-formedness: PCM parameters are present iff the MIME type denotes headerless raw PCM.
    /// Guards against an OperationHandler that forgets the params on `audio/L16`/`pcm` (silently lossy) or attaches
    /// them to a self-describing container (meaningless).
    pub(crate) fn is_well_formed(&self) -> bool {
        let raw_pcm = self.mime_type.contains("L16")
            || self.mime_type.ends_with("/pcm")
            || self.mime_type.contains("codec=pcm");
        raw_pcm == self.pcm.is_some()
    }
}

/// A single generated image. ADDITIVE (finding C3): `b64` and `url` may BOTH be present and both are
/// kept. `b64` is the common path; `url`/`uri` are additive (dall-e URL, Vertex `gcsUri`). The other
/// fields are provider-specific extras kept for lossless round-trip.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ImageOutput {
    pub(crate) b64: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) mime_type: Option<String>,
    pub(crate) revised_prompt: Option<String>, // dall-e-3
    pub(crate) seed: Option<u64>,              // SDXL / Stable Image
    pub(crate) finish_reason: Option<String>,  // SUCCESS / CONTENT_FILTERED / "Filter reason: …"
}

impl ImageOutput {
    /// At least one representation must be present — an image output with neither `b64` nor `url` is
    /// meaningless (and would silently drop the image).
    pub(crate) fn has_payload(&self) -> bool {
        self.b64.is_some() || self.url.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mediablob_pcm_required_iff_raw_pcm() {
        let l16 = MediaBlob {
            payload: MediaPayload::B64("AA==".into()),
            mime_type: "audio/L16;codec=pcm;rate=24000".into(),
            pcm: Some(PcmParams {
                sample_rate: 24000,
                channels: 1,
                bit_depth: 16,
            }),
        };
        assert!(l16.is_well_formed());

        let l16_missing = MediaBlob {
            pcm: None,
            ..l16.clone()
        };
        assert!(
            !l16_missing.is_well_formed(),
            "raw PCM without params is silently lossy"
        );

        let mp3 = MediaBlob {
            payload: MediaPayload::Bytes(Bytes::from_static(b"\xff\xfb")),
            mime_type: "audio/mpeg".into(),
            pcm: None,
        };
        assert!(mp3.is_well_formed());
    }

    #[test]
    fn image_output_is_additive_b64_and_url_coexist() {
        let img = ImageOutput {
            b64: Some("iVBORw0KGgo=".into()),
            url: Some("https://example/img.png".into()),
            ..Default::default()
        };
        // Both present, both kept — the C3 losslessness requirement a one-of would break.
        assert!(img.b64.is_some() && img.url.is_some());
        assert!(img.has_payload());
        assert!(!ImageOutput::default().has_payload());
    }
}
