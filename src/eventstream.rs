// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! AWS event-stream (`application/vnd.amazon.eventstream`) frame codec.
//!
//! [`drain_frames`] is the DECODER — just enough to pull `(:event-type, payload)` pairs out of
//! Bedrock ConverseStream responses so they can feed the Bedrock reader's existing
//! `read_response_events`. Incremental: leaves a trailing partial frame in the buffer. CRCs are not
//! validated on decode (we are a client decoder consuming well-formed AWS frames).
//!
//! [`encode_frame`] is the production ENCODER (the exact inverse of [`drain_frames`]) used for
//! Bedrock *ingress* streaming: a native AWS SDK Bedrock client consumes the binary framing, so the
//! frames must be byte-exact with VALID CRC32 (AWS clients reject malformed/zero CRCs).
//!
//! Frame layout:
//! ```text
//!   [total_len: u32 BE][headers_len: u32 BE][prelude_crc: u32 BE]
//!   [headers: headers_len bytes]
//!   [payload: total_len - headers_len - 16 bytes]
//!   [message_crc: u32 BE]
//! ```
//! Header: `[name_len: u8][name][value_type: u8][value]`. Bedrock uses string headers (type 7):
//! `[value_len: u16 BE][value]`.

/// Upper bound on a single event-stream frame. Bedrock ConverseStream frames are small JSON deltas
/// (well under this), so a declared `total_len` above this cap can only be a malformed or hostile
/// prelude. Bounding it stops a single frame's declared length from driving unbounded buffering.
///
/// NOTE on the effective per-frame ceiling: the egress reassembly path in
/// `StreamTranslate::feed` aborts a stream once its reassembly buffer exceeds
/// `StreamTranslate::MAX_BUF`. The two caps are deliberately kept equal so that any frame the decoder
/// here is willing to assemble can also be buffered to completion upstream — otherwise a frame
/// between the two caps would be aborted before `drain_frames` ever saw it. Keep `MAX_FRAME_BYTES`
/// and `StreamTranslate::MAX_BUF` in sync.
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Drain every COMPLETE frame from `buf`, returning `(event_type, payload_bytes)` per frame and
/// leaving any trailing partial frame buffered. A malformed prelude clears the buffer (the stream
/// is unrecoverable) rather than looping.
pub(crate) fn drain_frames(buf: &mut Vec<u8>) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    loop {
        if buf.len() < 12 {
            break; // need the full prelude
        }
        let total_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let headers_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        // `total_len` is attacker/upstream-controlled (up to ~4 GiB). Reject any frame larger than
        // MAX_FRAME_BYTES BEFORE waiting for `buf.len() >= total_len`, otherwise a crafted prelude
        // declaring an enormous internally-consistent length would force the caller to buffer
        // unbounded bytes toward a frame that never arrives (memory-exhaustion DoS). An oversized
        // length is treated like any other malformed prelude: abandon the (unrecoverable) stream.
        if !(16..=MAX_FRAME_BYTES).contains(&total_len) || headers_len > total_len - 16 {
            buf.clear(); // malformed — abandon the stream rather than spin
            break;
        }
        if buf.len() < total_len {
            break; // partial frame — wait for more bytes
        }
        let frame: Vec<u8> = buf.drain(..total_len).collect();
        let headers = &frame[12..12 + headers_len];
        let payload = &frame[12 + headers_len..total_len - 4];
        let event_type = parse_event_type(headers).unwrap_or_default();
        out.push((event_type, payload.to_vec()));
    }
    out
}

/// Find the `:event-type` string header value. Handles the u16-length-prefixed string/bytes value
/// types (string = 7, bytes = 6) by reading their value, and the AWS-spec fixed-width types
/// (bool/byte/short/int/long/timestamp/uuid) by SKIPPING the correct number of bytes so a non-string
/// header appearing before `:event-type` no longer aborts the scan. Returns `None` only when the
/// header block is truncated or carries a value-type byte with no defined width (a genuinely
/// malformed frame), so a future AWS framing header (e.g. a timestamp correlation header) does not
/// silently drop the event type.
fn parse_event_type(mut h: &[u8]) -> Option<String> {
    while !h.is_empty() {
        let name_len = *h.first()? as usize;
        if h.len() < 1 + name_len + 1 {
            return None;
        }
        let name = &h[1..1 + name_len];
        let value_type = h[1 + name_len];
        let mut p = 1 + name_len + 1;
        // AWS event-stream value types. Fixed-width types carry no length prefix and are skipped by
        // advancing `p`; the variable-width string/bytes types (6/7) carry a u16 length prefix.
        let fixed_width: Option<usize> = match value_type {
            0 | 1 => Some(0), // bool true / bool false — value is encoded in the type byte itself
            2 => Some(1),     // byte
            3 => Some(2),     // short
            4 => Some(4),     // int
            5 => Some(8),     // long
            8 => Some(8),     // timestamp
            9 => Some(16),    // uuid
            _ => None,
        };
        let value: Option<&[u8]> = match value_type {
            6 | 7 => {
                if h.len() < p + 2 {
                    return None;
                }
                let vlen = u16::from_be_bytes([h[p], h[p + 1]]) as usize;
                p += 2;
                if h.len() < p + vlen {
                    return None;
                }
                let v = &h[p..p + vlen];
                p += vlen;
                Some(v)
            }
            _ => match fixed_width {
                Some(w) => {
                    if h.len() < p + w {
                        return None;
                    }
                    p += w;
                    None
                }
                // Unknown value-type byte with no defined width: the frame is malformed, bail.
                None => return None,
            },
        };
        if name == b":event-type" {
            // `:event-type` is always a string (type 7) in AWS framing; if it appeared with a
            // fixed-width type there is no string value to return.
            return value.and_then(|v| std::str::from_utf8(v).ok().map(String::from));
        }
        h = &h[p..];
    }
    None
}

/// Append one `[name_len:u8][name][value_type:u8 = 7 string][value_len:u16 BE][value]` string
/// header to `headers`. Lengths are bounded by `MAX_FRAME_BYTES` framing (`name` is a fixed `:`-
/// prefixed label and `value` is a short event-type string), so the `u8`/`u16` casts never wrap on
/// any value this encoder produces.
fn push_string_header(headers: &mut Vec<u8>, name: &str, value: &str) {
    // name_len is a u8: header names here are fixed short literals (`:event-type` etc.), so
    // `min(255)` is a defensive clamp that never triggers on real input rather than a wrap risk.
    let name_len = name.len().min(u8::MAX as usize) as u8;
    headers.push(name_len);
    headers.extend_from_slice(&name.as_bytes()[..name_len as usize]);
    headers.push(7); // value_type 7 = UTF-8 string
    let value_len = value.len().min(u16::MAX as usize) as u16;
    headers.extend_from_slice(&value_len.to_be_bytes());
    headers.extend_from_slice(&value.as_bytes()[..value_len as usize]);
}

/// Encode one AWS `application/vnd.amazon.eventstream` message — the exact inverse of one
/// [`drain_frames`] iteration, with REAL CRC32 (AWS SDK clients validate both CRCs).
///
/// Wire layout:
/// ```text
///   [total_len:u32 BE][headers_len:u32 BE][prelude_crc:u32 BE = CRC32(first 8 bytes)]
///   [headers][payload]
///   [message_crc:u32 BE = CRC32(byte 0 .. end of payload)]
/// ```
/// A Bedrock ConverseStream frame carries three string headers — `:event-type` (the event name),
/// `:content-type` (`application/json`) and `:message-type` (`event`). Runs in the streaming hot
/// path: all arithmetic is `u64`-widened and the result is bounded by `MAX_FRAME_BYTES`, so no cast
/// can wrap (frame lengths are bounded and this never panics on the request path).
pub(crate) fn encode_frame(event_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut headers = Vec::new();
    push_string_header(&mut headers, ":event-type", event_type);
    push_string_header(&mut headers, ":content-type", "application/json");
    push_string_header(&mut headers, ":message-type", "event");
    encode_with_headers(headers, payload)
}

/// Encode a modeled-exception event-stream message for a native AWS SDK Bedrock client. AWS signals
/// a mid-stream error with `:message-type: exception` and an `:exception-type` header naming the
/// Converse exception (e.g. `InternalServerException`, `ModelStreamErrorException`); the payload is
/// the JSON `{"message": ...}` body the SDK surfaces. This is what a Bedrock-ingress stream must emit
/// on a mid-stream upstream failure instead of an SSE `event: error` text frame — writing SSE text
/// into a binary eventstream body produces an undecodable prelude/CRC for the SDK's decoder.
pub(crate) fn encode_exception_frame(exception_type: &str, message: &str) -> Vec<u8> {
    let payload = serde_json::to_vec(&serde_json::json!({ "message": message }))
        .unwrap_or_else(|_| b"{\"message\":\"upstream stream error\"}".to_vec());
    let mut headers = Vec::new();
    push_string_header(&mut headers, ":exception-type", exception_type);
    push_string_header(&mut headers, ":content-type", "application/json");
    push_string_header(&mut headers, ":message-type", "exception");
    encode_with_headers(headers, &payload)
}

/// Frame a pre-built header block + payload into a complete event-stream message with real CRC32s.
/// Shared by [`encode_frame`] and [`encode_exception_frame`].
///
/// A frame this encoder builds is always well under `MAX_FRAME_BYTES` (small JSON bodies). If the
/// header+payload would exceed the cap, the frame is DROPPED (empty `Vec` returned) rather than
/// byte-truncating the payload: a truncated JSON payload is syntactically invalid and a CRC-valid
/// frame carrying unparseable JSON is worse for a native SDK than no frame at all. The caller appends
/// the result to its output buffer, so an empty return simply emits nothing for this event.
fn encode_with_headers(headers: Vec<u8>, payload: &[u8]) -> Vec<u8> {
    // total_len = prelude(12) + headers + payload + message_crc(4). Widen to u64 so the sum cannot
    // overflow `usize` arithmetic, then bound it against MAX_FRAME_BYTES.
    let prelude = 12u64;
    let trailer = 4u64;
    let headers_len = headers.len() as u64;
    let total_len = prelude + headers_len + payload.len() as u64 + trailer;
    if total_len > MAX_FRAME_BYTES as u64 {
        // Oversized: drop the frame rather than emit corrupt (truncated) JSON. Unreachable for any
        // real Bedrock ConverseStream delta; this only guards a pathological multi-MiB single event.
        // Dropping a frame is graceful (the caller appends the empty result and emits nothing for
        // this event); a CRC-valid frame carrying truncated, unparseable JSON would be worse.
        tracing::warn!(
            total_len,
            cap = MAX_FRAME_BYTES,
            "event-stream frame exceeds MAX_FRAME_BYTES; dropping"
        );
        return Vec::new();
    }

    let mut frame = Vec::with_capacity(total_len as usize);
    // Prelude: total_len + headers_len (both u32 BE). Bounded above, so the casts are exact.
    frame.extend_from_slice(&(total_len as u32).to_be_bytes());
    frame.extend_from_slice(&(headers_len as u32).to_be_bytes());

    // prelude_crc = CRC32 of the first 8 bytes (the two length fields).
    let mut prelude_hasher = crc32fast::Hasher::new();
    prelude_hasher.update(&frame[..8]);
    frame.extend_from_slice(&prelude_hasher.finalize().to_be_bytes());

    frame.extend_from_slice(&headers);
    frame.extend_from_slice(payload);

    // message_crc = CRC32 of everything from byte 0 through the end of the payload (i.e. the whole
    // frame written so far, which is prelude + prelude_crc + headers + payload).
    let mut message_hasher = crc32fast::Hasher::new();
    message_hasher.update(&frame);
    frame.extend_from_slice(&message_hasher.finalize().to_be_bytes());

    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_single_frame() {
        let mut buf = encode_frame("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#);
        let frames = drain_frames(&mut buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, "contentBlockDelta");
        assert_eq!(frames[0].1, br#"{"delta":{"text":"hi"}}"#);
        assert!(buf.is_empty(), "fully-consumed buffer");
    }

    #[test]
    fn test_decode_multiple_and_partial() {
        let mut buf = encode_frame("messageStart", br#"{"role":"assistant"}"#);
        buf.extend(encode_frame("messageStop", br#"{"stopReason":"end_turn"}"#));
        // Append a truncated third frame (only part of its prelude+body).
        let partial = encode_frame("metadata", br#"{"usage":{}}"#);
        buf.extend_from_slice(&partial[..partial.len() - 5]);

        let frames = drain_frames(&mut buf);
        assert_eq!(frames.len(), 2, "two complete frames decoded");
        assert_eq!(frames[0].0, "messageStart");
        assert_eq!(frames[1].0, "messageStop");
        assert!(!buf.is_empty(), "partial third frame remains buffered");

        // Feed the rest → the third frame completes.
        buf.extend_from_slice(&partial[partial.len() - 5..]);
        let more = drain_frames(&mut buf);
        assert_eq!(more.len(), 1);
        assert_eq!(more[0].0, "metadata");
        assert!(buf.is_empty());
    }

    #[test]
    fn test_oversized_total_len_is_abandoned_not_buffered() {
        // A prelude declaring an enormous-but-internally-consistent total_len must be rejected
        // immediately (buffer cleared, stream abandoned) rather than waiting to accumulate that many
        // bytes — otherwise it is a memory-exhaustion DoS vector.
        let mut buf = Vec::new();
        let huge: u32 = u32::MAX; // ~4 GiB, far above MAX_FRAME_BYTES but >= 16 and self-consistent
        buf.extend_from_slice(&huge.to_be_bytes()); // total_len
        buf.extend_from_slice(&0u32.to_be_bytes()); // headers_len = 0 (<= total_len - 16)
        buf.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC
        buf.extend_from_slice(b"trailing junk"); // a few extra bytes

        let frames = drain_frames(&mut buf);
        assert!(frames.is_empty(), "no frame should be emitted");
        assert!(
            buf.is_empty(),
            "oversized frame must clear the buffer, not buffer toward total_len"
        );
    }

    #[test]
    fn test_frame_at_cap_still_decodes() {
        // A normal, small frame (well under MAX_FRAME_BYTES) is unaffected by the cap.
        let mut buf = encode_frame("contentBlockDelta", br#"{"delta":{"text":"ok"}}"#);
        let frames = drain_frames(&mut buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, "contentBlockDelta");
        assert!(buf.is_empty());
    }

    /// `drain_frames(encode_frame(x)) == [x]` for a spread of event types + payload sizes, including
    /// empty and large payloads. This is the encoder's primary acceptance gate: it proves the
    /// framing + CRC are correct against the existing production decoder (decode(encode(x)) == x).
    #[test]
    fn test_encode_decode_round_trip() {
        let cases: &[(&str, Vec<u8>)] = &[
            ("messageStart", br#"{"role":"assistant"}"#.to_vec()),
            ("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#.to_vec()),
            ("messageStop", br#"{"stopReason":"end_turn"}"#.to_vec()),
            (
                "metadata",
                br#"{"usage":{"inputTokens":3,"outputTokens":5}}"#.to_vec(),
            ),
            ("contentBlockStop", Vec::new()), // empty payload
            ("contentBlockDelta", vec![b'x'; 64 * 1024]), // large payload
        ];
        for (event_type, payload) in cases {
            let mut buf = encode_frame(event_type, payload);
            let frames = drain_frames(&mut buf);
            assert_eq!(frames.len(), 1, "exactly one frame for {event_type}");
            assert_eq!(&frames[0].0, event_type, "event type round-trips");
            assert_eq!(
                &frames[0].1, payload,
                "payload round-trips for {event_type}"
            );
            assert!(buf.is_empty(), "buffer fully consumed for {event_type}");
        }
    }

    /// The encoder writes REAL CRC32s (not the `[0,0,0,0]` placeholders the old test helper used).
    /// Independently recompute both CRCs over the exact byte ranges the spec defines and assert they
    /// match the bytes the encoder emitted — and that neither is zero.
    #[test]
    fn test_encode_crcs_are_real() {
        let frame = encode_frame("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#);
        let total_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(
            total_len,
            frame.len(),
            "total_len matches the bytes written"
        );

        // prelude_crc lives at bytes [8..12] and covers bytes [0..8].
        let prelude_crc = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
        let expected_prelude = crc32fast::hash(&frame[..8]);
        assert_eq!(
            prelude_crc, expected_prelude,
            "prelude CRC is the real CRC32"
        );
        assert_ne!(prelude_crc, 0, "prelude CRC is not the zero placeholder");

        // message_crc is the trailing 4 bytes and covers everything before it (bytes 0..len-4).
        let len = frame.len();
        let message_crc = u32::from_be_bytes([
            frame[len - 4],
            frame[len - 3],
            frame[len - 2],
            frame[len - 1],
        ]);
        let expected_message = crc32fast::hash(&frame[..len - 4]);
        assert_eq!(
            message_crc, expected_message,
            "message CRC is the real CRC32"
        );
        assert_ne!(message_crc, 0, "message CRC is not the zero placeholder");
    }

    /// `parse_event_type` must return `None` (rather than panic or misread) when it meets a header
    /// whose value-type byte is genuinely unknown / has no defined width.
    #[test]
    fn test_parse_event_type_unknown_value_type_returns_none() {
        // One header named "x" with value_type = 200 (not a real AWS type) → malformed → None.
        let mut h = Vec::new();
        h.push(1u8); // name_len
        h.extend_from_slice(b"x"); // name
        h.push(200u8); // value_type: unknown
        assert_eq!(parse_event_type(&h), None);
    }

    /// A fixed-width header (e.g. a `timestamp`, type 8) appearing BEFORE `:event-type` must be
    /// skipped by advancing the correct number of bytes, not abort the scan — so the event type is
    /// still recovered.
    #[test]
    fn test_parse_event_type_skips_fixed_width_header() {
        let mut h = Vec::new();
        // Header 1: ":ts" timestamp (type 8, 8-byte value) — must be skipped.
        h.push(3u8);
        h.extend_from_slice(b":ts");
        h.push(8u8); // timestamp
        h.extend_from_slice(&0u64.to_be_bytes()); // 8 bytes
                                                  // Header 2: ":event-type" string = "messageStart".
        h.push(11u8);
        h.extend_from_slice(b":event-type");
        h.push(7u8); // string
        let v = b"messageStart";
        h.extend_from_slice(&(v.len() as u16).to_be_bytes());
        h.extend_from_slice(v);
        assert_eq!(parse_event_type(&h), Some("messageStart".to_string()));
    }

    /// A zero-length `:event-type` string value yields `Some("")`, not `None` — a present-but-empty
    /// event type is distinct from an absent header.
    #[test]
    fn test_parse_event_type_empty_value() {
        let mut h = Vec::new();
        h.push(11u8);
        h.extend_from_slice(b":event-type");
        h.push(7u8); // string
        h.extend_from_slice(&0u16.to_be_bytes()); // zero-length value
        assert_eq!(parse_event_type(&h), Some(String::new()));
    }

    /// A modeled-exception frame is a valid event-stream message: real CRC32s, and a header block
    /// carrying `:message-type: exception` + `:exception-type` + the JSON `{"message":...}` payload.
    /// This is what a Bedrock-ingress stream emits on a mid-stream upstream failure.
    #[test]
    fn test_encode_exception_frame_is_valid() {
        let frame = encode_exception_frame("InternalServerException", "upstream stream error");
        // total_len must equal the bytes written.
        let total_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(total_len, frame.len(), "total_len matches frame bytes");
        // prelude CRC over [0..8] is real.
        let prelude_crc = u32::from_be_bytes([frame[8], frame[9], frame[10], frame[11]]);
        assert_eq!(prelude_crc, crc32fast::hash(&frame[..8]));
        // message CRC over [0..len-4] is real.
        let len = frame.len();
        let msg_crc = u32::from_be_bytes([
            frame[len - 4],
            frame[len - 3],
            frame[len - 2],
            frame[len - 1],
        ]);
        assert_eq!(msg_crc, crc32fast::hash(&frame[..len - 4]));
        // Header block carries the exception markers.
        let headers_len = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
        let headers = String::from_utf8_lossy(&frame[12..12 + headers_len]);
        assert!(headers.contains(":message-type"));
        assert!(headers.contains("exception"));
        assert!(headers.contains(":exception-type"));
        assert!(headers.contains("InternalServerException"));
        // Payload is the JSON body the SDK surfaces.
        let payload = &frame[12 + headers_len..len - 4];
        let v: serde_json::Value = serde_json::from_slice(payload).unwrap();
        assert_eq!(v["message"], "upstream stream error");
        // It must NOT be SSE text.
        assert!(!frame.starts_with(b"event:"));
    }

    /// An oversized payload (above `MAX_FRAME_BYTES`) must be DROPPED (empty frame), never emitted as
    /// a CRC-valid frame carrying byte-truncated, unparseable JSON. Exercises the cap branch that the
    /// round-trip test (64 KiB) never reaches.
    #[test]
    fn test_encode_frame_oversized_payload_drops_frame() {
        // A payload comfortably above MAX_FRAME_BYTES.
        let payload = vec![b'x'; MAX_FRAME_BYTES + 1024];
        let frame = encode_frame("contentBlockDelta", &payload);
        assert!(
            frame.is_empty(),
            "oversized payload must drop the frame, not truncate JSON into a CRC-valid corrupt frame"
        );
    }

    /// The encoder carries the three Bedrock framing headers (`:event-type`, `:content-type`,
    /// `:message-type`); `parse_event_type` must skip past the others and still find the event name.
    #[test]
    fn test_encode_carries_three_headers() {
        let frame = encode_frame("messageStart", br#"{"role":"assistant"}"#);
        let headers_len = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
        let headers = &frame[12..12 + headers_len];
        // :content-type and :message-type values must be present in the header block.
        let hs = String::from_utf8_lossy(headers);
        assert!(hs.contains(":event-type"));
        assert!(hs.contains(":content-type"));
        assert!(hs.contains("application/json"));
        assert!(hs.contains(":message-type"));
        assert!(hs.contains("event"));
    }
}
