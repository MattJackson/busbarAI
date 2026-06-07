// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! AWS event-stream (`application/vnd.amazon.eventstream`) frame decoder — just enough to
//! pull `(:event-type, payload)` pairs out of Bedrock ConverseStream responses so they can feed the
//! Bedrock reader's existing `read_response_events`. Incremental: leaves a trailing partial frame in
//! the buffer. CRCs are not validated (we are a client decoder consuming well-formed AWS frames).
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

/// Find the `:event-type` string header value. Handles the u16-length-prefixed value types (string
/// = 7, bytes = 6); bails on other types (Bedrock's framing headers are all strings).
fn parse_event_type(mut h: &[u8]) -> Option<String> {
    while !h.is_empty() {
        let name_len = *h.first()? as usize;
        if h.len() < 1 + name_len + 1 {
            return None;
        }
        let name = &h[1..1 + name_len];
        let value_type = h[1 + name_len];
        let mut p = 1 + name_len + 1;
        let value: &[u8] = match value_type {
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
                v
            }
            _ => return None, // unexpected non-string header before :event-type
        };
        if name == b":event-type" {
            return std::str::from_utf8(value).ok().map(String::from);
        }
        h = &h[p..];
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode one event-stream frame with a single `:event-type` string header + JSON payload.
    fn encode_frame(event_type: &str, payload: &[u8]) -> Vec<u8> {
        // header: name_len(1) + name + value_type(1=7) + value_len(2) + value
        let name = b":event-type";
        let mut headers = Vec::new();
        headers.push(name.len() as u8);
        headers.extend_from_slice(name);
        headers.push(7); // string
        headers.extend_from_slice(&(event_type.len() as u16).to_be_bytes());
        headers.extend_from_slice(event_type.as_bytes());

        let total_len = 12 + headers.len() + payload.len() + 4;
        let mut frame = Vec::new();
        frame.extend_from_slice(&(total_len as u32).to_be_bytes());
        frame.extend_from_slice(&(headers.len() as u32).to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC (unvalidated)
        frame.extend_from_slice(&headers);
        frame.extend_from_slice(payload);
        frame.extend_from_slice(&[0, 0, 0, 0]); // message CRC (unvalidated)
        frame
    }

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
}
