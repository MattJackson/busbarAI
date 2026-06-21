// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! AWS event-stream (`application/vnd.amazon.eventstream`) frame codec.
//!
//! [`drain_frames_checked`] is the production DECODER — just enough to pull `(event_type, payload)`
//! pairs out of Bedrock ConverseStream responses so they can feed the Bedrock reader's existing
//! `read_response_events`. Incremental: leaves a trailing partial frame in the buffer. CRCs are not
//! validated on decode (we are a client decoder consuming well-formed AWS frames). (`drain_frames`
//! is a test-only thin wrapper that discards the consumed-byte count.)
//!
//! The returned `event_type` is normally the frame's `:event-type` header. AWS, however, signals a
//! mid-stream MODELED EXCEPTION with a frame that carries `:message-type: exception` plus an
//! `:exception-type: <ExceptionName>` header and NO `:event-type` (e.g. a `ThrottlingException` or
//! `InternalServerException` mid ConverseStream). For those frames [`drain_frames_checked`] returns the
//! exception name normalized to the Smithy union-member form (leading letter lowercased, e.g.
//! `internalServerException`) so it matches the `read_response_events` exception arms and is surfaced
//! as an error event rather than being silently dropped as a typeless no-op frame.
//!
//! [`encode_frame`] is the production ENCODER (the exact inverse of [`drain_frames_checked`]) used for
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
/// between the two caps would be aborted before `drain_frames_checked` ever saw it. Keep `MAX_FRAME_BYTES`
/// and `StreamTranslate::MAX_BUF` in sync.
pub(crate) const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Outcome of a [`drain_frames_checked`] pass: WHY the decoder stopped pulling frames from the
/// buffer. This is the DISTINCT abandonment signal the egress reassembler (`StreamTranslate::feed`)
/// must key off — previously it inferred a malformed-prelude abort by observing that `drain_frames`
/// had emptied the buffer, which is fragile: a normal pass that happens to consume every buffered
/// byte ALSO leaves an empty buffer, so length alone cannot tell a clean full-drain apart from an
/// unrecoverable abort. Making the abort an explicit variant removes that ambiguity entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrainStatus {
    /// The decoder consumed every COMPLETE frame and stopped cleanly: either the buffer is now empty
    /// or it holds only a trailing PARTIAL frame awaiting more bytes. The buffer is intact and the
    /// stream is healthy — feed more bytes and call again.
    Ok,
    /// A malformed prelude (out-of-range `total_len`, or `headers_len` larger than the frame can
    /// hold) was encountered. The stream is UNRECOVERABLE: the buffer has been cleared and the caller
    /// must abandon the stream rather than continue feeding it. This is the propagated abort signal
    /// (no longer length-inferred).
    MalformedPrelude,
}

/// Drain every COMPLETE frame from `buf`, returning the `(event_type, payload_bytes)` pairs AND a
/// [`DrainStatus`] saying why the pass stopped. [`DrainStatus::MalformedPrelude`] is the EXPLICIT,
/// propagated abort signal: on a malformed prelude the buffer is cleared (the stream is
/// unrecoverable) and the status reflects it, so the caller no longer has to infer abandonment from
/// the (ambiguous) post-pass buffer length. A clean pass — buffer emptied or a trailing partial
/// frame left buffered — returns [`DrainStatus::Ok`]. The third tuple element is the count of bytes
/// consumed as COMPLETE VALID frames from the front of `buf` (excluding any malformed-prelude
/// remainder that was cleared), available to callers needing a byte-accurate count of bytes consumed
/// as complete valid frames (excluding any malformed-prelude remainder); the same-protocol verbatim
/// re-emit path uses the `consumed_sink` parameter instead and discards this count.
/// `consumed_sink`, when `Some`, receives the VERBATIM bytes of each complete valid frame as it is
/// drained (in frame order). The same-protocol bedrock→bedrock re-emit path uses this to forward the
/// original frame bytes unchanged WITHOUT cloning the whole reassembly buffer on every chunk: that
/// per-chunk `buf.clone()` was O(buf) each call, so a large frame arriving as many small chunks cost
/// O(chunks × buf) cumulative allocation (a memory-pressure DoS). The sink collects only the bytes
/// actually consumed — nothing on a chunk that completes no frame — and never the cleared
/// malformed-prelude remainder (the malformed branch breaks before the push). Pass `None` on the
/// cross-protocol path, which re-encodes and needs no verbatim copy.
pub(crate) fn drain_frames_checked(
    buf: &mut Vec<u8>,
    mut consumed_sink: Option<&mut Vec<u8>>,
) -> (Vec<(String, Vec<u8>)>, DrainStatus, usize) {
    let mut out = Vec::new();
    let mut status = DrainStatus::Ok;
    // Bytes consumed as COMPLETE, VALID frames from the FRONT. On a MalformedPrelude the buffer is
    // cleared, but this counts ONLY the valid frames drained before it — so a same-proto verbatim
    // re-emit can forward exactly those bytes and never the cleared malformed remainder.
    let mut valid_consumed = 0usize;
    loop {
        if buf.len() < PRELUDE_LEN {
            break; // need the full prelude
        }
        let total_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let headers_len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
        // `total_len` is attacker/upstream-controlled (up to ~4 GiB). Reject any frame larger than
        // MAX_FRAME_BYTES BEFORE waiting for `buf.len() >= total_len`, otherwise a crafted prelude
        // declaring an enormous internally-consistent length would force the caller to buffer
        // unbounded bytes toward a frame that never arrives (memory-exhaustion DoS). An oversized
        // length is treated like any other malformed prelude: abandon the (unrecoverable) stream.
        if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&total_len)
            || headers_len > total_len - MIN_FRAME_BYTES
        {
            buf.clear(); // malformed — abandon the stream rather than spin
            status = DrainStatus::MalformedPrelude; // distinct propagated signal, not length-inferred
            break;
        }
        if buf.len() < total_len {
            break; // partial frame — wait for more bytes
        }
        // Read the frame in place via slices into `buf` (one payload copy), then advance past it with
        // a single `drain` — rather than `drain(..total_len).collect()` into a throwaway per-frame
        // Vec (which was a SECOND heap allocation per frame on the hot streaming-decode path).
        let headers = &buf[PRELUDE_LEN..PRELUDE_LEN + headers_len];
        let event_type = event_type_for_frame(headers);
        let payload = buf[PRELUDE_LEN + headers_len..total_len - CRC_BYTES].to_vec();
        out.push((event_type, payload));
        // Capture the frame's verbatim bytes for the same-proto re-emit BEFORE draining them.
        if let Some(sink) = consumed_sink.as_deref_mut() {
            sink.extend_from_slice(&buf[..total_len]);
        }
        buf.drain(..total_len);
        valid_consumed += total_len;
    }
    (out, status, valid_consumed)
}

/// Drain every COMPLETE frame from `buf`, returning `(event_type, payload_bytes)` per frame and
/// leaving any trailing partial frame buffered. A malformed prelude clears the buffer (the stream
/// is unrecoverable) rather than looping.
///
/// Thin wrapper over [`drain_frames_checked`] that DISCARDS the [`DrainStatus`], used by the route /
/// proto tests that only need the decoded frames. Production code (the egress reassembler) calls
/// [`drain_frames_checked`] directly for the explicit malformed-prelude signal; after the byte-scanner's
/// `feed_eventstream` was removed, this convenience wrapper has only test callers, so it is
/// gated to test builds to avoid an unused-function warning in the 1.0 binary.
#[cfg(test)]
pub(crate) fn drain_frames(buf: &mut Vec<u8>) -> Vec<(String, Vec<u8>)> {
    drain_frames_checked(buf, None).0
}

/// The framing headers `drain_frames_checked` cares about: the normal `:event-type`, plus the
/// `:message-type` discriminator and `:exception-type` name that an AWS mid-stream modeled-exception
/// frame carries INSTEAD of an `:event-type`. All three are optional string headers.
#[derive(Default)]
struct FrameHeaders {
    event_type: Option<String>,
    message_type: Option<String>,
    exception_type: Option<String>,
}

/// Resolve the event-type token `drain_frames_checked` returns for one frame.
///
/// For a normal `event`-typed frame this is the `:event-type` header verbatim. For an AWS modeled
/// EXCEPTION frame (`:message-type: exception`, which carries `:exception-type: <ExceptionName>` and
/// NO `:event-type`), it is the exception name normalized to the Smithy union-member form (leading
/// letter lowercased) — `InternalServerException` → `internalServerException` — so it matches the
/// `read_response_events` exception arms instead of being dropped as a typeless no-op frame. Falls
/// back to the empty string when neither header is present (a genuinely typeless / malformed frame),
/// preserving the previous `unwrap_or_default()` behavior for that case.
fn event_type_for_frame(headers: &[u8]) -> String {
    let parsed = parse_frame_headers(headers);
    // An exception frame is identified by `:message-type: exception`. Prefer its `:exception-type`
    // (AWS does not set `:event-type` on these), normalized to the union-member token the reader
    // matches. This is what was previously lost: such a frame yielded `""` and was silently dropped.
    if parsed.message_type.as_deref() == Some(MSG_TYPE_EXCEPTION) {
        if let Some(exc) = parsed.exception_type {
            // AWS may qualify the `:exception-type` with a Smithy namespace / shape ARN prefix
            // (e.g. `com.amazon.coral.service#ThrottlingException`). Keep only the trailing bare
            // exception name before lowercasing — mirroring `extract_error`'s
            // `rsplit(['#', '/'])` in proto/bedrock.rs — so the normalized token matches the
            // `read_response_events` exception arms rather than being a no-op long namespaced string.
            //
            // Use the last NON-EMPTY token, not `.next()`: a value that ENDS with a delimiter
            // (e.g. `ThrottlingException#` or `aws.bedrock/`) makes `rsplit` yield an empty leading
            // token, which `.next()` would return verbatim — dropping the classification to `""`
            // and re-sinking the mid-stream error into the no-op arm. `.find(|s| !s.is_empty())`
            // skips that trailing-delimiter empty and recovers the bare name. The `unwrap_or(&exc)`
            // guards the all-delimiter case (e.g. `"#"`/`"/"`), where every token is empty: fall
            // back to the raw value rather than panicking or yielding `""`.
            let bare = exc
                .rsplit(['#', '/'])
                .find(|s| !s.is_empty())
                .unwrap_or(&exc);
            return lowercase_first(bare);
        }
    }
    parsed.event_type.unwrap_or_default()
}

/// Lowercase only the FIRST character of an exception name (`InternalServerException` →
/// `internalServerException`), mapping the AWS PascalCase `:exception-type` header to the Smithy
/// union-member token the `read_response_events` exception arms key off. ASCII-only by construction
/// (Converse exception names are ASCII identifiers); leaves the remainder untouched.
fn lowercase_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_ascii_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Scan the header block for the `:event-type`, `:message-type` and `:exception-type` string headers.
/// Handles the u16-length-prefixed string/bytes value types (string = 7, bytes = 6) by reading their
/// value, and the AWS-spec fixed-width types (bool/byte/short/int/long/timestamp/uuid) by SKIPPING
/// the correct number of bytes so a non-string header appearing before the ones we want no longer
/// aborts the scan. Stops early (returning whatever was found) only when the header block is
/// truncated or carries a value-type byte with no defined width (a genuinely malformed frame), so a
/// future AWS framing header (e.g. a timestamp correlation header) does not silently drop the
/// recognized headers that preceded it.
fn parse_frame_headers(mut h: &[u8]) -> FrameHeaders {
    let mut found = FrameHeaders::default();
    while !h.is_empty() {
        let Some(&name_len_byte) = h.first() else {
            break;
        };
        let name_len = name_len_byte as usize;
        if h.len() < 1 + name_len + 1 {
            break;
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
            6 | HDR_TYPE_STRING => {
                if h.len() < p + 2 {
                    break;
                }
                let vlen = u16::from_be_bytes([h[p], h[p + 1]]) as usize;
                p += 2;
                if h.len() < p + vlen {
                    break;
                }
                let v = &h[p..p + vlen];
                p += vlen;
                Some(v)
            }
            _ => match fixed_width {
                Some(w) => {
                    if h.len() < p + w {
                        break;
                    }
                    p += w;
                    None
                }
                // Unknown value-type byte with no defined width: the frame is malformed, bail.
                None => break,
            },
        };
        // These framing headers are always type-7 strings in AWS framing; capture each value when it
        // is one. A fixed-width-typed value carries no string to record.
        if let Some(v) = value.and_then(|v| std::str::from_utf8(v).ok()) {
            match name {
                n if n == HDR_EVENT_TYPE.as_bytes() => found.event_type = Some(v.to_string()),
                n if n == HDR_MESSAGE_TYPE.as_bytes() => found.message_type = Some(v.to_string()),
                n if n == HDR_EXCEPTION_TYPE.as_bytes() => {
                    found.exception_type = Some(v.to_string())
                }
                _ => {}
            }
        }
        h = &h[p..];
    }
    found
}

/// Append one `[name_len:u8][name][value_type:u8 = 7 string][value_len:u16 BE][value]` string
/// header to `headers`. The AWS event-stream spec caps a header name at 255 bytes (u8 length) and a
/// type-7 string value at 65535 bytes (u16 length). All current callers pass fixed short ASCII
/// labels and short event-type/exception names, so the limits never fire in practice.
///
/// Returns `false` (and pushes NOTHING) when `name` or `value` exceeds its length limit, rather than
/// silently byte-truncating: a truncation could split a multi-byte UTF-8 sequence, emitting a
/// CRC-valid frame carrying an invalid-UTF-8 type-7 string header that a strict AWS SDK rejects —
/// the exact "CRC-valid but corrupt" outcome `encode_with_headers` deliberately avoids for payloads.
/// The encoder treats a `false` return as a reason to DROP the whole frame (consistent with the
/// oversized-payload policy) — a graceful, no-panic outcome safe on the streaming request path in
/// every build profile (we do NOT `debug_assert`, which would panic a debug build on the hot path).
#[must_use]
fn push_string_header(headers: &mut Vec<u8>, name: &str, value: &str) -> bool {
    if name.len() > u8::MAX as usize || value.len() > u16::MAX as usize {
        return false; // oversized — drop rather than emit a truncated/corrupt header
    }
    headers.push(name.len() as u8);
    headers.extend_from_slice(name.as_bytes());
    headers.push(HDR_TYPE_STRING); // value_type 7 = UTF-8 string
    headers.extend_from_slice(&(value.len() as u16).to_be_bytes());
    headers.extend_from_slice(value.as_bytes());
    true
}

/// Encode one AWS `application/vnd.amazon.eventstream` message — the exact inverse of one
/// [`drain_frames_checked`] iteration, with REAL CRC32 (AWS SDK clients validate both CRCs).
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
    // Build the header block DIRECTLY into the frame buffer (after a 12-byte prelude placeholder)
    // rather than into a throwaway `headers` Vec that `encode_with_headers` would then copy — that
    // copy was a second heap allocation per frame on the Bedrock streaming hot path. `frame_open`
    // returns the single buffer with the prelude reserved; we append headers, then `frame_close`
    // backfills the prelude + CRCs. Byte output is identical to the prior two-buffer path.
    let mut frame = frame_open();
    // Drop the frame if any header is oversized rather than emit a corrupt/truncated header (see
    // push_string_header). `:event-type` is the only caller-supplied value; the others are literals.
    if !push_string_header(&mut frame, HDR_EVENT_TYPE, event_type)
        || !push_string_header(
            &mut frame,
            HDR_CONTENT_TYPE,
            crate::forward::APPLICATION_JSON,
        )
        || !push_string_header(&mut frame, HDR_MESSAGE_TYPE, MSG_TYPE_EVENT)
    {
        // An oversized header dropped the frame. This is unreachable for any real Bedrock event name
        // but must be OBSERVABLE rather than a silent empty-Vec: log it so a dropped streaming frame
        // is diagnosable. `:event-type` is the only caller-supplied (and thus possibly oversized)
        // value, so name it; the other two are fixed literals well under the cap.
        tracing::warn!(
            event_type_len = event_type.len(),
            "event-stream :event-type header exceeds the type-7 string cap; dropping frame"
        );
        return Vec::new();
    }
    frame_close(frame, payload)
}

/// Encode a modeled-exception event-stream message for a native AWS SDK Bedrock client. AWS signals
/// a mid-stream error with `:message-type: exception` and an `:exception-type` header naming the
/// Converse exception (e.g. `InternalServerException`, `ModelStreamErrorException`); the payload is
/// the JSON `{"message": ...}` body the SDK surfaces. This is what a Bedrock-ingress stream must emit
/// on a mid-stream upstream failure instead of an SSE `event: error` text frame — writing SSE text
/// into a binary eventstream body produces an undecodable prelude/CRC for the SDK's decoder.
pub(crate) fn encode_exception_frame(exception_type: &str, message: &str) -> Vec<u8> {
    // Fallback only if serializing `{"message": <string>}` somehow fails (effectively unreachable
    // for a plain string). Use AWS's own generic phrasing rather than any busbar-internal routing
    // vocabulary like "upstream" — a native Bedrock exception frame would never carry that word, so
    // leaking it here would be a protocol-indistinguishability tell (mirrors the scrub already done
    // for the Gemini truncation path in proto::gemini::GeminiJsonArrayFramer::finish_with_error).
    let payload = serde_json::to_vec(&serde_json::json!({ "message": message }))
        .unwrap_or_else(|_| b"{\"message\":\"An internal server error occurred.\"}".to_vec());
    // Build headers straight into the single frame buffer (see `encode_frame`) — one allocation.
    let mut frame = frame_open();
    if !push_string_header(&mut frame, HDR_EXCEPTION_TYPE, exception_type)
        || !push_string_header(
            &mut frame,
            HDR_CONTENT_TYPE,
            crate::forward::APPLICATION_JSON,
        )
        || !push_string_header(&mut frame, HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION)
    {
        // `:exception-type` is the caller-supplied value; an oversized one drops the frame. Log so a
        // dropped exception frame (a swallowed mid-stream error signal) is observable, not silent.
        tracing::warn!(
            exception_type_len = exception_type.len(),
            "event-stream :exception-type header exceeds the type-7 string cap; dropping frame"
        );
        return Vec::new();
    }
    frame_close(frame, &payload)
}

/// Length of the fixed event-stream prelude: `total_len:u32 + headers_len:u32 + prelude_crc:u32`.
const PRELUDE_LEN: usize = 12;

/// Length of the trailing CRC32 message checksum appended to every frame.
const CRC_BYTES: usize = 4;

/// Minimum valid frame size: prelude + message CRC, with zero-length headers and payload.
const MIN_FRAME_BYTES: usize = PRELUDE_LEN + CRC_BYTES;

/// AWS event-stream header name for the event type (normal frames).
const HDR_EVENT_TYPE: &str = ":event-type";

/// AWS event-stream header name for the content MIME type.
const HDR_CONTENT_TYPE: &str = ":content-type";

/// AWS event-stream header name for the message type discriminator (`event` or `exception`).
const HDR_MESSAGE_TYPE: &str = ":message-type";

/// AWS event-stream header name for the modeled-exception type (exception frames only).
const HDR_EXCEPTION_TYPE: &str = ":exception-type";

/// `:message-type` value for a normal Bedrock event frame.
const MSG_TYPE_EVENT: &str = "event";

/// `:message-type` value for an AWS mid-stream modeled-exception frame.
const MSG_TYPE_EXCEPTION: &str = "exception";

/// AWS event-stream value-type byte for a UTF-8 string header (type 7 per the spec).
const HDR_TYPE_STRING: u8 = 7;

/// Open a single frame buffer with the 12-byte prelude (`total_len`, `headers_len`, `prelude_crc`)
/// reserved as a zeroed placeholder. Callers append their header block directly after it, then hand
/// the buffer to [`frame_close`], which backfills the prelude. This keeps the WHOLE frame — prelude,
/// headers, payload and both CRCs — in ONE allocation (the prior `encode_with_headers` built headers
/// in a separate Vec and copied them in, a second per-frame allocation on the streaming hot path).
fn frame_open() -> Vec<u8> {
    vec![0u8; PRELUDE_LEN]
}

/// Close a frame opened by [`frame_open`] whose header block has been appended: backfill the prelude
/// (`total_len`, `headers_len`, real `prelude_crc`), append `payload`, then the real `message_crc`.
/// Shared by [`encode_frame`] and [`encode_exception_frame`]. The produced bytes are identical to the
/// prior two-buffer `encode_with_headers` path.
///
/// A frame this encoder builds is always well under `MAX_FRAME_BYTES` (small JSON bodies). If the
/// header+payload would exceed the cap, the frame is DROPPED (empty `Vec` returned) rather than
/// byte-truncating the payload: a truncated JSON payload is syntactically invalid and a CRC-valid
/// frame carrying unparseable JSON is worse for a native SDK than no frame at all. The caller appends
/// the result to its output buffer, so an empty return simply emits nothing for this event.
fn frame_close(mut frame: Vec<u8>, payload: &[u8]) -> Vec<u8> {
    // At entry `frame` is [12-byte prelude placeholder][headers]; everything past the prelude is the
    // header block.
    let headers_len = (frame.len() - PRELUDE_LEN) as u64;
    // total_len = prelude(12) + headers + payload + message_crc(4). Widen to u64 so the sum cannot
    // overflow `usize` arithmetic, then bound it against MAX_FRAME_BYTES.
    let total_len = PRELUDE_LEN as u64 + headers_len + payload.len() as u64 + CRC_BYTES as u64;
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

    // Reserve the payload + CRC trailer up front so appending them does not reallocate.
    frame.reserve(payload.len() + CRC_BYTES);

    // Backfill the prelude in place: total_len + headers_len (both u32 BE). Bounded above, so the
    // casts are exact.
    frame[0..4].copy_from_slice(&(total_len as u32).to_be_bytes());
    frame[4..8].copy_from_slice(&(headers_len as u32).to_be_bytes());

    // prelude_crc = CRC32 of the first 8 bytes (the two length fields).
    let prelude_crc = crc32fast::hash(&frame[..8]);
    frame[8..12].copy_from_slice(&prelude_crc.to_be_bytes());

    frame.extend_from_slice(payload);

    // message_crc = CRC32 of everything from byte 0 through the end of the payload (i.e. the whole
    // frame written so far, which is prelude + prelude_crc + headers + payload).
    let message_crc = crc32fast::hash(&frame);
    frame.extend_from_slice(&message_crc.to_be_bytes());

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
        // golden wire-contract literal (kept bare on purpose): pins the exact 4-byte CRC trailer offset.
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

    /// Build a header block with one type-7 string header `[name][value]`.
    fn string_header(name: &str, value: &str) -> Vec<u8> {
        let mut h = Vec::new();
        h.push(name.len() as u8);
        h.extend_from_slice(name.as_bytes());
        h.push(HDR_TYPE_STRING); // string
        h.extend_from_slice(&(value.len() as u16).to_be_bytes());
        h.extend_from_slice(value.as_bytes());
        h
    }

    /// `event_type_for_frame` returns `""` (rather than panic or misread) when it meets a header
    /// whose value-type byte is genuinely unknown / has no defined width before any recognized
    /// header.
    #[test]
    fn test_event_type_unknown_value_type_yields_empty() {
        // One header named "x" with value_type = 200 (not a real AWS type) → malformed → no headers.
        let mut h = Vec::new();
        h.push(1u8); // name_len
        h.extend_from_slice(b"x"); // name
        h.push(200u8); // value_type: unknown
        assert_eq!(event_type_for_frame(&h), "");
    }

    /// A fixed-width header (e.g. a `timestamp`, type 8) appearing BEFORE `:event-type` must be
    /// skipped by advancing the correct number of bytes, not abort the scan — so the event type is
    /// still recovered.
    #[test]
    fn test_event_type_skips_fixed_width_header() {
        let mut h = Vec::new();
        // Header 1: ":ts" timestamp (type 8, 8-byte value) — must be skipped.
        h.push(3u8);
        h.extend_from_slice(b":ts");
        h.push(8u8); // timestamp
        h.extend_from_slice(&0u64.to_be_bytes()); // 8 bytes
                                                  // Header 2: ":event-type" string = "messageStart".
        h.extend_from_slice(&string_header(HDR_EVENT_TYPE, "messageStart"));
        assert_eq!(event_type_for_frame(&h), "messageStart");
    }

    /// A zero-length `:event-type` string value yields `""` — a present-but-empty event type is
    /// indistinguishable from absent at the `drain_frames` boundary, which is fine (the reader
    /// treats both as a no-op frame).
    #[test]
    fn test_event_type_empty_value() {
        let h = string_header(HDR_EVENT_TYPE, "");
        assert_eq!(event_type_for_frame(&h), "");
    }

    /// REGRESSION (HIGH/conformance, eventstream.rs): an AWS modeled-exception frame carries
    /// `:message-type: exception` + `:exception-type: <Name>` and NO `:event-type`. `drain_frames`
    /// must surface the exception name (normalized to the Smithy union-member token the reader
    /// matches) rather than the old empty string that fell into the no-op arm and silently dropped
    /// the mid-stream error.
    #[test]
    fn test_event_type_exception_frame_returns_normalized_exception_name() {
        // Header order deliberately puts :exception-type before :message-type to prove the parser
        // does not depend on ordering.
        let mut h = string_header(HDR_EXCEPTION_TYPE, "InternalServerException");
        h.extend_from_slice(&string_header(
            HDR_CONTENT_TYPE,
            crate::forward::APPLICATION_JSON,
        ));
        h.extend_from_slice(&string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION));
        assert_eq!(event_type_for_frame(&h), "internalServerException");

        // A ThrottlingException maps the same way.
        let mut h2 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        h2.extend_from_slice(&string_header(HDR_EXCEPTION_TYPE, "ThrottlingException"));
        assert_eq!(event_type_for_frame(&h2), "throttlingException");
    }

    /// REGRESSION (LOW/conformance, eventstream.rs): AWS may qualify the `:exception-type`
    /// header with a Smithy namespace / shape-ARN prefix (e.g. `com.amazon.coral.service#ThrottlingException`).
    /// The prefix must be stripped before lowercasing — mirroring `extract_error`'s
    /// `rsplit(['#', '/'])` in proto/bedrock.rs — so the bare normalized name still matches the
    /// `read_response_events` exception arms. Before the fix this returned the whole namespaced
    /// string lowercased only at its first char (`com.amazon...`), which matched nothing and dropped
    /// the mid-stream error.
    #[test]
    fn test_event_type_exception_strips_namespace_prefix() {
        // `#`-delimited Smithy shape id.
        let mut h = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        h.extend_from_slice(&string_header(
            HDR_EXCEPTION_TYPE,
            "com.amazon.coral.service#ThrottlingException",
        ));
        assert_eq!(
            event_type_for_frame(&h),
            "throttlingException",
            "namespace prefix stripped before lowercasing the bare exception name"
        );

        // `/`-delimited ARN-style suffix.
        let mut h2 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        h2.extend_from_slice(&string_header(
            HDR_EXCEPTION_TYPE,
            "aws.bedrock/InternalServerException",
        ));
        assert_eq!(event_type_for_frame(&h2), "internalServerException");

        // A bare (unqualified) name is unaffected — no `#`/`/` to split on.
        let mut h3 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        h3.extend_from_slice(&string_header(
            HDR_EXCEPTION_TYPE,
            "ModelStreamErrorException",
        ));
        assert_eq!(event_type_for_frame(&h3), "modelStreamErrorException");
    }

    /// REGRESSION (LOW #14, eventstream.rs `event_type_for_frame`): an `:exception-type` value
    /// that ENDS with a Smithy/ARN delimiter (`ThrottlingException#`, `aws.bedrock/`) made
    /// `rsplit(['#', '/']).next()` return the empty LEADING token, dropping the classification to
    /// `""` — re-sinking the mid-stream error into the no-op arm the namespace fix was meant to
    /// prevent. Taking the last NON-EMPTY token (`.find(|s| !s.is_empty())`) strips the trailing
    /// delimiter and recovers the bare name. The normal namespaced case is unaffected.
    #[test]
    fn test_event_type_exception_trailing_delimiter_recovers_name() {
        // Trailing `#` — the empty leading token must be skipped, not returned.
        let mut h = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        h.extend_from_slice(&string_header(HDR_EXCEPTION_TYPE, "ThrottlingException#"));
        assert_eq!(
            event_type_for_frame(&h),
            "throttlingException",
            "a trailing `#` must not drop the exception classification to empty"
        );

        // Trailing `/` — same recovery.
        let mut h2 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        h2.extend_from_slice(&string_header(HDR_EXCEPTION_TYPE, "ThrottlingException/"));
        assert_eq!(
            event_type_for_frame(&h2),
            "throttlingException",
            "a trailing `/` must not drop the exception classification to empty"
        );

        // The normal namespaced value still resolves to the same bare token (no regression).
        let mut h3 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        h3.extend_from_slice(&string_header(
            HDR_EXCEPTION_TYPE,
            "com.amazon.coral.service#ThrottlingException",
        ));
        assert_eq!(event_type_for_frame(&h3), "throttlingException");

        // All-delimiter pathological value: every token is empty → `unwrap_or(&exc)` falls back to
        // the raw value (lowercased first char), never panics and never yields `""`.
        let mut h4 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        h4.extend_from_slice(&string_header(HDR_EXCEPTION_TYPE, "#"));
        assert_eq!(
            event_type_for_frame(&h4),
            "#",
            "an all-delimiter value falls back to the raw value, not empty/panic"
        );
    }

    /// REGRESSION (MEDIUM/test-coverage, eventstream.rs): an exception-typed frame
    /// (`:message-type: exception`) that carries NO `:exception-type` header must fall through to the
    /// empty string — never panic and never misreport. This guards the `None` arm of the
    /// `:exception-type` lookup, which a future refactor adding an assertion/panic there would break.
    #[test]
    fn test_event_type_exception_without_exception_type_yields_empty() {
        // Only `:message-type: exception` is present; no `:exception-type`, no `:event-type`.
        let h = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        assert_eq!(
            event_type_for_frame(&h),
            "",
            "exception frame missing :exception-type falls through to empty, no panic"
        );

        // Same, but with an unrelated (non-exception) header riding along — still empty.
        let mut h2 = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EXCEPTION);
        h2.extend_from_slice(&string_header(
            HDR_CONTENT_TYPE,
            crate::forward::APPLICATION_JSON,
        ));
        assert_eq!(
            event_type_for_frame(&h2),
            "",
            "exception frame with only :message-type + :content-type is still empty"
        );
    }

    /// A frame with `:message-type: event` (the normal case) must still report its `:event-type`,
    /// never an exception name, even if a stray `:exception-type` somehow rode along.
    #[test]
    fn test_event_type_event_message_type_prefers_event_type() {
        let mut h = string_header(HDR_MESSAGE_TYPE, MSG_TYPE_EVENT);
        h.extend_from_slice(&string_header(HDR_EVENT_TYPE, "contentBlockDelta"));
        assert_eq!(event_type_for_frame(&h), "contentBlockDelta");
    }

    /// End-to-end through `drain_frames`: a real binary exception frame (built by the production
    /// `encode_exception_frame`) decodes to the normalized exception event-type, so the egress
    /// decode path (`StreamTranslate::feed`) folds a matchable `type` into the JSON and the reader
    /// surfaces an error instead of dropping a typeless frame.
    #[test]
    fn test_drain_frames_surfaces_exception_event_type() {
        let mut buf =
            encode_exception_frame("ServiceUnavailableException", "upstream temporarily down");
        let frames = drain_frames(&mut buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].0, "serviceUnavailableException",
            "exception frame decodes to the normalized union-member token"
        );
        let payload: serde_json::Value = serde_json::from_slice(&frames[0].1).unwrap();
        assert_eq!(payload["message"], "upstream temporarily down");
        assert!(buf.is_empty());
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
            frame[len - CRC_BYTES],
            frame[len - CRC_BYTES + 1],
            frame[len - CRC_BYTES + 2],
            frame[len - CRC_BYTES + 3],
        ]);
        assert_eq!(msg_crc, crc32fast::hash(&frame[..len - CRC_BYTES]));
        // Header block carries the exception markers.
        let headers_len = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
        let headers = String::from_utf8_lossy(&frame[PRELUDE_LEN..PRELUDE_LEN + headers_len]);
        assert!(headers.contains(":message-type")); // golden wire-contract literal (kept bare on purpose)
        assert!(headers.contains("exception")); // golden wire-contract literal (kept bare on purpose)
        assert!(headers.contains(":exception-type")); // golden wire-contract literal (kept bare on purpose)
        assert!(headers.contains("InternalServerException")); // golden wire-contract literal (kept bare on purpose)
                                                              // Payload is the JSON body the SDK surfaces.
        let payload = &frame[PRELUDE_LEN + headers_len..len - CRC_BYTES];
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

    /// `drain_frames` must abandon (clear) the buffer on a frame whose `total_len` is in range but
    /// whose `headers_len` exceeds the space remaining after the 16-byte overhead — the second half
    /// of the prelude-validation guard, previously untested. Without the guard, `&frame[12..12 +
    /// headers_len]` would slice out of bounds and panic downstream.
    #[test]
    fn test_headers_len_overflow_abandoned() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&20u32.to_be_bytes()); // total_len = 20 (>= 16, <= cap)
        buf.extend_from_slice(&5u32.to_be_bytes()); // headers_len = 5 (> 20 - 16 = 4)
        buf.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC
        buf.extend_from_slice(b"junk extra bytes");

        let frames = drain_frames(&mut buf);
        assert!(
            frames.is_empty(),
            "no frame emitted for headers_len overflow"
        );
        assert!(
            buf.is_empty(),
            "headers_len overflow must abandon (clear) the buffer, not slice OOB"
        );
    }

    /// An oversized header NAME or VALUE must DROP the whole frame (empty `Vec`) rather than silently
    /// byte-truncate the string — a truncation could split a multi-byte UTF-8 sequence and emit a
    /// CRC-valid frame carrying an invalid-UTF-8 type-7 header a strict AWS SDK rejects.
    #[test]
    fn test_oversized_header_value_drops_frame() {
        // A header value just over the u16 cap (65535 bytes).
        let huge_value = "x".repeat(u16::MAX as usize + 1);
        let frame = encode_exception_frame(&huge_value, "msg");
        assert!(
            frame.is_empty(),
            "an oversized exception-type header must drop the frame, not truncate the string"
        );
        // A short, valid exception type still encodes normally.
        let ok = encode_exception_frame("InternalServerException", "msg");
        assert!(!ok.is_empty());
    }

    /// `encode_frame` must DROP the whole frame (empty `Vec`) when the caller-supplied `:event-type`
    /// value exceeds the type-7 string cap (u16, 65535 bytes), rather than emit a CRC-valid frame
    /// carrying a byte-truncated (possibly invalid-UTF-8) header. This exercises the `encode_frame`
    /// early-return on a failed `push_string_header` for `:event-type` — the only caller-supplied
    /// header in that path — which the payload-cap and exception-frame tests do not reach.
    #[test]
    fn test_encode_frame_oversized_event_type_drops_frame() {
        // An event-type value one byte over the u16 type-7 string cap.
        let huge_event_type = "e".repeat(u16::MAX as usize + 1);
        let frame = encode_frame(&huge_event_type, br#"{"x":1}"#);
        assert!(
            frame.is_empty(),
            "an oversized :event-type header must drop the frame, not truncate the string"
        );
        // A short, valid event type still encodes normally.
        let ok = encode_frame("contentBlockDelta", br#"{"x":1}"#);
        assert!(!ok.is_empty());
    }

    /// The encoder carries the three Bedrock framing headers (`:event-type`, `:content-type`,
    /// `:message-type`); `parse_event_type` must skip past the others and still find the event name.
    #[test]
    fn test_encode_carries_three_headers() {
        let frame = encode_frame("messageStart", br#"{"role":"assistant"}"#);
        let headers_len = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]) as usize;
        let headers = &frame[PRELUDE_LEN..PRELUDE_LEN + headers_len];
        // :content-type and :message-type values must be present in the header block.
        let hs = String::from_utf8_lossy(headers);
        assert!(hs.contains(":event-type")); // golden wire-contract literal (kept bare on purpose)
        assert!(hs.contains(":content-type")); // golden wire-contract literal (kept bare on purpose)
        assert!(hs.contains("application/json")); // golden wire-contract literal (kept bare on purpose)
        assert!(hs.contains(":message-type")); // golden wire-contract literal (kept bare on purpose)
        assert!(hs.contains("event")); // golden wire-contract literal (kept bare on purpose)
    }

    /// REGRESSION (MEDIUM/test-coverage, eventstream.rs): the SMALLEST valid frame —
    /// `total_len == 16` (12-byte prelude + 0-byte headers + 0-byte payload + 4-byte message CRC) —
    /// must decode cleanly. This is the lower boundary of the `(16..=MAX_FRAME_BYTES)` guard at line
    /// 61: a frame this small carries an empty header block and an empty payload (e.g. a
    /// `contentBlockStop` with no body). It is hand-crafted here (the production `encode_frame`
    /// always writes three headers, so it can never emit a 16-byte frame) so that tightening the
    /// guard from `16..=` to `17..=` — which would wrongly abandon a valid minimum frame — is caught.
    #[test]
    fn test_drain_frames_minimum_valid_frame() {
        // 16-byte frame: prelude(12) + headers(0) + payload(0) + message_crc(4).
        let mut frame = Vec::with_capacity(16); // golden wire-contract literal (kept bare on purpose)
        frame.extend_from_slice(&16u32.to_be_bytes()); // golden wire-contract literal (kept bare on purpose): total_len = 16 (the minimum valid value)
        frame.extend_from_slice(&0u32.to_be_bytes()); // headers_len = 0
        let prelude_crc = crc32fast::hash(&frame[..8]);
        frame.extend_from_slice(&prelude_crc.to_be_bytes()); // prelude CRC over [0..8]
                                                             // No headers, no payload. message_crc over everything written so far ([0..12]).
        let message_crc = crc32fast::hash(&frame);
        frame.extend_from_slice(&message_crc.to_be_bytes());
        assert_eq!(
            frame.len(),
            16, // golden wire-contract literal (kept bare on purpose)
            "hand-crafted frame is exactly the minimum size"
        );

        let mut buf = frame;
        let frames = drain_frames(&mut buf);
        assert_eq!(
            frames.len(),
            1,
            "the minimum 16-byte frame decodes to one frame"
        );
        assert_eq!(frames[0].0, "", "no :event-type header → empty event type");
        assert!(frames[0].1.is_empty(), "empty payload round-trips");
        assert!(buf.is_empty(), "minimum frame is fully consumed");
    }

    /// REGRESSION (LOW/perf, eventstream.rs / frame_open+frame_close): the single-buffer
    /// encoder must be BYTE-FOR-BYTE identical to the prior two-Vec (`headers` + `frame`) encoding.
    /// We independently rebuild the exact wire bytes from the documented layout — placeholder-free,
    /// in one pass — and assert equality, so a future refactor of the buffer plumbing that perturbs
    /// even one byte (a wrong CRC range, a misplaced length, a dropped/extra header byte) is caught.
    #[test]
    fn test_encode_frame_byte_for_byte_matches_reference() {
        // A representative Bedrock ConverseStream delta frame.
        let event_type = "contentBlockDelta";
        let payload = br#"{"delta":{"text":"hi"}}"#;
        let got = encode_frame(event_type, payload);

        // Reference encoding, built straight from the documented wire layout (NOT via encode_frame):
        //   header block = the three Bedrock string headers in order.
        // golden wire-contract literal (kept bare on purpose): header name/value strings pin the
        // exact bytes the encoder must emit; changing them here changes the wire format.
        let mut headers = Vec::new();
        headers.extend_from_slice(&string_header(":event-type", event_type));
        headers.extend_from_slice(&string_header(":content-type", "application/json"));
        headers.extend_from_slice(&string_header(":message-type", "event"));

        let headers_len = headers.len();
        let total_len = 12 + headers_len + payload.len() + 4; // golden wire-contract literal (kept bare on purpose)

        let mut want = Vec::new();
        want.extend_from_slice(&(total_len as u32).to_be_bytes()); // total_len
        want.extend_from_slice(&(headers_len as u32).to_be_bytes()); // headers_len
        let prelude_crc = crc32fast::hash(&want[..8]); // prelude CRC over the two length fields
        want.extend_from_slice(&prelude_crc.to_be_bytes());
        want.extend_from_slice(&headers);
        want.extend_from_slice(payload);
        let message_crc = crc32fast::hash(&want); // message CRC over everything written so far
        want.extend_from_slice(&message_crc.to_be_bytes());

        assert_eq!(
            got, want,
            "single-buffer encode_frame must be byte-for-byte identical to the reference encoding"
        );
    }

    /// A `tracing::Layer` that records the messages of WARN-level events it sees, so a test can
    /// assert a particular `tracing::warn!` fired.
    #[derive(Clone, Default)]
    struct WarnCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for WarnCapture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() != tracing::Level::WARN {
                return;
            }
            struct Vis(String);
            impl tracing::field::Visit for Vis {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.0 = format!("{value:?}");
                    }
                }
            }
            let mut vis = Vis(String::new());
            event.record(&mut vis);
            if let Ok(mut msgs) = self.0.lock() {
                msgs.push(vis.0);
            }
        }
    }

    /// REGRESSION (LOW/quality, eventstream.rs): when an oversized `:event-type` makes
    /// `push_string_header` reject the header, `encode_frame` drops the frame — but that drop MUST be
    /// observable via a `tracing::warn!`, not a silent empty `Vec`. This test captures WARN events:
    /// against the old (silent) code it FAILS (no warning), and passes once the warn! is emitted.
    #[test]
    fn test_encode_frame_oversized_event_type_warns() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let cap = WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());

        let huge_event_type = "e".repeat(u16::MAX as usize + 1);
        let frame = tracing::subscriber::with_default(subscriber, || {
            encode_frame(&huge_event_type, br#"{"x":1}"#)
        });

        assert!(
            frame.is_empty(),
            "oversized :event-type still drops the frame"
        );
        let msgs = cap.0.lock().unwrap();
        assert!(
            msgs.iter().any(|m| m.contains(":event-type")), // golden wire-contract literal (kept bare on purpose)
            "dropping an oversized :event-type frame must emit an observable warn!, got: {msgs:?}"
        );
    }

    /// REGRESSION (LOW/quality, eventstream.rs): the same observability guarantee for
    /// `encode_exception_frame` — an oversized `:exception-type` drops the frame but must warn, so a
    /// swallowed mid-stream error-signal frame is not silent.
    #[test]
    fn test_encode_exception_frame_oversized_type_warns() {
        use tracing_subscriber::layer::SubscriberExt as _;

        let cap = WarnCapture::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());

        let huge = "x".repeat(u16::MAX as usize + 1);
        let frame =
            tracing::subscriber::with_default(subscriber, || encode_exception_frame(&huge, "msg"));

        assert!(
            frame.is_empty(),
            "oversized :exception-type still drops the frame"
        );
        let msgs = cap.0.lock().unwrap();
        assert!(
            msgs.iter().any(|m| m.contains(":exception-type")), // golden wire-contract literal (kept bare on purpose)
            "dropping an oversized :exception-type frame must emit an observable warn!, got: {msgs:?}"
        );
    }

    /// REGRESSION (LOW #18, eventstream.rs `drain_frames_checked`): a malformed prelude must abandon
    /// the stream via a DISTINCT propagated status (`DrainStatus::MalformedPrelude`), not be inferred
    /// from the buffer being emptied. The key discriminator this test pins: a NORMAL full drain that
    /// also leaves the buffer empty returns `DrainStatus::Ok`, so the abort signal is unambiguous —
    /// length alone could not tell the two apart, which was the fragile behavior being fixed.
    #[test]
    fn test_drain_frames_checked_signals_malformed_prelude_distinctly() {
        // (a) Malformed prelude: oversized total_len. Buffer cleared AND status is MalformedPrelude.
        let mut bad = Vec::new();
        bad.extend_from_slice(&u32::MAX.to_be_bytes()); // total_len ~4 GiB, above MAX_FRAME_BYTES
        bad.extend_from_slice(&0u32.to_be_bytes()); // headers_len = 0
        bad.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC
        bad.extend_from_slice(b"trailing junk");
        let (frames, status, valid_consumed) = drain_frames_checked(&mut bad, None);
        assert!(
            frames.is_empty(),
            "no frame emitted for a malformed prelude"
        );
        assert!(bad.is_empty(), "malformed prelude clears the buffer");
        assert_eq!(
            valid_consumed, 0,
            "a malformed prelude at the front consumes ZERO valid frame bytes — the same-proto \
             verbatim emit must forward none of the cleared remainder"
        );
        assert_eq!(
            status,
            DrainStatus::MalformedPrelude,
            "malformed prelude must propagate the DISTINCT abort signal, not be length-inferred"
        );

        // (b) headers_len overflow is the OTHER malformed-prelude shape — same distinct signal.
        let mut bad2 = Vec::new();
        bad2.extend_from_slice(&20u32.to_be_bytes()); // total_len = 20 (>= 16, <= cap)
        bad2.extend_from_slice(&5u32.to_be_bytes()); // headers_len = 5 (> 20 - 16 = 4)
        bad2.extend_from_slice(&[0, 0, 0, 0]); // prelude CRC
        bad2.extend_from_slice(b"junk extra bytes");
        let (frames2, status2, _) = drain_frames_checked(&mut bad2, None);
        assert!(frames2.is_empty());
        assert!(bad2.is_empty());
        assert_eq!(status2, DrainStatus::MalformedPrelude);

        // (c) The AMBIGUITY case the old length-inference got wrong: a CLEAN full drain that consumes
        // every buffered byte also leaves an EMPTY buffer — but it is NOT an abort. Status is Ok.
        let mut good = encode_frame("contentBlockDelta", br#"{"delta":{"text":"hi"}}"#);
        let good_len = good.len();
        let (frames3, status3, valid_consumed3) = drain_frames_checked(&mut good, None);
        assert_eq!(frames3.len(), 1);
        assert_eq!(
            valid_consumed3, good_len,
            "a clean full drain reports the whole consumed frame length"
        );
        assert!(
            good.is_empty(),
            "a clean full drain also empties the buffer"
        );
        assert_eq!(
            status3,
            DrainStatus::Ok,
            "an empty buffer after a clean full drain must NOT be read as an abort"
        );

        // (d) A trailing PARTIAL frame is healthy too (buffer non-empty): status Ok, await more bytes.
        let full = encode_frame("messageStop", br#"{"stopReason":"end_turn"}"#);
        let mut partial = full[..full.len() - 4].to_vec();
        let (frames4, status4, _) = drain_frames_checked(&mut partial, None);
        assert!(frames4.is_empty(), "no complete frame yet");
        assert!(!partial.is_empty(), "partial frame stays buffered");
        assert_eq!(
            status4,
            DrainStatus::Ok,
            "a buffered partial is not an abort"
        );

        // (e) The thin `drain_frames` wrapper still returns just the frames (existing callers).
        let mut buf = encode_frame("messageStart", br#"{"role":"assistant"}"#);
        let only_frames = drain_frames(&mut buf);
        assert_eq!(only_frames.len(), 1);
        assert_eq!(only_frames[0].0, "messageStart");
    }

    /// REGRESSION (MEDIUM/test-coverage, eventstream.rs): the smallest frame with a NON-empty
    /// payload that carries no headers — `total_len == 18` (12 prelude + 0 headers + 2 payload + 4
    /// CRC). Sits one above the empty-payload minimum and guards the `12 + headers_len .. total_len
    /// - 4` payload slice arithmetic at its lower edge.
    #[test]
    fn test_drain_frames_two_byte_payload_no_headers() {
        let payload = b"hi";
        // total_len = prelude(12) + headers(0) + payload + message_crc(4) = 18.
        let total_len = PRELUDE_LEN as u32 + payload.len() as u32 + CRC_BYTES as u32;
        let mut frame = Vec::with_capacity(total_len as usize);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&0u32.to_be_bytes()); // headers_len = 0
        let prelude_crc = crc32fast::hash(&frame[..8]);
        frame.extend_from_slice(&prelude_crc.to_be_bytes());
        frame.extend_from_slice(payload);
        let message_crc = crc32fast::hash(&frame);
        frame.extend_from_slice(&message_crc.to_be_bytes());
        assert_eq!(frame.len(), 18); // golden wire-contract literal (kept bare on purpose)

        let mut buf = frame;
        let frames = drain_frames(&mut buf);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, "", "no :event-type header → empty event type");
        assert_eq!(frames[0].1, payload, "two-byte payload round-trips");
        assert!(buf.is_empty());
    }
}
