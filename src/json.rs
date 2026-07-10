// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson
//
//! The single seam where the JSON library is named.
//!
//! Every hot request/response body parse and serialize on the translate path goes through here, so
//! the implementation (today: sonic-rs, SIMD on the large string-heavy bodies LLM traffic carries)
//! lives in ONE place instead of being scattered as `sonic_rs::`/`serde_json::` across the request
//! path. Swapping the parser/serializer — or, later, eliminating the `serde_json::Value` intermediate
//! in favour of parsing straight into the IR — becomes a change to this module, not a hunt across
//! `route.rs` and `forward.rs`. ALL body JSON — hot translate path AND the cold error-body /
//! error-envelope / SSE-event paths — goes through here; only config (YAML) and tests use a JSON
//! library directly. The in-memory document type is `serde_json::Value` (sonic-rs parses/serializes
//! it directly); replacing it with a native value, or swapping the engine, is a change to THIS module.

/// Maximum JSON nesting depth accepted at any parse boundary. Matches `serde_json`'s long-standing
/// default of 128 — generous for real LLM payloads (object → messages → content → block → tool-schema
/// is a handful of levels) while bounding the recursion below. This is a SECURITY floor, not an
/// operational tunable: `sonic-rs` parses nesting ITERATIVELY into a `serde_json::Value` (no depth
/// limit on that path, unlike `serde_json::from_slice` which rejects past 128), but the resulting
/// `Value` is then recursively re-serialized (`to_vec` on the injected body) and recursively dropped —
/// and a ~10k-deep body (well under the 32 MiB body cap) overflows the worker stack and ABORTS the
/// process (uncatchable; kills every in-flight request). The pre-scan below rejects such input before
/// any `Value` is built, so it can neither be re-serialized nor dropped.
const MAX_JSON_DEPTH: usize = 128;

/// Single-pass, string-aware scan for the maximum `{`/`[` nesting depth in `bytes`. Brackets inside
/// JSON string literals (and `\`-escaped quotes) do not count. Returns `true` as soon as `max` is
/// exceeded (short-circuit). O(n), no allocation — far cheaper than the parse it guards.
fn exceeds_max_depth(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Parse body bytes into a document. SIMD-accelerated. Rejects pathologically-nested input (see
/// `MAX_JSON_DEPTH`) BEFORE building a `Value`, returning a parse `Err` so callers take their existing
/// malformed-body (400) path. Callers log via `parse_err_log(len)`, never the raw `Display`, so the
/// substitute error's message is never surfaced.
#[inline]
pub(crate) fn parse<'de, T: serde::Deserialize<'de>>(
    bytes: &'de [u8],
) -> Result<T, sonic_rs::Error> {
    if exceeds_max_depth(bytes, MAX_JSON_DEPTH) {
        // Manufacture a real `sonic_rs::Error` of the right type without touching the deep input.
        return sonic_rs::from_slice::<T>(b"");
    }
    sonic_rs::from_slice(bytes)
}

/// Parse a body `&str` into a document (e.g. an SSE `data:` payload). SIMD-accelerated. Same depth
/// guard as [`parse`].
#[inline]
pub(crate) fn parse_str<'de, T: serde::Deserialize<'de>>(
    s: &'de str,
) -> Result<T, sonic_rs::Error> {
    if exceeds_max_depth(s.as_bytes(), MAX_JSON_DEPTH) {
        return sonic_rs::from_slice::<T>(b"");
    }
    sonic_rs::from_slice(s.as_bytes())
}

/// Serialize a document to body bytes. SIMD-accelerated; the request/response hot-path serializer.
#[inline]
pub(crate) fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, sonic_rs::Error> {
    sonic_rs::to_vec(value)
}

/// Serialize a document to a `String` (error envelopes, SSE-event data). sonic-rs always emits valid
/// UTF-8, so `from_utf8_lossy` never substitutes a replacement char (that path never fires here) — it
/// scans the bytes and returns the borrowed `&str`, then `into_owned()` allocates the `String`. This is
/// a cold path (error envelopes and SSE data, not the per-chunk hot loop), so the extra copy is fine.
#[inline]
pub(crate) fn to_string<T: serde::Serialize>(value: &T) -> Result<String, sonic_rs::Error> {
    sonic_rs::to_vec(value).map(|v| String::from_utf8_lossy(&v).into_owned())
}

/// Sanitized one-line description of a parse error for OPERATOR LOGS — never the raw library `Display`,
/// which (with sonic-rs) embeds a fragment of the offending input bytes. A malformed body can contain
/// secrets/PII, so logs must not echo it; "<n> bytes" is enough to correlate without leaking content.
#[inline]
pub(crate) fn parse_err_log(bytes_len: usize) -> String {
    format!("invalid JSON ({bytes_len} bytes)")
}

#[cfg(test)]
mod depth_guard_tests {
    use super::*;

    #[test]
    fn rejects_pathologically_nested_input_without_overflow() {
        // A ~2 MB body 1,000,000 arrays deep would abort the process on re-serialize/drop if it
        // reached `from_slice`. The guard rejects it on the raw bytes first, so this returns Err
        // cleanly — no Value is ever built. (Runs on the default test stack; the point is it does
        // NOT abort.)
        let depth = 1_000_000usize;
        let mut s = String::with_capacity(depth * 2);
        for _ in 0..depth {
            s.push('[');
        }
        for _ in 0..depth {
            s.push(']');
        }
        assert!(
            parse::<serde_json::Value>(s.as_bytes()).is_err(),
            "deeply-nested body must be rejected"
        );
        assert!(exceeds_max_depth(s.as_bytes(), MAX_JSON_DEPTH));
    }

    #[test]
    fn accepts_realistic_depth_and_counts_correctly() {
        // A normal chat body (object → messages array → message object → content array → block
        // object) is ~5 deep — nowhere near 128.
        let body = br#"{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"hi [bracket] {brace} in a string is not depth"}]}]}"#;
        assert!(!exceeds_max_depth(body, MAX_JSON_DEPTH));
        assert!(parse::<serde_json::Value>(body).is_ok());
        // Brackets/braces inside string literals must NOT count toward depth.
        assert!(!exceeds_max_depth(br#"{"k":"[[[[[[[[[[ {{{{{{ ]]]]]"}"#, 8));
        // Exactly at the limit parses; one deeper is rejected.
        let at_limit = format!("{}{}", "[".repeat(128), "]".repeat(128));
        assert!(!exceeds_max_depth(at_limit.as_bytes(), MAX_JSON_DEPTH));
        let over = format!("{}{}", "[".repeat(129), "]".repeat(129));
        assert!(exceeds_max_depth(over.as_bytes(), MAX_JSON_DEPTH));
    }
}
