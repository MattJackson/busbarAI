// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Matthew Jackson

//! AWS Signature Version 4 request signing — hand-rolled with RustCrypto (sha2 + hmac), no
//! AWS SDK. Used by the Bedrock protocol writer to sign Converse requests. The core algorithm is
//! verified against AWS's published worked example (GET iam ListUsers, 20150830) in the tests, so
//! the canonical-request → string-to-sign → signature chain is known-correct.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Lowercase hex SHA-256 of `data`.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// HMAC-SHA256 of `data` under `key`. `Hmac::new_from_slice` is infallible for HMAC — the spec
/// accepts a key of ANY length — so the `Err` arm is unreachable. We still avoid `expect()`/panic
/// here because this runs transitively on the Bedrock request hot path (via `sign_v4` →
/// `sign_request`), where the project rule forbids a panic surface: a future refactor that swaps the
/// HMAC impl or key type must not turn a signing-init failure into a task abort. On the unreachable
/// error we return an empty digest, which yields a wrong signature → AWS responds 403 → the caller's
/// existing "misconfigured key" fallback surfaces it as an upstream auth failure, exactly the same
/// graceful path it already takes for an unparseable credential.
fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    match HmacSha256::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(data);
            mac.finalize().into_bytes().to_vec()
        }
        Err(e) => {
            tracing::error!(
                "HMAC-SHA256 init failed (unreachable: HMAC accepts any key length): {e}"
            );
            Vec::new()
        }
    }
}

/// Derive the SigV4 signing key: HMAC chain over date → region → service → "aws4_request".
/// File-private: the only caller is `sign_request` below.
fn signing_key(secret: &str, datestamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, b"aws4_request")
}

/// AWS URI-encode a path, preserving `/`. Unreserved chars (A-Za-z0-9-_.~) pass through; everything
/// else becomes %XX (uppercase hex). Bedrock model IDs contain `:` and `.`, so the path must be
/// encoded identically in the canonical request and the wire request.
pub(crate) fn uri_encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for &b in path.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            // Percent-encode directly into the pre-allocated buffer (no per-byte heap allocation
            // from `format!`). Index into a static hex table — a 4-bit nibble is always 0..=15, so
            // the indexing can never go out of bounds and there is no panic on the request path.
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
    out
}

/// Convert a Unix epoch (seconds) to (amzdate `YYYYMMDDTHHMMSSZ`, datestamp `YYYYMMDD`). Pure UTC,
/// no external date crate (a public-domain civil-from-days algorithm).
pub(crate) fn format_amz_time(epoch_secs: u64) -> (String, String) {
    let days = (epoch_secs / 86_400) as i64;
    let sod = epoch_secs % 86_400;
    let (h, mi, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);

    // civil_from_days: days since 1970-01-01 → (year, month, day)
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    (
        format!("{year:04}{month:02}{day:02}T{h:02}{mi:02}{s:02}Z"),
        format!("{year:04}{month:02}{day:02}"),
    )
}

/// Compute the SigV4 signature hex + the `SignedHeaders` string for a request. `headers` is the
/// full set of headers to sign (names case-insensitive); they are lowercased + sorted internally.
/// `canonical_uri` must already be URI-encoded; `canonical_querystring` sorted + encoded (or empty).
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_v4(
    secret: &str,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    canonical_querystring: &str,
    headers: &[(String, String)],
    payload_hash: &str,
    amzdate: &str,
    datestamp: &str,
) -> (String, String) {
    let mut h: Vec<(String, String)> = headers
        .iter()
        // AWS SigV4 canonicalization of a (non-quoted) header value: trim leading/trailing
        // whitespace AND collapse runs of internal whitespace to a single space. `split_whitespace`
        // splits on any ASCII/Unicode whitespace run and drops empties, so joining with one space
        // does both at once. Omitting the internal collapse risks a SignatureDoesNotMatch (403) if a
        // signed header value ever carries doubled spaces.
        .map(|(k, v)| {
            (
                k.to_lowercase(),
                v.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        })
        .collect();
    h.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = h.iter().map(|(k, v)| format!("{k}:{v}\n")).collect();
    let signed_headers = h
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );
    let scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let key = signing_key(secret, datestamp, region, service);
    let signature = hex::encode(hmac(&key, string_to_sign.as_bytes()));
    (signature, signed_headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_amz_time_known_epoch() {
        // 2015-08-30T12:36:00Z — the timestamp from AWS's worked SigV4 example.
        let (amz, date) = format_amz_time(1_440_938_160);
        assert_eq!(amz, "20150830T123600Z");
        assert_eq!(date, "20150830");
    }

    #[test]
    fn test_uri_encode_path_bedrock_model() {
        // Bedrock model IDs contain ':' and '.' — must encode ':' as %3A, keep '.' and '/'.
        assert_eq!(
            uri_encode_path("/model/anthropic.claude-3:0/converse"),
            "/model/anthropic.claude-3%3A0/converse"
        );
    }

    #[test]
    fn test_uri_encode_path_assorted_bytes() {
        // The allocation-free encoder must produce uppercase two-digit hex for every reserved byte
        // (regression for the `format!("%{b:02X}")` → static-table rewrite).
        assert_eq!(uri_encode_path(" "), "%20"); // 0x20
        assert_eq!(uri_encode_path("?a=b&c"), "%3Fa%3Db%26c");
        assert_eq!(uri_encode_path("/"), "/"); // slash preserved
                                               // Unreserved set passes through untouched.
        assert_eq!(uri_encode_path("aZ0-_.~"), "aZ0-_.~");
        // A high byte (0xC3 from the UTF-8 of 'Ã') still encodes uppercase, padded.
        assert_eq!(uri_encode_path("\u{00c3}"), "%C3%83");
    }

    #[test]
    fn test_sign_v4_collapses_internal_whitespace_in_header_value() {
        // Two requests whose only difference is collapsible internal whitespace in a signed header
        // value must produce the SAME signature, because SigV4 canonicalization collapses runs of
        // internal whitespace to a single space. (Regression for v.trim()-only canonicalization.)
        let payload_hash = sha256_hex(b"");
        let mk = |v: &str| {
            sign_v4(
                "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                "us-east-1",
                "iam",
                "GET",
                "/",
                "",
                &[
                    ("host".to_string(), "iam.amazonaws.com".to_string()),
                    ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
                    ("x-custom".to_string(), v.to_string()),
                ],
                &payload_hash,
                "20150830T123600Z",
                "20150830",
            )
        };
        let (sig_single, _) = mk("a b c");
        let (sig_double, _) = mk("a   b\t c"); // doubled spaces + tab collapse to single spaces
        assert_eq!(
            sig_single, sig_double,
            "internal whitespace must be collapsed before signing"
        );
        // Leading/trailing whitespace must still be trimmed (the original behavior).
        let (sig_padded, _) = mk("  a b c  ");
        assert_eq!(sig_single, sig_padded);
    }

    /// AWS published worked example — GET iam ListUsers, 2015-08-30. If our canonical-request →
    /// string-to-sign → signature chain reproduces AWS's documented signature, the algorithm is
    /// correct. (https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html)
    #[test]
    fn test_sign_v4_matches_aws_published_example() {
        let headers = vec![
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded; charset=utf-8".to_string(),
            ),
            ("host".to_string(), "iam.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ];
        let payload_hash = sha256_hex(b"");
        let (sig, signed) = sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "iam",
            "GET",
            "/",
            "Action=ListUsers&Version=2010-05-08",
            &headers,
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        );
        assert_eq!(signed, "content-type;host;x-amz-date");
        assert_eq!(
            sig,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }
}
