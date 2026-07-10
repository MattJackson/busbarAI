// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! AWS Signature Version 4 request signing — hand-rolled with RustCrypto (sha2 + hmac), no
//! AWS SDK. Used by the Bedrock protocol writer to sign Converse requests. The core algorithm is
//! verified against AWS's published worked example (GET iam ListUsers, 20150830) in the tests, so
//! the canonical-request → string-to-sign → signature chain is known-correct.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Seconds in a UTC day / hour, for the epoch↔civil-time conversions below. Named rather than bare
/// literals so the time arithmetic reads in canonical units. (`store` and `governance` keep their
/// own copies — layering forbids a cross-module import for a one-line constant.)
const SECS_PER_DAY: u64 = 86_400;
const SECS_PER_HOUR: u64 = 3_600;

/// The SigV4 algorithm token that appears in the `Authorization` header and the string-to-sign.
pub(crate) const SIGV4_ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The terminating scope component appended to every Credential scope and fed to the HMAC chain.
/// Used as `SIGV4_TERMINATION` (&str) or `SIGV4_TERMINATION.as_bytes()` (byte slice) so the
/// value is single-sourced even when a byte literal is required.
pub(crate) const SIGV4_TERMINATION: &str = "aws4_request";
/// The key-derivation prefix prepended to the secret access key before the first HMAC: `"AWS4"`.
/// Always used via `format!("{SIGV4_KEY_PREFIX}{secret}")`, not mixed into `SIGV4_ALGORITHM`.
const SIGV4_KEY_PREFIX: &str = "AWS4";
/// The canonical lowercase name of the `x-amz-date` header.
pub(crate) const X_AMZ_DATE: &str = "x-amz-date";
/// The canonical lowercase name of the `x-amz-content-sha256` header.
pub(crate) const X_AMZ_CONTENT_SHA256: &str = "x-amz-content-sha256";
/// The canonical lowercase name of the `x-amz-security-token` header (STS session credentials).
pub(crate) const X_AMZ_SECURITY_TOKEN: &str = "x-amz-security-token";

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
    let k_date = hmac(
        format!("{SIGV4_KEY_PREFIX}{secret}").as_bytes(),
        datestamp.as_bytes(),
    );
    let k_region = hmac(&k_date, region.as_bytes());
    let k_service = hmac(&k_region, service.as_bytes());
    hmac(&k_service, SIGV4_TERMINATION.as_bytes())
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

/// AWS URI-encode a query-string component (key or value). IDENTICAL to [`uri_encode_path`] EXCEPT
/// that `/` is ALSO percent-encoded (to `%2F`): in the query string `/` is not a path separator and
/// AWS encodes it. Unreserved chars (A-Za-z0-9-_.~) pass through; everything else (including `/`)
/// becomes %XX uppercase. Used by the inbound verifier to canonicalize the request query string the
/// same way a signer does.
pub(crate) fn uri_encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
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
    let days = (epoch_secs / SECS_PER_DAY) as i64;
    let sod = epoch_secs % SECS_PER_DAY;
    let (h, mi, s) = (sod / SECS_PER_HOUR, (sod % SECS_PER_HOUR) / 60, sod % 60);

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

/// Canonicalize a (non-quoted) signed-header value per AWS SigV4: trim leading/trailing ASCII
/// spaces (0x20) and collapse each run of sequential ASCII spaces to a single space. ONLY the ASCII
/// space character is treated as whitespace — tabs, NBSP (U+00A0), newlines, and every other Unicode
/// whitespace codepoint are preserved verbatim, because AWS does the same. (This is intentionally
/// NOT `split_whitespace`, which would also fold tabs/NBSP/newlines and break the signature.)
fn canonicalize_header_value(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut prev_space = false;
    for ch in v.chars() {
        if ch == ' ' {
            // Defer emitting until we know it is not a trailing run; mark that a space is pending.
            prev_space = true;
        } else {
            // Emit a single collapsed space before this non-space char, but only if we have already
            // emitted at least one char (i.e. drop any leading run).
            if prev_space && !out.is_empty() {
                out.push(' ');
            }
            prev_space = false;
            out.push(ch);
        }
    }
    out
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
        // AWS SigV4 canonicalization of a (non-quoted) header value: trim leading/trailing ASCII
        // spaces (0x20) AND collapse runs of sequential ASCII spaces to a single space. AWS operates
        // on ASCII space ONLY — NBSP (U+00A0), tabs, and other Unicode whitespace are NOT treated as
        // whitespace and must pass through verbatim, byte-for-byte, into the signed value. Using
        // `split_whitespace` here would (wrongly) split on tabs/NBSP/newlines and rewrite them to
        // 0x20, producing a canonical value that differs from what AWS computes → SignatureDoesNotMatch
        // (403). `canonicalize_header_value` collapses 0x20 runs only.
        .map(|(k, v)| (k.to_lowercase(), canonicalize_header_value(v)))
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
    let scope = format!("{datestamp}/{region}/{service}/{SIGV4_TERMINATION}");
    let string_to_sign = format!(
        "{SIGV4_ALGORITHM}\n{amzdate}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );
    let key = signing_key(secret, datestamp, region, service);
    let signature = hex::encode(hmac(&key, string_to_sign.as_bytes()));
    (signature, signed_headers)
}

// ============================================================================================
// INBOUND SigV4 VERIFICATION (the MinIO / S3-compatible model)
// --------------------------------------------------------------------------------------------
// A Bedrock-SDK client signs its request with an AWS-style access-key-id + secret access key that
// busbar issued (tied to a virtual key). To grant that client full virtual-key governance, busbar
// must VERIFY the inbound SigV4 signature itself. Verification RE-USES the exact signing internals
// above (`sign_v4` → `signing_key` → `hmac`, plus `sha256_hex`): we recompute the signature the
// same way the signer does and compare. There is deliberately NO second canonicalization
// implementation — a duplicate could drift from the signer and from AWS, which on the verify path
// is an AUTH BYPASS, not merely a 403. The ONLY verify-specific logic here is PARSING the inbound
// `Authorization` header and assembling `sign_v4`'s inputs from the request; the cryptographic core
// is shared, byte-for-byte, with the outbound signer that is tested against AWS's published example.
// ============================================================================================

/// Allowed clock skew (seconds) between the inbound request's `x-amz-date` and the verifier's clock.
/// AWS itself uses a 5-minute window; matching it rejects replay of a signature captured more than
/// `±CLOCK_SKEW_SECS` ago while tolerating ordinary client/server clock drift. Bounding the age of an
/// accepted signature is the replay defense (busbar does not track nonces).
pub(crate) const CLOCK_SKEW_SECS: u64 = 300;

/// Why an inbound SigV4 verification was rejected. The auth layer maps EVERY variant to the SAME
/// native-vendor auth-failure response (a 403 AccessDenied with no reason prose) — the distinction is
/// for server-side logging ONLY and must never reach the wire, or it becomes an oracle (e.g.
/// distinguishing "unknown AccessKeyId" from "bad signature" would let an attacker enumerate valid
/// AccessKeyIds). The variants carry NO secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifyError {
    /// No `Authorization` header, or it is not an `AWS4-HMAC-SHA256` credential.
    MissingAuthorization,
    /// The `Authorization` header is present but structurally malformed (bad Credential/SignedHeaders/
    /// Signature, or a Credential scope that is not `.../aws4_request`).
    MalformedAuthorization,
    /// No usable `x-amz-date` (absent, unparseable, or wrong format).
    MissingDate,
    /// `x-amz-date` is outside the ±`CLOCK_SKEW_SECS` window (stale → possible replay, or far future).
    Expired,
    /// A header named in `SignedHeaders` is not present on the request (cannot reconstruct the
    /// canonical headers the client signed), or the mandatory `host` header is not signed.
    SignedHeadersMismatch,
    /// The recomputed signature did not match the one in the `Authorization` header (wrong secret,
    /// tampered request, or — indistinguishably — an unknown AccessKeyId verified against a dummy
    /// secret).
    SignatureMismatch,
}

/// The parsed components of an inbound SigV4 `Authorization` header. All fields are non-secret (the
/// AccessKeyId and signature both travel in plaintext on the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedAuthHeader {
    pub(crate) access_key_id: String,
    pub(crate) datestamp: String,
    pub(crate) region: String,
    pub(crate) service: String,
    /// The lowercase, `;`-joined SignedHeaders list, e.g. `host;x-amz-content-sha256;x-amz-date`.
    pub(crate) signed_headers: String,
    /// The hex signature the client computed.
    pub(crate) signature: String,
}

/// Parse an inbound `Authorization: AWS4-HMAC-SHA256 Credential=.../..., SignedHeaders=..., Signature=...`
/// header into its components. Returns `MissingAuthorization` when the value is not an AWS4-HMAC-SHA256
/// credential at all (so a Bearer/Basic header falls through cleanly), and `MalformedAuthorization`
/// when it claims to be SigV4 but is structurally broken.
///
/// The `Credential` field is `AccessKeyId/datestamp/region/service/aws4_request` — five `/`-separated
/// parts, the last of which MUST be `aws4_request`. The three comma-separated sections
/// (Credential / SignedHeaders / Signature) may carry optional surrounding whitespace, which we trim.
pub(crate) fn parse_authorization_header(value: &str) -> Result<ParsedAuthHeader, VerifyError> {
    // The algorithm token and the rest are split on the FIRST space. Match the algorithm
    // case-sensitively against the single spelling AWS uses; anything else is "not SigV4".
    let value = value.trim();
    let Some((algo, rest)) = value.split_once(' ') else {
        return Err(VerifyError::MissingAuthorization);
    };
    if algo != SIGV4_ALGORITHM {
        return Err(VerifyError::MissingAuthorization);
    }

    // Collect the comma-separated key=value sections into a small map. We do NOT rely on order
    // (AWS emits Credential, SignedHeaders, Signature in that order, but tolerate any order here).
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for section in rest.split(',') {
        let section = section.trim();
        let Some((k, v)) = section.split_once('=') else {
            return Err(VerifyError::MalformedAuthorization);
        };
        match k.trim() {
            "Credential" => credential = Some(v.trim().to_string()),
            "SignedHeaders" => signed_headers = Some(v.trim().to_string()),
            "Signature" => signature = Some(v.trim().to_string()),
            // An unknown section key is SKIPPED, not rejected: AWS SigV4 clients may legitimately emit
            // extra/unknown sections in the Authorization header, and the signature itself binds the
            // request (an attacker cannot forge a valid one by adding sections). The three MANDATORY
            // sections (Credential, SignedHeaders, Signature) are still required below, and all
            // existing strictness on those fields is unchanged.
            _ => continue,
        }
    }
    let (Some(credential), Some(signed_headers), Some(signature)) =
        (credential, signed_headers, signature)
    else {
        return Err(VerifyError::MalformedAuthorization);
    };
    if signature.is_empty() || signed_headers.is_empty() {
        return Err(VerifyError::MalformedAuthorization);
    }

    // Credential = AccessKeyId/datestamp/region/service/aws4_request (exactly five parts).
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[4] != SIGV4_TERMINATION {
        return Err(VerifyError::MalformedAuthorization);
    }
    let access_key_id = parts[0].to_string();
    let datestamp = parts[1].to_string();
    let region = parts[2].to_string();
    let service = parts[3].to_string();
    if access_key_id.is_empty() || datestamp.is_empty() || region.is_empty() || service.is_empty() {
        return Err(VerifyError::MalformedAuthorization);
    }

    Ok(ParsedAuthHeader {
        access_key_id,
        datestamp,
        region,
        service,
        signed_headers,
        signature,
    })
}

/// Parse an `x-amz-date` value (`YYYYMMDDTHHMMSSZ`, basic ISO-8601 UTC) into a Unix epoch (seconds).
/// Returns `None` on any format deviation. Self-contained (a civil-date computation, the inverse of
/// `format_amz_time`); no external date crate. Used to bound the signature's age (clock-skew check).
fn parse_amz_date(amzdate: &str) -> Option<u64> {
    // Exact shape: 8 digits, 'T', 6 digits, 'Z' — 16 chars total. Reject anything else.
    let b = amzdate.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    // The slices below index by char position; guard against a non-ASCII multi-byte char straddling a
    // boundary (`amzdate[0..4]` etc. would panic). The valid format is pure ASCII (digits + 'T'/'Z'),
    // so any non-ASCII byte is already invalid. (Defense-in-depth: callers feed `HeaderValue::to_str`,
    // which today rejects non-ASCII before this — but the guarantee now lives locally, not implicitly.)
    if !amzdate.is_ascii() {
        return None;
    }
    let digits = |s: &str| -> Option<i64> {
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse::<i64>().ok()
        } else {
            None
        }
    };
    let year = digits(&amzdate[0..4])?;
    let month = digits(&amzdate[4..6])?;
    let day = digits(&amzdate[6..8])?;
    let hour = digits(&amzdate[9..11])?;
    let min = digits(&amzdate[11..13])?;
    let sec = digits(&amzdate[13..15])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    // days_from_civil (public-domain, inverse of format_amz_time's civil_from_days).
    let y = if month <= 2 { year - 1 } else { year };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let epoch = days * SECS_PER_DAY as i64 + hour * SECS_PER_HOUR as i64 + min * 60 + sec;
    if epoch < 0 {
        return None;
    }
    Some(epoch as u64)
}

/// The fully-assembled inputs for verifying ONE inbound SigV4 request. The caller (the auth layer)
/// extracts these from the live HTTP request; the verifier owns none of the HTTP types so it stays
/// trivially testable. `canonical_uri` MUST already be URI-encoded the SAME way the signer encodes it
/// (use [`uri_encode_path`]); `canonical_querystring` MUST be the sorted+encoded query string (or
/// empty). `headers` carries the ACTUAL request header values for (at least) every name in the parsed
/// `SignedHeaders` list; extra headers are ignored (only the signed ones enter the canonical request).
pub(crate) struct InboundRequest<'a> {
    pub(crate) method: &'a str,
    pub(crate) canonical_uri: &'a str,
    pub(crate) canonical_querystring: &'a str,
    /// (name, value) pairs from the request; names case-insensitive. Must include every signed header.
    pub(crate) headers: &'a [(String, String)],
    /// The hex SHA-256 payload hash the client signed (its `x-amz-content-sha256` header value).
    pub(crate) payload_hash: &'a str,
    /// The request's `x-amz-date` (`YYYYMMDDTHHMMSSZ`).
    pub(crate) amzdate: &'a str,
}

/// Verify an inbound SigV4 signature against a candidate `secret`, at wall-clock `now` (Unix seconds).
///
/// This is the SECURITY-CRITICAL core. It:
///   1. validates `x-amz-date` is within ±`CLOCK_SKEW_SECS` of `now` (replay/skew bound),
///   2. confirms the Credential's `datestamp` agrees with `x-amz-date`'s date (a signer always
///      derives the scope datestamp from the same timestamp),
///   3. selects EXACTLY the headers named in `SignedHeaders` from the request (rejecting if any is
///      absent, or if `host` is not among them — `host` MUST be signed),
///   4. recomputes the signature via the shared [`sign_v4`] (NO duplicate canonicalization), and
///   5. constant-time-compares the recomputed signature to the client's, AND constant-time-compares
///      the recomputed SignedHeaders string to the client's claimed one.
///
/// Returns `Ok(())` only when every check passes. The comparison uses
/// `crate::auth::AuthMiddleware::constant_time_eq` (the single constant-time primitive) so a partial
/// match cannot be recovered by timing. The caller MUST invoke this even for an UNKNOWN AccessKeyId
/// (with a dummy secret) so the unknown-key and bad-signature paths are timing/response
/// indistinguishable (no AccessKeyId-enumeration oracle).
pub(crate) fn verify_inbound_sigv4(
    parsed: &ParsedAuthHeader,
    req: &InboundRequest<'_>,
    secret: &str,
    now: u64,
) -> Result<(), VerifyError> {
    // (1) Clock-skew / replay bound on x-amz-date.
    let Some(req_epoch) = parse_amz_date(req.amzdate) else {
        return Err(VerifyError::MissingDate);
    };
    let skew = req_epoch.abs_diff(now);
    if skew > CLOCK_SKEW_SECS {
        return Err(VerifyError::Expired);
    }

    // (2) The Credential scope datestamp must match x-amz-date's date (YYYYMMDD prefix). A signer
    // derives both from one timestamp, so a mismatch is a malformed/forged credential. (Also ensures
    // the datestamp we feed `sign_v4` is the one the client used.)
    if req.amzdate.len() < 8 || parsed.datestamp != req.amzdate[0..8] {
        return Err(VerifyError::MalformedAuthorization);
    }

    // (3) Select exactly the signed headers, in the order the client listed them, taking each value
    // from the request. The signed-headers list is lowercase by construction (the signer lowercases);
    // match request header names case-insensitively. A missing signed header → cannot reconstruct →
    // reject. `host` MUST be signed (AWS requires it; an unsigned host would let a signature be
    // replayed against a different target).
    let signed: Vec<&str> = parsed.signed_headers.split(';').collect();
    if !signed.iter().any(|h| h.eq_ignore_ascii_case("host")) {
        return Err(VerifyError::SignedHeadersMismatch);
    }
    let mut selected: Vec<(String, String)> = Vec::with_capacity(signed.len());
    for name in &signed {
        let lname = name.to_ascii_lowercase();
        let Some((_, value)) = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&lname))
        else {
            return Err(VerifyError::SignedHeadersMismatch);
        };
        selected.push((lname, value.clone()));
    }

    // (4) Recompute via the SHARED signer — same canonicalization, byte-for-byte. `sign_v4` lowercases
    // + sorts the headers and derives its own SignedHeaders string from them.
    let (computed_sig, computed_signed_headers) = sign_v4(
        secret,
        &parsed.region,
        &parsed.service,
        req.method,
        req.canonical_uri,
        req.canonical_querystring,
        &selected,
        req.payload_hash,
        req.amzdate,
        &parsed.datestamp,
    );

    // (5) Constant-time compare BOTH the SignedHeaders string the client claimed and the signature.
    // The SignedHeaders compare catches a client that lists headers in a non-sorted order or includes
    // a name it did not actually fold into the canonical request — a mismatch there means our
    // reconstruction would diverge from theirs. Run BOTH compares unconditionally (no `&&`
    // short-circuit) and fold with bitwise-OR-of-inverses so the work — and thus the timing — does not
    // depend on WHICH check failed; only the final all-pass boolean is observable.
    let headers_ok = crate::auth::AuthMiddleware::constant_time_eq(
        &computed_signed_headers,
        &parsed.signed_headers,
    );
    let sig_ok = crate::auth::AuthMiddleware::constant_time_eq(&computed_sig, &parsed.signature);
    if std::hint::black_box(u8::from(headers_ok) & u8::from(sig_ok)) == 1 {
        Ok(())
    } else {
        Err(VerifyError::SignatureMismatch)
    }
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
    fn test_canonicalize_header_value_ascii_space_only() {
        // Runs of ASCII space (0x20) collapse to one; leading/trailing ASCII space is trimmed.
        assert_eq!(canonicalize_header_value("a   b    c"), "a b c");
        assert_eq!(canonicalize_header_value("  a b c  "), "a b c");
        assert_eq!(canonicalize_header_value(""), "");
        assert_eq!(canonicalize_header_value("   "), "");
        assert_eq!(canonicalize_header_value("single"), "single");

        // ASCII space ONLY. Tab (0x09), NBSP (U+00A0), and newline are NOT whitespace to SigV4 —
        // they must pass through verbatim and must NOT be folded into / collapsed with 0x20 runs.
        // (This is what `split_whitespace` got wrong.)
        assert_eq!(canonicalize_header_value("a\tb"), "a\tb"); // tab preserved
        assert_eq!(canonicalize_header_value("a\u{00a0}b"), "a\u{00a0}b"); // NBSP preserved
        assert_eq!(canonicalize_header_value("a\nb"), "a\nb"); // newline preserved
                                                               // A tab surrounded by ASCII spaces: the spaces collapse, the tab stays put.
        assert_eq!(canonicalize_header_value("a  \t  b"), "a \t b");
        // Leading NBSP is NOT trimmed (only ASCII space is).
        assert_eq!(canonicalize_header_value("\u{00a0}a"), "\u{00a0}a");
    }

    #[test]
    fn test_sign_v4_collapses_ascii_space_in_header_value() {
        // Two requests whose only difference is collapsible runs of ASCII space in a signed header
        // value must produce the SAME signature, because SigV4 collapses 0x20 runs to one space and
        // trims leading/trailing 0x20. (Regression for v.trim()-only canonicalization.)
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
                    (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
                    ("x-custom".to_string(), v.to_string()),
                ],
                &payload_hash,
                "20150830T123600Z",
                "20150830",
            )
        };
        let (sig_single, _) = mk("a b c");
        let (sig_double, _) = mk("a   b  c"); // doubled ASCII spaces collapse to single spaces
        assert_eq!(
            sig_single, sig_double,
            "runs of ASCII space must be collapsed before signing"
        );
        // Leading/trailing ASCII space must still be trimmed (the original behavior).
        let (sig_padded, _) = mk("  a b c  ");
        assert_eq!(sig_single, sig_padded);
    }

    #[test]
    fn test_sign_v4_does_not_fold_nbsp_or_tab_in_header_value() {
        // AWS canonicalizes ASCII space ONLY. A header value containing NBSP (U+00A0) or a tab must
        // be signed with those bytes intact — they must NOT be rewritten to a 0x20 space. This is the
        // bug in `split_whitespace().join(" ")`, which folds NBSP/tab into spaces and yields a
        // canonical string that differs from AWS's → SignatureDoesNotMatch (403).
        //
        // Proof: a value with a literal NBSP/tab must sign DIFFERENTLY from the same value with an
        // ASCII space in that position. Under the old (split_whitespace) code these collapsed to the
        // same signature; under the corrected code they diverge.
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
                    (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
                    ("x-custom".to_string(), v.to_string()),
                ],
                &payload_hash,
                "20150830T123600Z",
                "20150830",
            )
        };
        let (sig_space, _) = mk("a b");
        let (sig_nbsp, _) = mk("a\u{00a0}b");
        let (sig_tab, _) = mk("a\tb");
        assert_ne!(
            sig_space, sig_nbsp,
            "NBSP must be preserved verbatim, not folded to an ASCII space"
        );
        assert_ne!(
            sig_space, sig_tab,
            "tab must be preserved verbatim, not folded to an ASCII space"
        );
    }

    // ====================== INBOUND VERIFY TESTS ======================

    /// Build a self-consistent inbound request + parsed header by SIGNING with a known secret, then
    /// return everything the verifier needs. This is the round-trip fixture: sign → verify must pass.
    /// `now`/`amzdate` default to AWS's example timestamp; callers can tamper individual pieces.
    fn signed_fixture(
        secret: &str,
        region: &str,
        service: &str,
        amzdate: &str,
        datestamp: &str,
    ) -> (ParsedAuthHeader, Vec<(String, String)>, String) {
        let payload_hash = sha256_hex(b"{\"x\":1}");
        let headers = vec![
            (
                "host".to_string(),
                "bedrock-runtime.amazonaws.com".to_string(),
            ),
            (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
            (X_AMZ_DATE.to_string(), amzdate.to_string()),
        ];
        let (sig, signed_headers) = sign_v4(
            secret,
            region,
            service,
            "POST",
            "/model/anthropic.claude/converse",
            "",
            &headers,
            &payload_hash,
            amzdate,
            datestamp,
        );
        let parsed = ParsedAuthHeader {
            access_key_id: "AKIAEXAMPLE1234567890".to_string(),
            datestamp: datestamp.to_string(),
            region: region.to_string(),
            service: service.to_string(),
            signed_headers,
            signature: sig,
        };
        (parsed, headers, payload_hash)
    }

    fn inbound<'a>(
        headers: &'a [(String, String)],
        payload_hash: &'a str,
        amzdate: &'a str,
    ) -> InboundRequest<'a> {
        InboundRequest {
            method: "POST",
            canonical_uri: "/model/anthropic.claude/converse",
            canonical_querystring: "",
            headers,
            payload_hash,
            amzdate,
        }
    }

    #[test]
    fn test_parse_authorization_header_roundtrip() {
        let v = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc123";
        let p = parse_authorization_header(v).expect("must parse");
        assert_eq!(p.access_key_id, "AKID");
        assert_eq!(p.datestamp, "20150830");
        assert_eq!(p.region, "us-east-1");
        assert_eq!(p.service, "bedrock");
        assert_eq!(p.signed_headers, "host;x-amz-content-sha256;x-amz-date"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(p.signature, "abc123");
    }

    #[test]
    fn test_parse_authorization_header_rejections() {
        // A non-AWS4 scheme is "missing" (so a Bearer falls through cleanly), not malformed.
        assert_eq!(
            parse_authorization_header("Bearer xyz"),
            Err(VerifyError::MissingAuthorization)
        );
        assert_eq!(
            parse_authorization_header(""),
            Err(VerifyError::MissingAuthorization)
        );
        // AWS4 but structurally broken → malformed.
        for bad in [
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock, SignedHeaders=host, Signature=x", // scope not aws4_request (4 parts)
            "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=x", // no Credential
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, Signature=x", // no SignedHeaders
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, SignedHeaders=host", // no Signature
            "AWS4-HMAC-SHA256 Credential=//us-east-1/bedrock/aws4_request, SignedHeaders=host, Signature=x", // empty akid/date
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, SignedHeaders=, Signature=x", // empty signed headers
        ] {
            assert_eq!(
                parse_authorization_header(bad),
                Err(VerifyError::MalformedAuthorization),
                "must be malformed: {bad}"
            );
        }
    }

    #[test]
    fn test_parse_amz_date_roundtrips_with_format_amz_time() {
        // parse_amz_date is the inverse of format_amz_time.
        let epoch = 1_440_938_160u64; // 2015-08-30T12:36:00Z
        let (amz, _date) = format_amz_time(epoch);
        assert_eq!(parse_amz_date(&amz), Some(epoch));
        // Bad shapes return None.
        assert_eq!(parse_amz_date("20150830T123600"), None); // no Z
        assert_eq!(parse_amz_date("2015-08-30T12:36:00Z"), None); // extended format
        assert_eq!(parse_amz_date("20150830X123600Z"), None); // wrong sep
        assert_eq!(parse_amz_date("20151330T123600Z"), None); // month 13
        assert_eq!(parse_amz_date(""), None);
    }

    #[test]
    fn test_verify_inbound_sigv4_roundtrip_accepts() {
        // The headline: a request signed with a secret VERIFIES against that same secret.
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (parsed, headers, ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        let req = inbound(&headers, &ph, amzdate);
        assert_eq!(verify_inbound_sigv4(&parsed, &req, secret, now), Ok(()));
    }

    #[test]
    fn test_verify_inbound_sigv4_wrong_secret_rejected() {
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (parsed, headers, ph) = signed_fixture(
            "the-real-secret",
            "us-east-1",
            "bedrock",
            amzdate,
            "20150830",
        );
        let req = inbound(&headers, &ph, amzdate);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, "a-DIFFERENT-secret", now),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn test_verify_inbound_sigv4_tampered_signature_rejected() {
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (mut parsed, headers, ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        // Flip the last hex nibble of the signature.
        let mut sig = parsed.signature.clone();
        let last = sig.pop().unwrap();
        sig.push(if last == '0' { '1' } else { '0' });
        parsed.signature = sig;
        let req = inbound(&headers, &ph, amzdate);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn test_verify_inbound_sigv4_tampered_body_payload_hash_rejected() {
        // A changed payload hash (i.e. a tampered body whose x-amz-content-sha256 no longer matches
        // what was signed) must REJECT: the signed header value differs from the value fed to verify.
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (parsed, mut headers, _ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        // Tamper the content-sha256 header (and the payload_hash input) to a DIFFERENT body's hash.
        let tampered = sha256_hex(b"{\"evil\":true}");
        for h in headers.iter_mut() {
            if h.0 == X_AMZ_CONTENT_SHA256 {
                h.1 = tampered.clone();
            }
        }
        let req = inbound(&headers, &tampered, amzdate);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now),
            Err(VerifyError::SignatureMismatch)
        );
    }

    #[test]
    fn test_verify_inbound_sigv4_expired_date_rejected() {
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let signed_epoch = parse_amz_date(amzdate).unwrap();
        let (parsed, headers, ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        let req = inbound(&headers, &ph, amzdate);
        // `now` is 10 minutes after the signature — outside the ±5min window.
        let now = signed_epoch + CLOCK_SKEW_SECS + 60;
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now),
            Err(VerifyError::Expired)
        );
        // Far-future signature (clock ahead) is also rejected (abs diff).
        let now2 = signed_epoch.saturating_sub(CLOCK_SKEW_SECS + 60);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now2),
            Err(VerifyError::Expired)
        );
        // Just inside the window still verifies.
        let now3 = signed_epoch + CLOCK_SKEW_SECS - 1;
        assert_eq!(verify_inbound_sigv4(&parsed, &req, secret, now3), Ok(()));
    }

    #[test]
    fn test_verify_inbound_sigv4_signed_header_missing_rejected() {
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (parsed, headers, ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        // Drop x-amz-date from the request's headers — it is in SignedHeaders, so reconstruction fails.
        let pruned: Vec<(String, String)> = headers
            .into_iter()
            .filter(|(k, _)| k != X_AMZ_DATE)
            .collect();
        let req = inbound(&pruned, &ph, amzdate);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now),
            Err(VerifyError::SignedHeadersMismatch)
        );
    }

    #[test]
    fn test_verify_inbound_sigv4_host_must_be_signed() {
        // A SignedHeaders list WITHOUT host is rejected even before signature comparison.
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let payload_hash = sha256_hex(b"");
        let headers = vec![
            (X_AMZ_DATE.to_string(), amzdate.to_string()),
            (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        ];
        // Sign WITHOUT host (so the signature is self-consistent for these headers), but host-less.
        let (sig, signed_headers) = sign_v4(
            secret,
            "us-east-1",
            "bedrock",
            "POST",
            "/x",
            "",
            &headers,
            &payload_hash,
            amzdate,
            "20150830",
        );
        let parsed = ParsedAuthHeader {
            access_key_id: "AKID".to_string(),
            datestamp: "20150830".to_string(),
            region: "us-east-1".to_string(),
            service: "bedrock".to_string(),
            signed_headers,
            signature: sig,
        };
        let req = InboundRequest {
            method: "POST",
            canonical_uri: "/x",
            canonical_querystring: "",
            headers: &headers,
            payload_hash: &payload_hash,
            amzdate,
        };
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now),
            Err(VerifyError::SignedHeadersMismatch)
        );
    }

    #[test]
    fn test_verify_inbound_sigv4_datestamp_must_match_amzdate() {
        // A Credential datestamp that disagrees with x-amz-date's date is malformed/forged.
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (mut parsed, headers, ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        parsed.datestamp = "20150831".to_string(); // off by a day
        let req = inbound(&headers, &ph, amzdate);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now),
            Err(VerifyError::MalformedAuthorization)
        );
    }

    #[test]
    fn test_uri_encode_query_encodes_slash() {
        // Query encoding differs from path encoding: '/' is percent-encoded in the query.
        assert_eq!(uri_encode_query("a/b"), "a%2Fb");
        assert_eq!(uri_encode_query("k-v_1.~"), "k-v_1.~"); // unreserved pass through
        assert_eq!(uri_encode_query(" "), "%20");
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
            (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
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
        assert_eq!(signed, "content-type;host;x-amz-date"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(
            sig,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7" // golden wire-contract literal (kept bare on purpose)
        );
    }

    // Reference the canonical dummy secret from `crate::auth` (the single source of truth) rather
    // than maintaining a separate copy that could drift. Used to prove the unknown-key path produces
    // an ordinary SignatureMismatch, not a distinct variant.
    use crate::auth::DUMMY_SECRET;

    #[test]
    fn test_verify_inbound_sigv4_unknown_key_dummy_secret_is_signature_mismatch() {
        // H4 (dummy-secret guard): a request signed with a REAL secret, verified against the canonical
        // DUMMY secret (the path taken for an unknown AccessKeyId), must fail with the SAME ordinary
        // `SignatureMismatch` a wrong-secret attempt produces — NOT a distinct "key not found" variant.
        // This pins the FUNCTIONAL contract: an unknown AccessKeyId is verified against the canonical
        // dummy secret and returns `Err(SignatureMismatch)`, so the response is the same as a real key
        // with a bad signature — no key-existence enumeration oracle. (Timing-equalization is a design
        // property of always running the HMAC against the dummy secret; this test does not assert
        // timing, only the response contract.)
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (parsed, headers, ph) = signed_fixture(
            "a-real-tenant-secret",
            "us-east-1",
            "bedrock",
            amzdate,
            "20150830",
        );
        let req = inbound(&headers, &ph, amzdate);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, DUMMY_SECRET, now),
            Err(VerifyError::SignatureMismatch),
            "verifying a real-secret signature against the dummy secret must be an ordinary \
             SignatureMismatch, not a distinct key-not-found variant"
        );
    }

    #[test]
    fn test_parse_authorization_header_skips_unknown_sections() {
        // F3: an UNKNOWN section (AWS clients may emit extras) is SKIPPED, not rejected — as long as
        // the three mandatory sections are present and well-formed.
        let v = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, \
                 SignedHeaders=host;x-amz-date, Signature=abc123, X-Future-Extension=whatever";
        let p =
            parse_authorization_header(v).expect("unknown section must be skipped, not rejected");
        assert_eq!(p.access_key_id, "AKID");
        assert_eq!(p.signed_headers, "host;x-amz-date"); // golden wire-contract literal (kept bare on purpose)
        assert_eq!(p.signature, "abc123");
        // But a MISSING mandatory section (Signature) with an unknown one present still fails.
        let missing_sig =
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, \
                           SignedHeaders=host, X-Extra=1";
        assert_eq!(
            parse_authorization_header(missing_sig),
            Err(VerifyError::MalformedAuthorization),
            "an unknown section does not satisfy the mandatory Signature requirement"
        );
    }

    #[test]
    fn test_verify_inbound_sigv4_signed_headers_claim_stripped_rejected() {
        // M4/M8: an attacker who removes a header NAME from the SignedHeaders CLAIM (without re-signing)
        // must be rejected — the reconstructed SignedHeaders string no longer matches what was signed.
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (mut parsed, headers, ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        // Strip x-amz-content-sha256 from the SignedHeaders claim (host still present so the host check
        // passes and we reach the signature/headers compare). The signature was computed over all three.
        parsed.signed_headers = "host;x-amz-date".to_string();
        let req = inbound(&headers, &ph, amzdate);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now),
            Err(VerifyError::SignatureMismatch),
            "stripping a header from the SignedHeaders claim must fail-closed"
        );
    }

    #[test]
    fn test_verify_inbound_sigv4_signed_headers_wrong_sort_rejected() {
        // M4/M8: SignedHeaders MUST be sorted (the signer sorts). A claim listing the same names in a
        // non-sorted order diverges from the reconstruction and must be rejected.
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (mut parsed, headers, ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        // Reverse-sorted order (still contains host, so it passes the host-present gate).
        parsed.signed_headers = "x-amz-date;x-amz-content-sha256;host".to_string();
        let req = inbound(&headers, &ph, amzdate);
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now),
            Err(VerifyError::SignatureMismatch),
            "an unsorted SignedHeaders claim must fail-closed"
        );
    }

    #[test]
    fn test_verify_inbound_sigv4_exact_skew_boundary_accepted() {
        // M4: the clock-skew check is `skew > CLOCK_SKEW_SECS` (strict >), so a skew EXACTLY equal to
        // the bound must be ACCEPTED (only strictly-greater is Expired). Pins the boundary.
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let signed_epoch = parse_amz_date(amzdate).unwrap();
        let (parsed, headers, ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        let req = inbound(&headers, &ph, amzdate);
        // Exactly at the boundary (both directions) must verify.
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, signed_epoch + CLOCK_SKEW_SECS),
            Ok(()),
            "skew == CLOCK_SKEW_SECS (ahead) must be accepted under the strict > comparison"
        );
        assert_eq!(
            verify_inbound_sigv4(
                &parsed,
                &req,
                secret,
                signed_epoch.saturating_sub(CLOCK_SKEW_SECS)
            ),
            Ok(()),
            "skew == CLOCK_SKEW_SECS (behind) must be accepted"
        );
    }

    #[test]
    fn test_verify_inbound_sigv4_missing_date_rejected() {
        // M4: a request whose x-amz-date is not a parseable amz timestamp fails with MissingDate,
        // surfaced through verify_inbound_sigv4 itself (not just parse_amz_date in isolation).
        let secret = "the-real-secret";
        let amzdate = "20150830T123600Z";
        let now = parse_amz_date(amzdate).unwrap();
        let (parsed, headers, ph) =
            signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
        // Build an InboundRequest carrying an UNPARSEABLE amzdate.
        let req = InboundRequest {
            method: "POST",
            canonical_uri: "/model/anthropic.claude/converse",
            canonical_querystring: "",
            headers: &headers,
            payload_hash: &ph,
            amzdate: "not-a-date",
        };
        assert_eq!(
            verify_inbound_sigv4(&parsed, &req, secret, now),
            Err(VerifyError::MissingDate)
        );
    }
}
