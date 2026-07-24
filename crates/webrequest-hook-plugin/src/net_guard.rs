// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SSRF guard the `webrequest` forwarder applies to its operator-configured target URL.
//!
//! This plugin makes an OUTBOUND HTTP call to a URL the operator put in `settings.url`, so — exactly
//! like the retired `webhook` hook transport it replaces — it must refuse a URL that points at an
//! internal target (cloud-metadata, RFC1918 private, RFC6598 CGNAT, link-local, IPv6 ULA, or the
//! alternate IPv4 encodings a resolver still expands to those). A signed, trusted forwarder that
//! could be pointed at `169.254.169.254` would be an SSRF pivot; the guard closes that.
//!
//! ## Policy parity with the old `webhook` hook (deliberate)
//!
//! The retired `WebhookPolicy` validated its sidecar URL with `observability::validate_routing_webhook_url`,
//! which reused the OTLP carve-out: link-local / IMDS / RFC1918 / CGNAT / cloud-metadata are BLOCKED,
//! but loopback / `localhost` are ALLOWED (a hook sidecar is typically co-located on loopback), and
//! plaintext `http://` is permitted ONLY for a loopback host. This module keeps that policy bit-for-bit
//! so a hook currently on `route: webhook` can migrate by pointing this plugin at the same URL.
//!
//! ## Why the predicates are COPIED, not shared
//!
//! The pure context-free predicates below (`is_cgnat_shared_v4`, `is_unique_local_v6`,
//! `is_link_local_v6`, `is_alternate_ipv4_encoding`) are lifted verbatim from
//! `busbar/src/net_guard.rs`. A plugin cdylib must NOT depend on the `busbar` core crate (it would pull
//! the whole engine into a leaf `cdylib` and invert the plugin/core boundary), so the identical
//! security atoms are copied here. The design spec explicitly calls for the SSRF guard to LIVE in this
//! plugin. If these are ever hoisted into a tiny no-dep shared leaf crate, this copy should reference
//! it; until then the copies must be kept byte-identical — a contributor hardening one against a new
//! obfuscation form must harden both. The tests below pin the shared behaviour so drift is caught.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// ── Pure context-free predicates (copied verbatim from busbar/src/net_guard.rs) ────────────────────

/// IPv6 unique-local range `fc00::/7` (the first 7 bits are `1111110`).
pub(crate) fn is_unique_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// IPv6 link-local range `fe80::/10` (the first 10 bits are `1111111010`).
pub(crate) fn is_link_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// RFC 6598 Shared Address Space `100.64.0.0/10` (CGNAT) — routable inside AWS/GCP VPCs and k8s
/// clusters, so an SSRF target the private/link-local checks miss. `Ipv4Addr::is_private()` misses it.
pub(crate) fn is_cgnat_shared_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// True when `host` is an alternate (non-dotted-quad) IPv4 encoding that `IpAddr::from_str` rejects
/// but the OS resolver still maps to an IPv4 address (bare decimal `2130706433`, `0x`/`0X` hex, a
/// leading-zero octal, or a dotted form with fewer than four octets). A canonical dotted-quad is NOT
/// matched here (handled by the `parse::<IpAddr>()` path); a normal DNS hostname is not matched either.
pub(crate) fn is_alternate_ipv4_encoding(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        let all_numeric = parts.iter().all(|p| {
            if let Some(hex) = p.strip_prefix("0x").or_else(|| p.strip_prefix("0X")) {
                !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
            } else {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())
            }
        });
        if !all_numeric {
            return false;
        }
        if parts.len() < 4 {
            return true;
        }
        return parts.iter().any(|p| {
            p.starts_with("0x")
                || p.starts_with("0X")
                || (p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()))
        });
    }
    host.bytes().all(|b| b.is_ascii_digit())
}

/// True iff `host` is an alternate (non-dotted-quad) IPv4 encoding that unambiguously denotes the
/// loopback address `127.0.0.1` (decimal `2130706433`, hex `0x7f000001`, octal `017700000001`, or a
/// short-dotted `127.1` / `127.0.1`). Used to permit the loopback-sidecar exception while still
/// blocking every OTHER alternate-encoded internal target. Conservative: anything it cannot positively
/// confirm as loopback is treated as non-loopback (and therefore blocked). Mirrors
/// `observability::is_alternate_loopback_v4`.
pub(crate) fn is_alternate_loopback_v4(host: &str) -> bool {
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return u32::from_str_radix(hex, 16).ok() == Some(0x7f00_0001);
        }
        if let Some(oct) = host.strip_prefix('0').filter(|_| host.len() > 1) {
            if let Ok(v) = u32::from_str_radix(oct, 8) {
                return v == 0x7f00_0001;
            }
        }
        if let Ok(v) = host.parse::<u32>() {
            return v == 0x7f00_0001;
        }
        return false;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 4 || parts.is_empty() {
        return false;
    }
    let Some(first) = parts.first().and_then(|p| p.parse::<u32>().ok()) else {
        return false;
    };
    first == 127 && parts.iter().all(|p| p.parse::<u32>().is_ok())
}

// ── Context-specific block/loopback wrappers (parity with the old webhook/OTLP guard) ──────────────

/// The cloud-metadata DNS names blocked case-insensitively. Mirrors `observability::METADATA_HOSTS`.
const METADATA_HOSTS: &[&str] = &["metadata.google.internal", "metadata.internal"];

/// True for an IPv4 literal the forwarder must not POST to (EXCEPT loopback, which the caller carves
/// out): link-local (incl. `169.254.169.254` IMDS), RFC1918 private, RFC6598 CGNAT, unspecified,
/// broadcast, and the Azure WireServer / OCI IMDS public-but-metadata literals. Mirrors
/// `observability::is_internal_v4` (loopback is checked by the caller so the localhost carve-out is
/// visible at the call site).
fn is_internal_v4(v4: &Ipv4Addr) -> bool {
    const AZURE_WIRESERVER: Ipv4Addr = Ipv4Addr::new(168, 63, 129, 16);
    const OCI_IMDS: Ipv4Addr = Ipv4Addr::new(192, 0, 0, 192);
    v4.is_loopback()
        || v4.is_link_local()
        || v4.is_private()
        || is_cgnat_shared_v4(v4)
        || v4.is_unspecified()
        || v4.is_broadcast()
        || *v4 == AZURE_WIRESERVER
        || *v4 == OCI_IMDS
}

/// True iff the target URL's host is the loopback/localhost target the forwarder MAY reach — the exact
/// carve-out `host_is_blocked` leaves un-blocked (parity with the old webhook policy, which allowed a
/// loopback sidecar). Used to gate the plaintext-`http://` allowance to loopback only.
pub(crate) fn host_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = host_of(url) else {
        return false;
    };
    if is_alternate_ipv4_encoding(&host) {
        return is_alternate_loopback_v4(&host);
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(IpAddr::V6(v6)) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
        Err(_) => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .rsplit_once('.')
                    .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("localhost"))
        }
    }
}

/// SSRF block predicate for the target URL: identical to a full internal check EXCEPT loopback and the
/// `localhost` DNS name are NOT blocked (the loopback-sidecar carve-out the old webhook policy kept).
/// Every other internal/metadata target is blocked: cloud-metadata names + IMDS literal, RFC1918
/// private, RFC6598 CGNAT, link-local, IPv6 ULA/link-local/unspecified, and the alternate-IPv4
/// encodings that resolve to those. Mirrors `observability::otlp_host_is_blocked`.
pub(crate) fn host_is_blocked(url: &reqwest::Url) -> bool {
    let Some(host) = host_of(url) else {
        return true; // a URL with no host is unusable as a target
    };
    if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
        return true;
    }
    if is_alternate_ipv4_encoding(&host) {
        return !is_alternate_loopback_v4(&host);
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => !v4.is_loopback() && is_internal_v4(&v4),
        Ok(IpAddr::V6(v6)) => {
            if v6.is_loopback() {
                return false; // `::1` loopback sidecar — allowed
            }
            if let Some(v4) = v6.to_ipv4() {
                return !v4.is_loopback() && is_internal_v4(&v4);
            }
            v6.is_unspecified() || is_unique_local_v6(&v6) || is_link_local_v6(&v6)
        }
        // DNS name: metadata names blocked above; `localhost` and any external host allowed.
        Err(_) => false,
    }
}

/// The URL's host with the IPv6 `[...]` brackets and a single trailing FQDN-root `.` stripped, so the
/// predicates see the same canonical form the OTLP/webhook guard did. Returns `None` for a hostless URL.
fn host_of(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?;
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    Some(host.to_string())
}

/// Case-insensitive equality of a URL's scheme to `want` (an ASCII-lowercase literal).
fn scheme_is(url: &reqwest::Url, want: &str) -> bool {
    url.scheme().eq_ignore_ascii_case(want)
}

/// Validate the operator-configured target URL against the SSRF guard, returning the canonicalized URL
/// string on success or a stable, credential-free error on rejection. Accepts `https://` for any
/// allowed host and `http://` ONLY for a loopback host (parity with the old webhook policy: a plaintext
/// hop must stay on loopback so a payload — which may carry granted prompt/user content — is never sent
/// in cleartext to a remote host). Any embedded `user:pass@` userinfo is masked out of every error.
pub(crate) fn validate_target_url(raw: &str) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(raw)
        .map_err(|e| format!("webrequest: settings.url is not a valid URL: {e}"))?;
    if !(scheme_is(&url, "https") || scheme_is(&url, "http")) {
        return Err(format!(
            "webrequest: settings.url must be an http:// or https:// URL (got '{}')",
            mask_userinfo(raw)
        ));
    }
    if host_is_blocked(&url) {
        return Err(format!(
            "webrequest: settings.url must not target a link-local/private/CGNAT/cloud-metadata host \
             (SSRF guard; loopback sidecars are allowed); got '{}'",
            mask_userinfo(raw)
        ));
    }
    if scheme_is(&url, "http") && !host_is_loopback(&url) {
        return Err(format!(
            "webrequest: settings.url must use https:// for a non-loopback target (plaintext http:// is \
             only permitted for a loopback sidecar; the payload could otherwise be sent in cleartext); \
             got '{}'",
            mask_userinfo(raw)
        ));
    }
    Ok(url)
}

/// Replace any `user[:pass]@` userinfo in a URL-ish string with `***@` so a credential embedded in the
/// operator's URL never reaches a (logged) error message. Best-effort textual mask on the raw input.
pub(crate) fn mask_userinfo(raw: &str) -> String {
    // Only the authority segment can carry userinfo: between `://` and the next `/`, `?`, or `#`.
    let Some(scheme_end) = raw.find("://") else {
        return raw.to_string();
    };
    let auth_start = scheme_end + 3;
    let rest = &raw[auth_start..];
    let auth_end = rest
        .find(['/', '?', '#'])
        .map(|i| auth_start + i)
        .unwrap_or(raw.len());
    let authority = &raw[auth_start..auth_end];
    match authority.rfind('@') {
        Some(at) => format!("{}***@{}", &raw[..auth_start], &raw[auth_start + at + 1..]),
        None => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> reqwest::Url {
        reqwest::Url::parse(s).unwrap()
    }

    #[test]
    fn cgnat_ula_linklocal_predicates_match_core() {
        assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 64, 0, 0)));
        assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 100, 100, 200))); // Alibaba metadata
        assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_unique_local_v6(&"fc00::1".parse().unwrap()));
        assert!(is_unique_local_v6(&"fd00:ec2::254".parse().unwrap()));
        assert!(!is_unique_local_v6(&"fe80::1".parse().unwrap()));
        assert!(is_link_local_v6(&"fe80::1".parse().unwrap()));
        assert!(!is_link_local_v6(&"fc00::1".parse().unwrap()));
    }

    #[test]
    fn alternate_encoding_flags_obfuscated_forms() {
        assert!(is_alternate_ipv4_encoding("2130706433"));
        assert!(is_alternate_ipv4_encoding("0x7f000001"));
        assert!(is_alternate_ipv4_encoding("017700000001"));
        assert!(is_alternate_ipv4_encoding("127.1"));
        assert!(!is_alternate_ipv4_encoding("127.0.0.1"));
        assert!(!is_alternate_ipv4_encoding("example.com"));
        assert!(is_alternate_loopback_v4("2130706433"));
        assert!(is_alternate_loopback_v4("127.1"));
        assert!(!is_alternate_loopback_v4("2130706434"));
    }

    #[test]
    fn host_is_blocked_blocks_internal_targets() {
        // Cloud metadata / IMDS.
        assert!(host_is_blocked(&url("http://169.254.169.254/latest")));
        assert!(host_is_blocked(&url("https://metadata.google.internal/x")));
        assert!(host_is_blocked(&url("https://100.100.100.200/meta"))); // Alibaba CGNAT
        assert!(host_is_blocked(&url("https://168.63.129.16/x"))); // Azure WireServer
        assert!(host_is_blocked(&url("https://192.0.0.192/x"))); // OCI IMDS
                                                                 // RFC1918 / CGNAT / link-local / ULA.
        assert!(host_is_blocked(&url("https://10.0.0.1/x")));
        assert!(host_is_blocked(&url("https://192.168.1.1/x")));
        assert!(host_is_blocked(&url("https://100.64.0.1/x")));
        assert!(host_is_blocked(&url("https://[fc00::1]/x")));
        assert!(host_is_blocked(&url("https://[fe80::1]/x")));
        // Loopback + external are NOT blocked (the sidecar carve-out).
        assert!(!host_is_blocked(&url("http://127.0.0.1:8080/x")));
        assert!(!host_is_blocked(&url("http://localhost:8080/x")));
        assert!(!host_is_blocked(&url("https://[::1]:8080/x")));
        assert!(!host_is_blocked(&url("https://api.example.com/x")));
    }

    #[test]
    fn validate_rejects_scheme_and_plaintext_remote() {
        assert!(validate_target_url("ftp://example.com/x").is_err());
        // Plaintext http to a remote host is rejected (cleartext payload risk).
        assert!(validate_target_url("http://api.example.com/x").is_err());
        // Plaintext http to loopback is allowed (sidecar).
        assert!(validate_target_url("http://127.0.0.1:9000/route").is_ok());
        assert!(validate_target_url("http://localhost:9000/route").is_ok());
        // https to a remote host is allowed.
        assert!(validate_target_url("https://api.example.com/route").is_ok());
        // https to an internal host is rejected.
        assert!(validate_target_url("https://10.0.0.1/route").is_err());
    }

    #[test]
    fn errors_mask_embedded_userinfo() {
        let err = validate_target_url("https://svc:hunter2@10.0.0.1/route").unwrap_err();
        assert!(
            !err.contains("hunter2"),
            "SSRF error leaked userinfo: {err}"
        );
        assert_eq!(
            mask_userinfo("https://svc:hunter2@host/p?q=1"),
            "https://***@host/p?q=1"
        );
        assert_eq!(mask_userinfo("https://host/p"), "https://host/p");
    }
}
