//! Pure, std-only network-address primitives shared by busbar's SSRF guards.
//!
//! These predicates are the *context-free* atoms of the SSRF obfuscation defense: they answer
//! "is this `Ipv4Addr` in the RFC 6598 CGNAT range?", "is this `Ipv6Addr` in the unique-local
//! (`fc00::/7`) or link-local (`fe80::/10`) range?", and "is this host string an alternate (non
//! dotted-quad) IPv4 encoding the OS resolver still expands?" — questions whose answer must NOT
//! depend on which caller is asking. They previously lived as byte-identical copies (or inline
//! bit-mask expressions) in both
//! `config_validate` (the provider-base-URL SSRF guard, which hand-parses a raw config string) and
//! `observability` (the request-log-webhook / OTLP SSRF guard, which reads an already
//! `reqwest::Url::parse`d host). Duplicated *security* logic is the one place where "documented
//! divergence" does not fully neutralize drift: a contributor hardening one guard against a new
//! obfuscation form could silently miss the other copy. Hoisting just these identical primitives
//! into one tested leaf gives them a single source of truth.
//!
//! The *context-specific* wrappers stay with their callers on purpose, because they legitimately
//! differ: `config_validate` keeps `expand_alternate_ipv4` (it re-checks an obfuscated literal
//! against the metadata denylist) and its raw-string `percent_decode_host`; `observability` keeps
//! `is_internal_v4` (which additionally blocks `255.255.255.255` broadcast) and its
//! `METADATA_HOSTS` list shape. This module holds ONLY the parts that are — and must remain —
//! identical.
//!
//! Pure (no I/O, no globals), so each predicate is unit-testable in isolation; the tests live here.

use std::net::{Ipv4Addr, Ipv6Addr};

/// IPv6 unique-local range `fc00::/7` (the first 7 bits are `1111110`). No stable std predicate
/// exists for this range on the pinned toolchain, so the leading bits are checked directly.
pub(crate) fn is_unique_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xfe00) == 0xfc00
}

/// IPv6 link-local range `fe80::/10` (the first 10 bits are `1111111010`). No stable std predicate
/// exists for this range on the pinned toolchain, so the leading bits are checked directly.
pub(crate) fn is_link_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}

/// RFC 6598 Shared Address Space `100.64.0.0/10` (a.k.a. CGNAT). NOT covered by
/// `Ipv4Addr::is_private()`, yet routable inside AWS/GCP VPCs and many Kubernetes clusters where it
/// fronts internal services — so it is an SSRF target the private/link-local checks miss. The /10
/// is the addresses whose first octet is `100` and whose top two bits of the second octet are `01`.
pub(crate) fn is_cgnat_shared_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xC0) == 64
}

/// True when `host` is an alternate (non-dotted-quad) IPv4 encoding that `IpAddr::from_str` rejects
/// but the OS resolver (glibc `getaddrinfo`, used by reqwest's default resolver) still maps to an
/// IPv4 address: a bare decimal integer (`2130706433` = 127.0.0.1), a `0x`/`0X` hex literal
/// (`0x7f000001`), a leading-zero octal literal (`017700000001`), or a dotted form with FEWER than
/// four octets (`127.1`, `10.0.1`). On a raw, un-normalized host string these bypass the canonical
/// IP-literal checks while still resolving to loopback / link-local / private targets at connect
/// time, so they must be treated as blocked. A canonical four-octet dotted-quad is NOT matched here
/// (it is handled by the `parse::<IpAddr>()` path); a normal DNS hostname is not matched either.
pub(crate) fn is_alternate_ipv4_encoding(host: &str) -> bool {
    if host.is_empty() {
        return false;
    }

    // Whole-host `0x...` / `0X...` hex literal (e.g. `0x7f000001`). Only when there is no `.`; a
    // dotted per-octet hex form (`0x7f.0.0.1`) is handled by the dotted branch below.
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }

    // Dotted form: split on '.'. A canonical dotted-quad has exactly 4 parts and parses via
    // `IpAddr` — leave it to that path. Fewer than 4 numeric parts (e.g. `127.1`, `10.0.1`) is an
    // alternate short form getaddrinfo expands; flag it. Any part using a `0x` hex or leading-zero
    // octal encoding is also an alternate form.
    if host.contains('.') {
        let parts: Vec<&str> = host.split('.').collect();
        // Every part must be a numeric encoding (decimal, hex, or octal) for this to be an IP-ish
        // host at all; if any part has a non-numeric character it's a DNS name → not our concern.
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
        // Short dotted form (fewer than 4 parts) is an alternate encoding getaddrinfo expands.
        if parts.len() < 4 {
            return true;
        }
        // Four numeric parts: alternate iff any part is hex (`0x`) or leading-zero octal.
        return parts.iter().any(|p| {
            p.starts_with("0x")
                || p.starts_with("0X")
                || (p.len() > 1 && p.starts_with('0') && p.bytes().all(|b| b.is_ascii_digit()))
        });
    }

    // No '.', not `0x`: a bare all-digits host is a decimal integer IP encoding (e.g. `2130706433`).
    host.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_cgnat_shared_v4_covers_rfc6598_only() {
        // 100.64.0.0/10 = first octet 100, second octet's top two bits == 01 (i.e. 64..=127).
        assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 64, 0, 0)));
        assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 100, 100, 200))); // Alibaba metadata
        assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 127, 255, 255)));
        // Outside the /10: second octet below 64 or above 127, or different first octet.
        assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(100, 63, 255, 255)));
        assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(100, 128, 0, 0)));
        assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(99, 64, 0, 0)));
        assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn is_unique_local_v6_covers_fc00_slash_7() {
        // fc00::/7 — first 7 bits 1111110, so fc00.. and fd00.. are in-range.
        assert!(is_unique_local_v6(&"fc00::1".parse().unwrap()));
        assert!(is_unique_local_v6(&"fd00:ec2::254".parse().unwrap())); // EC2 IMDSv6
        assert!(is_unique_local_v6(&"fdff:ffff::".parse().unwrap()));
        // Outside fc00::/7.
        assert!(!is_unique_local_v6(&"fe80::1".parse().unwrap())); // link-local, not ULA
        assert!(!is_unique_local_v6(&"2001:db8::1".parse().unwrap()));
        assert!(!is_unique_local_v6(&"::1".parse().unwrap()));
    }

    #[test]
    fn is_link_local_v6_covers_fe80_slash_10() {
        // fe80::/10 — first 10 bits 1111111010.
        assert!(is_link_local_v6(&"fe80::1".parse().unwrap()));
        assert!(is_link_local_v6(&"febf:ffff::".parse().unwrap()));
        // Outside fe80::/10.
        assert!(!is_link_local_v6(&"fec0::1".parse().unwrap())); // site-local (deprecated), not fe80::/10
        assert!(!is_link_local_v6(&"fc00::1".parse().unwrap())); // ULA, not link-local
        assert!(!is_link_local_v6(&"2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn is_alternate_ipv4_encoding_flags_obfuscated_forms() {
        assert!(is_alternate_ipv4_encoding("2130706433")); // decimal 127.0.0.1
        assert!(is_alternate_ipv4_encoding("0x7f000001")); // hex
        assert!(is_alternate_ipv4_encoding("0X7F000001")); // hex, uppercase prefix
        assert!(is_alternate_ipv4_encoding("017700000001")); // leading-zero octal
        assert!(is_alternate_ipv4_encoding("127.1")); // short dotted
        assert!(is_alternate_ipv4_encoding("10.0.1")); // short dotted
        assert!(is_alternate_ipv4_encoding("0x7f.0.0.1")); // per-octet hex
        assert!(is_alternate_ipv4_encoding("0177.0.0.1")); // per-octet octal

        // Canonical dotted-quads are left to the `parse::<IpAddr>()` path, not flagged here.
        assert!(!is_alternate_ipv4_encoding("127.0.0.1"));
        assert!(!is_alternate_ipv4_encoding("8.8.8.8"));
        // DNS names and the empty string are not alternate encodings.
        assert!(!is_alternate_ipv4_encoding("api.openai.com"));
        assert!(!is_alternate_ipv4_encoding("example.com"));
        assert!(!is_alternate_ipv4_encoding(""));
    }
}
