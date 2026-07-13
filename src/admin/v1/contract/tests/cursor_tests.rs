
use super::{decode_offset_cursor, encode_offset_cursor};

#[test]
fn offset_cursor_round_trips_and_is_opaque() {
    for n in [0usize, 1, 42, 1000, usize::MAX] {
        let c = encode_offset_cursor(n);
        assert!(
            c.bytes().all(|b| b.is_ascii_hexdigit()),
            "cursor is URL-safe hex: {c}"
        );
        assert_ne!(c, n.to_string(), "cursor is opaque, not the bare integer");
        assert_eq!(decode_offset_cursor(&c), Some(n));
    }
    // Foreign / malformed cursors decode to None (transport -> invalid_request, not silent skip).
    assert_eq!(decode_offset_cursor(""), None);
    assert_eq!(decode_offset_cursor("zz"), None);
    assert_eq!(decode_offset_cursor("abc"), None); // odd length
    assert_eq!(decode_offset_cursor("6f"), None); // "o" alone — no ":<n>" tail
}
