//! Executable checks of the UTF-8 sanitizer and cap. The proofs cover every
//! input; these pin concrete sequences against the standard library's view.
use crate::utf8::*;

#[test]
fn valid_text_passes_through_and_matches_the_standard_library() {
    for text in ["", "plain", "é€😀", "\u{7f}\u{80}\u{7ff}\u{800}\u{ffff}\u{10000}\u{10ffff}", "mixed 日本語 and emoji 🎉"] {
        assert_eq!(sanitize(text.as_bytes()), text.as_bytes(), "{text:?}");
        assert_eq!(String::from_utf8(sanitize(text.as_bytes())).unwrap(), text);
    }
}

#[test]
fn every_ill_formed_byte_becomes_a_replacement_character() {
    let cases: &[(&[u8], &str)] = &[
        (b"\xff", "\u{fffd}"), (b"a\x80b", "a\u{fffd}b"),
        (b"\xc0\xaf", "\u{fffd}\u{fffd}"),                 // overlong slash
        (b"\xe0\x80\xaf", "\u{fffd}\u{fffd}\u{fffd}"),      // overlong three-byte
        (b"\xed\xa0\x80", "\u{fffd}\u{fffd}\u{fffd}"),      // surrogate
        (b"\xf4\x90\x80\x80", "\u{fffd}\u{fffd}\u{fffd}\u{fffd}"), // past U+10FFFF
        (b"\xf5\x80\x80\x80", "\u{fffd}\u{fffd}\u{fffd}\u{fffd}"),
        (b"\xe2\x82", "\u{fffd}\u{fffd}"),                   // truncated
        (b"\xe2\x82\xac\xe2", "€\u{fffd}"),
        (b"\xc3", "\u{fffd}"), (b"\xc3(", "\u{fffd}("),
    ];
    for (input, expected) in cases {
        let out = sanitize(input);
        assert_eq!(String::from_utf8(out.clone()).unwrap(), *expected, "{input:?}");
        assert!(std::str::from_utf8(&out).is_ok());
        assert_eq!(sanitize(&out), out, "sanitizing is idempotent");
    }
}

#[test]
fn validity_agrees_with_the_standard_library() {
    for text in ["", "plain", "é€😀", "\u{10ffff}"] { assert!(is_valid(text.as_bytes())); }
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..100_000 {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        let bytes: Vec<u8> = (0..(x % 8) as usize).map(|i| (x >> (8 * i)) as u8).collect();
        assert_eq!(is_valid(&bytes), std::str::from_utf8(&bytes).is_ok(), "{bytes:?}");
    }
}

#[test]
fn cap_cuts_only_at_character_boundaries() {
    let text = "aé€😀b".as_bytes(); // 1 + 2 + 3 + 4 + 1 bytes
    let expect = |limit: usize, s: &str| assert_eq!(cap(text, limit), s.as_bytes(), "limit {limit}");
    expect(0, ""); expect(1, "a"); expect(2, "a"); expect(3, "aé"); expect(4, "aé"); expect(5, "aé"); expect(6, "aé€");
    expect(7, "aé€"); expect(9, "aé€"); expect(10, "aé€😀"); expect(11, "aé€😀b"); expect(100, "aé€😀b");
    assert_eq!(cap(b"", 0), b"");
    for limit in 0..12 {
        let out = cap(text, limit);
        assert!(std::str::from_utf8(&out).is_ok() && out.len() <= limit && text.starts_with(&out));
    }
}

#[test]
fn char_len_follows_the_rfc_table() {
    let len = |bytes: &[u8]| char_len_exec(bytes, 0);
    assert_eq!(len(b""), 0); assert_eq!(len(b"a"), 1); assert_eq!(len(b"\xc2\x80"), 2); assert_eq!(len(b"\xdf\xbf"), 2);
    assert_eq!(len(b"\xc1\xbf"), 0); assert_eq!(len(b"\xe0\xa0\x80"), 3); assert_eq!(len(b"\xe0\x9f\xbf"), 0);
    assert_eq!(len(b"\xed\x9f\xbf"), 3); assert_eq!(len(b"\xed\xa0\x80"), 0); assert_eq!(len(b"\xef\xbf\xbd"), 3);
    assert_eq!(len(b"\xf0\x90\x80\x80"), 4); assert_eq!(len(b"\xf0\x8f\xbf\xbf"), 0); assert_eq!(len(b"\xf4\x8f\xbf\xbf"), 4);
    assert_eq!(len(b"\xf4\x90\x80\x80"), 0); assert_eq!(len(b"\xf0\x90\x80"), 0); assert_eq!(len(b"\x80"), 0);
    assert_eq!(char_len_exec(b"ab\xe2\x82\xac", 2), 3); assert_eq!(char_len_exec(b"ab", 5), 0);
}
