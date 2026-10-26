//! Executable checks of the base64url codec: the RFC 4648 vectors, the
//! url-safe characters, and the refusals the proof promises.
use crate::base64url::{decode, encode};

fn text(bytes: &[u8]) -> String { String::from_utf8(encode(bytes)).unwrap() }

#[test]
fn the_rfc_4648_vectors_encode_without_padding() {
    assert_eq!(text(b""), "");
    assert_eq!(text(b"f"), "Zg");
    assert_eq!(text(b"fo"), "Zm8");
    assert_eq!(text(b"foo"), "Zm9v");
    assert_eq!(text(b"foob"), "Zm9vYg");
    assert_eq!(text(b"fooba"), "Zm9vYmE");
    assert_eq!(text(b"foobar"), "Zm9vYmFy");
    assert_eq!(text(&[0xfb, 0xff, 0xbf]), "-_-_", "the url-safe alphabet");
}

#[test]
fn decoding_inverts_encoding_and_tolerates_trailing_padding() {
    assert_eq!(decode(b"Zm9vYg").as_deref(), Some(&b"foob"[..]));
    assert_eq!(decode(b"Zm9vYg==").as_deref(), Some(&b"foob"[..]));
    assert_eq!(decode(b"Zm8=").as_deref(), Some(&b"fo"[..]));
    assert_eq!(decode(b"").as_deref(), Some(&b""[..]));
    assert_eq!(decode(b"==").as_deref(), Some(&b""[..]));
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for n in 0..2000usize {
        let bytes: Vec<u8> = (0..n % 70).map(|_| { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; (seed >> 24) as u8 }).collect();
        assert_eq!(decode(&encode(&bytes)).as_deref(), Some(bytes.as_slice()));
    }
}

#[test]
fn texts_that_encode_nothing_are_refused() {
    assert_eq!(decode(b"Zm9vY"), None, "one character over a group");
    assert_eq!(decode(b"Z"), None);
    assert_eq!(decode(b"Zh"), None, "leftover bits set in a one byte tail");
    assert_eq!(decode(b"Zm9"), None, "leftover bits set in a two byte tail");
    assert_eq!(decode(b"Zm9v+A"), None, "the standard alphabet's plus");
    assert_eq!(decode(b"Zm9v/A"), None, "the standard alphabet's slash");
    assert_eq!(decode(b"Zm=9"), None, "padding inside");
    assert_eq!(decode(b"Zm9v\n"), None);
}
