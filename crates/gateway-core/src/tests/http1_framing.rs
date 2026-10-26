//! Executable checks of framing selection. The proofs cover every head; these
//! pin the smuggling refusals and the Content-Length edge cases.
use crate::headers::{Field, Rejection};
use crate::http1_framing::*;

fn field(name: &str, value: &str) -> Field { Field { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec(), sensitive: false } }

#[test]
fn selects_length_chunked_or_close() {
    assert_eq!(framing(&vec![field("content-length", "0")], true), Ok(Framing::Length(0)));
    assert_eq!(framing(&vec![field("content-length", "18446744073709551615")], false), Ok(Framing::Length(u64::MAX)));
    assert_eq!(framing(&vec![field("transfer-encoding", "chunked")], true), Ok(Framing::Chunked));
    assert_eq!(framing(&vec![field("transfer-encoding", "ChUnKeD")], false), Ok(Framing::Chunked));
    assert_eq!(framing(&vec![field("host", "h")], true), Ok(Framing::Length(0)));
    assert_eq!(framing(&vec![field("host", "h")], false), Ok(Framing::UntilClose));
}

#[test]
fn refuses_ambiguous_or_unsupported_framing() {
    let bad = Err(Rejection::BadRequest);
    // Both fields present: the smuggling ambiguity, refused whatever the values.
    assert_eq!(framing(&vec![field("content-length", "5"), field("transfer-encoding", "chunked")], true), bad);
    assert_eq!(framing(&vec![field("transfer-encoding", "chunked"), field("content-length", "0")], false), bad);
    // Repeated fields.
    assert_eq!(framing(&vec![field("content-length", "5"), field("content-length", "5")], true), bad);
    assert_eq!(framing(&vec![field("transfer-encoding", "chunked"), field("transfer-encoding", "chunked")], true), bad);
    // Codings other than chunked alone.
    for coding in ["gzip", "chunked, gzip", "gzip, chunked", "chunked;q=1", " chunked", "identity", ""] {
        assert_eq!(framing(&vec![field("transfer-encoding", coding)], false), bad, "{coding:?}");
    }
    // Content-Length that is not a canonical u64.
    for length in ["", "-1", "+5", "05", "00", "5 ", " 5", "5,5", "0x10", "18446744073709551616", "99999999999999999999", "1e3"] {
        assert_eq!(framing(&vec![field("content-length", length)], true), bad, "{length:?}");
    }
}

#[test]
fn parses_canonical_decimals_only() {
    assert_eq!(parse_decimal(b"0"), Some(0));
    assert_eq!(parse_decimal(b"7"), Some(7));
    assert_eq!(parse_decimal(b"1844674407370955161"), Some(1844674407370955161));
    assert_eq!(parse_decimal(b"18446744073709551615"), Some(u64::MAX));
    assert_eq!(parse_decimal(b"18446744073709551616"), None);
    assert_eq!(parse_decimal(b"184467440737095516150"), None);
    assert_eq!(parse_decimal(b"01"), None);
}
