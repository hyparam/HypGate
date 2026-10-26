//! Executable checks of the HTTP/1.1 head writers: exact bytes, and that what
//! is written parses back to the same head. The proofs cover every input.
use crate::headers::Field;
use crate::http1_head::*;
use crate::http1_write::*;

fn field(name: &str, value: &str) -> Field { Field { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec(), sensitive: false } }

#[test]
fn writes_a_request_head_byte_for_byte() {
    let mut out = b"prefix:".to_vec();
    write_request_head(b"POST", b"/v1/messages", &vec![field("host", "api.anthropic.com"), field("x-empty", "")], &mut out);
    assert_eq!(out, b"prefix:POST /v1/messages HTTP/1.1\r\nhost: api.anthropic.com\r\nx-empty: \r\n\r\n".to_vec());
}

#[test]
fn writes_a_status_head_with_and_without_a_reason() {
    let mut out = Vec::new();
    write_status_head(200, b"OK", &vec![field("content-type", "text/plain")], &mut out);
    assert_eq!(out, b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\n".to_vec());
    let mut out = Vec::new();
    write_status_head(503, b"", &vec![], &mut out);
    assert_eq!(out, b"HTTP/1.1 503 \r\n\r\n".to_vec());
    let mut out = Vec::new();
    write_status_head(100, b"Continue", &vec![], &mut out);
    assert_eq!(&out[..12], b"HTTP/1.1 100");
}

#[test]
fn written_heads_parse_back_to_the_same_heads() {
    let fields = vec![field("host", "h"), field("content-type", "application/json"), field("x-note", "a  b\tc"), field("x-empty", "")];
    let mut out = Vec::new();
    write_request_head(b"POST", b"/routes/7", &fields, &mut out);
    match parse_request(&out) {
        RequestProgress::Complete(head, len) => {
            assert_eq!(len, out.len());
            assert_eq!((head.method.as_slice(), head.target.as_slice()), (&b"POST"[..], &b"/routes/7"[..]));
            assert_eq!(head.fields.len(), fields.len());
            for (a, b) in head.fields.iter().zip(fields.iter()) { assert_eq!((&a.name, &a.value), (&b.name, &b.value)); }
        }
        _ => panic!("written request head did not parse"),
    }
    for status in [100u16, 200, 204, 304, 404, 599] {
        let mut out = Vec::new();
        write_status_head(status, b"Reason Phrase", &fields, &mut out);
        match parse_status(&out) {
            StatusProgress::Complete(head, len) => { assert_eq!((head.status, len, head.fields.len()), (status, out.len(), fields.len())); }
            _ => panic!("written status head did not parse"),
        }
    }
}

#[test]
fn wire_check_rejects_what_the_writers_may_not_be_given() {
    assert!(wire_ok(&vec![field("host", "h"), field("x-empty", ""), field("x-obs", "caf\u{e9}")]));
    for bad in [
        field("", "v"),            // empty name
        field("Host", "v"),        // uppercase name
        field("ho st", "v"),       // blank in name
        field("host", " v"),       // leading blank
        field("host", "v "),       // trailing blank
        field("host", "v\r\nx: y"), // line break
        field("host", "v\u{0}"),   // control byte
    ] {
        assert!(!wire_ok(&vec![field("ok", "v"), bad]));
    }
}
