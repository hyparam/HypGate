//! Executable checks of the HTTP/1.1 head parser on a corpus of valid and
//! malformed heads. The proofs cover every input; these pin concrete cases
//! and the shape of the output.
use crate::headers::Rejection;
use crate::http1_head::*;

fn request(bytes: &[u8]) -> RequestProgress { parse_request(bytes) }
fn status(bytes: &[u8]) -> StatusProgress { parse_status(bytes) }

fn complete_request(bytes: &[u8]) -> (RequestHead, usize) {
    match request(bytes) { RequestProgress::Complete(head, len) => (head, len), _ => panic!("expected a complete head") }
}
fn complete_status(bytes: &[u8]) -> (StatusHead, usize) {
    match status(bytes) { StatusProgress::Complete(head, len) => (head, len), _ => panic!("expected a complete head") }
}
fn rejected_request(bytes: &[u8]) -> Rejection {
    match request(bytes) { RequestProgress::Rejected(why) => why, _ => panic!("expected a rejection") }
}
fn incomplete_request(bytes: &[u8]) -> bool { matches!(request(bytes), RequestProgress::Incomplete) }

#[test]
fn parses_a_request_head_and_reports_the_bytes_consumed() {
    let bytes = b"POST /routes/7 HTTP/1.1\r\nHost: localhost\r\nContent-Type:  application/json \r\nX-Empty:\r\n\r\n{\"body\":1}";
    let (head, len) = complete_request(bytes);
    assert_eq!(&bytes[len..], b"{\"body\":1}");
    assert_eq!(head.method, b"POST");
    assert_eq!(head.target, b"/routes/7");
    let fields: Vec<(&[u8], &[u8])> = head.fields.iter().map(|f| (f.name.as_slice(), f.value.as_slice())).collect();
    assert_eq!(fields, vec![(&b"host"[..], &b"localhost"[..]), (b"content-type", b"application/json"), (b"x-empty", b"")]);
    assert!(head.fields.iter().all(|f| !f.sensitive));
}

#[test]
fn lowercases_names_and_keeps_values_byte_for_byte() {
    let (head, _) = complete_request(b"GET / HTTP/1.1\r\nAnThRoPiC-VeRsIoN:\t2023-06-01\t\r\nAuthorization: Bearer AbC.dEf \r\n\r\n");
    assert_eq!(head.fields[0].name, b"anthropic-version");
    assert_eq!(head.fields[0].value, b"2023-06-01");
    assert_eq!(head.fields[1].value, b"Bearer AbC.dEf");
}

#[test]
fn reports_incomplete_until_the_empty_line_arrives() {
    let full = b"POST /routes/1 HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n";
    for cut in 0..full.len() {
        assert!(incomplete_request(&full[..cut]), "cut at {cut}");
    }
    assert!(matches!(request(full), RequestProgress::Complete(_, len) if len == full.len()));
}

#[test]
fn rejects_malformed_start_lines() {
    for bad in [
        &b"POST /routes/1 HTTP/1.0\r\n\r\n"[..],            // wrong version
        b"POST /routes/1 HTTP/1.1 \r\n\r\n",                 // trailing blank
        b"POST  /routes/1 HTTP/1.1\r\n\r\n",                 // double space
        b" POST /routes/1 HTTP/1.1\r\n\r\n",                 // leading space
        b"POST routes/1 HTTP/1.1\r\n\r\n",                   // not origin-form
        b"POST http://h/routes/1 HTTP/1.1\r\n\r\n",          // absolute-form
        b"POST /rou tes HTTP/1.1\r\n\r\n",                   // blank in target
        b"PO ST /x HTTP/1.1\r\n\r\n",                        // blank in method
        b"P\x7fST /x HTTP/1.1\r\n\r\n",                      // control in method
        b"POST /x\x01 HTTP/1.1\r\n\r\n",                     // control in target
        b"POST /x HTTP/1.1\n\r\n",                           // bare LF
        b"POST /x HTTP/1.1\r\r\n",                           // bare CR
        b"\r\n\r\n",                                         // empty start line
    ] {
        assert_eq!(rejected_request(bad), Rejection::BadRequest, "{:?}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn rejects_malformed_field_lines() {
    for bad in [
        &b"GET / HTTP/1.1\r\nHost localhost\r\n\r\n"[..],     // no colon
        b"GET / HTTP/1.1\r\n: value\r\n\r\n",                 // empty name
        b"GET / HTTP/1.1\r\nHo st: a\r\n\r\n",                // blank in name
        b"GET / HTTP/1.1\r\nHost : a\r\n\r\n",                // blank before colon
        b"GET / HTTP/1.1\r\nHost: a\r\n b\r\n\r\n",           // obsolete folding
        b"GET / HTTP/1.1\r\nHost: a\x00b\r\n\r\n",            // NUL in value
        b"GET / HTTP/1.1\r\nHost: a\x7f\r\n\r\n",             // DEL in value
        b"GET / HTTP/1.1\r\nHost: a\rb\r\n\r\n",              // bare CR in value
        b"GET / HTTP/1.1\r\nHost: a\nb\r\n\r\n",              // bare LF in value
        b"GET / HTTP/1.1\r\nHost: a\r\n\n",                   // bare LF as terminator
    ] {
        assert_eq!(rejected_request(bad), Rejection::BadRequest, "{:?}", String::from_utf8_lossy(bad));
    }
}

#[test]
fn accepts_obs_text_and_internal_blanks_in_values() {
    let (head, _) = complete_request(b"GET / HTTP/1.1\r\nX-Note: caf\xc3\xa9  au  lait\r\n\r\n");
    assert_eq!(head.fields[0].value, "café  au  lait".as_bytes());
}

#[test]
fn enforces_the_field_count_and_byte_limits() {
    let mut many = b"GET / HTTP/1.1\r\n".to_vec();
    for i in 0..100 { many.extend_from_slice(format!("X-{i}: v\r\n").as_bytes()); }
    let mut ok = many.clone(); ok.extend_from_slice(b"\r\n");
    let (head, len) = complete_request(&ok);
    assert_eq!((head.fields.len(), len), (100, ok.len()));
    let mut over = many; over.extend_from_slice(b"X-100: v\r\n\r\n");
    assert_eq!(rejected_request(&over), Rejection::TooLarge);

    let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
    big.resize(32768 - 4, b'a'); big.extend_from_slice(b"\r\n\r\n");
    assert_eq!(big.len(), 32768);
    assert!(matches!(request(&big), RequestProgress::Complete(_, 32768)));
    let mut bigger = b"GET / HTTP/1.1\r\nX: ".to_vec();
    bigger.resize(32768 - 3, b'a'); bigger.extend_from_slice(b"\r\n\r\n");
    assert_eq!(rejected_request(&bigger), Rejection::TooLarge);
    // A head that has not ended by the limit is too large, not incomplete.
    let unterminated = vec![b'a'; 32768];
    assert_eq!(rejected_request(&unterminated), Rejection::TooLarge);
    assert!(incomplete_request(&vec![b'a'; 32767]));
}

#[test]
fn parses_status_heads_with_and_without_a_reason() {
    let (head, len) = complete_status(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata");
    assert_eq!((head.status, len), (200, 52));
    assert_eq!(head.fields[0].value, b"text/event-stream");
    let (head, _) = complete_status(b"HTTP/1.1 503\r\n\r\n");
    assert_eq!(head.status, 503);
    let (head, _) = complete_status(b"HTTP/1.1 429 Too Many Requests \r\n\r\n");
    assert_eq!(head.status, 429);
    for bad in [
        &b"HTTP/1.0 200 OK\r\n\r\n"[..], b"HTTP/1.1 200OK\r\n\r\n", b"HTTP/1.1 20 OK\r\n\r\n", b"HTTP/1.1 2000 OK\r\n\r\n",
        b"HTTP/1.1 099 Early\r\n\r\n", b"HTTP/1.1 600 Odd\r\n\r\n", b"HTTP/1.1  200 OK\r\n\r\n", b"HTTP/1.1 200 O\x00K\r\n\r\n",
    ] {
        assert!(matches!(status(bad), StatusProgress::Rejected(Rejection::BadRequest)), "{:?}", String::from_utf8_lossy(bad));
    }
    assert!(matches!(status(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"), StatusProgress::Incomplete));
}
