//! Executable checks of the exchange machines: the decision tables and the
//! sequences a connection and an upstream request may take. The proofs cover
//! every input; these pin concrete bytes and refusals.
use crate::exchange_lifecycle::Fault;
use crate::headers::Field;
use crate::http1_exchange::*;
use crate::http1_framing::Framing;
use crate::http1_head::{RequestProgress, StatusProgress, parse_request, parse_status};

fn field(name: &str, value: &str) -> Field { Field { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec(), sensitive: false } }

#[test]
fn statuses_come_from_the_tables() {
    assert_eq!(refusal_status(Refusal::HeadTooLarge), 431);
    assert_eq!(refusal_status(Refusal::Malformed), 400);
    assert_eq!(refusal_status(Refusal::Unauthorized), 401);
    assert_eq!(refusal_status(Refusal::MethodNotAllowed), 405);
    assert_eq!(refusal_status(Refusal::Unavailable), 503);
    assert_eq!(failure_status(Fault::Timeout), 504);
    for fault in [Fault::Connect, Fault::Tls, Fault::Http, Fault::Upload, Fault::Download, Fault::Log, Fault::Metadata, Fault::Client] {
        assert_eq!(failure_status(fault), 502, "{fault:?}");
    }
}

#[test]
fn continue_is_wanted_only_for_an_expect_field_saying_so() {
    assert!(wants_continue(&vec![field("host", "h"), field("expect", "100-continue")]));
    assert!(wants_continue(&vec![field("expect", "100-CONTINUE")]));
    assert!(!wants_continue(&vec![field("expect", "100-continue, other")]));
    assert!(!wants_continue(&vec![field("x-expect", "100-continue")]));
    assert!(!wants_continue(&vec![]));
}

#[test]
fn upstream_statuses_are_classified() {
    assert_eq!(upstream_status(100, &vec![]), UpstreamStatus::Interim);
    assert_eq!(upstream_status(103, &vec![field("link", "x")]), UpstreamStatus::Interim);
    assert_eq!(upstream_status(101, &vec![]), UpstreamStatus::Refused);
    assert_eq!(upstream_status(204, &vec![field("content-length", "5")]), UpstreamStatus::Bodiless);
    assert_eq!(upstream_status(304, &vec![]), UpstreamStatus::Bodiless);
    assert_eq!(upstream_status(200, &vec![field("content-length", "5")]), UpstreamStatus::Framed(Framing::Length(5)));
    assert_eq!(upstream_status(429, &vec![field("transfer-encoding", "chunked")]), UpstreamStatus::Framed(Framing::Chunked));
    assert_eq!(upstream_status(502, &vec![]), UpstreamStatus::Framed(Framing::UntilClose));
    assert_eq!(upstream_status(200, &vec![field("content-length", "5"), field("transfer-encoding", "chunked")]), UpstreamStatus::Refused);
    assert_eq!(upstream_status(200, &vec![field("transfer-encoding", "gzip")]), UpstreamStatus::Refused);
}

#[test]
fn a_connection_answers_once_with_close_and_matching_framing() {
    let mut connection = Connection::new();
    let interim = connection.interim_continue().unwrap();
    assert_eq!(interim, b"HTTP/1.1 100 Continue\r\n\r\n".to_vec());
    assert!(connection.interim_continue().is_none(), "the interim response is sent once");
    let bytes = connection.respond_fixed(200, b"OK", vec![field("content-type", "text/plain")], b"ok\n").unwrap();
    assert_eq!(bytes, b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\ncontent-length: 3\r\n\r\nok\n".to_vec());
    assert!(connection.respond_fixed(200, b"OK", vec![], b"").is_none(), "a second response is refused");
    assert!(connection.respond_stream(200, b"OK", vec![]).is_none());
    assert!(connection.interim_continue().is_none(), "no interim after the head");
    // The head parses back as what was meant.
    match parse_status(&bytes) {
        StatusProgress::Complete(head, len) => {
            assert_eq!((head.status, &bytes[len..]), (200, &b"ok\n"[..]));
            let names: Vec<&[u8]> = head.fields.iter().map(|f| f.name.as_slice()).collect();
            assert_eq!(names, vec![&b"content-type"[..], b"connection", b"content-length"]);
        }
        _ => panic!("head did not parse"),
    }
}

#[test]
fn fixed_responses_refuse_bad_statuses_bodies_and_fields() {
    for (status, body) in [(199u16, &b""[..]), (600, b""), (100, b""), (204, b"x"), (304, b"x")] {
        let mut connection = Connection::new();
        assert!(connection.respond_fixed(status, b"", vec![], body).is_none(), "{status}");
        assert!(connection.is_open(), "a refused response leaves the connection open");
    }
    let mut connection = Connection::new();
    assert!(connection.respond_fixed(200, b"OK", vec![field("x", "a\r\nb")], b"").is_none(), "no line break in a value");
    assert!(connection.respond_fixed(200, b"O\x00K", vec![], b"").is_none(), "no control byte in a reason");
    assert!(connection.respond_fixed(204, b"No Content", vec![], b"").is_some(), "204 with no body is fine");
}

#[test]
fn a_stream_ends_cleanly_only_through_the_last_chunk() {
    let mut connection = Connection::new();
    assert!(connection.respond_stream(204, b"", vec![]).is_none(), "204 never streams");
    let (head, mut stream) = connection.respond_stream(200, b"OK", vec![field("content-type", "text/event-stream")]).unwrap();
    assert_eq!(head, b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n".to_vec());
    let mut wire = head.clone();
    wire.extend(stream.frame(b"data: hello\n\n"));
    wire.extend(stream.frame(b"data: [DONE]\n\n"));
    assert!(!stream.is_ended());
    wire.extend(stream.end());
    assert!(stream.is_ended());
    connection.finish(stream);
    assert_eq!(&wire[head.len()..], &b"d\r\ndata: hello\n\n\r\ne\r\ndata: [DONE]\n\n\r\n0\r\n\r\n"[..]);
    // An aborted connection adds nothing.
    let mut aborted = Connection::new();
    let (_, mut stream) = aborted.respond_stream(200, b"OK", vec![]).unwrap();
    let _ = stream.frame(b"partial");
    aborted.abort();
    assert!(!stream.is_ended());
}

#[test]
fn an_upstream_request_carries_chunked_framing_and_close() {
    let mut upstream = Upstream::new();
    let (head, mut stream) = upstream.request(b"/v1/messages", vec![field("host", "api.anthropic.com"), field("x-api-key", "k")]).unwrap();
    assert_eq!(head, b"POST /v1/messages HTTP/1.1\r\nhost: api.anthropic.com\r\nx-api-key: k\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n".to_vec());
    assert!(upstream.request(b"/again", vec![]).is_none(), "one request per connection");
    let mut wire = head.clone();
    wire.extend(stream.frame(b"{\"a\":1}"));
    wire.extend(stream.end());
    upstream.finish(stream);
    match parse_request(&head) {
        RequestProgress::Complete(parsed, len) => {
            assert_eq!((parsed.method.as_slice(), parsed.target.as_slice(), len), (&b"POST"[..], &b"/v1/messages"[..], head.len()));
            assert_eq!(parsed.fields.len(), 4);
        }
        _ => panic!("request head did not parse"),
    }
    let mut bad = Upstream::new();
    assert!(bad.request(b"v1/messages", vec![]).is_none(), "origin-form only");
    assert!(bad.request(b"/v1/mes sages", vec![]).is_none(), "no blank in a target");
    assert!(bad.request(b"/ok", vec![field("Host", "h")]).is_none(), "names are lowercase");
}

#[test]
fn decimal_bytes_spell_canonical_numbers() {
    assert_eq!(decimal_bytes(0), b"0".to_vec());
    assert_eq!(decimal_bytes(7), b"7".to_vec());
    assert_eq!(decimal_bytes(1024), b"1024".to_vec());
    assert_eq!(decimal_bytes(u64::MAX), b"18446744073709551615".to_vec());
}
