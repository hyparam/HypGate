//! Executable checks of the projection's small decisions. The rows
//! themselves are pinned by the runtime's shipping tests against provider
//! bodies read back through serde_json.
use crate::json::Value;
use crate::projection::*;

fn s(v: Value) -> String { match v { Value::Str(b) => String::from_utf8(b).unwrap(), other => panic!("{other:?}") } }

#[test]
fn recognizes_event_streams() {
    for sse in [&b"event: message_start\ndata: {}\n"[..], b"data: {}\n", b": comment\n", b"  \r\n\tdata: x"] { assert!(is_sse(sse)); }
    for not in [&b""[..], b"{}", b"{\"data\":1}", b" {\"event\":1}", b"dat"] { assert!(!is_sse(not)); }
}

#[test]
fn names_providers_and_outcomes() {
    assert_eq!(s(provider(b"api.anthropic.com")), "anthropic");
    assert_eq!(s(provider(b"api.openai.com")), "openai");
    assert_eq!(s(provider(b"models.example")), "models.example");
    assert_eq!(s(provider(b"bad\xffhost")), "bad\u{fffd}host");
    let names: Vec<String> = (0..8).map(|c| s(outcome_name(c))).collect();
    assert_eq!(names, ["success", "upstream_failure", "upstream_timeout", "upload_failure", "download_failure", "client_disconnect", "log_refusal", "other"]);
    assert_eq!(s(outcome_name(200)), "other");
}

fn response(body: &[u8]) -> Value {
    use crate::{exchange_assembler::Assembler, framing::Header, metadata::*};
    let mut assembler = Assembler::new(4, 1 << 20);
    let start = encode_request_start(1_700_000_000_000, 7, b"https://api.openai.com/v1/chat/completions").unwrap();
    assembler.admit(Header { payload: start.len() as u32, tenant: 3, request: 42, chunk: 0, kind: 2 }, &start);
    assembler.admit(Header { payload: body.len() as u32, tenant: 3, request: 42, chunk: 1, kind: 1 }, body);
    let done = encode_completion(1_700_000_000_900, 0, 0, 1).unwrap();
    let exchange = assembler.admit(Header { payload: done.len() as u32, tenant: 3, request: 42, chunk: 0, kind: 4 }, &done).unwrap();
    rows(&[5; 16], &exchange, 1 << 20).pop().unwrap()
}

#[test]
fn multiline_sse_projects_text_before_usage() {
    for newline in ["\n", "\r\n", "\r"] {
        let body = "data: {\"choices\":\ndata: [{\"delta\":{\"content\":\"Hello\"}}]}\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1}}\n\n".replace('\n', newline);
        let row = response(body.as_bytes());
        assert_eq!(row.get(b"content_text").unwrap().as_str().unwrap(), b"Hello");
        assert_eq!(row.get(b"attributes").unwrap().get(b"usage").unwrap().get(b"total_tokens").unwrap().as_u64(), Some(3));
    }
}

#[test]
fn null_usage_is_unknown_and_does_not_erase_known_usage() {
    let chunk = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}],\"usage\":null}\n\n";
    let row = response(chunk.as_bytes());
    assert!(row.get(b"attributes").unwrap().get(b"usage").is_none());
    let known = "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1}}\n\n";
    let row = response(format!("{known}{chunk}data: [DONE]\n\n").as_bytes());
    assert_eq!(row.get(b"attributes").unwrap().get(b"usage").unwrap().get(b"total_tokens").unwrap().as_u64(), Some(3));
    for value in ["null", "false", "0", "\"unknown\"", "[]"] {
        let row = response(format!("{{\"content\":\"Hello\",\"usage\":{value}}}").as_bytes());
        assert!(row.get(b"attributes").unwrap().get(b"usage").is_none(), "{value}");
    }
    let row = response(br#"{"content":"Hello","usage":{"input_tokens":0,"output_tokens":0}}"#);
    assert_eq!(row.get(b"attributes").unwrap().get(b"usage").unwrap().get(b"total_tokens").unwrap().as_u64(), Some(0));
}

#[test]
fn sse_dispatches_only_complete_events_with_exact_data_spacing() {
    let input = b":comment\r\nid: 7\r\ndata: one\r\n: ignored\r\ndata:  two\r\ndata\r\n\r\n\r\ndata:\n\ndata: unfinished\n";
    let mut reader = crate::sse::Reader::new(input);
    assert_eq!(reader.next(), Some(b"one\n two\n".to_vec()));
    assert_eq!(reader.next(), Some(Vec::new()));
    assert_eq!(reader.next(), None);
    assert_eq!(reader.next(), None);
}
