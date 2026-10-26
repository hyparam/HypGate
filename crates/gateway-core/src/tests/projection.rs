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
