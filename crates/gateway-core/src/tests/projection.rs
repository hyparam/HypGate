//! Executable checks of the projection's small decisions. The rows
//! themselves are pinned by the runtime's shipping tests against provider
//! bodies read back through serde_json.
use crate::json::Value;
use crate::projection::*;

fn s(v: Value) -> String { match v { Value::Str(b) => String::from_utf8(b).unwrap(), other => panic!("{other:?}") } }

#[test]
fn recognizes_complete_events_by_grammar() {
    for prefix in ["", "id: 7\n", "retry: 1000\n", "unknown: value\n", ": comment\n", "\u{feff}"] {
        assert!(is_sse(format!("{prefix}data: {{}}\n\n").as_bytes()));
    }
    for not in [&b""[..], b"{}", b": comment\n", b"data: {}\n", b"event: error\n\n"] {
        assert!(!is_sse(not));
    }
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

fn response(body: &[u8]) -> Value { response_capped(body, 1 << 20) }

fn response_capped(body: &[u8], max_text: usize) -> Value {
    use crate::{exchange_assembler::Assembler, framing::Header, metadata::*};
    let mut assembler = Assembler::new(4, 1 << 20);
    let start = encode_request_start(1_700_000_000_000, 7, b"https://api.openai.com/v1/chat/completions").unwrap();
    assembler.admit(Header { payload: start.len() as u32, tenant: 3, request: 42, chunk: 0, kind: 2 }, &start);
    assembler.admit(Header { payload: body.len() as u32, tenant: 3, request: 42, chunk: 1, kind: 1 }, body);
    let done = encode_completion(1_700_000_000_900, 0, 0, 1).unwrap();
    let exchange = assembler.admit(Header { payload: done.len() as u32, tenant: 3, request: 42, chunk: 0, kind: 4 }, &done).unwrap();
    rows(&[5; 16], &exchange, max_text).pop().unwrap()
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

#[test]
fn every_sse_prefix_and_line_ending_reaches_projection() {
    let event = "data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1}}\n\n";
    for prefix in ["", "id: 7\n", "retry: 1000\n", "unknown: ignored\n", ": comment\n", "event: message\n", "data: invalid json\n\n", "data: [DONE]\n\n"] {
        for newline in ["\n", "\r\n", "\r"] {
            for bom in ["", "\u{feff}"] {
                let body = format!("{bom}{prefix}{event}").replace('\n', newline);
                let row = response(body.as_bytes());
                assert_eq!(row.get(b"content_text").unwrap().as_str().unwrap(), b"Hello", "{body:?}");
                let usage = row.get(b"attributes").unwrap().get(b"usage").unwrap();
                assert_eq!(usage.get(b"total_tokens").unwrap().as_u64(), Some(3));
            }
        }
    }
}

fn error(row: &Value) -> bool { matches!(row.get(b"is_error"), Some(Value::Bool(true))) }

#[test]
fn provider_failures_survive_every_event_position_and_later_success() {
    let failures = [
        r#"{"type":"error","error":{"type":"overloaded_error"}}"#,
        r#"{"error":{"code":"server_error"}}"#,
        r#"{"type":"response.failed","response":{"status":"failed"}}"#,
        r#"{"type":"response.incomplete","response":{"status":"incomplete"}}"#,
        r#"{"response":{"error":{"message":"failure"}}}"#,
        r#"{"status":"failed"}"#, r#"{"status":"incomplete"}"#, r#"{"status":"cancelled"}"#,
    ];
    let others = ["{}", "null", "not json", "[DONE]", r#"{"type":"future.event"}"#,
        r#"{"type":"response.completed","response":{"status":"completed","error":null}}"#];
    for failure in failures {
        assert!(error(&response(failure.as_bytes())), "JSON {failure}");
        for other in others {
            for (a, b) in [(failure, other), (other, failure)] {
                let body = format!("id: 7\ndata: {a}\n\ndata: {b}\n\n");
                assert!(error(&response(body.as_bytes())), "SSE {body}");
            }
        }
    }
    for other in others {
        assert!(!error(&response(other.as_bytes())), "JSON {other}");
        assert!(!error(&response(format!("data: {other}\n\n").as_bytes())), "SSE {other}");
    }
}

#[test]
fn incomplete_event_is_not_interpreted_and_json_strings_are_not_events() {
    assert!(!error(&response(b"data: {\"type\":\"error\"}\n")));
    assert!(!error(&response(br#"{"content":"data: {\"type\":\"error\"}\n\n","error":null}"#)));
}

#[test]
fn chat_alternatives_keep_their_own_fragment_order() {
    // Valid provider chunks: alternatives may appear in arbitrary event order,
    // and array order need not agree with the choice index.
    let events = [
        r#"{"choices":[{"index":9,"delta":{"content":"He"}},{"index":2,"delta":{"content":"Wo"}}]}"#,
        r#"{"choices":[{"index":2,"delta":{"content":"rld"}},{"index":9,"delta":{"content":"llo"}}]}"#,
        r#"{"choices":[],"usage":{"prompt_tokens":2,"completion_tokens":2}}"#,
    ];
    let body = events.iter().map(|v| format!("data: {v}\n\n")).collect::<String>();
    let row = response(body.as_bytes());
    assert_eq!(row.get(b"content_text").unwrap().as_str().unwrap(), b"Hello\nWorld");
    let usage = row.get(b"attributes").unwrap().get(b"usage").unwrap();
    assert_eq!(usage.get(b"output_tokens").unwrap().as_u64(), Some(2));
}

#[test]
fn choice_isolation_handles_sparse_indexes_unknown_events_and_incomplete_tails() {
    let body = concat!(
        "data: {\"choices\":[{\"index\":18446744073709551615,\"delta\":{\"content\":\"A\"}}]}\n\n",
        "data: not json\n\n",
        "data: {\"choices\":[{\"index\":-1,\"delta\":{\"content\":\"bad\"}},{\"index\":\"x\",\"delta\":{\"content\":\"bad\"}}]}\n\n",
        "data: {\"type\":\"future.event\"}\n\n",
        "data: {\"choices\":[{\"delta\":{\"content\":\"B\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":18446744073709551615,\"delta\":{\"content\":\"C\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"unfinished\"}}]}\n",
    );
    let row = response(body.as_bytes());
    assert_eq!(row.get(b"content_text").unwrap().as_str().unwrap(), b"AC\nB");
}

#[test]
fn anthropic_start_usage_survives_every_interruption_prefix() {
    let start = r#"{"type":"message_start","message":{"model":"claude","usage":{"input_tokens":10,"cache_read_input_tokens":20,"cache_creation_input_tokens":30,"output_tokens":1}}}"#;
    for tail in ["", "data: malformed\n\n", "data: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":null}\n\n", "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n"] {
        let row = response(format!("data: {start}\n\n{tail}").as_bytes());
        let usage = row.get(b"attributes").unwrap().get(b"usage").unwrap();
        for (key, expected) in [("input_tokens", 10), ("cache_read_tokens", 20), ("cache_write_tokens", 30), ("output_tokens", 1), ("total_tokens", 61)] {
            assert_eq!(usage.get(key.as_bytes()).unwrap().as_u64(), Some(expected), "{tail:?} {key}");
        }
    }
    for output in [0, 5, u64::MAX] {
        let row = response(format!("data: {start}\n\ndata: {{\"type\":\"message_delta\",\"usage\":{{\"output_tokens\":{output}}}}}\n\n").as_bytes());
        let usage = row.get(b"attributes").unwrap().get(b"usage").unwrap();
        assert_eq!(usage.get(b"input_tokens").unwrap().as_u64(), Some(10));
        assert_eq!(usage.get(b"cache_read_tokens").unwrap().as_u64(), Some(20));
        assert_eq!(usage.get(b"cache_write_tokens").unwrap().as_u64(), Some(30));
        assert_eq!(usage.get(b"output_tokens").unwrap().as_u64(), Some(output));
        assert_eq!(usage.get(b"total_tokens").unwrap().as_u64(), Some(60_u64.saturating_add(output)));
    }
}

#[test]
fn grouped_choices_reach_serialization_with_utf8_capping() {
    let body = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"é\"}},{\"index\":1,\"delta\":{\"content\":\"世界\"}}]}\n\n";
    for (cap, expected) in [(0, ""), (1, ""), (2, "é"), (3, "é\n"), (4, "é\n"), (6, "é\n世"), (9, "é\n世界")] {
        let row = response_capped(body.as_bytes(), cap);
        assert_eq!(row.get(b"content_text").unwrap().as_str().unwrap(), expected.as_bytes());
    }
}
