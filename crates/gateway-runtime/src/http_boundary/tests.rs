use super::*;
use crate::config::{MAX_CREDENTIAL_BYTES, MAX_DESTINATION_BYTES};
use crate::test_support::http::{field, has, value_of};
use serde_json::json;
use sha2::{Digest, Sha256};

fn config() -> GatewayConfig {
    let routes = json!([
        {"tenant":1,"selector":7,"origin":0,"credential":0},
        {"tenant":1,"selector":8,"origin":1,"credential":1}
    ]);
    let root = json!({
        "identities":[{"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"gateway-token"))}],
        "destinations":["https://api.openai.com:8443/v1/responses","https://api.anthropic.com/v1/messages"],
        "credentials":[{"tenant":1,"kind":"bearer","env":"OPENAI"},
                       {"tenant":1,"kind":"api_key","env":"ANTHROPIC"}],
        "grants":routes,"limits":{"requests":1,"chunk_bytes":4096},"logging":"strict"
    });
    GatewayConfig::from_json(&serde_json::to_vec(&root).unwrap(),
        &serde_json::to_vec(&json!({"routes":routes})).unwrap(), |name| Some(format!("secret-{name}"))).unwrap()
}
fn headers() -> Vec<Field> {
    vec![field("authorization", "Bearer gateway-token"), field("content-type", "application/json"), field("accept", "text/event-stream")]
}
fn head(method: &str, target: &str, fields: Vec<Field>) -> RequestHead {
    RequestHead { method: method.as_bytes().to_vec(), target: target.as_bytes().to_vec(), fields }
}
fn copy(h: &[Field]) -> Vec<Field> {
    h.iter().map(|f| Field { name: f.name.clone(), value: f.value.clone(), sensitive: f.sensitive }).collect()
}
fn prep<'a>(c: &'a GatewayConfig, h: &[Field], path: &str) -> Result<PreparedRequest<'a>, HttpError> {
    prepare(c, &head("POST", path, copy(h)))
}
fn set(h: &mut Vec<Field>, name: &str, value: &str) {
    h.retain(|f| f.name != name.as_bytes());
    h.push(field(name, value));
}
fn out<'a>(p: &'a PreparedRequest<'_>, name: &str) -> Option<&'a str> {
    value_of(p.upstream_fields(), name).map(|v| std::str::from_utf8(v).unwrap())
}

#[test]
fn fixed_destination_and_credentials_replace_host_and_client_secrets() {
    let c = config(); let mut h = headers();
    for name in ["host", "x-api-key", "proxy-authorization", "cookie", "forwarded", "x-forwarded-host",
        "x-upstream-url", "content-length", "transfer-encoding", "accept-encoding"] {
        set(&mut h, name, "attacker");
    }
    let p = prep(&c, &h, "/routes/7").unwrap();
    assert_eq!(p.destination_text(), "https://api.openai.com:8443/v1/responses");
    assert_eq!(out(&p, "host"), Some("api.openai.com:8443"));
    assert_eq!(out(&p, "authorization"), Some("Bearer secret-OPENAI"));
    assert!(p.upstream_fields().iter().find(|f| f.name == b"authorization").unwrap().sensitive);
    assert_eq!(out(&p, "accept-encoding"), Some("identity"));
    assert_eq!(out(&p, "content-type"), Some("application/json"));
    assert_eq!(p.upstream_fields().len(), 5);
    assert!(!p.upstream_fields().iter().any(|f| f.value == b"Bearer gateway-token"));
    drop(p);
    set(&mut h, "anthropic-version", "2023-06-01");
    set(&mut h, "anthropic-beta", "some-beta");
    let p = prep(&c, &h, "/routes/8").unwrap();
    assert_eq!(out(&p, "x-api-key"), Some("secret-ANTHROPIC"));
    assert!(!has(p.upstream_fields(), "authorization"));
    assert_eq!(out(&p, "anthropic-version"), Some("2023-06-01"));
}

#[test]
fn malformed_authentication_never_issues_a_prepared_request() {
    let c = config();
    for value in ["", "Basic gateway-token", "Bearer", "Bearer ", "Bearer  gateway-token",
        "Bearer gateway-token,other", "Bearer wrong", "Bearer gateway-token\t"] {
        let mut h = headers(); set(&mut h, "authorization", value);
        assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::Unauthorized)), "{value:?}");
    }
    let mut h = headers(); h.push(field("authorization", "Bearer gateway-token"));
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::Unauthorized)));
    h.retain(|f| f.name != b"authorization");
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::Unauthorized)));
    set(&mut h, "authorization", "bEaReR gateway-token");
    assert!(prep(&c, &h, "/routes/7").is_ok());
}

#[test]
fn caller_cannot_select_an_arbitrary_url_path_or_method() {
    let c = config(); let h = headers();
    for path in ["https://attacker.example/routes/7", "/routes/7?url=attacker", "/routes/07",
        "/routes/%37", "/routes/7/other", "/routes/+7", "/routes/", "/routes/18446744073709551616"] {
        assert!(matches!(prep(&c, &h, path), Err(HttpError::BadRequest)), "{path}");
    }
    for method in ["GET", "CONNECT", "PUT", "post"] {
        assert!(matches!(prepare(&c, &head(method, "/routes/7", copy(&h))), Err(HttpError::MethodNotAllowed)));
    }
    assert!(matches!(prep(&c, &h, "/routes/999"), Err(HttpError::Unauthorized)));
    assert!(prep(&c, &h, "/routes/7").is_ok());
}

#[test]
fn connection_nominations_are_stripped_but_cannot_suppress_root_credentials() {
    let c = config(); let mut h = headers();
    set(&mut h, "connection", "Accept, Authorization, Host");
    let p = prep(&c, &h, "/routes/7").unwrap();
    assert!(!has(p.upstream_fields(), "accept"));
    assert!(!has(p.upstream_fields(), "connection"));
    assert_eq!(out(&p, "authorization"), Some("Bearer secret-OPENAI"));
    assert_eq!(out(&p, "host"), Some("api.openai.com:8443"));
    drop(p);
    set(&mut h, "connection", "accept,,host");
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::BadRequest)));
}

#[test]
fn invalid_and_oversized_headers_do_not_leak_admission_slots() {
    let c = config();
    for name in ["content-encoding", "upgrade", "trailer"] {
        let mut h = headers(); set(&mut h, name, "value");
        assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::BadRequest)));
    }
    let mut h = headers(); h.push(field("content-type", "text/plain"));
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::BadRequest)));
    let mut h = headers(); h.push(Field { name: b"large".to_vec(), value: vec![b'x'; MAX_HEADER_BYTES], sensitive: false });
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::HeadersTooLarge)));
    let mut h = headers();
    for _ in 0..MAX_HEADER_VALUES { h.push(field("many", "x")); }
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::HeadersTooLarge)));
    let p = prep(&c, &headers(), "/routes/7").unwrap();
    assert!(matches!(prep(&c, &headers(), "/routes/7"), Err(HttpError::Unavailable)));
    drop(p);
    assert!(prep(&c, &headers(), "/routes/7").is_ok());
}

#[test]
fn upstream_response_cannot_forward_credentials_cookies_or_redirect_location() {
    let mut h = Vec::new();
    for name in ["authorization", "x-api-key", "set-cookie", "location", "content-length", "transfer-encoding"] {
        h.push(field(name, "untrusted"));
    }
    h.push(field("content-type", "text/event-stream"));
    h.push(field("content-encoding", "gzip"));
    h.push(field("x-request-id", "request-42"));
    h.push(field("connection", "X-Request-Id"));
    let out = response_fields(&h).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(value_of(&out, "content-type"), Some(&b"text/event-stream"[..]));
    assert_eq!(value_of(&out, "content-encoding"), Some(&b"gzip"[..]));
    set(&mut h, "connection", "Content-Encoding");
    assert!(response_fields(&h).is_err());
}

#[test]
fn prepared_request_keeps_values_byte_for_byte_and_sensitivity() {
    let c = config();
    let mut h = headers();
    h.push(Field { name: b"openai-beta".to_vec(), value: b"opaque-\x80-value".to_vec(), sensitive: true });
    let prepared = prepare(&c, &head("POST", "/routes/7", h)).unwrap();
    let beta = prepared.upstream_fields().iter().find(|f| f.name == b"openai-beta").unwrap();
    assert_eq!(beta.value, b"opaque-\x80-value");
    assert!(beta.sensitive);
    assert_eq!(out(&prepared, "authorization"), Some("Bearer secret-OPENAI"));
}

#[test]
fn prepared_response_keeps_status_and_repeated_fields_in_order() {
    let fields = vec![
        Field { name: b"request-id".to_vec(), value: b"opaque-\xff-id".to_vec(), sensitive: true },
        field("request-id", "second"),
    ];
    // The status is the driver's to keep; the fields pass through the verified projection.
    let output = response_fields(&fields).unwrap();
    let values: Vec<_> = output.iter().filter(|f| f.name == b"request-id").collect();
    assert_eq!(values[0].value, b"opaque-\xff-id"); assert!(values[0].sensitive);
    assert_eq!(values[1].value, b"second"); assert!(!values[1].sensitive);
}

#[test]
fn many_connection_tokens_keep_only_distinct_relevant_names_but_validate_all() {
    let c = config(); let mut h = headers();
    let repeated = "x-ignored,content-type,".repeat(500) + "x-final";
    set(&mut h, "connection", &repeated);
    let p = prep(&c, &h, "/routes/7").unwrap();
    assert!(!has(p.upstream_fields(), "content-type"));
    assert_eq!(out(&p, "accept"), Some("text/event-stream"));
    drop(p);
    set(&mut h, "connection", &(repeated + ",invalid name"));
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::BadRequest)));
}

#[test]
fn maximum_configured_request_head_serializes_below_64_kib() {
    let host = ["h".repeat(63), "h".repeat(63), "h".repeat(63), "h".repeat(61)].join(".");
    assert_eq!(host.len(), 253);
    let prefix = format!("https://{host}:65535/");
    let endpoint = format!("{prefix}{}", "p".repeat(MAX_DESTINATION_BYTES - prefix.len()));
    let routes = json!([{"tenant":1,"selector":7,"origin":0,"credential":0}]);
    let root = json!({
        "identities":[{"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"gateway-token"))}],
        "destinations":[endpoint], "credentials":[{"tenant":1,"kind":"bearer","env":"KEY"}],
        "grants":routes,"limits":{"requests":1,"chunk_bytes":4096},"logging":"strict"
    });
    let config = GatewayConfig::from_json(&serde_json::to_vec(&root).unwrap(),
        &serde_json::to_vec(&json!({"routes":routes})).unwrap(), |_| Some("k".repeat(MAX_CREDENTIAL_BYTES))).unwrap();
    let mut input = vec![field("authorization", "Bearer gateway-token")];
    for _ in 0..98 { input.push(field("accept", "x")); }
    let used: usize = input.iter().map(|f| f.name.len() + f.value.len()).sum();
    input.push(field("accept", &"a".repeat(MAX_HEADER_BYTES - used - "accept".len())));
    assert_eq!(input.len(), MAX_HEADER_VALUES);
    let mut prepared = prep(&config, &input, "/routes/7").unwrap();
    let upstream = prepared.take_upstream().unwrap();
    let mut fields = upstream.fields;
    fields.push(field("transfer-encoding", "chunked"));
    fields.push(field("connection", "close"));
    assert!(gateway_core::http1_write::wire_ok(&fields));
    let mut head = Vec::new();
    gateway_core::http1_write::write_request_head(b"POST", &upstream.path, &fields, &mut head);
    assert!(head.len() > 48 * 1024 && head.len() <= 65536);
    assert!(head.starts_with(format!("POST /{} HTTP/1.1\r\n", "p".repeat(MAX_DESTINATION_BYTES - prefix.len())).as_bytes()));
    assert!(String::from_utf8(head).unwrap().contains(&format!("authorization: Bearer {}\r\n", "k".repeat(MAX_CREDENTIAL_BYTES))));
}

#[test]
fn maximum_response_head_serializes_below_64_kib() {
    let mut input = Vec::new();
    for _ in 0..99 { input.push(field("request-id", "x")); }
    let used: usize = input.iter().map(|f| f.name.len() + f.value.len()).sum();
    input.push(field("request-id", &"r".repeat(MAX_HEADER_BYTES - used - "request-id".len())));
    assert_eq!(input.len(), MAX_HEADER_VALUES);
    let mut fields = response_fields(&input).unwrap();
    fields.push(field("connection", "close"));
    fields.push(field("transfer-encoding", "chunked"));
    assert!(gateway_core::http1_write::wire_ok(&fields));
    let mut head = Vec::new();
    gateway_core::http1_write::write_status_head(200, b"OK", &fields, &mut head);
    assert!(head.starts_with(b"HTTP/1.1 200 OK\r\n") && head.ends_with(b"\r\n\r\n"));
    assert_eq!(String::from_utf8_lossy(&head).matches("request-id:").count(), 100);
    assert!(head.len() > MAX_HEADER_BYTES && head.len() <= 33445);
}

#[test]
fn dispatch_rejects_changed_path_credentials_or_host_and_cannot_repeat() {
    let c = config();
    for change in 0..3 {
        let mut p = prep(&c, &headers(), "/routes/7").unwrap();
        let upstream = p.upstream.as_mut().unwrap();
        match change {
            0 => upstream.path = b"/other".to_vec(),
            1 => { upstream.fields.retain(|f| f.name != b"authorization"); upstream.fields.push(field("authorization", "Bearer other")); },
            _ => { upstream.fields.retain(|f| f.name != b"host"); upstream.fields.push(field("host", "other.example")); },
        }
        assert!(p.take_upstream().is_err());
        assert_eq!(p.destination_text(), "https://api.openai.com:8443/v1/responses");
    }
    let mut p = prep(&c, &headers(), "/routes/7").unwrap();
    let outgoing = p.take_upstream().unwrap();
    assert_eq!(outgoing.path, b"/v1/responses");
    assert_eq!(value_of(&outgoing.fields, "authorization"), Some(&b"Bearer secret-OPENAI"[..]));
    assert!(p.take_upstream().is_err());
}

#[test]
fn sdk_paths_match_only_the_admitted_endpoint_and_release_rejected_capacity() {
    let c = config(); let h = headers();
    for path in ["/routes/7/v1/responses", "/routes/8/v1/messages"] {
        assert!(prep(&c, &h, path).is_ok(), "{path}");
    }
    for path in ["/routes/7/v1/messages", "/routes/8/v1/responses", "/routes/7/",
        "/routes/7//v1/responses", "/routes/7/v1/responses?stream=true",
        "/routes/7/v1/responses/", "/routes/7/v1/../responses", "/routes/07/v1/responses",
        "/routes/%37/v1/responses", "/routes/18446744073709551616/v1/responses"] {
        assert!(matches!(prep(&c, &h, path), Err(HttpError::BadRequest)), "{path}");
        assert!(prep(&c, &h, "/routes/7").is_ok(), "rejected path retained a slot: {path}");
    }
    assert!(matches!(prep(&c, &h, "/routes/999/v1/responses"), Err(HttpError::Unauthorized)));
    let mut wrong = headers(); set(&mut wrong, "authorization", "Bearer wrong");
    assert!(matches!(prep(&c, &wrong, "/routes/7/v1/responses"), Err(HttpError::Unauthorized)));
}
