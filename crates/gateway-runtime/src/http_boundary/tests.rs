use super::*;
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
fn headers() -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("authorization", HeaderValue::from_static("Bearer gateway-token"));
    h.insert("content-type", HeaderValue::from_static("application/json"));
    h.insert("accept", HeaderValue::from_static("text/event-stream"));
    h
}
fn prep<'a>(c: &'a GatewayConfig, h: &HeaderMap, path: &str) -> Result<PreparedRequest<'a>, HttpError> {
    prepare(c, &Method::POST, &path.parse().unwrap(), h)
}

#[test]
fn fixed_destination_and_credentials_replace_host_and_client_secrets() {
    let c = config(); let mut h = headers();
    for name in ["host", "x-api-key", "proxy-authorization", "cookie", "forwarded", "x-forwarded-host",
        "x-upstream-url", "content-length", "transfer-encoding", "accept-encoding"] {
        h.insert(HeaderName::from_static(name), HeaderValue::from_static("attacker"));
    }
    let p = prep(&c, &h, "/routes/7").unwrap();
    let out = p.upstream.headers();
    assert_eq!(p.destination(), "https://api.openai.com:8443/v1/responses");
    assert_eq!(out["host"], "api.openai.com:8443");
    assert_eq!(out["authorization"], "Bearer secret-OPENAI");
    assert!(out["authorization"].is_sensitive());
    assert_eq!(out["accept-encoding"], "identity");
    assert_eq!(out["content-type"], "application/json");
    assert_eq!(out.len(), 5);
    assert!(!out.values().any(|v| v.as_bytes() == b"Bearer gateway-token"));
    drop(p);
    h.insert("anthropic-version", HeaderValue::from_static("2023-06-01"));
    h.insert("anthropic-beta", HeaderValue::from_static("some-beta"));
    let p = prep(&c, &h, "/routes/8").unwrap();
    assert_eq!(p.upstream.headers()["x-api-key"], "secret-ANTHROPIC");
    assert!(!p.upstream.headers().contains_key("authorization"));
    assert_eq!(p.upstream.headers()["anthropic-version"], "2023-06-01");
}

#[test]
fn malformed_authentication_never_issues_a_prepared_request() {
    let c = config();
    for value in ["", "Basic gateway-token", "Bearer", "Bearer ", "Bearer  gateway-token",
        "Bearer gateway-token,other", "Bearer wrong", "Bearer gateway-token\t"] {
        let mut h = headers(); h.insert("authorization", HeaderValue::from_str(value).unwrap());
        assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::Unauthorized)), "{value:?}");
    }
    let mut h = headers(); h.append("authorization", HeaderValue::from_static("Bearer gateway-token"));
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::Unauthorized)));
    h.remove("authorization");
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::Unauthorized)));
    h.insert("authorization", HeaderValue::from_static("bEaReR gateway-token"));
    assert!(prep(&c, &h, "/routes/7").is_ok());
}

#[test]
fn caller_cannot_select_an_arbitrary_url_path_or_method() {
    let c = config(); let h = headers();
    for path in ["https://attacker.example/routes/7", "/routes/7?url=attacker", "/routes/07",
        "/routes/%37", "/routes/7/other", "/routes/+7", "/routes/", "/routes/18446744073709551616"] {
        assert!(matches!(prep(&c, &h, path), Err(HttpError::BadRequest)), "{path}");
    }
    for method in [Method::GET, Method::CONNECT, Method::PUT] {
        assert!(matches!(prepare(&c, &method, &"/routes/7".parse().unwrap(), &h), Err(HttpError::MethodNotAllowed)));
    }
    assert!(matches!(prep(&c, &h, "/routes/999"), Err(HttpError::Unauthorized)));
    assert!(prep(&c, &h, "/routes/7").is_ok());
}

#[test]
fn connection_nominations_are_stripped_but_cannot_suppress_root_credentials() {
    let c = config(); let mut h = headers();
    h.insert("connection", HeaderValue::from_static("Accept, Authorization, Host"));
    let p = prep(&c, &h, "/routes/7").unwrap();
    assert!(!p.upstream.headers().contains_key("accept"));
    assert!(!p.upstream.headers().contains_key("connection"));
    assert_eq!(p.upstream.headers()["authorization"], "Bearer secret-OPENAI");
    assert_eq!(p.upstream.headers()["host"], "api.openai.com:8443");
    drop(p);
    h.insert("connection", HeaderValue::from_static("accept,,host"));
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::BadRequest)));
}

#[test]
fn invalid_and_oversized_headers_do_not_leak_admission_slots() {
    let c = config();
    for name in ["content-encoding", "upgrade", "trailer"] {
        let mut h = headers(); h.insert(HeaderName::from_static(name), HeaderValue::from_static("value"));
        assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::BadRequest)));
    }
    let mut h = headers(); h.append("content-type", HeaderValue::from_static("text/plain"));
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::BadRequest)));
    let mut h = headers(); h.insert("large", HeaderValue::from_bytes(&vec![b'x'; MAX_HEADER_BYTES]).unwrap());
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::HeadersTooLarge)));
    let mut h = headers();
    for _ in 0..MAX_HEADER_VALUES { h.append("many", HeaderValue::from_static("x")); }
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::HeadersTooLarge)));
    let p = prep(&c, &headers(), "/routes/7").unwrap();
    assert!(matches!(prep(&c, &headers(), "/routes/7"), Err(HttpError::Unavailable)));
    drop(p);
    assert!(prep(&c, &headers(), "/routes/7").is_ok());
}

#[test]
fn upstream_response_cannot_forward_credentials_cookies_or_redirect_location() {
    let mut h = HeaderMap::new();
    for name in ["authorization", "x-api-key", "set-cookie", "location", "content-length", "transfer-encoding"] {
        h.insert(HeaderName::from_static(name), HeaderValue::from_static("untrusted"));
    }
    h.insert("content-type", HeaderValue::from_static("text/event-stream"));
    h.insert("content-encoding", HeaderValue::from_static("gzip"));
    h.insert("x-request-id", HeaderValue::from_static("request-42"));
    h.insert("connection", HeaderValue::from_static("X-Request-Id"));
    let out = response_headers(&h).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out["content-type"], "text/event-stream");
    assert_eq!(out["content-encoding"], "gzip");
    h.insert("connection", HeaderValue::from_static("Content-Encoding"));
    assert!(response_headers(&h).is_err());
}
