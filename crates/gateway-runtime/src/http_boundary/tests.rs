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

struct HeaderBacking { bytes: Vec<u8>, dropped: std::sync::Arc<std::sync::atomic::AtomicUsize> }
impl AsRef<[u8]> for HeaderBacking { fn as_ref(&self) -> &[u8] { &self.bytes } }
impl Drop for HeaderBacking {
    fn drop(&mut self) { self.dropped.fetch_add(1, std::sync::atomic::Ordering::SeqCst); }
}
fn shared_header(value: &[u8], dropped: &std::sync::Arc<std::sync::atomic::AtomicUsize>) -> HeaderValue {
    let mut bytes = vec![b'x'; 256 * 1024]; bytes[..value.len()].copy_from_slice(value);
    let owner = bytes::Bytes::from_owner(HeaderBacking { bytes, dropped: dropped.clone() });
    let mut header = HeaderValue::from_maybe_shared(owner.slice(..value.len())).unwrap();
    header.set_sensitive(true);
    header
}

#[test]
fn prepared_request_drops_source_metadata_and_detaches_header_backing() {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    let c = config(); let dropped = Arc::new(AtomicUsize::new(0));
    let mut request = Request::new(());
    *request.method_mut() = Method::POST; *request.uri_mut() = "/routes/7".parse().unwrap();
    *request.headers_mut() = headers();
    request.headers_mut().insert("openai-beta", shared_header(b"opaque-\x80-value", &dropped));
    request.extensions_mut().insert(Arc::new(HeaderBacking { bytes: Vec::new(), dropped: dropped.clone() }));
    let (parts, ()) = request.into_parts();
    let prepared = prepare_request_parts(&c, parts).unwrap();
    // The original header owner and extension are gone while output is alive.
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert_eq!(prepared.upstream.headers()["openai-beta"].as_bytes(), b"opaque-\x80-value");
    assert!(prepared.upstream.headers()["openai-beta"].is_sensitive());
    assert_eq!(prepared.upstream.headers()["authorization"], "Bearer secret-OPENAI");
}

#[test]
fn prepared_response_drops_source_metadata_and_detaches_header_backing() {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut response = http::Response::new(());
    *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    response.headers_mut().append("request-id", shared_header(b"opaque-\xff-id", &dropped));
    response.headers_mut().append("request-id", HeaderValue::from_static("second"));
    response.extensions_mut().insert(Arc::new(HeaderBacking { bytes: Vec::new(), dropped: dropped.clone() }));
    let (parts, ()) = response.into_parts();
    let (status, output) = prepare_response_parts(parts).unwrap();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    let values: Vec<_> = output.get_all("request-id").iter().collect();
    assert_eq!(values[0].as_bytes(), b"opaque-\xff-id"); assert!(values[0].is_sensitive());
    assert_eq!(values[1], "second"); assert!(!values[1].is_sensitive());
}

#[test]
fn many_connection_tokens_keep_only_distinct_relevant_names_but_validate_all() {
    let c = config(); let mut h = headers();
    let repeated = "x-ignored,content-type,".repeat(500) + "x-final";
    h.insert("connection", HeaderValue::from_str(&repeated).unwrap());
    let options = connection_options(&h, FORWARDED_REQUEST_HEADERS).unwrap();
    assert_eq!(options.len(), 1); assert_eq!(options[0], "content-type");
    let p = prep(&c, &h, "/routes/7").unwrap();
    assert!(!p.upstream.headers().contains_key("content-type"));
    assert_eq!(p.upstream.headers()["accept"], "text/event-stream");
    drop(p);
    h.insert("connection", HeaderValue::from_str(&(repeated + ",invalid name")).unwrap());
    assert!(matches!(prep(&c, &h, "/routes/7"), Err(HttpError::BadRequest)));
}

#[tokio::test]
async fn maximum_configured_request_head_serializes_below_64_kib() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use http_body_util::BodyExt;
    use crate::config::{MAX_CREDENTIAL_BYTES, MAX_DESTINATION_BYTES};
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
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
        let mut input = HeaderMap::new();
        input.insert("authorization", HeaderValue::from_static("Bearer gateway-token"));
        for _ in 0..98 { input.append("accept", HeaderValue::from_static("x")); }
        let used: usize = input.iter().map(|(n, v)| n.as_str().len() + v.as_bytes().len()).sum();
        input.append("accept", HeaderValue::from_str(&"a".repeat(MAX_HEADER_BYTES - used - "accept".len())).unwrap());
        assert_eq!(input.len(), MAX_HEADER_VALUES);
        let mut prepared = prep(&config, &input, "/routes/7").unwrap();
        let path = prepared.upstream.uri().path_and_query().unwrap().clone();
        *prepared.upstream.uri_mut() = Uri::builder().path_and_query(path.clone()).build().unwrap();
        let (client, mut peer) = tokio::io::duplex(65536);
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new().writev(true)
            .handshake(hyper_util::rt::TokioIo::new(client)).await.unwrap();
        let driver = tokio::spawn(connection);
        let (mut writer, body) = crate::http_body::channel(16384);
        let request = std::mem::take(&mut prepared.upstream).map(|()| body);
        let capture = async {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(peer.read_u8().await.unwrap());
                assert!(head.len() <= 65536);
            }
            let mut end = [0; 5]; peer.read_exact(&mut end).await.unwrap(); assert_eq!(&end, b"0\r\n\r\n");
            peer.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await.unwrap();
            peer.shutdown().await.unwrap();
            head
        };
        let receive = async { sender.send_request(request).await.unwrap().into_body().collect().await.unwrap(); };
        let upload = async { writer.shutdown().await.unwrap(); };
        let (head, (), ()) = tokio::join!(capture, receive, upload);
        assert!(head.len() > 48 * 1024);
        assert!(head.starts_with(format!("POST {} HTTP/1.1\r\n", path.as_str()).as_bytes()));
        assert!(String::from_utf8(head).unwrap().contains(&format!("authorization: Bearer {}\r\n", "k".repeat(MAX_CREDENTIAL_BYTES))));
        drop(sender); driver.await.unwrap().unwrap();
    }).await.unwrap();
}
