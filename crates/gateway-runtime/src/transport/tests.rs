use super::*;
use crate::{config::GatewayConfig, http_boundary, transfer::LogRecord};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{service::service_fn, Response};
use rcgen::generate_simple_self_signed;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{convert::Infallible, pin::Pin, task::{Context, Poll}};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer}};

struct Output { bytes: Vec<u8>, status: Option<StatusCode>, headers: HeaderMap }
impl Output { fn new() -> Self { Self { bytes: Vec::new(), status: None, headers: HeaderMap::new() } } }
impl AsyncWrite for Output {
    fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        assert!(self.status.is_some());
        let n = bytes.len().min(2); self.bytes.extend_from_slice(&bytes[..n]); Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
}
impl ResponseSink for Output {
    async fn start(&mut self, status: StatusCode, headers: HeaderMap) -> io::Result<()> {
        assert!(self.status.is_none()); self.status = Some(status); self.headers = headers; Ok(())
    }
}
#[derive(Default)]
struct Log { upload: Vec<u8>, download: Vec<u8> }
impl AuditLog for Log {
    async fn append(&mut self, r: LogRecord<'_>) -> io::Result<crate::transfer::DurableFrame> {
        match r.direction { Direction::Upload => &mut self.upload, Direction::Download => &mut self.download }.extend_from_slice(r.bytes);
        Ok(crate::transfer::receipt_for_test(r))
    }
}
fn config(port: u16) -> GatewayConfig {
    let routes = json!([{"tenant":1,"selector":7,"origin":0,"credential":0}]);
    let root = json!({"identities":[{"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"gateway"))}],
        "destinations":[format!("https://localhost:{port}/v1/messages")],
        "credentials":[{"tenant":1,"kind":"api_key","env":"KEY"}],"grants":routes,
        "limits":{"requests":1,"chunk_bytes":3},"logging":"strict"});
    GatewayConfig::from_json(&serde_json::to_vec(&root).unwrap(), &serde_json::to_vec(&json!({"routes":routes})).unwrap(),
        |_| Some("provider-secret".into())).unwrap()
}
fn prepare(c: &GatewayConfig) -> PreparedRequest<'_> {
    let mut h = HeaderMap::new(); h.insert("authorization", "Bearer gateway".parse().unwrap());
    h.insert("host", "attacker.example".parse().unwrap());
    h.insert("x-api-key", "caller-key".parse().unwrap());
    http_boundary::prepare(c, &http::Method::POST, &"/routes/7".parse().unwrap(), &h).unwrap()
}
async fn tls() -> (TcpListener, TlsAcceptor, RootCertStore) {
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let config = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], key.into()).unwrap();
    (TcpListener::bind("127.0.0.1:0").await.unwrap(), TlsAcceptor::from(Arc::new(config)), roots)
}

#[tokio::test]
async fn tls_exchange_preserves_native_payloads_and_scoped_credentials() {
    let (listener, acceptor, roots) = tls().await;
    let port = listener.local_addr().unwrap().port(); let config = config(port);
    let expected = b"data: {\"delta\":\"hello\"}\n\ndata: [DONE]\n\n";
    let upstream = async {
        let (socket, _) = listener.accept().await.unwrap(); let socket = acceptor.accept(socket).await.unwrap();
        let service = service_fn(|request: hyper::Request<hyper::body::Incoming>| async move {
            assert_eq!(request.uri(), "/v1/messages");
            assert_eq!(request.headers()["host"], format!("localhost:{port}"));
            assert_eq!(request.headers()["x-api-key"], "provider-secret");
            assert!(!request.headers().contains_key("authorization"));
            assert_eq!(request.collect().await.unwrap().to_bytes(), "{\"stream\":true}");
            let mut response = Response::new(Full::new(Bytes::from_static(expected)));
            response.headers_mut().insert("content-type", "text/event-stream".parse().unwrap());
            response.headers_mut().insert("set-cookie", "secret".parse().unwrap());
            Ok::<_, Infallible>(response)
        });
        let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
    };
    let mut output = Output::new(); let mut log = Log::default();
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap();
    let mut input = &b"{\"stream\":true}"[..];
    let exchange = transport.exchange(prepare(&config), &mut input, &mut output, &mut log);
    let (result, ()) = tokio::join!(exchange, upstream);
    let stats = result.unwrap();
    assert_eq!(output.status, Some(StatusCode::OK));
    assert_eq!(output.bytes, expected); assert_eq!(log.download, expected);
    assert_eq!(log.upload, b"{\"stream\":true}");
    assert_eq!(stats.download.accepted_bytes, expected.len() as u64);
    assert!(!output.headers.contains_key("set-cookie"));
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn untrusted_certificate_is_rejected_before_http_credentials_are_sent() {
    let (listener, acceptor, _) = tls().await;
    let config = config(listener.local_addr().unwrap().port());
    let upstream = async {
        let (socket, _) = listener.accept().await.unwrap();
        assert!(acceptor.accept(socket).await.is_err());
    };
    let transport = HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(5)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"secret body"[..];
    let (result, ()) = tokio::join!(transport.exchange(prepare(&config), &mut input, &mut output, &mut log), upstream);
    assert!(matches!(result, Err(TransportError::Tls))); assert!(output.status.is_none());
    assert!(log.upload.is_empty()); assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn redirects_are_returned_without_opening_a_second_connection() {
    let (listener, acceptor, roots) = tls().await;
    let config = config(listener.local_addr().unwrap().port());
    let upstream = async {
        let (socket, _) = listener.accept().await.unwrap(); let socket = acceptor.accept(socket).await.unwrap();
        let service = service_fn(|request: hyper::Request<hyper::body::Incoming>| async move {
            request.collect().await.unwrap();
            let response = Response::builder().status(307).header("location", "https://attacker.example/")
                .body(Full::new(Bytes::from_static(b"redirect"))).unwrap();
            Ok::<_, Infallible>(response)
        });
        let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
        assert!(tokio::time::timeout(Duration::from_millis(20), listener.accept()).await.is_err());
    };
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let (result, ()) = tokio::join!(transport.exchange(prepare(&config), &mut input, &mut output, &mut log), upstream);
    result.unwrap(); assert_eq!(output.status, Some(StatusCode::TEMPORARY_REDIRECT));
    assert!(!output.headers.contains_key("location")); assert_eq!(output.bytes, b"redirect");
}

#[tokio::test]
async fn deadline_drops_connection_and_releases_admission() {
    let (listener, acceptor, roots) = tls().await;
    let config = config(listener.local_addr().unwrap().port());
    let upstream = async {
        let (socket, _) = listener.accept().await.unwrap();
        if let Ok(mut tls) = acceptor.accept(socket).await {
            use tokio::io::AsyncReadExt;
            let mut bytes = Vec::new(); let _ = tls.read_to_end(&mut bytes).await;
        }
    };
    let transport = HttpsTransport::with_roots(roots, Duration::from_millis(50)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let (result, ()) = tokio::join!(transport.exchange(prepare(&config), &mut input, &mut output, &mut log), upstream);
    assert!(matches!(result, Err(TransportError::Timeout)));
    assert!(output.status.is_none()); assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn truncated_response_is_never_reported_as_success() {
    let (listener, acceptor, roots) = tls().await;
    let config = config(listener.local_addr().unwrap().port());
    let upstream = async {
        use tokio::io::AsyncReadExt;
        let (socket, _) = listener.accept().await.unwrap(); let mut socket = acceptor.accept(socket).await.unwrap();
        let mut request = Vec::new(); let mut buf = [0; 256];
        while !request.ends_with(b"0\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap(); assert!(n != 0);
            request.extend_from_slice(&buf[..n]); assert!(request.len() < 8192);
        }
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial").await.unwrap();
        socket.shutdown().await.unwrap();
    };
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let (result, ()) = tokio::join!(transport.exchange(prepare(&config), &mut input, &mut output, &mut log), upstream);
    assert!(matches!(result, Err(TransportError::Http | TransportError::Download)));
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn unsolicited_protocol_switch_is_rejected_before_client_headers() {
    let (listener, acceptor, roots) = tls().await;
    let config = config(listener.local_addr().unwrap().port());
    let upstream = async {
        use tokio::io::AsyncReadExt;
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let mut request = Vec::new(); let mut buf = [0; 256];
        while !request.ends_with(b"0\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap(); assert_ne!(n, 0);
            request.extend_from_slice(&buf[..n]); assert!(request.len() < 8192);
        }
        socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\nupgraded-data").await.unwrap();
        let mut tail = Vec::new(); let _ = socket.read_to_end(&mut tail).await;
        assert!(tail.is_empty(), "gateway must not speak the upgraded protocol");
        assert!(tokio::time::timeout(Duration::from_millis(20), listener.accept()).await.is_err());
    };
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(2)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let (result, ()) = tokio::join!(transport.exchange(prepare(&config), &mut input, &mut output, &mut log), upstream);
    assert!(output.status.is_none(), "unexpected client status: {:?}", output.status);
    assert!(matches!(result, Err(TransportError::Metadata)));
    assert!(output.bytes.is_empty());
    assert_eq!(log.upload, b"{}"); assert!(log.download.is_empty());
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn interim_response_does_not_replace_final_status_or_payload() {
    let (listener, acceptor, roots) = tls().await;
    let config = config(listener.local_addr().unwrap().port());
    let upstream = async {
        use tokio::io::AsyncReadExt;
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = acceptor.accept(socket).await.unwrap();
        let mut request = Vec::new(); let mut buf = [0; 256];
        while !request.ends_with(b"0\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap(); assert_ne!(n, 0);
            request.extend_from_slice(&buf[..n]); assert!(request.len() < 8192);
        }
        socket.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </ignored>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}").await.unwrap();
        let mut tail = Vec::new(); let _ = socket.read_to_end(&mut tail).await;
    };
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(2)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let (result, ()) = tokio::join!(transport.exchange(prepare(&config), &mut input, &mut output, &mut log), upstream);
    assert_eq!(result.unwrap().download.accepted_bytes, 2);
    assert_eq!(output.status, Some(StatusCode::OK)); assert_eq!(output.bytes, b"{}");
    assert!(!output.headers.contains_key("link"));
    assert_eq!(log.upload, b"{}"); assert_eq!(log.download, b"{}");
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn canceling_tls_handshake_drops_socket_and_returns_owned_request_credit() {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, _acceptor, roots) = tls().await;
        let config = config(listener.local_addr().unwrap().port());
        let transport = HttpsTransport::with_roots(roots, Duration::from_secs(30)).unwrap();
        let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
        let mut exchange = Box::pin(transport.exchange(prepare(&config), &mut input, &mut output, &mut log));
        // Accept TCP but never answer the TLS ClientHello. No provider HTTP
        // request should have been submitted at this cancellation point.
        let (mut socket, _) = tokio::select! {
            accepted = listener.accept() => accepted.unwrap(),
            result = &mut exchange => panic!("exchange finished before cancellation: {}", result.is_ok()),
        };
        let mut record_header = [0; 5];
        tokio::select! {
            read = socket.read_exact(&mut record_header) => { read.unwrap(); },
            result = &mut exchange => panic!("exchange finished during handshake: {}", result.is_ok()),
        }
        assert_eq!(record_header[0], 22); // TLS handshake record
        assert!(config.admit(b"gateway", 7).is_err());
        drop(exchange);
        let replacement = config.admit(b"gateway", 7).unwrap();
        let mut handshake_bytes = Vec::new();
        socket.read_to_end(&mut handshake_bytes).await.unwrap();
        assert!(output.status.is_none());
        assert!(output.bytes.is_empty());
        assert!(log.upload.is_empty());
        assert!(log.download.is_empty());
        drop(replacement);
    }).await.unwrap();
}
