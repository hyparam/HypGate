use super::*;
use crate::{config::GatewayConfig, http_boundary, test_support::tls, transfer::LogRecord};
use rcgen::generate_simple_self_signed;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{service::service_fn, Response};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{convert::Infallible, io::{Read, Write}, pin::Pin, sync::atomic::{AtomicBool, Ordering}, task::{Context, Poll}};
use tokio::{io::{AsyncReadExt, ReadBuf}, net::TcpListener};
use tokio_rustls::{TlsAcceptor, rustls::{CipherSuite, CipherSuiteCommon, ClientConnection, ContentType, HandshakeKind,
    ProtocolVersion, ServerConfig, ServerConnection, SupportedCipherSuite, Tls13CipherSuite, pki_types::PrivatePkcs8KeyDer,
    version::{TLS12, TLS13}, crypto::{cipher::{AeadKey, Iv, OutboundChunks, OutboundPlainMessage},
    ring::cipher_suite::{TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256}}}};

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
    fn session_id(&self) -> u128 { 0 }
    async fn append(&mut self, r: LogRecord<'_>) -> io::Result<crate::transfer::DurableFrame> {
        match r.kind.direction() {
            Some(Direction::Upload) => self.upload.extend_from_slice(r.bytes),
            Some(Direction::Download) => self.download.extend_from_slice(r.bytes),
            None => {}, // metadata records are checked by the server tests
        }
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
// Each exchange needs its own worker: a worker issues every HTTP role once.
fn worker_http() -> http_body::WorkerHttp {
    let registry = Arc::new(std::sync::Mutex::new(gateway_core::http_worker::WorkerRegistry::new(1)));
    let (_task, issuer) = registry.lock().unwrap().acquire().unwrap();
    http_body::WorkerHttp::new(registry, issuer)
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
    let http = worker_http();
    let mut prepared = prepare(&config);
    let exchange = transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http);
    let (result, ()) = tokio::join!(exchange, upstream);
    drop(prepared);
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
    let http = worker_http();
    let mut prepared = prepare(&config);
    let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), upstream);
    drop(prepared);
    assert!(matches!(result, Err(TransportError::Tls))); assert!(output.status.is_none());
    assert!(log.upload.is_empty()); assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn trusted_certificate_with_large_wrong_purpose_list_is_rejected_before_upload() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for count in [1, 4096] {
            let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
            params.extended_key_usages = (0..count)
                .map(|_| rcgen::ExtendedKeyUsagePurpose::Other(vec![1, 2, 3])).collect();
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();
            assert!(cert.der().len() < 32768);
            let mut roots = RootCertStore::empty(); roots.add(cert.der().clone()).unwrap();
            let server = ServerConfig::builder().with_no_client_auth()
                .with_single_cert(vec![cert.der().clone()], PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(server));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config = config(listener.local_addr().unwrap().port());
            let provider = async {
                let (tcp, _) = listener.accept().await.unwrap();
                assert!(acceptor.accept(tcp).await.is_err());
            };
            let transport = HttpsTransport::with_roots(roots, Duration::from_secs(3)).unwrap();
            let mut output = Output::new(); let mut log = Log::default();
            let mut input = &b"secret body"[..];
            let http = worker_http();
            let mut prepared = prepare(&config);
            let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), provider);
            drop(prepared);
            assert!(matches!(result, Err(TransportError::Tls)));
            assert_eq!(input, b"secret body");
            assert!(output.status.is_none()); assert!(output.bytes.is_empty());
            assert!(log.upload.is_empty()); assert!(log.download.is_empty());
            assert_eq!(config.usage(), Some((0, 1)));
        }
    }).await.unwrap();
}

#[tokio::test]
async fn tls_drain_guard_holds_control_queue_stable_and_resumes_exact_bytes() {
    struct Gated { tcp: TcpStream, blocked: Arc<AtomicBool> }
    impl AsyncRead for Gated {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.tcp).poll_read(cx, out)
        }
    }
    impl AsyncWrite for Gated {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            // The fixture explicitly repolls after unblocking; no task waits
            // for this synthetic gate to wake it.
            if self.blocked.load(Ordering::SeqCst) { return Poll::Pending; }
            Pin::new(&mut self.tcp).poll_write(cx, bytes)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.tcp).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.tcp).poll_shutdown(cx)
        }
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        let (listener, acceptor, roots) = tls().await;
        let blocked = Arc::new(AtomicBool::new(false));
        let connector = TlsConnector::from(Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()));
        let connect = async {
            let tcp = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            tcp.set_nodelay(true).unwrap();
            connector.connect(ServerName::try_from("localhost").unwrap(), Gated { tcp, blocked: blocked.clone() }).await.unwrap()
        };
        let accept = async {
            let (tcp, _) = listener.accept().await.unwrap(); tcp.set_nodelay(true).unwrap();
            acceptor.accept(tcp).await.unwrap()
        };
        let (mut client, mut server) = tokio::join!(connect, accept);
        assert_eq!(client.get_ref().1.protocol_version(), Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3));
        client.get_mut().1.set_buffer_limit(Some(TLS_APPLICATION_BUFFER));
        blocked.store(true, Ordering::SeqCst);
        let initial = vec![7; TLS_APPLICATION_BUFFER];
        assert_eq!(std::io::Write::write(&mut client.get_mut().1.writer(), &initial).unwrap(), initial.len());
        let baseline = client.get_mut().1.process_new_packets().unwrap().tls_bytes_to_write();
        let mut client = tls_io::DrainBeforeWrite(client);
        for round in 0..3000 {
            server.get_mut().1.refresh_traffic_keys().unwrap();
            server.write_all(b"x").await.unwrap(); server.flush().await.unwrap();
            let mut byte = [0]; client.read_exact(&mut byte).await.unwrap(); assert_eq!(&byte, b"x");
            let pending = std::future::poll_fn(|cx| {
                let result = if round % 2 == 0 { Pin::new(&mut client).poll_write(cx, b"y") }
                    else { Pin::new(&mut client).poll_write_vectored(cx, &[io::IoSlice::new(b"y")]) };
                Poll::Ready(result.is_pending())
            }).await;
            assert!(pending);
            assert_eq!(client.0.get_mut().1.process_new_packets().unwrap().tls_bytes_to_write(), baseline);
        }
        blocked.store(false, Ordering::SeqCst);
        let send = async { client.write_all(b"y").await.unwrap(); client.flush().await.unwrap(); };
        let receive = async {
            let mut actual = vec![0; initial.len() + 1]; server.read_exact(&mut actual).await.unwrap();
            assert_eq!(&actual[..initial.len()], initial.as_slice()); assert_eq!(actual[initial.len()], b'y');
        };
        tokio::join!(send, receive);
        assert_eq!(client.0.get_mut().1.process_new_packets().unwrap().tls_bytes_to_write(), 0);
    }).await.unwrap();
}

#[test]
fn tls_application_write_fragment_overhead_is_bounded_for_pinned_suites() {
    let suites = tokio_rustls::rustls::crypto::ring::default_provider().cipher_suites;
    let mut exercised = 0;
    for suite in suites {
        let overhead = match suite.suite() {
            CipherSuite::TLS13_AES_128_GCM_SHA256 | CipherSuite::TLS13_AES_256_GCM_SHA384
                | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 22,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => 29,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => 21,
            _ => continue, // Fixture certificate is ECDSA; RSA uses the same record ciphers.
        };
        for vectored in [false, true] {
            let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
            let mut crypto = tokio_rustls::rustls::crypto::ring::default_provider();
            crypto.cipher_suites = vec![suite]; let crypto = Arc::new(crypto);
            let server_config = ServerConfig::builder_with_provider(crypto.clone())
                .with_protocol_versions(&[suite.version()]).unwrap().with_no_client_auth().with_single_cert(
                    vec![cert.cert.der().clone()], PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
            let client_config = ClientConfig::builder_with_provider(crypto)
                .with_protocol_versions(&[suite.version()]).unwrap().with_root_certificates(roots).with_no_client_auth();
            let mut client = ClientConnection::new(Arc::new(client_config), ServerName::try_from("localhost").unwrap()).unwrap();
            let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
            for _ in 0..10 {
                let mut wire = Vec::new(); client.write_tls(&mut wire).unwrap();
                if !wire.is_empty() { server.read_tls(&mut &wire[..]).unwrap(); server.process_new_packets().unwrap(); }
                let mut wire = Vec::new(); server.write_tls(&mut wire).unwrap();
                if !wire.is_empty() { client.read_tls(&mut &wire[..]).unwrap(); client.process_new_packets().unwrap(); }
                if !client.is_handshaking() && !server.is_handshaking() && !client.wants_write() && !server.wants_write() { break; }
            }
            assert!(!client.is_handshaking() && !server.is_handshaking());
            assert!(!client.wants_write() && !server.wants_write());
            assert_eq!(client.negotiated_cipher_suite().unwrap().suite(), suite.suite());
            client.set_buffer_limit(Some(TLS_APPLICATION_BUFFER));
            let payload = vec![42; TLS_APPLICATION_BUFFER + 1];
            let accepted = if vectored {
                let slices: Vec<_> = payload.chunks(1).map(io::IoSlice::new).collect();
                client.writer().write_vectored(&slices).unwrap()
            } else { client.writer().write(&payload).unwrap() };
            assert_eq!(accepted, TLS_APPLICATION_BUFFER);
            let mut wire = Vec::new(); client.write_tls(&mut wire).unwrap();
            assert_eq!(wire.len(), TLS_APPLICATION_BUFFER + 4 * overhead);
            let mut offset = 0; let mut records = 0;
            while offset < wire.len() {
                assert_eq!(wire[offset], 23);
                let len = u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]) as usize;
                assert_eq!(len + 5, 16384 + overhead);
                offset += 5 + len; records += 1;
            }
            assert_eq!(records, 4); assert_eq!(offset, wire.len());
            let mut incoming = &wire[..]; let mut actual = Vec::new();
            while !incoming.is_empty() {
                assert!(server.read_tls(&mut incoming).unwrap() > 0);
                let available = server.process_new_packets().unwrap().plaintext_bytes_to_read();
                let start = actual.len(); actual.resize(start + available, 0);
                server.reader().read_exact(&mut actual[start..]).unwrap();
            }
            assert_eq!(actual, payload[..accepted]); exercised += 1;
        }
    }
    assert_eq!(exercised, 12);
}

// Lower only the test suite's refresh threshold, retaining real AES-GCM and
// key scheduling. Production uses ring's unmodified confidentiality limits.
#[test]
fn tls_automatic_refresh_bounds_records_at_each_batch_boundary() {
    static SHORT_KEYS: std::sync::LazyLock<Tls13CipherSuite> = std::sync::LazyLock::new(|| {
        let base = tokio_rustls::rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256.tls13().unwrap();
        Tls13CipherSuite {
            common: CipherSuiteCommon { suite: base.common.suite, hash_provider: base.common.hash_provider, confidentiality_limit: 8 },
            hkdf_provider: base.hkdf_provider, aead_alg: base.aead_alg, quic: None,
        }
    });
    let mut observed_refreshes = 0;
    for warmup in 0..8 {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
        let mut crypto = tokio_rustls::rustls::crypto::ring::default_provider();
        crypto.cipher_suites = vec![SupportedCipherSuite::Tls13(&SHORT_KEYS)]; let crypto = Arc::new(crypto);
        let server_config = ServerConfig::builder_with_provider(crypto.clone())
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13]).unwrap()
            .with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
        let client_config = ClientConfig::builder_with_provider(crypto)
            .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13]).unwrap()
            .with_root_certificates(roots).with_no_client_auth();
        let mut client = ClientConnection::new(Arc::new(client_config), ServerName::try_from("localhost").unwrap()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        for _ in 0..10 {
            let mut wire = Vec::new(); client.write_tls(&mut wire).unwrap();
            if !wire.is_empty() { server.read_tls(&mut &wire[..]).unwrap(); server.process_new_packets().unwrap(); }
            let mut wire = Vec::new(); server.write_tls(&mut wire).unwrap();
            if !wire.is_empty() { client.read_tls(&mut &wire[..]).unwrap(); client.process_new_packets().unwrap(); }
            if !client.is_handshaking() && !server.is_handshaking() && !client.wants_write() && !server.wants_write() { break; }
        }
        assert!(!client.is_handshaking() && !server.is_handshaking());
        assert!(!client.wants_write() && !server.wants_write());
        for _ in 0..warmup {
            client.writer().write_all(b"w").unwrap();
            let mut wire = Vec::new(); client.write_tls(&mut wire).unwrap();
            server.read_tls(&mut &wire[..]).unwrap(); server.process_new_packets().unwrap();
            let mut byte = [0]; server.reader().read_exact(&mut byte).unwrap(); assert_eq!(&byte, b"w");
        }
        client.set_buffer_limit(Some(TLS_APPLICATION_BUFFER));
        let payload = vec![42; TLS_APPLICATION_BUFFER + 1];
        let accepted = client.writer().write(&payload).unwrap();
        assert!(accepted > 0 && accepted <= TLS_APPLICATION_BUFFER);
        let mut wire = Vec::new(); client.write_tls(&mut wire).unwrap();
        let mut offset = 0; let mut app_records = 0; let mut updates = 0;
        while offset < wire.len() {
            assert_eq!(wire[offset], 23); // TLS 1.3 encrypted outer type.
            let len = u16::from_be_bytes([wire[offset + 3], wire[offset + 4]]) as usize + 5;
            if len == 27 { updates += 1; } else { app_records += 1; }
            offset += len;
        }
        assert_eq!(offset, wire.len()); assert!(app_records <= 4); assert!(updates <= 1);
        assert_eq!(wire.len(), accepted + app_records * 22 + updates * 27);
        assert!(wire.len() <= TLS_APPLICATION_BUFFER + 4 * 22 + 27);
        observed_refreshes += updates;
        let mut incoming = &wire[..]; let mut actual = Vec::new();
        while !incoming.is_empty() {
            assert!(server.read_tls(&mut incoming).unwrap() > 0);
            let available = server.process_new_packets().unwrap().plaintext_bytes_to_read();
            let start = actual.len(); actual.resize(start + available, 0);
            server.reader().read_exact(&mut actual[start..]).unwrap();
        }
        assert_eq!(actual, payload[..accepted]);
    }
    assert!(observed_refreshes >= 4);
}

#[test]
fn tls_record_encoding_reuses_exact_sized_encryption_allocation() {
    for suite in [TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256] {
        // Synthetic keys never leave this unit test. Increasing sequence numbers
        // ensure each record uses a distinct nonce under its test key.
        let mut encrypter = suite.tls13().unwrap().aead_alg.encrypter(AeadKey::from([0; 32]), Iv::new([0; 12]));
        for (seq, length) in [0, 1, 5, 16383, 16384].into_iter().enumerate() {
            let input = vec![42; length];
            let chunks: Vec<&[u8]> = input.chunks(1).collect();
            let encrypted = encrypter.encrypt(OutboundPlainMessage {
                typ: ContentType::ApplicationData, version: ProtocolVersion::TLSv1_2,
                payload: OutboundChunks::new(&chunks),
            }, seq as u64).unwrap();
            let payload_address = encrypted.payload.as_ref().as_ptr();
            let encoded = encrypted.encode();
            assert_eq!(encoded.len(), length + 22);
            assert_eq!(encoded.capacity(), encoded.len());
            assert_eq!(encoded.as_ptr().wrapping_add(5), payload_address);
        }
    }
}

// Dependency-level counterexample, not a production HTTP scheduling test.
#[test]
fn tls_control_replies_can_exceed_application_buffer_limit() {
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
    let server_config = ServerConfig::builder().with_no_client_auth().with_single_cert(
        vec![cert.cert.der().clone()], PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
    let client_config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let mut client = ClientConnection::new(Arc::new(client_config), ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    for _ in 0..10 {
        let mut wire = Vec::new(); client.write_tls(&mut wire).unwrap();
        if !wire.is_empty() { server.read_tls(&mut &wire[..]).unwrap(); server.process_new_packets().unwrap(); }
        let mut wire = Vec::new(); server.write_tls(&mut wire).unwrap();
        if !wire.is_empty() { client.read_tls(&mut &wire[..]).unwrap(); client.process_new_packets().unwrap(); }
        if !client.is_handshaking() && !server.is_handshaking() && !client.wants_write() && !server.wants_write() { break; }
    }
    assert!(!client.is_handshaking() && !server.is_handshaking());
    assert!(!client.wants_write() && !server.wants_write());
    assert_eq!(client.protocol_version(), Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3));
    let limit = 65536;
    client.set_buffer_limit(Some(limit));
    assert_eq!(client.writer().write(&vec![0; limit]).unwrap(), limit);
    let baseline = client.process_new_packets().unwrap().tls_bytes_to_write();
    // Do not drain client ciphertext: model a stalled outbound socket while
    // reads and attempted application writes continue. Each peer byte resets
    // the consecutive key-update counter and is consumed before the next round.
    for _ in 0..3000 {
        server.refresh_traffic_keys().unwrap();
        server.writer().write_all(b"x").unwrap();
        let mut wire = Vec::new(); server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut &wire[..]).unwrap(); client.process_new_packets().unwrap();
        let mut byte = [0]; client.reader().read_exact(&mut byte).unwrap(); assert_eq!(&byte, b"x");
        assert_eq!(client.writer().write(b"y").unwrap(), 0);
    }
    let queued = client.process_new_packets().unwrap().tls_bytes_to_write();
    assert_eq!(queued, baseline + 3000 * 27);
    assert!(queued > 2 * limit);
}

#[tokio::test]
async fn tls_key_update_burst_limit_rejects_without_response_or_replay() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for updates in [32, 33] {
            let (listener, acceptor, roots) = tls().await;
            let config = config(listener.local_addr().unwrap().port());
            let provider = async {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut socket = acceptor.accept(tcp).await.unwrap();
                assert_eq!(socket.get_ref().1.protocol_version(), Some(tokio_rustls::rustls::ProtocolVersion::TLSv1_3));
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                    assert!(request.len() < 8192);
                }
                if String::from_utf8(request).unwrap().to_ascii_lowercase().contains("transfer-encoding: chunked") {
                    let mut end = [0; 5]; socket.read_exact(&mut end).await.unwrap();
                    assert_eq!(&end, b"0\r\n\r\n");
                }
                for _ in 0..updates { socket.get_mut().1.refresh_traffic_keys().unwrap(); }
                let _ = socket.flush().await;
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                let _ = socket.write_all(response).await;
                let _ = socket.shutdown().await;
                assert!(tokio::time::timeout(Duration::from_millis(20), listener.accept()).await.is_err());
            };
            let transport = HttpsTransport::with_roots(roots, Duration::from_secs(3)).unwrap();
            let mut output = Output::new(); let mut log = Log::default(); let mut input = &b""[..];
            let http = worker_http();
            let mut prepared = prepare(&config);
            let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), provider);
            drop(prepared);
            if updates == 32 {
                result.unwrap(); assert_eq!(output.status, Some(StatusCode::OK));
                assert_eq!(output.bytes, b"ok"); assert_eq!(log.download, b"ok");
            } else {
                assert!(matches!(result, Err(TransportError::Http)));
                assert!(output.status.is_none()); assert!(output.bytes.is_empty());
                assert!(log.download.is_empty());
            }
            assert_eq!(config.usage(), Some((0, 1)));
        }
    }).await.unwrap();
}

#[tokio::test]
async fn oversized_handshake_is_rejected_from_its_length_before_upload() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for declared in [65535usize, 65536] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config = config(listener.local_addr().unwrap().port());
            let provider = async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut record = [0; 5]; socket.read_exact(&mut record).await.unwrap();
                assert_eq!(record[0], 22); // ClientHello handshake record.
                let size = u16::from_be_bytes([record[3], record[4]]) as usize;
                assert!(size <= 18432);
                let mut hello = vec![0; size]; socket.read_exact(&mut hello).await.unwrap();
                // Send only a ServerHello header, withhold its entire payload,
                // and keep the socket open. The within-limit control must wait;
                // the oversized declaration must be rejected without EOF/data.
                socket.write_all(&[22, 3, 3, 0, 4, 2,
                    (declared >> 16) as u8, (declared >> 8) as u8, declared as u8]).await.unwrap();
                let mut tail = Vec::new(); socket.read_to_end(&mut tail).await.unwrap();
                assert!(!tail.windows(b"provider-secret".len()).any(|w| w == b"provider-secret"));
            };
            let transport = HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(1)).unwrap();
            let mut output = Output::new(); let mut log = Log::default();
            let mut input = &b"secret body"[..];
            let http = worker_http();
            let mut prepared = prepare(&config);
            let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), provider);
            drop(prepared);
            let expected = if declared == 65535 { TransportError::Timeout } else { TransportError::Tls };
            assert!(matches!(result, Err(ref error) if *error == expected));
            assert_eq!(input, b"secret body");
            assert!(output.status.is_none()); assert!(output.bytes.is_empty());
            assert!(log.upload.is_empty()); assert!(log.download.is_empty());
            assert_eq!(config.usage(), Some((0, 1)));
        }
    }).await.unwrap();
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
    let http = worker_http();
    let mut prepared = prepare(&config);
    let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), upstream);
    drop(prepared);
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
            let mut bytes = Vec::new(); let _ = tls.read_to_end(&mut bytes).await;
        }
    };
    let transport = HttpsTransport::with_roots(roots, Duration::from_millis(50)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let http = worker_http();
    let mut prepared = prepare(&config);
    let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), upstream);
    drop(prepared);
    assert!(matches!(result, Err(TransportError::Timeout)));
    assert!(output.status.is_none()); assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn truncated_response_is_never_reported_as_success() {
    let (listener, acceptor, roots) = tls().await;
    let config = config(listener.local_addr().unwrap().port());
    let upstream = async {
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
    let http = worker_http();
    let mut prepared = prepare(&config);
    let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), upstream);
    drop(prepared);
    assert!(matches!(result, Err(TransportError::Http | TransportError::Download)));
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn unsolicited_protocol_switch_is_rejected_before_client_headers() {
    let (listener, acceptor, roots) = tls().await;
    let config = config(listener.local_addr().unwrap().port());
    let upstream = async {
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
    let http = worker_http();
    let mut prepared = prepare(&config);
    let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), upstream);
    drop(prepared);
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
    let http = worker_http();
    let mut prepared = prepare(&config);
    let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), upstream);
    drop(prepared);
    assert_eq!(result.unwrap().download.accepted_bytes, 2);
    assert_eq!(output.status, Some(StatusCode::OK)); assert_eq!(output.bytes, b"{}");
    assert!(!output.headers.contains_key("link"));
    assert_eq!(log.upload, b"{}"); assert_eq!(log.download, b"{}");
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[tokio::test]
async fn canceling_tls_handshake_drops_socket_and_returns_owned_request_credit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (listener, _acceptor, roots) = tls().await;
        let config = config(listener.local_addr().unwrap().port());
        let transport = HttpsTransport::with_roots(roots, Duration::from_secs(30)).unwrap();
        let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
        let http = worker_http();
        let mut prepared = prepare(&config);
        let mut exchange = Box::pin(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http));
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
        drop(exchange); drop(prepared);
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

#[tokio::test]
async fn tls_session_cache_bounds_servers_and_tickets_without_disabling_resumption() {
    async fn connect(listener: &TcpListener, acceptor: &TlsAcceptor, transport: &HttpsTransport,
        name: &str, expected: HandshakeKind) {
        let provider = async {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(tcp).await.unwrap();
            assert_eq!(stream.get_ref().1.handshake_kind(), Some(expected));
            assert_eq!(stream.get_ref().1.server_name(), Some(name));
            stream.write_all(b"ticket delivery").await.unwrap();
            stream.shutdown().await.unwrap();
        };
        let client = async {
            let tcp = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
            let mut stream = transport.connector.connect(
                ServerName::try_from(name.to_owned()).unwrap(), tcp).await.unwrap();
            assert_eq!(stream.get_ref().1.handshake_kind(), Some(expected));
            // Reading through close_notify processes post-handshake tickets.
            let mut received = Vec::new(); stream.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, b"ticket delivery");
        };
        tokio::join!(provider, client);
    }
    tokio::time::timeout(Duration::from_secs(15), async {
        for version in [&TLS12, &TLS13] {
            // 33 distinct names exceed the production cache's 32-server capacity.
            let names: Vec<_> = (0..33).map(|i| format!("provider-{i}.example")).collect();
            let cert = generate_simple_self_signed(names.clone()).unwrap();
            let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
            let mut server = ServerConfig::builder_with_protocol_versions(&[version])
                .with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
            // Keep server-side tickets valid throughout client-cache eviction,
            // including tickets read late from the held connection.
            server.session_storage = tokio_rustls::rustls::server::ServerSessionMemoryCache::new(4096);
            server.send_tls13_tickets = 24; // deliberately exceeds the eight-ticket client budget
            let acceptor = TlsAcceptor::from(Arc::new(server.clone()));
            server.send_tls13_tickets = 0; // shares server-side session storage with the first config
            let no_tickets = TlsAcceptor::from(Arc::new(server));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let transport = HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap();
            connect(&listener, &acceptor, &transport, &names[0], HandshakeKind::Full).await;
            // Keep a resumed connection alive across eviction. Its session and
            // authenticated peer state must not be treated as freed cache data.
            let held_provider = async {
                let (tcp, _) = listener.accept().await.unwrap();
                acceptor.accept(tcp).await.unwrap()
            };
            let held_client = async {
                let tcp = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
                transport.connector.connect(ServerName::try_from(names[0].clone()).unwrap(), tcp).await.unwrap()
            };
            let (mut held_provider, mut held_client) = tokio::join!(held_provider, held_client);
            assert_eq!(held_provider.get_ref().1.handshake_kind(), Some(HandshakeKind::Resumed));
            assert_eq!(held_client.get_ref().1.handshake_kind(), Some(HandshakeKind::Resumed));
            let mut order: Vec<_> = (1..33).map(|i| (i, HandshakeKind::Full)).collect();
            order.push((0, HandshakeKind::Full)); // oldest entry was evicted
            order.push((0, HandshakeKind::Resumed)); // replacement remains usable
            for (index, expected) in order {
                connect(&listener, &acceptor, &transport, &names[index], expected).await;
            }
            assert!(!held_client.get_ref().1.peer_certificates().unwrap().is_empty());
            let send_held = async {
                held_provider.write_all(b"alive after eviction").await.unwrap();
                held_provider.shutdown().await.unwrap();
            };
            let receive_held = async {
                let mut received = Vec::new();
                held_client.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, b"alive after eviction");
            };
            tokio::join!(send_held, receive_held);
            drop(held_provider); drop(held_client);
            if version.version == TLS13.version {
                // Only eight of the last 24 issued tickets may remain. Consume
                // them without replacement; the ninth connection must be full.
                for _ in 0..8 {
                    connect(&listener, &no_tickets, &transport, &names[0], HandshakeKind::Resumed).await;
                }
                connect(&listener, &no_tickets, &transport, &names[0], HandshakeKind::Full).await;
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn upstream_wire_head_and_header_count_limits_cover_status_line() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut cases = Vec::new();
        let prefix = "HTTP/1.1 200 "; let suffix = "\r\nContent-Length: 0\r\n\r\n";
        for extra in [0, 1] {
            let response = format!("{prefix}{}{suffix}", "x".repeat(crate::http_boundary::MAX_HEADER_BYTES + extra - prefix.len() - suffix.len()));
            cases.push((response, extra == 0));
        }
        for count in [100, 101] {
            let mut response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n".to_owned();
            for i in 1..count { response.push_str(&format!("x-{i}: a\r\n")); }
            response.push_str("\r\n"); cases.push((response, count == 100));
        }
        for (response, accepted) in cases {
            let (listener, acceptor, roots) = tls().await;
            let config = config(listener.local_addr().unwrap().port());
            let transport = HttpsTransport::with_roots(roots, Duration::from_secs(3)).unwrap();
            let provider = async {
                let (tcp, _) = listener.accept().await.unwrap(); let mut socket = acceptor.accept(tcp).await.unwrap();
                let mut request = Vec::new(); let mut byte = [0];
                while !request.ends_with(b"\r\n\r\n") {
                    socket.read_exact(&mut byte).await.unwrap(); request.push(byte[0]); assert!(request.len() < 8192);
                }
                if String::from_utf8(request).unwrap().to_ascii_lowercase().contains("transfer-encoding: chunked") {
                    let mut end = [0; 5]; socket.read_exact(&mut end).await.unwrap(); assert_eq!(&end, b"0\r\n\r\n");
                }
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            };
            let mut output = Output::new(); let mut log = Log::default(); let mut input = &b""[..];
            let http = worker_http();
            let mut prepared = prepare(&config);
            let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), provider);
            drop(prepared);
            if accepted { result.unwrap(); assert_eq!(output.status, Some(StatusCode::OK)); }
            else { assert!(matches!(result, Err(TransportError::Http))); assert!(output.status.is_none()); }
            assert!(output.bytes.is_empty()); assert!(log.download.is_empty());
            assert!(config.admit(b"gateway", 7).is_ok());
        }
    }).await.unwrap();
}

/// Splits a TLS 1.3 ClientHello handshake message into its echoed session id,
/// declared extension length, and the bytes following that length field.
fn hello_parts(handshake: &[u8]) -> (&[u8], usize, &[u8]) {
    assert_eq!(handshake[0], 1);
    let declared = ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    assert_eq!(declared + 4, handshake.len());
    let session_len = handshake[38] as usize;
    let session = &handshake[39..39 + session_len];
    let mut at = 39 + session_len;
    at += 2 + u16::from_be_bytes([handshake[at], handshake[at + 1]]) as usize;
    at += 1 + handshake[at] as usize;
    let extensions = u16::from_be_bytes([handshake[at], handshake[at + 1]]) as usize;
    (session, extensions, &handshake[at + 2..])
}
fn cookie_extension(mut extensions: &[u8]) -> Option<&[u8]> {
    while extensions.len() >= 4 {
        let kind = u16::from_be_bytes([extensions[0], extensions[1]]);
        let len = u16::from_be_bytes([extensions[2], extensions[3]]) as usize;
        let (data, rest) = extensions[4..].split_at(len);
        if kind == 44 { return Some(&data[2..]); }
        extensions = rest;
    }
    None
}
/// Stateless HelloRetryRequest: fixed RFC 8446 random, echoed session id,
/// TLS_AES_128_GCM_SHA256, supported_versions, and a cookie of 42s.
fn hello_retry_request(session: &[u8], cookie_len: usize) -> Vec<u8> {
    let random = [0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c];
    let mut extensions = vec![0, 43, 0, 2, 3, 4, 0, 44];
    extensions.extend_from_slice(&((cookie_len + 2) as u16).to_be_bytes());
    extensions.extend_from_slice(&(cookie_len as u16).to_be_bytes());
    extensions.resize(extensions.len() + cookie_len, 42);
    let mut body = vec![3, 3]; body.extend_from_slice(&random);
    body.push(session.len() as u8); body.extend_from_slice(session); body.extend_from_slice(&[0x13, 1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes()); body.extend_from_slice(&extensions);
    assert!(body.len() <= 65535);
    let mut handshake = vec![2]; handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body); handshake
}
fn handshake_records(handshake: &[u8]) -> Vec<Vec<u8>> {
    handshake.chunks(16384).map(|fragment| {
        let mut record = vec![22, 3, 3]; record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        record.extend_from_slice(fragment); record
    }).collect()
}
/// Concatenates handshake record payloads, skipping the compatibility CCS record.
fn handshake_messages(mut wire: &[u8]) -> Vec<u8> {
    let mut handshake = Vec::new();
    while !wire.is_empty() {
        let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        assert!(len <= 16384);
        let (record, rest) = wire.split_at(5 + len);
        match record[0] { 22 => handshake.extend_from_slice(&record[5..]), 20 => assert_eq!(&record[5..], &[1]), other => panic!("record {other}") }
        wire = rest;
    }
    handshake
}

#[test]
fn tls_retry_cookie_echo_is_bounded_by_the_client_hello_extension_field() {
    let config = Arc::new(ClientConfig::builder().with_root_certificates(RootCertStore::empty()).with_no_client_auth());
    for extra in [0usize, 1] {
        let mut client = ClientConnection::new(config.clone(), ServerName::try_from("localhost").unwrap()).unwrap();
        client.set_buffer_limit(Some(TLS_APPLICATION_BUFFER));
        let mut wire = Vec::new(); client.write_tls(&mut wire).unwrap();
        let first = handshake_messages(&wire);
        let (session, declared, extensions) = hello_parts(&first);
        assert_eq!(declared, extensions.len());
        // The echoed cookie adds a four-byte extension header and two length bytes.
        let cookie_len = 65535 - declared - 6 + extra;
        let retry = hello_retry_request(session, cookie_len);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for record in handshake_records(&retry) {
                let mut incoming = &record[..];
                while !incoming.is_empty() { client.read_tls(&mut incoming).unwrap(); }
                client.process_new_packets().unwrap();
            }
            let mut wire = Vec::new(); client.write_tls(&mut wire).unwrap(); wire
        }));
        if extra == 0 {
            let wire = outcome.unwrap();
            assert_eq!(&wire[..6], &[20, 3, 3, 0, 1, 1]);
            let second = handshake_messages(&wire);
            let (_, declared, extensions) = hello_parts(&second);
            assert_eq!(declared, 65535); assert_eq!(extensions.len(), 65535);
            assert_eq!(cookie_extension(extensions), Some(&vec![42u8; cookie_len][..]));
            // Handshake output is not limited by the application buffer setting.
            assert!(wire.len() > TLS_APPLICATION_BUFFER);
        } else if cfg!(debug_assertions) {
            // Pinned rustls asserts the u16 extension length only in debug builds.
            assert!(outcome.is_err());
        } else {
            let second = handshake_messages(&outcome.unwrap());
            let (_, declared, extensions) = hello_parts(&second);
            assert_eq!(declared, 0); assert_eq!(extensions.len(), 65536);
        }
    }
}

#[tokio::test]
async fn retry_cookie_is_echoed_above_the_buffer_limit_and_closure_fails_before_upload() {
    async fn read_handshake_message(socket: &mut TcpStream) -> Vec<u8> {
        let mut handshake = Vec::new();
        loop {
            let mut header = [0; 5]; socket.read_exact(&mut header).await.unwrap();
            let mut payload = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            socket.read_exact(&mut payload).await.unwrap();
            match header[0] { 22 => handshake.extend_from_slice(&payload), 20 => assert_eq!(payload, [1]), other => panic!("record {other}") }
            if handshake.len() >= 4 && handshake.len() == 4 + (((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize) { return handshake; }
        }
    }
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = config(listener.local_addr().unwrap().port());
        let provider = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let first = read_handshake_message(&mut socket).await;
            let (session, declared, _) = hello_parts(&first);
            let cookie_len = 65535 - declared - 6;
            for record in handshake_records(&hello_retry_request(session, cookie_len)) { socket.write_all(&record).await.unwrap(); }
            let second = read_handshake_message(&mut socket).await;
            let (_, declared, extensions) = hello_parts(&second);
            assert_eq!(declared, 65535); assert_eq!(extensions.len(), 65535);
            assert_eq!(cookie_extension(extensions), Some(&vec![42u8; cookie_len][..]));
            assert!(second.len() > TLS_APPLICATION_BUFFER);
            // Close without a ServerHello; the client must fail without any request bytes.
            drop(socket);
        };
        let transport = HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(5)).unwrap();
        let mut output = Output::new(); let mut log = Log::default();
        let mut input = &b"secret body"[..];
        let http = worker_http();
        let mut prepared = prepare(&config);
        let (result, ()) = tokio::join!(transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http), provider);
        drop(prepared);
        assert!(matches!(result, Err(TransportError::Tls)));
        assert_eq!(input, b"secret body");
        assert!(output.status.is_none()); assert!(output.bytes.is_empty());
        assert!(log.upload.is_empty()); assert!(log.download.is_empty());
        assert_eq!(config.usage(), Some((0, 1)));
    }).await.unwrap();
}

#[test]
fn tls_peer_certificate_chain_is_owned_per_connection_and_restored_on_resumption() {
    fn settle(client: &mut ClientConnection, server: &mut ServerConnection) {
        for _ in 0..16 {
            let mut wire = Vec::new(); client.write_tls(&mut wire).unwrap();
            let mut incoming = &wire[..];
            while !incoming.is_empty() { server.read_tls(&mut incoming).unwrap(); server.process_new_packets().unwrap(); }
            let mut wire = Vec::new(); server.write_tls(&mut wire).unwrap();
            let mut incoming = &wire[..];
            while !incoming.is_empty() { client.read_tls(&mut incoming).unwrap(); client.process_new_packets().unwrap(); }
            if !client.is_handshaking() && !server.is_handshaking() && !client.wants_write() && !server.wants_write() { return; }
        }
        panic!("handshake did not settle");
    }
    // Large non-critical extensions make the two DER entries total above 48 KiB
    // while the Certificate message stays under the 65,535-byte handshake limit.
    let mut issuer = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    issuer.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    issuer.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], vec![7; 20_000])];
    let issuer_key = rcgen::KeyPair::generate().unwrap();
    let issuer_cert = issuer.self_signed(&issuer_key).unwrap();
    let mut leaf = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    leaf.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 2], vec![9; 30_000])];
    let leaf_key = rcgen::KeyPair::generate().unwrap();
    let leaf_cert = leaf.signed_by(&leaf_key, &rcgen::Issuer::from_params(&issuer, &issuer_key)).unwrap();
    let chain = vec![leaf_cert.der().clone(), issuer_cert.der().clone()];
    let total: usize = chain.iter().map(|der| der.len()).sum();
    assert!(total > 49_152 && total < 65_000, "{total}");
    let mut roots = RootCertStore::empty(); roots.add(issuer_cert.der().clone()).unwrap();
    let mut server_config = ServerConfig::builder().with_no_client_auth()
        .with_single_cert(chain.clone(), PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into()).unwrap();
    server_config.send_tls13_tickets = 2;
    let server_config = Arc::new(server_config);
    let client_config = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
    let mut first = ClientConnection::new(client_config.clone(), ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config.clone()).unwrap();
    settle(&mut first, &mut server);
    assert_eq!(first.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(first.peer_certificates(), Some(&chain[..]));
    // The resumed connection receives no Certificate message; its chain is a
    // separate copy restored from the cached ticket value, not a shared view.
    let mut second = ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    settle(&mut second, &mut server);
    assert_eq!(second.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(second.peer_certificates(), Some(&chain[..]));
    drop(first);
    assert_eq!(second.peer_certificates().map(|chain| chain.iter().map(|der| der.len()).sum::<usize>()), Some(total));
}
