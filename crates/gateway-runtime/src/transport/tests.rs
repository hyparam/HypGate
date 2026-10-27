use super::*;
use super::exchange::{ExchangeStats, ResponseSink};
use gateway_core::exchange_lifecycle::Fault as TransportError;
use gateway_core::headers::Field;
use crate::{config::GatewayConfig, http_boundary, net::Cancel, test_support::{accept_tls, tls, http::{field, has, read_request, write_response}}, transfer::LogRecord};
use gateway_core::http1_head::RequestHead;
use rcgen::generate_simple_self_signed;
use rustls::{CipherSuite, CipherSuiteCommon, ContentType, HandshakeKind, ProtocolVersion, ServerConfig, ServerConnection,
    SupportedCipherSuite, Tls13CipherSuite, pki_types::PrivatePkcs8KeyDer, version::{TLS12, TLS13},
    crypto::{cipher::{AeadKey, Iv, OutboundChunks, OutboundPlainMessage}, ring::cipher_suite::{TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256}}};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{io::{Read, Write}, net::{Shutdown, TcpListener, TcpStream}, thread};

struct Output { bytes: Vec<u8>, status: Option<u16>, headers: Vec<Field> }
impl Output { fn new() -> Self { Self { bytes: Vec::new(), status: None, headers: Vec::new() } } }
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(self.status.is_some());
        let n = bytes.len().min(2); self.bytes.extend_from_slice(&bytes[..n]); Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl ResponseSink for Output {
    fn start(&mut self, status: u16, headers: Vec<Field>) -> io::Result<()> {
        assert!(self.status.is_none()); self.status = Some(status); self.headers = headers; Ok(())
    }
}
#[derive(Default)]
struct Log { upload: Vec<u8>, download: Vec<u8> }
impl AuditLog for Log {
    fn session_id(&self) -> u128 { 0 }
    fn append(&mut self, r: LogRecord<'_>) -> io::Result<crate::transfer::DurableFrame> {
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
    let fields = vec![field("authorization", "Bearer gateway"), field("host", "attacker.example"), field("x-api-key", "caller-key")];
    http_boundary::prepare(c, &RequestHead { method: b"POST".to_vec(), target: b"/routes/7".to_vec(), fields }).unwrap()
}
// Each exchange needs its own worker: a worker issues every HTTP role once.
fn worker_http() -> http_body::WorkerHttp {
    let registry = Arc::new(std::sync::Mutex::new(gateway_core::http_worker::WorkerRegistry::new(1)));
    let (_task, issuer) = registry.lock().unwrap().acquire().unwrap();
    http_body::WorkerHttp::new(registry, issuer)
}
/// One exchange on this thread against a provider that is already running.
fn exchange(transport: &HttpsTransport, config: &GatewayConfig, input: &mut &[u8], output: &mut Output, log: &mut Log)
    -> Result<ExchangeStats, TransportError>
{
    let http = worker_http();
    let mut prepared = prepare(config);
    let result = transport.exchange(&mut prepared, input, output, log, &http, &Cancel::new());
    drop(prepared);
    result
}
fn describe(result: &Result<ExchangeStats, TransportError>) -> String {
    match result { Ok(_) => "Ok".into(), Err(fault) => format!("{fault:?}") }
}
/// The provider must not be asked for a second connection.
fn no_second_connection(listener: &TcpListener) {
    listener.set_nonblocking(true).unwrap();
    thread::sleep(Duration::from_millis(20));
    assert_eq!(listener.accept().unwrap_err().kind(), io::ErrorKind::WouldBlock);
}
/// Read the gateway's request head and its empty chunked body, byte by byte.
fn read_head_and_empty_body<IO: Read>(socket: &mut IO) {
    let mut request = Vec::new(); let mut byte = [0];
    while !request.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte).unwrap(); request.push(byte[0]); assert!(request.len() < 8192);
    }
    if String::from_utf8(request).unwrap().to_ascii_lowercase().contains("transfer-encoding: chunked") {
        let mut end = [0; 5]; socket.read_exact(&mut end).unwrap(); assert_eq!(&end, b"0\r\n\r\n");
    }
}
/// Read until the request's last chunk has arrived.
fn read_until_last_chunk<IO: Read>(socket: &mut IO) {
    let mut request = Vec::new(); let mut buf = [0; 256];
    while !request.ends_with(b"0\r\n\r\n") {
        let n = socket.read(&mut buf).unwrap(); assert_ne!(n, 0);
        request.extend_from_slice(&buf[..n]); assert!(request.len() < 8192);
    }
}
/// Close a server-side TLS stream the way a well-behaved provider does.
fn close_tls(stream: &mut crate::test_support::ServerTls) {
    stream.conn.send_close_notify();
    let _ = stream.flush();
    let _ = stream.sock.shutdown(Shutdown::Write);
}
/// Drive two in-memory connections through their handshake.
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
/// Feed ciphertext to a server connection and collect the plaintext it yields.
fn decrypt_all(server: &mut ServerConnection, mut incoming: &[u8]) -> Vec<u8> {
    let mut actual = Vec::new();
    while !incoming.is_empty() {
        assert!(server.read_tls(&mut incoming).unwrap() > 0);
        let available = server.process_new_packets().unwrap().plaintext_bytes_to_read();
        let start = actual.len(); actual.resize(start + available, 0);
        server.reader().read_exact(&mut actual[start..]).unwrap();
    }
    actual
}

#[test]
fn tls_exchange_preserves_native_payloads_and_scoped_credentials() {
    let (listener, acceptor, roots) = tls();
    let port = listener.local_addr().unwrap().port(); let config = config(port);
    let expected = b"data: {\"delta\":\"hello\"}\n\ndata: [DONE]\n\n";
    let upstream = thread::spawn(move || {
        let mut socket = accept_tls(&listener, &acceptor).unwrap();
        let request = read_request(&mut socket).unwrap();
        assert_eq!(request.target(), "/v1/messages");
        assert_eq!(request.header("host"), Some(format!("localhost:{port}").as_str()));
        assert_eq!(request.header("x-api-key"), Some("provider-secret"));
        assert!(request.header("authorization").is_none());
        assert_eq!(request.body, b"{\"stream\":true}");
        write_response(&mut socket, 200, &[("content-type", "text/event-stream"), ("set-cookie", "secret")], expected).unwrap();
        close_tls(&mut socket);
    });
    let mut output = Output::new(); let mut log = Log::default();
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap();
    let mut input = &b"{\"stream\":true}"[..];
    let stats = exchange(&transport, &config, &mut input, &mut output, &mut log).unwrap();
    upstream.join().unwrap();
    assert_eq!(output.status, Some(200));
    assert_eq!(output.bytes, expected); assert_eq!(log.download, expected);
    assert_eq!(log.upload, b"{\"stream\":true}");
    assert_eq!(stats.upload.accepted_bytes(), log.upload.len() as u64);
    assert_eq!(stats.download.accepted_bytes(), expected.len() as u64);
    assert!(!has(&output.headers, "set-cookie"));
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[test]
fn untrusted_certificate_is_rejected_before_http_credentials_are_sent() {
    let (listener, acceptor, _) = tls();
    let config = config(listener.local_addr().unwrap().port());
    let upstream = thread::spawn(move || assert!(accept_tls(&listener, &acceptor).is_err()));
    let transport = HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(5)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"secret body"[..];
    let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
    upstream.join().unwrap();
    assert!(matches!(result, Err(TransportError::Tls))); assert!(output.status.is_none());
    assert!(log.upload.is_empty()); assert!(config.admit(b"gateway", 7).is_ok());
}

#[test]
fn trusted_certificate_with_large_wrong_purpose_list_is_rejected_before_upload() {
    for count in [1, 4096] {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.extended_key_usages = (0..count)
            .map(|_| rcgen::ExtendedKeyUsagePurpose::Other(vec![1, 2, 3])).collect();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        assert!(cert.der().len() < 32768);
        let mut roots = RootCertStore::empty(); roots.add(cert.der().clone()).unwrap();
        let server = Arc::new(ServerConfig::builder().with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], PrivatePkcs8KeyDer::from(key.serialize_der()).into()).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let config = config(listener.local_addr().unwrap().port());
        let provider = thread::spawn(move || assert!(accept_tls(&listener, &server).is_err()));
        let transport = HttpsTransport::with_roots(roots, Duration::from_secs(3)).unwrap();
        let mut output = Output::new(); let mut log = Log::default();
        let mut input = &b"secret body"[..];
        let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
        provider.join().unwrap();
        assert!(matches!(result, Err(TransportError::Tls)));
        assert_eq!(input, b"secret body");
        assert!(output.status.is_none()); assert!(output.bytes.is_empty());
        assert!(log.upload.is_empty()); assert!(log.download.is_empty());
        assert_eq!(config.usage(), Some((0, 1)));
    }
}

// The blocking rustls stream drains queued ciphertext before accepting more
// plaintext: while the socket cannot take bytes, repeated writes fail without
// growing the TLS output queue, and the bytes accepted earlier arrive intact
// once it can. This is the property the async drain guard used to supply.
#[test]
fn tls_write_through_a_stalled_socket_queues_no_extra_ciphertext_and_resumes_exact_bytes() {
    struct Gated { blocked: bool, out: Vec<u8> }
    impl Read for Gated { fn read(&mut self, _: &mut [u8]) -> io::Result<usize> { Err(io::ErrorKind::WouldBlock.into()) } }
    impl Write for Gated {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.blocked { return Err(io::ErrorKind::WouldBlock.into()); }
            self.out.extend_from_slice(bytes); Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
    let server_config = ServerConfig::builder().with_no_client_auth().with_single_cert(
        vec![cert.cert.der().clone()], PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
    let client_config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let mut client = ClientConnection::new(Arc::new(client_config), ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
    settle(&mut client, &mut server);
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
    client.set_buffer_limit(Some(TLS_APPLICATION_BUFFER));
    let initial = vec![7; TLS_APPLICATION_BUFFER];
    assert_eq!(client.writer().write(&initial).unwrap(), initial.len());
    let baseline = client.process_new_packets().unwrap().tls_bytes_to_write();
    assert!(baseline > 0);
    let mut gated = Gated { blocked: true, out: Vec::new() };
    for round in 0..3000 {
        let error = {
            let mut stream = rustls::Stream::new(&mut client, &mut gated);
            if round % 2 == 0 { stream.write(b"y").unwrap_err() } else { stream.write_vectored(&[io::IoSlice::new(b"y")]).unwrap_err() }
        };
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(client.process_new_packets().unwrap().tls_bytes_to_write(), baseline);
        assert!(gated.out.is_empty());
    }
    gated.blocked = false;
    {
        let mut stream = rustls::Stream::new(&mut client, &mut gated);
        stream.write_all(b"y").unwrap(); stream.flush().unwrap();
    }
    assert_eq!(client.process_new_packets().unwrap().tls_bytes_to_write(), 0);
    let actual = decrypt_all(&mut server, &gated.out);
    assert_eq!(actual.len(), initial.len() + 1);
    assert_eq!(&actual[..initial.len()], initial.as_slice()); assert_eq!(actual[initial.len()], b'y');
}

#[test]
fn tls_application_write_fragment_overhead_is_bounded_for_pinned_suites() {
    let suites = rustls::crypto::ring::default_provider().cipher_suites;
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
            let mut crypto = rustls::crypto::ring::default_provider();
            crypto.cipher_suites = vec![suite]; let crypto = Arc::new(crypto);
            let server_config = ServerConfig::builder_with_provider(crypto.clone())
                .with_protocol_versions(&[suite.version()]).unwrap().with_no_client_auth().with_single_cert(
                    vec![cert.cert.der().clone()], PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
            let client_config = ClientConfig::builder_with_provider(crypto)
                .with_protocol_versions(&[suite.version()]).unwrap().with_root_certificates(roots).with_no_client_auth();
            let mut client = ClientConnection::new(Arc::new(client_config), ServerName::try_from("localhost").unwrap()).unwrap();
            let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
            settle(&mut client, &mut server);
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
            assert_eq!(decrypt_all(&mut server, &wire), payload[..accepted]); exercised += 1;
        }
    }
    assert_eq!(exercised, 12);
}

// Lower only the test suite's refresh threshold, retaining real AES-GCM and
// key scheduling. Production uses ring's unmodified confidentiality limits.
#[test]
fn tls_automatic_refresh_bounds_records_at_each_batch_boundary() {
    static SHORT_KEYS: std::sync::LazyLock<Tls13CipherSuite> = std::sync::LazyLock::new(|| {
        let base = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256.tls13().unwrap();
        Tls13CipherSuite {
            common: CipherSuiteCommon { suite: base.common.suite, hash_provider: base.common.hash_provider, confidentiality_limit: 8 },
            hkdf_provider: base.hkdf_provider, aead_alg: base.aead_alg, quic: None,
        }
    });
    let mut observed_refreshes = 0;
    for warmup in 0..8 {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
        let mut crypto = rustls::crypto::ring::default_provider();
        crypto.cipher_suites = vec![SupportedCipherSuite::Tls13(&SHORT_KEYS)]; let crypto = Arc::new(crypto);
        let server_config = ServerConfig::builder_with_provider(crypto.clone())
            .with_protocol_versions(&[&TLS13]).unwrap()
            .with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
        let client_config = ClientConfig::builder_with_provider(crypto)
            .with_protocol_versions(&[&TLS13]).unwrap()
            .with_root_certificates(roots).with_no_client_auth();
        let mut client = ClientConnection::new(Arc::new(client_config), ServerName::try_from("localhost").unwrap()).unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();
        settle(&mut client, &mut server);
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
        assert_eq!(decrypt_all(&mut server, &wire), payload[..accepted]);
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
    settle(&mut client, &mut server);
    assert_eq!(client.protocol_version(), Some(ProtocolVersion::TLSv1_3));
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

#[test]
fn tls_key_update_burst_limit_rejects_without_response_or_replay() {
    for updates in [32, 33] {
        let (listener, acceptor, roots) = tls();
        let config = config(listener.local_addr().unwrap().port());
        let provider = thread::spawn(move || {
            let mut socket = accept_tls(&listener, &acceptor).unwrap();
            assert_eq!(socket.conn.protocol_version(), Some(ProtocolVersion::TLSv1_3));
            read_head_and_empty_body(&mut socket);
            for _ in 0..updates { socket.conn.refresh_traffic_keys().unwrap(); }
            let _ = socket.flush();
            let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = socket.write_all(response);
            close_tls(&mut socket);
            no_second_connection(&listener);
        });
        let transport = HttpsTransport::with_roots(roots, Duration::from_secs(3)).unwrap();
        let mut output = Output::new(); let mut log = Log::default(); let mut input = &b""[..];
        let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
        provider.join().unwrap();
        if updates == 32 {
            result.unwrap(); assert_eq!(output.status, Some(200));
            assert_eq!(output.bytes, b"ok"); assert_eq!(log.download, b"ok");
        } else {
            assert!(matches!(result, Err(TransportError::Http)));
            assert!(output.status.is_none()); assert!(output.bytes.is_empty());
            assert!(log.download.is_empty());
        }
        assert_eq!(config.usage(), Some((0, 1)));
    }
}

#[test]
fn oversized_handshake_is_rejected_from_its_length_before_upload() {
    for declared in [65535usize, 65536] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let config = config(listener.local_addr().unwrap().port());
        let provider = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut record = [0; 5]; socket.read_exact(&mut record).unwrap();
            assert_eq!(record[0], 22); // ClientHello handshake record.
            let size = u16::from_be_bytes([record[3], record[4]]) as usize;
            assert!(size <= 18432);
            let mut hello = vec![0; size]; socket.read_exact(&mut hello).unwrap();
            // Send only a ServerHello header, withhold its entire payload,
            // and keep the socket open. The within-limit control must wait;
            // the oversized declaration must be rejected without EOF/data.
            socket.write_all(&[22, 3, 3, 0, 4, 2,
                (declared >> 16) as u8, (declared >> 8) as u8, declared as u8]).unwrap();
            let mut tail = Vec::new(); let _ = socket.read_to_end(&mut tail);
            assert!(!tail.windows(b"provider-secret".len()).any(|w| w == b"provider-secret"));
        });
        let transport = HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(1)).unwrap();
        let mut output = Output::new(); let mut log = Log::default();
        let mut input = &b"secret body"[..];
        let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
        provider.join().unwrap();
        let expected = if declared == 65535 { TransportError::Timeout } else { TransportError::Tls };
        assert!(matches!(result, Err(ref error) if *error == expected), "{}", describe(&result));
        assert_eq!(input, b"secret body");
        assert!(output.status.is_none()); assert!(output.bytes.is_empty());
        assert!(log.upload.is_empty()); assert!(log.download.is_empty());
        assert_eq!(config.usage(), Some((0, 1)));
    }
}

#[test]
fn redirects_are_returned_without_opening_a_second_connection() {
    let (listener, acceptor, roots) = tls();
    let config = config(listener.local_addr().unwrap().port());
    let upstream = thread::spawn(move || {
        let mut socket = accept_tls(&listener, &acceptor).unwrap();
        read_request(&mut socket).unwrap();
        write_response(&mut socket, 307, &[("location", "https://attacker.example/")], b"redirect").unwrap();
        close_tls(&mut socket);
        no_second_connection(&listener);
    });
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
    upstream.join().unwrap();
    result.unwrap(); assert_eq!(output.status, Some(307));
    assert!(!has(&output.headers, "location")); assert_eq!(output.bytes, b"redirect");
}

#[test]
fn deadline_drops_connection_and_releases_admission() {
    let (listener, acceptor, roots) = tls();
    let config = config(listener.local_addr().unwrap().port());
    let upstream = thread::spawn(move || {
        if let Ok(mut tls) = accept_tls(&listener, &acceptor) {
            let mut bytes = Vec::new(); let _ = tls.read_to_end(&mut bytes);
        }
    });
    let transport = HttpsTransport::with_roots(roots, Duration::from_millis(50)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let started = std::time::Instant::now();
    let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
    assert!(started.elapsed() < Duration::from_secs(5));
    upstream.join().unwrap();
    assert!(matches!(result, Err(TransportError::Timeout)), "{}", describe(&result));
    assert!(output.status.is_none()); assert!(config.admit(b"gateway", 7).is_ok());
}

#[test]
fn truncated_response_is_never_reported_as_success() {
    let (listener, acceptor, roots) = tls();
    let config = config(listener.local_addr().unwrap().port());
    let upstream = thread::spawn(move || {
        let mut socket = accept_tls(&listener, &acceptor).unwrap();
        read_until_last_chunk(&mut socket);
        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial").unwrap();
        close_tls(&mut socket);
    });
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
    upstream.join().unwrap();
    assert!(matches!(result, Err(TransportError::Http | TransportError::Download)), "{}", describe(&result));
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[test]
fn unsolicited_protocol_switch_is_rejected_before_client_headers() {
    let (listener, acceptor, roots) = tls();
    let config = config(listener.local_addr().unwrap().port());
    let upstream = thread::spawn(move || {
        let mut socket = accept_tls(&listener, &acceptor).unwrap();
        read_until_last_chunk(&mut socket);
        socket.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\nupgraded-data").unwrap();
        let _ = socket.flush();
        let mut tail = Vec::new(); let _ = socket.read_to_end(&mut tail);
        assert!(tail.is_empty(), "gateway must not speak the upgraded protocol");
        no_second_connection(&listener);
    });
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(2)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
    upstream.join().unwrap();
    assert!(output.status.is_none(), "unexpected client status: {:?}", output.status);
    assert!(matches!(result, Err(TransportError::Http | TransportError::Metadata)), "{}", describe(&result));
    assert!(output.bytes.is_empty());
    assert_eq!(log.upload, b"{}"); assert!(log.download.is_empty());
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[test]
fn interim_response_does_not_replace_final_status_or_payload() {
    let (listener, acceptor, roots) = tls();
    let config = config(listener.local_addr().unwrap().port());
    let upstream = thread::spawn(move || {
        let mut socket = accept_tls(&listener, &acceptor).unwrap();
        read_until_last_chunk(&mut socket);
        socket.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </ignored>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}").unwrap();
        let _ = socket.flush();
        let mut tail = Vec::new(); let _ = socket.read_to_end(&mut tail);
    });
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(2)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
    upstream.join().unwrap();
    assert_eq!(result.unwrap().download.accepted_bytes(), 2);
    assert_eq!(output.status, Some(200)); assert_eq!(output.bytes, b"{}");
    assert!(!has(&output.headers, "link"));
    assert_eq!(log.upload, b"{}"); assert_eq!(log.download, b"{}");
    assert!(config.admit(b"gateway", 7).is_ok());
}

#[test]
fn cancelling_tls_handshake_drops_socket_and_returns_owned_request_credit() {
    let (listener, _acceptor, roots) = tls();
    let config = config(listener.local_addr().unwrap().port());
    let transport = HttpsTransport::with_roots(roots, Duration::from_secs(30)).unwrap();
    let mut output = Output::new(); let mut log = Log::default(); let mut input = &b"{}"[..];
    let http = worker_http();
    let cancel = Cancel::new();
    let mut prepared = prepare(&config);
    let (result, handshake_bytes) = thread::scope(|s| {
        let exchange = s.spawn(|| transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http, &cancel));
        // Accept TCP but never answer the TLS ClientHello. No provider HTTP
        // request should have been submitted at this cancellation point.
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut record_header = [0; 5];
        socket.read_exact(&mut record_header).unwrap();
        assert_eq!(record_header[0], 22); // TLS handshake record
        assert!(!exchange.is_finished(), "exchange finished during handshake");
        assert!(config.admit(b"gateway", 7).is_err());
        cancel.cancel();
        let result = exchange.join().unwrap();
        let mut handshake_bytes = Vec::new();
        let _ = socket.read_to_end(&mut handshake_bytes);
        (result, handshake_bytes)
    });
    assert!(matches!(result, Err(TransportError::Cancelled)), "{}", describe(&result));
    drop(prepared);
    let replacement = config.admit(b"gateway", 7).unwrap();
    assert!(!handshake_bytes.windows(b"provider-secret".len()).any(|w| w == b"provider-secret"));
    assert!(output.status.is_none());
    assert!(output.bytes.is_empty());
    assert!(log.upload.is_empty());
    assert!(log.download.is_empty());
    drop(replacement);
}

#[test]
fn tls_session_cache_bounds_servers_and_tickets_without_disabling_resumption() {
    fn client_connect(listener: &TcpListener, transport: &HttpsTransport, name: &str) -> StreamOwned<ClientConnection, TcpStream> {
        let tcp = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let connection = ClientConnection::new(transport.config.clone(), ServerName::try_from(name.to_owned()).unwrap()).unwrap();
        let mut stream = StreamOwned::new(connection, tcp);
        while stream.conn.is_handshaking() { stream.conn.complete_io(&mut stream.sock).unwrap(); }
        stream
    }
    fn connect(listener: &TcpListener, server: &Arc<ServerConfig>, transport: &HttpsTransport, name: &str, expected: HandshakeKind) {
        thread::scope(|s| {
            let provider = s.spawn(|| {
                let mut stream = accept_tls(listener, server).unwrap();
                assert_eq!(stream.conn.handshake_kind(), Some(expected));
                assert_eq!(stream.conn.server_name(), Some(name));
                stream.write_all(b"ticket delivery").unwrap();
                close_tls(&mut stream);
            });
            let mut stream = client_connect(listener, transport, name);
            assert_eq!(stream.conn.handshake_kind(), Some(expected));
            // Reading through close_notify processes post-handshake tickets.
            let mut received = Vec::new(); stream.read_to_end(&mut received).unwrap();
            assert_eq!(received, b"ticket delivery");
            provider.join().unwrap();
        });
    }
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
        server.session_storage = rustls::server::ServerSessionMemoryCache::new(4096);
        server.send_tls13_tickets = 24; // deliberately exceeds the eight-ticket client budget
        let acceptor = Arc::new(server.clone());
        server.send_tls13_tickets = 0; // shares server-side session storage with the first config
        let no_tickets = Arc::new(server);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let transport = HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap();
        connect(&listener, &acceptor, &transport, &names[0], HandshakeKind::Full);
        // Keep a resumed connection alive across eviction. Its session and
        // authenticated peer state must not be treated as freed cache data.
        let (mut held_provider, mut held_client) = thread::scope(|s| {
            let provider = s.spawn(|| accept_tls(&listener, &acceptor).unwrap());
            let client = client_connect(&listener, &transport, &names[0]);
            (provider.join().unwrap(), client)
        });
        assert_eq!(held_provider.conn.handshake_kind(), Some(HandshakeKind::Resumed));
        assert_eq!(held_client.conn.handshake_kind(), Some(HandshakeKind::Resumed));
        let mut order: Vec<_> = (1..33).map(|i| (i, HandshakeKind::Full)).collect();
        order.push((0, HandshakeKind::Full)); // oldest entry was evicted
        order.push((0, HandshakeKind::Resumed)); // replacement remains usable
        for (index, expected) in order {
            connect(&listener, &acceptor, &transport, &names[index], expected);
        }
        assert!(!held_client.conn.peer_certificates().unwrap().is_empty());
        thread::scope(|s| {
            let send = s.spawn(|| {
                held_provider.write_all(b"alive after eviction").unwrap();
                close_tls(&mut held_provider);
            });
            let mut received = Vec::new();
            held_client.read_to_end(&mut received).unwrap();
            assert_eq!(received, b"alive after eviction");
            send.join().unwrap();
        });
        drop(held_provider); drop(held_client);
        if version.version == TLS13.version {
            // Only eight of the last 24 issued tickets may remain. Consume
            // them without replacement; the ninth connection must be full.
            for _ in 0..8 {
                connect(&listener, &no_tickets, &transport, &names[0], HandshakeKind::Resumed);
            }
            connect(&listener, &no_tickets, &transport, &names[0], HandshakeKind::Full);
        }
    }
}

#[test]
fn upstream_wire_head_and_header_count_limits_cover_status_line() {
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
        let (listener, acceptor, roots) = tls();
        let config = config(listener.local_addr().unwrap().port());
        let transport = HttpsTransport::with_roots(roots, Duration::from_secs(3)).unwrap();
        let provider = thread::spawn(move || {
            let mut socket = accept_tls(&listener, &acceptor).unwrap();
            read_head_and_empty_body(&mut socket);
            let _ = socket.write_all(response.as_bytes());
            close_tls(&mut socket);
        });
        let mut output = Output::new(); let mut log = Log::default(); let mut input = &b""[..];
        let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
        provider.join().unwrap();
        if accepted { result.unwrap(); assert_eq!(output.status, Some(200)); }
        else { assert!(matches!(result, Err(TransportError::Http)), "{}", describe(&result)); assert!(output.status.is_none()); }
        assert!(output.bytes.is_empty()); assert!(log.download.is_empty());
        assert!(config.admit(b"gateway", 7).is_ok());
    }
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

#[test]
fn retry_cookie_is_echoed_above_the_buffer_limit_and_closure_fails_before_upload() {
    fn read_handshake_message(socket: &mut TcpStream) -> Vec<u8> {
        let mut handshake = Vec::new();
        loop {
            let mut header = [0; 5]; socket.read_exact(&mut header).unwrap();
            let mut payload = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            socket.read_exact(&mut payload).unwrap();
            match header[0] { 22 => handshake.extend_from_slice(&payload), 20 => assert_eq!(payload, [1]), other => panic!("record {other}") }
            if handshake.len() >= 4 && handshake.len() == 4 + (((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize) { return handshake; }
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = config(listener.local_addr().unwrap().port());
    let provider = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let first = read_handshake_message(&mut socket);
        let (session, declared, _) = hello_parts(&first);
        let cookie_len = 65535 - declared - 6;
        for record in handshake_records(&hello_retry_request(session, cookie_len)) { socket.write_all(&record).unwrap(); }
        let second = read_handshake_message(&mut socket);
        let (_, declared, extensions) = hello_parts(&second);
        assert_eq!(declared, 65535); assert_eq!(extensions.len(), 65535);
        assert_eq!(cookie_extension(extensions), Some(&vec![42u8; cookie_len][..]));
        assert!(second.len() > TLS_APPLICATION_BUFFER);
        // Close without a ServerHello; the client must fail without any request bytes.
        drop(socket);
    });
    let transport = HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(5)).unwrap();
    let mut output = Output::new(); let mut log = Log::default();
    let mut input = &b"secret body"[..];
    let result = exchange(&transport, &config, &mut input, &mut output, &mut log);
    provider.join().unwrap();
    assert!(matches!(result, Err(TransportError::Tls)), "{}", describe(&result));
    assert_eq!(input, b"secret body");
    assert!(output.status.is_none()); assert!(output.bytes.is_empty());
    assert!(log.upload.is_empty()); assert!(log.download.is_empty());
    assert_eq!(config.usage(), Some((0, 1)));
}

#[test]
fn tls_peer_certificate_chain_is_owned_per_connection_and_restored_on_resumption() {
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
