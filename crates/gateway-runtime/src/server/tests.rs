use super::*;
use crate::disk_log::LogReader;
use http_body_util::BodyExt;
use rcgen::generate_simple_self_signed;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::File, sync::Mutex};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, rustls::{RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer}};

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let mut random = [0; 16]; getrandom::fill(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("soundgate-server-{name}"));
        std::fs::create_dir(&path).unwrap(); Self(path)
    }
}
impl Drop for TempDir { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn config(port: u16, availability: bool) -> GatewayConfig {
    let routes = json!([{"tenant":1,"selector":7,"origin":0,"credential":0}]);
    let root = json!({"identities":[{"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"gateway"))}],
        "destinations":[format!("https://localhost:{port}/v1/messages")],
        "credentials":[{"tenant":1,"kind":"api_key","env":"KEY"}],"grants":routes,
        "limits":{"requests":1,"chunk_bytes":3},"logging":if availability { "availability" } else { "strict" }});
    GatewayConfig::from_json(&serde_json::to_vec(&root).unwrap(), &serde_json::to_vec(&json!({"routes":routes})).unwrap(),
        |_| Some("provider-secret".into())).unwrap()
}
async fn send(port: u16, path: &str, token: &str, method: &str) -> (Response<Incoming>, JoinHandle<()>) {
    let socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(socket)).await.unwrap();
    let connection = tokio::spawn(async move { let _ = conn.await; });
    let request = Request::builder().method(method).uri(path).header("host", "attacker.example")
        .header("authorization", format!("Bearer {token}")).header("x-api-key", "caller-secret")
        .body(Full::new(Bytes::from_static(b"{\"stream\":true}"))).unwrap();
    (sender.send_request(request).await.unwrap(), connection)
}

#[derive(Clone, Copy)]
enum Stop { None, Disconnect, Drain, Abort }

async fn exercise(availability: bool, failed_log: bool, truncated: bool, stop: Stop) {
    tokio::time::timeout(Duration::from_secs(25), async {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
        let tls = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = config(upstream.local_addr().unwrap().port(), availability);
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let log = DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap();
        if failed_log { log.inject_failure(); }
        // Shutdown tests must expire through the drain, not the transport deadline.
        let deadline = if matches!(stop, Stop::Drain | Stop::Abort) { 60 } else { 5 };
        let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(deadline)).unwrap(), log);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); let port = listener.local_addr().unwrap().port();
        let (shutdown, stopped) = oneshot::channel();
        let gateway = tokio::spawn(serve(listener, app.clone(), 4, Duration::from_secs(deadline + 3), async { let _ = stopped.await; }));
        for (path, token, method, status) in [("/healthz", "", "GET", 200), ("/readyz", "", "GET", if failed_log && !availability { 503 } else { 200 }),
            ("/routes/7", "wrong", "POST", 401), ("/routes/99", "gateway", "POST", 401)] {
            let (r, c) = send(port, path, token, method).await;
            assert_eq!(r.status().as_u16(), status); r.collect().await.unwrap(); c.await.unwrap();
        }
        // Rejected requests must not have connected to the provider.
        assert!(tokio::time::timeout(Duration::from_millis(20), upstream.accept()).await.is_err());
        if failed_log && !availability {
            let (r, c) = send(port, "/routes/7", "gateway", "POST").await;
            assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
            r.collect().await.unwrap(); c.await.unwrap();
            assert!(tokio::time::timeout(Duration::from_millis(20), upstream.accept()).await.is_err());
            shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
            assert!(app.workers.is_empty()); assert_eq!(app.audit_gaps(), 0);
            return;
        }
        let (release, waiting) = oneshot::channel(); let waiting = Arc::new(Mutex::new(Some(waiting)));
        let upstream_task = tokio::spawn(async move {
            let (socket, _) = upstream.accept().await.unwrap(); let socket = acceptor.accept(socket).await.unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let waiting = waiting.lock().unwrap().take().unwrap();
                async move {
                    assert_eq!(request.uri(), "/v1/messages");
                    assert_eq!(request.headers()["x-api-key"], "provider-secret");
                    assert!(!request.headers().contains_key("authorization"));
                    assert_eq!(request.collect().await.unwrap().to_bytes(), "{\"stream\":true}");
                    let (mut writer, body) = http_body::channel(16);
                    tokio::spawn(async move {
                        writer.write_all(b"data: hello\n\n").await.unwrap();
                        if waiting.await.is_err() { return; }
                        if truncated { return; } // no End marker: simulate a provider disconnect
                        if writer.write_all(b"data: [DONE]\n\n").await.is_ok() { let _ = writer.shutdown().await; }
                    });
                    Ok::<_, Infallible>(Response::builder().header("content-type", "text/event-stream")
                        .header("set-cookie", "provider-secret").body(body).unwrap())
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
        });
        let (mut response, connection) = send(port, "/routes/7", "gateway", "POST").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("set-cookie"));
        let first = response.body_mut().frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(!first.is_empty()); // arrives while the upstream is waiting, before EOF
        // The first request still owns the sole admission slot while streaming.
        let (busy, busy_connection) = send(port, "/routes/7", "gateway", "POST").await;
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        busy.collect().await.unwrap(); busy_connection.await.unwrap();
        if matches!(stop, Stop::Drain | Stop::Abort) {
            let started = tokio::time::Instant::now();
            shutdown.send(()).unwrap();
            // Observe listener closure before releasing the provider. This proves
            // the stream is completing during drain, rather than before shutdown.
            tokio::time::timeout(Duration::from_secs(1), async {
                while TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                    tokio::task::yield_now().await;
                }
            }).await.unwrap();
            assert!(!gateway.is_finished());
            if matches!(stop, Stop::Drain) {
                release.send(()).unwrap();
                let mut bytes = first.to_vec();
                bytes.extend_from_slice(&response.collect().await.unwrap().to_bytes());
                assert_eq!(bytes, b"data: hello\n\ndata: [DONE]\n\n");
                tokio::time::timeout(Duration::from_secs(2), gateway).await.unwrap().unwrap().unwrap();
                assert_eq!(app.failed_exchanges(), 0);
            } else {
                // The provider remains blocked and both network deadlines are
                // over a minute away: only the ten-second drain can end this.
                tokio::time::timeout(Duration::from_secs(15), gateway).await.unwrap().unwrap().unwrap();
                assert!(started.elapsed() >= Duration::from_secs(10));
                assert!(response.collect().await.is_err());
                drop(release);
            }
            connection.await.unwrap(); upstream_task.await.unwrap();
            assert!(app.workers.is_empty());
            assert!(app.config.admit(b"gateway", 7).is_ok());
            return;
        }
        if matches!(stop, Stop::Disconnect) {
            drop(response); connection.abort(); let _ = connection.await;
            // No new provider output is needed to make cancellation observable.
            tokio::time::timeout(Duration::from_secs(1), async {
                while !app.workers.is_empty() { tokio::task::yield_now().await; }
            }).await.unwrap();
            assert!(app.config.admit(b"gateway", 7).is_ok());
            drop(release); upstream_task.await.unwrap();
            shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
            assert!(app.workers.is_empty()); return;
        }
        release.send(()).unwrap();
        let rest = response.collect().await;
        let mut bytes = first.to_vec();
        if truncated { assert!(rest.is_err()); }
        else {
            bytes.extend_from_slice(&rest.unwrap().to_bytes());
            assert_eq!(bytes, b"data: hello\n\ndata: [DONE]\n\n");
        }
        connection.await.unwrap(); upstream_task.await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !app.workers.is_empty() { tokio::task::yield_now().await; }
        }).await.unwrap();
        let (metrics, metrics_connection) = send(port, "/metrics", "", "GET").await;
        let metrics = metrics.collect().await.unwrap().to_bytes(); metrics_connection.await.unwrap();
        let metrics = std::str::from_utf8(&metrics).unwrap();
        assert!(metrics.contains(&format!("soundgate_audit_gap_requests_total {}\n", u8::from(failed_log && availability))));
        assert!(metrics.contains(&format!("soundgate_failed_exchanges_total {}\n", u8::from(truncated))));
        assert!(metrics.contains(&format!("soundgate_audit_healthy {}\n", u8::from(!failed_log))));
        shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
        assert!(app.workers.is_empty()); assert_eq!(app.failed_exchanges(), u64::from(truncated));
        assert_eq!(app.audit_gaps(), u64::from(failed_log && availability));
        assert!(app.config.admit(b"gateway", 7).is_ok());
        let mut reader = LogReader::new(File::open(path).unwrap()).unwrap();
        let mut upload = Vec::new(); let mut download = Vec::new();
        while let Some(r) = reader.next_record().unwrap() {
            match r.direction { crate::transfer::Direction::Upload => &mut upload,
                crate::transfer::Direction::Download => &mut download }.extend(r.bytes);
        }
        if failed_log { assert!(upload.is_empty()); assert!(download.is_empty()); }
        else {
            assert_eq!(upload, b"{\"stream\":true}");
            if !truncated { assert_eq!(download, bytes); }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn worker_body_drop_aborts_pending_request() {
    let tracker = TaskTracker::new();
    let task = tracker.spawn(std::future::pending::<()>());
    let (writer, body) = http_body::channel(16);
    let response = GatewayBody::Stream { body, _task: AbortOnDrop(Some(task)) };
    drop(response); drop(writer); tracker.close();
    tokio::time::timeout(Duration::from_secs(1), tracker.wait()).await.unwrap();
    assert!(tracker.is_empty());
}

#[tokio::test]
async fn full_gateway_streams_before_upstream_eof_and_logs_exact_bytes() { exercise(false, false, false, Stop::None).await; }
#[tokio::test]
async fn strict_log_failure_prevents_even_upstream_connection() { exercise(false, true, false, Stop::None).await; }
#[tokio::test]
async fn availability_log_failure_preserves_stream_and_reports_gap() { exercise(true, true, false, Stop::None).await; }
#[tokio::test]
async fn truncated_generation_is_an_error_and_still_reports_audit_gap() { exercise(true, true, true, Stop::None).await; }

#[tokio::test]
async fn concurrent_tenants_keep_credentials_bodies_and_audit_records_isolated() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
        let tls = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let routes = json!([
            {"tenant":1,"selector":7,"origin":0,"credential":0},
            {"tenant":2,"selector":7,"origin":0,"credential":1}
        ]);
        let root = json!({
            "identities":[
                {"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"tenant-one"))},
                {"tenant":2,"sha256":format!("{:x}",Sha256::digest(b"tenant-two"))}
            ],
            "destinations":[format!("https://localhost:{}/v1/messages", upstream.local_addr().unwrap().port())],
            "credentials":[{"tenant":1,"kind":"api_key","env":"KEY_ONE"},
                           {"tenant":2,"kind":"api_key","env":"KEY_TWO"}],
            "grants":routes,"limits":{"requests":2,"chunk_bytes":3},"logging":"strict"
        });
        let config = GatewayConfig::from_json(&serde_json::to_vec(&root).unwrap(),
            &serde_json::to_vec(&json!({"routes":routes})).unwrap(), |name| Some(format!("secret-{name}"))).unwrap();
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(),
            DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); let port = listener.local_addr().unwrap().port();
        let (shutdown, stopped) = oneshot::channel();
        let gateway = tokio::spawn(serve(listener, app.clone(), 4, Duration::from_secs(8), async { let _ = stopped.await; }));
        // Neither provider response starts until both tenant requests have arrived.
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let upstream_task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            for _ in 0..2 {
                let (socket, _) = upstream.accept().await.unwrap();
                let acceptor = acceptor.clone(); let barrier = barrier.clone();
                connections.spawn(async move {
                    let socket = acceptor.accept(socket).await.unwrap();
                    let service = service_fn(move |request: Request<Incoming>| {
                        let barrier = barrier.clone();
                        async move {
                            let credential = request.headers()["x-api-key"].to_str().unwrap().to_owned();
                            assert!(!request.headers().contains_key("authorization"));
                            let bytes = request.collect().await.unwrap().to_bytes();
                            match bytes.as_ref() {
                                b"body-one" => assert_eq!(credential, "secret-KEY_ONE"),
                                b"body-two" => assert_eq!(credential, "secret-KEY_TWO"),
                                _ => panic!("unexpected tenant body"),
                            }
                            barrier.wait().await;
                            Ok::<_, Infallible>(Response::new(Full::new(bytes)))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
                });
            }
            while let Some(result) = connections.join_next().await { result.unwrap(); }
        });
        let client = |token: &'static str, bytes: &'static [u8]| async move {
            let socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket)).await.unwrap();
            let connection = tokio::spawn(async move { let _ = connection.await; });
            let request = Request::builder().method("POST").uri("/routes/7").header("host", "localhost")
                .header("authorization", format!("Bearer {token}")).header("x-api-key", "malicious-override")
                .body(Full::new(Bytes::from_static(bytes))).unwrap();
            let response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.collect().await.unwrap().to_bytes(), bytes);
            connection.await.unwrap();
        };
        tokio::join!(client("tenant-one", b"body-one"), client("tenant-two", b"body-two"));
        upstream_task.await.unwrap(); shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
        assert!(app.workers.is_empty()); assert_eq!(app.failed_exchanges(), 0);
        let mut reader = LogReader::new(File::open(path).unwrap()).unwrap();
        let mut records = std::collections::BTreeMap::<u64, (u64, u64, Vec<u8>, Vec<u8>)>::new();
        while let Some(record) = reader.next_record().unwrap() {
            let entry = records.entry(record.request).or_insert((record.tenant, 0, Vec::new(), Vec::new()));
            assert_eq!(entry.0, record.tenant); assert_eq!(record.chunk, entry.1 + 1); entry.1 = record.chunk;
            match record.direction { crate::transfer::Direction::Upload => &mut entry.2,
                crate::transfer::Direction::Download => &mut entry.3 }.extend(record.bytes);
        }
        assert_eq!(records.len(), 2);
        let tenants: std::collections::BTreeSet<_> = records.values().map(|r| r.0).collect();
        assert_eq!(tenants, [1, 2].into_iter().collect());
        for (tenant, _, upload, download) in records.values() {
            let expected = if *tenant == 1 { b"body-one" } else { b"body-two" };
            assert_eq!(upload, expected); assert_eq!(download, expected);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn client_disconnect_cancels_stalled_provider_and_releases_request() { exercise(false, false, false, Stop::Disconnect).await; }

#[tokio::test]
async fn shutdown_drains_active_response_without_truncation() {
    exercise(false, false, false, Stop::Drain).await;
}

#[tokio::test]
async fn shutdown_aborts_stalled_response_after_drain_and_releases_request() {
    exercise(false, false, false, Stop::Abort).await;
}
