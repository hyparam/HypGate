use super::*;
use crate::disk_log::LogReader;
use http_body_util::BodyExt;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs::File, sync::Mutex};
use tokio::{io::AsyncReadExt, net::TcpStream};
use tokio_rustls::{TlsAcceptor, rustls::RootCertStore};
use crate::test_support::{self_signed, tls, TempDir};

mod benchmark;
mod memory;
mod overload;
mod process_crash;
mod stalled_log;

fn config(port: u16, availability: bool) -> GatewayConfig { config_with_limits(port, availability, 1, 3) }
fn config_with_limits(port: u16, availability: bool, requests: usize, chunk_bytes: usize) -> GatewayConfig {
    let routes = json!([{"tenant":1,"selector":7,"origin":0,"credential":0}]);
    let root = json!({"identities":[{"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"gateway"))}],
        "destinations":[format!("https://localhost:{port}/v1/messages")],
        "credentials":[{"tenant":1,"kind":"api_key","env":"KEY"}],"grants":routes,
        "limits":{"requests":requests,"chunk_bytes":chunk_bytes},"logging":if availability { "availability" } else { "strict" }});
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
/// Serve `app` on a fresh loopback port until the returned sender fires or drops.
async fn spawn_gateway(app: &Arc<Gateway>, connections: usize, deadline: Duration)
    -> (u16, oneshot::Sender<()>, JoinHandle<io::Result<()>>)
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (shutdown, stopped) = oneshot::channel();
    let gateway = tokio::spawn(serve(listener, app.clone(), connections, deadline, async { let _ = stopped.await; }));
    (port, shutdown, gateway)
}

/// Every record of a finished log, in order.
fn audit_records(path: &std::path::Path) -> Vec<crate::disk_log::StoredRecord> {
    let mut reader = LogReader::new(File::open(path).unwrap()).unwrap();
    let records: Vec<_> = std::iter::from_fn(|| reader.next_record().unwrap()).collect();
    assert_eq!(reader.valid_end(), std::fs::metadata(path).unwrap().len());
    records
}
/// Checks one request's trace: kind 2, upload chunks, kind 3 when `status` is
/// given, download chunks, then kind 4 with `outcome`; monotone timestamps,
/// the configured destination, selector 7, and the body chunk ids 1 and up.
/// Returns the concatenated upload and download bytes.
fn assert_trace(records: &[crate::disk_log::StoredRecord], destination: &str, status: Option<u16>, outcome: u8) -> (Vec<u8>, Vec<u8>) {
    use crate::{disk_log::Metadata, transfer::RecordKind};
    let request = records.first().expect("a logged request").request;
    assert!(records.iter().all(|r| r.request == request && r.tenant == 1), "{records:?}");
    let kinds: Vec<_> = records.iter().map(|r| r.kind).collect();
    let (mut upload, mut download) = (Vec::new(), Vec::new());
    let mut phase = 0; let mut chunk = 0; let mut last_time = 0;
    for record in records {
        if record.direction().is_some() {
            assert_eq!(record.chunk, chunk + 1, "body chunks are numbered from 1: {kinds:?}"); chunk = record.chunk;
        } else { assert_eq!(record.chunk, 0, "metadata uses chunk 0: {kinds:?}"); }
        match (record.kind, record.metadata()) {
            (RecordKind::RequestStart, Some(Metadata::RequestStart(start))) => {
                assert_eq!(phase, 0, "{kinds:?}"); phase = 1;
                assert_eq!(std::str::from_utf8(&start.destination).unwrap(), destination);
                assert_eq!(start.selector, 7); last_time = start.time_ms;
            }
            (RecordKind::Upload, None) => { assert_eq!(phase, 1, "{kinds:?}"); upload.extend(&record.bytes); }
            (RecordKind::ResponseHead, Some(Metadata::ResponseHead(head))) => {
                assert_eq!(phase, 1, "{kinds:?}"); phase = 2;
                assert_eq!(Some(head.status), status); assert!(head.time_ms >= last_time); last_time = head.time_ms;
            }
            (RecordKind::Download, None) => { assert_eq!(phase, 2, "{kinds:?}"); download.extend(&record.bytes); }
            (RecordKind::Completion, Some(Metadata::Completion(done))) => {
                assert!(phase == 1 || phase == 2, "{kinds:?}"); phase = 3;
                assert_eq!(done.outcome, outcome, "{kinds:?}"); assert!(done.time_ms >= last_time);
                if outcome == 0 {
                    assert_eq!((done.upload_bytes, done.download_bytes), (upload.len() as u64, download.len() as u64));
                } else { assert_eq!((done.upload_bytes, done.download_bytes), (0, 0)); }
            }
            other => panic!("unexpected record {other:?} in {kinds:?}"),
        }
    }
    assert_eq!(phase, 3, "trace must end with a completion: {kinds:?}");
    if status.is_none() { assert!(!kinds.contains(&RecordKind::ResponseHead)); }
    (upload, download)
}

// One provider connection that streams a first event, then waits for `waiting`
// before finishing cleanly or, when truncated, disconnecting without an End marker.
fn stalling_provider(upstream: TcpListener, acceptor: TlsAcceptor, waiting: oneshot::Receiver<()>, truncated: bool) -> JoinHandle<()> {
    let waiting = Arc::new(Mutex::new(Some(waiting)));
    tokio::spawn(async move {
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
    })
}

#[derive(Clone, Copy)]
enum Stop { None, Disconnect, Drain, Abort, SharedAbort }

async fn exercise(availability: bool, failed_log: bool, truncated: bool, stop: Stop) {
    tokio::time::timeout(Duration::from_secs(25), async {
        let (upstream, acceptor, roots) = tls().await;
        let config = config(upstream.local_addr().unwrap().port(), availability);
        let destination = format!("https://localhost:{}/v1/messages", upstream.local_addr().unwrap().port());
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let log = DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap();
        if failed_log { log.inject_failure(); }
        // Shutdown tests must expire through the drain, not the transport deadline.
        let deadline = if matches!(stop, Stop::Drain | Stop::Abort | Stop::SharedAbort) { 60 } else { 5 };
        let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(deadline)).unwrap(), log);
        let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(deadline + 3)).await;
        let shutdown_port = port;
        let mut shared = None;
        let port = if matches!(stop, Stop::SharedAbort) {
            let (port, shutdown, task) = spawn_gateway(&app, 4, Duration::from_secs(63)).await;
            shared = Some((shutdown, task));
            port
        } else { port };
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
        let (release, waiting) = oneshot::channel();
        let upstream_task = stalling_provider(upstream, acceptor, waiting, truncated);
        let (mut response, connection) = send(port, "/routes/7", "gateway", "POST").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!response.headers().contains_key("set-cookie"));
        let first = response.body_mut().frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(!first.is_empty()); // arrives while the upstream is waiting, before EOF
        // The first request still owns the sole admission slot while streaming.
        let (busy, busy_connection) = send(port, "/routes/7", "gateway", "POST").await;
        assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
        busy.collect().await.unwrap(); busy_connection.await.unwrap();
        let (metrics, metrics_connection) = send(port, "/metrics", "", "GET").await;
        let metrics = metrics.collect().await.unwrap().to_bytes(); metrics_connection.await.unwrap();
        let metrics = std::str::from_utf8(&metrics).unwrap();
        assert!(metrics.contains("soundgate_admission_healthy 1\n"));
        assert!(metrics.contains("soundgate_requests_active 1\n"));
        assert!(metrics.contains("soundgate_requests_limit 1\n"));
        if matches!(stop, Stop::Drain | Stop::Abort | Stop::SharedAbort) {
            let started = tokio::time::Instant::now();
            shutdown.send(()).unwrap();
            // Observe listener closure before releasing the provider. This proves
            // the stream is completing during drain, rather than before shutdown.
            tokio::time::timeout(Duration::from_secs(1), async {
                while TcpStream::connect(("127.0.0.1", shutdown_port)).await.is_ok() {
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
            if let Some((shutdown, task)) = shared {
                let (response, connection) = send(port, "/readyz", "", "GET").await;
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                response.collect().await.unwrap(); connection.await.unwrap();
                shutdown.send(()).unwrap(); task.await.unwrap().unwrap();
            }
            assert!(app.workers.is_empty());
            assert!(app.config.admit(b"gateway", 7).is_ok());
            // Drain completes the exchange (outcome 0); the cancellation after the
            // drain window records a client-disconnect outcome before the slot returns.
            let outcome = if matches!(stop, Stop::Drain) { 0 } else { gateway_core::metadata::OUTCOME_CLIENT_DISCONNECT };
            let (upload, download) = assert_trace(&audit_records(&path), &destination, Some(200), outcome);
            assert_eq!(upload, b"{\"stream\":true}");
            if matches!(stop, Stop::Drain) { assert_eq!(download, b"data: hello\n\ndata: [DONE]\n\n"); }
            else { assert!(download.starts_with(&first) && b"data: hello\n\ndata: [DONE]\n\n".starts_with(&download), "{download:?}"); }
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
            assert!(app.workers.is_empty());
            // The canceled exchange still closed its trace: outcome 5 after the head
            // and the one download chunk the client had already received.
            let (upload, download) = assert_trace(&audit_records(&path), &destination, Some(200),
                gateway_core::metadata::OUTCOME_CLIENT_DISCONNECT);
            assert_eq!(upload, b"{\"stream\":true}");
            assert!(download.starts_with(&first) && b"data: hello\n\ndata: [DONE]\n\n".starts_with(&download), "{download:?}");
            return;
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
        assert!(metrics.contains("soundgate_requests_active 0\n"));
        assert!(metrics.contains(&format!("soundgate_audit_gap_requests_total {}\n", u8::from(failed_log && availability))));
        assert!(metrics.contains(&format!("soundgate_failed_exchanges_total {}\n", u8::from(truncated))));
        assert!(metrics.contains(&format!("soundgate_audit_healthy {}\n", u8::from(!failed_log))));
        shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
        assert!(app.workers.is_empty()); assert_eq!(app.failed_exchanges(), u64::from(truncated));
        assert_eq!(app.audit_gaps(), u64::from(failed_log && availability));
        assert!(app.config.admit(b"gateway", 7).is_ok());
        let records = audit_records(&path);
        // An unhealthy logger records nothing at all, not even a completion.
        if failed_log { assert!(records.is_empty(), "{records:?}"); return; }
        let outcome = if truncated { gateway_core::metadata::OUTCOME_DOWNLOAD_FAILURE } else { 0 };
        let (upload, download) = assert_trace(&records, &destination, Some(200), outcome);
        assert_eq!(upload, b"{\"stream\":true}");
        if truncated { assert!(download.starts_with(&first) && b"data: hello\n\ndata: [DONE]\n\n".starts_with(&download), "{download:?}"); }
        else { assert_eq!(download, bytes); }
    }).await.unwrap();
}

#[tokio::test]
async fn worker_body_drop_cancels_pending_request() {
    let tracker = TaskTracker::new();
    let token = tokio_util::sync::CancellationToken::new();
    let cancelled = token.clone();
    let task = tracker.spawn(async move { cancelled.cancelled().await; });
    let (writer, body) = http_body::channel(16);
    let response = GatewayBody::Stream { body, _task: CancelOnDrop { token, task: Some(task) } };
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
async fn truncated_provider_records_a_download_failure_completion() { exercise(false, false, true, Stop::None).await; }

#[tokio::test]
async fn failed_start_record_refuses_in_strict_mode_and_forwards_with_one_gap_in_availability_mode() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for availability in [false, true] {
            let (upstream, acceptor, roots) = tls().await;
            let destination = format!("https://localhost:{}/v1/messages", upstream.local_addr().unwrap().port());
            let config = config(upstream.local_addr().unwrap().port(), availability);
            let dir = TempDir::new(); let path = dir.0.join("audit.log");
            // A payload limit below the start record's size fails exactly that
            // append (invalid input, logger stays healthy); the 25-byte completion
            // and the 3-byte body chunks still fit.
            let log = DiskLog::create_with_payload_limit(&path, 4, Duration::from_secs(2), 32).unwrap();
            let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(), log);
            let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(8)).await;
            let (release, waiting) = oneshot::channel();
            let upstream_task = stalling_provider(upstream, acceptor, waiting, false);
            let (response, connection) = send(port, "/routes/7", "gateway", "POST").await;
            if availability {
                assert_eq!(response.status(), StatusCode::OK);
                release.send(()).unwrap();
                assert_eq!(response.collect().await.unwrap().to_bytes(), b"data: hello\n\ndata: [DONE]\n\n"[..]);
                connection.await.unwrap(); upstream_task.await.unwrap();
            } else {
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                response.collect().await.unwrap(); connection.await.unwrap();
                // No provider connection was opened without the start record.
                assert!(tokio::time::timeout(Duration::from_millis(50), upstream_task).await.is_err());
                drop(release);
            }
            tokio::time::timeout(Duration::from_secs(1), async {
                while !app.workers.is_empty() { tokio::task::yield_now().await; }
            }).await.unwrap();
            let (metrics, metrics_connection) = send(port, "/metrics", "", "GET").await;
            let metrics = metrics.collect().await.unwrap().to_bytes(); metrics_connection.await.unwrap();
            let metrics = std::str::from_utf8(&metrics).unwrap();
            assert!(metrics.contains(&format!("soundgate_audit_gap_requests_total {}\n", u8::from(availability))));
            assert!(metrics.contains("soundgate_audit_healthy 1\n"));
            assert!(app.log.healthy());
            shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
            assert_eq!(app.audit_gaps(), u64::from(availability));
            assert_eq!(app.failed_exchanges(), 0);
            // The request is log-failed after the start record, so body and head
            // records are skipped; the completion is still written while the
            // logger is healthy: a logging refusal in strict mode, success in availability.
            let records = audit_records(&path);
            assert_eq!(records.iter().map(|r| (r.kind, r.chunk)).collect::<Vec<_>>(), vec![(crate::transfer::RecordKind::Completion, 0)]);
            let Some(crate::disk_log::Metadata::Completion(done)) = records[0].metadata() else { panic!("{records:?}") };
            assert_eq!(done.outcome, if availability { 0 } else { gateway_core::metadata::OUTCOME_LOG_REFUSAL });
            assert_eq!((done.upload_bytes, done.download_bytes), if availability { (15, 27) } else { (0, 0) });
            let _ = destination;
        }
    }).await.unwrap();
}

#[tokio::test]
async fn upstream_timeout_records_a_timeout_completion_after_the_start_record() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = format!("https://localhost:{}/v1/messages", upstream.local_addr().unwrap().port());
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
            HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_millis(300)).unwrap(),
            DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap());
        let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(5)).await;
        // Accept the TCP connection and withhold the TLS handshake until the
        // exchange deadline expires.
        let provider = tokio::spawn(async move {
            let (socket, _) = upstream.accept().await.unwrap();
            let mut first = [0; 5]; let _ = (&socket).readable().await;
            let _ = socket.try_read(&mut first);
            std::future::pending::<()>().await;
        });
        let (response, connection) = send(port, "/routes/7", "gateway", "POST").await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        response.collect().await.unwrap(); connection.await.unwrap();
        provider.abort();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !app.workers.is_empty() { tokio::task::yield_now().await; }
        }).await.unwrap();
        shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
        assert_eq!(app.failed_exchanges(), 1); assert_eq!(app.audit_gaps(), 0);
        let records = audit_records(&path);
        assert_eq!(records.iter().map(|r| r.kind).collect::<Vec<_>>(),
            vec![crate::transfer::RecordKind::RequestStart, crate::transfer::RecordKind::Completion]);
        assert_trace(&records, &destination, None, gateway_core::metadata::OUTCOME_UPSTREAM_TIMEOUT);
    }).await.unwrap();
}

#[tokio::test]
async fn concurrent_tenants_keep_credentials_bodies_and_audit_records_isolated() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (upstream, acceptor, roots) = tls().await;
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
        let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(8)).await;
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
            let Some(direction) = record.direction() else { continue; }; // metadata uses chunk 0
            let entry = records.entry(record.request).or_insert((record.tenant, 0, Vec::new(), Vec::new()));
            assert_eq!(entry.0, record.tenant); assert_eq!(record.chunk, entry.1 + 1); entry.1 = record.chunk;
            match direction { crate::transfer::Direction::Upload => &mut entry.2,
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

#[tokio::test]
async fn shutdown_cancels_stalled_workers_owned_by_another_listener() {
    for availability in [false, true] { exercise(availability, false, false, Stop::SharedAbort).await; }
}

#[tokio::test]
async fn client_disconnect_before_headers_cancels_request_and_upstream_socket() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (upstream, acceptor, roots) = tls().await;
        let dir = TempDir::new();
        let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
            HttpsTransport::with_roots(roots, Duration::from_secs(60)).unwrap(),
            DiskLog::create(&dir.0.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
        let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(65)).await;
        let (received, request_received) = oneshot::channel();
        let provider = tokio::spawn(async move {
            let (socket, _) = upstream.accept().await.unwrap();
            let mut socket = acceptor.accept(socket).await.unwrap();
            let mut request = Vec::new();
            // Read the empty chunked upload without sending any response bytes.
            // One-byte reads deliberately avoid consuming closure before signaling.
            loop {
                let mut byte = [0];
                assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
                request.push(byte[0]);
                assert!(request.len() < 4096);
                if request.ends_with(b"\r\n\r\n0\r\n\r\n") { break; }
            }
            received.send(()).unwrap();
            let mut byte = [0];
            // TLS may report an unclean EOF when cancellation drops the socket.
            match socket.read(&mut byte).await {
                Ok(0) => {},
                Err(error) => assert!(matches!(error.kind(), io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe), "unexpected socket error: {error}"),
                Ok(_) => panic!("unexpected bytes after empty upload"),
            }
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        client.write_all(b"POST /routes/7 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer gateway\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        request_received.await.unwrap();
        assert!(!app.workers.is_empty());
        assert!(app.config.admit(b"gateway", 7).is_err());
        drop(client);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !app.workers.is_empty() { tokio::task::yield_now().await; }
        }).await.unwrap();
        assert!(app.config.admit(b"gateway", 7).is_ok());
        provider.await.unwrap();
        shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn incomplete_connections_expire_without_workers_and_capacity_recovers() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let dir = TempDir::new();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
            HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(60)).unwrap(),
            DiskLog::create(&dir.0.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
        let (port, shutdown, gateway) = spawn_gateway(&app, 2, Duration::from_millis(200)).await;
        let mut peers = JoinSet::new();
        for _ in 0..8 {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            peers.spawn(async move {
                // No complete header, hence no request worker or upstream dispatch.
                // Excess sockets may already have been closed by admission.
                let _ = socket.write_all(b"POST /routes/7 HTTP/1.1\r\nHost:").await;
                let mut bytes = Vec::new();
                match socket.read_to_end(&mut bytes).await {
                    Ok(_) => assert!(bytes.is_empty()),
                    Err(error) => assert!(matches!(error.kind(), io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe)),
                }
            });
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(result) = peers.join_next().await { result.unwrap(); }
        }).await.unwrap();
        assert!(app.workers.is_empty());
        assert!(tokio::time::timeout(Duration::from_millis(20), upstream.accept()).await.is_err());
        let (response, connection) = send(port, "/healthz", "", "GET").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.collect().await.unwrap().to_bytes(), b"ok\n"[..]);
        connection.await.unwrap();
        assert!(app.config.admit(b"gateway", 7).is_ok());
        shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn poisoned_admission_is_unready_and_fail_closed_in_both_logging_modes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for availability in [false, true] {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dir = TempDir::new();
            let app = Gateway::new(config(upstream.local_addr().unwrap().port(), availability),
                HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(60)).unwrap(),
                DiskLog::create(&dir.0.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
            app.config.poison_admission_for_test();
            let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(10)).await;
            for (path, method, status) in [("/healthz", "GET", 200), ("/readyz", "GET", 503), ("/routes/7", "POST", 503)] {
                let (response, connection) = send(port, path, "gateway", method).await;
                assert_eq!(response.status().as_u16(), status);
                response.collect().await.unwrap(); connection.await.unwrap();
            }
            let (metrics, connection) = send(port, "/metrics", "", "GET").await;
            let metrics = metrics.collect().await.unwrap().to_bytes(); connection.await.unwrap();
            let metrics = std::str::from_utf8(&metrics).unwrap();
            assert!(metrics.contains("soundgate_admission_healthy 0\n"));
            assert!(!metrics.contains("soundgate_requests_active"));
            assert!(!metrics.contains("soundgate_requests_limit"));
            assert!(metrics.contains("soundgate_audit_healthy 1\n"));
            assert!(tokio::time::timeout(Duration::from_millis(20), upstream.accept()).await.is_err());
            shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
            assert!(app.workers.is_empty());
        }
    }).await.unwrap();
}

#[tokio::test]
async fn bodyless_http_statuses_finish_worker_accounting() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for status in [StatusCode::NO_CONTENT, StatusCode::NOT_MODIFIED, StatusCode::OK] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let (done, completed) = oneshot::channel();
            let done = Arc::new(Mutex::new(Some(done)));
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let service = service_fn(move |_: Request<Incoming>| {
                    let done = done.lock().unwrap().take().unwrap();
                    async move {
                        let (head, headers) = oneshot::channel();
                        let (writer, body) = http_body::channel(16);
                        let task = tokio::spawn(async move {
                            let mut output = Output { head: Some(head), writer };
                            output.start(status, HeaderMap::new()).await.unwrap();
                            output.finish().await.unwrap();
                            // Emulates final metrics/lease cleanup after draining.
                            done.send(()).unwrap();
                        });
                        worker_response(headers, body, CancelOnDrop { token: Default::default(), task: Some(task) }).await
                    }
                });
                hyper::server::conn::http1::Builder::new().keep_alive(false)
                    .serve_connection(TokioIo::new(socket), service).await.unwrap();
            });
            let (response, connection) = send(port, "/", "", "GET").await;
            assert_eq!(response.status(), status);
            assert!(response.collect().await.unwrap().to_bytes().is_empty());
            connection.await.unwrap(); server.await.unwrap();
            completed.await.expect("HTTP body suppression must not abort final worker accounting");
        }
    }).await.unwrap();
}

#[tokio::test]
async fn bodyless_status_rejects_payload_or_missing_completion() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for status in [StatusCode::NO_CONTENT, StatusCode::NOT_MODIFIED] {
            for payload in [false, true] {
                let (head, headers) = oneshot::channel();
                let (writer, body) = http_body::channel(16);
                let task = tokio::spawn(async move {
                    let mut output = Output { head: Some(head), writer };
                    output.start(status, HeaderMap::new()).await.unwrap();
                    if payload { output.write_all(b"unexpected").await.unwrap(); }
                    // Missing clean completion is an error, even with no bytes.
                });
                let response = worker_response(headers, body, CancelOnDrop { token: Default::default(), task: Some(task) }).await.unwrap();
                assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn worker_budget_covers_cleanup_without_consuming_request_slots() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dir = TempDir::new();
        let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
            HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(2)).unwrap(),
            DiskLog::create(&dir.0.join("workers.log"), 2, Duration::from_secs(1)).unwrap());
        // Hold a worker lifetime with no request lease, as during rejected-request
        // or post-EOF cleanup. Registry-only admission cannot bound this state.
        let lease = app.worker_slots.acquire(&app.workers).unwrap();
        assert_eq!(app.config.usage(), Some((0, 1)));
        let (port, shutdown, gateway) = spawn_gateway(&app, 32, Duration::from_secs(3)).await;
        let mut clients = JoinSet::new();
        for _ in 0..16 {
            clients.spawn(async move {
                let (response, connection) = send(port, "/routes/7", "gateway", "POST").await;
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                response.collect().await.unwrap(); connection.await.unwrap();
            });
        }
        for path in ["/healthz", "/readyz", "/metrics"] {
            let (response, connection) = send(port, path, "", "GET").await;
            assert_eq!(response.status(), StatusCode::OK);
            response.collect().await.unwrap(); connection.await.unwrap();
        }
        while let Some(result) = clients.join_next().await { result.unwrap(); }
        assert_eq!(app.workers.len(), 1);
        assert_eq!(app.config.usage(), Some((0, 1)));
        assert!(tokio::time::timeout(Duration::from_millis(20), upstream.accept()).await.is_err());
        // Cancel before the task's first poll: its captured lease must still drop.
        let worker = lease.spawn(async move { std::future::pending::<()>().await; });
        worker.abort(); assert!(worker.await.unwrap_err().is_cancelled());
        assert!(app.workers.is_empty());
        assert_eq!(app.worker_slots.usage(), Some((0, 1)));
        let (response, connection) = send(port, "/routes/7", "invalid", "POST").await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        response.collect().await.unwrap(); connection.await.unwrap();
        while !app.workers.is_empty() { tokio::task::yield_now().await; }
        assert_eq!(app.worker_slots.usage(), Some((0, 1)));
        shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn poisoned_worker_registry_is_unready_and_fail_closed_in_both_modes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for availability in [false, true] {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dir = TempDir::new();
            let app = Gateway::new(config(upstream.local_addr().unwrap().port(), availability),
                HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(2)).unwrap(),
                DiskLog::create(&dir.0.join("audit.log"), 2, Duration::from_secs(1)).unwrap());
            // Poison with a live key, then release it: Drop must not recover the
            // registry or make it usable again, even with healthy core admission.
            let lease = app.worker_slots.acquire(&app.workers).unwrap();
            app.worker_slots.poison_for_test();
            drop(lease);
            assert!(app.workers.is_empty());
            assert_eq!(app.worker_slots.usage(), None);
            assert_eq!(app.config.usage(), Some((0, 1)));
            let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(3)).await;
            for (path, method, status) in [("/healthz", "GET", 200), ("/readyz", "GET", 503), ("/routes/7", "POST", 503)] {
                let (response, connection) = send(port, path, "gateway", method).await;
                assert_eq!(response.status().as_u16(), status);
                response.collect().await.unwrap(); connection.await.unwrap();
            }
            let (response, connection) = send(port, "/metrics", "", "GET").await;
            let metrics = response.collect().await.unwrap().to_bytes(); connection.await.unwrap();
            let metrics = std::str::from_utf8(&metrics).unwrap();
            assert!(metrics.contains("soundgate_worker_admission_healthy 0\n"));
            assert!(metrics.contains("soundgate_admission_healthy 1\n"));
            assert!(tokio::time::timeout(Duration::from_millis(20), upstream.accept()).await.is_err());
            shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
            assert!(app.workers.is_empty());
        }
    }).await.unwrap();
}

#[tokio::test]
async fn inbound_wire_head_and_header_count_limits_apply_before_health_dispatch() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dir = TempDir::new();
        let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
            HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(2)).unwrap(),
            DiskLog::create(&dir.0.join("headers.log"), 2, Duration::from_secs(1)).unwrap());
        let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(3)).await;
        let prefix = "GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Pad: ";
        let mut cases = Vec::new();
        for extra in [0, 1] {
            let request = format!("{prefix}{}\r\n\r\n", "x".repeat(http_boundary::MAX_HEADER_BYTES + extra - prefix.len() - 4));
            cases.push((request, if extra == 0 { 200 } else { 431 }));
        }
        for count in [100, 101] {
            let mut request = "GET /healthz HTTP/1.1\r\nHost: localhost\r\n".to_owned();
            for i in 1..count { request.push_str(&format!("x-{i}: a\r\n")); }
            request.push_str("\r\n"); cases.push((request, if count == 100 { 200 } else { 431 }));
        }
        for (request, expected) in cases {
            let mut socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            socket.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            let result = socket.read_to_end(&mut response).await;
            if let Err(error) = result { assert_eq!(error.kind(), io::ErrorKind::ConnectionReset); }
            assert!(response.starts_with(format!("HTTP/1.1 {expected}").as_bytes()));
        }
        assert_eq!(app.config.usage(), Some((0, 1))); assert!(app.workers.is_empty());
        assert!(tokio::time::timeout(Duration::from_millis(20), upstream.accept()).await.is_err());
        shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn aborting_server_drops_connections_and_recovers_worker_credit_across_restarts() {
    tokio::time::timeout(Duration::from_secs(15), async {
        for availability in [false, true] {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dir = TempDir::new();
            let app = Gateway::new(config(upstream.local_addr().unwrap().port(), availability),
                HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(60)).unwrap(),
                DiskLog::create(&dir.0.join("abort.log"), 2, Duration::from_secs(1)).unwrap());
            for _ in 0..16 {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let gateway = tokio::spawn(serve(listener, app.clone(), 1, Duration::from_secs(60), std::future::pending()));
                let mut client = TcpStream::connect(address).await.unwrap();
                client.write_all(b"POST /routes/7 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer gateway\r\nContent-Length: 0\r\n\r\n").await.unwrap();
                let (mut provider, _) = upstream.accept().await.unwrap();
                // Observe the TLS ClientHello, then withhold the handshake.
                // Both deadlines are longer than the whole test's timeout.
                let mut first = [0; 5]; provider.read_exact(&mut first).await.unwrap();
                assert_eq!(first[0], 22);
                assert_eq!(app.config.usage(), Some((1, 1)));
                assert_eq!(app.worker_slots.usage(), Some((1, 1)));
                assert_eq!(app.workers.len(), 1);
                gateway.abort();
                assert!(gateway.await.unwrap_err().is_cancelled());
                // JoinSet Drop requests cancellation; joining serve alone does
                // not imply its children have finished their destructors.
                let mut tail = Vec::new();
                provider.read_to_end(&mut tail).await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert!(response.is_empty());
                while !app.workers.is_empty() || app.worker_slots.usage() != Some((0, 1))
                    || app.connection_slots.get().unwrap().usage() != Some((0, 1)) {
                    tokio::task::yield_now().await;
                }
                assert_eq!(app.config.usage(), Some((0, 1)));
                assert!(TcpStream::connect(address).await.is_err());
                assert!(app.log.healthy());
            }
            // Aborting serve bypasses its explicit logger shutdown. Its owner
            // must still shut down the shared logger after the final restart.
            app.log.shutdown(Duration::from_secs(1)).await.unwrap();
            assert_eq!(app.audit_gaps(), 0);
        }
    }).await.unwrap();
}

#[tokio::test]
async fn serve_invocations_share_connection_credit_and_reject_limit_changes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let dir = TempDir::new();
        let app = Gateway::new(config(443, false),
            HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(60)).unwrap(),
            DiskLog::create(&dir.0.join("connections.log"), 2, Duration::from_secs(1)).unwrap());
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let first_address = first.local_addr().unwrap();
        let first_task = tokio::spawn(serve(first, app.clone(), 1, Duration::from_secs(60), std::future::pending()));
        let mut held = TcpStream::connect(first_address).await.unwrap();
        held.write_all(b"GET /healthz HTTP/1.1\r\n").await.unwrap();
        while app.connection_slots.get().and_then(|slots| slots.usage()) != Some((1, 1)) {
            tokio::task::yield_now().await;
        }
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = second.local_addr().unwrap().port();
        let second_task = tokio::spawn(serve(second, app.clone(), 1, Duration::from_secs(60), std::future::pending()));
        let mut excess = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut byte = [0];
        match excess.read(&mut byte).await {
            Ok(0) => (),
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => (),
            other => panic!("excess connection was not closed: {other:?}"),
        }
        assert_eq!(app.connection_slots.get().unwrap().usage(), Some((1, 1)));
        let changed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(serve(changed, app.clone(), 2, Duration::from_secs(60), std::future::pending())
            .await.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        first_task.abort(); assert!(first_task.await.unwrap_err().is_cancelled());
        while app.connection_slots.get().unwrap().usage() != Some((0, 1)) {
            tokio::task::yield_now().await;
        }
        let (response, driver) = send(port, "/healthz", "", "GET").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.collect().await.unwrap().to_bytes(), "ok\n");
        driver.await.unwrap();
        second_task.abort(); assert!(second_task.await.unwrap_err().is_cancelled());
        while app.connection_slots.get().unwrap().usage() != Some((0, 1)) {
            tokio::task::yield_now().await;
        }
        assert!(app.log.healthy());
        app.log.shutdown(Duration::from_secs(1)).await.unwrap();
    }).await.unwrap();
}

#[tokio::test]
async fn shutdown_closes_shared_worker_admission_before_waiting_for_existing_work() {
    tokio::time::timeout(Duration::from_secs(8), async {
        for availability in [false, true] {
            let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let dir = TempDir::new();
            let app = Gateway::new(config_with_limits(upstream.local_addr().unwrap().port(), availability, 2, 16384),
                HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(2)).unwrap(),
                DiskLog::create(&dir.0.join("shutdown.log"), 2, Duration::from_secs(1)).unwrap());
            let lease = app.worker_slots.acquire(&app.workers).unwrap();
            let (_, stop_first, first) = spawn_gateway(&app, 8, Duration::from_secs(3)).await;
            let (port, stop_second, second) = spawn_gateway(&app, 8, Duration::from_secs(3)).await;
            stop_first.send(()).unwrap();
            while app.worker_slots.healthy() { tokio::task::yield_now().await; }
            assert!(!first.is_finished()); // Existing credit still protects drain.
            assert!(app.log.healthy());
            for route in ["/routes/7", "/readyz"] {
                let (response, connection) = send(port, route, "gateway", "GET").await;
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                response.collect().await.unwrap(); connection.await.unwrap();
            }
            assert!(app.worker_slots.acquire(&app.workers).is_none());
            assert_eq!(app.worker_slots.usage(), Some((1, 2)));
            drop(lease);
            first.await.unwrap().unwrap();
            assert_eq!(app.worker_slots.usage(), Some((0, 2)));
            assert!(app.workers.is_empty());
            assert!(tokio::time::timeout(Duration::from_millis(20), upstream.accept()).await.is_err());
            stop_second.send(()).unwrap(); second.await.unwrap().unwrap();
        }
    }).await.unwrap();
}

/// A shipper thread that panics changes the shipping metrics and nothing
/// else: the gateway keeps forwarding, stays ready, and shuts down; the
/// panic is reported by the shipper handle alone.
#[tokio::test]
async fn shipping_thread_panic_changes_only_metrics() {
    use crate::shipping::Shipper;
    tokio::time::timeout(Duration::from_secs(30), async {
        let (upstream, acceptor, roots) = tls().await;
        let config = config(upstream.local_addr().unwrap().port(), false);
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let log = DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap();
        let shipper = Shipper::spawn_for_test(|| panic!("injected shipper failure")).unwrap();
        let metrics = shipper.metrics();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !metrics.panicked() { tokio::time::sleep(Duration::from_millis(10)).await; }
        }).await.unwrap();
        let app = Gateway::with_shipping_metrics(config, HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(), log, Some(metrics.clone()));
        let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(8)).await;
        let (release, waiting) = oneshot::channel();
        let upstream_task = stalling_provider(upstream, acceptor, waiting, false);
        let (response, connection) = send(port, "/routes/7", "gateway", "POST").await;
        assert_eq!(response.status(), StatusCode::OK);
        release.send(()).unwrap();
        assert_eq!(response.collect().await.unwrap().to_bytes(), "data: hello\n\ndata: [DONE]\n\n");
        connection.await.unwrap(); upstream_task.await.unwrap();
        for (path, status) in [("/healthz", 200), ("/readyz", 200)] {
            let (r, c) = send(port, path, "", "GET").await;
            assert_eq!(r.status().as_u16(), status, "{path}"); r.collect().await.unwrap(); c.await.unwrap();
        }
        let (text, c) = send(port, "/metrics", "", "GET").await;
        let text = String::from_utf8(text.collect().await.unwrap().to_bytes().to_vec()).unwrap(); c.await.unwrap();
        assert!(text.contains("soundgate_shipping_enabled 1\n") && text.contains("soundgate_shipping_stopped 1\n"), "{text}");
        assert!(text.contains("soundgate_shipping_batches_acknowledged_total 0\n"));
        shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
        let result = tokio::task::spawn_blocking(move || shipper.shutdown(Duration::from_secs(2))).await.unwrap();
        assert_eq!(result.unwrap_err().to_string(), "shipper panicked");
    }).await.unwrap();
}

/// A gateway with the shipper configured forwards through the provider fixture
/// while the shipper uploads the same exchange; a hanging HypAware server never
/// touches readiness or forwarding, and shutdown still completes.
#[tokio::test]
async fn shipping_uploads_forwarded_exchanges_without_touching_readiness() {
    use crate::shipping::{Shipper, ShippingConfig};
    tokio::time::timeout(Duration::from_secs(30), async {
        for hang in [false, true] {
            let (upstream, acceptor, roots) = tls().await;
            let config = config(upstream.local_addr().unwrap().port(), false);
            let dir = TempDir::new(); let path = dir.0.join("audit.log"); let state = dir.0.join("state"); std::fs::create_dir(&state).unwrap();
            let log = DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap();
            let (cloud_port, cloud_roots, cloud, _cloud_task) = crate::shipping::tests::fake_server_for_gateway(hang).await;
            let shipping = ShippingConfig::from_root_json(&serde_json::to_vec(&json!({"identities":[],"destinations":[],"credentials":[],"grants":[],
                "limits":{"requests":1,"chunk_bytes":4},"logging":"strict",
                "shipping":{"server": format!("https://localhost:{cloud_port}/"), "token_env": "T", "state_dir": state.to_str().unwrap(), "poll_ms": 100}})).unwrap(),
                |_| Some(crate::shipping::tests::TOKEN.to_owned())).unwrap().unwrap();
            let shipper = Shipper::spawn_with_roots(shipping, path.clone(), Some(cloud_roots)).unwrap();
            let app = Gateway::with_shipping_metrics(config, HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(), log, Some(shipper.metrics()));
            let (port, shutdown, gateway) = spawn_gateway(&app, 4, Duration::from_secs(8)).await;
            let (release, waiting) = oneshot::channel();
            let upstream_task = stalling_provider(upstream, acceptor, waiting, false);
            let (response, connection) = send(port, "/routes/7", "gateway", "POST").await;
            assert_eq!(response.status(), StatusCode::OK);
            release.send(()).unwrap();
            assert_eq!(response.collect().await.unwrap().to_bytes(), "data: hello\n\ndata: [DONE]\n\n");
            connection.await.unwrap(); upstream_task.await.unwrap();
            let metrics = shipper.metrics();
            if hang {
                tokio::time::sleep(Duration::from_millis(500)).await;
                assert_eq!(metrics.batches_acknowledged(), 0);
                assert!(cloud.lock().unwrap().requests.iter().any(|p| p == "/v1/identity/bootstrap"), "the shipper did reach the hanging server");
            } else {
                tokio::time::timeout(Duration::from_secs(10), async {
                    while metrics.batches_acknowledged() == 0 { tokio::time::sleep(Duration::from_millis(20)).await; }
                }).await.unwrap();
            }
            for (path, status) in [("/healthz", 200), ("/readyz", 200)] {
                let (r, c) = send(port, path, "", "GET").await;
                assert_eq!(r.status().as_u16(), status, "{path} with hang={hang}"); r.collect().await.unwrap(); c.await.unwrap();
            }
            let (text, c) = send(port, "/metrics", "", "GET").await;
            let text = String::from_utf8(text.collect().await.unwrap().to_bytes().to_vec()).unwrap(); c.await.unwrap();
            assert!(text.contains("soundgate_shipping_enabled 1\n"), "{text}");
            assert!(text.contains(&format!("soundgate_shipping_batches_acknowledged_total {}\n", u8::from(!hang))), "{text}");
            assert!(text.contains("soundgate_shipping_stopped 0\n"));
            shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
            let started = std::time::Instant::now();
            let result = tokio::task::spawn_blocking(move || shipper.shutdown(Duration::from_secs(2))).await.unwrap();
            assert_eq!(result.is_err(), hang, "a shipper stuck in a request is left behind, a free one joins");
            assert!(started.elapsed() < Duration::from_secs(4));
            if !hang {
                let cloud = cloud.lock().unwrap();
                let rows: Vec<_> = cloud.batches.iter().flat_map(|b| b.1.iter()).collect();
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0]["content_text"], "{\"stream\":true}");
                assert_eq!(rows[1]["content_text"], "data: hello\n\ndata: [DONE]\n\n", "unparsed SSE ships verbatim");
                assert_eq!(rows[1]["attributes"]["gateway"]["status_code"], 200);
                assert_eq!(rows[0]["attributes"]["gateway"]["outcome"], "success");
                assert_eq!(rows[0]["provider"], "localhost");
                assert!(!rows.iter().any(|r| r.to_string().contains("provider-secret") || r.to_string().contains("caller-secret")));
            }
        }
    }).await.unwrap();
}
