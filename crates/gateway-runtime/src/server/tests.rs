use super::*;
use crate::disk_log::LogReader;
use crate::test_support::http::{read_request, send_request, start_streaming, write_response, Answer};
use crate::test_support::{self_signed, accept_tls, tls, wait_until, ServerTls, TempDir};
use rustls::{RootCertStore, ServerConfig};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::net::TcpListener as StdListener;
use std::sync::mpsc;
use std::thread::JoinHandle;

mod benchmark;
mod memory;
mod overload;
mod process_crash;
mod stalled_log;
mod sdk;

fn config(port: u16, availability: bool) -> GatewayConfig { config_with_limits(port, availability, 1, 3) }
fn config_with_limits(port: u16, availability: bool, requests: usize, chunk_bytes: usize) -> GatewayConfig {
    let routes = json!([{"tenant":1,"selector":7,"origin":0,"credential":0}]);
    let root = json!({"identities":[{"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"gateway"))}],
        "destinations":[format!("https://localhost:{port}/v1/messages")],
        "credentials":[{"tenant":1,"kind":"api_key","env":"KEY"}],"grants":routes,
        "limits":{"requests":requests,"chunk_bytes":chunk_bytes},"logging":if availability { "availability" } else { "strict" }});
    GatewayConfig::from_json(&serde_json::to_vec(&root).unwrap(),
        |_| Some("provider-secret".into())).unwrap()
}
type Client = Answer<TcpStream>;
/// A client socket with timeouts, so a hung test fails instead of blocking.
fn connect(port: u16) -> TcpStream {
    let socket = TcpStream::connect(("127.0.0.1", port)).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    socket
}
/// One request over a fresh connection.
fn send(port: u16, path: &str, token: &str, method: &str) -> Client {
    send_body(port, path, token, method, b"{\"stream\":true}")
}
fn send_body(port: u16, path: &str, token: &str, method: &str, body: &[u8]) -> Client {
    let token = format!("Bearer {token}");
    send_request(connect(port), method, path, &[("host", "attacker.example"), ("authorization", &token), ("x-api-key", "caller-secret")], body)
        .unwrap_or_else(|e| panic!("{method} {path}: {e}"))
}
/// A running `serve` on its own thread.
struct Served { port: u16, shutdown: Shutdown, thread: Option<JoinHandle<io::Result<()>>> }
impl Served {
    fn start(listener: StdListener, app: &Arc<Gateway>, connections: usize, deadline: Duration) -> Self {
        let port = listener.local_addr().unwrap().port();
        let shutdown = Shutdown::new();
        let (app, signal) = (app.clone(), shutdown.clone());
        let thread = std::thread::spawn(move || serve(listener, app, connections, deadline, &signal));
        Self { port, shutdown, thread: Some(thread) }
    }
    fn is_finished(&self) -> bool { self.thread.as_ref().is_none_or(|thread| thread.is_finished()) }
    /// Wait for `serve` to return.
    fn join(mut self) -> io::Result<()> { self.thread.take().unwrap().join().unwrap() }
    /// Trigger shutdown and wait for `serve` to return.
    fn stop(self) -> io::Result<()> { self.shutdown.trigger(); self.join() }
}
/// Serve `app` on a fresh loopback port.
fn spawn_gateway(app: &Arc<Gateway>, connections: usize, deadline: Duration) -> Served {
    Served::start(StdListener::bind("127.0.0.1:0").unwrap(), app, connections, deadline)
}
/// Connections holding credit. A connection thread returns its credit only
/// after its watcher thread is joined, which can lag the client's view of the
/// response by a watcher poll (about 20 ms); tests that burst connections
/// wait for the credits rather than racing them.
fn connections_in_use(app: &Gateway) -> usize {
    app.connection_slots.get().and_then(|slots| slots.usage()).map(|(active, _)| active).unwrap_or(0)
}
fn wait_connections_at_most(app: &Gateway, n: usize) {
    assert!(wait_until(Duration::from_secs(3), || connections_in_use(app) <= n), "connection credits did not return");
}
/// No worker holds credit.
fn workers_idle(app: &Gateway) -> bool { app.worker_slots.usage().is_some_and(|(active, _)| active == 0) }
fn wait_workers_idle(app: &Gateway) { assert!(wait_until(Duration::from_secs(3), || workers_idle(app)), "workers did not drain"); }
/// True when nothing connects to `listener` within `wait`.
fn no_connection(listener: &StdListener, wait: Duration) -> bool {
    listener.set_nonblocking(true).unwrap();
    let started = Instant::now();
    let quiet = loop {
        match listener.accept() {
            Ok(_) => break false,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if started.elapsed() >= wait { break true; }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(e) => panic!("{e}"),
        }
    };
    listener.set_nonblocking(false).unwrap();
    quiet
}
/// Complete a TLS handshake on an accepted socket.
fn tls_accept(socket: TcpStream, config: &Arc<ServerConfig>) -> ServerTls {
    socket.set_nonblocking(false).unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    socket.set_write_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut connection = rustls::ServerConnection::new(config.clone()).unwrap();
    while connection.is_handshaking() { connection.complete_io(&mut &socket).unwrap(); }
    rustls::StreamOwned::new(connection, socket)
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
fn stalling_provider(upstream: StdListener, config: Arc<ServerConfig>, waiting: mpsc::Receiver<()>, truncated: bool, disconnected: bool) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut socket = accept_tls(&upstream, &config).unwrap();
        let request = read_request(&mut socket).unwrap();
        assert_eq!(request.target(), "/v1/messages");
        assert_eq!(request.header("x-api-key"), Some("provider-secret"));
        assert!(request.header("authorization").is_none());
        assert_eq!(request.body, b"{\"stream\":true}");
        let mut stream = start_streaming(socket, 200, &[("content-type", "text/event-stream"), ("set-cookie", "provider-secret")]).unwrap();
        stream.send(b"data: hello\n\n").unwrap();
        if waiting.recv().is_err() { return; }
        if truncated { return; } // no last chunk: simulate a provider disconnect
        if disconnected {
            // Enough resumed output to expose the peer's closure even if a
            // few writes succeed before the TCP reset reaches the gateway.
            let _ = stream.send(&vec![b'x'; 1024 * 1024]);
            return;
        }
        if stream.send(b"data: [DONE]\n\n").is_ok() { let _ = stream.finish(); }
    })
}
#[derive(Clone, Copy)]
enum Stop { None, Disconnect, Drain, Abort, SharedAbort }

fn exercise(availability: bool, failed_log: bool, truncated: bool, stop: Stop) {
    let (upstream, acceptor, roots) = tls();
    let config = config(upstream.local_addr().unwrap().port(), availability);
    let destination = format!("https://localhost:{}/v1/messages", upstream.local_addr().unwrap().port());
    let dir = TempDir::new(); let path = dir.0.join("audit.log");
    let log = DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap();
    if failed_log { log.inject_failure(); }
    // Shutdown tests must expire through the drain, not the transport deadline.
    let deadline = if matches!(stop, Stop::Drain | Stop::Abort | Stop::SharedAbort) { 60 } else { 5 };
    let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(deadline)).unwrap(), log);
    let gateway = spawn_gateway(&app, 4, Duration::from_secs(deadline + 3));
    let shutdown_port = gateway.port;
    let mut shared = None;
    let port = if matches!(stop, Stop::SharedAbort) {
        let second = spawn_gateway(&app, 4, Duration::from_secs(63));
        let port = second.port;
        shared = Some(second);
        port
    } else { gateway.port };
    for (path, token, method, status) in [("/healthz", "", "GET", 200), ("/readyz", "", "GET", if failed_log && !availability { 503 } else { 200 }),
        ("/routes/7", "wrong", "POST", 401), ("/routes/99", "gateway", "POST", 401)] {
        let r = send(port, path, token, method);
        assert_eq!(r.status, status); r.collect().unwrap();
    }
    // Rejected requests must not have connected to the provider.
    assert!(no_connection(&upstream, Duration::from_millis(20)));
    wait_connections_at_most(&app, 0);
    if failed_log && !availability {
        let r = send(port, "/routes/7", "gateway", "POST");
        assert_eq!(r.status, 503);
        r.collect().unwrap();
        assert!(no_connection(&upstream, Duration::from_millis(20)));
        wait_workers_idle(&app);
        if let Some(shared) = shared { shared.stop().unwrap(); }
        gateway.stop().unwrap();
        assert!(workers_idle(&app)); assert_eq!(app.audit_gaps(), 0);
        return;
    }
    let (release, waiting) = mpsc::channel();
    let upstream_task = stalling_provider(upstream, acceptor, waiting, truncated, matches!(stop, Stop::Disconnect));
    let mut response = send(port, "/routes/7", "gateway", "POST");
    assert_eq!(response.status, 200);
    assert!(response.header("set-cookie").is_none());
    let first = response.chunk().unwrap().unwrap();
    assert!(!first.is_empty()); // arrives while the upstream is waiting, before EOF
    // The first request still owns the sole admission slot while streaming.
    let busy = send(port, "/routes/7", "gateway", "POST");
    assert_eq!(busy.status, 503);
    busy.collect().unwrap();
    wait_connections_at_most(&app, 1);
    let metrics = send(port, "/metrics", "", "GET").collect().unwrap();
    wait_connections_at_most(&app, 1);
    let metrics = std::str::from_utf8(&metrics).unwrap();
    assert!(metrics.contains("hypgate_admission_healthy 1\n"));
    assert!(metrics.contains("hypgate_requests_active 1\n"));
    assert!(metrics.contains("hypgate_requests_limit 1\n"));
    if matches!(stop, Stop::Drain | Stop::Abort | Stop::SharedAbort) {
        let started = Instant::now();
        gateway.shutdown.trigger();
        // Observe listener closure before releasing the provider. This proves
        // the stream is completing during drain, rather than before shutdown.
        assert!(wait_until(Duration::from_secs(2), || TcpStream::connect(("127.0.0.1", shutdown_port)).is_err()));
        assert!(!gateway.is_finished());
        if matches!(stop, Stop::Drain) {
            release.send(()).unwrap();
            let mut bytes = first.to_vec();
            bytes.extend_from_slice(&response.collect().unwrap());
            assert_eq!(bytes, b"data: hello\n\ndata: [DONE]\n\n");
            gateway.join().unwrap();
            assert!(started.elapsed() < Duration::from_secs(5), "drain completed the stream, no cancellation needed");
            assert_eq!(app.failed_exchanges(), 0);
        } else {
            // The provider remains blocked and both network deadlines are
            // over a minute away: only the ten-second drain can end this.
            gateway.join().unwrap();
            assert!(started.elapsed() >= Duration::from_secs(10));
            assert!(started.elapsed() < Duration::from_secs(25));
            assert!(response.collect().is_err());
            drop(release);
        }
        upstream_task.join().unwrap();
        if let Some(second) = shared {
            let response = send(port, "/readyz", "", "GET");
            assert_eq!(response.status, 503);
            response.collect().unwrap();
            second.stop().unwrap();
        }
        assert!(workers_idle(&app));
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
        drop(response); // the client leaves mid-stream
        // A FIN is ambiguous; resumed output exposes the failed delivery.
        release.send(()).unwrap();
        wait_workers_idle(&app);
        assert!(app.config.admit(b"gateway", 7).is_ok());
        drop(release); upstream_task.join().unwrap();
        gateway.stop().unwrap();
        assert!(workers_idle(&app));
        // Failed delivery still closes its trace with outcome 5; the log may
        // include further bytes attempted after the client left.
        let (upload, download) = assert_trace(&audit_records(&path), &destination, Some(200),
            gateway_core::metadata::OUTCOME_CLIENT_DISCONNECT);
        assert_eq!(upload, b"{\"stream\":true}");
        assert!(download.starts_with(&first));
        return;
    }
    release.send(()).unwrap();
    let rest = response.collect();
    let mut bytes = first.to_vec();
    if truncated { assert!(rest.is_err()); }
    else {
        bytes.extend_from_slice(&rest.unwrap());
        assert_eq!(bytes, b"data: hello\n\ndata: [DONE]\n\n");
    }
    upstream_task.join().unwrap();
    wait_workers_idle(&app);
    let metrics = send(port, "/metrics", "", "GET").collect().unwrap();
    let metrics = std::str::from_utf8(&metrics).unwrap();
    assert!(metrics.contains("hypgate_requests_active 0\n"));
    assert!(metrics.contains(&format!("hypgate_audit_gap_requests_total {}\n", u8::from(failed_log && availability))));
    assert!(metrics.contains(&format!("hypgate_failed_exchanges_total {}\n", u8::from(truncated))));
    assert!(metrics.contains(&format!("hypgate_audit_healthy {}\n", u8::from(!failed_log))));
    gateway.stop().unwrap();
    assert!(workers_idle(&app)); assert_eq!(app.failed_exchanges(), u64::from(truncated));
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
}

#[test]
fn full_gateway_streams_before_upstream_eof_and_logs_exact_bytes() { exercise(false, false, false, Stop::None); }
#[test]
fn strict_log_failure_prevents_even_upstream_connection() { exercise(false, true, false, Stop::None); }
#[test]
fn availability_log_failure_preserves_stream_and_reports_gap() { exercise(true, true, false, Stop::None); }
#[test]
fn truncated_generation_is_an_error_and_still_reports_audit_gap() { exercise(true, true, true, Stop::None); }
#[test]
fn truncated_provider_records_a_download_failure_completion() { exercise(false, false, true, Stop::None); }

#[test]
fn failed_start_record_refuses_in_strict_mode_and_forwards_with_one_gap_in_availability_mode() {
    for availability in [false, true] {
        let (upstream, acceptor, roots) = tls();
        let destination = format!("https://localhost:{}/v1/messages", upstream.local_addr().unwrap().port());
        let config = config(upstream.local_addr().unwrap().port(), availability);
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        // A payload limit below the start record's size fails exactly that
        // append (invalid input, logger stays healthy); the 25-byte completion
        // and the 3-byte body chunks still fit.
        let log = DiskLog::create_with_payload_limit(&path, 4, Duration::from_secs(2), 32).unwrap();
        let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(), log);
        let gateway = spawn_gateway(&app, 4, Duration::from_secs(8));
        let port = gateway.port;
        let (release, waiting) = mpsc::channel();
        let (quiet_tx, quiet_rx) = mpsc::channel::<()>();
        let upstream_task = if availability { Some(stalling_provider(upstream, acceptor, waiting, false, false)) } else {
            // No provider connection may be opened without the start record.
            let listener = upstream;
            Some(std::thread::spawn(move || { assert!(no_connection(&listener, Duration::from_millis(300))); let _ = quiet_tx.send(()); }))
        };
        let response = send(port, "/routes/7", "gateway", "POST");
        if availability {
            assert_eq!(response.status, 200);
            release.send(()).unwrap();
            assert_eq!(response.collect().unwrap(), b"data: hello\n\ndata: [DONE]\n\n"[..]);
        } else {
            assert_eq!(response.status, 503);
            response.collect().unwrap();
            quiet_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            drop(release);
        }
        upstream_task.unwrap().join().unwrap();
        wait_workers_idle(&app);
        let metrics = send(port, "/metrics", "", "GET").collect().unwrap();
        let metrics = std::str::from_utf8(&metrics).unwrap();
        assert!(metrics.contains(&format!("hypgate_audit_gap_requests_total {}\n", u8::from(availability))));
        assert!(metrics.contains("hypgate_audit_healthy 1\n"));
        assert!(app.log.healthy());
        gateway.stop().unwrap();
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
}

#[test]
fn upstream_timeout_records_a_timeout_completion_after_the_start_record() {
    let upstream = StdListener::bind("127.0.0.1:0").unwrap();
    let destination = format!("https://localhost:{}/v1/messages", upstream.local_addr().unwrap().port());
    let dir = TempDir::new(); let path = dir.0.join("audit.log");
    let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
        HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_millis(300)).unwrap(),
        DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap());
    let gateway = spawn_gateway(&app, 4, Duration::from_secs(5));
    // Accept the TCP connection and withhold the TLS handshake until the
    // exchange deadline expires.
    let (stop, stopped) = mpsc::channel::<()>();
    let provider = std::thread::spawn(move || {
        let (socket, _) = upstream.accept().unwrap();
        let mut first = [0; 5];
        socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let _ = (&socket).read(&mut first);
        let _ = stopped.recv();
    });
    let response = send(gateway.port, "/routes/7", "gateway", "POST");
    assert_eq!(response.status, 504);
    response.collect().unwrap();
    drop(stop); provider.join().unwrap();
    wait_workers_idle(&app);
    gateway.stop().unwrap();
    assert_eq!(app.failed_exchanges(), 1); assert_eq!(app.audit_gaps(), 0);
    let records = audit_records(&path);
    assert_eq!(records.iter().map(|r| r.kind).collect::<Vec<_>>(),
        vec![crate::transfer::RecordKind::RequestStart, crate::transfer::RecordKind::Completion]);
    assert_trace(&records, &destination, None, gateway_core::metadata::OUTCOME_UPSTREAM_TIMEOUT);
}

#[test]
fn concurrent_tenants_keep_credentials_bodies_and_audit_records_isolated() {
    let (upstream, acceptor, roots) = tls();
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
        |name| Some(format!("secret-{name}"))).unwrap();
    let dir = TempDir::new(); let path = dir.0.join("audit.log");
    let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(),
        DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap());
    let gateway = spawn_gateway(&app, 4, Duration::from_secs(8));
    let port = gateway.port;
    // Neither provider response starts until both tenant requests have arrived.
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let upstream_task = std::thread::spawn(move || {
        let mut connections = Vec::new();
        for _ in 0..2 {
            let mut socket = accept_tls(&upstream, &acceptor).unwrap();
            let barrier = barrier.clone();
            connections.push(std::thread::spawn(move || {
                let request = read_request(&mut socket).unwrap();
                let credential = request.header("x-api-key").unwrap().to_owned();
                assert!(request.header("authorization").is_none());
                match request.body.as_slice() {
                    b"body-one" => assert_eq!(credential, "secret-KEY_ONE"),
                    b"body-two" => assert_eq!(credential, "secret-KEY_TWO"),
                    _ => panic!("unexpected tenant body"),
                }
                barrier.wait();
                write_response(&mut socket, 200, &[], &request.body).unwrap();
            }));
        }
        for connection in connections { connection.join().unwrap(); }
    });
    let client = |token: &'static str, bytes: &'static [u8]| std::thread::spawn(move || {
        let token = format!("Bearer {token}");
        let response = send_request(connect(port), "POST", "/routes/7", &[("host", "localhost"), ("authorization", &token), ("x-api-key", "malicious-override")], bytes).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.collect().unwrap(), bytes);
    });
    let (one, two) = (client("tenant-one", b"body-one"), client("tenant-two", b"body-two"));
    one.join().unwrap(); two.join().unwrap();
    upstream_task.join().unwrap();
    wait_workers_idle(&app);
    gateway.stop().unwrap();
    assert!(workers_idle(&app)); assert_eq!(app.failed_exchanges(), 0);
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
}

#[test]
fn client_disconnect_during_response_cancels_and_releases_request() { exercise(false, false, false, Stop::Disconnect); }

#[test]
fn shutdown_drains_active_response_without_truncation() {
    exercise(false, false, false, Stop::Drain);
}

#[test]
fn shutdown_aborts_stalled_response_after_drain_and_releases_request() {
    exercise(false, false, false, Stop::Abort);
}

#[test]
fn shutdown_cancels_stalled_workers_owned_by_another_listener() {
    for availability in [false, true] { exercise(availability, false, false, Stop::SharedAbort); }
}

#[test]
fn half_closed_client_receives_complete_response_before_and_after_headers() {
    for chunked in [false, true] {
        for after_headers in [false, true] {
            let (upstream, acceptor, roots) = tls();
            let port = upstream.local_addr().unwrap().port();
            let dir = TempDir::new();
            let path = dir.0.join("audit.log");
            let app = Gateway::new(config(port, false),
                HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(),
                DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap());
            let gateway = spawn_gateway(&app, 4, Duration::from_secs(6));
            let (release, waiting) = mpsc::channel();
            let provider = std::thread::spawn(move || {
                let mut socket = accept_tls(&upstream, &acceptor).unwrap();
                assert_eq!(read_request(&mut socket).unwrap().body, b"test");
                if after_headers {
                    let mut response = start_streaming(socket, 200, &[]).unwrap();
                    response.send(b"first").unwrap();
                    waiting.recv_timeout(Duration::from_secs(3)).unwrap();
                    response.send(b"second").unwrap();
                    response.finish().unwrap();
                } else {
                    waiting.recv_timeout(Duration::from_secs(3)).unwrap();
                    write_response(&mut socket, 200, &[], b"firstsecond").unwrap();
                }
            });
            let mut client = connect(gateway.port);
            let control = client.try_clone().unwrap();
            client.write_all(b"POST /routes/7 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer gateway\r\n").unwrap();
            client.write_all(if chunked { b"Transfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n" }
                else { b"Content-Length: 4\r\n\r\ntest" }).unwrap();
            let mut bytes = Vec::new();
            let mut response = if after_headers {
                let mut response = crate::test_support::http::read_response(client.try_clone().unwrap()).unwrap();
                bytes.extend_from_slice(&response.chunk().unwrap().unwrap());
                Some(response)
            } else { None };
            control.shutdown(SocketShutdown::Write).unwrap();
            // Give the watcher an opportunity to consume FIN before the next response bytes.
            std::thread::sleep(Duration::from_millis(50));
            release.send(()).unwrap();
            let response = response.take().unwrap_or_else(|| crate::test_support::http::read_response(client).unwrap());
            assert_eq!(response.status, 200);
            bytes.extend_from_slice(&response.collect().unwrap());
            assert_eq!(bytes, b"firstsecond");
            provider.join().unwrap();
            wait_workers_idle(&app);
            gateway.stop().unwrap();
            let (upload, download) = assert_trace(&audit_records(&path), &format!("https://localhost:{port}/v1/messages"), Some(200), 0);
            assert_eq!(upload, b"test");
            assert_eq!(download, b"firstsecond");
            assert_eq!(app.failed_exchanges(), 0);
        }
    }
}

#[test]
fn half_close_retires_watcher_without_cancelling_receive_side() {
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let mut client = connect(listener.local_addr().unwrap().port());
    let (mut server, _) = listener.accept().unwrap();
    let cancel = Cancel::new();
    cancel.watch_socket(&server).unwrap();
    let watcher = ClientWatch::start(server.try_clone().unwrap(), cancel.clone()).unwrap();
    client.shutdown(SocketShutdown::Write).unwrap();
    assert!(wait_until(Duration::from_secs(2), || watcher.thread.as_ref().unwrap().is_finished()));
    assert!(!cancel.is_cancelled());
    server.write_all(b"still receiving").unwrap();
    let mut bytes = [0; 15];
    client.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"still receiving");
    watcher.finish();
}

#[test]
fn clean_client_close_before_headers_waits_for_deadline() {
    let (upstream, acceptor, roots) = tls();
    let upstream_port = upstream.local_addr().unwrap().port();
    let dir = TempDir::new();
    let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
        HttpsTransport::with_roots(roots, Duration::from_millis(800)).unwrap(),
        DiskLog::create(&dir.0.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
    let gateway = spawn_gateway(&app, 4, Duration::from_secs(5));
    let (received, request_received) = mpsc::channel();
    let provider = std::thread::spawn(move || {
        let mut socket = accept_tls(&upstream, &acceptor).unwrap();
        let mut request = Vec::new();
        // Read the empty chunked upload without sending any response bytes.
        // One-byte reads deliberately avoid consuming closure before signaling.
        loop {
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).unwrap(), 1);
            request.push(byte[0]);
            assert!(request.len() < 4096);
            if request.ends_with(b"\r\n\r\n0\r\n\r\n") { break; }
        }
        received.send(()).unwrap();
        let mut byte = [0];
        // TLS may report an unclean EOF when the expired exchange drops its socket.
        match socket.read(&mut byte) {
            Ok(0) => {},
            Err(error) => assert!(matches!(error.kind(), io::ErrorKind::UnexpectedEof
                | io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                | io::ErrorKind::BrokenPipe), "unexpected socket error: {error}"),
            Ok(_) => panic!("unexpected bytes after empty upload"),
        }
    });
    let mut client = connect(gateway.port);
    client.write_all(b"POST /routes/7 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer gateway\r\nContent-Length: 0\r\n\r\n").unwrap();
    request_received.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(!workers_idle(&app));
    assert!(app.config.admit(b"gateway", 7).is_err());
    drop(client);
    // FIN alone is also consistent with a client still awaiting a response.
    std::thread::sleep(Duration::from_millis(50));
    assert!(!workers_idle(&app));
    wait_workers_idle(&app);
    assert!(app.config.admit(b"gateway", 7).is_ok());
    provider.join().unwrap();
    gateway.stop().unwrap();
    let records = audit_records(&dir.0.join("audit.log"));
    assert_trace(&records, &format!("https://localhost:{upstream_port}/v1/messages"), None,
        gateway_core::metadata::OUTCOME_UPSTREAM_TIMEOUT);
}

#[test]
fn incomplete_connections_expire_without_workers_and_capacity_recovers() {
    let dir = TempDir::new();
    let upstream = StdListener::bind("127.0.0.1:0").unwrap();
    let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
        HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(60)).unwrap(),
        DiskLog::create(&dir.0.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
    let gateway = spawn_gateway(&app, 2, Duration::from_millis(200));
    let port = gateway.port;
    let peers: Vec<_> = (0..8).map(|_| {
        let mut socket = connect(port);
        std::thread::spawn(move || {
            // No complete header, hence no request worker or upstream dispatch.
            // Excess sockets may already have been closed by admission.
            let _ = socket.write_all(b"POST /routes/7 HTTP/1.1\r\nHost:");
            let mut bytes = Vec::new();
            match socket.read_to_end(&mut bytes) {
                Ok(_) => assert!(bytes.is_empty()),
                Err(error) => assert!(matches!(error.kind(), io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe), "{error}"),
            }
        })
    }).collect();
    for peer in peers { peer.join().unwrap(); }
    assert!(workers_idle(&app));
    assert!(no_connection(&upstream, Duration::from_millis(20)));
    let response = send(port, "/healthz", "", "GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.collect().unwrap(), b"ok\n"[..]);
    assert!(app.config.admit(b"gateway", 7).is_ok());
    gateway.stop().unwrap();
}

#[test]
fn poisoned_admission_is_unready_and_fail_closed_in_both_logging_modes() {
    for availability in [false, true] {
        let upstream = StdListener::bind("127.0.0.1:0").unwrap();
        let dir = TempDir::new();
        let app = Gateway::new(config(upstream.local_addr().unwrap().port(), availability),
            HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(60)).unwrap(),
            DiskLog::create(&dir.0.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
        app.config.poison_admission_for_test();
        let gateway = spawn_gateway(&app, 4, Duration::from_secs(10));
        for (path, method, status) in [("/healthz", "GET", 200), ("/readyz", "GET", 503), ("/routes/7", "POST", 503)] {
            let response = send(gateway.port, path, "gateway", method);
            assert_eq!(response.status, status);
            response.collect().unwrap();
        }
        let metrics = send(gateway.port, "/metrics", "", "GET").collect().unwrap();
        let metrics = std::str::from_utf8(&metrics).unwrap();
        assert!(metrics.contains("hypgate_admission_healthy 0\n"));
        assert!(!metrics.contains("hypgate_requests_active"));
        assert!(!metrics.contains("hypgate_requests_limit"));
        assert!(metrics.contains("hypgate_audit_healthy 1\n"));
        assert!(no_connection(&upstream, Duration::from_millis(20)));
        wait_workers_idle(&app);
        gateway.stop().unwrap();
        assert!(workers_idle(&app));
    }
}

/// Raw bytes of one POST to the gateway and everything it answers until it closes.
fn raw_post(port: u16, body: &[u8]) -> Vec<u8> {
    use crate::test_support::http::field;
    let fields = vec![field("host", "attacker.example"), field("authorization", "Bearer gateway"), field("x-api-key", "caller-secret"),
        field("content-length", &body.len().to_string())];
    let mut bytes = Vec::new();
    gateway_core::http1_write::write_request_head(b"POST", b"/routes/7", &fields, &mut bytes);
    bytes.extend_from_slice(body);
    let mut socket = connect(port);
    crate::test_support::http::raw_exchange(&mut socket, &bytes).unwrap()
}

#[test]
fn bodyless_upstream_statuses_reach_the_client_as_a_complete_fixed_head() {
    for status in [204u16, 304] {
        let (upstream, acceptor, roots) = tls();
        let port = upstream.local_addr().unwrap().port();
        let destination = format!("https://localhost:{port}/v1/messages");
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let app = Gateway::new(config(port, false), HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(),
            DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap());
        let gateway = spawn_gateway(&app, 4, Duration::from_secs(8));
        let provider = std::thread::spawn(move || {
            let mut socket = accept_tls(&upstream, &acceptor).unwrap();
            let request = read_request(&mut socket).unwrap();
            assert_eq!(request.body, b"{}");
            // No body may follow these statuses; the provider sends the head alone.
            write_response(&mut socket, status, &[("x-upstream", "kept"), ("set-cookie", "dropped")], b"").unwrap();
            let _ = socket.conn.send_close_notify();
            let _ = socket.flush();
        });
        let answer = raw_post(gateway.port, b"{}");
        provider.join().unwrap();
        let text = std::str::from_utf8(&answer).unwrap();
        let phrase = if status == 204 { "No Content" } else { "Not Modified" };
        assert!(text.starts_with(&format!("HTTP/1.1 {status} {phrase}\r\n")), "{text}");
        assert!(text.ends_with("connection: close\r\n\r\n"), "the head is the whole response: {text}");
        assert!(!text.contains("content-length") && !text.contains("transfer-encoding") && !text.contains("set-cookie"), "{text}");
        wait_workers_idle(&app);
        gateway.stop().unwrap();
        assert_eq!(app.failed_exchanges(), 0);
        let (upload, download) = assert_trace(&audit_records(&path), &destination, Some(status), 0);
        assert_eq!((upload.as_slice(), download.len()), (&b"{}"[..], 0));
    }
}

#[test]
fn worker_budget_covers_cleanup_without_consuming_request_slots() {
    let upstream = StdListener::bind("127.0.0.1:0").unwrap();
    let dir = TempDir::new();
    let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
        HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(2)).unwrap(),
        DiskLog::create(&dir.0.join("workers.log"), 2, Duration::from_secs(1)).unwrap());
    // Hold a worker lifetime with no request lease, as during rejected-request
    // or post-EOF cleanup. Registry-only admission cannot bound this state.
    let lease = app.worker_slots.acquire().unwrap();
    assert_eq!(app.config.usage(), Some((0, 1)));
    let gateway = spawn_gateway(&app, 32, Duration::from_secs(3));
    let port = gateway.port;
    let clients: Vec<_> = (0..16).map(|_| std::thread::spawn(move || {
        let response = send(port, "/routes/7", "gateway", "POST");
        assert_eq!(response.status, 503);
        response.collect().unwrap();
    })).collect();
    for path in ["/healthz", "/readyz", "/metrics"] {
        let response = send(port, path, "", "GET");
        assert_eq!(response.status, 200);
        response.collect().unwrap();
    }
    for client in clients { client.join().unwrap(); }
    assert_eq!(app.worker_slots.usage(), Some((1, 1)));
    assert_eq!(app.config.usage(), Some((0, 1)));
    assert!(no_connection(&upstream, Duration::from_millis(20)));
    // A lease dropped before any work ran still returns its credit.
    drop(lease);
    assert_eq!(app.worker_slots.usage(), Some((0, 1)));
    let response = send(port, "/routes/7", "invalid", "POST");
    assert_eq!(response.status, 401);
    response.collect().unwrap();
    wait_workers_idle(&app);
    assert_eq!(app.worker_slots.usage(), Some((0, 1)));
    gateway.stop().unwrap();
}

#[test]
fn poisoned_worker_registry_is_unready_and_fail_closed_in_both_modes() {
    for availability in [false, true] {
        let upstream = StdListener::bind("127.0.0.1:0").unwrap();
        let dir = TempDir::new();
        let app = Gateway::new(config(upstream.local_addr().unwrap().port(), availability),
            HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(2)).unwrap(),
            DiskLog::create(&dir.0.join("audit.log"), 2, Duration::from_secs(1)).unwrap());
        // Poison with a live key, then release it: Drop must not recover the
        // registry or make it usable again, even with healthy core admission.
        let lease = app.worker_slots.acquire().unwrap();
        app.worker_slots.poison_for_test();
        drop(lease);
        assert_eq!(app.worker_slots.usage(), None);
        assert_eq!(app.config.usage(), Some((0, 1)));
        let gateway = spawn_gateway(&app, 4, Duration::from_secs(3));
        for (path, method, status) in [("/healthz", "GET", 200), ("/readyz", "GET", 503), ("/routes/7", "POST", 503)] {
            let response = send(gateway.port, path, "gateway", method);
            assert_eq!(response.status, status);
            response.collect().unwrap();
        }
        let metrics = send(gateway.port, "/metrics", "", "GET").collect().unwrap();
        let metrics = std::str::from_utf8(&metrics).unwrap();
        assert!(metrics.contains("hypgate_worker_admission_healthy 0\n"));
        assert!(metrics.contains("hypgate_admission_healthy 1\n"));
        assert!(no_connection(&upstream, Duration::from_millis(20)));
        // A poisoned registry reports no usage; the drain window ends shutdown.
        let started = Instant::now();
        gateway.stop().unwrap();
        assert!(started.elapsed() < Duration::from_secs(25));
    }
}

#[test]
fn inbound_wire_head_and_header_count_limits_apply_before_health_dispatch() {
    let upstream = StdListener::bind("127.0.0.1:0").unwrap();
    let dir = TempDir::new();
    let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
        HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(2)).unwrap(),
        DiskLog::create(&dir.0.join("headers.log"), 2, Duration::from_secs(1)).unwrap());
    let gateway = spawn_gateway(&app, 4, Duration::from_secs(3));
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
        let mut socket = connect(gateway.port);
        socket.write_all(request.as_bytes()).unwrap();
        let mut response = Vec::new();
        let result = socket.read_to_end(&mut response);
        if let Err(error) = result { assert_eq!(error.kind(), io::ErrorKind::ConnectionReset); }
        assert!(response.starts_with(format!("HTTP/1.1 {expected}").as_bytes()), "{}", String::from_utf8_lossy(&response));
    }
    assert_eq!(app.config.usage(), Some((0, 1))); assert!(workers_idle(&app));
    assert!(no_connection(&upstream, Duration::from_millis(20)));
    gateway.stop().unwrap();
}

#[test]
fn shutdown_during_a_stalled_handshake_cancels_it_after_the_drain_and_recovers_credit() {
    for availability in [false, true] {
        let upstream = StdListener::bind("127.0.0.1:0").unwrap();
        let dir = TempDir::new();
        let app = Gateway::new(config(upstream.local_addr().unwrap().port(), availability),
            HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(60)).unwrap(),
            DiskLog::create(&dir.0.join("abort.log"), 2, Duration::from_secs(1)).unwrap());
        let gateway = spawn_gateway(&app, 1, Duration::from_secs(60));
        let address = ("127.0.0.1", gateway.port);
        let mut client = connect(gateway.port);
        client.write_all(b"POST /routes/7 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer gateway\r\nContent-Length: 0\r\n\r\n").unwrap();
        let (mut provider, _) = upstream.accept().unwrap();
        provider.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        // Observe the TLS ClientHello, then withhold the handshake.
        // Both deadlines are longer than the whole test.
        let mut first = [0; 5]; provider.read_exact(&mut first).unwrap();
        assert_eq!(first[0], 22);
        assert_eq!(app.config.usage(), Some((1, 1)));
        assert_eq!(app.worker_slots.usage(), Some((1, 1)));
        let started = Instant::now();
        gateway.shutdown.trigger();
        assert!(wait_until(Duration::from_secs(2), || TcpStream::connect(address).is_err()));
        // The drain window passes, then the stalled exchange is cancelled: its
        // sockets are shut, the client sees no response, and credit returns.
        gateway.join().unwrap();
        assert!(started.elapsed() >= Duration::from_secs(10) && started.elapsed() < Duration::from_secs(25));
        let mut tail = Vec::new();
        let _ = provider.read_to_end(&mut tail);
        let mut response = Vec::new();
        let _ = client.read_to_end(&mut response);
        assert!(response.is_empty(), "{}", String::from_utf8_lossy(&response));
        assert_eq!(app.worker_slots.usage(), Some((0, 1)));
        assert_eq!(app.connection_slots.get().unwrap().usage(), Some((0, 1)));
        assert_eq!(app.config.usage(), Some((0, 1)));
        assert_eq!(app.failed_exchanges(), 1);
        assert_eq!(app.audit_gaps(), 0);
        let records = audit_records(&dir.0.join("abort.log"));
        assert_eq!(records.iter().map(|r| r.kind).collect::<Vec<_>>(),
            vec![crate::transfer::RecordKind::RequestStart, crate::transfer::RecordKind::Completion]);
        let Some(crate::disk_log::Metadata::Completion(done)) = records[1].metadata() else { panic!("{records:?}") };
        assert_eq!(done.outcome, gateway_core::metadata::OUTCOME_CLIENT_DISCONNECT);
    }
}

#[test]
fn serve_invocations_share_connection_credit_and_reject_limit_changes() {
    let dir = TempDir::new();
    let app = Gateway::new(config(443, false),
        HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(60)).unwrap(),
        DiskLog::create(&dir.0.join("connections.log"), 2, Duration::from_secs(1)).unwrap());
    let first = spawn_gateway(&app, 1, Duration::from_secs(60));
    let mut held = connect(first.port);
    held.write_all(b"GET /healthz HTTP/1.1\r\n").unwrap();
    assert!(wait_until(Duration::from_secs(2), || app.connection_slots.get().and_then(|slots| slots.usage()) == Some((1, 1))));
    let second = spawn_gateway(&app, 1, Duration::from_secs(60));
    let port = second.port;
    let mut excess = connect(port);
    let mut byte = [0];
    match excess.read(&mut byte) {
        Ok(0) => (),
        Err(e) if e.kind() == io::ErrorKind::ConnectionReset => (),
        other => panic!("excess connection was not closed: {other:?}"),
    }
    assert_eq!(app.connection_slots.get().unwrap().usage(), Some((1, 1)));
    let changed = StdListener::bind("127.0.0.1:0").unwrap();
    assert_eq!(serve(changed, app.clone(), 2, Duration::from_secs(60), &Shutdown::new()).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    // The held connection ends when its client leaves; the first listener then
    // drains promptly. Shutting it down closes shared worker admission, but
    // the operator endpoints on the second listener keep answering.
    drop(held);
    assert!(wait_until(Duration::from_secs(2), || app.connection_slots.get().unwrap().usage() == Some((0, 1))));
    let started = Instant::now();
    first.stop().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    let response = send(port, "/healthz", "", "GET");
    assert_eq!(response.status, 200);
    assert_eq!(response.collect().unwrap(), b"ok\n");
    assert!(wait_until(Duration::from_secs(2), || app.connection_slots.get().unwrap().usage() == Some((0, 1))));
    second.stop().unwrap();
    assert_eq!(app.connection_slots.get().unwrap().usage(), Some((0, 1)));
}

#[test]
fn shutdown_closes_shared_worker_admission_before_waiting_for_existing_work() {
    for availability in [false, true] {
        let upstream = StdListener::bind("127.0.0.1:0").unwrap();
        let dir = TempDir::new();
        let app = Gateway::new(config_with_limits(upstream.local_addr().unwrap().port(), availability, 2, 16384),
            HttpsTransport::with_roots(RootCertStore::empty(), Duration::from_secs(2)).unwrap(),
            DiskLog::create(&dir.0.join("shutdown.log"), 2, Duration::from_secs(1)).unwrap());
        let lease = app.worker_slots.acquire().unwrap();
        let first = spawn_gateway(&app, 8, Duration::from_secs(3));
        let second = spawn_gateway(&app, 8, Duration::from_secs(3));
        let port = second.port;
        first.shutdown.trigger();
        assert!(wait_until(Duration::from_secs(2), || !app.worker_slots.healthy()));
        assert!(!first.is_finished()); // Existing credit still protects drain.
        assert!(app.log.healthy());
        for route in ["/routes/7", "/readyz"] {
            let response = send(port, route, "gateway", "GET");
            assert_eq!(response.status, 503);
            response.collect().unwrap();
        }
        assert!(app.worker_slots.acquire().is_none());
        assert_eq!(app.worker_slots.usage(), Some((1, 2)));
        drop(lease);
        first.join().unwrap();
        assert_eq!(app.worker_slots.usage(), Some((0, 2)));
        assert!(workers_idle(&app));
        assert!(no_connection(&upstream, Duration::from_millis(20)));
        second.stop().unwrap();
    }
}

/// A shipper thread that panics changes the shipping metrics and nothing
/// else: the gateway keeps forwarding, stays ready, and shuts down; the
/// panic is reported by the shipper handle alone.
#[test]
fn shipping_thread_panic_changes_only_metrics() {
    use crate::shipping::Shipper;
    let (upstream, acceptor, roots) = tls();
    let config = config(upstream.local_addr().unwrap().port(), false);
    let dir = TempDir::new(); let path = dir.0.join("audit.log");
    let log = DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap();
    let shipper = Shipper::spawn_for_test(|| panic!("injected shipper failure")).unwrap();
    let metrics = shipper.metrics();
    assert!(wait_until(Duration::from_secs(5), || metrics.panicked()));
    let app = Gateway::with_shipping_metrics(config, HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(), log, Some(metrics.clone()));
    let gateway = spawn_gateway(&app, 4, Duration::from_secs(8));
    let port = gateway.port;
    let (release, waiting) = mpsc::channel();
    let upstream_task = stalling_provider(upstream, acceptor, waiting, false, false);
    let response = send(port, "/routes/7", "gateway", "POST");
    assert_eq!(response.status, 200);
    release.send(()).unwrap();
    assert_eq!(response.collect().unwrap(), b"data: hello\n\ndata: [DONE]\n\n");
    upstream_task.join().unwrap();
    for (path, status) in [("/healthz", 200), ("/readyz", 200)] {
        let r = send(port, path, "", "GET");
        assert_eq!(r.status, status, "{path}"); r.collect().unwrap();
    }
    let text = String::from_utf8(send(port, "/metrics", "", "GET").collect().unwrap()).unwrap();
    assert!(text.contains("hypgate_shipping_enabled 1\n") && text.contains("hypgate_shipping_stopped 1\n"), "{text}");
    assert!(text.contains("hypgate_shipping_batches_acknowledged_total 0\n"));
    wait_workers_idle(&app);
    gateway.stop().unwrap();
    assert_eq!(shipper.shutdown(Duration::from_secs(2)).unwrap_err().to_string(), "shipper panicked");
}

// ---- a minimal fake HypAware server for the gateway-level shipping test ----

/// Requests seen and rows stored by the fake cloud.
#[derive(Default)]
struct Cloud { requests: Vec<String>, rows: Vec<serde_json::Value>, hang: bool }
type SharedCloud = Arc<Mutex<Cloud>>;
fn fake_jwt(sub: &str, exp: u64) -> String {
    use crate::shipping::state::base64url_encode;
    let header = base64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = base64url_encode(json!({"sub": sub, "exp": exp, "org": "acme"}).to_string().as_bytes());
    format!("{header}.{payload}.{}", base64url_encode(b"signature-not-checked-by-client"))
}
/// A fake HypAware Cloud on a fresh port: bootstrap issues a JWT, ingest
/// stores the rows; with `hang` every request is left unanswered.
fn fake_cloud(hang: bool) -> (u16, RootCertStore, SharedCloud) {
    let (listener, config, roots) = tls();
    let port = listener.local_addr().unwrap().port();
    let state: SharedCloud = Arc::new(Mutex::new(Cloud { hang, ..Default::default() }));
    let shared = state.clone();
    std::thread::spawn(move || {
        while let Ok(mut socket) = accept_tls(&listener, &config) {
            let state = shared.clone();
            std::thread::spawn(move || {
                let Ok(request) = read_request(&mut socket) else { return; };
                let path = request.target().to_owned();
                let hang = { let mut cloud = state.lock().unwrap(); cloud.requests.push(path.clone()); cloud.hang };
                if hang { std::thread::sleep(Duration::from_secs(3600)); return; }
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                let (status, body) = match path.as_str() {
                    "/v1/identity/bootstrap" => (200, json!({"jwt": fake_jwt("gw-0123456789abcdef", now + 21 * 86_400), "expires_at": now + 21 * 86_400, "org": "acme"}).to_string()),
                    "/v1/ingest/proxy" => {
                        assert!(request.header("authorization").is_some_and(|a| a.starts_with("Bearer ey")));
                        let rows: Vec<serde_json::Value> = request.body.split(|b| *b == b'\n').filter(|l| !l.is_empty())
                            .map(|l| serde_json::from_slice(l).expect("ndjson row")).collect();
                        state.lock().unwrap().rows.extend(rows);
                        (202, "{}".to_owned())
                    }
                    _ => (404, r#"{"error":"unknown_path"}"#.to_owned()),
                };
                let _ = write_response(&mut socket, status, &[], body.as_bytes());
            });
        }
    });
    (port, roots, state)
}

/// A gateway with the shipper configured forwards through the provider fixture
/// while the shipper uploads the same exchange; a hanging HypAware server never
/// touches readiness or forwarding, and shutdown still completes.
#[test]
fn shipping_uploads_forwarded_exchanges_without_touching_readiness() {
    use crate::shipping::{Shipper, ShippingConfig};
    const TOKEN: &str = "hsa_0123456789abcdef_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
    for hang in [false, true] {
        let (upstream, acceptor, roots) = tls();
        let config = config(upstream.local_addr().unwrap().port(), false);
        let dir = TempDir::new(); let path = dir.0.join("audit.log"); let state = dir.0.join("state"); std::fs::create_dir(&state).unwrap();
        let log = DiskLog::create(&path, 4, Duration::from_secs(2)).unwrap();
        let (cloud_port, cloud_roots, cloud) = fake_cloud(hang);
        let shipping = ShippingConfig::from_root_json(&serde_json::to_vec(&json!({"identities":[],"destinations":[],"credentials":[],"grants":[],
            "limits":{"requests":1,"chunk_bytes":4},"logging":"strict",
            "shipping":{"server": format!("https://localhost:{cloud_port}/"), "token_env": "T", "state_dir": state.to_str().unwrap(), "poll_ms": 100}})).unwrap(),
            |_| Some(TOKEN.to_owned())).unwrap().unwrap();
        let shipper = Shipper::spawn_with_roots(shipping, path.clone(), Some(cloud_roots)).unwrap();
        let app = Gateway::with_shipping_metrics(config, HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(), log, Some(shipper.metrics()));
        let gateway = spawn_gateway(&app, 4, Duration::from_secs(8));
        let port = gateway.port;
        let (release, waiting) = mpsc::channel();
        let upstream_task = stalling_provider(upstream, acceptor, waiting, false, false);
        let response = send(port, "/routes/7", "gateway", "POST");
        assert_eq!(response.status, 200);
        release.send(()).unwrap();
        assert_eq!(response.collect().unwrap(), b"data: hello\n\ndata: [DONE]\n\n");
        upstream_task.join().unwrap();
        let metrics = shipper.metrics();
        if hang {
            assert!(wait_until(Duration::from_secs(5), || cloud.lock().unwrap().requests.iter().any(|p| p == "/v1/identity/bootstrap")), "the shipper did reach the hanging server");
            std::thread::sleep(Duration::from_millis(300));
            assert_eq!(metrics.batches_acknowledged(), 0);
        } else {
            assert!(wait_until(Duration::from_secs(10), || metrics.batches_acknowledged() > 0));
        }
        for (path, status) in [("/healthz", 200), ("/readyz", 200)] {
            let r = send(port, path, "", "GET");
            assert_eq!(r.status, status, "{path} with hang={hang}"); r.collect().unwrap();
        }
        let text = String::from_utf8(send(port, "/metrics", "", "GET").collect().unwrap()).unwrap();
        assert!(text.contains("hypgate_shipping_enabled 1\n"), "{text}");
        assert!(text.contains(&format!("hypgate_shipping_batches_acknowledged_total {}\n", u8::from(!hang))), "{text}");
        assert!(text.contains("hypgate_shipping_stopped 0\n"));
        wait_workers_idle(&app);
        gateway.stop().unwrap();
        let started = Instant::now();
        let result = shipper.shutdown(Duration::from_secs(2));
        assert_eq!(result.is_err(), hang, "a shipper stuck in a request is left behind, a free one joins");
        assert!(started.elapsed() < Duration::from_secs(4));
        if !hang {
            let cloud = cloud.lock().unwrap();
            let rows = &cloud.rows;
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0]["content_text"], "{\"stream\":true}");
            assert_eq!(rows[1]["content_text"], "data: hello\n\ndata: [DONE]\n\n", "unparsed SSE ships verbatim");
            assert_eq!(rows[1]["attributes"]["gateway"]["status_code"], 200);
            assert_eq!(rows[0]["attributes"]["gateway"]["outcome"], "success");
            assert_eq!(rows[0]["provider"], "localhost");
            assert!(!rows.iter().any(|r| r.to_string().contains("provider-secret") || r.to_string().contains("caller-secret")));
        }
    }
}

mod lifetime;
