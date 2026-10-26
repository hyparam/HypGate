#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
use super::*;
use super::config::ShippingConfig;
use super::state::{base64url_encode, jwt_claims, load_checkpoint, load_identity, save_checkpoint, save_identity};
use crate::disk_log::DiskLog;
use crate::test_support::{self_signed, wait_until, TempDir};
use crate::transfer::{AuditLog, LogRecord, RecordKind};
use gateway_core::exchange_assembler::{Assembler, Exchange};
use gateway_core::metadata::{encode_completion, encode_request_start, encode_response_head};
use crate::test_support::http::{read_request, write_response, Received};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};
use std::{collections::HashSet, io::{self, Write}, net::{SocketAddr, TcpListener, TcpStream}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, thread, time::Duration};

/// The projected rows, written by the verified writer and read back by serde_json for the assertions.
fn project(session: &[u8; 16], exchange: &gateway_core::exchange_assembler::Exchange, max_text: usize) -> Vec<Value> {
    gateway_core::projection::rows(session, exchange, max_text).iter()
        .map(|row| serde_json::from_slice(&crate::json_build::write(row)).expect("the writer emits a document")).collect()
}

// ---- fake HypAware server -------------------------------------------------

#[derive(Default)]
pub(crate) struct Fake {
    /// Scripted ingest replies consumed in order; afterwards every batch is accepted.
    ingest_script: std::collections::VecDeque<(u16, &'static str, Option<u64>)>,
    bootstrap_script: std::collections::VecDeque<(u16, &'static str)>,
    refresh_script: std::collections::VecDeque<(u16, &'static str)>,
    expected_token: String,
    jwt_ttl: u64,
    issued: u64,
    pub(crate) batches: Vec<(String, Vec<Value>, String)>,
    seen_ids: HashSet<String>,
    seen_parts: HashSet<String>,
    stored_rows: usize,
    pub(crate) requests: Vec<String>,
    hang: bool,
}
pub(crate) type Shared = Arc<Mutex<Fake>>;

/// The fake server's accept thread. Dropping it stops accepting and joins the
/// thread; connections already being served finish on their own threads.
pub(crate) struct FakeServer { stop: Arc<AtomicBool>, address: SocketAddr, thread: Option<thread::JoinHandle<()>> }
impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_secs(1));
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

fn fake_jwt(sub: &str, exp: u64, serial: u64) -> String {
    let header = base64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = base64url_encode(json!({"sub": sub, "exp": exp, "iat": serial, "org": "acme"}).to_string().as_bytes());
    format!("{header}.{payload}.{}", base64url_encode(b"signature-not-checked-by-client"))
}

/// Complete the server side of a TLS handshake on an accepted socket.
fn tls_server(socket: TcpStream, config: &Arc<ServerConfig>) -> io::Result<StreamOwned<ServerConnection, TcpStream>> {
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut connection = ServerConnection::new(config.clone()).map_err(io::Error::other)?;
    while connection.is_handshaking() { connection.complete_io(&mut &socket)?; }
    Ok(StreamOwned::new(connection, socket))
}

fn serve_fake(listener: TcpListener, config: Arc<ServerConfig>, state: Shared, stop: Arc<AtomicBool>) {
    loop {
        let Ok((socket, _)) = listener.accept() else { return; };
        if stop.load(Ordering::SeqCst) { return; }
        let config = config.clone(); let state = state.clone();
        thread::spawn(move || {
            let Ok(mut tls) = tls_server(socket, &config) else { return; };
            let Ok(received) = read_request(&mut tls) else { return; };
            let (status, body, retry_after) = handle_fake(received, state);
            let retry = retry_after.map(|seconds| seconds.to_string());
            let mut fields: Vec<(&str, &str)> = Vec::new();
            if let Some(retry) = retry.as_deref() { fields.push(("retry-after", retry)); }
            fields.push(("accept-encoding", "gzip"));
            let _ = write_response(&mut tls, status, &fields, body.as_bytes());
            tls.conn.send_close_notify();
            let _ = tls.flush();
            let _ = tls.sock.shutdown(std::net::Shutdown::Both);
        });
    }
}

/// The fake's reply: status, body, and an optional Retry-After in seconds.
fn handle_fake(request: Received, state: Shared) -> (u16, String, Option<u64>) {
    let path = request.target().to_owned();
    let auth = request.header("authorization").map(str::to_owned).unwrap_or_default();
    let batch_id = request.header("x-hyp-batch-id").map(str::to_owned);
    let content_type = request.header("content-type").map(str::to_owned).unwrap_or_default();
    let body = request.body;
    let hang = { let mut fake = state.lock().unwrap(); fake.requests.push(path.clone()); fake.hang };
    if hang { thread::sleep(Duration::from_secs(3600)); }
    let reply = |status: u16, body: String, retry_after: Option<u64>| (status, body, retry_after);
    let mut fake = state.lock().unwrap();
    let now = now_seconds();
    match path.as_str() {
        BOOTSTRAP_PATH => {
            if let Some((status, code)) = fake.bootstrap_script.pop_front() { if status != 200 { return reply(status, format!("{{\"error\":\"{code}\"}}"), None); } }
            let token = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v["bootstrap_token"].as_str().map(str::to_owned));
            assert!(auth.is_empty()); assert_eq!(content_type, "application/json");
            if token.as_deref() != Some(fake.expected_token.as_str()) { return reply(401, r#"{"error":"bootstrap_token_invalid"}"#.into(), None); }
            fake.issued += 1; let exp = now + fake.jwt_ttl;
            let jwt = fake_jwt("gw-0123456789abcdef", exp, fake.issued);
            reply(200, json!({"jwt": jwt, "expires_at": exp, "org": "acme"}).to_string(), None)
        }
        REFRESH_PATH => {
            if let Some((status, code)) = fake.refresh_script.pop_front() { if status != 200 { return reply(status, format!("{{\"error\":\"{code}\"}}"), None); } }
            if !auth.starts_with("Bearer ey") { return reply(401, r#"{"error":"jwt_invalid_or_revoked"}"#.into(), None); }
            fake.issued += 1; let exp = now + fake.jwt_ttl;
            let jwt = fake_jwt("gw-0123456789abcdef", exp, fake.issued);
            reply(200, json!({"jwt": jwt, "expires_at": exp, "org": "acme"}).to_string(), None)
        }
        INGEST_PATH => {
            assert_eq!(content_type, "application/x-ndjson");
            let Some(id) = batch_id else { return reply(400, r#"{"error":"missing_batch_id"}"#.into(), None); };
            if !auth.starts_with("Bearer ey") { return reply(401, r#"{"error":"unauthorized"}"#.into(), None); }
            if let Some((status, code, retry_after)) = fake.ingest_script.pop_front() {
                return reply(status, if code.is_empty() { "{}".into() } else { format!("{{\"error\":\"{code}\"}}") }, retry_after);
            }
            if fake.seen_ids.contains(&id) { return reply(202, "{}".into(), None); }
            let rows: Vec<Value> = body.split(|b| *b == b'\n').filter(|l| !l.is_empty())
                .map(|l| serde_json::from_slice(l).expect("ndjson row")).collect();
            assert!(!rows.is_empty() && rows.len() <= 5000 && body.len() <= 4 * 1024 * 1024);
            fake.seen_ids.insert(id.clone());
            // Like the server, repeated part ids across the org are dropped silently.
            let fresh: Vec<Value> = rows.into_iter().filter(|r| fake.seen_parts.insert(r["part_id"].as_str().unwrap().to_owned())).collect();
            fake.stored_rows += fresh.len();
            fake.batches.push((id, fresh, auth));
            reply(202, "{}".into(), None)
        }
        _ => reply(404, r#"{"error":"unknown_path"}"#.into(), None),
    }
}

/// A fake server on a fresh port with its trust roots and shared state.
fn fake_server(token: &str) -> (u16, RootCertStore, Shared, FakeServer) {
    let (_, config, roots) = self_signed();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(Fake { expected_token: token.into(), jwt_ttl: 21 * 86_400, ..Default::default() }));
    let stop = Arc::new(AtomicBool::new(false));
    let thread = { let state = state.clone(); let stop = stop.clone(); thread::spawn(move || serve_fake(listener, config, state, stop)) };
    (address.port(), roots, state, FakeServer { stop, address, thread: Some(thread) })
}

pub(crate) const TOKEN: &str = "hsa_0123456789abcdef_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";

/// The fake server for the gateway-level test, optionally hanging every request.
pub(crate) fn fake_server_for_gateway(hang: bool) -> (u16, RootCertStore, Shared, FakeServer) {
    let (port, roots, state, server) = fake_server(TOKEN);
    state.lock().unwrap().hang = hang;
    (port, roots, state, server)
}

fn shipping_json(port: u16, state_dir: &std::path::Path, extra: Value) -> Vec<u8> {
    let mut section = json!({"server": format!("https://localhost:{port}/"), "token_env": "HYP_TOKEN",
        "state_dir": state_dir.to_str().unwrap(), "poll_ms": 100});
    if let Value::Object(extra) = extra { for (k, v) in extra { section[k] = v; } }
    serde_json::to_vec(&json!({"identities":[],"destinations":[],"credentials":[],"grants":[],
        "limits":{"requests":1,"chunk_bytes":4},"logging":"strict","shipping": section})).unwrap()
}
fn shipping_config(port: u16, state_dir: &std::path::Path, extra: Value) -> ShippingConfig {
    ShippingConfig::from_root_json(&shipping_json(port, state_dir, extra), |name| (name == "HYP_TOKEN").then(|| TOKEN.to_owned())).unwrap().unwrap()
}

/// Append one complete exchange to the log and return its request id.
fn write_exchange(log: &mut DiskLog, request: u64, destination: &str, upload: &[u8], status: u16, download: &[&[u8]], outcome: u8) {
    let start = encode_request_start(1_700_000_000_000 + request, 7, destination.as_bytes()).unwrap();
    log.append(LogRecord { tenant: 1, request, chunk: 0, kind: RecordKind::RequestStart, bytes: &start }).unwrap();
    log.append(LogRecord { tenant: 1, request, chunk: 1, kind: RecordKind::Upload, bytes: upload }).unwrap();
    let head = encode_response_head(1_700_000_000_500 + request, status).unwrap();
    log.append(LogRecord { tenant: 1, request, chunk: 0, kind: RecordKind::ResponseHead, bytes: &head }).unwrap();
    for (i, chunk) in download.iter().enumerate() {
        log.append(LogRecord { tenant: 1, request, chunk: 2 + i as u64, kind: RecordKind::Download, bytes: chunk }).unwrap();
    }
    let total: usize = download.iter().map(|c| c.len()).sum();
    let done = encode_completion(1_700_000_001_000 + request, outcome, upload.len() as u64, total as u64).unwrap();
    log.append(LogRecord { tenant: 1, request, chunk: 0, kind: RecordKind::Completion, bytes: &done }).unwrap();
}

const ANTHROPIC_REQUEST: &str = r#"{"model":"claude-opus-4","max_tokens":64,"metadata":{"user_id":"session-abc"},"messages":[{"role":"user","content":"hello there"}]}"#;
const ANTHROPIC_RESPONSE: &str = r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-opus-4","content":[{"type":"text","text":"Hi! "},{"type":"text","text":"How can I help?"}],"usage":{"input_tokens":12,"cache_read_input_tokens":3,"cache_creation_input_tokens":1,"output_tokens":7}}"#;

// ---- shipper against the fake server ---------------------------------------

#[test]
fn ships_exchanges_once_with_stable_ids_and_resumes_from_checkpoint() {
    let (port, roots, state, _server) = fake_server(TOKEN);
    let dir = TempDir::new(); let state_dir = dir.0.join("state"); std::fs::create_dir(&state_dir).unwrap();
    let log_path = dir.0.join("audit.log");
    let mut log = DiskLog::create(&log_path, 4, Duration::from_secs(2)).unwrap();
    write_exchange(&mut log, 1, "https://api.anthropic.com/v1/messages", ANTHROPIC_REQUEST.as_bytes(), 200, &[ANTHROPIC_RESPONSE.as_bytes()], 0);
    let shipper = Shipper::spawn_with_roots(shipping_config(port, &state_dir, json!({})), log_path.clone(), Some(roots.clone())).unwrap();
    let metrics = shipper.metrics();
    assert!(wait_until(Duration::from_secs(10), || metrics.batches_acknowledged() == 1), "first batch");
    // Tail: a second exchange written while the shipper runs is shipped in a later batch.
    write_exchange(&mut log, 2, "https://api.openai.com/v1/responses", br#"{"model":"gpt-5","user":"u-9","input":"ping"}"#, 500, &[b"upstream exploded"], 1);
    assert!(wait_until(Duration::from_secs(10), || metrics.batches_acknowledged() == 2), "second batch");
    assert!(metrics.enrolled() && !metrics.stopped() && metrics.lag() == 0);
    shipper.shutdown(Duration::from_secs(5)).unwrap();
    let identity = load_identity(&state_dir).expect("identity persisted");
    assert_eq!(identity.gateway_id, "gw-0123456789abcdef");
    assert_eq!(identity.token_fingerprint, state::fingerprint(TOKEN.as_bytes()));
    assert!(!std::fs::read_to_string(state_dir.join("identity.json")).unwrap().contains(TOKEN));
    #[cfg(unix)] { use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(state_dir.join("identity.json")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(state_dir.join("checkpoint.json")).unwrap().permissions().mode() & 0o777, 0o600); }
    let checkpoint = load_checkpoint(&state_dir).expect("checkpoint persisted");
    assert_eq!((checkpoint.resolved, checkpoint.poisoned), (2, 0));
    assert_eq!(checkpoint.session, hex(&log.session()));

    let batches = state.lock().unwrap().batches.clone();
    assert_eq!(batches.len(), 2);
    assert_eq!(batches[0].1.len(), 2);
    let (user, assistant) = (&batches[0].1[0], &batches[0].1[1]);
    assert_eq!(user["role"], "user"); assert_eq!(assistant["role"], "assistant");
    assert_eq!(user["content_text"], "hello there"); assert_eq!(assistant["content_text"], "Hi! \nHow can I help?");
    assert_eq!(user["session_id"], "session-abc"); assert_eq!(user["provider"], "anthropic"); assert_eq!(user["model"], "claude-opus-4");
    assert_eq!(assistant["attributes"]["usage"], json!({"input_tokens":12,"cache_read_tokens":3,"cache_write_tokens":1,"output_tokens":7,"total_tokens":23}));
    assert_eq!(assistant["attributes"]["gateway"]["status_code"], 200); assert_eq!(user["attributes"]["gateway"]["outcome"], "success");
    assert_eq!(user["date"], "2023-11-14"); assert_eq!(user["schema_version"], 7);
    assert_ne!(user["part_id"], assistant["part_id"]); assert_eq!(assistant["previous_message_id"][0], user["message_id"]);
    for required in ["session_id","provider","conversation_started_at","message_id","message_index","message_created_at","role","part_id","part_index","part_type","date"] {
        assert!(!user[required].is_null() && !assistant[required].is_null(), "{required}");
    }
    assert!(user.get("gateway_id").is_none() && user.get("org").is_none());
    let second = &batches[1].1;
    assert_eq!(second[0]["provider"], "openai"); assert_eq!(second[0]["session_id"], "u-9"); assert_eq!(second[0]["content_text"], "ping");
    assert_eq!(second[1]["content_text"], "upstream exploded"); assert_eq!(second[1]["is_error"], true);
    assert_eq!(second[1]["attributes"]["gateway"]["outcome"], "upstream_failure");
    let ids: HashSet<_> = batches.iter().flat_map(|b| b.1.iter().map(|r| r["part_id"].as_str().unwrap().to_owned())).collect();
    assert_eq!(ids.len(), 4);
    let first_id = batches[0].0.clone();
    assert_eq!(first_id.len(), 80); assert!(first_id.starts_with(&hex(&log.session())));

    // Restart from the checkpoint: nothing already resolved is sent again, and a
    // new exchange goes out. Wiping the checkpoint re-sends everything under the
    // same batch id, which the server's ledger recognizes.
    write_exchange(&mut log, 3, "https://api.anthropic.com/v1/messages", b"not json", 200, &[b"plain"], 0);
    let shipper = Shipper::spawn_with_roots(shipping_config(port, &state_dir, json!({})), log_path.clone(), Some(roots.clone())).unwrap();
    let metrics = shipper.metrics();
    assert!(wait_until(Duration::from_secs(10), || metrics.batches_acknowledged() == 1));
    shipper.shutdown(Duration::from_secs(5)).unwrap();
    assert_eq!(state.lock().unwrap().batches.len(), 3);
    assert_eq!(state.lock().unwrap().batches[2].1[0]["content_text"], "not json");
    assert_eq!(state.lock().unwrap().requests.iter().filter(|p| *p == BOOTSTRAP_PATH).count(), 1, "identity reused across restarts");
    std::fs::remove_file(state_dir.join("checkpoint.json")).unwrap();
    let shipper = Shipper::spawn_with_roots(shipping_config(port, &state_dir, json!({})), log_path.clone(), Some(roots)).unwrap();
    let metrics = shipper.metrics();
    assert!(wait_until(Duration::from_secs(10), || metrics.batches_acknowledged() == 1));
    shipper.shutdown(Duration::from_secs(5)).unwrap();
    let fake = state.lock().unwrap();
    // The replay batched all three exchanges together, so its id is new, but
    // every row repeats a part id the server already holds: nothing is stored twice.
    assert_eq!(fake.requests.iter().filter(|p| *p == INGEST_PATH).count(), 4);
    assert_eq!(fake.stored_rows, 6);
    assert!(fake.batches.last().unwrap().1.is_empty());
    assert_eq!(fake.batches[0].0, first_id);
}

#[test]
fn ships_many_exchanges_in_bounded_batches_with_drain_mode() {
    let (port, roots, state, _server) = fake_server(TOKEN);
    let dir = TempDir::new(); let state_dir = dir.0.join("state"); std::fs::create_dir(&state_dir).unwrap();
    let log_path = dir.0.join("audit.log");
    let mut log = DiskLog::create(&log_path, 8, Duration::from_secs(2)).unwrap();
    let big = vec![b'x'; 300 * 1024];
    for request in 1..=20u64 {
        write_exchange(&mut log, request, "https://api.anthropic.com/v1/messages", &big, 200, &[&big], 0);
    }
    // Two open exchanges never complete; drain flushes them as incomplete.
    let start = encode_request_start(1, 7, b"https://api.anthropic.com/v1/messages").unwrap();
    log.append(LogRecord { tenant: 1, request: 21, chunk: 0, kind: RecordKind::RequestStart, bytes: &start }).unwrap();
    log.append(LogRecord { tenant: 1, request: 22, chunk: 0, kind: RecordKind::RequestStart, bytes: &start }).unwrap();
    log.append(LogRecord { tenant: 1, request: 22, chunk: 1, kind: RecordKind::Upload, bytes: b"partial" }).unwrap();
    drop(log);
    let mut config = shipping_config(port, &state_dir, json!({"max_exchange_bytes": 1048576}));
    config.poll_ms = 100;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(ship_to_end_with_roots(config, log_path, Some(roots)).map(|m| m.batches_acknowledged()));
    });
    let result = rx.recv_timeout(Duration::from_secs(60)).expect("drain thread reports");
    let acknowledged = result.expect("drain finishes");
    let fake = state.lock().unwrap();
    let rows: Vec<&Value> = fake.batches.iter().flat_map(|b| b.1.iter()).collect();
    assert_eq!(rows.len(), 44);
    assert!(acknowledged >= 4, "600 KiB per exchange cannot fit 22 exchanges into one 4 MiB batch: {acknowledged}");
    assert_eq!(fake.batches.len() as u64, acknowledged);
    for batch in &fake.batches { assert!(batch.1.len() % 2 == 0, "batches hold whole exchanges"); }
    let incomplete: Vec<_> = rows.iter().filter(|r| r["attributes"]["gateway"]["incomplete"] == true).collect();
    assert_eq!(incomplete.len(), 4);
    assert!(rows.iter().all(|r| r["attributes"]["gateway"]["truncated"] == false));
    let part_ids: HashSet<_> = rows.iter().map(|r| r["part_id"].as_str().unwrap()).collect();
    assert_eq!(part_ids.len(), 44);
    assert_eq!(load_checkpoint(&state_dir).unwrap().resolved, 22);
}

#[test]
fn recovers_from_rejected_tokens_throttling_and_poison_and_stops_on_revocation() {
    let (port, roots, state, _server) = fake_server(TOKEN);
    {
        let mut fake = state.lock().unwrap();
        fake.ingest_script.extend([
            (401, "unauthorized", None),            // one refresh, then retry
            (429, "byte_rate", Some(1)),            // honor Retry-After 1s
            (422, "malformed_ndjson", None),        // whole batch rejected: isolate exchanges
            (422, "malformed_ndjson", None),        // single exchange rejected: poison it
            (401, "unauthorized", None),            // refresh is rejected too: bootstrap again
            (401, "unauthorized", None),            // one refresh after the new enrollment
        ]);
        fake.refresh_script.push_back((200, ""));
        fake.refresh_script.push_back((401, "jwt_invalid_or_revoked"));
    }
    let dir = TempDir::new(); let state_dir = dir.0.join("state"); std::fs::create_dir(&state_dir).unwrap();
    let log_path = dir.0.join("audit.log");
    let mut log = DiskLog::create(&log_path, 4, Duration::from_secs(2)).unwrap();
    for request in 1..=3u64 { write_exchange(&mut log, request, "https://api.anthropic.com/v1/messages", b"{}", 200, &[b"{}"], 0); }
    let shipper = Shipper::spawn_with_roots(shipping_config(port, &state_dir, json!({})), log_path.clone(), Some(roots.clone())).unwrap();
    let metrics = shipper.metrics();
    assert!(wait_until(Duration::from_secs(30), || metrics.batches_acknowledged() == 2 && metrics.poisoned_batches() == 1),
        "acked {} poisoned {} requests {:?}", metrics.batches_acknowledged(), metrics.poisoned_batches(), state.lock().unwrap().requests);
    {
        let fake = state.lock().unwrap();
        assert_eq!(fake.requests.iter().filter(|p| *p == BOOTSTRAP_PATH).count(), 2, "{:?}", fake.requests);
        assert_eq!(fake.requests.iter().filter(|p| *p == REFRESH_PATH).count(), 3, "{:?}", fake.requests);
        // The poisoned exchange (request 1) is skipped; requests 2 and 3 arrive one per batch.
        assert_eq!(fake.batches.len(), 2);
        let requests: Vec<_> = fake.batches.iter().flat_map(|b| b.1.iter()).map(|r| r["attributes"]["gateway"]["exchange_id"].as_str().unwrap().to_owned()).collect();
        assert_eq!(requests.len(), 4);
        assert!(!requests.iter().any(|id| *id == hex(&gateway_core::shipping_identity::exchange_key(&log.session(), 1))));
    }
    assert_eq!(load_checkpoint(&state_dir).unwrap().poisoned, 1);
    // Revocation stops the shipper for good; later exchanges stay unshipped.
    state.lock().unwrap().ingest_script.push_back((403, "service_token_revoked", None));
    write_exchange(&mut log, 4, "https://api.anthropic.com/v1/messages", b"{}", 200, &[b"{}"], 0);
    assert!(wait_until(Duration::from_secs(10), || metrics.stopped()));
    write_exchange(&mut log, 5, "https://api.anthropic.com/v1/messages", b"{}", 200, &[b"{}"], 0);
    thread::sleep(Duration::from_millis(400));
    assert_eq!(state.lock().unwrap().batches.len(), 2);
    assert!(!metrics.enrolled());
    shipper.shutdown(Duration::from_secs(5)).unwrap();
    // A fresh shipper with the same token is told so at bootstrap and stops too.
    state.lock().unwrap().bootstrap_script.push_back((403, "service_account_disabled"));
    std::fs::remove_file(state_dir.join("identity.json")).unwrap();
    let shipper = Shipper::spawn_with_roots(shipping_config(port, &state_dir, json!({})), log_path, Some(roots)).unwrap();
    let metrics = shipper.metrics();
    assert!(wait_until(Duration::from_secs(10), || metrics.stopped()));
    shipper.shutdown(Duration::from_secs(5)).unwrap();
}

#[test]
fn shutdown_returns_within_its_window_while_the_server_hangs() {
    let (port, roots, state, _server) = fake_server(TOKEN);
    state.lock().unwrap().hang = true;
    let dir = TempDir::new(); let state_dir = dir.0.join("state"); std::fs::create_dir(&state_dir).unwrap();
    let log_path = dir.0.join("audit.log");
    let mut log = DiskLog::create(&log_path, 4, Duration::from_secs(2)).unwrap();
    write_exchange(&mut log, 1, "https://api.anthropic.com/v1/messages", b"{}", 200, &[b"{}"], 0);
    let shipper = Shipper::spawn_with_roots(shipping_config(port, &state_dir, json!({})), log_path, Some(roots)).unwrap();
    let metrics = shipper.metrics();
    assert!(wait_until(Duration::from_secs(5), || state.lock().unwrap().requests.iter().any(|p| p == BOOTSTRAP_PATH)));
    let started = std::time::Instant::now();
    let result = shipper.shutdown(Duration::from_millis(300));
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(metrics.batches_acknowledged(), 0);
}

// ---- configuration ---------------------------------------------------------

#[test]
fn shipping_section_is_optional_and_validated() {
    let dir = TempDir::new();
    let resolver = |name: &str| (name == "HYP_TOKEN").then(|| TOKEN.to_owned());
    let without = br#"{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{"requests":1,"chunk_bytes":4},"logging":"strict"}"#;
    assert!(ShippingConfig::from_root_json(without, resolver).unwrap().is_none());
    assert!(crate::config::GatewayConfig::from_json(&shipping_json(443, &dir.0, json!({})), br#"{"routes":[]}"#, |_| None).is_ok(),
        "the gateway configuration ignores the section");
    let config = ShippingConfig::from_root_json(&shipping_json(443, &dir.0, json!({})), resolver).unwrap().unwrap();
    assert_eq!(config.server.url(), "https://localhost:443/");
    assert_eq!((config.max_open_exchanges, config.max_exchange_bytes, config.poll_ms), (64, 1_048_576, 100));
    for (extra, error) in [
        (json!({"server": "http://localhost/"}), crate::config::ConfigError::Destination),
        (json!({"server": "https://user@localhost/"}), crate::config::ConfigError::Destination),
        (json!({"max_open_exchanges": 0}), crate::config::ConfigError::Limits),
        (json!({"max_open_exchanges": 65537}), crate::config::ConfigError::Limits),
        (json!({"max_exchange_bytes": 4095}), crate::config::ConfigError::Limits),
        (json!({"max_exchange_bytes": 16 * 1024 * 1024 + 1}), crate::config::ConfigError::Limits),
        (json!({"poll_ms": 99}), crate::config::ConfigError::Limits),
        (json!({"poll_ms": 60001}), crate::config::ConfigError::Limits),
        (json!({"token_env": "has space"}), crate::config::ConfigError::Credential),
        (json!({"token_env": "MISSING"}), crate::config::ConfigError::Credential),
        (json!({"state_dir": ""}), crate::config::ConfigError::Limits),
        (json!({"unknown": 1}), crate::config::ConfigError::Syntax),
    ] {
        assert_eq!(ShippingConfig::from_root_json(&shipping_json(443, &dir.0, extra.clone()), resolver).err(), Some(error), "{extra}");
    }
    for bad in ["", "with space", &"x".repeat(513), "tab\there"] {
        let bad = bad.to_owned();
        assert_eq!(ShippingConfig::from_root_json(&shipping_json(443, &dir.0, json!({})), |_| Some(bad.clone())).err(), Some(crate::config::ConfigError::Credential));
    }
    assert!(ShippingConfig::from_root_json(&shipping_json(443, &dir.0, json!({})), |_| Some("x".repeat(512))).is_ok());
}

// ---- state files -----------------------------------------------------------

#[test]
fn state_files_round_trip_and_jwt_claims_are_read_without_verification() {
    let dir = TempDir::new();
    let identity = Identity { jwt: fake_jwt("gw-abc", 99, 1), expires_at: 99, gateway_id: "gw-abc".into(), server: "https://h/".into(), token_fingerprint: "ff".into() };
    save_identity(&dir.0, &identity).unwrap();
    assert_eq!(load_identity(&dir.0).unwrap(), identity);
    let checkpoint = Checkpoint { session: "00".repeat(16), resolved: 5, poisoned: 1, max_open_exchanges: 64, max_exchange_bytes: 4096 };
    save_checkpoint(&dir.0, &checkpoint).unwrap();
    assert_eq!(load_checkpoint(&dir.0).unwrap(), checkpoint);
    assert!(!dir.0.join("identity.json.tmp").exists());
    std::fs::write(dir.0.join("checkpoint.json"), b"not json").unwrap();
    assert!(load_checkpoint(&dir.0).is_none());
    assert!(load_identity(&dir.0.join("missing")).is_none());
    assert_eq!(jwt_claims(&fake_jwt("gw-0123456789abcdef", 1_800_000_000, 1)), Some(("gw-0123456789abcdef".into(), 1_800_000_000)));
    assert!(jwt_claims("not.a").is_none());
    assert!(jwt_claims("a.b.c.d").is_none());
    assert!(jwt_claims(&format!("x.{}.y", base64url_encode(br#"{"exp":1}"#))).is_none(), "no sub");
    assert!(jwt_claims(&format!("x.{}.y", base64url_encode(br#"{"sub":"g"}"#))).is_none(), "no exp");
    assert!(jwt_claims(&format!("x.{}.y", base64url_encode(br#"{"sub":"","exp":1}"#))).is_none());
    assert!(jwt_claims("x.!!!!.y").is_none());
    for bytes in [&b""[..], b"a", b"ab", b"abc", b"abcd", &[0xff, 0x00, 0x80]] {
        assert_eq!(state::base64url_decode_for_test(&base64url_encode(bytes)).unwrap(), bytes);
    }
}

// ---- projection ------------------------------------------------------------

fn exchange(destination: &str, upload: &[u8], status: Option<u16>, download: &[&[u8]], outcome: Option<u8>) -> Exchange {
    let mut a = Assembler::new(4, 1 << 20);
    let start = encode_request_start(1_700_000_000_000, 7, destination.as_bytes()).unwrap();
    a.admit(Header { payload: start.len() as u32, tenant: 3, request: 42, chunk: 0, kind: 2 }, &start);
    a.admit(Header { payload: upload.len() as u32, tenant: 3, request: 42, chunk: 1, kind: 0 }, upload);
    if let Some(status) = status {
        let head = encode_response_head(1_700_000_000_250, status).unwrap();
        a.admit(Header { payload: head.len() as u32, tenant: 3, request: 42, chunk: 0, kind: 3 }, &head);
    }
    for (i, chunk) in download.iter().enumerate() {
        a.admit(Header { payload: chunk.len() as u32, tenant: 3, request: 42, chunk: 2 + i as u64, kind: 1 }, chunk);
    }
    match outcome {
        Some(outcome) => {
            let done = encode_completion(1_700_000_000_900, outcome, 1, 1).unwrap();
            a.admit(Header { payload: done.len() as u32, tenant: 3, request: 42, chunk: 0, kind: 4 }, &done).unwrap()
        }
        None => a.evict_oldest().unwrap(),
    }
}

#[test]
fn projection_reads_anthropic_sse_openai_json_and_sse_and_raw_bodies() {
    let session = [5u8; 16];
    let sse = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4\",\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":4,\"cache_creation_input_tokens\":0,\"output_tokens\":1}}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hel\"}}\n\n\
event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"lo\"}}\n\n\
event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":9}}\n\n\
event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    let e = exchange("https://api.anthropic.com/v1/messages", br#"{"model":"claude-sonnet-4","stream":true,"messages":[{"role":"user","content":[{"type":"text","text":"a"},{"type":"text","text":"b"}]},{"role":"assistant","content":"x"},{"role":"user","content":"second"}]}"#,
        Some(200), &[&sse[..40], &sse[40..]], Some(0));
    let rows = project(&session, &e, 1 << 20);
    assert_eq!(rows[0]["content_text"], "second"); assert_eq!(rows[1]["content_text"], "Hello");
    assert_eq!(rows[1]["attributes"]["usage"], json!({"input_tokens":10,"cache_read_tokens":4,"cache_write_tokens":0,"output_tokens":9,"total_tokens":23}));
    assert_eq!(rows[1]["attributes"]["gateway"]["is_sse"], true); assert_eq!(rows[0]["model"], "claude-sonnet-4");
    assert_eq!(rows[0]["session_id"], rows[0]["attributes"]["gateway"]["exchange_id"], "no hint: the exchange id");
    assert_eq!(rows[0]["user_id"], "3"); assert_eq!(rows[0]["conversation_started_at"], "2023-11-14T22:13:20.000Z");
    assert_eq!(rows[1]["message_created_at"], "2023-11-14T22:13:20.900Z"); assert_eq!(rows[0]["is_error"], false);

    let openai = br#"{"id":"resp_1","model":"gpt-5","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Pong"}]}],"usage":{"input_tokens":20,"input_tokens_details":{"cached_tokens":5},"output_tokens":3}}"#;
    let e = exchange("https://api.openai.com/v1/responses", br#"{"model":"gpt-5","input":[{"role":"user","content":[{"type":"input_text","text":"Ping"}]}]}"#, Some(200), &[openai], Some(0));
    let rows_openai = project(&session, &e, 1 << 20);
    assert_eq!(rows_openai[0]["content_text"], "Ping"); assert_eq!(rows_openai[1]["content_text"], "Pong");
    assert_eq!(rows_openai[1]["attributes"]["usage"], json!({"input_tokens":15,"cache_read_tokens":5,"cache_write_tokens":0,"output_tokens":3,"total_tokens":23}));
    assert_eq!(rows_openai[0]["provider"], "openai");

    let openai_sse = b"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"Po\"}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"ng\"}\n\nevent: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"model\":\"gpt-5-mini\",\"usage\":{\"input_tokens\":8,\"output_tokens\":2}}}\n\n";
    let e = exchange("https://api.openai.com/v1/responses", br#"{"input":"hi"}"#, Some(200), &[openai_sse], Some(0));
    let rows_sse = project(&session, &e, 1 << 20);
    assert_eq!(rows_sse[1]["content_text"], "Pong"); assert_eq!(rows_sse[0]["model"], "gpt-5-mini");
    assert_eq!(rows_sse[1]["attributes"]["usage"]["total_tokens"], 10);

    let chat = br#"{"choices":[{"message":{"role":"assistant","content":"Yo"}}],"usage":{"prompt_tokens":4,"completion_tokens":1,"prompt_tokens_details":{"cached_tokens":1}}}"#;
    let e = exchange("https://llm.example.net:8443/v1/chat/completions", b"\xff\xfe not utf8 or json", Some(200), &[chat], Some(0));
    let rows_chat = project(&session, &e, 1 << 20);
    assert_eq!(rows_chat[0]["provider"], "llm.example.net"); assert_eq!(rows_chat[1]["content_text"], "Yo");
    assert_eq!(rows_chat[1]["attributes"]["usage"], json!({"input_tokens":3,"cache_read_tokens":1,"cache_write_tokens":0,"output_tokens":1,"total_tokens":5}));
    assert_eq!(rows_chat[0]["attributes"]["gateway"]["path"], "/v1/chat/completions");
    assert!(rows_chat[0]["content_text"].as_str().unwrap().contains("not utf8 or json"));

    // Failure before any response head: no status, outcome from the completion, raw text capped.
    let e = exchange("https://api.anthropic.com/v1/messages", &vec![b'q'; 100], None, &[], Some(2));
    let rows_timeout = project(&session, &e, 10);
    assert_eq!(rows_timeout[0]["content_text"].as_str().unwrap().len(), 10);
    assert_eq!(rows_timeout[1]["content_text"], ""); assert!(rows_timeout[1]["attributes"].get("usage").is_none());
    assert_eq!(rows_timeout[1]["is_error"], true); assert_eq!(rows_timeout[1]["status"], json!({"code": null, "outcome": 2}));
    assert_eq!(rows_timeout[1]["attributes"]["gateway"]["outcome"], "upstream_timeout");
    // Evicted without completion: incomplete and an error.
    let e = exchange("https://api.anthropic.com/v1/messages", b"{}", Some(200), &[b"{\"content\":[]}"], None);
    let rows_incomplete = project(&session, &e, 1 << 20);
    assert_eq!(rows_incomplete[0]["attributes"]["gateway"]["incomplete"], true); assert_eq!(rows_incomplete[0]["is_error"], true);
    assert_eq!(rows_incomplete[1]["message_created_at"], "2023-11-14T22:13:20.250Z");
    for row in rows_incomplete.iter().chain(&rows_timeout).chain(&rows_chat) {
        let text = row.to_string();
        assert!(!text.contains("raw_frame") && !text.contains("authorization") && !text.contains("x-api-key"));
        assert!(!text.contains('\n'));
    }
}
