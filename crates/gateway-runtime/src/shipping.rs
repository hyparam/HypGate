//! Cloud shipping: one dedicated thread tails the audit log read-only, groups
//! records into exchanges with the verified assembler, projects them into
//! HypAware rows, and uploads NDJSON batches to the configured server. It
//! shares no executor, pool, or handle with request workers; its only inputs
//! are the log path, the server, the token, and a state directory, and its only
//! outputs are metrics. Failure here never touches admission or readiness.
use gateway_core::batch_builder::BatchBuilder;
use gateway_core::enrollment::{throttle_delay, transport_delay, Enrollment, Recovery};
use gateway_core::exchange_assembler::{Assembler, Exchange};
use gateway_core::framing::Header;
use gateway_core::upload_cursor::UploadCursor;
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, fs::File, io::{self, Seek, SeekFrom}, path::PathBuf, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}, mpsc}, time::{Duration, SystemTime}};
use tokio_rustls::rustls::RootCertStore;
use crate::disk_log::{LogReader, ScanError};

pub mod config;
pub mod client;
pub mod state;
pub mod projection;
pub use config::ShippingConfig;
use client::{Client, ClientError, Reply};
use state::{hex, Checkpoint, Identity};

const INGEST_PATH: &str = "/v1/ingest/proxy";
const BOOTSTRAP_PATH: &str = "/v1/identity/bootstrap";
const REFRESH_PATH: &str = "/v1/identity/refresh";
const REQUEST_DEADLINE: Duration = Duration::from_secs(30);
const STACK_BYTES: usize = 2 * 1024 * 1024;
/// Polls with no new bytes before a drain run flushes open exchanges and exits.
const DRAIN_IDLE_POLLS: u32 = 5;

#[derive(Default)]
pub struct Metrics {
    enrolled: AtomicBool, stopped: AtomicBool, read_failed: AtomicBool,
    records_read: AtomicU64, exchanges_emitted: AtomicU64, lag: AtomicU64,
    batches_acknowledged: AtomicU64, last_acknowledged_ms: AtomicU64, poisoned_batches: AtomicU64,
}
impl Metrics {
    pub fn stopped(&self) -> bool { self.stopped.load(Ordering::Relaxed) }
    pub fn enrolled(&self) -> bool { self.enrolled.load(Ordering::Relaxed) }
    pub fn batches_acknowledged(&self) -> u64 { self.batches_acknowledged.load(Ordering::Relaxed) }
    pub fn poisoned_batches(&self) -> u64 { self.poisoned_batches.load(Ordering::Relaxed) }
    pub fn lag(&self) -> u64 { self.lag.load(Ordering::Relaxed) }
    pub fn records_read(&self) -> u64 { self.records_read.load(Ordering::Relaxed) }
    /// Prometheus text lines; `enabled` is 1 whenever a shipper exists.
    pub fn render(&self, out: &mut String) {
        use std::fmt::Write as _;
        let _ = write!(out, "soundgate_shipping_enabled 1\nsoundgate_shipping_enrolled {}\nsoundgate_shipping_stopped {}\nsoundgate_shipping_log_read_failed {}\n\
            soundgate_shipping_records_read_total {}\nsoundgate_shipping_exchanges_emitted_total {}\nsoundgate_shipping_lag_exchanges {}\n\
            soundgate_shipping_batches_acknowledged_total {}\nsoundgate_shipping_last_acknowledged_unix_ms {}\nsoundgate_shipping_poisoned_batches_total {}\n",
            u8::from(self.enrolled()), u8::from(self.stopped()), u8::from(self.read_failed.load(Ordering::Relaxed)),
            self.records_read(), self.exchanges_emitted.load(Ordering::Relaxed), self.lag(),
            self.batches_acknowledged(), self.last_acknowledged_ms.load(Ordering::Relaxed), self.poisoned_batches());
    }
}

/// Handle to the shipper thread: metrics and shutdown only.
pub struct Shipper { stop: Arc<AtomicBool>, finished: mpsc::Receiver<()>, thread: Option<std::thread::JoinHandle<()>>, metrics: Arc<Metrics> }
impl Shipper {
    /// Start the thread. The log must already exist with a valid header.
    pub fn spawn(config: ShippingConfig, log_path: PathBuf) -> io::Result<Self> { Self::spawn_with_roots(config, log_path, None) }
    pub fn spawn_with_roots(config: ShippingConfig, log_path: PathBuf, roots: Option<RootCertStore>) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Metrics::default());
        let (done, finished) = mpsc::channel();
        let (flag, shared) = (stop.clone(), metrics.clone());
        let thread = std::thread::Builder::new().name("soundgate-shipping".into()).stack_size(STACK_BYTES).spawn(move || {
            let _done = done; // dropped when the thread ends, however it ends
            let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(runtime) => runtime, Err(_) => { shared.stopped.store(true, Ordering::Relaxed); return; }
            };
            let result = runtime.block_on(Engine::new(config, log_path, roots, flag, shared.clone()).run(Mode::Follow));
            if result.is_err() { shared.stopped.store(true, Ordering::Relaxed); }
        })?;
        Ok(Self { stop, finished, thread: Some(thread), metrics })
    }
    pub fn metrics(&self) -> Arc<Metrics> { self.metrics.clone() }
    /// Ask the thread to stop after its current step and join it within the
    /// deadline. A thread still inside a request is left to finish on its own;
    /// nothing replaces it.
    pub fn shutdown(mut self, deadline: Duration) -> io::Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        match self.finished.recv_timeout(deadline) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.thread.take().map(|t| t.join()).transpose().map(|_| ()).map_err(|_| io::Error::other("shipper panicked"))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => { self.thread.take(); Err(io::ErrorKind::TimedOut.into()) }
        }
    }
}
impl Drop for Shipper { fn drop(&mut self) { self.stop.store(true, Ordering::Relaxed); } }

/// Ship a finished log on the current thread until every exchange is resolved
/// or the enrollment is stopped for good. Used by `soundgate ship`.
pub fn ship_to_end(config: ShippingConfig, log_path: PathBuf) -> Result<Metrics, &'static str> { ship_to_end_with_roots(config, log_path, None) }
pub fn ship_to_end_with_roots(config: ShippingConfig, log_path: PathBuf, roots: Option<RootCertStore>) -> Result<Metrics, &'static str> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| "cannot start shipping runtime")?;
    let metrics = Arc::new(Metrics::default());
    let stop = Arc::new(AtomicBool::new(false));
    let result = runtime.block_on(Engine::new(config, log_path, roots, stop, metrics.clone()).run(Mode::Drain));
    result.map(|_| Arc::try_unwrap(metrics).unwrap_or_default())
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Mode { Follow, Drain }

struct Pending { rows: Vec<Vec<u8>> }

struct Engine {
    config: ShippingConfig,
    log_path: PathBuf,
    roots: Option<RootCertStore>,
    stop: Arc<AtomicBool>,
    metrics: Arc<Metrics>,
    client: Option<Client>,
    session: Option<[u8; 16]>,
    valid_end: u64,
    read_failed: bool,
    assembler: Assembler,
    cursor: UploadCursor,
    emitted_total: u64,
    skip: u64,
    queue: VecDeque<Pending>,
    enrollment: Enrollment,
    jwt: Option<String>,
    gateway_id: Option<String>,
    throttle_attempt: u32,
    transport_attempt: u32,
    enroll_attempt: u32,
    /// Exchanges per batch; drops to one after a rejected batch so the bad
    /// exchange is isolated and poisoned alone, and recovers after a success.
    batch_limit: u64,
}

fn now_seconds() -> u64 { SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
fn now_ms() -> u64 { SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis().min(u64::MAX as u128) as u64).unwrap_or(0) }

impl Engine {
    fn new(config: ShippingConfig, log_path: PathBuf, roots: Option<RootCertStore>, stop: Arc<AtomicBool>, metrics: Arc<Metrics>) -> Self {
        let assembler = Assembler::new(config.max_open_exchanges, config.max_exchange_bytes);
        Engine { config, log_path, roots, stop, metrics, client: None, session: None, valid_end: 56, read_failed: false,
            assembler, cursor: UploadCursor::restore(0, 0, 0).expect("empty cursor"), emitted_total: 0, skip: 0,
            queue: VecDeque::new(), enrollment: Enrollment::new(), jwt: None, gateway_id: None,
            throttle_attempt: 0, transport_attempt: 0, enroll_attempt: 0, batch_limit: u64::MAX }
    }

    fn stopping(&self) -> bool { self.stop.load(Ordering::Relaxed) }

    /// Sleep in short slices so a stop request is honored promptly. False when stopping.
    async fn wait(&self, duration: Duration) -> bool {
        let mut remaining = duration;
        while !remaining.is_zero() {
            if self.stopping() { return false; }
            let slice = remaining.min(Duration::from_millis(100));
            tokio::time::sleep(slice).await;
            remaining -= slice;
        }
        !self.stopping()
    }

    async fn run(mut self, mode: Mode) -> Result<(), &'static str> {
        let client = match self.roots.take() {
            Some(roots) => Client::with_roots(roots, &self.config.server, REQUEST_DEADLINE),
            None => Client::new(&self.config.server, REQUEST_DEADLINE),
        }.map_err(|_| "cannot initialize shipping client")?;
        self.client = Some(client);
        self.restore_identity();
        let mut idle_polls = 0u32;
        loop {
            if self.stopping() { return Ok(()); }
            if self.enrollment.is_stopped() {
                self.metrics.stopped.store(true, Ordering::Relaxed);
                if mode == Mode::Drain { return Err("shipping stopped: token revoked or account disabled"); }
                self.wait(Duration::from_millis(self.config.poll_ms)).await;
                continue;
            }
            // The log file is the buffer: stop reading while the queue is full.
            let read = if self.read_failed || self.queue.len() >= self.config.max_open_exchanges { 0 } else { self.read_records() };
            if mode == Mode::Drain {
                if read == 0 { idle_polls += 1; } else { idle_polls = 0; }
                if idle_polls >= DRAIN_IDLE_POLLS {
                    while let Some(exchange) = self.assembler.evict_oldest() { self.emit(exchange); }
                    if self.queue.is_empty() { return Ok(()); }
                }
            }
            if self.queue.is_empty() {
                if !self.wait(Duration::from_millis(self.config.poll_ms)).await { return Ok(()); }
                continue;
            }
            self.ship_next().await;
        }
    }

    fn restore_identity(&mut self) {
        let Some(identity) = state::load_identity(&self.config.state_dir) else { return; };
        let same = identity.server == self.config.server.to_string()
            && identity.token_fingerprint == state::fingerprint(self.config.token());
        if !same { return; }
        if self.enrollment.enrolled(identity.expires_at, now_seconds()) {
            self.jwt = Some(identity.jwt); self.gateway_id = Some(identity.gateway_id);
            self.metrics.enrolled.store(true, Ordering::Relaxed);
        }
    }

    /// Scan from the last valid end; returns the number of records admitted.
    /// Corruption or an I/O error stops reading for good but not shipping.
    fn read_records(&mut self) -> u64 {
        let Ok(mut file) = File::open(&self.log_path) else { return 0; };
        let mut reader = if let Some(session) = self.session {
            if file.seek(SeekFrom::Start(self.valid_end)).is_err() { return 0; }
            match LogReader::resume(file, session, self.valid_end) { Ok(r) => r, Err(_) => { self.fail_reading(); return 0; } }
        } else {
            match LogReader::new(file) {
                Ok(reader) => { self.start_session(reader.session()); reader }
                Err(ScanError::Incomplete) => return 0,
                Err(_) => { self.fail_reading(); return 0; }
            }
        };
        let mut count = 0;
        loop {
            match reader.next_record() {
                Ok(Some(record)) => {
                    count += 1;
                    self.metrics.records_read.fetch_add(1, Ordering::Relaxed);
                    let header = Header { payload: record.bytes.len() as u32, tenant: record.tenant, request: record.request,
                        chunk: record.chunk, kind: record.kind.id() };
                    if let Some(exchange) = self.assembler.admit(header, &record.bytes) { self.emit(exchange); }
                    if self.queue.len() >= self.config.max_open_exchanges { break; }
                }
                Ok(None) | Err(ScanError::Incomplete) => break,
                Err(_) => { self.fail_reading(); break; }
            }
        }
        self.valid_end = reader.valid_end();
        count
    }

    fn fail_reading(&mut self) { self.read_failed = true; self.metrics.read_failed.store(true, Ordering::Relaxed); }

    fn start_session(&mut self, session: [u8; 16]) {
        self.session = Some(session);
        self.valid_end = 56;
        let checkpoint = state::load_checkpoint(&self.config.state_dir).filter(|c| c.session == hex(&session)
            && c.max_open_exchanges == self.config.max_open_exchanges && c.max_exchange_bytes == self.config.max_exchange_bytes);
        if let Some(checkpoint) = checkpoint {
            if let Some(cursor) = UploadCursor::restore(checkpoint.resolved, checkpoint.resolved, checkpoint.poisoned) {
                self.cursor = cursor; self.skip = checkpoint.resolved;
            }
        }
    }

    /// Project an emitted exchange and queue its rows, unless the checkpoint
    /// says the server already has it.
    fn emit(&mut self, exchange: Exchange) {
        let index = self.emitted_total; self.emitted_total += 1;
        self.metrics.exchanges_emitted.fetch_add(1, Ordering::Relaxed);
        if index < self.skip { return; }
        if !self.cursor.emit(1) { self.fail_reading(); return; }
        let session = self.session.unwrap_or([0; 16]);
        let rows = projection::rows(&session, &exchange, self.config.max_exchange_bytes).iter()
            .map(|row| serde_json::to_vec(row).unwrap_or_default()).collect();
        self.queue.push_back(Pending { rows });
        self.metrics.lag.store(self.queue.len() as u64, Ordering::Relaxed);
    }

    fn save_checkpoint(&self) {
        let Some(session) = self.session else { return; };
        let (_, resolved, poisoned) = self.cursor.counts();
        let _ = state::save_checkpoint(&self.config.state_dir, &Checkpoint { session: hex(&session), resolved, poisoned,
            max_open_exchanges: self.config.max_open_exchanges, max_exchange_bytes: self.config.max_exchange_bytes });
    }

    fn resolve_front(&mut self, count: u64) {
        for _ in 0..count { self.queue.pop_front(); }
        self.metrics.lag.store(self.queue.len() as u64, Ordering::Relaxed);
        self.save_checkpoint();
    }

    /// Build the next batch from whole exchanges at the queue front and send it.
    async fn ship_next(&mut self) {
        if !self.ensure_enrolled().await { return; }
        let Some(session) = self.session else { return; };
        let mut builder = BatchBuilder::new();
        let mut count = 0u64;
        for pending in &self.queue {
            if count >= self.batch_limit { break; }
            let before = builder.len();
            let fits = pending.rows.iter().all(|row| builder.push(row));
            if !fits {
                if count == 0 {
                    // An exchange no batch can hold: poison it without sending.
                    let digest = Sha256::digest(builder.bytes());
                    let _ = self.cursor.open_batch(1, &session, &digest.into());
                    self.poison();
                    return;
                }
                // Drop the partial rows of this exchange and send what fits.
                let kept = builder.bytes()[..before].to_vec();
                builder = BatchBuilder::new();
                for row in kept.split_inclusive(|b| *b == b'\n') { builder.push(&row[..row.len() - 1]); }
                break;
            }
            count += 1;
        }
        if count == 0 || builder.is_empty() { return; }
        let body = builder.finish();
        let digest: [u8; 32] = Sha256::digest(&body).into();
        if !self.cursor.open_batch(count, &session, &digest) { return; }
        let id = hex(self.cursor.current().map(|b| b.batch_id().as_slice()).unwrap_or(&[]));
        let Some(jwt) = self.jwt.clone() else { self.cursor.abandon(); return; };
        let headers = [("content-type", "application/x-ndjson".to_owned()), ("x-hyp-batch-id", id.clone())];
        let reply = self.client.as_ref().expect("client").request("POST", INGEST_PATH, Some(&jwt), &headers, body).await;
        match reply {
            Ok(Reply { status: 200 | 202, .. }) => {
                let raw = self.cursor.current().map(|b| b.batch_id().clone()).unwrap_or_default();
                if self.cursor.acknowledge(&raw) {
                    self.resolve_front(count);
                    self.enrollment.uploaded();
                    self.metrics.batches_acknowledged.fetch_add(1, Ordering::Relaxed);
                    self.metrics.last_acknowledged_ms.store(now_ms(), Ordering::Relaxed);
                    self.throttle_attempt = 0; self.transport_attempt = 0; self.batch_limit = u64::MAX;
                }
            }
            Ok(Reply { status: 401, .. }) => {
                self.cursor.abandon();
                match self.enrollment.rejected() {
                    Recovery::Refresh => self.refresh().await,
                    Recovery::Bootstrap => { self.jwt = None; self.metrics.enrolled.store(false, Ordering::Relaxed); }
                    Recovery::Stop => {}
                }
            }
            Ok(reply @ Reply { status: 403, .. }) => {
                self.cursor.abandon();
                if is_revocation(&reply) { self.revoke(); } else { self.throttle(None).await; }
            }
            Ok(Reply { status: 400 | 413 | 415 | 422, .. }) => {
                if count > 1 { self.cursor.abandon(); self.batch_limit = 1; } else { self.poison(); }
            }
            Ok(Reply { status: 429 | 503, retry_after, .. }) => { self.cursor.abandon(); self.throttle(retry_after).await; }
            Ok(_) | Err(_) => { self.cursor.abandon(); self.transport_failure().await; }
        }
    }

    fn poison(&mut self) {
        let (_, before, _) = self.cursor.counts();
        if self.cursor.poison() {
            let (_, after, _) = self.cursor.counts();
            self.metrics.poisoned_batches.fetch_add(1, Ordering::Relaxed);
            self.resolve_front(after - before);
        }
    }

    fn revoke(&mut self) {
        self.enrollment.revoked();
        self.jwt = None;
        self.metrics.enrolled.store(false, Ordering::Relaxed);
        self.metrics.stopped.store(true, Ordering::Relaxed);
    }

    async fn throttle(&mut self, retry_after: Option<u64>) {
        let delay = throttle_delay(self.throttle_attempt, retry_after);
        self.throttle_attempt = self.throttle_attempt.saturating_add(1);
        self.wait(Duration::from_secs(delay)).await;
    }

    async fn transport_failure(&mut self) {
        let delay = transport_delay(self.transport_attempt);
        self.transport_attempt = self.transport_attempt.saturating_add(1);
        self.wait(Duration::from_secs(delay)).await;
    }

    /// True when an unexpired enrollment is available for the next upload.
    async fn ensure_enrolled(&mut self) -> bool {
        if self.enrollment.is_stopped() { return false; }
        let now = now_seconds();
        if self.enrollment.needs_bootstrap() { self.bootstrap().await; }
        else if self.enrollment.needs_refresh(now) { self.refresh().await; }
        let ok = self.enrollment.can_upload(now_seconds()) && self.jwt.is_some();
        self.metrics.enrolled.store(ok, Ordering::Relaxed);
        ok
    }

    fn adopt(&mut self, reply: &Reply) -> bool {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(&reply.body) else { return false; };
        let (Some(jwt), Some(expires_at)) = (value.get("jwt").and_then(|v| v.as_str()), value.get("expires_at").and_then(|v| v.as_u64())) else { return false; };
        if jwt.len() > 16 * 1024 { return false; }
        let Some((gateway_id, exp)) = state::jwt_claims(jwt) else { return false; };
        let expires_at = expires_at.min(exp);
        if !self.enrollment.enrolled(expires_at, now_seconds()) { return false; }
        self.jwt = Some(jwt.to_owned());
        self.gateway_id = Some(gateway_id.clone());
        self.enroll_attempt = 0;
        self.metrics.enrolled.store(true, Ordering::Relaxed);
        let _ = state::save_identity(&self.config.state_dir, &Identity { jwt: jwt.to_owned(), expires_at, gateway_id,
            server: self.config.server.to_string(), token_fingerprint: state::fingerprint(self.config.token()) });
        true
    }

    async fn bootstrap(&mut self) {
        let body = serde_json::to_vec(&serde_json::json!({"bootstrap_token": String::from_utf8_lossy(self.config.token())})).unwrap_or_default();
        let headers = [("content-type", "application/json".to_owned())];
        let reply = self.client.as_ref().expect("client").request("POST", BOOTSTRAP_PATH, None, &headers, body).await;
        self.handle_enrollment_reply(reply, true).await;
    }

    async fn refresh(&mut self) {
        let Some(jwt) = self.jwt.clone() else { return; };
        let reply = self.client.as_ref().expect("client").request("POST", REFRESH_PATH, Some(&jwt), &[], Vec::new()).await;
        self.handle_enrollment_reply(reply, false).await;
    }

    async fn handle_enrollment_reply(&mut self, reply: Result<Reply, ClientError>, bootstrap: bool) {
        match reply {
            Ok(reply @ Reply { status: 200, .. }) => { if !self.adopt(&reply) { self.enroll_backoff().await; } }
            Ok(reply @ Reply { status: 403, .. }) if is_revocation(&reply) => self.revoke(),
            Ok(Reply { status: 401 | 400 | 403, .. }) => {
                if bootstrap { self.enroll_backoff().await; }
                else { self.enrollment.refresh_rejected(); self.jwt = None; self.metrics.enrolled.store(false, Ordering::Relaxed); }
            }
            Ok(Reply { status: 429 | 503, retry_after, .. }) => self.throttle(retry_after).await,
            Ok(_) | Err(_) => self.transport_failure().await,
        }
    }

    async fn enroll_backoff(&mut self) {
        let delay = throttle_delay(self.enroll_attempt, None);
        self.enroll_attempt = self.enroll_attempt.saturating_add(1);
        self.wait(Duration::from_secs(delay)).await;
    }
}

fn is_revocation(reply: &Reply) -> bool {
    matches!(reply.error_code().as_deref(), Some("service_token_revoked" | "service_account_disabled"))
}

#[cfg(test)]
pub(crate) mod tests;
