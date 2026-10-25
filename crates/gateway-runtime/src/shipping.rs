//! Cloud shipping: one dedicated thread tails the audit log read-only and
//! drives the verified shipper machine, which groups records into exchanges,
//! batches their projections, and decides every request, retry, and
//! checkpoint. This module performs those actions against the one configured
//! server and reports replies back. It shares no executor, pool, or handle with
//! request workers; its only inputs are the log path, the server, the token,
//! and a state directory, and its only outputs are metrics. Failure here never
//! touches admission or readiness.
use gateway_core::framing::Header;
use gateway_core::shipper::{Action, Credential, Emitted, Machine, Outcome, Path as ShipPath, Reply as MachineReply, Request};
use std::{fs::File, io::{self, Seek, SeekFrom}, path::PathBuf, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}, mpsc}, time::{Duration, SystemTime}};
use tokio_rustls::rustls::RootCertStore;
use crate::disk_log::{LogReader, ScanError};

pub mod config;
pub mod client;
pub mod state;
pub mod projection;
pub use config::ShippingConfig;
use client::{Client, Reply};
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

/// The runtime half of the shipper: it performs the actions the verified
/// machine chooses and reports replies back. It makes no decisions of its own
/// about what to send, where progress stands, or when to retry.
struct Engine {
    config: ShippingConfig,
    log_path: PathBuf,
    roots: Option<RootCertStore>,
    stop: Arc<AtomicBool>,
    metrics: Arc<Metrics>,
    client: Option<Client>,
    /// Created once the log header is readable, since the session names the checkpoint.
    machine: Option<Machine>,
    valid_end: u64,
    idle_polls: u32,
}

fn now_seconds() -> u64 { SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
fn now_ms() -> u64 { SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis().min(u64::MAX as u128) as u64).unwrap_or(0) }

/// A credential parsed from an enrollment reply, with the gateway id for the identity file.
struct Issued { credential: Credential, gateway_id: String, expires_at: u64 }

fn parse_credential(body: &[u8]) -> Option<Issued> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let jwt = value.get("jwt")?.as_str()?;
    let expires_at = value.get("expires_at")?.as_u64()?;
    if jwt.len() > 16 * 1024 { return None; }
    let (gateway_id, exp) = state::jwt_claims(jwt)?;
    let expires_at = expires_at.min(exp);
    Some(Issued { credential: Credential { jwt: jwt.as_bytes().to_vec(), expires_at }, gateway_id, expires_at })
}

impl Engine {
    fn new(config: ShippingConfig, log_path: PathBuf, roots: Option<RootCertStore>, stop: Arc<AtomicBool>, metrics: Arc<Metrics>) -> Self {
        Engine { config, log_path, roots, stop, metrics, client: None, machine: None, valid_end: 56, idle_polls: 0 }
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
        let poll = Duration::from_millis(self.config.poll_ms);
        loop {
            if self.stopping() { return Ok(()); }
            if self.machine.is_none() {
                match self.open_session() {
                    Some(machine) => self.machine = Some(machine),
                    None => { if !self.wait(poll).await { return Ok(()); } continue; }
                }
            }
            let now = now_seconds();
            let action = self.machine.as_mut().map(|m| m.next(now)).ok_or("shipping machine missing")?;
            match action {
                Action::Stopped => {
                    self.metrics.stopped.store(true, Ordering::Relaxed);
                    if mode == Mode::Drain { return Err("shipping stopped: token revoked or account disabled"); }
                    if !self.wait(poll).await { return Ok(()); }
                }
                Action::Sleep(seconds) => { if !self.wait(Duration::from_secs(seconds)).await { return Ok(()); } }
                Action::Read => {
                    let read = self.read_records();
                    if read == 0 { self.idle_polls = self.idle_polls.saturating_add(1); } else { self.idle_polls = 0; }
                }
                Action::Idle => {
                    if mode == Mode::Drain && self.idle_polls >= DRAIN_IDLE_POLLS {
                        if !self.flush_open() { return Ok(()); }
                        continue;
                    }
                    if !self.wait(poll).await { return Ok(()); }
                }
                Action::Poisoned => {
                    self.metrics.poisoned_batches.fetch_add(1, Ordering::Relaxed);
                    self.save_checkpoint();
                }
                Action::Send(request) => self.perform(request).await,
            }
            if let Some(machine) = &self.machine { self.metrics.lag.store(machine.queue_len() as u64, Ordering::Relaxed); }
        }
    }

    /// Read the log header, build the machine from the matching checkpoint, and
    /// adopt a saved identity for this server and token.
    fn open_session(&mut self) -> Option<Machine> {
        let file = File::open(&self.log_path).ok()?;
        let reader = match LogReader::new(file) {
            Ok(reader) => reader,
            Err(ScanError::Incomplete) => return None,
            Err(_) => { self.metrics.read_failed.store(true, Ordering::Relaxed); return None; }
        };
        let session = reader.session();
        self.valid_end = 56;
        let checkpoint = state::load_checkpoint(&self.config.state_dir).filter(|c| c.session == hex(&session)
            && c.max_open_exchanges == self.config.max_open_exchanges && c.max_exchange_bytes == self.config.max_exchange_bytes);
        let (resolved, poisoned) = checkpoint.map(|c| (c.resolved, c.poisoned)).unwrap_or((0, 0));
        let mut machine = Machine::new(self.config.token().to_vec(), session, self.config.max_open_exchanges,
            self.config.max_exchange_bytes, resolved, poisoned);
        if let Some(identity) = state::load_identity(&self.config.state_dir) {
            let same = identity.server == self.config.server.to_string()
                && identity.token_fingerprint == state::fingerprint(self.config.token());
            if same && machine.adopt_identity(identity.jwt.into_bytes(), identity.expires_at, now_seconds()) {
                self.metrics.enrolled.store(true, Ordering::Relaxed);
            }
        }
        Some(machine)
    }

    /// Scan from the last valid end while the machine wants records; returns
    /// the number of records admitted. Corruption or an I/O error stops reading
    /// for good but not shipping.
    fn read_records(&mut self) -> u64 {
        let Some(machine) = self.machine.as_mut() else { return 0; };
        let session = *machine.session_id();
        let Ok(mut file) = File::open(&self.log_path) else { machine.end_of_log(); return 0; };
        if file.seek(SeekFrom::Start(self.valid_end)).is_err() { machine.end_of_log(); return 0; }
        let mut reader = match LogReader::resume(file, session, self.valid_end) {
            Ok(reader) => reader,
            Err(_) => { machine.log_failed(); self.metrics.read_failed.store(true, Ordering::Relaxed); return 0; }
        };
        let mut count = 0;
        while machine.wants_records() {
            match reader.next_record() {
                Ok(Some(record)) => {
                    count += 1;
                    self.metrics.records_read.fetch_add(1, Ordering::Relaxed);
                    let header = Header { payload: record.bytes.len() as u32, tenant: record.tenant, request: record.request,
                        chunk: record.chunk, kind: record.kind.id() };
                    if let Some(token) = machine.admit(header, &record.bytes) { Self::project(machine, &self.metrics, token); }
                }
                Ok(None) | Err(ScanError::Incomplete) => { machine.end_of_log(); break; }
                Err(_) => { machine.log_failed(); self.metrics.read_failed.store(true, Ordering::Relaxed); break; }
            }
        }
        self.valid_end = reader.valid_end();
        count
    }

    /// Project an emitted exchange into rows and queue it.
    fn project(machine: &mut Machine, metrics: &Metrics, token: Emitted) {
        metrics.exchanges_emitted.fetch_add(1, Ordering::Relaxed);
        let session = *machine.session_id();
        let rows = projection::rows(&session, token.exchange(), machine.exchange_cap());
        let mut body = Vec::new();
        for row in &rows { body.extend_from_slice(&serde_json::to_vec(row).unwrap_or_default()); body.push(b'\n'); }
        if machine.enqueue(token, body, rows.len()).is_err() { machine.log_failed(); metrics.read_failed.store(true, Ordering::Relaxed); }
    }

    /// Drain mode after an idle stretch: emit every open exchange as incomplete.
    /// False when nothing was open and nothing is queued, so the run is finished.
    fn flush_open(&mut self) -> bool {
        let Some(machine) = self.machine.as_mut() else { return false; };
        let mut flushed = false;
        while machine.open_exchanges() > 0 && machine.wants_records() {
            match machine.flush() { Some(token) => { flushed = true; Self::project(machine, &self.metrics, token); } None => break }
        }
        self.idle_polls = 0;
        flushed || machine.queue_len() > 0 || machine.open_exchanges() > 0
    }

    fn save_checkpoint(&self) {
        let Some(machine) = &self.machine else { return; };
        let (resolved, poisoned) = machine.progress();
        let _ = state::save_checkpoint(&self.config.state_dir, &Checkpoint { session: hex(machine.session_id()), resolved, poisoned,
            max_open_exchanges: self.config.max_open_exchanges, max_exchange_bytes: self.config.max_exchange_bytes });
    }

    /// Send the request the machine chose and hand it the reply.
    async fn perform(&mut self, request: Request) {
        let path = match request.path { ShipPath::Bootstrap => BOOTSTRAP_PATH, ShipPath::Refresh => REFRESH_PATH, ShipPath::Ingest => INGEST_PATH };
        let bearer = request.bearer.as_deref().and_then(|b| std::str::from_utf8(b).ok());
        let mut headers: Vec<(&str, String)> = Vec::new();
        match request.path {
            ShipPath::Bootstrap => headers.push(("content-type", "application/json".to_owned())),
            ShipPath::Ingest => {
                headers.push(("content-type", "application/x-ndjson".to_owned()));
                headers.push(("x-hyp-batch-id", hex(request.batch_id.as_deref().unwrap_or(&[]))));
            }
            ShipPath::Refresh => {}
        }
        let Some(client) = self.client.as_ref() else { return; };
        let result = client.request("POST", path, bearer, &headers, request.body).await;
        let (reply, issued) = match result {
            Ok(reply) => {
                let revocation = is_revocation(&reply);
                let issued = if request.path != ShipPath::Ingest && reply.status == 200 { parse_credential(&reply.body) } else { None };
                (MachineReply { status: reply.status, retry_after: reply.retry_after, revocation,
                    credential: issued.as_ref().map(|i| Credential { jwt: i.credential.jwt.clone(), expires_at: i.credential.expires_at }) }, issued)
            }
            Err(_) => (MachineReply { status: 0, retry_after: None, revocation: false, credential: None }, None),
        };
        let now = now_seconds();
        let Some(machine) = self.machine.as_mut() else { return; };
        let outcome = machine.reply(now, reply);
        // Lag and enrollment first, so a reader who sees the acknowledgment count sees them too.
        self.metrics.lag.store(machine.queue_len() as u64, Ordering::Relaxed);
        self.metrics.enrolled.store(machine.is_enrolled(now), Ordering::Relaxed);
        match outcome {
            Outcome::Acknowledged(_) => {
                self.metrics.batches_acknowledged.fetch_add(1, Ordering::Relaxed);
                self.metrics.last_acknowledged_ms.store(now_ms(), Ordering::Relaxed);
                self.save_checkpoint();
            }
            Outcome::Poisoned => { self.metrics.poisoned_batches.fetch_add(1, Ordering::Relaxed); self.save_checkpoint(); }
            Outcome::Enrolled => {
                if let Some(issued) = issued {
                    let jwt = String::from_utf8(issued.credential.jwt).unwrap_or_default();
                    let _ = state::save_identity(&self.config.state_dir, &Identity { jwt, expires_at: issued.expires_at, gateway_id: issued.gateway_id,
                        server: self.config.server.to_string(), token_fingerprint: state::fingerprint(self.config.token()) });
                }
            }
            Outcome::Revoked => self.metrics.stopped.store(true, Ordering::Relaxed),
            Outcome::Unenrolled | Outcome::Isolating | Outcome::Deferred(_) | Outcome::Nothing => {}
        }
    }
}

fn is_revocation(reply: &Reply) -> bool {
    matches!(reply.error_code().as_deref(), Some("service_token_revoked" | "service_account_disabled"))
}

#[cfg(test)]
pub(crate) mod tests;
