//! Cloud shipping: one dedicated thread tails the audit log read-only and
//! drives the verified shipper machine, which groups records into exchanges,
//! batches their projections, and decides every request, retry, and
//! checkpoint. This module performs those actions against the one configured
//! server and reports replies back. It shares no executor, pool, or handle with
//! request workers; its only inputs are the log path, the server, the token,
//! and a state directory, and its only outputs are metrics. Failure here never
//! touches admission or readiness.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unreachable, clippy::todo, clippy::unimplemented,
    clippy::indexing_slicing, clippy::arithmetic_side_effects)]
use gateway_core::exchange_assembler::Exchange;
use gateway_core::framing::Header;
use gateway_core::shipper::{Credential, Machine, Outcome, Path as ShipPath, Reply as MachineReply, Request};
use gateway_core::shipping_driver::{drive, Effects, Event, Halt, Mode, Projected, Read};
use std::{fs::File, io::{self, Seek, SeekFrom}, path::PathBuf, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}, mpsc}, time::{Duration, SystemTime}};
use tokio_rustls::rustls::RootCertStore;
use crate::disk_log::{LogReader, ScanError};
use crate::thread_runtime::EnteredRuntime;
use gateway_core::thread_context::ThreadContext;

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

#[derive(Default)]
pub struct Metrics {
    enrolled: AtomicBool, stopped: AtomicBool, read_failed: AtomicBool, panicked: AtomicBool,
    records_read: AtomicU64, exchanges_emitted: AtomicU64, lag: AtomicU64,
    batches_acknowledged: AtomicU64, last_acknowledged_ms: AtomicU64, poisoned_batches: AtomicU64,
}
impl Metrics {
    pub fn stopped(&self) -> bool { self.stopped.load(Ordering::Relaxed) }
    /// The thread body panicked; the panic was contained and the shipper is stopped.
    pub fn panicked(&self) -> bool { self.panicked.load(Ordering::Relaxed) }
    pub fn enrolled(&self) -> bool { self.enrolled.load(Ordering::Relaxed) }
    pub fn batches_acknowledged(&self) -> u64 { self.batches_acknowledged.load(Ordering::Relaxed) }
    pub fn poisoned_batches(&self) -> u64 { self.poisoned_batches.load(Ordering::Relaxed) }
    pub fn lag(&self) -> u64 { self.lag.load(Ordering::Relaxed) }
    pub fn records_read(&self) -> u64 { self.records_read.load(Ordering::Relaxed) }
    /// Prometheus text lines; `enabled` is 1 whenever a shipper exists.
    pub fn render(&self, out: &mut String) {
        use std::fmt::Write as _;
        let _ = write!(out, "loggate_shipping_enabled 1\nloggate_shipping_enrolled {}\nloggate_shipping_stopped {}\nloggate_shipping_log_read_failed {}\n\
            loggate_shipping_records_read_total {}\nloggate_shipping_exchanges_emitted_total {}\nloggate_shipping_lag_exchanges {}\n\
            loggate_shipping_batches_acknowledged_total {}\nloggate_shipping_last_acknowledged_unix_ms {}\nloggate_shipping_poisoned_batches_total {}\n",
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
        Self::spawn_thread(move |stop, metrics, context| {
            let runtime = match EnteredRuntime::current_thread(context) {
                Ok(runtime) => runtime, Err(_) => { metrics.stopped.store(true, Ordering::Relaxed); return; }
            };
            let result = Engine::new(config, log_path, roots, stop, metrics.clone(), runtime).run(Mode::Follow);
            if result.is_err() { metrics.stopped.store(true, Ordering::Relaxed); }
        })
    }
    /// The thread body runs under `catch_unwind`: a panic marks the shipper
    /// stopped and panicked and ends the thread. Nothing else in the process
    /// observes it; the gateway holds only this metrics view.
    fn spawn_thread(body: impl FnOnce(Arc<AtomicBool>, Arc<Metrics>, ThreadContext) + Send + 'static) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Metrics::default());
        let (done, finished) = mpsc::channel();
        let (flag, shared) = (stop.clone(), metrics.clone());
        let thread = crate::thread_runtime::spawn_fresh(std::thread::Builder::new().name("loggate-shipping".into()).stack_size(STACK_BYTES), move |context| {
            let _done = done; // dropped when the thread ends, however it ends
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| body(flag, shared.clone(), context)));
            if outcome.is_err() {
                shared.panicked.store(true, Ordering::Relaxed);
                shared.stopped.store(true, Ordering::Relaxed);
            }
        })?;
        Ok(Self { stop, finished, thread: Some(thread), metrics })
    }
    #[cfg(test)]
    pub(crate) fn spawn_for_test(body: impl FnOnce() + Send + 'static) -> io::Result<Self> { Self::spawn_thread(move |_, _, _| body()) }
    pub fn metrics(&self) -> Arc<Metrics> { self.metrics.clone() }
    /// Ask the thread to stop after its current step and join it within the
    /// deadline. A thread still inside a request is left to finish on its own;
    /// nothing replaces it.
    pub fn shutdown(mut self, deadline: Duration) -> io::Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        match self.finished.recv_timeout(deadline) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.thread.take().map(|t| t.join()).transpose().map(|_| ()).map_err(|_| io::Error::other("shipper panicked"))?;
                if self.metrics.panicked() { return Err(io::Error::other("shipper panicked")); }
                Ok(())
            }
            Err(mpsc::RecvTimeoutError::Timeout) => { self.thread.take(); Err(io::ErrorKind::TimedOut.into()) }
        }
    }
}
impl Drop for Shipper { fn drop(&mut self) { self.stop.store(true, Ordering::Relaxed); } }

/// Ship a finished log on the current thread until every exchange is resolved
/// or the enrollment is stopped for good. Used by `loggate ship`. The caller's
/// thread context is spent on the runtime the loop blocks on.
pub fn ship_to_end(config: ShippingConfig, log_path: PathBuf, context: ThreadContext) -> Result<Metrics, &'static str> { ship_to_end_with_roots(config, log_path, None, context) }
pub fn ship_to_end_with_roots(config: ShippingConfig, log_path: PathBuf, roots: Option<RootCertStore>, context: ThreadContext) -> Result<Metrics, &'static str> {
    let runtime = EnteredRuntime::current_thread(context).map_err(|_| "cannot start shipping runtime")?;
    let metrics = Arc::new(Metrics::default());
    let stop = Arc::new(AtomicBool::new(false));
    let result = Engine::new(config, log_path, roots, stop, metrics.clone(), runtime).run(Mode::Drain);
    result.map(|_| Arc::try_unwrap(metrics).unwrap_or_default())
}

/// The runtime half of the shipper: the effects the verified driver asks
/// for. It performs each action against the one configured server and the
/// operator's log and state files, and makes no decision of its own about
/// what to send, where progress stands, or when to retry.
struct Engine {
    config: ShippingConfig,
    log_path: PathBuf,
    roots: Option<RootCertStore>,
    stop: Arc<AtomicBool>,
    metrics: Arc<Metrics>,
    runtime: EnteredRuntime,
    client: Option<Client>,
    session: Option<[u8; 16]>,
    reader: Option<LogReader<File>>,
    valid_end: u64,
    /// The credential parsed from the last enrollment reply, kept for the identity file.
    issued: Option<Issued>,
}

fn now_seconds() -> u64 { SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }
fn now_ms() -> u64 { SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_millis().min(u64::MAX as u128) as u64).unwrap_or(0) }

/// A credential parsed from an enrollment reply, with the gateway id for the identity file.
struct Issued { jwt: String, gateway_id: String, expires_at: u64 }

fn parse_credential(body: &[u8]) -> Option<Issued> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let jwt = value.get("jwt")?.as_str()?;
    let expires_at = value.get("expires_at")?.as_u64()?;
    if jwt.len() > 16 * 1024 { return None; }
    let (gateway_id, exp) = state::jwt_claims(jwt)?;
    Some(Issued { jwt: jwt.to_owned(), gateway_id, expires_at: expires_at.min(exp) })
}

impl Engine {
    fn new(config: ShippingConfig, log_path: PathBuf, roots: Option<RootCertStore>, stop: Arc<AtomicBool>, metrics: Arc<Metrics>,
        runtime: EnteredRuntime) -> Self {
        Engine { config, log_path, roots, stop, metrics, runtime, client: None, session: None, reader: None, valid_end: 56, issued: None }
    }

    /// Sleep in short slices so a stop request is honored promptly. False when stopping.
    fn wait(&self, duration: Duration) -> bool {
        let mut remaining = duration;
        while !remaining.is_zero() {
            if self.stop.load(Ordering::Relaxed) { return false; }
            let slice = remaining.min(Duration::from_millis(100));
            std::thread::sleep(slice);
            remaining = remaining.saturating_sub(slice);
        }
        !self.stop.load(Ordering::Relaxed)
    }

    fn run(mut self, mode: Mode) -> Result<(), &'static str> {
        let client = match self.roots.take() {
            Some(roots) => Client::with_roots(roots, &self.config.server, REQUEST_DEADLINE),
            None => Client::new(&self.config.server, REQUEST_DEADLINE),
        }.map_err(|_| "cannot initialize shipping client")?;
        self.client = Some(client);
        loop {
            if self.stop_requested() { return Ok(()); }
            match self.open_session() {
                Some(mut machine) => {
                    return match drive(&mut machine, &mut self, mode) {
                        Halt::Revoked => Err("shipping stopped: token revoked or account disabled"),
                        Halt::StopRequested | Halt::Drained => Ok(()),
                    };
                }
                None => { if !self.idle() { return Ok(()); } }
            }
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
        self.session = Some(session);
        self.valid_end = 56;
        let checkpoint = state::load_checkpoint(&self.config.state_dir).filter(|c| c.session == hex(&session)
            && c.max_open_exchanges == self.config.max_open_exchanges && c.max_exchange_bytes == self.config.max_exchange_bytes);
        let (resolved, poisoned) = checkpoint.map(|c| (c.resolved, c.poisoned)).unwrap_or((0, 0));
        let mut machine = Machine::new(self.config.token().to_vec(), session, self.config.max_open_exchanges,
            self.config.max_exchange_bytes, resolved, poisoned);
        if let Some(identity) = state::load_identity(&self.config.state_dir) {
            let same = identity.server == self.config.server.uri().to_string()
                && identity.token_fingerprint == state::fingerprint(self.config.token());
            if same && machine.adopt_identity(identity.jwt.into_bytes(), identity.expires_at, now_seconds()) {
                self.metrics.enrolled.store(true, Ordering::Relaxed);
            }
        }
        Some(machine)
    }

    fn save_identity(&self, issued: &Issued) {
        let _ = state::save_identity(&self.config.state_dir, &Identity { jwt: issued.jwt.clone(), expires_at: issued.expires_at,
            gateway_id: issued.gateway_id.clone(), server: self.config.server.uri().to_string(),
            token_fingerprint: state::fingerprint(self.config.token()) });
    }
}

impl Effects for Engine {
    fn stop_requested(&mut self) -> bool { self.stop.load(Ordering::Relaxed) }
    fn now(&mut self) -> u64 { now_seconds() }

    /// The next record after the last valid end. The reader is kept across
    /// calls while records keep coming and reopened at the same offset after
    /// the end of the file, so the file is read exactly once in order
    /// (`recovery::emission_step` and `lemma_records_resume`).
    fn read(&mut self) -> Read {
        let Some(session) = self.session else { return Read::Failed; };
        if self.reader.is_none() {
            let Ok(mut file) = File::open(&self.log_path) else { return Read::End; };
            if file.seek(SeekFrom::Start(self.valid_end)).is_err() { return Read::End; }
            match LogReader::resume(file, session, self.valid_end) {
                Ok(reader) => self.reader = Some(reader),
                Err(_) => { self.metrics.read_failed.store(true, Ordering::Relaxed); return Read::Failed; }
            }
        }
        let Some(reader) = self.reader.as_mut() else { return Read::End; };
        let next = reader.next_record();
        self.valid_end = reader.valid_end();
        match next {
            Ok(Some(record)) => Read::Record(Header { payload: record.bytes.len() as u32, tenant: record.tenant, request: record.request,
                chunk: record.chunk, kind: record.kind.id() }, record.bytes),
            Ok(None) | Err(ScanError::Incomplete) => { self.reader = None; Read::End }
            Err(_) => { self.reader = None; self.metrics.read_failed.store(true, Ordering::Relaxed); Read::Failed }
        }
    }

    fn project(&mut self, exchange: &Exchange) -> Projected {
        let session = self.session.unwrap_or([0; 16]);
        let rows = projection::rows(&session, exchange, self.config.max_exchange_bytes);
        let mut body = Vec::new();
        for row in &rows { body.extend_from_slice(&serde_json::to_vec(row).unwrap_or_default()); body.push(b'\n'); }
        Projected { body, rows: rows.len() }
    }

    /// Send the request the machine chose to the configured server.
    fn send(&mut self, request: Request) -> MachineReply {
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
        let failed = MachineReply { status: 0, retry_after: None, revocation: false, credential: None };
        let Some(client) = self.client.as_ref() else { return failed; };
        let Ok(reply) = self.runtime.block_on(client.request("POST", path, bearer, &headers, request.body)) else { return failed; };
        let revocation = is_revocation(&reply);
        self.issued = if request.path != ShipPath::Ingest && reply.status == 200 { parse_credential(&reply.body) } else { None };
        let credential = self.issued.as_ref().map(|i| Credential { jwt: i.jwt.as_bytes().to_vec(), expires_at: i.expires_at });
        MachineReply { status: reply.status, retry_after: reply.retry_after, revocation, credential }
    }

    fn sleep(&mut self, seconds: u64) -> bool { self.wait(Duration::from_secs(seconds)) }
    fn idle(&mut self) -> bool { self.wait(Duration::from_millis(self.config.poll_ms)) }

    fn checkpoint(&mut self, _machine: &Machine, resolved: u64, poisoned: u64) {
        let Some(session) = self.session else { return; };
        let _ = state::save_checkpoint(&self.config.state_dir, &Checkpoint { session: hex(&session), resolved, poisoned,
            max_open_exchanges: self.config.max_open_exchanges, max_exchange_bytes: self.config.max_exchange_bytes });
    }

    fn observe(&mut self, event: Event, machine: &Machine) {
        match event {
            Event::RecordRead => { self.metrics.records_read.fetch_add(1, Ordering::Relaxed); }
            Event::ExchangeEmitted => { self.metrics.exchanges_emitted.fetch_add(1, Ordering::Relaxed); }
            Event::Replied(outcome) => {
                // Lag and enrollment first, so a reader who sees the acknowledgment count sees them too.
                self.metrics.lag.store(machine.queue_len() as u64, Ordering::Relaxed);
                self.metrics.enrolled.store(machine.is_enrolled(now_seconds()), Ordering::Relaxed);
                match outcome {
                    Outcome::Acknowledged(_) => {
                        self.metrics.batches_acknowledged.fetch_add(1, Ordering::Relaxed);
                        self.metrics.last_acknowledged_ms.store(now_ms(), Ordering::Relaxed);
                    }
                    Outcome::Poisoned => { self.metrics.poisoned_batches.fetch_add(1, Ordering::Relaxed); }
                    Outcome::Enrolled => { if let Some(issued) = self.issued.take() { self.save_identity(&issued); } }
                    Outcome::Revoked => self.metrics.stopped.store(true, Ordering::Relaxed),
                    Outcome::Unenrolled | Outcome::Isolating | Outcome::Deferred(_) | Outcome::Nothing => {}
                }
            }
            Event::PoisonedUnsent => {
                self.metrics.poisoned_batches.fetch_add(1, Ordering::Relaxed);
                self.metrics.lag.store(machine.queue_len() as u64, Ordering::Relaxed);
            }
            Event::Stopped => self.metrics.stopped.store(true, Ordering::Relaxed),
            Event::Waiting => self.metrics.lag.store(machine.queue_len() as u64, Ordering::Relaxed),
        }
    }
}

fn is_revocation(reply: &Reply) -> bool {
    matches!(reply.error_code().as_deref(), Some("service_token_revoked" | "service_account_disabled"))
}

#[cfg(test)]
pub(crate) mod tests;
