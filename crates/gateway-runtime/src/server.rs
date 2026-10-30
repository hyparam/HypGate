//! Inbound HTTP/1 server. Deploy behind a trusted TLS terminator; the
//! executable binds loopback only. One thread accepts; each accepted
//! connection gets its own thread, which hands the connection to the verified
//! exchange driver (`gateway_core::exchange_driver`) and performs the effects
//! it asks for: read the head, move bytes, admit, open the provider session,
//! run the body copies, append records. Nothing here decides the order of
//! those effects or what is written; the driver does, and the connection and
//! chunk-stream machines produce every byte. Blocking sockets throughout;
//! deadlines are socket timeouts (`net::Timed`), and a client that leaves is
//! noticed by a small watcher thread that cancels the exchange.
use gateway_core::framed_copy::{Framed, Downloaded};
use crate::{config::GatewayConfig, disk_log::DiskLog, http1, http_body, http_boundary, net::{Cancel, Deadline, Timed},
    transport::{HttpsTransport, Session}, transfer::{AuditLog, LogRecord, TransferError}};
use gateway_core::request_context::TransferKey;
use gateway_core::exchange_driver::{self, Admit, Body, ConnectFailure, Effects, Event, Failure, FixedResponse, HeadRead, WriteScope};
use gateway_core::http1_exchange::{Refusal, refusal_status};
use gateway_core::http1_framing::Framing;
use gateway_core::http1_head::{RequestHead, StatusHead};
use gateway_core::health::{GapObserver, Readiness};
use gateway_core::serve_driver::{self, Accepted, Window};
use std::{collections::HashMap, io::{self, Write}, net::{Shutdown as SocketShutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, AtomicU64, Ordering}}, time::{Duration, Instant}};

mod workers;
mod leased;
use workers::{WorkerLease, WorkerSlots};
mod connections;
use connections::{ConnectionLease, ConnectionSlots};

/// How long a connection may take to send its complete request head.
pub(crate) const HEAD_DEADLINE: Duration = Duration::from_secs(10);
/// Stack reserved for each connection thread and for its client watcher.
pub const CONNECTION_STACK_BYTES: usize = 512 * 1024;
pub const WATCHER_STACK_BYTES: usize = 64 * 1024;
/// How long shutdown waits for connections and workers before cancelling them.
const DRAIN_WINDOW: Duration = Duration::from_secs(10);

pub struct Gateway {
    config: Arc<GatewayConfig>,
    transport: HttpsTransport,
    log: DiskLog,
    worker_slots: Arc<WorkerSlots>,
    connection_slots: OnceLock<Arc<ConnectionSlots>>,
    // Exchanges in flight, so shutdown can cancel them after the drain window.
    live: Mutex<HashMap<u64, Cancel>>,
    next_live: AtomicU64,
    audit_gaps: AtomicU64,
    failed_exchanges: AtomicU64,
    // Read-only view of the shipper thread's counters for `/metrics`. The
    // gateway never calls into the shipper and readiness never reads this.
    shipping: Option<Arc<crate::shipping::Metrics>>,
}
impl Gateway {
    pub fn new(config: GatewayConfig, transport: HttpsTransport, log: DiskLog) -> Arc<Self> {
        Self::with_shipping_metrics(config, transport, log, None)
    }
    pub fn with_shipping_metrics(config: GatewayConfig, transport: HttpsTransport, log: DiskLog,
        shipping: Option<Arc<crate::shipping::Metrics>>) -> Arc<Self> {
        Arc::new(Self { worker_slots: WorkerSlots::new(config.request_limit()), config: Arc::new(config), transport, log,
            connection_slots: OnceLock::new(), live: Mutex::new(HashMap::new()), next_live: AtomicU64::new(1),
            audit_gaps: AtomicU64::new(0), failed_exchanges: AtomicU64::new(0), shipping })
    }
    pub fn audit_gaps(&self) -> u64 { self.audit_gaps.load(Ordering::Relaxed) }
    pub fn failed_exchanges(&self) -> u64 { self.failed_exchanges.load(Ordering::Relaxed) }

    fn track(&self, cancel: &Cancel) -> u64 {
        let id = self.next_live.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut live) = self.live.lock() { live.insert(id, cancel.clone()); }
        id
    }
    fn untrack(&self, id: u64) { if let Ok(mut live) = self.live.lock() { live.remove(&id); } }
    fn cancel_live(&self) {
        let cancels: Vec<Cancel> = match self.live.lock() { Ok(live) => live.values().cloned().collect(), Err(_) => return };
        for cancel in cancels { cancel.shutdown(); }
    }

    /// The operator endpoints, answered without a worker.
    fn endpoint(&self, target: &[u8]) -> Option<FixedResponse> {
        match target {
            b"/metrics" => {
                use std::fmt::Write as _;
                let mut text = format!("hypgate_audit_gap_requests_total {}\nhypgate_failed_exchanges_total {}\nhypgate_audit_healthy {}\nhypgate_worker_admission_healthy {}\n",
                    self.audit_gaps(), self.failed_exchanges(), u8::from(self.log.healthy()), u8::from(self.worker_slots.healthy()));
                match self.config.usage() {
                    Some((active, limit)) => { let _ = write!(text, "hypgate_admission_healthy 1\nhypgate_requests_active {active}\nhypgate_requests_limit {limit}\n"); }
                    None => text.push_str("hypgate_admission_healthy 0\n"),
                }
                match &self.shipping { Some(metrics) => metrics.render(&mut text), None => text.push_str("hypgate_shipping_enabled 0\n") }
                Some(FixedResponse { status: 200, fields: vec![http1::field(b"content-type", b"text/plain; version=0.0.4".to_vec())], body: text.into_bytes() })
            }
            b"/healthz" => Some(fixed(200, b"ok\n".to_vec())),
            b"/readyz" => {
                // The rule is the verified `health::readiness`; this only samples its inputs.
                Some(match gateway_core::health::readiness(self.config.admission_healthy(), self.worker_slots.healthy(),
                    self.config.requires_audit(), self.log.healthy()) {
                    Readiness::Ready => fixed(200, b"ready\n".to_vec()),
                    Readiness::AdmissionUnavailable => fixed(refusal_status(Refusal::Unavailable), b"admission unavailable\n".to_vec()),
                    Readiness::AuditUnavailable => fixed(refusal_status(Refusal::Unavailable), b"audit unavailable\n".to_vec()),
                })
            }
            _ => None,
        }
    }
}
fn fixed(status: u16, text: Vec<u8>) -> FixedResponse { FixedResponse { status, fields: Vec::new(), body: text } }

// Report potential audit loss at the first failed append, not only after a
// successful response: cancellation and provider failures must not hide it.
// The verified observer decides when an append counts; this only adds one.
struct ObservedLog<'a> { deadline: Option<Deadline>, log: DiskLog, gaps: &'a AtomicU64, observer: GapObserver }
impl AuditLog for ObservedLog<'_> {
    fn session_id(&self) -> u128 { self.log.session_id() }
    fn append(&mut self, record: LogRecord<'_>) -> io::Result<crate::transfer::AuditReceipt> {
        let result = match self.deadline {
            Some(deadline) => deadline.remaining().and_then(|_| deadline.end()).and_then(|end| self.log.append_until(record, Some(end))),
            None => self.log.append(record),
        };
        if self.observer.observe(result.is_err()) { self.gaps.fetch_add(1, Ordering::Relaxed); }
        result
    }
}

/// A sink for a body that must be empty: the fixed head said so.
struct NoBody;
impl Write for NoBody {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::ErrorKind::InvalidData.into()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

/// The runtime's side of one connection: the effects the verified driver
/// asks for, performed against this connection's sockets, the worker it
/// holds, its admitted request, and the audit log. No decisions live here.
struct ConnectionEffects<'a> {
    app: &'a Gateway,
    deadline: Deadline,
    exchange_deadline: Option<Deadline>,
    reader: Option<Timed<TcpStream>>,
    writer: Timed<TcpStream>,
    leftover: Vec<u8>,
    lease: Option<leased::Started<WorkerLease>>,
    http: Option<http_body::WorkerHttp>,
    prepared: Option<http_boundary::PreparedRequest<'a>>,
    input: Option<http_body::Reader<http1::BodyReader<Timed<TcpStream>>>>,
    session: Option<Session>,
    log: ObservedLog<'a>,
    cancel: Cancel,
    // The client watcher starts with the worker: only an exchange in flight
    // has anything to cancel, and a refused connection returns its credit at once.
    probe: Option<TcpStream>,
    watcher: Option<ClientWatch>,
}
impl<'a> ConnectionEffects<'a> {
    fn new(app: &'a Gateway, socket: TcpStream, deadline: Deadline, cancel: Cancel) -> io::Result<Self> {
        let write_half = socket.try_clone()?;
        let probe = socket.try_clone()?;
        Ok(Self {
            app, deadline, exchange_deadline: None, reader: Some(Timed::new(socket, deadline.cap(HEAD_DEADLINE))), writer: Timed::new(write_half, deadline),
            leftover: Vec::new(), lease: None, http: None, prepared: None, input: None, session: None,
            log: ObservedLog { deadline: None, log: app.log.clone(), gaps: &app.audit_gaps, observer: GapObserver::new(!app.config.requires_audit()) }, cancel,
            probe: Some(probe), watcher: None,
        })
    }
}
impl Effects for ConnectionEffects<'_> {
    fn read_head(&mut self) -> HeadRead {
        let Some(mut reader) = self.reader.take() else { return HeadRead::Closed; };
        let outcome = http1::read_request_head(&mut reader, Vec::new());
        // The head's own deadline is spent; the rest of the connection runs under the connection deadline.
        self.reader = Some(Timed::new(reader.into_inner(), self.deadline));
        match outcome {
            Ok((head, leftover)) => { self.leftover = leftover; HeadRead::Head(head) }
            Err(http1::HeadError::TooLarge) => HeadRead::TooLarge,
            Err(http1::HeadError::Malformed) => HeadRead::Malformed,
            Err(_) => HeadRead::Closed, // closed or silent before a complete head
        }
    }
    fn write_client(&mut self, bytes: &Vec<u8>, scope: WriteScope) -> bool {
        let deadline = match scope {
            WriteScope::Control => self.deadline,
            WriteScope::Exchange => match self.exchange_deadline { Some(deadline) => deadline, None => return false },
        };
        let mut writer = Timed::new(self.writer.inner(), deadline);
        http1::write_fully(&mut writer, bytes).and_then(|()| writer.flush()).is_ok()
    }
    fn close_client(&mut self) { let _ = self.writer.inner().shutdown(SocketShutdown::Write); }
    fn endpoint(&mut self, target: &Vec<u8>) -> Option<FixedResponse> { self.app.endpoint(target) }
    fn acquire_worker(&mut self) -> bool {
        let Some(lease) = self.app.worker_slots.acquire() else { return false; };
        match self.probe.take().and_then(|probe| ClientWatch::start(probe, self.cancel.clone()).ok()) {
            Some(watcher) => self.watcher = Some(watcher),
            None => return false, // no watcher, no exchange: the lease returns unstarted
        }
        self.http = Some(lease.http());
        self.lease = Some(leased::start(lease));
        true
    }
    fn admit(&mut self, head: &RequestHead) -> Admit {
        match http_boundary::prepare(&self.app.config, head) {
            Ok(prepared) => {
                // One descendant budget is created at dispatch, before audit or DNS.
                // The same value reaches both client directions, audit waits, and TLS.
                let deadline = self.app.transport.deadline(self.deadline);
                self.exchange_deadline = Some(deadline);
                self.log.deadline = Some(deadline);
                self.prepared = Some(prepared);
                Admit::Admitted
            }
            Err(error) => Admit::Refused(error.refusal()),
        }
    }
    fn strict(&mut self) -> bool { self.app.config.requires_audit() }
    fn log_healthy(&mut self) -> bool { self.app.log.healthy() }
    fn now_ms(&mut self) -> u64 { http_boundary::unix_ms() }
    fn audit_request_start(&mut self) -> bool {
        let Some(prepared) = self.prepared.as_mut() else { return false; };
        prepared.audit_request_start(&mut self.log).is_ok()
    }
    fn bind_input(&mut self, framing: Framing) -> bool {
        let (Some(reader), Some(http)) = (self.reader.take(), self.http.as_ref()) else { return false; };
        let Some(deadline) = self.exchange_deadline else { return false; };
        let reader = Timed::new(reader.into_inner(), deadline);
        let body = http1::BodyReader::new(reader, std::mem::take(&mut self.leftover), framing);
        match http.input(body) { Some(input) => { self.input = Some(input); true } None => false }
    }
    fn upstream_head(&mut self, input: &RequestHead) -> Option<gateway_core::request_context::ProviderHead> {
        self.prepared.as_mut()?.take_upstream_for(input).ok()
    }
    fn connect(&mut self) -> Result<(), ConnectFailure> {
        let Some(prepared) = self.prepared.as_mut() else { return Err(ConnectFailure::Resolve); };
        self.session = Some(self.app.transport.connect(prepared, &self.cancel, self.exchange_deadline.ok_or(ConnectFailure::Timeout)?)?);
        Ok(())
    }
    fn write_upstream(&mut self, bytes: &Vec<u8>) -> bool {
        self.session.as_mut().is_some_and(|session| session.write(bytes))
    }
    fn upload(&mut self, key: &TransferKey, stream: gateway_core::http1_exchange::ChunkStream) -> Framed {
        let Self { session, prepared, input, log, http, .. } = self;
        let (Some(session), Some(prepared), Some(input), Some(http)) = (session.as_mut(), prepared.as_mut(), input.as_mut(), http.as_ref()) else {
            return Framed::failed(stream, Failure::Io);
        };
        session.upload(prepared, key, input, log, http, stream)
    }
    fn read_status_head(&mut self) -> Result<StatusHead, Failure> {
        match self.session.as_mut() { Some(session) => session.read_status_head(), None => Err(Failure::Io) }
    }
    fn audit_response_head(&mut self, status: u16) -> bool {
        let Some(prepared) = self.prepared.as_mut() else { return false; };
        match prepared.audit_response_head(&mut self.log, status) {
            Ok(()) => true,
            Err(TransferError::Log) => false,
            Err(_) => false,
        }
    }
    fn download(&mut self, key: &TransferKey, framing: Framing, body: Body) -> Downloaded {
        let Self { session, prepared, log, http, writer, exchange_deadline, .. } = self;
        let (Some(session), Some(prepared), Some(http)) = (session.as_mut(), prepared.as_mut(), http.as_ref()) else {
            return match body { Body::Fixed => Downloaded::Fixed(Err(Failure::Io)), Body::Stream(s) => Downloaded::Stream(Framed::failed(s, Failure::Io)) };
        };
        match body {
            Body::Fixed => Downloaded::Fixed(session.download(prepared, key, log, http, framing, &mut NoBody)),
            Body::Stream(stream) => {
                // The chunks go to the client through the worker's response role.
                let Some(deadline) = *exchange_deadline else { return Downloaded::Stream(Framed::failed(stream, Failure::Io)); };
                let mut timed = Timed::new(writer.inner(), deadline);
                let mut sink = match http.response_writer(&mut timed) {
                    Ok(sink) => sink,
                    Err(_) => return Downloaded::Stream(Framed::failed(stream, Failure::Io)),
                };
                Downloaded::Stream(session.download_framed(prepared, key, log, http, framing, &mut sink, stream))
            }
        }
    }
    fn audit_completion(&mut self, payload: &Vec<u8>) -> bool {
        // Teardown records must remain possible after exchange expiry; the
        // logger's own acknowledgment deadline bounds this separate phase.
        self.log.deadline = None;
        let Some(prepared) = self.prepared.as_mut() else { return false; };
        prepared.audit_completion(&mut self.log, payload).is_ok()
    }
    fn observe(&mut self, event: Event) {
        match event { Event::Failed(_) => { self.app.failed_exchanges.fetch_add(1, Ordering::Relaxed); } }
    }
}

/// Watches for a reset while the exchange runs. EOF only means the client
/// finished sending: the verified cancellation rule retires the watcher and
/// preserves the response. A clean disconnect is indistinguishable from a
/// half-close until a response write fails or the exchange deadline expires.
struct ClientWatch { thread: Option<std::thread::JoinHandle<()>>, finished: Arc<AtomicBool>, socket: TcpStream }
impl ClientWatch {
    fn start(socket: TcpStream, cancel: Cancel) -> io::Result<Self> {
        let finished = Arc::new(AtomicBool::new(false));
        let probe = socket.try_clone()?;
        let flag = finished.clone();
        let thread = std::thread::Builder::new().name("hypgate-watch".into()).stack_size(WATCHER_STACK_BYTES).spawn(move || {
            let mut byte = [0u8; 1];
            loop {
                if flag.load(Ordering::Acquire) { return; }
                let result = probe.peek(&mut byte);
                if flag.load(Ordering::Acquire) { return; }
                if !cancel.observe_read(&result) { return; }
                std::thread::sleep(Duration::from_millis(if result.is_ok() { 20 } else { 5 }));
            }
        })?;
        Ok(Self { thread: Some(thread), finished, socket })
    }
    /// The exchange is over: stop watching and join.
    fn finish(self) { drop(self); }
}
impl Drop for ClientWatch {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Release);
        let _ = self.socket.shutdown(SocketShutdown::Both);
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

/// Serve one connection: hand it to the verified driver and perform what it
/// asks. The worker lease, if one was taken, returns its credit only after
/// every stream the worker issued is gone.
struct ConnectionScope {
    app: Arc<Gateway>, cancel: Cancel, id: Option<u64>,
    socket: Option<TcpStream>, deadline: Deadline,
}
impl ConnectionScope {
    fn cleanup(&mut self) {
        if let Some(id) = self.id.take() {
            self.app.untrack(id);
            self.cancel.release_sockets();
        }
    }
}
// Rust unwinding is outside the core model; the same cleanup runs on unwind.
impl Drop for ConnectionScope { fn drop(&mut self) { self.cleanup(); } }
impl gateway_core::scope::Effects for ConnectionScope {
    type Output = io::Result<()>;
    fn body(&mut self) -> Self::Output {
        let socket = self.socket.take().ok_or(io::ErrorKind::InvalidInput)?;
        let mut effects = ConnectionEffects::new(&self.app, socket, self.deadline, self.cancel.clone())?;
        let driven = exchange_driver::drive(&mut effects);
        let lease = effects.lease.take();
        let watcher = effects.watcher.take();
        drop(effects); // all issued HTTP streams are gone before returning worker credit
        if let Some(lease) = lease { lease.finish(); }
        let _closed = driven.closed;
        if let Some(watcher) = watcher { watcher.finish(); }
        Ok(())
    }
    fn cleanup(&mut self) { self.cleanup(); }
}
fn serve_connection(socket: TcpStream, app: Arc<Gateway>, connection_deadline: Duration) -> io::Result<()> {
    let deadline = Deadline::start(connection_deadline)?;
    let cancel = Cancel::new();
    cancel.watch_socket(&socket)?;
    let id = app.track(&cancel);
    let mut scope = ConnectionScope { app, cancel, id: Some(id), socket: Some(socket), deadline };
    gateway_core::scope::run(&mut scope)
}

/// Asks a running `serve` to stop accepting and drain. Triggering before
/// `serve` starts makes it return at once.
#[derive(Clone, Default)]
pub struct Shutdown { triggered: Arc<AtomicBool>, address: Arc<Mutex<Option<SocketAddr>>> }
impl Shutdown {
    pub fn new() -> Self { Self::default() }
    pub fn is_triggered(&self) -> bool { self.triggered.load(Ordering::Acquire) }
    pub fn trigger(&self) {
        self.triggered.store(true, Ordering::Release);
        let address = self.address.lock().ok().and_then(|address| *address);
        if let Some(address) = address { wake_accept(address); }
    }
    fn attach(&self, address: SocketAddr) { if let Ok(mut slot) = self.address.lock() { *slot = Some(address); } }
}
// Effect site: a loopback connection to the gateway's own listener, which
// returns the accept loop from its blocking accept so it can see the flag.
#[allow(clippy::disallowed_methods)]
fn wake_accept(address: SocketAddr) { let _ = TcpStream::connect_timeout(&address, Duration::from_secs(1)); }

/// The accept loop and the drain, as the verified `serve_driver` asks for
/// them: each method performs one effect and reports what happened.
struct ServeEffects {
    listener: Option<TcpListener>, app: Arc<Gateway>, slots: Arc<ConnectionSlots>, connection_deadline: Duration, shutdown: Shutdown,
    accepted: Option<TcpStream>, lease: Option<ConnectionLease>, accept_error: Option<io::Error>, log_error: Option<io::Error>,
}
impl serve_driver::Effects for ServeEffects {
    fn triggered(&mut self) -> bool { self.shutdown.is_triggered() }
    fn accept(&mut self) -> Accepted {
        let Some(listener) = self.listener.as_ref() else { return Accepted::Failed };
        match listener.accept() {
            Ok((socket, _)) => { self.accepted = Some(socket); Accepted::Connection }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Accepted::Interrupted,
            Err(e) => { self.accept_error = Some(e); Accepted::Failed }
        }
    }
    fn admit_connection(&mut self) -> bool {
        match self.slots.acquire() {
            Some(lease) => { self.lease = Some(lease); true }
            None => { self.accepted = None; false } // over the limit: closed unanswered
        }
    }
    fn serve_connection(&mut self) {
        let (Some(socket), Some(lease)) = (self.accepted.take(), self.lease.take()) else { return };
        let app = self.app.clone();
        let deadline = self.connection_deadline;
        // A thread that cannot start drops its socket and lease here.
        let _ = std::thread::Builder::new().name("hypgate-connection".into()).stack_size(CONNECTION_STACK_BYTES).spawn(move || {
            leased::run(lease, move || { let _ = serve_connection(socket, app, deadline); });
        });
    }
    fn discard_connection(&mut self) { self.accepted = None; }
    fn stop_accepting(&mut self) { self.listener = None; }
    fn close_workers(&mut self) { self.app.worker_slots.close(); }
    fn wait_drained(&mut self, _window: Window) -> bool {
        // One shared window covers connections and workers from all listeners.
        let Some(end) = Instant::now().checked_add(DRAIN_WINDOW) else { return false };
        self.slots.wait_drained(end) && self.app.worker_slots.wait_drained(end)
    }
    fn cancel_live(&mut self) { self.app.cancel_live(); }
    fn close_log(&mut self) -> bool {
        match self.app.log.shutdown(Duration::from_secs(2)) { Ok(()) => true, Err(e) => { self.log_error = Some(e); false } }
    }
}

/// Admission bounds live requests; this separate limit bounds unauthenticated
/// connections and header parsing. Excess accepted sockets are immediately
/// closed. Trigger `shutdown` to drain and join children and close the logger:
/// connections and workers get a drain window, then in-flight exchanges are
/// cancelled and their completion records written. The first invocation fixes
/// the connection limit for this Gateway. Later invocations must use the same
/// limit and share credits. Graceful shutdown permanently closes shared worker
/// admission; a graceful restart requires a fresh Gateway/logger. The order of
/// all of it is the verified `serve_driver`'s.
pub fn serve(listener: TcpListener, app: Arc<Gateway>, connections: usize,
    connection_deadline: Duration, shutdown: &Shutdown) -> io::Result<()> {
    if connections == 0 || connections > 65536 || connection_deadline.is_zero()
        || connection_deadline > Duration::from_secs(3600) { return Err(io::ErrorKind::InvalidInput.into()); }
    let slots = app.connection_slots.get_or_init(|| ConnectionSlots::new(connections)).clone();
    if slots.limit() != connections { return Err(io::ErrorKind::InvalidInput.into()); }
    shutdown.attach(listener.local_addr()?);
    let mut effects = ServeEffects { listener: Some(listener), app, slots, connection_deadline, shutdown: shutdown.clone(),
        accepted: None, lease: None, accept_error: None, log_error: None };
    let driven = serve_driver::serve(&mut effects);
    let result = if driven.accept_ok { Ok(()) } else { Err(effects.accept_error.take().unwrap_or_else(|| io::ErrorKind::Other.into())) };
    let log_result = if driven.log_ok { Ok(()) } else { Err(effects.log_error.take().unwrap_or_else(|| io::ErrorKind::Other.into())) };
    result.and(log_result)
}

#[cfg(test)]
mod tests;
