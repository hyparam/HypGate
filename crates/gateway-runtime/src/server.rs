//! Inbound HTTP/1 server over the verified codec. Deploy behind a trusted TLS
//! terminator; the executable binds loopback only. One thread accepts; each
//! accepted connection gets its own thread, which reads the head and body
//! with the verified parsers, runs the exchange, and writes the response with
//! the verified writers, then closes. Blocking sockets throughout; deadlines
//! are socket timeouts (`net::Timed`), and a client that leaves is noticed by
//! a small watcher thread that cancels the exchange.
use crate::{config::GatewayConfig, disk_log::DiskLog, http1, http_body, http_boundary, net::{Cancel, Deadline, Timed},
    transport::{HttpsTransport, ResponseSink}, transfer::{AuditLog, LogRecord}};
use gateway_core::headers::Field;
use gateway_core::http1_exchange::{Connection, Refusal, failure_status, refusal_status, wants_continue};
use gateway_core::http1_framing::framing;
use gateway_core::http1_head::RequestHead;
use gateway_core::{exchange_lifecycle::{Closed, Fault, Lifecycle}, health::{GapObserver, Readiness}};
use std::{collections::HashMap, io::{self, Write}, net::{Shutdown as SocketShutdown, SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, AtomicU64, Ordering}}, time::{Duration, Instant}};

mod workers;
mod leased;
use workers::WorkerSlots;
mod connections;
use connections::ConnectionSlots;

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
        for cancel in cancels { cancel.cancel(); }
    }

    /// The operator endpoints, answered without a worker.
    fn endpoint(&self, target: &[u8]) -> Option<Response> {
        match target {
            b"/metrics" => {
                use std::fmt::Write as _;
                let mut text = format!("loggate_audit_gap_requests_total {}\nloggate_failed_exchanges_total {}\nloggate_audit_healthy {}\nloggate_worker_admission_healthy {}\n",
                    self.audit_gaps(), self.failed_exchanges(), u8::from(self.log.healthy()), u8::from(self.worker_slots.healthy()));
                match self.config.usage() {
                    Some((active, limit)) => { let _ = write!(text, "loggate_admission_healthy 1\nloggate_requests_active {active}\nloggate_requests_limit {limit}\n"); }
                    None => text.push_str("loggate_admission_healthy 0\n"),
                }
                match &self.shipping { Some(metrics) => metrics.render(&mut text), None => text.push_str("loggate_shipping_enabled 0\n") }
                let mut response = fixed(200, text.into_bytes());
                response.fields.push(http1::field(b"content-type", b"text/plain; version=0.0.4".to_vec()));
                Some(response)
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

    /// Every admitted exchange ends in the verified lifecycle's terminal state
    /// and returns its `Closed` token, so the worker cannot finish without the
    /// completion record having been attempted. Only a request refused before
    /// admission closes without one: it has no records anywhere.
    fn run_exchange(&self, http: http_body::WorkerHttp, head: RequestHead, input: http1::BodyReader<Timed<TcpStream>>,
        output: &mut http_body::Charged<Output>, cancel: &Cancel) -> Closed
    {
        let mut prepared = match http_boundary::prepare(&self.config, &head) {
            Ok(p) => p,
            Err(e) => { let _ = output.get_mut().refuse(e.status()); return e.close(); }
        };
        drop(head);
        let mut life = Lifecycle::begin();
        let mut log = ObservedLog { log: self.log.clone(), gaps: &self.audit_gaps,
            observer: GapObserver::new(!self.config.requires_audit()) };
        // If strict logging is already unavailable, do not even open an
        // upstream connection. Later failures still use the stream gate.
        if self.config.requires_audit() && !self.log.healthy() {
            let _ = output.get_mut().refuse(refusal_status(Refusal::Unavailable));
            life.failed(Fault::Log);
            return self.audit_completion(&mut prepared, &mut log, life);
        }
        // Kind 2 before any DNS, TCP, or TLS effect. Strict mode needs the
        // acknowledgment before dispatch; availability mode marks the request
        // log-failed (the gap counter already incremented) and forwards.
        if prepared.audit_request_start(&mut log).is_err() && self.config.requires_audit() {
            let _ = output.get_mut().refuse(refusal_status(Refusal::Unavailable));
            life.failed(Fault::StartRefused);
            return self.audit_completion(&mut prepared, &mut log, life);
        }
        let Some(mut input) = http.input(input) else {
            life.failed(Fault::InputUnavailable);
            return self.audit_completion(&mut prepared, &mut log, life);
        };
        // Cancellation shuts the exchange's sockets, so the transport returns
        // promptly with `Fault::Cancelled`; the completion record follows.
        let result = self.transport.exchange(&mut prepared, &mut input, output, &mut log, &http, cancel);
        drop(input);
        match result {
            Ok(stats) => {
                life.upload_finished(&stats.upload);
                life.succeeded(&stats.download); // the transport's finish wrote the last chunk
            }
            Err(e) => {
                life.failed(e);
                self.failed_exchanges.fetch_add(1, Ordering::Relaxed);
                let output = output.get_mut();
                if output.head_sent() { output.abort(); } else { let _ = output.refuse(failure_status(e)); }
                // After the head, closing without the last chunk tells the
                // client the body is truncated; it is never a clean end.
            }
        }
        self.audit_completion(&mut prepared, &mut log, life)
    }

    // Kind 4 is best effort in both modes: the client-visible result is already
    // fixed, so its failure changes nothing for the client. It is written
    // before the worker releases its slot, and skipped when the logger is
    // already unhealthy.
    fn audit_completion(&self, prepared: &mut http_boundary::PreparedRequest<'_>, log: &mut ObservedLog<'_>, life: Lifecycle) -> Closed {
        if !self.log.healthy() { return life.close(false); }
        let payload = life.completion(http_boundary::unix_ms());
        let recorded = prepared.audit_completion(log, &payload).is_ok();
        life.close(recorded)
    }
}

// Report potential audit loss at the first failed append, not only after a
// successful response: cancellation and provider failures must not hide it.
// The verified observer decides when an append counts; this only adds one.
struct ObservedLog<'a> { log: DiskLog, gaps: &'a AtomicU64, observer: GapObserver }
impl AuditLog for ObservedLog<'_> {
    fn session_id(&self) -> u128 { self.log.session_id() }
    fn append(&mut self, record: LogRecord<'_>) -> io::Result<crate::transfer::DurableFrame> {
        let result = self.log.append(record);
        if self.observer.observe(result.is_err()) { self.gaps.fetch_add(1, Ordering::Relaxed); }
        result
    }
}

/// A response the connection writes without a worker: the head fields without
/// framing or Connection, which the machine adds, and a fixed body.
struct Response { status: u16, fields: Vec<Field>, body: Vec<u8> }
fn fixed(status: u16, text: Vec<u8>) -> Response { Response { status, fields: Vec::new(), body: text } }

/// The client's side of the response. Every byte it writes comes from the
/// verified `Connection` machine: one head, framing that matches the body,
/// and a last chunk only through `finish`.
struct Output { io: Option<Timed<TcpStream>>, connection: Connection, body: Option<http1::ChunkedWriter<Timed<TcpStream>>>, head_sent: bool }
impl Output {
    fn new(io: Timed<TcpStream>, connection: Connection) -> Self { Self { io: Some(io), connection, body: None, head_sent: false } }
    fn head_sent(&self) -> bool { self.head_sent }
    /// A complete response with a fixed body, then the write side is closed.
    fn respond_fixed(&mut self, status: u16, fields: Vec<Field>, text: &[u8]) -> io::Result<()> {
        let bytes = self.connection.respond_fixed(status, http1::reason(status), fields, text).ok_or(io::ErrorKind::InvalidData)?;
        self.head_sent = true;
        let io = self.io.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        http1::write_fully(io, &bytes)?;
        io.flush()?;
        self.close_write();
        Ok(())
    }
    /// A refusal or failure: the machine's status, no body.
    fn refuse(&mut self, status: u16) -> io::Result<()> { self.respond_fixed(status, Vec::new(), b"") }
    /// Stop without the last chunk: a truncated stream is never a clean end.
    fn abort(&mut self) {
        self.connection.abort();
        if let Some(body) = self.body.take() { let (io, _) = body.into_parts(); self.io = Some(io); }
        self.close_write();
    }
    fn close_write(&mut self) {
        if let Some(io) = &self.io { let _ = io.inner().shutdown(SocketShutdown::Write); }
    }
}
impl Drop for Output {
    fn drop(&mut self) {
        // Leaving with a stream open is an abort: the client never sees a last chunk.
        if self.body.is_some() { self.abort(); } else { self.close_write(); }
    }
}
impl ResponseSink for Output {
    fn start(&mut self, status: u16, fields: Vec<Field>) -> io::Result<()> {
        if self.head_sent { return Err(io::ErrorKind::InvalidInput.into()); }
        if status == 204 || status == 304 {
            // No body may follow these statuses; the machine writes the fixed head.
            let bytes = self.connection.respond_fixed(status, http1::reason(status), fields, b"").ok_or(io::ErrorKind::InvalidData)?;
            self.head_sent = true;
            let io = self.io.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
            http1::write_fully(io, &bytes)?;
            return io.flush();
        }
        let (head, stream) = self.connection.respond_stream(status, http1::reason(status), fields).ok_or(io::ErrorKind::InvalidData)?;
        self.head_sent = true;
        let mut io = self.io.take().ok_or(io::ErrorKind::BrokenPipe)?;
        http1::write_fully(&mut io, &head)?;
        io.flush()?;
        self.body = Some(http1::ChunkedWriter::new(io, stream));
        Ok(())
    }
    fn finish(&mut self) -> io::Result<()> {
        if !self.head_sent { return Err(io::ErrorKind::InvalidInput.into()); }
        if let Some(mut body) = self.body.take() {
            let finished = body.finish();
            let (io, stream) = body.into_parts();
            self.io = Some(io);
            finished?;
            self.connection.finish(stream);
        }
        self.close_write();
        Ok(())
    }
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let body = self.body.as_mut().ok_or(io::ErrorKind::BrokenPipe)?;
        let n = body.write(bytes)?;
        body.flush()?; // each frame reaches the client as soon as it is copied
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { self.body.as_mut().ok_or(io::ErrorKind::BrokenPipe)?.flush() }
}

/// Answer a refusal with the verified machine's status and no body, then close.
fn refuse(io: &mut Timed<TcpStream>, connection: &mut Connection, refusal: Refusal) -> io::Result<()> {
    let status = refusal_status(refusal);
    let bytes = connection.respond_fixed(status, http1::reason(status), Vec::new(), b"").ok_or(io::ErrorKind::InvalidData)?;
    http1::write_fully(io, &bytes)?;
    io.flush()?;
    io.inner().shutdown(SocketShutdown::Write)
}

/// Watches the client socket while the exchange runs and cancels the exchange
/// when the client leaves: EOF or an error on a peek, once the request bytes
/// have been consumed. Stray bytes after the body are left in place and keep
/// the watcher polling; a client that half-closes after its request is, as
/// before, treated as gone.
struct ClientWatch { thread: Option<std::thread::JoinHandle<()>>, finished: Arc<AtomicBool>, socket: TcpStream }
impl ClientWatch {
    fn start(socket: TcpStream, cancel: Cancel) -> io::Result<Self> {
        let finished = Arc::new(AtomicBool::new(false));
        let probe = socket.try_clone()?;
        let flag = finished.clone();
        let thread = std::thread::Builder::new().name("loggate-watch".into()).stack_size(WATCHER_STACK_BYTES).spawn(move || {
            let mut byte = [0u8; 1];
            loop {
                if flag.load(Ordering::Acquire) { return; }
                match probe.peek(&mut byte) {
                    Ok(0) => break, // EOF: the client is gone
                    Ok(_) => std::thread::sleep(Duration::from_millis(20)), // request bytes still being consumed
                    Err(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            if !flag.load(Ordering::Acquire) { cancel.cancel(); }
        })?;
        Ok(Self { thread: Some(thread), finished, socket })
    }
    /// The exchange is over: stop watching and join.
    fn finish(mut self) {
        self.finished.store(true, Ordering::Release);
        let _ = self.socket.shutdown(SocketShutdown::Both);
        if let Some(thread) = self.thread.take() { let _ = thread.join(); }
    }
}

/// Serve one connection: one request, one response, then close. A head that
/// does not arrive in time or does not parse gets no worker and no record.
fn serve_connection(socket: TcpStream, app: Arc<Gateway>, connection_deadline: Duration) -> io::Result<()> {
    let deadline = Deadline::start(connection_deadline)?;
    let write_half = socket.try_clone()?;
    // Every byte this connection writes is produced by the verified machine.
    let mut connection = Connection::new();
    let mut writer = Timed::new(write_half, deadline);
    let mut reader = Timed::new(socket, Deadline::start(HEAD_DEADLINE)?.min(deadline));
    let (head, leftover) = match http1::read_request_head(&mut reader, Vec::new()) {
        Ok(parsed) => parsed,
        Err(http1::HeadError::TooLarge) => return refuse(&mut writer, &mut connection, Refusal::HeadTooLarge),
        Err(http1::HeadError::Malformed) => return refuse(&mut writer, &mut connection, Refusal::Malformed),
        Err(_) => return Ok(()), // closed or silent before a complete head
    };
    let reader = Timed::new(reader.into_inner(), deadline);
    let body_framing = match framing(&head.fields, true) {
        Ok(f) => f,
        Err(_) => return refuse(&mut writer, &mut connection, Refusal::Malformed),
    };
    // A client waiting for permission to send its body gets it; the body is
    // read whether or not the request is then admitted.
    if wants_continue(&head.fields) {
        if let Some(bytes) = connection.interim_continue() { http1::write_fully(&mut writer, &bytes)?; writer.flush()?; }
    }
    let mut output = Output::new(writer, connection);
    if head.method == b"GET" {
        if let Some(response) = app.endpoint(&head.target) { return output.respond_fixed(response.status, response.fields, &response.body); }
    }
    let Some(lease) = app.worker_slots.acquire() else {
        return output.respond_fixed(refusal_status(Refusal::Unavailable), Vec::new(), b"workers unavailable\n");
    };
    let http = lease.http();
    let Some(mut output) = http.response_writer(output) else {
        return Err(io::ErrorKind::Other.into()); // a fresh worker issues every role once
    };
    let cancel = Cancel::new();
    cancel.watch_socket(reader.inner())?; // gateway shutdown closes the client too
    let watcher = ClientWatch::start(reader.inner().try_clone()?, cancel.clone())?;
    let id = app.track(&cancel);
    let body = http1::BodyReader::new(reader, leftover, body_framing);
    let exchange_cancel = cancel.clone();
    let worker_app = app.clone();
    leased::run(lease, move || {
        let _closed = worker_app.run_exchange(http, head, body, &mut output, &exchange_cancel);
        drop(output); // every stream the worker issued is gone before its credit returns
    });
    app.untrack(id);
    cancel.release_sockets();
    watcher.finish();
    Ok(())
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

/// Admission bounds live requests; this separate limit bounds unauthenticated
/// connections and header parsing. Excess accepted sockets are immediately
/// closed. Trigger `shutdown` to drain and join children and close the logger:
/// connections and workers get a drain window, then in-flight exchanges are
/// cancelled and their completion records written. The first invocation fixes
/// the connection limit for this Gateway. Later invocations must use the same
/// limit and share credits. Graceful shutdown permanently closes shared worker
/// admission; a graceful restart requires a fresh Gateway/logger.
pub fn serve(listener: TcpListener, app: Arc<Gateway>, connections: usize,
    connection_deadline: Duration, shutdown: &Shutdown) -> io::Result<()> {
    if connections == 0 || connections > 65536 || connection_deadline.is_zero()
        || connection_deadline > Duration::from_secs(3600) { return Err(io::ErrorKind::InvalidInput.into()); }
    let slots = app.connection_slots.get_or_init(|| ConnectionSlots::new(connections)).clone();
    if slots.limit() != connections { return Err(io::ErrorKind::InvalidInput.into()); }
    shutdown.attach(listener.local_addr()?);
    let result = loop {
        if shutdown.is_triggered() { break Ok(()); }
        let (socket, _) = match listener.accept() {
            Ok(accepted) => accepted,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => break Err(e),
        };
        if shutdown.is_triggered() { break Ok(()); } // the wake-up connection, or a late client
        let Some(lease) = slots.acquire() else { continue; }; // over the limit: closed unanswered
        let app = app.clone();
        // A thread that cannot start drops its socket and lease here.
        let _ = std::thread::Builder::new().name("loggate-connection".into()).stack_size(CONNECTION_STACK_BYTES).spawn(move || {
            leased::run(lease, move || { let _ = serve_connection(socket, app, connection_deadline); });
        });
    };
    drop(listener);
    app.worker_slots.close();
    // One shared drain window covers connections and workers from all listeners.
    let drain_end = Instant::now() + DRAIN_WINDOW;
    let drained = slots.wait_drained(drain_end) && app.worker_slots.wait_drained(drain_end);
    if !drained {
        app.cancel_live();
        let cancel_end = Instant::now() + DRAIN_WINDOW;
        slots.wait_drained(cancel_end);
        app.worker_slots.wait_drained(cancel_end);
    }
    let log_result = app.log.shutdown(Duration::from_secs(2));
    result.and(log_result)
}

#[cfg(test)]
mod tests;
