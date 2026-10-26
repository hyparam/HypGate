//! Inbound HTTP/1 server over the verified codec. Deploy behind a trusted TLS
//! terminator; the executable binds loopback only. Each connection serves one
//! request and owns its worker; the connection task reads the head and body
//! with the verified parsers and writes the response with the verified
//! writers, and the worker runs the exchange.
use crate::{config::GatewayConfig, disk_log::DiskLog, http1, http_body, http_boundary,
    transport::{HttpsTransport, ResponseSink}, transfer::{AuditLog, LogRecord}};
use gateway_core::headers::Field;
use gateway_core::http1_exchange::{Connection, Refusal, failure_status, refusal_status, wants_continue};
use gateway_core::http1_framing::framing;
use gateway_core::http1_head::RequestHead;
use std::{future::Future, io, pin::Pin, sync::{Arc, atomic::{AtomicU64, Ordering}}, task::{Context, Poll}, time::Duration};
use tokio::{io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::oneshot, task::{JoinHandle, JoinSet}};
use gateway_core::{exchange_lifecycle::{Closed, Fault, Lifecycle}, health::{GapObserver, Readiness}};
use tokio_util::task::TaskTracker;

mod workers;
mod leased_task;
use workers::WorkerSlots;
mod connections;
use connections::ConnectionSlots;

/// How long a connection may take to send its complete request head.
pub(crate) const HEAD_DEADLINE: Duration = Duration::from_secs(10);

pub struct Gateway {
    config: Arc<GatewayConfig>,
    transport: HttpsTransport,
    log: DiskLog,
    workers: TaskTracker,
    cancel_workers: tokio_util::sync::CancellationToken,
    worker_slots: Arc<WorkerSlots>,
    connection_slots: std::sync::OnceLock<Arc<ConnectionSlots>>,
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
        Arc::new(Self { worker_slots: WorkerSlots::new(config.request_limit()), config: Arc::new(config), transport, log, workers: TaskTracker::new(),
            connection_slots: std::sync::OnceLock::new(),
            cancel_workers: tokio_util::sync::CancellationToken::new(),
            audit_gaps: AtomicU64::new(0), failed_exchanges: AtomicU64::new(0), shipping })
    }
    pub fn audit_gaps(&self) -> u64 { self.audit_gaps.load(Ordering::Relaxed) }
    pub fn failed_exchanges(&self) -> u64 { self.failed_exchanges.load(Ordering::Relaxed) }

    /// Dispatch one parsed request. `input` is its body; the response is what
    /// the connection task writes.
    async fn handle<B: AsyncRead + Unpin + Send + 'static>(self: Arc<Self>, head: RequestHead, input: B,
        responses: http_body::ConnectionResponses) -> Response {
        if head.method == b"GET" {
            match head.target.as_slice() {
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
                    return response;
                }
                b"/healthz" => return fixed(200, b"ok\n".to_vec()),
                b"/readyz" => {
                    // The rule is the verified `health::readiness`; this only samples its inputs.
                    return match gateway_core::health::readiness(self.config.admission_healthy(), self.worker_slots.healthy(),
                        self.config.requires_audit(), self.log.healthy()) {
                        Readiness::Ready => fixed(200, b"ready\n".to_vec()),
                        Readiness::AdmissionUnavailable => fixed(refusal_status(Refusal::Unavailable), b"admission unavailable\n".to_vec()),
                        Readiness::AuditUnavailable => fixed(refusal_status(Refusal::Unavailable), b"audit unavailable\n".to_vec()),
                    };
                }
                _ => {}
            }
        }
        let lease = match self.worker_slots.acquire(&self.workers) {
            Some(lease) => lease,
            None => return fixed(refusal_status(Refusal::Unavailable), b"workers unavailable\n".to_vec()),
        };
        let (head_sender, head_receiver) = oneshot::channel();
        let Some((writer, body)) = responses.channel(16 * 1024) else {
            return fixed(refusal_status(Refusal::Unavailable), b"response unavailable\n".to_vec());
        };
        let http = lease.http();
        let Some(writer) = http.response_writer(writer) else {
            return fixed(refusal_status(Refusal::Unavailable), b"workers unavailable\n".to_vec());
        };
        let app = self.clone();
        // The client's response body owns this token: dropping the body before
        // clean EOF cancels the exchange cooperatively, so the worker can still
        // record the completion before releasing its slot. Shutdown shares the
        // same path through the gateway-wide token.
        let disconnect = tokio_util::sync::CancellationToken::new();
        let task = lease.spawn(app.run_exchange(http, head, input, Output { head: Some(head_sender), writer }, disconnect.clone()));
        let guard = CancelOnDrop { token: disconnect, task: Some(task) };
        worker_response(head_receiver, body, guard).await
    }

    /// Every admitted exchange ends in the verified lifecycle's terminal state
    /// and returns its `Closed` token, so the worker cannot finish without the
    /// completion record having been attempted. Only a request refused before
    /// admission closes without one: it has no records anywhere.
    async fn run_exchange<B: AsyncRead + Unpin>(self: Arc<Self>, http: http_body::WorkerHttp, head: RequestHead,
        input: B, mut output: Output, disconnect: tokio_util::sync::CancellationToken) -> Closed
    {
        let mut prepared = match http_boundary::prepare(&self.config, &head) {
            Ok(p) => p,
            Err(e) => {
                let _ = output.start(e.status(), Vec::new()).await;
                let _ = output.shutdown().await;
                return e.close();
            }
        };
        drop(head);
        let mut life = Lifecycle::begin();
        let mut log = ObservedLog { log: self.log.clone(), gaps: &self.audit_gaps,
            observer: GapObserver::new(!self.config.requires_audit()) };
        // If strict logging is already unavailable, do not even open an
        // upstream connection. Later failures still use the stream gate.
        if self.config.requires_audit() && !self.log.healthy() {
            let _ = output.start(refusal_status(Refusal::Unavailable), Vec::new()).await;
            let _ = output.shutdown().await;
            life.failed(Fault::Log);
            return self.audit_completion(&mut prepared, &mut log, life).await;
        }
        // Kind 2 before any DNS, TCP, or TLS effect. Strict mode needs the
        // acknowledgment before dispatch; availability mode marks the request
        // log-failed (the gap counter already incremented) and forwards.
        if prepared.audit_request_start(&mut log).await.is_err() && self.config.requires_audit() {
            let _ = output.start(refusal_status(Refusal::Unavailable), Vec::new()).await;
            let _ = output.shutdown().await;
            life.failed(Fault::StartRefused);
            return self.audit_completion(&mut prepared, &mut log, life).await;
        }
        let Some(mut input) = http.input(input) else {
            life.failed(Fault::InputUnavailable);
            return self.audit_completion(&mut prepared, &mut log, life).await;
        };
        // Cancellation drops the exchange future, and with it every upstream
        // socket and body future, before the completion record is written.
        let result = tokio::select! {
            biased;
            _ = self.cancel_workers.cancelled() => None,
            _ = disconnect.cancelled() => None,
            result = self.transport.exchange(&mut prepared, &mut input, &mut output, &mut log, &http) => Some(result),
        };
        match result {
            Some(Ok(stats)) => {
                life.upload_finished(&stats.upload);
                life.succeeded(&stats.download);
                let _ = output.shutdown().await; // only success sends the clean EOF marker
            }
            Some(Err(e)) => {
                life.failed(e);
                self.failed_exchanges.fetch_add(1, Ordering::Relaxed);
                if output.head.is_some() {
                    let _ = output.start(failure_status(e), Vec::new()).await;
                    let _ = output.shutdown().await;
                }
                // After headers, dropping the writer makes the body fail;
                // never turn a truncated generation into successful HTTP EOF.
            }
            None => life.failed(Fault::Cancelled), // the head sender or body writer drops unfinished
        }
        self.audit_completion(&mut prepared, &mut log, life).await
    }

    // Kind 4 is best effort in both modes: the client-visible result is already
    // fixed, so its failure changes nothing for the client. It is written inline
    // before the worker releases its slot, never from a detached task, and
    // skipped when the logger is already unhealthy.
    async fn audit_completion(&self, prepared: &mut http_boundary::PreparedRequest<'_>, log: &mut ObservedLog<'_>,
        life: Lifecycle) -> Closed
    {
        if !self.log.healthy() { return life.close(false); }
        let payload = life.completion(http_boundary::unix_ms());
        let recorded = prepared.audit_completion(log, &payload).await.is_ok();
        life.close(recorded)
    }
}

// Build the response while retaining cancellation ownership of its worker.
async fn worker_response(headers: oneshot::Receiver<(u16, Vec<Field>)>,
    mut body: http_body::ChannelBody, mut guard: CancelOnDrop) -> Response
{
    match headers.await {
        Ok((status, fields)) => {
            // No body may follow these statuses. Drain the empty channel and
            // await accounting before transferring the head, otherwise dropping
            // an unpolled body aborts a successful worker.
            if status == 204 || status == 304 {
                if body.next_frame().await.is_some() {
                    return fixed(failure_status(Fault::Download), b"unexpected upstream body\n".to_vec());
                }
                if let Some(task) = &mut guard.task {
                    if task.await.is_err() { return fixed(failure_status(Fault::Download), b"upstream failed\n".to_vec()); }
                }
                guard.task.take();
                return Response { status, fields, body: GatewayBody::Fixed(Vec::new()) };
            }
            Response { status, fields, body: GatewayBody::Stream { body, task: guard } }
        }
        Err(_) => fixed(failure_status(Fault::Http), b"upstream failed\n".to_vec()),
    }
}

// Report potential audit loss at the first failed append, not only after a
// successful response: cancellation and provider failures must not hide it.
// The verified observer decides when an append counts; this only adds one.
struct ObservedLog<'a> { log: DiskLog, gaps: &'a AtomicU64, observer: GapObserver }
impl AuditLog for ObservedLog<'_> {
    fn session_id(&self) -> u128 { self.log.session_id() }
    async fn append(&mut self, record: LogRecord<'_>) -> io::Result<crate::transfer::DurableFrame> {
        let result = self.log.append(record).await;
        if self.observer.observe(result.is_err()) { self.gaps.fetch_add(1, Ordering::Relaxed); }
        result
    }
}

// Dropping the guard before clean EOF cancels the worker's exchange through its
// token; the worker then records the completion and finishes on its own.
struct CancelOnDrop { token: tokio_util::sync::CancellationToken, task: Option<JoinHandle<()>> }
impl Drop for CancelOnDrop { fn drop(&mut self) { if self.task.is_some() { self.token.cancel(); } } }

/// A response the connection task writes: the head fields without framing
/// or Connection, which the writer adds, and a fixed or streamed body.
struct Response { status: u16, fields: Vec<Field>, body: GatewayBody }
enum GatewayBody { Fixed(Vec<u8>), Stream { body: http_body::ChannelBody, task: CancelOnDrop } }
fn fixed(status: u16, text: Vec<u8>) -> Response { Response { status, fields: Vec::new(), body: GatewayBody::Fixed(text) } }

struct Output { head: Option<oneshot::Sender<(u16, Vec<Field>)>>, writer: http_body::Writer }
impl ResponseSink for Output {
    async fn finish(&mut self) -> io::Result<()> { self.shutdown().await }
    async fn start(&mut self, status: u16, fields: Vec<Field>) -> io::Result<()> {
        self.head.take().ok_or(io::ErrorKind::InvalidInput)?.send((status, fields)).map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}
impl AsyncWrite for Output {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

/// Answer a refusal with the verified machine's status and no body, then close.
async fn refuse<W: AsyncWrite + Unpin>(io: &mut W, connection: &mut Connection, refusal: Refusal) -> io::Result<()> {
    let status = refusal_status(refusal);
    let bytes = connection.respond_fixed(status, http1::reason(status), Vec::new(), b"").ok_or(io::ErrorKind::InvalidData)?;
    io.write_all(&bytes).await?;
    io.shutdown().await
}

/// Serve one connection: one request, one response, then close. A head that
/// does not arrive in time or does not parse gets no worker and no record.
async fn serve_connection(socket: TcpStream, app: Arc<Gateway>, responses: http_body::ConnectionResponses) -> io::Result<()> {
    let (mut reader, mut writer) = socket.into_split();
    // Every byte this connection writes is produced by the verified machine.
    let mut connection = Connection::new();
    let head = tokio::time::timeout(HEAD_DEADLINE, http1::read_request_head(&mut reader, Vec::new())).await;
    let (head, leftover) = match head {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(http1::HeadError::TooLarge)) => return refuse(&mut writer, &mut connection, Refusal::HeadTooLarge).await,
        Ok(Err(http1::HeadError::Malformed)) => return refuse(&mut writer, &mut connection, Refusal::Malformed).await,
        Ok(Err(_)) | Err(_) => return Ok(()), // closed or silent before a complete head
    };
    let body_framing = match framing(&head.fields, true) {
        Ok(f) => f,
        Err(_) => return refuse(&mut writer, &mut connection, Refusal::Malformed).await,
    };
    // A client waiting for permission to send its body gets it; the body is
    // read whether or not the request is then admitted.
    if wants_continue(&head.fields) {
        if let Some(bytes) = connection.interim_continue() { writer.write_all(&bytes).await?; }
    }
    // The connection task keeps the socket. It pumps the framed request body
    // into the worker's bounded channel and, once the body is complete, keeps
    // watching the socket: a close or error there is the client leaving, which
    // cancels the worker through the response's drop guard, as before.
    let (mut body_tx, body_rx) = http_body::channel(http1::READ_BYTES);
    let client_gone = tokio_util::sync::CancellationToken::new();
    let pump = {
        let client_gone = client_gone.clone();
        async move {
            let mut source = http1::BodyReader::new(reader, leftover, body_framing);
            let mut buffer = vec![0u8; http1::READ_BYTES];
            loop {
                match source.read(&mut buffer).await {
                    Ok(0) => break,
                    // A worker that no longer reads its body is not a client fault;
                    // keep watching the socket for the client leaving.
                    Ok(n) => { if body_tx.write_all(&buffer[..n]).await.is_err() { break; } }
                    Err(_) => { drop(body_tx); client_gone.cancel(); return std::future::pending::<()>().await; }
                }
            }
            let mut reader = source.into_inner();
            let end = async { let _ = body_tx.shutdown().await; drop(body_tx); };
            let watch = async {
                let mut byte = [0u8; 1];
                let _ = reader.read(&mut byte).await; // EOF, error, or stray bytes: the client is done with us
                client_gone.cancel();
            };
            tokio::join!(watch, end);
            std::future::pending::<()>().await
        }
    };
    tokio::pin!(pump);
    let handle = app.handle(head, body_rx, responses);
    let response = tokio::select! {
        response = handle => response,
        _ = &mut pump => unreachable!("the pump never completes"),
        _ = client_gone.cancelled() => return Ok(()), // the client left before the response head
    };
    let write = async {
        let status = response.status;
        match response.body {
            GatewayBody::Fixed(text) => {
                let bytes = connection.respond_fixed(status, http1::reason(status), response.fields, &text).ok_or(io::ErrorKind::InvalidData)?;
                writer.write_all(&bytes).await?;
                writer.shutdown().await
            }
            GatewayBody::Stream { mut body, task } => {
                let (head, stream) = connection.respond_stream(status, http1::reason(status), response.fields).ok_or(io::ErrorKind::InvalidData)?;
                writer.write_all(&head).await?;
                let mut chunked = http1::ChunkedWriter::new(&mut writer, stream);
                loop {
                    match body.next_frame().await {
                        Some(Ok(frame)) => { chunked.write_all(&frame).await?; chunked.flush().await?; }
                        // A failed body ends the connection without the last chunk:
                        // a truncated stream is never a clean end.
                        Some(Err(e)) => { connection.abort(); return Err(e); }
                        None => break,
                    }
                }
                chunked.shutdown().await?;
                connection.finish(chunked.into_stream());
                // Clean EOF acknowledged the drained queue. Let the tracked worker
                // finish accounting rather than canceling it.
                let mut task = task;
                task.task.take();
                drop(body);
                writer.shutdown().await
            }
        }
    };
    tokio::select! {
        result = write => result,
        _ = &mut pump => unreachable!("the pump never completes"),
        _ = client_gone.cancelled() => Ok(()), // the client left mid-response; dropping the body cancels the worker
    }
}

/// Admission bounds live requests; this separate limit bounds unauthenticated
/// connections and header parsing. Excess accepted sockets are immediately closed.
/// Signal `shutdown` and await this function to drain and join children and close
/// the logger. Dropping this future only requests child cancellation: cleanup
/// may outlive it, and the shared logger's explicit shutdown is skipped. The
/// first invocation fixes the connection limit for this Gateway. Later invocations
/// must use the same limit and share credits, including canceled-task cleanup.
/// Graceful shutdown permanently closes shared worker admission and cancels
/// remaining shared workers after the drain window; other invocations still
/// own their listeners. A graceful restart requires a fresh Gateway/logger.
pub async fn serve(listener: TcpListener, app: Arc<Gateway>, connections: usize,
    connection_deadline: Duration, shutdown: impl Future<Output = ()>) -> io::Result<()> {
    if connections == 0 || connections > 65536 || connection_deadline.is_zero()
        || connection_deadline > Duration::from_secs(3600) { return Err(io::ErrorKind::InvalidInput.into()); }
    let slots = app.connection_slots.get_or_init(|| ConnectionSlots::new(connections)).clone();
    if slots.limit() != connections { return Err(io::ErrorKind::InvalidInput.into()); }
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break Ok(()),
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (socket, _) = match accepted { Ok(v) => v, Err(e) => break Err(e) };
                if tasks.len() >= connections { drop(socket); continue; }
                let Some(lease) = slots.acquire() else { drop(socket); continue; };
                let app = app.clone();
                let responses = lease.responses();
                tasks.spawn(lease.task(async move {
                    let _ = tokio::time::timeout(connection_deadline, serve_connection(socket, app, responses)).await;
                }));
            }
        }
    };
    drop(listener);
    app.worker_slots.close(&app.workers);
    // One shared drain window covers connections and workers from all listeners.
    let drain_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    if tokio::time::timeout_at(drain_deadline, async { while tasks.join_next().await.is_some() {} }).await.is_err() {
        tasks.abort_all(); while tasks.join_next().await.is_some() {}
    }
    if tokio::time::timeout_at(drain_deadline, app.worker_slots.wait_drained(&app.workers)).await.is_err() {
        app.cancel_workers.cancel();
        app.worker_slots.wait_drained(&app.workers).await;
    }
    let log_result = app.log.shutdown(Duration::from_secs(2)).await;
    result.and(log_result)
}

#[cfg(test)]
mod tests;
