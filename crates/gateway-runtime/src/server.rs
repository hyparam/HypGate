//! Inbound HTTP/1 server. Deploy behind a trusted TLS terminator; the executable
//! binds loopback only. Each connection serves one request and owns its worker.
use crate::{config::GatewayConfig, disk_log::DiskLog, http_body, http_boundary,
    transport::{HttpsTransport, ResponseSink, TransportError}, transfer::{AuditLog, LogRecord}};
use bytes::Bytes;
use http::{HeaderMap, Request, Response, StatusCode};
use ::http_body::{Body, Frame};
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{convert::Infallible, future::Future, io, pin::Pin, sync::{Arc, atomic::{AtomicU64, Ordering}},
    task::{Context, Poll}, time::Duration};
use tokio::{io::{AsyncWrite, AsyncWriteExt}, net::TcpListener, sync::oneshot, task::{JoinHandle, JoinSet}};
use gateway_core::{exchange_lifecycle::{Closed, Fault, Lifecycle}, health::{GapObserver, Readiness}};
use tokio_util::task::TaskTracker;

mod workers;
mod leased_task;
use workers::WorkerSlots;
mod connections;
use connections::ConnectionSlots;

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

    async fn handle(self: Arc<Self>, request: Request<Incoming>, responses: http_body::ConnectionResponses) -> Result<Response<GatewayBody>, Infallible> {
        if request.method() == http::Method::GET {
            match request.uri().path() {
                "/metrics" => {
                    use std::fmt::Write as _;
                    let mut text = format!("loggate_audit_gap_requests_total {}\nloggate_failed_exchanges_total {}\nloggate_audit_healthy {}\nloggate_worker_admission_healthy {}\n",
                        self.audit_gaps(), self.failed_exchanges(), u8::from(self.log.healthy()), u8::from(self.worker_slots.healthy()));
                    match self.config.usage() {
                        Some((active, limit)) => { let _ = write!(text, "loggate_admission_healthy 1\nloggate_requests_active {active}\nloggate_requests_limit {limit}\n"); }
                        None => text.push_str("loggate_admission_healthy 0\n"),
                    }
                    match &self.shipping { Some(metrics) => metrics.render(&mut text), None => text.push_str("loggate_shipping_enabled 0\n") }
                    let mut response = Response::new(GatewayBody::Fixed(Full::new(Bytes::from(text))));
                    response.headers_mut().insert("content-type", http::HeaderValue::from_static("text/plain; version=0.0.4"));
                    return Ok(response);
                }
                "/healthz" => return Ok(fixed(StatusCode::OK, "ok\n")),
                "/readyz" => {
                    // The rule is the verified `health::readiness`; this only samples its inputs.
                    return Ok(match gateway_core::health::readiness(self.config.admission_healthy(), self.worker_slots.healthy(),
                        self.config.requires_audit(), self.log.healthy()) {
                        Readiness::Ready => fixed(StatusCode::OK, "ready\n"),
                        Readiness::AdmissionUnavailable => fixed(StatusCode::SERVICE_UNAVAILABLE, "admission unavailable\n"),
                        Readiness::AuditUnavailable => fixed(StatusCode::SERVICE_UNAVAILABLE, "audit unavailable\n"),
                    });
                }
                _ => {}
            }
        }
        let lease = match self.worker_slots.acquire(&self.workers) {
            Some(lease) => lease,
            None => return Ok(fixed(StatusCode::SERVICE_UNAVAILABLE, "workers unavailable\n")),
        };
        let (parts, input) = request.into_parts();
        let (head, headers) = oneshot::channel();
        let Some((writer, body)) = responses.channel(16 * 1024) else {
            return Ok(fixed(StatusCode::SERVICE_UNAVAILABLE, "response unavailable\n"));
        };
        let http = lease.http();
        let Some(writer) = http.response_writer(writer) else {
            return Ok(fixed(StatusCode::SERVICE_UNAVAILABLE, "workers unavailable\n"));
        };
        let app = self.clone();
        // The client's response body owns this token: dropping the body before
        // clean EOF cancels the exchange cooperatively, so the worker can still
        // record the completion before releasing its slot. Shutdown shares the
        // same path through the gateway-wide token.
        let disconnect = tokio_util::sync::CancellationToken::new();
        let task = lease.spawn(app.run_exchange(http, parts, input, Output { head: Some(head), writer }, disconnect.clone()));
        let guard = CancelOnDrop { token: disconnect, task: Some(task) };
        worker_response(headers, body, guard).await
    }

    /// Every admitted exchange ends in the verified lifecycle's terminal state
    /// and returns its `Closed` token, so the worker cannot finish without the
    /// completion record having been attempted. Only a request refused before
    /// admission closes without one: it has no records anywhere.
    async fn run_exchange(self: Arc<Self>, http: http_body::WorkerHttp, parts: http::request::Parts,
        input: Incoming, mut output: Output, disconnect: tokio_util::sync::CancellationToken) -> Closed
    {
        let mut prepared = match http_boundary::prepare_request_parts(&self.config, parts) {
            Ok(p) => p,
            Err(e) => {
                let _ = output.start(e.status(), HeaderMap::new()).await;
                let _ = output.shutdown().await;
                return e.close();
            }
        };
        let mut life = Lifecycle::begin();
        let mut log = ObservedLog { log: self.log.clone(), gaps: &self.audit_gaps,
            observer: GapObserver::new(!self.config.requires_audit()) };
        // If strict logging is already unavailable, do not even open an
        // upstream connection. Later failures still use the stream gate.
        if self.config.requires_audit() && !self.log.healthy() {
            let _ = output.start(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new()).await;
            let _ = output.shutdown().await;
            life.failed(Fault::Log);
            return self.audit_completion(&mut prepared, &mut log, life).await;
        }
        // Kind 2 before any DNS, TCP, or TLS effect. Strict mode needs the
        // acknowledgment before dispatch; availability mode marks the request
        // log-failed (the gap counter already incremented) and forwards.
        if prepared.audit_request_start(&mut log).await.is_err() && self.config.requires_audit() {
            let _ = output.start(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new()).await;
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
                    let status = if e == TransportError::Timeout { StatusCode::GATEWAY_TIMEOUT } else { StatusCode::BAD_GATEWAY };
                    let _ = output.start(status, HeaderMap::new()).await;
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
async fn worker_response(headers: oneshot::Receiver<(StatusCode, HeaderMap)>,
    mut body: http_body::ChannelBody, mut guard: CancelOnDrop) -> Result<Response<GatewayBody>, Infallible>
{
    match headers.await {
        Ok((status, headers)) => {
            // Hyper suppresses body polling for these statuses. Drain the
            // empty channel and await accounting before transferring headers,
            // otherwise dropping an unpolled body aborts a successful worker.
            if status == StatusCode::NO_CONTENT || status == StatusCode::NOT_MODIFIED {
                if http_body_util::BodyExt::frame(&mut body).await.is_some() {
                    return Ok(fixed(StatusCode::BAD_GATEWAY, "unexpected upstream body\n"));
                }
                if let Some(task) = &mut guard.task {
                    if task.await.is_err() { return Ok(fixed(StatusCode::BAD_GATEWAY, "upstream failed\n")); }
                }
                guard.task.take();
                let mut response = fixed(status, "");
                *response.headers_mut() = headers;
                return Ok(response);
            }
            let mut response = Response::new(GatewayBody::Stream { body, _task: guard });
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            Ok(response)
        }
        Err(_) => Ok(fixed(StatusCode::BAD_GATEWAY, "upstream failed\n")),
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
enum GatewayBody { Fixed(Full<Bytes>), Stream { body: http_body::ChannelBody, _task: CancelOnDrop } }
impl Body for GatewayBody {
    type Data = Bytes; type Error = io::Error;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            Self::Fixed(body) => Pin::new(body).poll_frame(cx).map(|f| f.map(|r| r.map_err(|never| match never {}))),
            Self::Stream { body, _task } => {
                let result = Pin::new(body).poll_frame(cx);
                // Clean EOF acknowledged the drained queue. Let the tracked worker
                // finish accounting rather than canceling it when Hyper drops us.
                if matches!(result, Poll::Ready(None)) { _task.task.take(); }
                result
            },
        }
    }
    fn is_end_stream(&self) -> bool { match self { Self::Fixed(b) => b.is_end_stream(), Self::Stream { body, .. } => body.is_end_stream() } }
}
fn fixed(status: StatusCode, text: &'static str) -> Response<GatewayBody> {
    let mut response = Response::new(GatewayBody::Fixed(Full::new(Bytes::from_static(text.as_bytes()))));
    *response.status_mut() = status; response
}
struct Output { head: Option<oneshot::Sender<(StatusCode, HeaderMap)>>, writer: http_body::Writer }
impl ResponseSink for Output {
    async fn finish(&mut self) -> io::Result<()> { self.shutdown().await }
    async fn start(&mut self, status: StatusCode, headers: HeaderMap) -> io::Result<()> {
        self.head.take().ok_or(io::ErrorKind::InvalidInput)?.send((status, headers)).map_err(|_| io::ErrorKind::BrokenPipe.into())
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
                    let service = service_fn(move |request| app.clone().handle(request, responses.clone()));
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    // Keep bounded body frames in Hyper's queue strategy.
                    builder.keep_alive(false).writev(true).max_headers(http_boundary::MAX_HEADER_VALUES)
                        .max_header_size(http_boundary::MAX_HEADER_BYTES).max_buf_size(http_body::MAX_INPUT_FRAME)
                        .timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10));
                    let _ = tokio::time::timeout(connection_deadline, builder.serve_connection(TokioIo::new(crate::http_io::ReadLimited::new(socket)), service)).await;
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
