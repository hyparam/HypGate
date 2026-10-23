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
use tokio_util::task::TaskTracker;

pub struct Gateway {
    config: Arc<GatewayConfig>,
    transport: HttpsTransport,
    log: DiskLog,
    workers: TaskTracker,
    audit_gaps: AtomicU64,
    failed_exchanges: AtomicU64,
}
impl Gateway {
    pub fn new(config: GatewayConfig, transport: HttpsTransport, log: DiskLog) -> Arc<Self> {
        Arc::new(Self { config: Arc::new(config), transport, log, workers: TaskTracker::new(),
            audit_gaps: AtomicU64::new(0), failed_exchanges: AtomicU64::new(0) })
    }
    pub fn audit_gaps(&self) -> u64 { self.audit_gaps.load(Ordering::Relaxed) }
    pub fn failed_exchanges(&self) -> u64 { self.failed_exchanges.load(Ordering::Relaxed) }

    async fn handle(self: Arc<Self>, request: Request<Incoming>) -> Result<Response<GatewayBody>, Infallible> {
        if request.method() == http::Method::GET && request.uri().path() == "/metrics" {
            let text = format!("soundgate_audit_gap_requests_total {}\nsoundgate_failed_exchanges_total {}\nsoundgate_audit_healthy {}\n",
                self.audit_gaps(), self.failed_exchanges(), u8::from(self.log.healthy()));
            let mut response = Response::new(GatewayBody::Fixed(Full::new(Bytes::from(text))));
            response.headers_mut().insert("content-type", http::HeaderValue::from_static("text/plain; version=0.0.4"));
            return Ok(response);
        }
        if request.method() == http::Method::GET && request.uri().path() == "/healthz" {
            return Ok(fixed(StatusCode::OK, "ok\n"));
        }
        if request.method() == http::Method::GET && request.uri().path() == "/readyz" {
            let ready = !self.config.requires_audit() || self.log.healthy();
            return Ok(fixed(if ready { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE },
                if ready { "ready\n" } else { "audit unavailable\n" }));
        }
        let (parts, input) = request.into_parts();
        let (head, headers) = oneshot::channel();
        let (writer, body) = http_body::channel(16 * 1024);
        let app = self.clone();
        let task = self.workers.spawn(async move {
            let mut output = Output { head: Some(head), writer };
            let prepared = match http_boundary::prepare(&app.config, &parts.method, &parts.uri, &parts.headers) {
                Ok(p) => p,
                Err(e) => {
                    let _ = output.start(e.status(), HeaderMap::new()).await;
                    let _ = output.shutdown().await;
                    return;
                }
            };
            // If strict logging is already unavailable, do not even open an
            // upstream connection. Later failures still use the stream gate.
            if app.config.requires_audit() && !app.log.healthy() {
                let _ = output.start(StatusCode::SERVICE_UNAVAILABLE, HeaderMap::new()).await;
                let _ = output.shutdown().await;
                return;
            }
            let mut log = ObservedLog { log: app.log.clone(), gaps: &app.audit_gaps,
                availability: !app.config.requires_audit(), reported: false };
            let result = app.transport.exchange(prepared, &mut http_body::Reader::new(input), &mut output, &mut log).await;
            match result {
                Ok(_) => {
                    let _ = output.shutdown().await; // only success sends the clean EOF marker
                }
                Err(e) => {
                    app.failed_exchanges.fetch_add(1, Ordering::Relaxed);
                    if output.head.is_some() {
                        let status = if e == TransportError::Timeout { StatusCode::GATEWAY_TIMEOUT } else { StatusCode::BAD_GATEWAY };
                        let _ = output.start(status, HeaderMap::new()).await;
                        let _ = output.shutdown().await;
                    }
                    // After headers, dropping the writer makes the body fail;
                    // never turn a truncated generation into successful HTTP EOF.
                }
            }
        });
        let guard = AbortOnDrop(Some(task));
        match headers.await {
            Ok((status, headers)) => {
                let mut response = Response::new(GatewayBody::Stream { body, _task: guard });
                *response.status_mut() = status;
                *response.headers_mut() = headers;
                Ok(response)
            }
            Err(_) => Ok(fixed(StatusCode::BAD_GATEWAY, "upstream failed\n")),
        }
    }
}

// Report potential audit loss at the first failed append, not only after a
// successful response: cancellation and provider failures must not hide it.
struct ObservedLog<'a> { log: DiskLog, gaps: &'a AtomicU64, availability: bool, reported: bool }
impl AuditLog for ObservedLog<'_> {
    async fn append(&mut self, record: LogRecord<'_>) -> io::Result<()> {
        let result = self.log.append(record).await;
        if result.is_err() && self.availability && !self.reported {
            self.gaps.fetch_add(1, Ordering::Relaxed); self.reported = true;
        }
        result
    }
}

struct AbortOnDrop(Option<JoinHandle<()>>);
impl Drop for AbortOnDrop { fn drop(&mut self) { if let Some(task) = &self.0 { task.abort(); } } }
enum GatewayBody { Fixed(Full<Bytes>), Stream { body: http_body::ChannelBody, _task: AbortOnDrop } }
impl Body for GatewayBody {
    type Data = Bytes; type Error = io::Error;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        match self.get_mut() {
            Self::Fixed(body) => Pin::new(body).poll_frame(cx).map(|f| f.map(|r| r.map_err(|never| match never {}))),
            Self::Stream { body, _task } => {
                let result = Pin::new(body).poll_frame(cx);
                // Clean EOF acknowledged the drained queue. Let the tracked worker
                // finish accounting rather than aborting it when Hyper drops us.
                if matches!(result, Poll::Ready(None)) { _task.0.take(); }
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
pub async fn serve(listener: TcpListener, app: Arc<Gateway>, connections: usize,
    connection_deadline: Duration, shutdown: impl Future<Output = ()>) -> io::Result<()> {
    if connections == 0 || connections > 65536 || connection_deadline.is_zero()
        || connection_deadline > Duration::from_secs(3600) { return Err(io::ErrorKind::InvalidInput.into()); }
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
                let app = app.clone();
                tasks.spawn(async move {
                    let service = service_fn(move |request| app.clone().handle(request));
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder.keep_alive(false).max_headers(100).max_buf_size(32 * 1024)
                        .timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10));
                    let _ = tokio::time::timeout(connection_deadline, builder.serve_connection(TokioIo::new(socket), service)).await;
                });
            }
        }
    };
    drop(listener);
    // A bounded drain then abort: no request is replayed during shutdown.
    if tokio::time::timeout(Duration::from_secs(10), async { while tasks.join_next().await.is_some() {} }).await.is_err() {
        tasks.abort_all(); while tasks.join_next().await.is_some() {}
    }
    app.workers.close(); app.workers.wait().await;
    result
}

#[cfg(test)]
mod tests;
