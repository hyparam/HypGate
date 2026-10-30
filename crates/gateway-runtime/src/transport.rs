//! The provider side of one exchange over the verified codec, on the calling
//! thread with blocking sockets and rustls used directly. No redirects,
//! ambient proxies, pooling, or replay. These are the effects the verified
//! exchange driver asks for, in the order it asks: connect, write, upload,
//! read a status head, download. One deadline covers them all; it is
//! enforced by the socket timeouts the `net::Timed` stream re-arms before
//! every read and write. Nothing here decides what happens next.
use crate::{http1, http_body, http_boundary::PreparedRequest, net::{Cancel, Deadline, Tls},
    transfer::{AuditLog, Direction, TransferError}};
use gateway_core::body_driver::Completed;
use gateway_core::framed_copy::Framed;
use gateway_core::request_context::TransferKey;
use gateway_core::exchange_driver::{ConnectFailure, Failure};
use gateway_core::http1_exchange::ChunkStream;
use gateway_core::http1_framing::Framing;
use gateway_core::http1_head::StatusHead;
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use std::{io::{self, Read, Write}, net::{SocketAddr, TcpStream}, sync::Arc, time::Duration};

// Application-data buffering only; handshake/control traffic and record overhead
// have separate rustls limits. See docs/dependency-resources.md.
const TLS_APPLICATION_BUFFER: usize = 64 * 1024;
// rustls 0.23 rounds this ticket budget to 32 server entries, with eight
// TLS 1.3 tickets and one TLS 1.2 session per server. Not a heap-byte limit.
const TLS_SESSION_CACHE: usize = 256;

mod resolver;

// Effect site: the only provider socket, opened under a permit the verified
// core minted for this request's resolved destination; the addresses come
// from resolving that permit's host, and each connect has the exchange deadline.
#[allow(clippy::disallowed_methods)]
fn open_socket(_permit: &gateway_core::egress::Egress<'_, gateway_core::destination::Parts>, addresses: &[SocketAddr], deadline: &Deadline)
    -> io::Result<TcpStream>
{
    let mut failure = io::Error::from(io::ErrorKind::NotConnected);
    for address in addresses {
        match TcpStream::connect_timeout(address, deadline.remaining()?) {
            Ok(socket) => return Ok(socket),
            Err(error) => failure = error,
        }
    }
    Err(failure)
}

fn timed_out(error: &io::Error) -> bool { matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) }

pub struct HttpsTransport { config: Arc<ClientConfig>, deadline: Duration, resolver: resolver::Resolver }
impl HttpsTransport {
    pub fn new(deadline: Duration) -> io::Result<Self> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots, deadline)
    }
    pub(crate) fn with_roots(roots: RootCertStore, deadline: Duration) -> io::Result<Self> {
        if deadline.is_zero() || deadline > Duration::from_secs(3600) { return Err(io::ErrorKind::InvalidInput.into()); }
        let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        config.resumption = rustls::client::Resumption::in_memory_sessions(TLS_SESSION_CACHE);
        config.enable_early_data = false;
        // Keep optional certificate decompression outside the transport even if
        // another dependency enables additional rustls codec features.
        config.cert_decompressors.clear();
        Ok(Self { config: Arc::new(config), deadline, resolver: resolver::Resolver::new()? })
    }

    pub(crate) fn deadline(&self, connection: Deadline) -> Deadline { connection.cap(self.deadline) }

    /// Resolve, connect, and complete the TLS handshake for the request's
    /// resolved destination, under the caller's shared exchange deadline. The host and
    /// port come from the verified destination parts of the permit's target,
    /// never from the request. `cancel` can end the session from another thread.
    pub(crate) fn connect(&self, prepared: &mut PreparedRequest<'_>, cancel: &Cancel, deadline: Deadline) -> Result<Session, ConnectFailure> {
        let (host, port) = {
            let permit = prepared.egress().ok_or(ConnectFailure::Resolve)?;
            let target = permit.target();
            (std::str::from_utf8(&target.host).map_err(|_| ConnectFailure::Resolve)?.to_owned(), target.port)
        };
        let server = ServerName::try_from(host.clone()).map_err(|_| ConnectFailure::Resolve)?;
        let tcp = {
            let pending = self.resolver.resolve(host, port).map_err(|_| ConnectFailure::Resolve)?;
            let reply = pending.wait(deadline.remaining().map_err(|_| ConnectFailure::Timeout)?)
                .map_err(|e| if timed_out(&e) { ConnectFailure::Timeout } else { ConnectFailure::Resolve })?;
            let addresses = reply.adopt(prepared.stream()).map_err(|_| ConnectFailure::Resolve)?;
            open_socket(prepared.egress().ok_or(ConnectFailure::Resolve)?, addresses.as_slice(), &deadline)
                .map_err(|e| if timed_out(&e) { ConnectFailure::Timeout } else { ConnectFailure::Tcp })?
        };
        // Cancellation shuts this socket down; the blocked operation then fails.
        cancel.watch_socket(&tcp).map_err(|_| ConnectFailure::Tcp)?;
        let mut connection = ClientConnection::new(self.config.clone(), server).map_err(|_| ConnectFailure::Tls)?;
        connection.set_buffer_limit(Some(TLS_APPLICATION_BUFFER));
        let mut tls: Tls = Tls::new(connection, tcp, deadline);
        if tls.handshake().is_err() {
            return Err(if cancel.is_cancelled() { ConnectFailure::Cancelled } else if tls.expired() { ConnectFailure::Timeout } else { ConnectFailure::Tls });
        }
        Ok(Session { tls, leftover: Vec::new(), cancel: cancel.clone() })
    }
}

/// One connected provider session. Every method performs one effect the
/// driver named and reports what happened.
pub(crate) struct Session { tls: Tls, leftover: Vec<u8>, cancel: Cancel }
impl Session {
    /// How the last failed operation should be read: cancellation and the
    /// deadline take precedence over the phase's own fault.
    fn failure(&self) -> Failure {
        if self.cancel.is_cancelled() { Failure::Cancelled } else if self.tls.expired() { Failure::Timeout } else { Failure::Io }
    }
    fn transfer_failure(&self, error: TransferError) -> Failure {
        if self.tls.expired() { Failure::Timeout } else if error == TransferError::Log { Failure::Log } else { self.failure() }
    }
    pub(crate) fn write(&mut self, bytes: &[u8]) -> bool {
        http1::write_fully(&mut self.tls, bytes).and_then(|()| self.tls.flush()).is_ok()
    }
    /// The request body as chunks of `stream`, through the worker's upload role.
    pub(crate) fn upload<R: Read, L: AuditLog>(&mut self, prepared: &mut PreparedRequest<'_>, key: &TransferKey, input: &mut R, log: &mut L,
        http: &http_body::WorkerHttp, stream: ChunkStream) -> Framed
    {
        let mut writer = match http.upload_writer(&mut self.tls) {
            Ok(writer) => writer,
            Err(_) => return Framed::failed(stream, Failure::Io),
        };
        let mut copied = crate::transfer::copy_body_framed(prepared.stream(), key, input, &mut writer, log, stream, Direction::Upload);
        drop(writer);
        if let Some(error) = copied.body_failure() { copied.reject(self.transfer_failure(error.into())); }
        copied
    }
    pub(crate) fn read_status_head(&mut self) -> Result<StatusHead, Failure> {
        let leftover = std::mem::take(&mut self.leftover);
        match http1::read_status_head(&mut self.tls, leftover) {
            Ok((head, rest)) => { self.leftover = rest; Ok(head) }
            Err(_) => Err(self.failure()),
        }
    }
    /// The response body, framed as given, copied to `sink` through the
    /// worker's output role. `Ok` only when the body was complete as framed.
    #[allow(clippy::too_many_arguments)] // Each argument holds a distinct request, reader, writer or audit role.
    pub(crate) fn download_framed<W: Write, L: AuditLog>(&mut self, prepared: &mut PreparedRequest<'_>, key: &TransferKey, log: &mut L,
        http: &http_body::WorkerHttp, framing: Framing, sink: &mut W, stream: ChunkStream) -> Framed
    {
        let leftover = std::mem::take(&mut self.leftover);
        let body = http1::BodyReader::new(&mut self.tls, leftover, framing);
        let Some(mut reader) = http.output(body) else { return Framed::failed(stream, Failure::Io); };
        let mut copied = crate::transfer::copy_body_framed(prepared.stream(), key, &mut reader, sink, log, stream, Direction::Download);
        let complete = reader.body().is_complete();
        drop(reader);
        if let Some(error) = copied.body_failure() {
            let error = TransferError::from(error);
            if matches!(error, TransferError::Write | TransferError::WriteZero | TransferError::Flush) { self.cancel.delivery_failed(); }
            copied.reject(self.transfer_failure(error));
        } else if !complete { copied.reject(self.failure()); }
        copied
    }

    pub(crate) fn download<W: Write, L: AuditLog>(&mut self, prepared: &mut PreparedRequest<'_>, key: &TransferKey, log: &mut L,
        http: &http_body::WorkerHttp, framing: Framing, sink: &mut W) -> Result<Completed, Failure>
    {
        let leftover = std::mem::take(&mut self.leftover);
        let body = http1::BodyReader::new(&mut self.tls, leftover, framing);
        let Some(mut reader) = http.output(body) else { return Err(Failure::Io); };
        let copied = prepared.copy_body(key, &mut reader, sink, log, Direction::Download);
        let complete = reader.body().is_complete();
        drop(reader);
        // Failed delivery authorizes aborting the exchange without asserting
        // that the peer is gone. Publish it before classifying the failure.
        if matches!(copied, Err(TransferError::Write | TransferError::WriteZero | TransferError::Flush)) {
            self.cancel.delivery_failed();
        }
        let copy = copied.map_err(|error| self.transfer_failure(error))?;
        // A body that stopped before its framing said so is a failure, never a clean end.
        if !complete { return Err(self.failure()); }
        Ok(copy)
    }
}

/// Test-only: the exchange composed from the session effects in the order the
/// verified driver takes them, so the transport tests can exercise the
/// provider side without a client connection. Production never calls this;
/// the driver sequences the real exchange.
#[cfg(test)]
pub(crate) mod exchange {
    use super::*;
    use gateway_core::headers::Field;
    use gateway_core::exchange_lifecycle::Fault;
    use gateway_core::http1_exchange::{Upstream, UpstreamStatus, upstream_status};

    pub(crate) trait ResponseSink: Write {
        fn start(&mut self, status: u16, fields: Vec<Field>) -> io::Result<()>;
        fn finish(&mut self) -> io::Result<()> { Ok(()) }
    }
    pub(crate) struct ExchangeStats { pub upload: Completed, pub download: Completed }
    fn fault(failure: Failure, phase: Fault) -> Fault {
        match failure { Failure::Cancelled => Fault::Cancelled, Failure::Timeout => Fault::Timeout, Failure::Log => Fault::Log, Failure::Io => phase }
    }
    impl HttpsTransport {
        pub(crate) fn exchange<R: Read, W: ResponseSink, L: AuditLog>(&self, prepared: &mut PreparedRequest<'_>, input: &mut R, output: &mut W,
            log: &mut L, http: &http_body::WorkerHttp, cancel: &Cancel) -> Result<ExchangeStats, Fault>
        {
            let upstream = prepared.take_upstream().map_err(|_| Fault::Metadata)?;
            let mut session = self.connect(prepared, cancel, Deadline::start(self.deadline).map_err(|_| Fault::Timeout)?).map_err(|failure| match failure {
                ConnectFailure::Resolve | ConnectFailure::Tcp => Fault::Connect, ConnectFailure::Tls => Fault::Tls,
                ConnectFailure::Timeout => Fault::Timeout, ConnectFailure::Cancelled => Fault::Cancelled })?;
            let mut machine = Upstream::new();
            let (path, fields, key) = upstream.into_dispatch();
            let (head, stream) = machine.request(&path, fields).ok_or(Fault::Metadata)?;
            if !session.write(&head) { return Err(fault(session.failure(), Fault::Http)); }
            let (uploaded, mut stream) = session.upload(prepared, &key, input, log, http, stream).into_parts();
            let upload = uploaded.map_err(|failure| fault(failure, Fault::Upload))?;
            let last = stream.end();
            if !session.write(&last) { return Err(fault(session.failure(), Fault::Upload)); }
            machine.finish(stream);
            let (status, fields, framing) = loop {
                let head = session.read_status_head().map_err(|failure| fault(failure, Fault::Http))?;
                match upstream_status(head.status, &head.fields) {
                    UpstreamStatus::Interim => {}
                    UpstreamStatus::Refused => return Err(Fault::Metadata),
                    UpstreamStatus::Bodiless => break (head.status, head.fields, Framing::Length(0)),
                    UpstreamStatus::Framed(framing) => break (head.status, head.fields, framing),
                }
            };
            let fields = gateway_core::headers::forward_response(&fields).map_err(|_| Fault::Metadata)?;
            match prepared.audit_response_head(log, status) {
                Ok(()) => {},
                Err(TransferError::Log) if !prepared.stream().strict() => {},
                Err(TransferError::Log) => return Err(Fault::Log),
                Err(_) => return Err(Fault::Metadata),
            }
            output.start(status, fields).map_err(|_| Fault::Client)?;
            let download = session.download(prepared, &key, log, http, framing, output).map_err(|failure| fault(failure, Fault::Download))?;
            output.finish().map_err(|_| Fault::Client)?;
            Ok(ExchangeStats { upload, download })
        }
    }
}

#[cfg(test)]
mod tests;
