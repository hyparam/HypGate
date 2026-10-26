//! One HTTPS HTTP/1.1 exchange over the verified codec, on the calling thread
//! with blocking sockets and rustls used directly. No redirects, ambient
//! proxies, pooling, or replay. One deadline covers resolution, connect,
//! handshake, upload, and download; it is enforced by the socket timeouts the
//! `net::Timed` stream re-arms before every read and write.
use crate::{http1, http_body, http_boundary::{PreparedRequest, prepare_response_head}, net::{Cancel, Deadline, Timed},
    transfer::{AuditLog, Direction, TransferError}};
use gateway_core::headers::Field;
use gateway_core::{body_copy::BodyCopy, exchange_lifecycle::Fault};
use gateway_core::http1_exchange::{Upstream, UpstreamStatus, upstream_status};
use gateway_core::http1_framing::Framing;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use std::{io::{self, Read, Write}, net::{SocketAddr, TcpStream}, sync::Arc, time::Duration};

pub trait ResponseSink: Write {
    /// Called once before response body bytes. This must preserve status and the
    /// supplied filtered fields. A body error afterward must abort HTTP framing.
    fn start(&mut self, status: u16, fields: Vec<Field>) -> io::Result<()>;
    /// Complete a successful body.
    fn finish(&mut self) -> io::Result<()> { Ok(()) }
}
impl<W: ResponseSink> ResponseSink for http_body::Charged<W> {
    fn start(&mut self, status: u16, fields: Vec<Field>) -> io::Result<()> { self.get_mut().start(status, fields) }
    fn finish(&mut self) -> io::Result<()> { self.get_mut().finish() }
}

/// A failed exchange names the verified lifecycle's fault directly, so the
/// completion record's outcome code is a checked function of what happened
/// with no mapping in between. `Log` is a strict-mode refusal: a body or
/// response-head append failed, so no further bytes were forwarded.
/// Availability mode never returns it.
pub type TransportError = Fault;

// A strict-mode logging refusal during a body copy keeps its own code; other
// transfer failures are attributed to the direction being copied.
fn body_error(error: TransferError, direction: TransportError) -> TransportError {
    if error == TransferError::Log { TransportError::Log } else { direction }
}

/// The two finished body-copy machines, with their proved byte counts.
pub struct ExchangeStats { pub upload: BodyCopy, pub download: BodyCopy }

// Application-data buffering only; handshake/control traffic and record overhead
// have separate rustls limits. See docs/dependency-resources.md.
const TLS_APPLICATION_BUFFER: usize = 64 * 1024;
// rustls 0.23 rounds this ticket budget to 32 server entries, with eight
// TLS 1.3 tickets and one TLS 1.2 session per server. Not a heap-byte limit.
const TLS_SESSION_CACHE: usize = 256;

mod resolver;

type Tls = Timed<StreamOwned<ClientConnection, TcpStream>>;

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

/// The deadline if the stream saw it pass, else the phase's own fault.
fn fault_of(tls: &Tls, fallback: Fault) -> Fault { if tls.expired() { Fault::Timeout } else { fallback } }
fn timeout_or(error: &io::Error, fallback: Fault) -> Fault {
    if matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) { Fault::Timeout } else { fallback }
}

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

    /// Borrows the authority for the whole exchange; the caller keeps its lease
    /// afterwards to record the completion and then release the slot. The
    /// exchange runs on the calling thread, never spawned or transparently
    /// retried. `cancel` ends it early from another thread: its sockets are
    /// shut down and the failure is reported as `Fault::Cancelled`.
    pub(crate) fn exchange<R: Read, W: ResponseSink, L: AuditLog>(
        &self, prepared: &mut PreparedRequest<'_>, input: &mut R, output: &mut W, log: &mut L,
        http: &http_body::WorkerHttp, cancel: &Cancel,
    ) -> Result<ExchangeStats, TransportError> {
        let deadline = Deadline::start(self.deadline).map_err(|_| Fault::Timeout)?;
        self.run(prepared, input, output, log, http, cancel, deadline)
            .map_err(|fault| if cancel.is_cancelled() { Fault::Cancelled } else { fault })
    }

    #[allow(clippy::too_many_arguments)]
    fn run<R: Read, W: ResponseSink, L: AuditLog>(
        &self, prepared: &mut PreparedRequest<'_>, input: &mut R, output: &mut W, log: &mut L,
        http: &http_body::WorkerHttp, cancel: &Cancel, deadline: Deadline,
    ) -> Result<ExchangeStats, Fault> {
        let upstream = prepared.take_upstream().map_err(|_| Fault::Metadata)?;
        // The host and port come from the verified destination parts of the
        // permit's target, never from the request.
        let (host, port) = {
            let permit = prepared.egress();
            let target = permit.target();
            (std::str::from_utf8(&target.host).map_err(|_| Fault::Metadata)?.to_owned(), target.port)
        };
        let server = ServerName::try_from(host.clone()).map_err(|_| Fault::Metadata)?;
        let tcp = {
            let pending = self.resolver.resolve(host, port).map_err(|_| Fault::Connect)?;
            let reply = pending.wait(deadline.remaining().map_err(|_| Fault::Timeout)?).map_err(|e| timeout_or(&e, Fault::Connect))?;
            let addresses = reply.adopt(prepared.stream()).map_err(|_| Fault::Connect)?;
            open_socket(&prepared.egress(), addresses.as_slice(), &deadline).map_err(|e| timeout_or(&e, Fault::Connect))?
        };
        // Cancellation shuts this socket down; the blocked operation then fails.
        cancel.watch_socket(&tcp).map_err(|_| Fault::Connect)?;
        let mut connection = ClientConnection::new(self.config.clone(), server).map_err(|_| Fault::Tls)?;
        connection.set_buffer_limit(Some(TLS_APPLICATION_BUFFER));
        let mut tls: Tls = Timed::new(StreamOwned::new(connection, tcp), deadline);
        let shaken = tls.handshake();
        shaken.map_err(|_| fault_of(&tls, Fault::Tls))?;

        // The head and its framing are the verified machine's: the projection's
        // fields plus chunked framing and `Connection: close`. Nothing in the
        // head came from the client unfiltered.
        let mut machine = Upstream::new();
        let (head, stream) = machine.request(&upstream.path, upstream.fields).ok_or(Fault::Metadata)?;
        let written = http1::write_fully(&mut tls, &head);
        written.map_err(|_| fault_of(&tls, Fault::Http))?;

        // Upload: the body copy writes chunks straight to the connection.
        let upload = {
            let mut body_writer = http.upload_writer(http1::ChunkedWriter::new(&mut tls, stream)).ok_or(Fault::Http)?;
            let copied = prepared.copy_body(input, &mut body_writer, log, Direction::Upload);
            let finished = copied.and_then(|copy| body_writer.get_mut().finish().map(|()| copy).map_err(|_| TransferError::Write));
            let (_, stream) = body_writer.into_inner().into_parts();
            machine.finish(stream);
            finished
        };
        let upload = upload.map_err(|error| body_error(error, fault_of(&tls, Fault::Upload)))?;

        // Response heads until a final one; the machine classifies each.
        let mut leftover = Vec::new();
        let (status_head, leftover, response_framing) = loop {
            let read = http1::read_status_head(&mut tls, leftover);
            let (status_head, rest) = read.map_err(|_| fault_of(&tls, Fault::Http))?;
            match upstream_status(status_head.status, &status_head.fields) {
                UpstreamStatus::Interim => { leftover = rest; }
                UpstreamStatus::Refused => return Err(Fault::Metadata),
                UpstreamStatus::Bodiless => break (status_head, rest, Framing::Length(0)),
                UpstreamStatus::Framed(framing) => break (status_head, rest, framing),
            }
        };
        let (status, fields) = prepare_response_head(status_head).map_err(|_| Fault::Metadata)?;
        // Kind 3 before the head reaches the client. Strict mode stops here
        // on a failed append; availability mode continues with a gap.
        match prepared.audit_response_head(log, status) {
            Ok(()) => {},
            Err(TransferError::Log) if !prepared.stream().strict() => {},
            Err(TransferError::Log) => return Err(Fault::Log),
            Err(_) => return Err(Fault::Metadata),
        }
        output.start(status, fields).map_err(|_| Fault::Client)?;
        let (copied, complete) = {
            let body = http1::BodyReader::new(&mut tls, leftover, response_framing);
            let mut reader = http.output(body).ok_or(Fault::Http)?;
            let copied = prepared.copy_body(&mut reader, output, log, Direction::Download);
            (copied, reader.body().is_complete())
        };
        let download = copied.map_err(|error| body_error(error, fault_of(&tls, Fault::Download)))?;
        // A body that stopped before its framing said so is a failure, never a clean end.
        if !complete { return Err(fault_of(&tls, Fault::Download)); }
        output.finish().map_err(|_| Fault::Client)?;
        Ok(ExchangeStats { upload, download })
    }
}

#[cfg(test)]
mod tests;
