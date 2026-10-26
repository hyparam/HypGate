//! One HTTPS HTTP/1.1 exchange over the verified codec. No redirects, ambient
//! proxies, pooling, or replay.
use crate::{http1, http_body, http_boundary::{PreparedRequest, prepare_response_head}, transfer::{AuditLog, Direction, TransferError}};
use gateway_core::headers::Field;
use gateway_core::{body_copy::BodyCopy, exchange_lifecycle::Fault};
use gateway_core::http1_framing::{Framing, framing};
use gateway_core::http1_write::{wire_ok, write_request_head};
use std::{future::Future, io, sync::Arc, time::Duration};
use tokio::{io::{AsyncRead, AsyncWrite, AsyncWriteExt}, net::TcpStream};
use tokio_rustls::{TlsConnector, rustls::{ClientConfig, RootCertStore, pki_types::ServerName}};

pub trait ResponseSink: AsyncWrite + Unpin {
    /// Called once before response body bytes. This must preserve status and the
    /// supplied filtered fields. A body error afterward must abort HTTP framing.
    fn start(&mut self, status: u16, fields: Vec<Field>) -> impl Future<Output = io::Result<()>> + Send;
    /// Complete a successful body and drain any sink-owned application queue.
    fn finish(&mut self) -> impl Future<Output = io::Result<()>> + Send { async { Ok(()) } }
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
mod tls_io;
mod handshake;

// Effect site: the only provider socket. It is opened under a permit the
// verified core minted for this request's resolved destination; the
// addresses come from resolving that permit's host.
#[allow(clippy::disallowed_methods)]
async fn open_socket(_permit: &gateway_core::egress::Egress<'_, gateway_core::destination::Parts>, addresses: &[std::net::SocketAddr]) -> io::Result<TcpStream> {
    TcpStream::connect(addresses).await
}

pub struct HttpsTransport { connector: TlsConnector, deadline: Duration, resolver: resolver::Resolver, handshakes: handshake::Pool }
impl HttpsTransport {
    pub fn new(deadline: Duration) -> io::Result<Self> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots, deadline)
    }
    pub(crate) fn with_roots(roots: RootCertStore, deadline: Duration) -> io::Result<Self> {
        if deadline.is_zero() || deadline > Duration::from_secs(3600) { return Err(io::ErrorKind::InvalidInput.into()); }
        let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        config.resumption = tokio_rustls::rustls::client::Resumption::in_memory_sessions(TLS_SESSION_CACHE);
        config.enable_early_data = false;
        // Keep optional certificate decompression outside the transport even if
        // another dependency enables additional rustls codec features.
        config.cert_decompressors.clear();
        Ok(Self { connector: TlsConnector::from(Arc::new(config)), deadline, resolver: resolver::Resolver::new()?, handshakes: handshake::Pool::new()? })
    }

    /// Borrows the authority for the whole exchange; the caller keeps its lease
    /// afterwards to record the completion and then release the slot.
    /// The connection is driven inline, never spawned or transparently retried.
    /// TLS handshakes run on a separately credited, bounded dedicated pool.
    pub(crate) async fn exchange<R: AsyncRead + Unpin, W: ResponseSink, L: AuditLog>(
        &self, prepared: &mut PreparedRequest<'_>, input: &mut R, output: &mut W, log: &mut L,
        http: &http_body::WorkerHttp,
    ) -> Result<ExchangeStats, TransportError> {
        // The owner lives outside the timed future, which borrows it and owns
        // the connection and body futures. Their cleanup precedes returning its credit.
        tokio::time::timeout(self.deadline, self.run(prepared, input, output, log, http))
            .await.map_err(|_| TransportError::Timeout)?
    }

    async fn run<R: AsyncRead + Unpin, W: ResponseSink, L: AuditLog>(
        &self, prepared: &mut PreparedRequest<'_>, input: &mut R, output: &mut W, log: &mut L,
        http: &http_body::WorkerHttp,
    ) -> Result<ExchangeStats, TransportError> {
        let upstream = prepared.take_upstream().map_err(|_| TransportError::Metadata)?;
        // The host and port come from the verified destination parts of the
        // permit's target, never from the request.
        let (host, port) = {
            let permit = prepared.egress();
            let target = permit.target();
            (std::str::from_utf8(&target.host).map_err(|_| TransportError::Metadata)?.to_owned(), target.port)
        };
        let server = ServerName::try_from(host.clone()).map_err(|_| TransportError::Metadata)?;
        let tcp = {
            let addresses = self.resolver.resolve(host, port).await.map_err(|_| TransportError::Connect)?
                .adopt(prepared.stream()).map_err(|_| TransportError::Connect)?;
            open_socket(&prepared.egress(), addresses.as_slice()).await.map_err(|_| TransportError::Connect)?
        };
        let connector = self.connector.clone();
        let tls = self.handshakes.run(async move {
            connector.connect_with(server, tcp, |connection| {
                connection.set_buffer_limit(Some(TLS_APPLICATION_BUFFER));
            }).await
        }).await.map_err(|_| TransportError::Tls)?
            .adopt(prepared.stream()).map_err(|_| TransportError::Tls)?;
        let mut tls = crate::http_io::ReadLimited::new(tls_io::DrainBeforeWrite(tls));

        // The head: the verified projection's fields plus the framing this
        // transport generates from the body stream, written by the verified
        // writer. Nothing in the head came from the client unfiltered.
        let mut fields = upstream.fields;
        fields.push(http1::field(b"transfer-encoding", b"chunked".to_vec()));
        fields.push(http1::field(b"connection", b"close".to_vec()));
        if !wire_ok(&fields) { return Err(TransportError::Metadata); }
        let mut head = Vec::new();
        write_request_head(b"POST", &upstream.path, &fields, &mut head);
        tls.write_all(&head).await.map_err(|_| TransportError::Http)?;

        // Upload: the body copy writes chunks straight to the connection.
        let mut body_writer = http.upload_writer(http1::ChunkedWriter::new(&mut tls)).ok_or(TransportError::Http)?;
        let upload = prepared.copy_body(input, &mut body_writer, log, Direction::Upload)
            .await.map_err(|error| body_error(error, TransportError::Upload))?;
        body_writer.shutdown().await.map_err(|_| TransportError::Upload)?;
        drop(body_writer);

        // Response head, then the filtered fields and the framing it declares.
        let (status_head, leftover) = http1::read_status_head(&mut tls, Vec::new()).await.map_err(|_| TransportError::Http)?;
        let response_framing = match status_head.status {
            204 | 304 => Framing::Length(0),
            _ => framing(&status_head.fields, false).map_err(|_| TransportError::Metadata)?,
        };
        let (status, fields) = prepare_response_head(status_head).map_err(|_| TransportError::Metadata)?;
        // Kind 3 before the head reaches the client. Strict mode stops here
        // on a failed append; availability mode continues with a gap.
        match prepared.audit_response_head(log, status).await {
            Ok(()) => {},
            Err(TransferError::Log) if !prepared.stream().strict() => {},
            Err(TransferError::Log) => return Err(TransportError::Log),
            Err(_) => return Err(TransportError::Metadata),
        }
        output.start(status, fields).await.map_err(|_| TransportError::Client)?;
        let body = http1::BodyReader::new(&mut tls, leftover, response_framing);
        let mut reader = http.output(body).ok_or(TransportError::Http)?;
        let download = prepared.copy_body(&mut reader, output, log, Direction::Download)
            .await.map_err(|error| body_error(error, TransportError::Download))?;
        // A body that stopped before its framing said so is a failure, never a clean end.
        if !reader.body().is_complete() { return Err(TransportError::Download); }
        drop(reader);
        output.finish().await.map_err(|_| TransportError::Client)?;
        Ok(ExchangeStats { upload, download })
    }
}

#[cfg(test)]
mod tests;
