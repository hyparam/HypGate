//! One HTTPS HTTP/1.1 exchange. No redirects, ambient proxies, pooling, or replay.
use crate::{http_body, http_boundary::{PreparedRequest, prepare_response_parts}, transfer::{AuditLog, Direction, TransferStats}};
use http::{HeaderMap, StatusCode};
use hyper_util::rt::TokioIo;
use std::{future::Future, io, sync::Arc, time::Duration};
use tokio::{io::{AsyncRead, AsyncWrite, AsyncWriteExt}, net::TcpStream};
use tokio_rustls::{TlsConnector, rustls::{ClientConfig, RootCertStore, pki_types::ServerName}};

pub trait ResponseSink: AsyncWrite + Unpin {
    /// Called once before response body bytes. This must preserve status and the
    /// supplied filtered headers. A body error afterward must abort HTTP framing.
    fn start(&mut self, status: StatusCode, headers: HeaderMap) -> impl Future<Output = io::Result<()>> + Send;
    /// Complete a successful body and drain any sink-owned application queue.
    fn finish(&mut self) -> impl Future<Output = io::Result<()>> + Send { async { Ok(()) } }
}
#[derive(Debug, PartialEq, Eq)]
pub enum TransportError { Timeout, Connect, Tls, Http, Metadata, Upload, Download, Client }
pub struct ExchangeStats { pub upload: TransferStats, pub download: TransferStats }

// Application-data buffering only; handshake/control traffic and record overhead
// have separate rustls limits. See docs/dependency-resources.md.
const TLS_APPLICATION_BUFFER: usize = 64 * 1024;
// rustls 0.23 rounds this ticket budget to 32 server entries, with eight
// TLS 1.3 tickets and one TLS 1.2 session per server. Not a heap-byte limit.
const TLS_SESSION_CACHE: usize = 256;

mod resolver;
mod tls_io;
mod handshake;

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

    /// Consumes authority and retains its lease through all response processing.
    /// The HTTP connection future is polled inline, never spawned or transparently retried.
    /// TLS handshakes run on a separately credited, bounded dedicated pool.
    pub(crate) async fn exchange<R: AsyncRead + Unpin, W: ResponseSink, L: AuditLog>(
        &self, mut prepared: PreparedRequest<'_>, input: &mut R, output: &mut W, log: &mut L,
        http: &http_body::WorkerHttp,
    ) -> Result<ExchangeStats, TransportError> {
        // The owner lives outside the timed future, which borrows it and owns
        // connection/body futures. Their cleanup precedes returning its credit.
        tokio::time::timeout(self.deadline, self.run(&mut prepared, input, output, log, http))
            .await.map_err(|_| TransportError::Timeout)?
    }

    async fn run<R: AsyncRead + Unpin, W: ResponseSink, L: AuditLog>(
        &self, prepared: &mut PreparedRequest<'_>, input: &mut R, output: &mut W, log: &mut L,
        http: &http_body::WorkerHttp,
    ) -> Result<ExchangeStats, TransportError> {
        let upstream = prepared.take_upstream().map_err(|_| TransportError::Metadata)?;
        let host = prepared.destination().host().ok_or(TransportError::Metadata)?
            .trim_start_matches('[').trim_end_matches(']').to_owned();
        let port = prepared.destination().port_u16().unwrap_or(443);
        let server = ServerName::try_from(host.clone()).map_err(|_| TransportError::Metadata)?;
        let tcp = {
            let addresses = self.resolver.resolve(host, port).await.map_err(|_| TransportError::Connect)?
                .adopt(prepared.stream()).map_err(|_| TransportError::Connect)?;
            TcpStream::connect(addresses.as_slice()).await.map_err(|_| TransportError::Connect)?
        };
        let connector = self.connector.clone();
        let tls = self.handshakes.run(async move {
            connector.connect_with(server, tcp, |connection| {
                connection.set_buffer_limit(Some(TLS_APPLICATION_BUFFER));
            }).await
        }).await.map_err(|_| TransportError::Tls)?
            .adopt(prepared.stream()).map_err(|_| TransportError::Tls)?;
        // Explicit queue strategy keeps body-buffer accounting stable across TLS adapters.
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .writev(true).max_headers(crate::http_boundary::MAX_HEADER_VALUES)
            .max_header_size(crate::http_boundary::MAX_HEADER_BYTES)
            .max_buf_size(http_body::MAX_INPUT_FRAME).handshake(TokioIo::new(crate::http_io::ReadLimited::new(tls_io::DrainBeforeWrite(tls)))).await.map_err(|_| TransportError::Http)?;
        let (mut body_writer, body) = http.upload(16 * 1024).ok_or(TransportError::Http)?;
        // Direct HTTP/1 connection uses origin-form; authority was already bound
        // to the TCP/TLS destination and the trusted Host header.
        let request = upstream.map(|()| body);
        let operation = async {
            let upload = async {
                let stats = prepared.copy_body(input, &mut body_writer, log, Direction::Upload)
                    .await.map_err(|_| TransportError::Upload)?;
                body_writer.shutdown().await.map_err(|_| TransportError::Upload)?;
                Ok::<_, TransportError>(stats)
            };
            let response = async { sender.send_request(request).await.map_err(|_| TransportError::Http) };
            let (upload, response) = tokio::try_join!(upload, response)?;
            let (parts, body) = response.into_parts();
            let (status, headers) = prepare_response_parts(parts).map_err(|_| TransportError::Metadata)?;
            output.start(status, headers).await.map_err(|_| TransportError::Client)?;
            let mut reader = http.output(body).ok_or(TransportError::Http)?;
            let download = prepared.copy_body(&mut reader, output, log, Direction::Download)
                .await.map_err(|_| TransportError::Download)?;
            output.finish().await.map_err(|_| TransportError::Client)?;
            Ok(ExchangeStats { upload, download })
        };
        tokio::pin!(operation, connection);
        tokio::select! {
            result = &mut operation => result,
            result = &mut connection => {
                result.map_err(|_| TransportError::Http)?;
                // A clean connection EOF may race with the final buffered body.
                operation.await
            }
        }
    }
}

#[cfg(test)]
mod tests;
