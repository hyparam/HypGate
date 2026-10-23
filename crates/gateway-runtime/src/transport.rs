//! One HTTPS HTTP/1.1 exchange. No redirects, ambient proxies, pooling, or replay.
use crate::{http_body, http_boundary::{PreparedRequest, response_headers}, transfer::{self, AuditLog, Direction, TransferStats}};
use http::{HeaderMap, StatusCode};
use hyper_util::rt::TokioIo;
use std::{future::Future, io, sync::Arc, time::Duration};
use tokio::{io::{AsyncRead, AsyncWrite, AsyncWriteExt}, net::TcpStream};
use tokio_rustls::{TlsConnector, rustls::{ClientConfig, RootCertStore, pki_types::ServerName}};

pub trait ResponseSink: AsyncWrite + Unpin {
    /// Called once before response body bytes. This must preserve status and the
    /// supplied filtered headers. A body error afterward must abort HTTP framing.
    fn start(&mut self, status: StatusCode, headers: HeaderMap) -> impl Future<Output = io::Result<()>>;
}
#[derive(Debug, PartialEq, Eq)]
pub enum TransportError { Timeout, Connect, Tls, Http, Metadata, Upload, Download, Client }
pub struct ExchangeStats { pub upload: TransferStats, pub download: TransferStats }

pub struct HttpsTransport { connector: TlsConnector, deadline: Duration }
impl HttpsTransport {
    pub fn new(deadline: Duration) -> io::Result<Self> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(roots, deadline)
    }
    fn with_roots(roots: RootCertStore, deadline: Duration) -> io::Result<Self> {
        if deadline.is_zero() || deadline > Duration::from_secs(3600) { return Err(io::ErrorKind::InvalidInput.into()); }
        let config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        Ok(Self { connector: TlsConnector::from(Arc::new(config)), deadline })
    }

    /// Consumes authority and retains its lease through all response processing.
    /// The connection future is polled inline, never spawned or transparently retried.
    pub async fn exchange<R: AsyncRead + Unpin, W: ResponseSink, L: AuditLog>(
        &self, prepared: PreparedRequest<'_>, input: &mut R, output: &mut W, log: &mut L,
    ) -> Result<ExchangeStats, TransportError> {
        tokio::time::timeout(self.deadline, self.run(prepared, input, output, log))
            .await.map_err(|_| TransportError::Timeout)?
    }

    async fn run<R: AsyncRead + Unpin, W: ResponseSink, L: AuditLog>(
        &self, mut prepared: PreparedRequest<'_>, input: &mut R, output: &mut W, log: &mut L,
    ) -> Result<ExchangeStats, TransportError> {
        let host = prepared.destination().host().ok_or(TransportError::Metadata)?
            .trim_start_matches('[').trim_end_matches(']').to_owned();
        let port = prepared.destination().port_u16().unwrap_or(443);
        let server = ServerName::try_from(host.clone()).map_err(|_| TransportError::Metadata)?;
        let tcp = TcpStream::connect((host.as_str(), port)).await.map_err(|_| TransportError::Connect)?;
        let tls = self.connector.connect(server, tcp).await.map_err(|_| TransportError::Tls)?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(32 * 1024).handshake(TokioIo::new(tls)).await.map_err(|_| TransportError::Http)?;
        let (mut body_writer, body) = http_body::channel(16 * 1024);
        // Direct HTTP/1 connection uses origin-form; authority was already bound
        // to the TCP/TLS destination and the trusted Host header.
        let path = prepared.upstream.uri().path_and_query().ok_or(TransportError::Metadata)?.clone();
        *prepared.upstream.uri_mut() = http::Uri::builder().path_and_query(path).build().map_err(|_| TransportError::Metadata)?;
        let request = prepared.upstream.map(|()| body);
        let operation = async {
            let upload = async {
                let stats = transfer::copy_body(prepared.routed.stream(), input, &mut body_writer, log, Direction::Upload)
                    .await.map_err(|_| TransportError::Upload)?;
                body_writer.shutdown().await.map_err(|_| TransportError::Upload)?;
                Ok::<_, TransportError>(stats)
            };
            let response = async { sender.send_request(request).await.map_err(|_| TransportError::Http) };
            let (upload, response) = tokio::try_join!(upload, response)?;
            let (parts, body) = response.into_parts();
            let headers = response_headers(&parts.headers).map_err(|_| TransportError::Metadata)?;
            output.start(parts.status, headers).await.map_err(|_| TransportError::Client)?;
            let download = transfer::copy_body(prepared.routed.stream(), &mut http_body::Reader::new(body), output, log, Direction::Download)
                .await.map_err(|_| TransportError::Download)?;
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
