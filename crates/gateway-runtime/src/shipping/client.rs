//! One HTTPS request at a time to the configured HypAware server. Blocking DNS
//! and an inline handshake on the shipper's own thread; no redirects, proxies,
//! pooling, or retries here. Response bodies are capped.
use super::config::ShippingServer;
use gateway_core::egress::Egress;
use http::Request;
use http_body_util::{BodyExt, Full, Limited};
use hyper_util::rt::TokioIo;
use std::{io, net::ToSocketAddrs, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls::{ClientConfig, RootCertStore, pki_types::ServerName}};
use bytes::Bytes;

pub const MAX_REPLY_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ClientError { Resolve, Connect, Tls, Http, Timeout }

#[derive(Debug)]
pub struct Reply { pub status: u16, pub retry_after: Option<u64>, pub body: Vec<u8> }
impl Reply {
    /// The `error` code of a `{"error":"..."}` body, if any.
    pub fn error_code(&self) -> Option<String> {
        serde_json::from_slice::<serde_json::Value>(&self.body).ok()?.get("error")?.as_str().map(str::to_owned)
    }
}

pub struct Client { connector: TlsConnector, server: ShippingServer, host: String, authority: String, deadline: Duration }

// Effect site: the only cloud socket. Resolution and connection happen under a
// permit minted from the configured shipping server and nothing else.
#[allow(clippy::disallowed_methods)]
async fn open_socket(permit: &Egress<'_, ShippingServer>) -> Result<TcpStream, ClientError> {
    let target = permit.target();
    let addresses: Vec<_> = (target.host(), target.port()).to_socket_addrs().map_err(|_| ClientError::Resolve)?.take(16).collect();
    if addresses.is_empty() { return Err(ClientError::Resolve); }
    TcpStream::connect(addresses.as_slice()).await.map_err(|_| ClientError::Connect)
}

impl Client {
    pub fn new(server: &ShippingServer, deadline: Duration) -> io::Result<Self> {
        Self::with_roots(RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()), server, deadline)
    }
    pub fn with_roots(roots: RootCertStore, server: &ShippingServer, deadline: Duration) -> io::Result<Self> {
        if deadline.is_zero() || deadline > Duration::from_secs(3600) { return Err(io::ErrorKind::InvalidInput.into()); }
        let (server, uri) = (server.clone(), server.uri());
        let host = server.host().to_owned();
        ServerName::try_from(host.clone()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        config.enable_early_data = false;
        config.cert_decompressors.clear();
        let authority = uri.authority().ok_or(io::ErrorKind::InvalidInput)?.as_str().to_owned();
        Ok(Self { connector: TlsConnector::from(Arc::new(config)), server, host, authority, deadline })
    }

    /// `bearer` becomes an `Authorization` header; `headers` are added verbatim.
    pub async fn request(&self, method: &str, path: &str, bearer: Option<&str>, headers: &[(&str, String)], body: Vec<u8>)
        -> Result<Reply, ClientError>
    {
        tokio::time::timeout(self.deadline, self.run(method, path, bearer, headers, body)).await.map_err(|_| ClientError::Timeout)?
    }

    async fn run(&self, method: &str, path: &str, bearer: Option<&str>, headers: &[(&str, String)], body: Vec<u8>)
        -> Result<Reply, ClientError>
    {
        let permit = Egress::cloud(&self.server);
        let tcp = open_socket(&permit).await?;
        let server = ServerName::try_from(self.host.clone()).map_err(|_| ClientError::Tls)?;
        let tls = self.connector.connect(server, tcp).await.map_err(|_| ClientError::Tls)?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_headers(crate::http_boundary::MAX_HEADER_VALUES).max_header_size(crate::http_boundary::MAX_HEADER_BYTES)
            .handshake(TokioIo::new(tls)).await.map_err(|_| ClientError::Http)?;
        let mut builder = Request::builder().method(method).uri(path)
            .header("host", &self.authority).header("connection", "close")
            .header("content-length", body.len().to_string());
        if let Some(token) = bearer {
            let mut value = http::HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| ClientError::Http)?;
            value.set_sensitive(true);
            builder = builder.header("authorization", value);
        }
        for (name, value) in headers { builder = builder.header(*name, value); }
        let request = builder.body(Full::new(Bytes::from(body))).map_err(|_| ClientError::Http)?;
        let operation = async {
            let response = sender.send_request(request).await.map_err(|_| ClientError::Http)?;
            let (parts, body) = response.into_parts();
            let retry_after = parts.headers.get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.trim().parse().ok());
            let bytes = Limited::new(body, MAX_REPLY_BYTES).collect().await.map_err(|_| ClientError::Http)?.to_bytes();
            Ok(Reply { status: parts.status.as_u16(), retry_after, body: bytes.to_vec() })
        };
        tokio::pin!(operation, connection);
        tokio::select! {
            result = &mut operation => result,
            result = &mut connection => { result.map_err(|_| ClientError::Http)?; operation.await }
        }
    }
}
