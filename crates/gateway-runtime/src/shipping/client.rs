//! One HTTPS request at a time to the configured HypAware server, over the
//! verified codec. Blocking DNS and an inline handshake on the shipper's own
//! thread; no redirects, proxies, pooling, or retries here. Response bodies
//! are capped.
use super::config::ShippingServer;
use crate::http1;
use gateway_core::egress::Egress;
use gateway_core::headers::Field;
use gateway_core::http1_framing::{Framing, framing};
use gateway_core::http1_write::{wire_ok, write_request_head};
use std::{io, net::ToSocketAddrs, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, rustls::{ClientConfig, RootCertStore, pki_types::ServerName}};

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

pub struct Client { connector: TlsConnector, server: ShippingServer, host: String, deadline: Duration }

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
        let server = server.clone();
        let host = server.host().to_owned();
        ServerName::try_from(host.clone()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        config.enable_early_data = false;
        config.cert_decompressors.clear();
        Ok(Self { connector: TlsConnector::from(Arc::new(config)), server, host, deadline })
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
        let mut tls = self.connector.connect(server, tcp).await.map_err(|_| ClientError::Tls)?;
        let mut fields = vec![
            http1::field(b"host", self.server.authority().as_bytes().to_vec()),
            http1::field(b"connection", b"close".to_vec()),
            http1::field(b"content-length", body.len().to_string().into_bytes()),
        ];
        if let Some(token) = bearer {
            fields.push(Field { name: b"authorization".to_vec(), value: format!("Bearer {token}").into_bytes(), sensitive: true });
        }
        for (name, value) in headers { fields.push(Field { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec(), sensitive: false }); }
        if !wire_ok(&fields) || !path.starts_with('/') || path.bytes().any(|b| !(33..=126).contains(&b)) { return Err(ClientError::Http); }
        let mut head = Vec::new();
        write_request_head(method.as_bytes(), path.as_bytes(), &fields, &mut head);
        head.extend_from_slice(&body);
        tls.write_all(&head).await.map_err(|_| ClientError::Http)?;
        let (status_head, leftover) = http1::read_status_head(&mut tls, Vec::new()).await.map_err(|_| ClientError::Http)?;
        let retry_after = status_head.fields.iter().find(|f| f.name == b"retry-after")
            .and_then(|f| std::str::from_utf8(&f.value).ok()).and_then(|v| v.trim().parse().ok());
        let reply_framing = match status_head.status {
            204 | 304 => Framing::Length(0),
            _ => framing(&status_head.fields, false).map_err(|_| ClientError::Http)?,
        };
        if let Framing::Length(n) = reply_framing { if n > MAX_REPLY_BYTES as u64 { return Err(ClientError::Http); } }
        let mut reader = http1::BodyReader::new(&mut tls, leftover, reply_framing);
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let n = reader.read(&mut buffer).await.map_err(|_| ClientError::Http)?;
            if n == 0 { break; }
            if bytes.len().checked_add(n).is_none_or(|total| total > MAX_REPLY_BYTES) { return Err(ClientError::Http); }
            bytes.extend_from_slice(buffer.get(..n).ok_or(ClientError::Http)?);
        }
        Ok(Reply { status: status_head.status, retry_after, body: bytes })
    }
}
