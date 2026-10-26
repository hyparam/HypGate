//! One HTTPS request at a time to the configured HypAware server, over the
//! verified codec, on the shipper's own thread: blocking sockets and rustls
//! used directly. No redirects, proxies, pooling, or retries here. One
//! deadline covers the connect, the handshake, the request, and the reply
//! (`net::Timed`), so a peer that trickles bytes cannot outlast it. Name
//! resolution is blocking and outside the deadline. Response bodies are capped.
use super::config::ShippingServer;
use crate::http1::{self, BodyReader, read_status_head};
use gateway_core::egress::Egress;
use gateway_core::headers::Field;
use gateway_core::http1_exchange::{UpstreamStatus, upstream_status};
use gateway_core::http1_framing::Framing;
use gateway_core::http1_write::{wire_ok, write_request_head};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use crate::net::{Deadline, Timed};
use std::{io::{self, Read, Write}, net::{TcpStream, ToSocketAddrs}, sync::Arc, time::Duration};

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

pub struct Client { config: Arc<ClientConfig>, server: ShippingServer, host: String, deadline: Duration }

type Tls = Timed<StreamOwned<ClientConnection, TcpStream>>;
/// The error to report for a failed operation: the deadline if it passed, else `fault`.
fn failure(tls: &Tls, fault: ClientError) -> ClientError { if tls.expired() { ClientError::Timeout } else { fault } }

// Effect site: the only cloud socket. Resolution and connection happen under a
// permit minted from the configured shipping server and nothing else, and the
// connect is bounded by the request deadline.
#[allow(clippy::disallowed_methods)]
fn open_socket(permit: &Egress<'_, ShippingServer>, deadline: &Deadline) -> Result<TcpStream, ClientError> {
    let target = permit.target();
    let addresses: Vec<_> = (target.host(), target.port()).to_socket_addrs().map_err(|_| ClientError::Resolve)?.take(16).collect();
    if addresses.is_empty() { return Err(ClientError::Resolve); }
    let mut failure = ClientError::Connect;
    for address in &addresses {
        match TcpStream::connect_timeout(address, deadline.remaining().map_err(|_| ClientError::Timeout)?) {
            Ok(socket) => return Ok(socket),
            Err(e) if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) => failure = ClientError::Timeout,
            Err(_) => {}
        }
    }
    Err(failure)
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
        Ok(Self { config: Arc::new(config), server, host, deadline })
    }

    /// `bearer` becomes an `Authorization` header; `headers` are added verbatim.
    /// Blocks the calling thread for at most the deadline plus name resolution.
    pub fn request(&self, method: &str, path: &str, bearer: Option<&str>, headers: &[(&str, String)], body: Vec<u8>)
        -> Result<Reply, ClientError>
    {
        let deadline = Deadline::start(self.deadline).map_err(|_| ClientError::Timeout)?;
        let permit = Egress::cloud(&self.server);
        let tcp = open_socket(&permit, &deadline)?;
        let server = ServerName::try_from(self.host.clone()).map_err(|_| ClientError::Tls)?;
        let connection = ClientConnection::new(self.config.clone(), server).map_err(|_| ClientError::Tls)?;
        let mut tls: Tls = Timed::new(StreamOwned::new(connection, tcp), deadline);
        let shaken = tls.handshake();
        shaken.map_err(|_| failure(&tls, ClientError::Tls))?;

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
        let sent = tls.write_all(&head).and_then(|()| tls.flush());
        sent.map_err(|_| failure(&tls, ClientError::Http))?;

        let mut leftover = Vec::new();
        let (status_head, leftover, reply_framing) = loop {
            let read = read_status_head(&mut tls, leftover);
            let (status_head, rest) = read.map_err(|_| failure(&tls, ClientError::Http))?;
            match upstream_status(status_head.status, &status_head.fields) {
                UpstreamStatus::Interim => { leftover = rest; }
                UpstreamStatus::Refused => return Err(ClientError::Http),
                UpstreamStatus::Bodiless => break (status_head, rest, Framing::Length(0)),
                UpstreamStatus::Framed(framing) => break (status_head, rest, framing),
            }
        };
        let retry_after = status_head.fields.iter().find(|f| f.name == b"retry-after")
            .and_then(|f| std::str::from_utf8(&f.value).ok()).and_then(|v| v.trim().parse().ok());
        if let Framing::Length(n) = reply_framing { if n > MAX_REPLY_BYTES as u64 { return Err(ClientError::Http); } }
        let body = read_body(&mut tls, leftover, reply_framing);
        let bytes = body.map_err(|_| failure(&tls, ClientError::Http))?;
        Ok(Reply { status: status_head.status, retry_after, body: bytes })
    }
}

/// The whole reply body, capped; an error is a framing fault, a short body, or the deadline.
fn read_body(tls: &mut Tls, leftover: Vec<u8>, framing: Framing) -> Result<Vec<u8>, ()> {
    let mut reader = BodyReader::new(tls, leftover, framing);
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let n = reader.read(&mut buffer).map_err(|_| ())?;
        if n == 0 { return Ok(bytes); }
        if bytes.len().checked_add(n).is_none_or(|total| total > MAX_REPLY_BYTES) { return Err(()); }
        bytes.extend_from_slice(buffer.get(..n).ok_or(())?);
    }
}
