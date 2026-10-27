//! One HTTPS request at a time to the configured HypAware server, over the
//! verified codec, on the shipper's own thread: blocking sockets and rustls
//! used directly. No redirects, proxies, pooling, or retries here. One
//! deadline covers the connect, the handshake, the request, and the reply
//! (`net::Tls` over `net::Timed<TcpStream>`); trickling cannot renew it. Name
//! resolution runs on the client's one lookup thread and is waited for within
//! the same deadline (`lookup`). Response bodies are capped.
use super::config::ShippingServer;
use super::lookup::Lookup;
use crate::http1::{self, BodyReader, read_status_head};
use gateway_core::egress::Egress;
use gateway_core::headers::Field;
use gateway_core::http1_exchange::{UpstreamStatus, upstream_status};
use gateway_core::http1_framing::Framing;
use gateway_core::http1_write::{wire_ok, write_request_head};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use crate::net::{Deadline, Tls};
use std::{io::{self, Read, Write}, net::{SocketAddr, TcpStream}, sync::Arc, time::Duration};

pub const MAX_REPLY_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ClientError { Resolve, Connect, Tls, Http, Timeout }

#[derive(Debug)]
pub struct Reply { pub status: u16, pub retry_after: Option<u64>, pub body: Vec<u8> }
impl Reply {
    /// The `error` code of a `{"error":"..."}` body, if any.
    pub fn error_code(&self) -> Option<String> {
        String::from_utf8(gateway_core::json::parse(&self.body)?.get(b"error")?.as_str()?.clone()).ok()
    }
}

pub struct Client { config: Arc<ClientConfig>, server: ShippingServer, host: String, deadline: Duration, lookup: Lookup }

/// The error to report for a failed operation: the deadline if it passed, else `fault`.
fn failure(tls: &Tls, fault: ClientError) -> ClientError { if tls.expired() { ClientError::Timeout } else { fault } }

// Effect site: the only cloud socket, opened under a permit minted from the
// configured shipping server and nothing else; the addresses come from
// resolving that permit's host, and each connect is bounded by the request deadline.
#[allow(clippy::disallowed_methods)]
fn open_socket(_permit: &Egress<'_, ShippingServer>, addresses: &[SocketAddr], deadline: &Deadline) -> Result<TcpStream, ClientError> {
    let mut failure = ClientError::Connect;
    for address in addresses {
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
        Ok(Self { config: Arc::new(config), server, host, deadline, lookup: Lookup::new()? })
    }
    /// The server's addresses, within the deadline. A lookup thread still busy
    /// from an earlier request is a `Resolve` error, not a wait.
    fn resolve(&self, deadline: &Deadline) -> Result<Vec<SocketAddr>, ClientError> {
        let left = deadline.remaining().map_err(|_| ClientError::Timeout)?;
        self.lookup.resolve(self.server.host(), self.server.port(), left)
            .map_err(|e| if e.kind() == io::ErrorKind::TimedOut { ClientError::Timeout } else { ClientError::Resolve })
    }

    /// `bearer` becomes an `Authorization` header; `headers` are added verbatim.
    /// Uses the deadline on name resolution and each socket operation; OS
    /// scheduling and TLS computation are outside any hard wall-clock guarantee.
    pub fn request(&self, method: &str, path: &str, bearer: Option<&str>, headers: &[(&str, String)], body: Vec<u8>)
        -> Result<Reply, ClientError>
    {
        let mut fields = vec![
            http1::field(b"host", self.server.authority().as_bytes().to_vec()),
            http1::field(b"connection", b"close".to_vec()),
            http1::field(b"content-length", body.len().to_string().into_bytes()),
        ];
        if let Some(token) = bearer {
            fields.push(Field { name: b"authorization".to_vec(), value: format!("Bearer {token}").into_bytes(), sensitive: true });
        }
        for (name, value) in headers { fields.push(Field { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec(), sensitive: name.eq_ignore_ascii_case("authorization") || name.eq_ignore_ascii_case("x-amz-security-token") }); }
        self.request_fields(method.as_bytes(), path.as_bytes(), fields, body)
    }

    /// Send the verified S3 request verbatim, under this client's sole egress permit.
    pub(super) fn put(&self, request: gateway_core::s3_delivery::Put) -> Result<Reply, ClientError> {
        if request.authority != self.server.authority().as_bytes() { return Err(ClientError::Http); }
        self.request_fields(&request.method, &request.path, request.headers, request.body)
    }

    fn request_fields(&self, method: &[u8], path: &[u8], fields: Vec<Field>, body: Vec<u8>) -> Result<Reply, ClientError> {
        if !wire_ok(&fields) || !path.starts_with(b"/") || path.iter().any(|b| !(33..=126).contains(b)) { return Err(ClientError::Http); }
        let deadline = Deadline::start(self.deadline).map_err(|_| ClientError::Timeout)?;
        let permit = Egress::cloud(&self.server);
        let addresses = self.resolve(&deadline)?;
        let tcp = open_socket(&permit, &addresses, &deadline)?;
        let server = ServerName::try_from(self.host.clone()).map_err(|_| ClientError::Tls)?;
        let connection = ClientConnection::new(self.config.clone(), server).map_err(|_| ClientError::Tls)?;
        let mut tls: Tls = Tls::new(connection, tcp, deadline);
        let shaken = tls.handshake();
        shaken.map_err(|_| failure(&tls, ClientError::Tls))?;

        let mut head = Vec::new();
        write_request_head(method, path, &fields, &mut head);
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
