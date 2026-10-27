//! One HTTPS request at a time to the configured HypAware server, on the
//! shipper's own thread: blocking sockets and rustls used directly. No
//! redirects, proxies, pooling, or retries here. One deadline covers the
//! connect, the handshake, the request, and the reply (`net::Tls` over
//! `net::Timed<TcpStream>`); trickling cannot renew it. Name resolution runs
//! on the client's one lookup thread and is waited for within the same
//! deadline (`lookup`). Once the connection is up, the exchange itself is the
//! verified `client_exchange` driver: the head and body are written once, in
//! order, interim heads are skipped up to a bound, and the reply body is read
//! under the verified body reader within the cap. This module performs the
//! connect and the handshake, and classifies a failure as the deadline or a fault.
use super::config::ShippingServer;
use super::lookup::Lookup;
use gateway_core::egress::Egress;
use gateway_core::http1_write::{wire_ok, write_request_head};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use crate::net::{Deadline, Tls};
use std::{io, net::{SocketAddr, TcpStream}, sync::Arc, time::Duration};

pub const MAX_REPLY_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ClientError { Resolve, Connect, Tls, Http, Timeout }

/// A reply as the machine sees it: the status, the verified `Retry-After`
/// reading of the head, and the whole body.
#[derive(Debug)]
pub struct Reply { pub status: u16, pub retry_after: Option<u64>, pub body: Vec<u8> }

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

    /// Send the verified S3 request verbatim, under this client's sole egress
    /// permit: its head is the verified writer's rendering of the request's
    /// own method, path, and fields.
    pub(super) fn put(&self, request: gateway_core::s3_delivery::Put) -> Result<Reply, ClientError> {
        if request.authority != self.server.authority().as_bytes() { return Err(ClientError::Http); }
        if !wire_ok(&request.headers) || !request.path.starts_with(b"/") || request.path.iter().any(|b| !(33..=126).contains(b)) {
            return Err(ClientError::Http);
        }
        let mut head = Vec::new();
        write_request_head(&request.method, &request.path, &request.headers, &mut head);
        self.request(&head, &request.body)
    }

    /// Send a request head and body (the head from the verified
    /// `shipping_wire::request_head` or the verified S3 request) and read the
    /// reply through the verified exchange driver. Uses the deadline on name
    /// resolution and each socket operation; OS scheduling and TLS computation
    /// are outside any hard wall-clock guarantee.
    pub fn request(&self, head: &[u8], body: &[u8]) -> Result<Reply, ClientError> {
        let deadline = Deadline::start(self.deadline).map_err(|_| ClientError::Timeout)?;
        let permit = Egress::cloud(&self.server);
        let addresses = self.resolve(&deadline)?;
        let tcp = open_socket(&permit, &addresses, &deadline)?;
        let server = ServerName::try_from(self.host.clone()).map_err(|_| ClientError::Tls)?;
        let connection = ClientConnection::new(self.config.clone(), server).map_err(|_| ClientError::Tls)?;
        let mut tls: Tls = Tls::new(connection, tcp, deadline);
        let shaken = tls.handshake();
        shaken.map_err(|_| failure(&tls, ClientError::Tls))?;
        let exchanged = crate::http1::client_exchange(&mut tls, head, body, MAX_REPLY_BYTES);
        let reply = exchanged.map_err(|_| failure(&tls, ClientError::Http))?;
        let retry_after = gateway_core::shipping_wire::retry_after(&reply.head.fields);
        Ok(Reply { status: reply.head.status, retry_after, body: reply.body })
    }
}
