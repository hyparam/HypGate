//! Fixtures shared by this crate's unit tests: blocking sockets and rustls
//! server connections, since the crate links no executor.
use crate::admission::Admission;
use gateway_core::policy::{Identity, Policy, Route};
use rcgen::{CertifiedKey, KeyPair};
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
use std::{net::{TcpListener, TcpStream}, sync::Arc};

pub(crate) type ServerTls = StreamOwned<ServerConnection, TcpStream>;

/// A self-signed `localhost` certificate with its server config and a store trusting it.
pub(crate) fn self_signed() -> (CertifiedKey<KeyPair>, Arc<ServerConfig>, RootCertStore) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let config = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], key.into()).unwrap();
    (cert, Arc::new(config), roots)
}

/// A loopback listener with the server config and roots for TLS on it.
pub(crate) fn tls() -> (TcpListener, Arc<ServerConfig>, RootCertStore) {
    let (_, config, roots) = self_signed();
    (TcpListener::bind("127.0.0.1:0").unwrap(), config, roots)
}

/// Accept one connection and complete the TLS handshake on it.
pub(crate) fn accept_tls(listener: &TcpListener, config: &Arc<ServerConfig>) -> std::io::Result<ServerTls> {
    let (socket, _) = listener.accept()?;
    socket.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    socket.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let mut connection = ServerConnection::new(config.clone()).map_err(std::io::Error::other)?;
    while connection.is_handshaking() { connection.complete_io(&mut &socket)?; }
    Ok(StreamOwned::new(connection, socket))
}

/// A fresh directory under the system temp dir, removed on drop.
pub(crate) struct TempDir(pub(crate) std::path::PathBuf);
impl TempDir {
    pub(crate) fn new() -> Self {
        let mut random = [0; 16]; getrandom::fill(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("loggate-test-{name}"));
        std::fs::create_dir(&path).unwrap(); Self(path)
    }
}
impl Drop for TempDir { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

/// One tenant, digest `[11; 32]`, granted selector 7 to origin 0 with credential 0.
pub(crate) fn admission(slots: usize, chunk_bytes: usize, strict: bool) -> Admission {
    let route = || Route { tenant: 1, selector: 7, origin: 0, credential: 0 };
    let policy = Policy::validate(vec![Identity { tenant: 1, digest: vec![11; 32] }],
        vec![route()], vec![route()], 1, vec![1]).unwrap();
    Admission::new(policy, slots, chunk_bytes, strict)
}

/// Poll `condition` until it holds or `deadline` passes; true when it held.
pub(crate) fn wait_until(deadline: std::time::Duration, mut condition: impl FnMut() -> bool) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline { if condition() { return true; } std::thread::sleep(std::time::Duration::from_millis(5)); }
    condition()
}

#[path = "test_support/http.rs"]
pub(crate) mod http;
