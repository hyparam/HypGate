//! Fixtures shared by this crate's unit tests.
use crate::admission::Admission;
use gateway_core::policy::{Identity, Policy, Route};
use rcgen::{CertifiedKey, KeyPair};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, rustls::{RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer}};

/// A self-signed `localhost` certificate with its acceptor and a store trusting it.
pub(crate) fn self_signed() -> (CertifiedKey<KeyPair>, TlsAcceptor, RootCertStore) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let config = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()], key.into()).unwrap();
    (cert, TlsAcceptor::from(Arc::new(config)), roots)
}

/// A loopback listener with the acceptor and roots for TLS on it.
pub(crate) async fn tls() -> (TcpListener, TlsAcceptor, RootCertStore) {
    let (_, acceptor, roots) = self_signed();
    (TcpListener::bind("127.0.0.1:0").await.unwrap(), acceptor, roots)
}

/// A fresh directory under the system temp dir, removed on drop.
pub(crate) struct TempDir(pub(crate) std::path::PathBuf);
impl TempDir {
    pub(crate) fn new() -> Self {
        let mut random = [0; 16]; getrandom::fill(&mut random).unwrap();
        let name: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let path = std::env::temp_dir().join(format!("soundgate-test-{name}"));
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
