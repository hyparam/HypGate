//! Process-crash experiment: the kernel and filesystem caches remain alive.
use super::*;
use std::{io::Write, process::{Child, Command, Stdio}};
use tokio_rustls::{TlsConnector, rustls::{ClientConfig, pki_types::{CertificateDer, ServerName}}};

struct Process(Child);
impl Drop for Process { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

#[test]
fn gateway_child() {
    let Some(directory) = std::env::var_os("LOGGATE_GATEWAY_CRASH_CHILD") else { return; };
    let directory = std::path::PathBuf::from(directory);
    let upstream: u16 = std::fs::read_to_string(directory.join("upstream")).unwrap().parse().unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(std::fs::read(directory.join("root.der")).unwrap())).unwrap();
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let app = Gateway::new(config(upstream, false),
            HttpsTransport::with_roots(roots, Duration::from_secs(60)).unwrap(),
            DiskLog::create(&directory.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        std::fs::write(directory.join("port"), listener.local_addr().unwrap().port().to_string()).unwrap();
        std::io::stdout().flush().unwrap();
        serve(listener, app, 4, Duration::from_secs(65), std::future::pending()).await.unwrap();
    });
}

async fn start(directory: &TempDir, root: &[u8], upstream: u16) -> (Process, u16) {
    std::fs::write(directory.0.join("root.der"), root).unwrap();
    std::fs::write(directory.0.join("upstream"), upstream.to_string()).unwrap();
    let mut child = Process(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "server::tests::process_crash::gateway_child", "--nocapture"])
        .env("LOGGATE_GATEWAY_CRASH_CHILD", &directory.0)
        .stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap());
    let port = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(child.0.try_wait().unwrap().is_none(), "gateway child exited during startup");
            if let Ok(text) = std::fs::read_to_string(directory.0.join("port")) {
                if let Ok(port) = text.parse::<u16>() { break port; }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    (child, port)
}

#[tokio::test]
async fn killed_gateway_truncates_response_preserves_audit_prefix_and_does_not_replay() { exercise(false).await; }

#[tokio::test]
#[ignore = "requires HAProxy; set LOGGATE_HAPROXY and run with --ignored"]
async fn proxy_gateway_process_failover_without_replay() { exercise(true).await; }

async fn exercise(with_proxy: bool) {
    tokio::time::timeout(Duration::from_secs(25), async {
        let (cert, acceptor, _) = self_signed();
        let upstream = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let upstream_port = upstream.local_addr().unwrap().port();
        let (release, waiting) = oneshot::channel::<()>();
        let waiting = Arc::new(Mutex::new(Some(waiting)));
        let provider_listener = upstream.clone();
        let first_acceptor = acceptor.clone();
        let provider = tokio::spawn(async move {
            let (socket, _) = provider_listener.accept().await.unwrap();
            let socket = first_acceptor.accept(socket).await.unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let waiting = waiting.lock().unwrap().take().unwrap();
                async move {
                    assert_eq!(request.headers()["x-api-key"], "provider-secret");
                    assert_eq!(request.collect().await.unwrap().to_bytes(), "{\"stream\":true}");
                    let (mut writer, body) = http_body::channel(16);
                    tokio::spawn(async move {
                        writer.write_all(b"prefix").await.unwrap();
                        let _ = waiting.await;
                        // Never send a clean EOF: the gateway dies mid-generation.
                    });
                    Ok::<_, Infallible>(Response::new(body))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
        });
        let dir = TempDir::new();
        let (mut child, port) = start(&dir, cert.cert.der(), upstream_port).await;
        let standby_dir = TempDir::new();
        let standby = if with_proxy { Some(start(&standby_dir, cert.cert.der(), upstream_port).await) } else { None };
        let proxy_dir = TempDir::new();
        let proxy = if let Some((_, standby_port)) = &standby {
            Some(start_proxy(&proxy_dir, port, *standby_port,
                &(cert.cert.pem() + &cert.signing_key.serialize_pem())).await)
        } else { None };
        let (mut response, connection) = if let Some((_, proxy_port)) = &proxy {
            send_proxy(*proxy_port, cert.cert.der(), b"{\"stream\":true}").await
        } else { send(port, "/routes/7", "gateway", "POST").await };
        assert_eq!(response.status(), StatusCode::OK);
        let mut visible = Vec::new();
        while visible.len() < 6 {
            visible.extend_from_slice(&response.body_mut().frame().await.unwrap().unwrap().into_data().unwrap());
        }
        assert_eq!(visible, b"prefix");
        child.0.kill().unwrap(); assert!(!child.0.wait().unwrap().success());
        assert!(response.collect().await.is_err(), "process death must not become successful EOF");
        connection.await.unwrap(); drop(release); provider.await.unwrap();
        let path = dir.0.join("audit.log"); let before = std::fs::read(&path).unwrap();
        let mut scanner = LogReader::new(File::open(&path).unwrap()).unwrap();
        let session = scanner.session();
        let mut upload = Vec::new(); let mut download = Vec::new();
        while let Some(record) = scanner.next_record().unwrap() {
            assert_eq!((record.tenant, record.request), (1, 1));
            match record.kind {
                crate::transfer::RecordKind::Upload => upload.extend(record.bytes),
                crate::transfer::RecordKind::Download => download.extend(record.bytes),
                _ => {},
            }
        }
        assert_eq!(upload, b"{\"stream\":true}"); assert_eq!(download, visible);
        assert_eq!(scanner.valid_end(), before.len() as u64);
        if let Some((_, proxy_port)) = &proxy {
            // Two failed 1-second readiness checks remove the dead primary.
            // Any attempted replay would create a provider connection here.
            assert!(tokio::time::timeout(Duration::from_millis(2500), upstream.accept()).await.is_err());
            let provider_listener = upstream.clone();
            let second = tokio::spawn(async move {
                let (socket, _) = provider_listener.accept().await.unwrap();
                let socket = acceptor.accept(socket).await.unwrap();
                let service = service_fn(|request: Request<Incoming>| async move {
                    assert_eq!(request.headers()["x-api-key"], "provider-secret");
                    assert_eq!(request.collect().await.unwrap().to_bytes(), b"second-request"[..]);
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"standby-response"))))
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
            let (response, connection) = send_proxy(*proxy_port, cert.cert.der(), b"second-request").await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.collect().await.unwrap().to_bytes(), b"standby-response"[..]);
            connection.await.unwrap(); second.await.unwrap();
            let mut recovered = LogReader::new(File::open(standby_dir.0.join("audit.log")).unwrap()).unwrap();
            assert_ne!(recovered.session(), session);
            let mut upload = Vec::new(); let mut download = Vec::new();
            while let Some(record) = recovered.next_record().unwrap() {
                assert_eq!((record.tenant, record.request), (1, 1));
                match record.kind {
                    crate::transfer::RecordKind::Upload => upload.extend(record.bytes),
                    crate::transfer::RecordKind::Download => download.extend(record.bytes),
                    _ => {},
                }
            }
            assert_eq!(upload, b"second-request"); assert_eq!(download, b"standby-response");
            assert_eq!(std::fs::read(path).unwrap(), before);
            return;
        }
        let restart_dir = TempDir::new();
        let (_restart, restarted_port) = start(&restart_dir, cert.cert.der(), upstream_port).await;
        let (health, connection) = send(restarted_port, "/healthz", "", "GET").await;
        assert_eq!(health.status(), StatusCode::OK); health.collect().await.unwrap(); connection.await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(100), upstream.accept()).await.is_err());
        let restarted = LogReader::new(File::open(restart_dir.0.join("audit.log")).unwrap()).unwrap();
        assert_ne!(session, restarted.session());
        assert_eq!(std::fs::read(path).unwrap(), before);
    }).await.unwrap();
}


async fn start_proxy(directory: &TempDir, primary: u16, standby: u16, pem: &str) -> (Process, u16) {
    let reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = reservation.local_addr().unwrap().port();
    let certificate = directory.0.join("tls.pem");
    std::fs::write(&certificate, pem).unwrap();
    let config = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/haproxy.cfg"))
        .replace("bind :8443", &format!("bind 127.0.0.1:{port}"))
        .replace("127.0.0.1:8081", &format!("127.0.0.1:{primary}"))
        .replace("127.0.0.1:8082", &format!("127.0.0.1:{standby}"));
    let path = directory.0.join("haproxy.cfg"); std::fs::write(&path, config).unwrap();
    drop(reservation);
    let mut process = Process(Command::new(std::env::var_os("LOGGATE_HAPROXY").unwrap_or_else(|| "haproxy".into()))
        .arg("-db").arg("-f").arg(&path).env("LOGGATE_TLS_PEM", certificate)
        .stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            assert!(process.0.try_wait().unwrap().is_none(), "proxy exited during startup");
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() { break; }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    (process, port)
}

async fn send_proxy(port: u16, root: &[u8], payload: &'static [u8]) -> (Response<Incoming>, JoinHandle<()>) {
    let mut roots = RootCertStore::empty(); roots.add(CertificateDer::from(root.to_vec())).unwrap();
    let connector = TlsConnector::from(Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()));
    let socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let socket = connector.connect(ServerName::try_from("localhost").unwrap(), socket).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(socket)).await.unwrap();
    let connection = tokio::spawn(async move { let _ = conn.await; });
    let request = Request::builder().method("POST").uri("/routes/7").header("host", "localhost")
        .header("authorization", "Bearer gateway").body(Full::new(Bytes::from_static(payload))).unwrap();
    (sender.send_request(request).await.unwrap(), connection)
}
