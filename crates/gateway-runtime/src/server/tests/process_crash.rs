//! Process-crash experiment: the kernel and filesystem caches remain alive.
use super::*;
use std::{io::Write, process::{Child, Command, Stdio}};
use tokio_rustls::rustls::pki_types::CertificateDer;

struct Process(Child);
impl Drop for Process { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

#[test]
fn gateway_child() {
    let Some(directory) = std::env::var_os("SOUNDGATE_GATEWAY_CRASH_CHILD") else { return; };
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
        .env("SOUNDGATE_GATEWAY_CRASH_CHILD", &directory.0)
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
async fn killed_gateway_truncates_response_preserves_audit_prefix_and_does_not_replay() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let tls = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let upstream = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let upstream_port = upstream.local_addr().unwrap().port();
        let (release, waiting) = oneshot::channel::<()>();
        let waiting = Arc::new(Mutex::new(Some(waiting)));
        let provider_listener = upstream.clone();
        let provider = tokio::spawn(async move {
            let (socket, _) = provider_listener.accept().await.unwrap();
            let socket = acceptor.accept(socket).await.unwrap();
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
        let (mut response, connection) = send(port, "/routes/7", "gateway", "POST").await;
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
            match record.direction {
                crate::transfer::Direction::Upload => upload.extend(record.bytes),
                crate::transfer::Direction::Download => download.extend(record.bytes),
            }
        }
        assert_eq!(upload, b"{\"stream\":true}"); assert_eq!(download, visible);
        assert_eq!(scanner.valid_end(), before.len() as u64);
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
