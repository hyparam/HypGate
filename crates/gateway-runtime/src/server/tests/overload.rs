use super::*;

#[tokio::test]
async fn repeated_overload_preserves_active_streams_health_and_reusable_capacity() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for availability in [false, true] { exercise(availability).await; }
    }).await.unwrap();
}

async fn exercise(availability: bool) {
    const SLOTS: usize = 8;
    const BURST: usize = 32;
    const ROUNDS: usize = 4;
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
    let tls = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = TempDir::new(); let path = dir.0.join("overload.log");
    let app = Gateway::new(config_with_limits(upstream.local_addr().unwrap().port(), availability, SLOTS, 16384),
        HttpsTransport::with_roots(roots, Duration::from_secs(20)).unwrap(),
        DiskLog::create(&path, 16, Duration::from_secs(2)).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); let port = listener.local_addr().unwrap().port();
    let (shutdown, stopped) = oneshot::channel();
    let gateway = tokio::spawn(serve(listener, app.clone(), 128, Duration::from_secs(25), async { let _ = stopped.await; }));
    let (release, waiting) = tokio::sync::watch::channel(false);
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepted = connections.clone();
    let provider = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        for _ in 0..SLOTS + 1 {
            let (socket, _) = upstream.accept().await.unwrap();
            accepted.fetch_add(1, Ordering::Relaxed);
            let acceptor = acceptor.clone(); let waiting = waiting.clone();
            tasks.spawn(async move {
                let socket = acceptor.accept(socket).await.unwrap();
                let service = service_fn(move |request: Request<Incoming>| {
                    let mut waiting = waiting.clone();
                    async move {
                        assert_eq!(request.headers()["x-api-key"], "provider-secret");
                        assert_eq!(request.collect().await.unwrap().to_bytes(), b"{\"stream\":true}"[..]);
                        let (mut writer, body) = http_body::channel(16);
                        tokio::spawn(async move {
                            writer.write_all(b"held").await.unwrap();
                            while !*waiting.borrow_and_update() { waiting.changed().await.unwrap(); }
                            writer.write_all(b"done").await.unwrap(); writer.shutdown().await.unwrap();
                        });
                        Ok::<_, Infallible>(Response::new(body))
                    }
                });
                hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await.unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await { result.unwrap(); }
    });
    let mut held = Vec::new();
    for _ in 0..SLOTS {
        let (mut response, connection) = send(port, "/routes/7", "gateway", "POST").await;
        assert_eq!(response.status(), StatusCode::OK);
        let prefix = response.body_mut().frame().await.unwrap().unwrap().into_data().unwrap();
        assert!(!prefix.is_empty()); held.push((response, connection, prefix));
    }
    for _ in 0..ROUNDS {
        assert_eq!(app.config.usage(), Some((SLOTS, SLOTS)));
        let mut excess = JoinSet::new();
        for _ in 0..BURST {
            excess.spawn(async move {
                let (response, connection) = send(port, "/routes/7", "gateway", "POST").await;
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                response.collect().await.unwrap(); connection.await.unwrap();
            });
        }
        // Check health while excess requests are in flight, not only afterward.
        for route in ["/healthz", "/readyz", "/metrics"] {
            let (response, connection) = send(port, route, "", "GET").await;
            assert_eq!(response.status(), StatusCode::OK);
            response.collect().await.unwrap(); connection.await.unwrap();
        }
        while let Some(result) = excess.join_next().await { result.unwrap(); }
        assert_eq!(app.config.usage(), Some((SLOTS, SLOTS)));
        assert_eq!(connections.load(Ordering::Relaxed), SLOTS);
    }
    release.send(true).unwrap();
    for (response, connection, prefix) in held {
        let mut bytes = prefix.to_vec(); bytes.extend_from_slice(&response.collect().await.unwrap().to_bytes());
        assert_eq!(bytes, b"helddone"); connection.await.unwrap();
    }
    while !app.workers.is_empty() { tokio::task::yield_now().await; }
    assert_eq!(app.config.usage(), Some((0, SLOTS)));
    // A fresh generation must succeed after all overloaded waves drain.
    let (response, connection) = send(port, "/routes/7", "gateway", "POST").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.collect().await.unwrap().to_bytes(), b"helddone"[..]); connection.await.unwrap();
    provider.await.unwrap(); shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
    assert_eq!(app.config.usage(), Some((0, SLOTS))); assert!(app.workers.is_empty());
    assert_eq!(app.failed_exchanges(), 0); assert_eq!(app.audit_gaps(), 0);
    let mut scanner = LogReader::new(File::open(path).unwrap()).unwrap();
    let mut records = std::collections::BTreeMap::<u64, (Vec<u8>, Vec<u8>)>::new();
    while let Some(record) = scanner.next_record().unwrap() {
        assert_eq!(record.tenant, 1);
        let entry = records.entry(record.request).or_default();
        match record.direction {
            crate::transfer::Direction::Upload => entry.0.extend(record.bytes),
            crate::transfer::Direction::Download => entry.1.extend(record.bytes),
        }
    }
    assert_eq!(records.len(), SLOTS + 1);
    for (upload, download) in records.values() {
        assert_eq!(upload, b"{\"stream\":true}"); assert_eq!(download, b"helddone");
    }
}
