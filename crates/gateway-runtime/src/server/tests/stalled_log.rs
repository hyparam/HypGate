use super::*;

#[tokio::test]
async fn stalled_log_under_load_preserves_health_deadlines_and_mode_policy() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for availability in [false, true] { exercise(availability).await; }
    }).await.unwrap();
}

async fn exercise(availability: bool) {
    const SLOTS: usize = 8;
    let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
    let tls = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()],
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (log, started, release, writes) = DiskLog::stalled_for_test(2, Duration::from_secs(1));
    let app = Gateway::new(config_with_limits(upstream.local_addr().unwrap().port(), availability, SLOTS, 16384),
        HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(), log);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); let port = listener.local_addr().unwrap().port();
    let (shutdown, stopped) = oneshot::channel();
    let gateway = tokio::spawn(serve(listener, app.clone(), 64, Duration::from_secs(7), async { let _ = stopped.await; }));
    let connections = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let accepted = connections.clone();
    let (stop_provider, provider_stopped) = oneshot::channel();
    let provider = tokio::spawn(async move {
        tokio::pin!(provider_stopped);
        let mut tasks = JoinSet::new();
        loop {
            let socket = tokio::select! {
                _ = &mut provider_stopped => break,
                result = upstream.accept() => result.unwrap().0,
            };
            accepted.fetch_add(1, Ordering::Relaxed);
            let acceptor = acceptor.clone();
            tasks.spawn(async move {
                let socket = acceptor.accept(socket).await.unwrap();
                let service = service_fn(move |mut request: Request<Incoming>| async move {
                    assert_eq!(request.headers()["x-api-key"], "provider-secret");
                    let mut bytes = Vec::new(); let mut failed = false;
                    while let Some(frame) = request.body_mut().frame().await {
                        match frame {
                            Ok(frame) => if let Ok(data) = frame.into_data() { bytes.extend_from_slice(&data); },
                            Err(_) => { failed = true; break; },
                        }
                    }
                    if availability { assert!(!failed); assert_eq!(bytes, b"{\"stream\":true}"); }
                    else { assert!(failed); assert!(bytes.is_empty()); }
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"complete"))))
                });
                let result = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(socket), service).await;
                if availability { result.unwrap(); }
            });
        }
        while let Some(result) = tasks.join_next().await { result.unwrap(); }
    });
    let mut clients = JoinSet::new();
    clients.spawn(request(port, availability, false));
    started.await.unwrap(); // The real disk worker is blocked inside sync.
    // Fill both queue slots before creating enough traffic to hit saturation.
    for queued in 1..=2 {
        clients.spawn(request(port, availability, false));
        while app.log.queued_for_test() < queued { tokio::task::yield_now().await; }
    }
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    for _ in 3..SLOTS { clients.spawn(request(port, availability, false)); }
    for path in ["/healthz", "/metrics"] {
        let (response, connection) = send(port, path, "", "GET").await;
        assert_eq!(response.status(), StatusCode::OK);
        response.collect().await.unwrap(); connection.await.unwrap();
    }
    while let Some(result) = clients.join_next().await { result.unwrap(); }
    while !app.workers.is_empty() { tokio::task::yield_now().await; }
    assert!(!app.log.healthy());
    assert_eq!(app.config.usage(), Some((0, SLOTS)));
    assert_eq!(app.log.queued_for_test(), 2);
    let (ready, connection) = send(port, "/readyz", "", "GET").await;
    assert_eq!(ready.status(), if availability { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE });
    ready.collect().await.unwrap(); connection.await.unwrap();
    for _ in 0..SLOTS { clients.spawn(request(port, availability, true)); }
    while let Some(result) = clients.join_next().await { result.unwrap(); }
    while !app.workers.is_empty() { tokio::task::yield_now().await; }
    assert_eq!(app.config.usage(), Some((0, SLOTS)));
    assert_eq!(connections.load(Ordering::Relaxed), if availability { 2 * SLOTS } else { SLOTS });
    assert_eq!(app.audit_gaps(), if availability { (2 * SLOTS) as u64 } else { 0 });
    assert_eq!(writes.load(Ordering::Relaxed), 1); // No replacement writer or retry.
    release.send(()).unwrap();
    app.log.shutdown(Duration::from_secs(1)).await.unwrap();
    assert_eq!(writes.load(Ordering::Relaxed), 1); // Queued jobs fail after timeout.
    stop_provider.send(()).unwrap(); provider.await.unwrap();
    shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
    assert!(app.workers.is_empty());
}

async fn request(port: u16, availability: bool, unhealthy: bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (response, connection) = send(port, "/routes/7", "gateway", "POST").await;
        let expected = if availability { StatusCode::OK } else if unhealthy {
            StatusCode::SERVICE_UNAVAILABLE
        } else { StatusCode::BAD_GATEWAY };
        assert_eq!(response.status(), expected);
        let bytes = response.collect().await.unwrap().to_bytes();
        if availability { assert_eq!(bytes, b"complete"[..]); }
        connection.await.unwrap();
    }).await.unwrap();
}
