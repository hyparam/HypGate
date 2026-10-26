use super::*;

#[tokio::test]
async fn stalled_log_under_load_preserves_health_deadlines_and_mode_policy() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for availability in [false, true] { exercise(availability, false).await; }
    }).await.unwrap();
}

#[tokio::test]
async fn shutdown_with_blocked_disk_returns_error_without_replacement_or_replay() {
    tokio::time::timeout(Duration::from_secs(20), async {
        for availability in [false, true] { exercise(availability, true).await; }
    }).await.unwrap();
}

async fn exercise(availability: bool, shutdown_blocked: bool) {
    const SLOTS: usize = 8;
    let (upstream, acceptor, roots) = tls().await;
    let (log, started, release, writes) = DiskLog::stalled_for_test(2, Duration::from_secs(1));
    let app = Gateway::new(config_with_limits(upstream.local_addr().unwrap().port(), availability, SLOTS, 16384),
        HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(), log);
    let (port, shutdown, gateway) = spawn_gateway(&app, 64, Duration::from_secs(7)).await;
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
                let mut socket = acceptor.accept(socket).await.unwrap();
                let request = read_request(&mut socket).await;
                assert!(availability, "strict mode must not connect without a start record");
                let request = request.unwrap();
                assert_eq!(request.header("x-api-key"), Some("provider-secret"));
                assert_eq!(request.body, b"{\"stream\":true}");
                write_response(&mut socket, 200, &[], b"complete").await.unwrap();
            });
        }
        while let Some(result) = tasks.join_next().await { result.unwrap(); }
    });
    // Strict mode now refuses at the request-start record, before any upstream
    // connection: a stalled logger is observed at kind 2, not during the body.
    let mut clients = JoinSet::new();
    clients.spawn(request(port, availability));
    started.await.unwrap(); // The real disk worker is blocked inside sync.
    // Fill both queue slots before creating enough traffic to hit saturation.
    for queued in 1..=2 {
        clients.spawn(request(port, availability));
        while app.log.queued_for_test() < queued { tokio::task::yield_now().await; }
    }
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    for _ in 3..SLOTS { clients.spawn(request(port, availability)); }
    for path in ["/healthz", "/metrics"] {
        let (response, connection) = send(port, path, "", "GET").await;
        assert_eq!(response.status, 200);
        response.collect().await.unwrap(); connection.await.unwrap();
    }
    while let Some(result) = clients.join_next().await { result.unwrap(); }
    while !app.workers.is_empty() { tokio::task::yield_now().await; }
    assert!(!app.log.healthy());
    assert_eq!(app.config.usage(), Some((0, SLOTS)));
    assert_eq!(app.log.queued_for_test(), 2);
    let (ready, connection) = send(port, "/readyz", "", "GET").await;
    assert_eq!(ready.status, if availability { 200 } else { 503 });
    ready.collect().await.unwrap(); connection.await.unwrap();
    for _ in 0..SLOTS { clients.spawn(request(port, availability)); }
    while let Some(result) = clients.join_next().await { result.unwrap(); }
    while !app.workers.is_empty() { tokio::task::yield_now().await; }
    assert_eq!(app.config.usage(), Some((0, SLOTS)));
    assert_eq!(connections.load(Ordering::Relaxed), if availability { 2 * SLOTS } else { 0 });
    assert_eq!(app.audit_gaps(), if availability { (2 * SLOTS) as u64 } else { 0 });
    assert_eq!(writes.load(Ordering::Relaxed), 1); // No replacement writer or retry.
    stop_provider.send(()).unwrap(); provider.await.unwrap();
    if shutdown_blocked {
        shutdown.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(4), gateway).await.unwrap().unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(app.workers.is_empty());
        assert_eq!(app.config.usage(), Some((0, SLOTS)));
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        assert_eq!(app.log.queued_for_test(), 2);
        assert!(!app.log.healthy());
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_err());
    } else {
        release.send(()).unwrap();
        app.log.shutdown(Duration::from_secs(1)).await.unwrap();
        shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        assert!(app.workers.is_empty());
        return;
    }
    release.send(()).unwrap();
    app.log.shutdown(Duration::from_secs(1)).await.unwrap();
    assert_eq!(writes.load(Ordering::Relaxed), 1); // Queued jobs fail after timeout.
    assert!(app.workers.is_empty());
}

async fn request(port: u16, availability: bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        let (response, connection) = send(port, "/routes/7", "gateway", "POST").await;
        let expected = if availability { 200 } else { 503 };
        assert_eq!(response.status, expected);
        let bytes = response.collect().await.unwrap();
        if availability { assert_eq!(bytes, b"complete"[..]); }
        connection.await.unwrap();
    }).await.unwrap();
}
