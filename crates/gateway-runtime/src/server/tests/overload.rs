use super::*;

#[tokio::test]
async fn repeated_overload_preserves_active_streams_health_and_reusable_capacity() {
    tokio::time::timeout(Duration::from_secs(30), async {
        for availability in [false, true] { exercise(availability, Duration::ZERO).await; }
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "sustained overload workload: five minutes per logging mode unless SOUNDGATE_OVERLOAD_SECONDS says otherwise"]
async fn sustained_overload_preserves_active_streams_and_health() {
    let seconds = std::env::var("SOUNDGATE_OVERLOAD_SECONDS").map_or(300, |value| value.parse().expect("SOUNDGATE_OVERLOAD_SECONDS must be a whole number of seconds"));
    tokio::time::timeout(Duration::from_secs(2 * seconds + 60), async {
        for availability in [false, true] {
            exercise(availability, Duration::from_secs(seconds)).await;
        }
    }).await.unwrap();
}

async fn exercise(availability: bool, duration: Duration) {
    const SLOTS: usize = 8;
    const BURST: usize = 32;
    const ROUNDS: usize = 4;
    let (upstream, acceptor, roots) = tls().await;
    let dir = TempDir::new(); let path = dir.0.join("overload.log");
    let app = Gateway::new(config_with_limits(upstream.local_addr().unwrap().port(), availability, SLOTS, 16384),
        HttpsTransport::with_roots(roots, Duration::from_secs(360)).unwrap(),
        DiskLog::create(&path, 16, Duration::from_secs(2)).unwrap());
    let (port, shutdown, gateway) = spawn_gateway(&app, 128, Duration::from_secs(365)).await;
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
    let started = std::time::Instant::now();
    let mut rounds = 0;
    let mut max_health = Duration::ZERO;
    let mut max_rejection = Duration::ZERO;
    while rounds < ROUNDS || started.elapsed() < duration {
        let round_started = std::time::Instant::now();
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
            let health_started = std::time::Instant::now();
            let (response, connection) = send(port, route, "", "GET").await;
            assert_eq!(response.status(), StatusCode::OK);
            response.collect().await.unwrap(); connection.await.unwrap();
            max_health = max_health.max(health_started.elapsed());
        }
        while let Some(result) = excess.join_next().await { result.unwrap(); }
        assert_eq!(app.config.usage(), Some((SLOTS, SLOTS)));
        assert_eq!(connections.load(Ordering::Relaxed), SLOTS);
        rounds += 1;
        max_rejection = max_rejection.max(round_started.elapsed());
        // Pace sustained arrivals while retaining all eight active streams.
        if !duration.is_zero() { tokio::time::sleep(Duration::from_millis(20)).await; }
    }
    println!("{}", serde_json::json!({"workload":"admission_overload",
        "availability":availability, "elapsed_ms":started.elapsed().as_millis(),
        "rejected":rounds * BURST, "held_streams":SLOTS,
        "max_health_ms":max_health.as_secs_f64() * 1000.0,
        "max_rejection_wave_ms":max_rejection.as_secs_f64() * 1000.0}));
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
