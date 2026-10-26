use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

#[test]
fn repeated_overload_preserves_active_streams_health_and_reusable_capacity() {
    for availability in [false, true] { exercise(availability, Duration::ZERO); }
}

#[test]
#[ignore = "sustained overload workload: five minutes per logging mode unless LOGGATE_OVERLOAD_SECONDS says otherwise"]
fn sustained_overload_preserves_active_streams_and_health() {
    let seconds = std::env::var("LOGGATE_OVERLOAD_SECONDS").map_or(300, |value| value.parse().expect("LOGGATE_OVERLOAD_SECONDS must be a whole number of seconds"));
    for availability in [false, true] {
        exercise(availability, Duration::from_secs(seconds));
    }
}

fn exercise(availability: bool, duration: Duration) {
    const SLOTS: usize = 8;
    const BURST: usize = 32;
    const ROUNDS: usize = 4;
    let (upstream, acceptor, roots) = tls();
    let dir = TempDir::new(); let path = dir.0.join("overload.log");
    let app = Gateway::new(config_with_limits(upstream.local_addr().unwrap().port(), availability, SLOTS, 16384),
        HttpsTransport::with_roots(roots, Duration::from_secs(360)).unwrap(),
        DiskLog::create(&path, 16, Duration::from_secs(2)).unwrap());
    let gateway = spawn_gateway(&app, 128, Duration::from_secs(365));
    let port = gateway.port;
    let release = Arc::new(AtomicBool::new(false));
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = connections.clone();
    let waiting = release.clone();
    let provider = std::thread::spawn(move || {
        let mut tasks = Vec::new();
        for _ in 0..SLOTS + 1 {
            let (socket, _) = upstream.accept().unwrap();
            accepted.fetch_add(1, Ordering::Relaxed);
            let acceptor = acceptor.clone(); let waiting = waiting.clone();
            tasks.push(std::thread::spawn(move || {
                let mut socket = tls_accept(socket, &acceptor);
                socket.sock.set_read_timeout(Some(duration + Duration::from_secs(60))).unwrap();
                let request = read_request(&mut socket).unwrap();
                assert_eq!(request.header("x-api-key"), Some("provider-secret"));
                assert_eq!(request.body, b"{\"stream\":true}");
                let mut stream = start_streaming(socket, 200, &[]).unwrap();
                stream.send(b"held").unwrap();
                while !waiting.load(Ordering::Relaxed) { std::thread::sleep(Duration::from_millis(10)); }
                stream.send(b"done").unwrap(); stream.finish().unwrap();
            }));
        }
        for task in tasks { task.join().unwrap(); }
    });
    let mut held = Vec::new();
    for _ in 0..SLOTS {
        let socket = connect(port);
        socket.set_read_timeout(Some(duration + Duration::from_secs(60))).unwrap();
        let mut response = send_request(socket, "POST", "/routes/7", &[("host", "attacker.example"), ("authorization", "Bearer gateway")], b"{\"stream\":true}").unwrap();
        assert_eq!(response.status, 200);
        let prefix = response.chunk().unwrap().unwrap();
        assert!(!prefix.is_empty()); held.push((response, prefix));
    }
    let started = Instant::now();
    let mut rounds = 0;
    let mut max_health = Duration::ZERO;
    let mut max_rejection = Duration::ZERO;
    while rounds < ROUNDS || started.elapsed() < duration {
        let round_started = Instant::now();
        assert_eq!(app.config.usage(), Some((SLOTS, SLOTS)));
        let excess: Vec<_> = (0..BURST).map(|_| std::thread::spawn(move || {
            let response = send(port, "/routes/7", "gateway", "POST");
            assert_eq!(response.status, 503);
            response.collect().unwrap();
        })).collect();
        // Check health while excess requests are in flight, not only afterward.
        for route in ["/healthz", "/readyz", "/metrics"] {
            let health_started = Instant::now();
            let response = send(port, route, "", "GET");
            assert_eq!(response.status, 200);
            response.collect().unwrap();
            max_health = max_health.max(health_started.elapsed());
        }
        for client in excess { client.join().unwrap(); }
        assert_eq!(app.config.usage(), Some((SLOTS, SLOTS)));
        assert_eq!(connections.load(Ordering::Relaxed), SLOTS);
        rounds += 1;
        max_rejection = max_rejection.max(round_started.elapsed());
        // Pace sustained arrivals while retaining all eight active streams.
        if !duration.is_zero() { std::thread::sleep(Duration::from_millis(20)); }
    }
    println!("{}", serde_json::json!({"workload":"admission_overload",
        "availability":availability, "elapsed_ms":started.elapsed().as_millis(),
        "rejected":rounds * BURST, "held_streams":SLOTS,
        "max_health_ms":max_health.as_secs_f64() * 1000.0,
        "max_rejection_wave_ms":max_rejection.as_secs_f64() * 1000.0}));
    release.store(true, Ordering::Relaxed);
    for (response, prefix) in held {
        let mut bytes = prefix.to_vec(); bytes.extend_from_slice(&response.collect().unwrap());
        assert_eq!(bytes, b"helddone");
    }
    wait_workers_idle(&app);
    assert_eq!(app.config.usage(), Some((0, SLOTS)));
    // A fresh generation must succeed after all overloaded waves drain.
    let response = send(port, "/routes/7", "gateway", "POST");
    assert_eq!(response.status, 200);
    assert_eq!(response.collect().unwrap(), b"helddone"[..]);
    provider.join().unwrap();
    wait_workers_idle(&app);
    gateway.stop().unwrap();
    assert_eq!(app.config.usage(), Some((0, SLOTS))); assert!(workers_idle(&app));
    assert_eq!(app.failed_exchanges(), 0); assert_eq!(app.audit_gaps(), 0);
    let mut scanner = LogReader::new(File::open(path).unwrap()).unwrap();
    let mut records = std::collections::BTreeMap::<u64, (Vec<u8>, Vec<u8>)>::new();
    while let Some(record) = scanner.next_record().unwrap() {
        assert_eq!(record.tenant, 1);
        let entry = records.entry(record.request).or_default();
        match record.kind {
            crate::transfer::RecordKind::Upload => entry.0.extend(record.bytes),
            crate::transfer::RecordKind::Download => entry.1.extend(record.bytes),
            _ => {},
        }
    }
    assert_eq!(records.len(), SLOTS + 1);
    for (upload, download) in records.values() {
        assert_eq!(upload, b"{\"stream\":true}"); assert_eq!(download, b"helddone");
    }
}
