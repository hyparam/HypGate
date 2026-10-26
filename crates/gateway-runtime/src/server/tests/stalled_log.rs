use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

#[test]
fn stalled_log_under_load_preserves_health_deadlines_and_mode_policy() {
    for availability in [false, true] { exercise(availability, false); }
}

#[test]
fn shutdown_with_blocked_disk_returns_error_without_replacement_or_replay() {
    for availability in [false, true] { exercise(availability, true); }
}

fn exercise(availability: bool, shutdown_blocked: bool) {
    const SLOTS: usize = 8;
    let (upstream, acceptor, roots) = tls();
    let (log, started, release, writes) = DiskLog::stalled_for_test(2, Duration::from_secs(1));
    let app = Gateway::new(config_with_limits(upstream.local_addr().unwrap().port(), availability, SLOTS, 16384),
        HttpsTransport::with_roots(roots, Duration::from_secs(5)).unwrap(), log);
    let gateway = spawn_gateway(&app, 64, Duration::from_secs(7));
    let port = gateway.port;
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = connections.clone();
    let stop_provider = Arc::new(AtomicBool::new(false));
    let stopping = stop_provider.clone();
    let provider = std::thread::spawn(move || {
        upstream.set_nonblocking(true).unwrap();
        let mut handlers = Vec::new();
        while !stopping.load(Ordering::Relaxed) {
            let socket = match upstream.accept() {
                Ok((socket, _)) => socket,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => { std::thread::sleep(Duration::from_millis(5)); continue; }
                Err(e) => panic!("{e}"),
            };
            accepted.fetch_add(1, Ordering::Relaxed);
            let acceptor = acceptor.clone();
            handlers.push(std::thread::spawn(move || {
                let mut socket = tls_accept(socket, &acceptor);
                let request = read_request(&mut socket);
                assert!(availability, "strict mode must not connect without a start record");
                let request = request.unwrap();
                assert_eq!(request.header("x-api-key"), Some("provider-secret"));
                assert_eq!(request.body, b"{\"stream\":true}");
                write_response(&mut socket, 200, &[], b"complete").unwrap();
            }));
        }
        for handler in handlers { handler.join().unwrap(); }
    });
    // Strict mode refuses at the request-start record, before any upstream
    // connection: a stalled logger is observed at kind 2, not during the body.
    let mut clients = vec![request(port, availability)];
    started.recv_timeout(Duration::from_secs(5)).unwrap(); // The real disk worker is blocked inside sync.
    // Fill both queue slots before creating enough traffic to hit saturation.
    for queued in 1..=2 {
        clients.push(request(port, availability));
        assert!(wait_until(Duration::from_secs(3), || app.log.queued_for_test() >= queued));
    }
    assert_eq!(writes.load(Ordering::Relaxed), 1);
    for _ in 3..SLOTS { clients.push(request(port, availability)); }
    for path in ["/healthz", "/metrics"] {
        let response = send(port, path, "", "GET");
        assert_eq!(response.status, 200);
        response.collect().unwrap();
    }
    for client in clients.drain(..) { client.join().unwrap(); }
    wait_workers_idle(&app);
    assert!(!app.log.healthy());
    assert_eq!(app.config.usage(), Some((0, SLOTS)));
    assert_eq!(app.log.queued_for_test(), 2);
    let ready = send(port, "/readyz", "", "GET");
    assert_eq!(ready.status, if availability { 200 } else { 503 });
    ready.collect().unwrap();
    for _ in 0..SLOTS { clients.push(request(port, availability)); }
    for client in clients.drain(..) { client.join().unwrap(); }
    wait_workers_idle(&app);
    assert_eq!(app.config.usage(), Some((0, SLOTS)));
    assert_eq!(connections.load(Ordering::Relaxed), if availability { 2 * SLOTS } else { 0 });
    assert_eq!(app.audit_gaps(), if availability { (2 * SLOTS) as u64 } else { 0 });
    assert_eq!(writes.load(Ordering::Relaxed), 1); // No replacement writer or retry.
    stop_provider.store(true, Ordering::Relaxed); provider.join().unwrap();
    if shutdown_blocked {
        let stopped = Instant::now();
        let result = gateway.stop();
        assert!(stopped.elapsed() < Duration::from_secs(5));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(workers_idle(&app));
        assert_eq!(app.config.usage(), Some((0, SLOTS)));
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        assert_eq!(app.log.queued_for_test(), 2);
        assert!(!app.log.healthy());
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    } else {
        release.send(()).unwrap();
        app.log.shutdown(Duration::from_secs(1)).unwrap();
        gateway.stop().unwrap();
        assert_eq!(writes.load(Ordering::Relaxed), 1);
        assert!(workers_idle(&app));
        return;
    }
    release.send(()).unwrap();
    app.log.shutdown(Duration::from_secs(1)).unwrap();
    assert_eq!(writes.load(Ordering::Relaxed), 1); // Queued jobs fail after timeout.
    assert!(workers_idle(&app));
}

fn request(port: u16, availability: bool) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let response = send(port, "/routes/7", "gateway", "POST");
        let expected = if availability { 200 } else { 503 };
        assert_eq!(response.status, expected);
        let bytes = response.collect().unwrap();
        if availability { assert_eq!(bytes, b"complete"[..]); }
    })
}
