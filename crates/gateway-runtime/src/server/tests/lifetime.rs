//! Regression coverage for the runtime bindings of deadline and scope proofs.
use super::*;

#[test]
fn stalled_upload_obeys_exchange_deadline() {
    let (upstream, acceptor, roots) = tls();
    let dir = TempDir::new();
    let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
        HttpsTransport::with_roots(roots, Duration::from_millis(150)).unwrap(),
        DiskLog::create(&dir.0.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
    let gateway = spawn_gateway(&app, 4, Duration::from_secs(5));
    let (sent, received) = mpsc::channel();
    let provider = std::thread::spawn(move || {
        let mut socket = accept_tls(&upstream, &acceptor).unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).unwrap(), 1);
            request.push(byte[0]);
        }
        sent.send(()).unwrap();
        let _ = socket.read(&mut [0]);
    });
    let mut client = connect(gateway.port);
    client.write_all(b"POST /routes/7 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer gateway\r\nContent-Length: 10\r\n\r\n").unwrap();
    received.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::sleep(Duration::from_millis(800));
    let released = workers_idle(&app);
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 504"), "{:?}", String::from_utf8_lossy(&response));
    drop(client);
    provider.join().unwrap();
    gateway.stop().unwrap();
    assert!(released, "request still holds worker 800ms after a 150ms exchange deadline");
}

#[test]
fn connection_setup_failure_releases_tracking() {
    if std::env::var_os("HYPGATE_FD_EXHAUSTION_CHILD").is_none() {
        let status = std::process::Command::new("sh")
            .args(["-c", "ulimit -n 128; exec \"$1\" --exact server::tests::lifetime::connection_setup_failure_releases_tracking --nocapture", "hypgate-test"])
            .arg(std::env::current_exe().unwrap())
            .env("HYPGATE_FD_EXHAUSTION_CHILD", "1").status().unwrap();
        assert!(status.success());
        return;
    }
    let (upstream, _, roots) = tls();
    let dir = TempDir::new();
    let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
        HttpsTransport::with_roots(roots, Duration::from_secs(1)).unwrap(),
        DiskLog::create(&dir.0.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
    for spare in 0..=2 {
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (socket, _) = listener.accept().unwrap();
        let mut files = Vec::new();
        while let Ok(file) = File::open("/dev/null") { files.push(file); assert!(files.len() < 1024); }
        // Fail the cancellation clone, writer clone, then watcher clone.
        for _ in 0..spare { files.pop(); }
        let result = serve_connection(socket, app.clone(), Duration::from_secs(1));
        drop(files);
        assert!(result.is_err());
        assert_eq!(app.live.lock().unwrap().len(), 0, "failed setup remains tracked");
        peer.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0, "failed setup kept its socket open");
    }
    app.log.shutdown(Duration::from_secs(2)).unwrap();
}

#[test]
fn unwinding_drops_registration_and_registered_sockets() {
    let (upstream, _, roots) = tls();
    let dir = TempDir::new();
    let app = Gateway::new(config(upstream.local_addr().unwrap().port(), false),
        HttpsTransport::with_roots(roots, Duration::from_secs(1)).unwrap(),
        DiskLog::create(&dir.0.join("audit.log"), 4, Duration::from_secs(2)).unwrap());
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (socket, _) = listener.accept().unwrap();
    let cancel = Cancel::new();
    cancel.watch_socket(&socket).unwrap();
    let id = app.track(&cancel);
    let scope = ConnectionScope { app: app.clone(), cancel, id: Some(id), socket: Some(socket),
        deadline: Deadline::start(Duration::from_secs(1)).unwrap() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _scope = scope;
        panic!("injected setup panic");
    }));
    assert!(result.is_err());
    assert!(app.live.lock().unwrap().is_empty());
    peer.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    app.log.shutdown(Duration::from_secs(2)).unwrap();
}
