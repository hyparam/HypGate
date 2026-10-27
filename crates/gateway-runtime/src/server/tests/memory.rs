//! Opt-in process-isolated RSS evidence, not a whole-process memory proof.
use super::*;
use rustls::pki_types::CertificateDer;
use std::{process::{Child, Command, Stdio}, sync::atomic::AtomicBool};

const CLIENTS: usize = 8;
const RESPONSE: usize = 1024 * 1024;
struct Process(Child);
impl Drop for Process { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

#[test]
fn memory_child() {
    let Some(directory) = std::env::var_os("HYPGATE_MEMORY_CHILD") else { return; };
    let directory = std::path::PathBuf::from(directory);
    let port = std::fs::read_to_string(directory.join("upstream")).unwrap().parse().unwrap();
    let availability = std::fs::read_to_string(directory.join("mode")).unwrap() == "availability";
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(std::fs::read(directory.join("root.der")).unwrap())).unwrap();
    let app = Gateway::new(config_with_limits(port, availability, CLIENTS, 16384),
        HttpsTransport::with_roots(roots, Duration::from_secs(60)).unwrap(),
        DiskLog::create(&directory.join("audit.log"), 16, Duration::from_secs(5)).unwrap());
    let listener = StdListener::bind("127.0.0.1:0").unwrap();
    std::fs::write(directory.join("port"), listener.local_addr().unwrap().port().to_string()).unwrap();
    let stop = directory.join("stop");
    let shutdown = Shutdown::new();
    let signal = shutdown.clone();
    std::thread::spawn(move || {
        while !stop.exists() { std::thread::sleep(Duration::from_millis(20)); }
        signal.trigger();
    });
    serve(listener, app.clone(), 128, Duration::from_secs(65), &shutdown).unwrap();
    assert_eq!(app.audit_gaps(), 0); assert_eq!(app.failed_exchanges(), 0);
    assert_eq!(app.config.usage(), Some((0, CLIENTS)));
    assert!(workers_idle(&app));
}

// Linux supplies a kernel high-water mark; macOS reports only sampled RSS.
fn memory(pid: u32) -> (u64, Option<u64>) {
    if cfg!(target_os = "linux") {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let field = |name: &str| -> u64 {
            status.lines().find_map(|line| line.strip_prefix(name))
                .unwrap().split_whitespace().next().unwrap().parse::<u64>().unwrap() * 1024
        };
        (field("VmRSS:"), Some(field("VmHWM:")))
    } else {
        assert!(cfg!(target_os = "macos"), "RSS fixture supports Linux or macOS");
        let output = Command::new("ps").args(["-o", "rss=", "-p", &pid.to_string()]).output().unwrap();
        assert!(output.status.success());
        (std::str::from_utf8(&output.stdout).unwrap().trim().parse::<u64>().unwrap() * 1024, None)
    }
}

#[test]
#[ignore = "isolated gateway RSS workload; run with --ignored --nocapture"]
fn isolated_gateway_memory_in_both_logging_modes() {
    for availability in [false, true] { workload(availability, 3); }
}

#[test]
#[ignore = "long isolated gateway RSS workload; run with --ignored --nocapture"]
fn isolated_gateway_memory_soak_in_both_logging_modes() {
    for availability in [false, true] { workload(availability, 100); }
}

fn workload(availability: bool, waves: usize) {
    let started = Instant::now();
    let (cert, acceptor, _) = self_signed();
    let upstream = StdListener::bind("127.0.0.1:0").unwrap();
    let dir = TempDir::new();
    std::fs::write(dir.0.join("root.der"), cert.cert.der()).unwrap();
    std::fs::write(dir.0.join("upstream"), upstream.local_addr().unwrap().port().to_string()).unwrap();
    std::fs::write(dir.0.join("mode"), if availability { "availability" } else { "strict" }).unwrap();
    let mut child = Process(Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "server::tests::memory::memory_child", "--nocapture"])
        .env("HYPGATE_MEMORY_CHILD", &dir.0).stdout(Stdio::null()).stderr(Stdio::inherit())
        .spawn().unwrap());
    let port = loop {
        assert!(child.0.try_wait().unwrap().is_none(), "gateway child exited during startup");
        if let Ok(text) = std::fs::read_to_string(dir.0.join("port")) {
            if let Ok(port) = text.parse::<u16>() { break port; }
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let pid = child.0.id();
    let baseline = memory(pid);
    let stop_sampling = Arc::new(AtomicBool::new(false));
    let sampling = stop_sampling.clone();
    let sampler = std::thread::spawn(move || {
        let mut peak = baseline.0; let mut kernel_peak = baseline.1; let mut samples = 0;
        loop {
            let (rss, hwm) = memory(pid); peak = peak.max(rss);
            kernel_peak = match (kernel_peak, hwm) { (Some(a), Some(b)) => Some(a.max(b)), _ => None };
            samples += 1;
            if sampling.load(Ordering::Relaxed) { break; }
            std::thread::sleep(Duration::from_millis(50));
        }
        (peak, kernel_peak, samples)
    });
    let provider = std::thread::spawn(move || {
        let mut connections = Vec::new();
        for _ in 0..waves * CLIENTS {
            let mut socket = accept_tls(&upstream, &acceptor).unwrap();
            connections.push(std::thread::spawn(move || {
                let request = read_request(&mut socket).unwrap();
                assert_eq!(request.header("x-api-key"), Some("provider-secret"));
                assert_eq!(request.body, b"{\"stream\":true}");
                let mut stream = start_streaming(socket, 200, &[]).unwrap();
                for _ in 0..RESPONSE / 16384 {
                    stream.send(&[29; 16384]).unwrap();
                    std::thread::sleep(Duration::from_millis(2));
                }
                stream.finish().unwrap();
            }));
        }
        for connection in connections { connection.join().unwrap(); }
    });
    let mut settled = Vec::new();
    for _ in 0..waves {
        let clients: Vec<_> = (0..CLIENTS).map(|_| std::thread::spawn(move || {
            let mut response = send(port, "/routes/7", "gateway", "POST");
            assert_eq!(response.status, 200);
            let mut received = 0;
            while let Some(data) = response.chunk().unwrap() {
                assert!(data.iter().all(|b| *b == 29)); received += data.len();
                std::thread::sleep(Duration::from_millis(3));
            }
            assert_eq!(received, RESPONSE);
        })).collect();
        for client in clients { client.join().unwrap(); }
        std::thread::sleep(Duration::from_millis(100));
        settled.push(memory(pid).0);
    }
    provider.join().unwrap();
    let final_memory = memory(pid);
    stop_sampling.store(true, Ordering::Relaxed); let (peak, kernel_peak, samples) = sampler.join().unwrap();
    let peak = peak.max(final_memory.0);
    let kernel_peak = match (kernel_peak, final_memory.1) { (Some(a), Some(b)) => Some(a.max(b)), _ => None };
    std::fs::write(dir.0.join("stop"), b"stop").unwrap();
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() { break status; }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "gateway did not drain cleanly");
    let mut reader = LogReader::new(File::open(dir.0.join("audit.log")).unwrap()).unwrap();
    let mut totals = std::collections::BTreeMap::<u64, (usize, usize)>::new();
    while let Some(record) = reader.next_record().unwrap() {
        assert_eq!(record.tenant, 1);
        let total = totals.entry(record.request).or_default();
        match record.kind {
            crate::transfer::RecordKind::Upload => total.0 += record.bytes.len(),
            crate::transfer::RecordKind::Download => {
                assert!(record.bytes.iter().all(|b| *b == 29)); total.1 += record.bytes.len();
            }
            _ => {},
        }
    }
    assert_eq!(totals.len(), CLIENTS * waves);
    assert!(totals.values().all(|&(up, down)| up == b"{\"stream\":true}".len() && down == RESPONSE));
    println!("isolated_gateway_memory {}", json!({"availability": availability,
        "os": std::env::consts::OS, "waves":waves, "elapsed_ms":started.elapsed().as_millis(),
        "requests":CLIENTS * waves, "concurrency":CLIENTS,
        "response_bytes":RESPONSE, "baseline_rss_bytes":baseline.0, "sampled_peak_rss_bytes":peak,
        "kernel_peak_rss_bytes":kernel_peak, "settled_rss_bytes":settled, "samples":samples}));
}
