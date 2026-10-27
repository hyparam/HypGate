//! Opt-in local workloads; results include fixture and client overhead.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize};

const REQUESTS: usize = 32;
const CONCURRENCY: usize = 8;
const UPLOAD: usize = 8 * 1024;
const DOWNLOAD: usize = 64 * 1024;
const PIECE: usize = 16384;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Workload { Healthy, SlowPeers, FailedLog, ConcurrencySweep, LongStreams, LargeUploads, QueueContention }

impl Workload {
    fn name(self) -> &'static str {
        match self {
            Self::Healthy => "healthy", Self::SlowPeers => "slow_peers", Self::FailedLog => "failed_log",
            Self::ConcurrencySweep => "concurrency_sweep", Self::LongStreams => "long_streams",
            Self::LargeUploads => "large_uploads", Self::QueueContention => "queue_contention",
        }
    }
}

enum Outcome { Complete(f64, f64, Vec<f64>), Rejected }

/// One closed-loop run: `requests / concurrency` batches of `concurrency` clients.
#[derive(Clone, Copy)]
struct Profile {
    workload: Workload, requests: usize, concurrency: usize, upload: usize, download: usize,
    /// Provider delay before each 16 KiB piece; client delay between body frames.
    provider_pace_ms: u64, client_pace_ms: u64, repeat: usize, timeout_secs: u64,
}

impl Profile {
    fn baseline(workload: Workload) -> Self {
        let slow = workload == Workload::SlowPeers;
        Self { workload, requests: REQUESTS, concurrency: CONCURRENCY, upload: UPLOAD,
            download: if slow { 4 * 1024 * 1024 } else { DOWNLOAD }, provider_pace_ms: if slow { 2 } else { 0 },
            client_pace_ms: if slow { 5 } else { 0 }, repeat: 0, timeout_secs: 120 }
    }
}

fn benchmark(availability: bool, profile: Profile) {
    let Profile { workload, requests, concurrency, upload, download, provider_pace_ms, client_pace_ms, timeout_secs, .. } = profile;
    assert!(requests % concurrency == 0 && download % PIECE == 0);
    let failed_log = workload == Workload::FailedLog;
    let forwarded = if failed_log && !availability { concurrency } else { requests };
    let (upstream, acceptor, roots) = tls();
    let routes = json!([{"tenant":1,"selector":7,"origin":0,"credential":0}]);
    let root = json!({"identities":[{"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"gateway"))}],
        "destinations":[format!("https://localhost:{}/v1/messages", upstream.local_addr().unwrap().port())],
        "credentials":[{"tenant":1,"kind":"api_key","env":"KEY"}],"grants":routes,
        "limits":{"requests":concurrency,"chunk_bytes":16384},
        "logging":if availability { "availability" } else { "strict" }});
    let config = GatewayConfig::from_json(&serde_json::to_vec(&root).unwrap(),
        |_| Some("fixture-key".into())).unwrap();
    let dir = TempDir::new(); let path = dir.0.join("benchmark.log");
    let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(300)).unwrap(),
        DiskLog::create(&path, 16, Duration::from_secs(2)).unwrap());
    let gateway = spawn_gateway(&app, 128, Duration::from_secs(310));
    let port = gateway.port;
    let provider = std::thread::spawn(move || {
        let mut connections = Vec::new();
        for _ in 0..forwarded {
            let mut socket = accept_tls(&upstream, &acceptor).unwrap();
            socket.sock.set_write_timeout(Some(Duration::from_secs(timeout_secs))).unwrap();
            connections.push(std::thread::spawn(move || {
                let request = read_request(&mut socket).unwrap();
                assert_eq!(request.header("x-api-key"), Some("fixture-key"));
                assert_eq!(request.body.len(), upload); assert!(request.body.iter().all(|b| *b == 17));
                let mut stream = start_streaming(socket, 200, &[]).unwrap();
                for _ in 0..download / PIECE {
                    if provider_pace_ms > 0 { std::thread::sleep(Duration::from_millis(provider_pace_ms)); }
                    stream.send(&[29; PIECE]).unwrap();
                }
                stream.finish().unwrap();
            }));
        }
        for connection in connections { connection.join().unwrap(); }
    });
    let peak = Arc::new(AtomicUsize::new(0));
    let stop_sampling = Arc::new(AtomicBool::new(false));
    let sample_app = app.clone(); let sample_peak = peak.clone(); let sampling = stop_sampling.clone();
    let sampler = std::thread::spawn(move || {
        while !sampling.load(Ordering::Relaxed) {
            let (active, limit) = sample_app.config.usage().unwrap();
            assert_eq!(limit, concurrency); assert!(active <= limit);
            sample_peak.fetch_max(active, Ordering::Relaxed);
            std::thread::sleep(Duration::from_millis(1));
        }
    });
    let start = Instant::now();
    let mut rejected = 0;
    let mut latencies = Vec::new(); let mut first_bytes = Vec::new(); let mut gaps = Vec::new();
    // Fixed closed-loop batches: queueing outside these clients is not
    // included. This is a reproducible workload, not an overload experiment.
    for batch in 0..requests / concurrency {
        if failed_log && batch == 1 { app.log.inject_failure(); }
        let expect_rejection = failed_log && batch >= 1 && !availability;
        let clients: Vec<_> = (0..concurrency).map(|_| std::thread::spawn(move || {
            let start = Instant::now();
            let socket = connect(port);
            socket.set_read_timeout(Some(Duration::from_secs(timeout_secs))).unwrap();
            let body = vec![17u8; upload];
            let mut response = send_request(socket, "POST", "/routes/7", &[("host", "localhost"), ("authorization", "Bearer gateway")], &body).unwrap();
            if expect_rejection {
                assert_eq!(response.status, 503);
                response.collect().unwrap();
                return Outcome::Rejected;
            }
            assert_eq!(response.status, 200);
            let first = response.chunk().unwrap().unwrap();
            assert!(!first.is_empty());
            let first_byte = start.elapsed().as_secs_f64() * 1000.;
            assert!(first.iter().all(|b| *b == 29));
            let mut received = first.len(); let mut previous = Instant::now();
            let mut frame_gaps = Vec::new();
            loop {
                if client_pace_ms > 0 { std::thread::sleep(Duration::from_millis(client_pace_ms)); }
                let Some(bytes) = response.chunk().unwrap() else { break; };
                let now = Instant::now();
                frame_gaps.push((now - previous).as_secs_f64() * 1000.); previous = now;
                assert!(bytes.iter().all(|b| *b == 29)); received += bytes.len();
            }
            assert_eq!(received, download);
            let elapsed = start.elapsed().as_secs_f64() * 1000.;
            Outcome::Complete(first_byte, elapsed, frame_gaps)
        })).collect();
        for client in clients {
            match client.join().unwrap() {
                Outcome::Complete(first, elapsed, frame_gaps) => {
                    first_bytes.push(first); latencies.push(elapsed); gaps.extend(frame_gaps);
                }
                Outcome::Rejected => rejected += 1,
            }
        }
        // Successful client EOF can precede final worker bookkeeping.
        wait_workers_idle(&app);
    }
    let elapsed = start.elapsed().as_secs_f64();
    stop_sampling.store(true, Ordering::Relaxed); sampler.join().unwrap();
    assert_eq!(app.config.usage(), Some((0, concurrency)));
    assert_eq!(rejected, requests - forwarded);
    provider.join().unwrap(); gateway.stop().unwrap();
    assert!(workers_idle(&app));
    let completed = latencies.len();
    assert_eq!(completed, forwarded);
    assert_eq!(app.audit_gaps(), if failed_log && availability { (requests - concurrency) as u64 } else { 0 });
    assert_eq!(app.failed_exchanges(), 0);
    let mut scanner = LogReader::new(File::open(&path).unwrap()).unwrap();
    let mut totals = std::collections::BTreeMap::<u64, (usize, usize)>::new();
    while let Some(record) = scanner.next_record().unwrap() {
        let entry = totals.entry(record.request).or_default();
        match record.kind {
            crate::transfer::RecordKind::Upload => entry.0 += record.bytes.len(),
            crate::transfer::RecordKind::Download => entry.1 += record.bytes.len(),
            _ => {},
        }
    }
    assert_eq!(totals.len(), if failed_log { concurrency } else { requests });
    assert!(totals.values().all(|total| *total == (upload, download)));
    first_bytes.sort_by(f64::total_cmp); latencies.sort_by(f64::total_cmp); gaps.sort_by(f64::total_cmp);
    let percentile = |values: &[f64], percent: usize| values[(values.len() * percent).div_ceil(100) - 1];
    let payload = completed as f64 * (upload + download) as f64;
    let percentile_or_zero = |values: &[f64], percent: usize| if values.is_empty() { 0. } else { percentile(values, percent) };
    println!("{}", json!({"benchmark":"local_tls_disk", "workload":workload.name(), "repeat":profile.repeat,
        "mode":if availability { "availability" } else { "strict" },
        "requests":requests, "concurrency":concurrency, "upload_bytes":upload, "download_bytes":download,
        "provider_pace_ms":provider_pace_ms, "client_pace_ms":client_pace_ms, "forwarded":forwarded, "rejected":rejected,
        "completed":completed, "failed_exchanges":app.failed_exchanges(), "logged_requests":totals.len(),
        "peak_active_sampled":peak.load(Ordering::Relaxed), "audit_gaps":app.audit_gaps(),
        "elapsed_seconds":elapsed, "requests_per_second":requests as f64 / elapsed, "forwarded_per_second":forwarded as f64 / elapsed,
        "payload_mib_per_second":payload / elapsed / (1024. * 1024.),
        "first_byte_p50_ms":percentile_or_zero(&first_bytes, 50), "first_byte_p95_ms":percentile_or_zero(&first_bytes, 95),
        "complete_p50_ms":percentile_or_zero(&latencies, 50), "complete_p95_ms":percentile_or_zero(&latencies, 95),
        "complete_max_ms":percentile_or_zero(&latencies, 100),
        "frame_gap_p50_ms":percentile_or_zero(&gaps, 50), "frame_gap_p99_ms":percentile_or_zero(&gaps, 99), "frame_gap_max_ms":percentile_or_zero(&gaps, 100),
        "frames":gaps.len() + completed, "audit_file_bytes":std::fs::metadata(path).unwrap().len()}));
}

/// Concurrency levels one through 32 with four batches each, repeated three
/// times, to report throughput and latency scaling with run-to-run variation.
/// Above 16, appends wait for one of the 16 audit queue slots.
fn concurrency_sweep(availability: bool) {
    for repeat in 0..3 {
        for concurrency in [1, 2, 4, 8, 16, 32] {
            benchmark(availability, Profile { workload: Workload::ConcurrencySweep, requests: 4 * concurrency, concurrency,
                upload: UPLOAD, download: DOWNLOAD, provider_pace_ms: 0, client_pace_ms: 0, repeat, timeout_secs: 120 });
        }
    }
}

/// 128 requests at 32 concurrent against the 16-record audit queue: every
/// append beyond the queue depth waits for a slot, so all requests must complete
/// exactly, with no failed exchange and no audit gap, in both modes.
fn queue_contention(availability: bool) {
    benchmark(availability, Profile { workload: Workload::QueueContention, requests: 128, concurrency: 32, upload: UPLOAD,
        download: DOWNLOAD, provider_pace_ms: 0, client_pace_ms: 0, repeat: 0, timeout_secs: 120 });
}

/// Eight concurrent 32 MiB responses paced at 16 KiB per 15 ms: roughly half a
/// minute per stream, with client-observed inter-frame gaps reported.
fn long_streams(availability: bool) {
    benchmark(availability, Profile { workload: Workload::LongStreams, requests: 8, concurrency: 8, upload: UPLOAD,
        download: 32 * 1024 * 1024, provider_pace_ms: 15, client_pace_ms: 0, repeat: 0, timeout_secs: 300 });
}

/// 1 MiB uploads with 16 KiB responses: 64 strict audit records per request body.
fn large_uploads(availability: bool) {
    benchmark(availability, Profile { workload: Workload::LargeUploads, requests: REQUESTS, concurrency: CONCURRENCY,
        upload: 1024 * 1024, download: PIECE, provider_pace_ms: 0, client_pace_ms: 0, repeat: 0, timeout_secs: 300 });
}

#[test]
#[ignore = "local benchmark; run in release mode with --ignored --nocapture --test-threads=1"]
fn strict_tls_disk() { benchmark(false, Profile::baseline(Workload::Healthy)); }

#[test]
#[ignore = "local benchmark; run in release mode with --ignored --nocapture --test-threads=1"]
fn availability_tls_disk() { benchmark(true, Profile::baseline(Workload::Healthy)); }

#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn strict_slow_peers() { benchmark(false, Profile::baseline(Workload::SlowPeers)); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn availability_slow_peers() { benchmark(true, Profile::baseline(Workload::SlowPeers)); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn strict_failed_log() { benchmark(false, Profile::baseline(Workload::FailedLog)); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn availability_failed_log() { benchmark(true, Profile::baseline(Workload::FailedLog)); }

#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn strict_concurrency_sweep() { concurrency_sweep(false); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn availability_concurrency_sweep() { concurrency_sweep(true); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn strict_queue_contention() { queue_contention(false); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn availability_queue_contention() { queue_contention(true); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn strict_long_streams() { long_streams(false); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn availability_long_streams() { long_streams(true); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn strict_large_uploads() { large_uploads(false); }
#[test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
fn availability_large_uploads() { large_uploads(true); }
