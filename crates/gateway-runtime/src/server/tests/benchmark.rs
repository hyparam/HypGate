//! Opt-in local workload; results include fixture and client overhead.
use super::*;

const REQUESTS: usize = 32;
const CONCURRENCY: usize = 8;
const UPLOAD: usize = 8 * 1024;
const DOWNLOAD: usize = 64 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Workload { Healthy, SlowPeers, FailedLog }

async fn benchmark(availability: bool, workload: Workload) {
    tokio::time::timeout(Duration::from_secs(120), async {
        let slow = workload == Workload::SlowPeers;
        let download_bytes = if slow { 4 * 1024 * 1024 } else { DOWNLOAD };
        let failed_log = workload == Workload::FailedLog;
        let forwarded = if failed_log && !availability { CONCURRENCY } else { REQUESTS };
        let cert = generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut roots = RootCertStore::empty(); roots.add(cert.cert.der().clone()).unwrap();
        let tls = ServerConfig::builder().with_no_client_auth().with_single_cert(vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into()).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(tls));
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let routes = json!([{"tenant":1,"selector":7,"origin":0,"credential":0}]);
        let root = json!({"identities":[{"tenant":1,"sha256":format!("{:x}",Sha256::digest(b"gateway"))}],
            "destinations":[format!("https://localhost:{}/v1/messages", upstream.local_addr().unwrap().port())],
            "credentials":[{"tenant":1,"kind":"api_key","env":"KEY"}],"grants":routes,
            "limits":{"requests":CONCURRENCY,"chunk_bytes":16384},
            "logging":if availability { "availability" } else { "strict" }});
        let config = GatewayConfig::from_json(&serde_json::to_vec(&root).unwrap(),
            &serde_json::to_vec(&json!({"routes":routes})).unwrap(), |_| Some("fixture-key".into())).unwrap();
        let dir = TempDir::new(); let path = dir.0.join("benchmark.log");
        let app = Gateway::new(config, HttpsTransport::with_roots(roots, Duration::from_secs(60)).unwrap(),
            DiskLog::create(&path, 16, Duration::from_secs(2)).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap(); let port = listener.local_addr().unwrap().port();
        let (shutdown, stopped) = oneshot::channel();
        let gateway = tokio::spawn(serve(listener, app.clone(), 128, Duration::from_secs(65), async { let _ = stopped.await; }));
        let provider = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            for _ in 0..forwarded {
                let (socket, _) = upstream.accept().await.unwrap(); let acceptor = acceptor.clone();
                connections.spawn(async move {
                    let socket = acceptor.accept(socket).await.unwrap();
                    let service = service_fn(move |request: Request<Incoming>| async move {
                        assert_eq!(request.headers()["x-api-key"], "fixture-key");
                        assert_eq!(request.collect().await.unwrap().to_bytes(), vec![17; UPLOAD]);
                        let (mut writer, body) = http_body::channel(16384);
                        tokio::spawn(async move {
                            for _ in 0..download_bytes / 16384 {
                                if slow { tokio::time::sleep(Duration::from_millis(2)).await; }
                                writer.write_all(&[29; 16384]).await.unwrap();
                            }
                            writer.shutdown().await.unwrap();
                        });
                        Ok::<_, Infallible>(Response::new(body))
                    });
                    hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await.unwrap();
                });
            }
            while let Some(result) = connections.join_next().await { result.unwrap(); }
        });
        let peak = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (stop_sampling, sampling_done) = oneshot::channel();
        let sample_app = app.clone(); let sample_peak = peak.clone();
        let sampler = tokio::spawn(async move {
            tokio::pin!(sampling_done);
            loop {
                let (active, limit) = sample_app.config.usage().unwrap();
                assert_eq!(limit, CONCURRENCY); assert!(active <= limit);
                sample_peak.fetch_max(active, Ordering::Relaxed);
                tokio::select! {
                    _ = &mut sampling_done => break,
                    _ = tokio::time::sleep(Duration::from_millis(1)) => {},
                }
            }
        });
        let start = tokio::time::Instant::now();
        let mut rejected = 0;
        let mut latencies = Vec::new(); let mut first_bytes = Vec::new();
        // Fixed closed-loop batches: queueing outside these eight clients is not
        // included. This is a reproducible baseline, not an overload experiment.
        for batch in 0..REQUESTS / CONCURRENCY {
            if failed_log && batch == 1 { app.log.inject_failure(); }
            let expect_rejection = failed_log && batch >= 1 && !availability;
            let mut clients = JoinSet::new();
            for _ in 0..CONCURRENCY {
                clients.spawn(async move {
                    let start = tokio::time::Instant::now();
                    let socket = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(socket)).await.unwrap();
                    let connection = tokio::spawn(async move { connection.await.unwrap(); });
                    let request = Request::builder().method("POST").uri("/routes/7").header("host", "localhost")
                        .header("authorization", "Bearer gateway").body(Full::new(Bytes::from(vec![17; UPLOAD]))).unwrap();
                    let mut response = sender.send_request(request).await.unwrap();
                    if expect_rejection {
                        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                        response.collect().await.unwrap(); connection.await.unwrap();
                        return None;
                    }
                    assert_eq!(response.status(), StatusCode::OK);
                    let first = response.body_mut().frame().await.unwrap().unwrap().into_data().unwrap();
                    assert!(!first.is_empty());
                    let first_byte = start.elapsed().as_secs_f64() * 1000.;
                    assert!(first.iter().all(|b| *b == 29));
                    let mut received = first.len();
                    loop {
                        if slow { tokio::time::sleep(Duration::from_millis(5)).await; }
                        let Some(frame) = response.body_mut().frame().await else { break; };
                        let bytes = frame.unwrap().into_data().unwrap();
                        assert!(bytes.iter().all(|b| *b == 29)); received += bytes.len();
                    }
                    assert_eq!(received, download_bytes);
                    let elapsed = start.elapsed().as_secs_f64() * 1000.;
                    connection.await.unwrap(); Some((first_byte, elapsed))
                });
            }
            while let Some(result) = clients.join_next().await {
                if let Some((first, elapsed)) = result.unwrap() {
                    first_bytes.push(first); latencies.push(elapsed);
                } else { rejected += 1; }
            }
            // Successful client EOF can precede final worker bookkeeping.
            while !app.workers.is_empty() { tokio::task::yield_now().await; }
        }
        let elapsed = start.elapsed().as_secs_f64();
        stop_sampling.send(()).unwrap(); sampler.await.unwrap();
        assert_eq!(app.config.usage(), Some((0, CONCURRENCY)));
        assert_eq!(rejected, REQUESTS - forwarded);
        provider.await.unwrap(); shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
        assert!(app.workers.is_empty()); assert_eq!(app.audit_gaps(), if failed_log && availability { (REQUESTS - CONCURRENCY) as u64 } else { 0 }); assert_eq!(app.failed_exchanges(), 0);
        let mut scanner = LogReader::new(File::open(&path).unwrap()).unwrap();
        let mut totals = std::collections::BTreeMap::<u64, (usize, usize)>::new();
        while let Some(record) = scanner.next_record().unwrap() {
            let entry = totals.entry(record.request).or_default();
            match record.direction {
                crate::transfer::Direction::Upload => entry.0 += record.bytes.len(),
                crate::transfer::Direction::Download => entry.1 += record.bytes.len(),
            }
        }
        assert_eq!(totals.len(), if failed_log { CONCURRENCY } else { REQUESTS });
        assert!(totals.values().all(|total| *total == (UPLOAD, download_bytes)));
        first_bytes.sort_by(f64::total_cmp); latencies.sort_by(f64::total_cmp);
        let percentile = |values: &[f64], percent: usize| values[(values.len() * percent).div_ceil(100) - 1];
        println!("{}", json!({"benchmark":"local_tls_disk", "workload":match workload { Workload::Healthy => "healthy", Workload::SlowPeers => "slow_peers", Workload::FailedLog => "failed_log" }, "mode":if availability { "availability" } else { "strict" },
            "requests":REQUESTS, "concurrency":CONCURRENCY, "upload_bytes":UPLOAD, "download_bytes":download_bytes, "forwarded":forwarded, "rejected":rejected,
            "peak_active_sampled":peak.load(Ordering::Relaxed), "audit_gaps":app.audit_gaps(),
            "elapsed_seconds":elapsed, "requests_per_second":REQUESTS as f64 / elapsed, "forwarded_per_second":forwarded as f64 / elapsed,
            "first_byte_p50_ms":percentile(&first_bytes, 50), "first_byte_p95_ms":percentile(&first_bytes, 95),
            "complete_p50_ms":percentile(&latencies, 50), "complete_p95_ms":percentile(&latencies, 95),
            "audit_file_bytes":std::fs::metadata(path).unwrap().len()}));
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "local benchmark; run in release mode with --ignored --nocapture --test-threads=1"]
async fn strict_tls_disk() { benchmark(false, Workload::Healthy).await; }

#[tokio::test]
#[ignore = "local benchmark; run in release mode with --ignored --nocapture --test-threads=1"]
async fn availability_tls_disk() { benchmark(true, Workload::Healthy).await; }


#[tokio::test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
async fn strict_slow_peers() { benchmark(false, Workload::SlowPeers).await; }
#[tokio::test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
async fn availability_slow_peers() { benchmark(true, Workload::SlowPeers).await; }
#[tokio::test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
async fn strict_failed_log() { benchmark(false, Workload::FailedLog).await; }
#[tokio::test]
#[ignore = "local workload; run in release mode with --ignored --nocapture --test-threads=1"]
async fn availability_failed_log() { benchmark(true, Workload::FailedLog).await; }
