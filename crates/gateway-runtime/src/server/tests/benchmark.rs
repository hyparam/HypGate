//! Opt-in local workload; results include fixture and client overhead.
use super::*;

const REQUESTS: usize = 32;
const CONCURRENCY: usize = 8;
const UPLOAD: usize = 8 * 1024;
const DOWNLOAD: usize = 64 * 1024;

async fn benchmark(availability: bool) {
    tokio::time::timeout(Duration::from_secs(120), async {
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
            for _ in 0..REQUESTS {
                let (socket, _) = upstream.accept().await.unwrap(); let acceptor = acceptor.clone();
                connections.spawn(async move {
                    let socket = acceptor.accept(socket).await.unwrap();
                    let service = service_fn(|request: Request<Incoming>| async move {
                        assert_eq!(request.headers()["x-api-key"], "fixture-key");
                        assert_eq!(request.collect().await.unwrap().to_bytes(), vec![17; UPLOAD]);
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(vec![29; DOWNLOAD]))))
                    });
                    hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await.unwrap();
                });
            }
            while let Some(result) = connections.join_next().await { result.unwrap(); }
        });
        let start = tokio::time::Instant::now();
        let mut latencies = Vec::new(); let mut first_bytes = Vec::new();
        // Fixed closed-loop batches: queueing outside these eight clients is not
        // included. This is a reproducible baseline, not an overload experiment.
        for _ in 0..REQUESTS / CONCURRENCY {
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
                    assert_eq!(response.status(), StatusCode::OK);
                    let first = response.body_mut().frame().await.unwrap().unwrap().into_data().unwrap();
                    assert!(!first.is_empty());
                    let first_byte = start.elapsed().as_secs_f64() * 1000.;
                    let mut bytes = first.to_vec(); bytes.extend_from_slice(&response.collect().await.unwrap().to_bytes());
                    assert_eq!(bytes, vec![29; DOWNLOAD]);
                    let elapsed = start.elapsed().as_secs_f64() * 1000.;
                    connection.await.unwrap(); (first_byte, elapsed)
                });
            }
            while let Some(result) = clients.join_next().await {
                let (first, elapsed) = result.unwrap(); first_bytes.push(first); latencies.push(elapsed);
            }
            // Successful client EOF can precede final worker bookkeeping.
            while !app.workers.is_empty() { tokio::task::yield_now().await; }
        }
        let elapsed = start.elapsed().as_secs_f64();
        provider.await.unwrap(); shutdown.send(()).unwrap(); gateway.await.unwrap().unwrap();
        assert!(app.workers.is_empty()); assert_eq!(app.audit_gaps(), 0); assert_eq!(app.failed_exchanges(), 0);
        let mut scanner = LogReader::new(File::open(&path).unwrap()).unwrap();
        let mut totals = std::collections::BTreeMap::<u64, (usize, usize)>::new();
        while let Some(record) = scanner.next_record().unwrap() {
            let entry = totals.entry(record.request).or_default();
            match record.direction {
                crate::transfer::Direction::Upload => entry.0 += record.bytes.len(),
                crate::transfer::Direction::Download => entry.1 += record.bytes.len(),
            }
        }
        assert_eq!(totals.len(), REQUESTS);
        assert!(totals.values().all(|total| *total == (UPLOAD, DOWNLOAD)));
        first_bytes.sort_by(f64::total_cmp); latencies.sort_by(f64::total_cmp);
        let percentile = |values: &[f64], percent: usize| values[(values.len() * percent).div_ceil(100) - 1];
        println!("{}", json!({"benchmark":"local_tls_disk", "mode":if availability { "availability" } else { "strict" },
            "requests":REQUESTS, "concurrency":CONCURRENCY, "upload_bytes":UPLOAD, "download_bytes":DOWNLOAD,
            "elapsed_seconds":elapsed, "requests_per_second":REQUESTS as f64 / elapsed,
            "first_byte_p50_ms":percentile(&first_bytes, 50), "first_byte_p95_ms":percentile(&first_bytes, 95),
            "complete_p50_ms":percentile(&latencies, 50), "complete_p95_ms":percentile(&latencies, 95),
            "audit_file_bytes":std::fs::metadata(path).unwrap().len()}));
    }).await.unwrap();
}

#[tokio::test]
#[ignore = "local benchmark; run in release mode with --ignored --nocapture --test-threads=1"]
async fn strict_tls_disk() { benchmark(false).await; }

#[tokio::test]
#[ignore = "local benchmark; run in release mode with --ignored --nocapture --test-threads=1"]
async fn availability_tls_disk() { benchmark(true).await; }
