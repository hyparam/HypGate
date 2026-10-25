#![deny(clippy::disallowed_methods)]
use gateway_runtime::{config::GatewayConfig, disk_log::{DiskLog, LogReader, Metadata, ScanError, StoredRecord}, server::{self, Gateway},
    shipping::{self, Shipper, ShippingConfig}, transport::HttpsTransport};
use std::{io::{self, Read, Write}, net::SocketAddr, path::Path, time::Duration};

// Effect site: secrets come only from the environment variables the root
// policy names, read once at startup.
#[allow(clippy::disallowed_methods)]
fn secret(name: &str) -> Option<String> { std::env::var(name).ok() }

// Effect site: the one listening socket.
#[allow(clippy::disallowed_methods)]
async fn bind(address: SocketAddr) -> io::Result<tokio::net::TcpListener> { tokio::net::TcpListener::bind(address).await }

fn bounded_file(path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(message) = run().await { eprintln!("soundgate: {message}"); std::process::exit(1); }
}
async fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("scan") {
        if args.len() != 3 { return Err("usage: soundgate scan LOG"); }
        return scan(&args[2]);
    }
    if args.get(1).map(String::as_str) == Some("ship") {
        if args.len() != 4 { return Err("usage: soundgate ship ROOT.json LOG"); }
        return ship(&args[2], &args[3]);
    }
    if !(4..=5).contains(&args.len()) { return Err("usage: soundgate ROOT.json ROUTES.json NEW_LOG [127.0.0.1:8080]"); }
    let address: SocketAddr = args.get(4).map(String::as_str).unwrap_or("127.0.0.1:8080").parse().map_err(|_| "invalid listen address")?;
    if !address.ip().is_loopback() { return Err("listen address must be loopback; use a trusted TLS reverse proxy for remote clients"); }
    let (config, shipping) = {
        let root = bounded_file(&args[1]).map_err(|_| "cannot read root policy")?;
        let routes = bounded_file(&args[2]).map_err(|_| "cannot read candidate routes")?;
        let config = GatewayConfig::from_json(&root, &routes, secret)
            .map_err(|_| "invalid configuration or missing credential")?;
        // The cloud token is read here once and moves into the shipper thread;
        // the gateway configuration above never holds it.
        let shipping = ShippingConfig::from_root_json(&root, secret)
            .map_err(|_| "invalid shipping configuration or missing token")?;
        (config, shipping)
    }; // Source JSON buffers are startup scratch, not server-lifetime storage.
    let transport = HttpsTransport::new(Duration::from_secs(300)).map_err(|_| "cannot initialize transport")?;
    // Metadata records need room for an 8192-byte destination even when the
    // body chunk is smaller; the queue bound in docs/resource-composition.md uses this value.
    let payload_limit = config.chunk_bytes().max(gateway_core::metadata::MAX_PAYLOAD);
    let log = DiskLog::create_with_payload_limit(Path::new(&args[3]), 16, Duration::from_secs(2), payload_limit).map_err(|_| "cannot create and sync new audit log")?;
    // One extra thread with its own runtime; it only ever reads this file.
    let shipping_limits = shipping.as_ref().map(|s| (s.max_open_exchanges, s.max_exchange_bytes));
    let shipper = match shipping {
        Some(shipping) => Some(Shipper::spawn(shipping, Path::new(&args[3]).to_path_buf()).map_err(|_| "cannot start shipping thread")?),
        None => None,
    };
    let listener = bind(address).await.map_err(|_| "cannot bind listener")?;
    eprintln!("soundgate listening on {}", listener.local_addr().map_err(|_| "cannot read listen address")?);
    let budget = gateway_runtime::budget::compose(gateway_runtime::budget::Limits {
        requests: config.request_limit(), chunk_bytes: config.chunk_bytes(), connections: 128, queue: 16,
    }).ok_or("allocation budget overflow")?;
    // Informational only: a closed stderr must not stop the server.
    let _ = writeln!(io::stderr().lock(), "soundgate requested-allocation budget {} bytes under docs/resource-composition.md assumptions", budget.total);
    if let Some((open, bytes)) = shipping_limits {
        let extra = gateway_runtime::budget::shipping(open, bytes).ok_or("shipping budget overflow")?;
        let _ = writeln!(io::stderr().lock(), "soundgate shipping thread adds {extra} bytes to that budget");
    }
    let shutdown = async {
        #[cfg(unix)] {
            if let Ok(mut terminate) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
                return;
            }
        }
        let _ = tokio::signal::ctrl_c().await;
    };
    let metrics = shipper.as_ref().map(Shipper::metrics);
    let served = server::serve(listener, Gateway::with_shipping_metrics(config, transport, log, metrics), 128, Duration::from_secs(310), shutdown)
        .await.map_err(|_| "server failed");
    // After request workers and the logger: a bounded window, no replacement.
    if let Some(shipper) = shipper {
        if shipper.shutdown(Duration::from_secs(2)).is_err() { eprintln!("soundgate: shipping thread did not stop within its window"); }
    }
    served
}

/// Ship a finished log with the root policy's `shipping` section, then exit.
fn ship(root_path: &str, log_path: &str) -> Result<(), &'static str> {
    let root = bounded_file(root_path).map_err(|_| "cannot read root policy")?;
    let config = ShippingConfig::from_root_json(&root, secret)
        .map_err(|_| "invalid shipping configuration or missing token")?.ok_or("root policy has no shipping section")?;
    let metrics = shipping::ship_to_end(config, Path::new(log_path).to_path_buf())?;
    let mut text = String::new(); metrics.render(&mut text);
    print!("{text}");
    Ok(())
}

fn scan(path: &str) -> Result<(), &'static str> {
    let file = std::fs::File::open(path).map_err(|_| "cannot open audit log")?;
    let mut reader = LogReader::new(file).map_err(|_| "invalid or incomplete audit header")?;
    let session: String = reader.session().iter().map(|b| format!("{b:02x}")).collect();
    let mut output = io::stdout().lock();
    let mut records = 0u64;
    let error = loop {
        match reader.next_record() {
            Ok(Some(record)) => {
                records = records.checked_add(1).ok_or("record count exhausted")?;
                writeln!(output, "{}", scan_row(&session, &record, reader.valid_end())).map_err(|_| "cannot write scan output")?;
            }
            Ok(None) => break None,
            Err(error) => break Some(error),
        }
    };
    let status = match error { None => "complete", Some(ScanError::Incomplete) => "incomplete",
        Some(ScanError::Corrupt) => "corrupt", Some(ScanError::Io) => "io_error" };
    writeln!(output, "{}", serde_json::json!({"type":"summary", "session":session,
        "records":records, "valid_end":reader.valid_end(), "status":status})).map_err(|_| "cannot write scan output")?;
    if error.is_some() { Err("scan stopped at invalid tail; file unchanged") } else { Ok(()) }
}

// Body payloads are never printed; metadata fields are decoded with the
// verified codecs, and a metadata payload that does not decode is reported as such.
fn scan_row(session: &str, record: &StoredRecord, valid_end: u64) -> serde_json::Value {
    let mut row = serde_json::json!({"type":"record", "session":session,
        "tenant":record.tenant, "request":record.request, "chunk":record.chunk,
        "kind":record.kind.name(), "payload_bytes":record.bytes.len(), "valid_end":valid_end});
    if let Some(direction) = record.direction() {
        row["direction"] = serde_json::json!(match direction {
            gateway_runtime::transfer::Direction::Upload => "upload",
            gateway_runtime::transfer::Direction::Download => "download",
        });
        return row;
    }
    match record.metadata() {
        Some(Metadata::RequestStart(start)) => {
            row["time_ms"] = serde_json::json!(start.time_ms);
            row["selector"] = serde_json::json!(start.selector);
            row["destination"] = serde_json::json!(String::from_utf8_lossy(&start.destination));
        }
        Some(Metadata::ResponseHead(head)) => {
            row["time_ms"] = serde_json::json!(head.time_ms);
            row["status"] = serde_json::json!(head.status);
        }
        Some(Metadata::Completion(done)) => {
            row["time_ms"] = serde_json::json!(done.time_ms);
            row["outcome"] = serde_json::json!(done.outcome);
            row["upload_bytes"] = serde_json::json!(done.upload_bytes);
            row["download_bytes"] = serde_json::json!(done.download_bytes);
        }
        None => { row["metadata"] = serde_json::json!("invalid"); }
    }
    row
}
