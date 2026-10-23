use gateway_runtime::{config::GatewayConfig, disk_log::{DiskLog, LogReader, ScanError}, server::{self, Gateway}, transport::HttpsTransport};
use std::{io::{self, Read, Write}, net::SocketAddr, path::Path, time::Duration};

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
    if !(4..=5).contains(&args.len()) { return Err("usage: soundgate ROOT.json ROUTES.json NEW_LOG [127.0.0.1:8080]"); }
    let address: SocketAddr = args.get(4).map(String::as_str).unwrap_or("127.0.0.1:8080").parse().map_err(|_| "invalid listen address")?;
    if !address.ip().is_loopback() { return Err("listen address must be loopback; use a trusted TLS reverse proxy for remote clients"); }
    let root = bounded_file(&args[1]).map_err(|_| "cannot read root policy")?;
    let routes = bounded_file(&args[2]).map_err(|_| "cannot read candidate routes")?;
    let config = GatewayConfig::from_json(&root, &routes, |name| std::env::var(name).ok()).map_err(|_| "invalid configuration or missing credential")?;
    let transport = HttpsTransport::new(Duration::from_secs(300)).map_err(|_| "cannot initialize TLS")?;
    let log = DiskLog::create(Path::new(&args[3]), 16, Duration::from_secs(2)).map_err(|_| "cannot create and sync new audit log")?;
    let listener = tokio::net::TcpListener::bind(address).await.map_err(|_| "cannot bind listener")?;
    eprintln!("soundgate listening on {}", listener.local_addr().map_err(|_| "cannot read listen address")?);
    let shutdown = async {
        #[cfg(unix)] {
            if let Ok(mut terminate) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
                return;
            }
        }
        let _ = tokio::signal::ctrl_c().await;
    };
    server::serve(listener, Gateway::new(config, transport, log), 128, Duration::from_secs(310), shutdown)
        .await.map_err(|_| "server failed")
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
                let row = serde_json::json!({"type":"record", "session":session,
                    "tenant":record.tenant, "request":record.request, "chunk":record.chunk,
                    "direction":match record.direction {
                        gateway_runtime::transfer::Direction::Upload => "upload",
                        gateway_runtime::transfer::Direction::Download => "download",
                    }, "payload_bytes":record.bytes.len(), "valid_end":reader.valid_end()});
                writeln!(output, "{row}").map_err(|_| "cannot write scan output")?;
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
