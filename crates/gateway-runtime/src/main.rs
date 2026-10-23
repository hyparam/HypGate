use gateway_runtime::{config::GatewayConfig, disk_log::DiskLog, server::{self, Gateway}, transport::HttpsTransport};
use std::{io::{self, Read}, net::SocketAddr, path::Path, time::Duration};

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
