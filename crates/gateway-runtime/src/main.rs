#![deny(clippy::disallowed_methods)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unreachable, clippy::todo,
    clippy::unimplemented, clippy::indexing_slicing, clippy::arithmetic_side_effects))]
#![deny(unsafe_code)]
mod cli;
mod scan;
#[allow(unsafe_code)]
mod signal;
use gateway_runtime::{
    config::GatewayConfig,
    disk_log::DiskLog,
    server::{self, Gateway, Shutdown},
    shipping::{self, Shipper, ShippingConfig},
    transport::HttpsTransport,
};
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    time::Duration,
};

const CONNECTION_LIMIT: usize = 128;
const AUDIT_QUEUE_CAPACITY: usize = 16;
const AUDIT_TIMEOUT: Duration = Duration::from_secs(2);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(300);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(310);
const CONFIG_READ_LIMIT: u64 = 1024 * 1024 + 1;

// Effect site: secrets come only from the environment variables the root
// policy names, read once at startup.
#[allow(clippy::disallowed_methods)]
fn secret(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

// Effect site: the one listening socket.
#[allow(clippy::disallowed_methods)]
fn bind(address: SocketAddr) -> io::Result<TcpListener> {
    TcpListener::bind(address)
}

fn bounded_file(path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(CONFIG_READ_LIMIT)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn main() {
    if let Err(message) = run() {
        eprintln!("loggate: {message}");
        std::process::exit(1);
    }
}
fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match cli::Command::parse(&args)? {
        cli::Command::Help => {
            println!("{}", cli::HELP);
            Ok(())
        }
        cli::Command::Version => {
            println!("loggate {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        cli::Command::Scan { log } => scan::run(log),
        cli::Command::Ship { root, log } => ship(root, log),
        cli::Command::Serve {
            root,
            routes,
            log,
            address,
        } => serve(root, routes, log, address),
    }
}

fn serve(
    root_path: &str,
    routes_path: &str,
    log_path: &str,
    address: SocketAddr,
) -> Result<(), &'static str> {
    let (config, shipping) = {
        let root = bounded_file(root_path).map_err(|_| "cannot read root policy")?;
        let routes = bounded_file(routes_path).map_err(|_| "cannot read candidate routes")?;
        let config = GatewayConfig::from_json(&root, &routes, secret)
            .map_err(|_| "invalid configuration or missing credential")?;
        // The cloud token is read here once and moves into the shipper thread;
        // the gateway configuration above never holds it.
        let shipping = ShippingConfig::from_root_json(&root, secret)
            .map_err(|_| "invalid shipping configuration or missing token")?;
        (config, shipping)
    }; // Source JSON buffers are startup scratch, not server-lifetime storage.
    let transport =
        HttpsTransport::new(UPSTREAM_TIMEOUT).map_err(|_| "cannot initialize transport")?;
    // Metadata records need room for an 8192-byte destination even when the
    // body chunk is smaller; the queue bound in docs/resource-composition.md uses this value.
    let payload_limit = config
        .chunk_bytes()
        .max(gateway_core::metadata::MAX_PAYLOAD);
    let log = DiskLog::create_with_payload_limit(
        Path::new(log_path),
        AUDIT_QUEUE_CAPACITY,
        AUDIT_TIMEOUT,
        payload_limit,
    )
    .map_err(|_| "cannot create and sync new audit log")?;
    // One extra thread that only ever reads this file.
    let shipping_limits = shipping
        .as_ref()
        .map(|s| (s.max_open_exchanges, s.max_exchange_bytes));
    let shipper = match shipping {
        Some(shipping) => Some(
            Shipper::spawn(shipping, Path::new(log_path).to_path_buf())
                .map_err(|_| "cannot start shipping thread")?,
        ),
        None => None,
    };
    let listener = bind(address).map_err(|_| "cannot bind listener")?;
    eprintln!(
        "loggate listening on {}",
        listener
            .local_addr()
            .map_err(|_| "cannot read listen address")?
    );
    let budget = gateway_runtime::budget::compose(gateway_runtime::budget::Limits {
        requests: config.request_limit(),
        chunk_bytes: config.chunk_bytes(),
        connections: CONNECTION_LIMIT,
        queue: AUDIT_QUEUE_CAPACITY,
    })
    .ok_or("allocation budget overflow")?;
    // Informational only: a closed stderr must not stop the server.
    let _ = writeln!(io::stderr().lock(), "loggate requested-allocation budget {} bytes under docs/resource-composition.md assumptions", budget.total);
    if let Some((open, bytes)) = shipping_limits {
        let extra =
            gateway_runtime::budget::shipping(open, bytes).ok_or("shipping budget overflow")?;
        let _ = writeln!(
            io::stderr().lock(),
            "loggate shipping thread adds {extra} bytes to that budget"
        );
    }
    // SIGTERM and SIGINT trigger the cooperative drain (signal.rs). SIGKILL
    // still ends in-flight exchanges abruptly: every record already
    // acknowledged is durable, and the recovery scanner tolerates a torn tail.
    let shutdown = Shutdown::new();
    let trigger = shutdown.clone();
    signal::on_termination(move || trigger.trigger())
        .map_err(|_| "cannot install signal handlers")?;
    let metrics = shipper.as_ref().map(Shipper::metrics);
    let served = server::serve(
        listener,
        Gateway::with_shipping_metrics(config, transport, log, metrics),
        CONNECTION_LIMIT,
        CONNECTION_TIMEOUT,
        &shutdown,
    )
    .map_err(|_| "server failed");
    // After request workers and the logger: a bounded window, no replacement.
    if let Some(shipper) = shipper {
        if shipper.shutdown(Duration::from_secs(2)).is_err() {
            eprintln!("loggate: shipping thread did not stop within its window");
        }
    }
    served
}

/// Ship a finished log with the root policy's `shipping` section, then exit.
/// Runs on the main thread with blocking sockets.
fn ship(root_path: &str, log_path: &str) -> Result<(), &'static str> {
    let root = bounded_file(root_path).map_err(|_| "cannot read root policy")?;
    let config = ShippingConfig::from_root_json(&root, secret)
        .map_err(|_| "invalid shipping configuration or missing token")?
        .ok_or("root policy has no shipping section")?;
    let metrics = shipping::ship_to_end(config, Path::new(log_path).to_path_buf())?;
    let mut text = String::new();
    metrics.render(&mut text);
    print!("{text}");
    Ok(())
}
