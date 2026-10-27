#!/usr/bin/env python3
"""Audit regression: TLS trickle input must obey the absolute deadline.

Uses the production net.rs unchanged and the locked rustls build. Only loopback
sockets and temporary files are used. Exits nonzero when the deadline is bypassed.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
build = subprocess.run(
    ["cargo", "build", "-p", "gateway-runtime", "--lib", "--locked", "--message-format=json"],
    cwd=ROOT, capture_output=True, text=True,
)
if build.returncode:
    sys.stderr.write(build.stderr)
    sys.stderr.write(build.stdout)
    raise SystemExit(build.returncode)
rustls = None
core = None
for line in build.stdout.splitlines():
    item = json.loads(line)
    if item.get("reason") == "compiler-artifact" and item["target"]["name"] == "gateway_core":
        core = next((p for p in item["filenames"] if p.endswith(".rlib")), core)
    if item.get("reason") == "compiler-artifact" and item["target"]["name"] == "rustls":
        rustls = next((p for p in item["filenames"] if p.endswith(".rlib")), rustls)
if rustls is None or core is None:
    raise SystemExit("locked build did not report the rustls and gateway_core libraries")

source = r'''
#![allow(dead_code)]
#[path = NET_PATH]
mod net;
use std::{io::{Read, Write}, net::{TcpListener, TcpStream}, sync::Arc,
          thread, time::{Duration, Instant}};
use rustls::{ClientConfig, ClientConnection, RootCertStore,
             pki_types::ServerName};
fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
        let _ = socket.read(&mut [0; 4096]); // consume ClientHello
        // Start a TLS handshake record, but never complete it. No valid
        // certificate is required to reach this unauthenticated boundary.
        if socket.write_all(&[22, 3, 3, 4, 0]).is_err() { return; }
        for _ in 0..40 {
            thread::sleep(Duration::from_millis(25));
            if socket.write_all(&[0]).is_err() { break; }
        }
    });
    let config = ClientConfig::builder().with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    let conn = ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap()).unwrap();
    let socket = TcpStream::connect(address).unwrap();
    let start = Instant::now();
    let mut tls = net::Tls::new(conn, socket,
        net::Deadline::start(Duration::from_millis(150)).unwrap());
    let result = tls.handshake();
    let elapsed = start.elapsed();
    println!("deadline=150ms elapsed={}ms expired={} result={:?}",
        elapsed.as_millis(), tls.expired(), result);
    drop(tls);
    peer.join().unwrap();
    assert!(elapsed < Duration::from_millis(450),
        "TLS trickle bypassed the absolute deadline (including 300ms scheduling allowance)");
    assert!(result.is_err() && tls_expired_result(result), "expected timeout");
}
fn tls_expired_result(result: std::io::Result<()>) -> bool {
    matches!(result, Err(e) if matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock))
}
'''.replace("NET_PATH", json.dumps(str(ROOT / "crates/gateway-runtime/src/net.rs")))
with tempfile.TemporaryDirectory(prefix="hypgate-deadline-audit-") as temporary:
    directory = Path(temporary)
    path = directory / "probe.rs"
    path.write_text(source)
    binary = directory / "probe"
    subprocess.run(["rustc", "--edition=2021", str(path), "--extern", f"rustls={rustls}",
                    "--extern", f"gateway_core={core}", "-L", f"dependency={Path(rustls).parent}", "-o", str(binary)], cwd=ROOT, check=True)
    result = subprocess.run([str(binary)], timeout=10)
    raise SystemExit(result.returncode)
