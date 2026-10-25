use gateway_runtime::{disk_log::DiskLog, transfer::{AuditLog, Direction, LogRecord}};
use std::{fs, io::{BufRead, BufReader, Read, Write}, net::TcpStream, process::{Command, Stdio}, time::Duration};
mod common;
use common::{Process, TempDir};

#[test]
fn executable_starts_and_serves_health_with_real_configuration() {
    let dir = TempDir::new("soundgate-cli");
    let root = dir.0.join("root.json"); let routes = dir.0.join("routes.json"); let log = dir.0.join("audit.log");
    fs::write(&root, br#"{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{"requests":1,"chunk_bytes":4},"logging":"strict"}"#).unwrap();
    fs::write(&routes, br#"{"routes":[]}"#).unwrap();
    let mut child = Process(Command::new(env!("CARGO_BIN_EXE_soundgate"))
        .args([root.as_os_str(), routes.as_os_str(), log.as_os_str()]).arg("127.0.0.1:0")
        .stderr(Stdio::piped()).spawn().unwrap());
    let mut startup = String::new();
    BufReader::new(child.0.stderr.take().unwrap()).read_line(&mut startup).unwrap();
    let address = startup.trim().strip_prefix("soundgate listening on ").expect("server startup message");
    let mut socket = TcpStream::connect(address).unwrap(); socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new(); socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK")); assert!(response.contains("ok\n"));
    assert!(fs::metadata(log).unwrap().len() >= 56);
    drop(child); fs::remove_dir_all(&dir.0).unwrap();
}

#[test]
fn scan_command_reports_valid_prefix_without_printing_payload_or_editing_log() {
    let dir = TempDir::new("soundgate-scan"); let path = dir.0.join("audit.log");
    tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
        let mut log = DiskLog::create(&path, 1, Duration::from_secs(2)).unwrap();
        log.append(LogRecord { tenant: 1, request: 2, chunk: 3, direction: Direction::Upload,
            bytes: b"private-payload-marker" }).await.unwrap();
    });
    let complete_length = fs::metadata(&path).unwrap().len();
    for incomplete in [false, true] {
        if incomplete { fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"SG").unwrap(); }
        let before = fs::read(&path).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_soundgate")).arg("scan").arg(&path).output().unwrap();
        assert_eq!(result.status.success(), !incomplete);
        let text = std::str::from_utf8(&result.stdout).unwrap();
        assert!(!text.contains("private-payload-marker"));
        let rows: Vec<serde_json::Value> = text.lines().map(|s| serde_json::from_str(s).unwrap()).collect();
        assert_eq!(rows.len(), 2); assert_eq!(rows[0]["request"], 2);
        assert_eq!(rows[1]["records"], 1); assert_eq!(rows[1]["valid_end"], complete_length);
        assert_eq!(rows[1]["status"], if incomplete { "incomplete" } else { "complete" });
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    fs::remove_dir_all(&dir.0).unwrap();
}
