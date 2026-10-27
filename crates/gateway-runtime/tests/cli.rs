use gateway_runtime::{disk_log::DiskLog, transfer::{AuditLog, LogRecord, RecordKind}};
use std::{fs, io::{BufRead, BufReader, Read, Write}, net::TcpStream, process::{Command, Stdio}, time::Duration};
mod common;
use common::{Process, TempDir};
fn json(value: impl Into<serde_json::Value>) -> serde_json::Value { value.into() }

#[test]
fn executable_starts_and_serves_health_with_real_configuration() {
    let dir = TempDir::new("hypgate-cli");
    let root = dir.0.join("root.json"); let routes = dir.0.join("routes.json"); let log = dir.0.join("audit.log");
    fs::write(&root, br#"{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{"requests":1,"chunk_bytes":4},"logging":"strict"}"#).unwrap();
    fs::write(&routes, br#"{"routes":[]}"#).unwrap();
    let mut child = Process(Command::new(env!("CARGO_BIN_EXE_hypgate"))
        .args([root.as_os_str(), routes.as_os_str(), log.as_os_str()]).arg("127.0.0.1:0")
        .stderr(Stdio::piped()).spawn().unwrap());
    let mut startup = String::new();
    BufReader::new(child.0.stderr.take().unwrap()).read_line(&mut startup).unwrap();
    let address = startup.trim().strip_prefix("hypgate listening on ").expect("server startup message");
    let mut socket = TcpStream::connect(address).unwrap(); socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new(); socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK")); assert!(response.contains("ok\n"));
    assert!(fs::metadata(log).unwrap().len() >= 56);
    drop(child); fs::remove_dir_all(&dir.0).unwrap();
}

#[test]
fn sigterm_drains_and_exits_cleanly_with_a_complete_log() {
    let dir = TempDir::new("hypgate-sigterm");
    let root = dir.0.join("root.json"); let routes = dir.0.join("routes.json"); let log = dir.0.join("audit.log");
    fs::write(&root, br#"{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{"requests":1,"chunk_bytes":4},"logging":"strict"}"#).unwrap();
    fs::write(&routes, br#"{"routes":[]}"#).unwrap();
    let mut child = Process(Command::new(env!("CARGO_BIN_EXE_hypgate"))
        .args([root.as_os_str(), routes.as_os_str(), log.as_os_str()]).arg("127.0.0.1:0")
        .stderr(Stdio::piped()).spawn().unwrap());
    let mut startup = String::new();
    BufReader::new(child.0.stderr.take().unwrap()).read_line(&mut startup).unwrap();
    let address = startup.trim().strip_prefix("hypgate listening on ").expect("server startup message").to_owned();
    // An idle connection holding a connection credit: the drain must not wait for its deadline.
    let mut idle = TcpStream::connect(&address).unwrap(); idle.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let started = std::time::Instant::now();
    assert!(Command::new("kill").args(["-TERM", &child.0.id().to_string()]).status().unwrap().success());
    let exit = child.0.wait().unwrap();
    assert!(exit.success(), "a drained gateway exits cleanly: {exit:?}");
    assert!(started.elapsed() < Duration::from_secs(25), "the drain is bounded");
    // The idle connection was closed by the gateway, not left to its deadline.
    let mut rest = Vec::new(); assert_eq!(idle.read_to_end(&mut rest).map(|_| rest.len()).unwrap_or(0), 0);
    assert!(TcpStream::connect(&address).is_err(), "the listener is gone");
    let scan = Command::new(env!("CARGO_BIN_EXE_hypgate")).arg("scan").arg(&log).output().unwrap();
    assert!(scan.status.success(), "the log is complete after a drain: {}", String::from_utf8_lossy(&scan.stderr));
    drop(child); fs::remove_dir_all(&dir.0).unwrap();
}

#[test]
fn scan_command_reports_valid_prefix_without_printing_payload_or_editing_log() {
    let dir = TempDir::new("hypgate-scan"); let path = dir.0.join("audit.log");
    {
        let mut log = DiskLog::create(&path, 1, Duration::from_secs(2)).unwrap();
        let start = gateway_core::metadata::encode_request_start(1_700_000_000_000, 7, b"https://example.test/v1/messages").unwrap();
        log.append(LogRecord { tenant: 1, request: 2, chunk: 0, kind: RecordKind::RequestStart, bytes: &start }).unwrap();
        log.append(LogRecord { tenant: 1, request: 2, chunk: 1, kind: RecordKind::Upload,
            bytes: b"private-payload-marker" }).unwrap();
        let head = gateway_core::metadata::encode_response_head(1_700_000_000_001, 200).unwrap();
        log.append(LogRecord { tenant: 1, request: 2, chunk: 0, kind: RecordKind::ResponseHead, bytes: &head }).unwrap();
        log.append(LogRecord { tenant: 1, request: 2, chunk: 1, kind: RecordKind::Download,
            bytes: b"private-response-marker" }).unwrap();
        let done = gateway_core::metadata::encode_completion(1_700_000_000_002, 0, 22, 23).unwrap();
        log.append(LogRecord { tenant: 1, request: 2, chunk: 0, kind: RecordKind::Completion, bytes: &done }).unwrap();
    }
    let complete_length = fs::metadata(&path).unwrap().len();
    for incomplete in [false, true] {
        if incomplete { fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b"SG").unwrap(); }
        let before = fs::read(&path).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_hypgate")).arg("scan").arg(&path).output().unwrap();
        assert_eq!(result.status.success(), !incomplete);
        let text = std::str::from_utf8(&result.stdout).unwrap();
        assert!(!text.contains("private-payload-marker")); assert!(!text.contains("private-response-marker"));
        let rows: Vec<serde_json::Value> = text.lines().map(|s| serde_json::from_str(s).unwrap()).collect();
        assert_eq!(rows.len(), 6);
        assert!(rows[..5].iter().all(|row| row["request"] == 2 && row["type"] == "record"));
        assert_eq!((&rows[0]["kind"], &rows[0]["chunk"], &rows[0]["time_ms"], &rows[0]["selector"], &rows[0]["destination"]),
            (&json("request_start"), &json(0), &json(1_700_000_000_000u64), &json(7), &json("https://example.test/v1/messages")));
        assert_eq!((&rows[1]["kind"], &rows[1]["direction"], &rows[1]["chunk"], &rows[1]["payload_bytes"]),
            (&json("upload"), &json("upload"), &json(1), &json(22)));
        assert_eq!((&rows[2]["kind"], &rows[2]["time_ms"], &rows[2]["status"]), (&json("response_head"), &json(1_700_000_000_001u64), &json(200)));
        assert_eq!((&rows[3]["kind"], &rows[3]["direction"]), (&json("download"), &json("download")));
        assert_eq!((&rows[4]["kind"], &rows[4]["outcome"], &rows[4]["upload_bytes"], &rows[4]["download_bytes"]),
            (&json("completion"), &json(0), &json(22), &json(23)));
        assert!(rows[0].get("direction").is_none() && rows[1].get("destination").is_none());
        assert_eq!(rows[5]["records"], 5); assert_eq!(rows[5]["valid_end"], complete_length);
        assert_eq!(rows[5]["status"], if incomplete { "incomplete" } else { "complete" });
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    fs::remove_dir_all(&dir.0).unwrap();
}

#[test]
fn executable_starts_the_shipper_from_the_root_policy_and_reports_it_in_metrics() {
    let dir = TempDir::new("hypgate-ship");
    let root = dir.0.join("root.json"); let routes = dir.0.join("routes.json"); let log = dir.0.join("audit.log");
    let state = dir.0.join("state"); fs::create_dir(&state).unwrap();
    fs::write(&root, format!(r#"{{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{{"requests":1,"chunk_bytes":4}},"logging":"strict",
        "shipping":{{"server":"https://localhost:1/","token_env":"HYPGATE_TEST_HYP_TOKEN","state_dir":"{}","poll_ms":100}}}}"#, state.display())).unwrap();
    fs::write(&routes, br#"{"routes":[]}"#).unwrap();
    // Without the token the executable refuses to start.
    let refused = Command::new(env!("CARGO_BIN_EXE_hypgate")).args([root.as_os_str(), routes.as_os_str(), log.as_os_str()]).arg("127.0.0.1:0")
        .env_remove("HYPGATE_TEST_HYP_TOKEN").output().unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("missing token"));
    assert!(!log.exists());
    let mut child = Process(Command::new(env!("CARGO_BIN_EXE_hypgate"))
        .args([root.as_os_str(), routes.as_os_str(), log.as_os_str()]).arg("127.0.0.1:0")
        .env("HYPGATE_TEST_HYP_TOKEN", "hsa_0123456789abcdef_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq")
        .stderr(Stdio::piped()).spawn().unwrap());
    let mut stderr = BufReader::new(child.0.stderr.take().unwrap());
    let mut startup = String::new(); stderr.read_line(&mut startup).unwrap();
    let address = startup.trim().strip_prefix("hypgate listening on ").expect("server startup message").to_owned();
    let mut budget = String::new(); stderr.read_line(&mut budget).unwrap();
    let mut extra = String::new(); stderr.read_line(&mut extra).unwrap();
    assert!(extra.starts_with("hypgate shipping thread adds "), "{extra}");
    let mut socket = TcpStream::connect(&address).unwrap(); socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new(); socket.read_to_string(&mut response).unwrap();
    assert!(response.contains("hypgate_shipping_enabled 1\n"), "{response}");
    assert!(response.contains("hypgate_shipping_enrolled 0\n"));
    assert!(response.contains("hypgate_shipping_stopped 0\n"));
    let mut socket = TcpStream::connect(&address).unwrap(); socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new(); socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "an unreachable cloud never affects readiness: {response}");
    drop(child);
    // The standalone subcommand needs the section.
    fs::write(&root, br#"{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{"requests":1,"chunk_bytes":4},"logging":"strict"}"#).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_hypgate")).arg("ship").arg(&root).arg(&log).output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("no shipping section"));
    // With the section, the subcommand runs the drain loop to its end. The log
    // holds only its header, so nothing is sent and the unreachable server is
    // never contacted; the run must still finish cleanly and print its metrics.
    fs::write(&root, format!(r#"{{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{{"requests":1,"chunk_bytes":4}},"logging":"strict",
        "shipping":{{"server":"https://localhost:1/","token_env":"HYPGATE_TEST_HYP_TOKEN","state_dir":"{}","poll_ms":100}}}}"#, state.display())).unwrap();
    let shipped = Command::new(env!("CARGO_BIN_EXE_hypgate")).arg("ship").arg(&root).arg(&log)
        .env("HYPGATE_TEST_HYP_TOKEN", "hsa_0123456789abcdef_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq").output().unwrap();
    let stderr = String::from_utf8_lossy(&shipped.stderr);
    assert!(shipped.status.success(), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    let stdout = String::from_utf8_lossy(&shipped.stdout);
    assert!(stdout.contains("hypgate_shipping_enrolled 0\n"), "{stdout}");
    assert!(stdout.contains("hypgate_shipping_exchanges_emitted_total 0\n"), "{stdout}");
    fs::remove_dir_all(&dir.0).unwrap();
}

#[test]
fn help_and_version_succeed_without_loading_configuration() {
    for flag in ["--help", "-h", "--version", "-V"] {
        let result = Command::new(env!("CARGO_BIN_EXE_hypgate")).arg(flag).output().unwrap();
        assert!(result.status.success(), "{flag}: {}", String::from_utf8_lossy(&result.stderr));
        assert!(result.stderr.is_empty());
        let output = String::from_utf8(result.stdout).unwrap();
        if flag == "--help" || flag == "-h" {
            assert!(output.contains("hypgate scan LOG"));
            assert!(output.contains("NEW_LOG must not exist"));
        } else {
            assert_eq!(output.trim(), concat!("hypgate ", env!("CARGO_PKG_VERSION")));
        }
    }
}

#[test]
fn invalid_commands_and_public_listeners_are_rejected_before_file_access() {
    for (args, message) in [
        (vec![], "usage:"),
        (vec!["scan"], "usage: hypgate scan"),
        (vec!["ship", "missing-root"], "usage: hypgate ship"),
        (vec!["missing-root", "missing-routes", "unused-log", "0.0.0.0:8080"], "listen address must be loopback"),
        (vec!["missing-root", "missing-routes", "unused-log", "[::]:8080"], "listen address must be loopback"),
        (vec!["missing-root", "missing-routes", "unused-log", "invalid"], "invalid listen address"),
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_hypgate")).args(args).output().unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains(message));
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn scan_follows_rotated_segments_and_identifies_physical_offsets() {
    let dir = TempDir::new("hypgate-rotated-scan"); let path = dir.0.join("audit.log");
    let mut log = DiskLog::create_rotating(&path, 2, Duration::from_secs(2), 1024,
        gateway_runtime::disk_log::Rotation { max_bytes: 128, ..Default::default() }).unwrap();
    for chunk in 1..=3 {
        log.append(LogRecord { tenant: 1, request: 2, chunk, kind: RecordKind::Download,
            bytes: b"private-payload-marker" }).unwrap();
    }
    log.shutdown(Duration::from_secs(2)).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_hypgate")).arg("scan").arg(&path).output().unwrap();
    assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(!text.contains("private-payload-marker"));
    let rows: Vec<serde_json::Value> = text.lines().map(|s| serde_json::from_str(s).unwrap()).collect();
    assert_eq!(rows.len(), 4);
    for (index, row) in rows[..3].iter().enumerate() {
        assert_eq!(row["chunk"], index + 1);
        assert_eq!(row["segment"], index);
        assert_eq!(row["session"], rows[0]["session"]);
    }
    assert_eq!(rows[3]["records"], 3);
    assert_eq!(rows[3]["status"], "complete");
}
