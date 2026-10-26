use gateway_runtime::{disk_log::DiskLog, transfer::{AuditLog, LogRecord, RecordKind}};
use std::{fs, io::{BufRead, BufReader, Read, Write}, net::TcpStream, process::{Command, Stdio}, time::Duration};
mod common;
use common::{Process, TempDir};
fn json(value: impl Into<serde_json::Value>) -> serde_json::Value { value.into() }

#[test]
fn executable_starts_and_serves_health_with_real_configuration() {
    let dir = TempDir::new("loggate-cli");
    let root = dir.0.join("root.json"); let routes = dir.0.join("routes.json"); let log = dir.0.join("audit.log");
    fs::write(&root, br#"{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{"requests":1,"chunk_bytes":4},"logging":"strict"}"#).unwrap();
    fs::write(&routes, br#"{"routes":[]}"#).unwrap();
    let mut child = Process(Command::new(env!("CARGO_BIN_EXE_loggate"))
        .args([root.as_os_str(), routes.as_os_str(), log.as_os_str()]).arg("127.0.0.1:0")
        .stderr(Stdio::piped()).spawn().unwrap());
    let mut startup = String::new();
    BufReader::new(child.0.stderr.take().unwrap()).read_line(&mut startup).unwrap();
    let address = startup.trim().strip_prefix("loggate listening on ").expect("server startup message");
    let mut socket = TcpStream::connect(address).unwrap(); socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new(); socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK")); assert!(response.contains("ok\n"));
    assert!(fs::metadata(log).unwrap().len() >= 56);
    drop(child); fs::remove_dir_all(&dir.0).unwrap();
}

#[test]
fn scan_command_reports_valid_prefix_without_printing_payload_or_editing_log() {
    let dir = TempDir::new("loggate-scan"); let path = dir.0.join("audit.log");
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
        let result = Command::new(env!("CARGO_BIN_EXE_loggate")).arg("scan").arg(&path).output().unwrap();
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
    let dir = TempDir::new("loggate-ship");
    let root = dir.0.join("root.json"); let routes = dir.0.join("routes.json"); let log = dir.0.join("audit.log");
    let state = dir.0.join("state"); fs::create_dir(&state).unwrap();
    fs::write(&root, format!(r#"{{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{{"requests":1,"chunk_bytes":4}},"logging":"strict",
        "shipping":{{"server":"https://localhost:1/","token_env":"LOGGATE_TEST_HYP_TOKEN","state_dir":"{}","poll_ms":100}}}}"#, state.display())).unwrap();
    fs::write(&routes, br#"{"routes":[]}"#).unwrap();
    // Without the token the executable refuses to start.
    let refused = Command::new(env!("CARGO_BIN_EXE_loggate")).args([root.as_os_str(), routes.as_os_str(), log.as_os_str()]).arg("127.0.0.1:0")
        .env_remove("LOGGATE_TEST_HYP_TOKEN").output().unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("missing token"));
    assert!(!log.exists());
    let mut child = Process(Command::new(env!("CARGO_BIN_EXE_loggate"))
        .args([root.as_os_str(), routes.as_os_str(), log.as_os_str()]).arg("127.0.0.1:0")
        .env("LOGGATE_TEST_HYP_TOKEN", "hsa_0123456789abcdef_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq")
        .stderr(Stdio::piped()).spawn().unwrap());
    let mut stderr = BufReader::new(child.0.stderr.take().unwrap());
    let mut startup = String::new(); stderr.read_line(&mut startup).unwrap();
    let address = startup.trim().strip_prefix("loggate listening on ").expect("server startup message").to_owned();
    let mut budget = String::new(); stderr.read_line(&mut budget).unwrap();
    let mut extra = String::new(); stderr.read_line(&mut extra).unwrap();
    assert!(extra.starts_with("loggate shipping thread adds "), "{extra}");
    let mut socket = TcpStream::connect(&address).unwrap(); socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new(); socket.read_to_string(&mut response).unwrap();
    assert!(response.contains("loggate_shipping_enabled 1\n"), "{response}");
    assert!(response.contains("loggate_shipping_enrolled 0\n"));
    assert!(response.contains("loggate_shipping_stopped 0\n"));
    let mut socket = TcpStream::connect(&address).unwrap(); socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    socket.write_all(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new(); socket.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"), "an unreachable cloud never affects readiness: {response}");
    drop(child);
    // The standalone subcommand needs the section.
    fs::write(&root, br#"{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{"requests":1,"chunk_bytes":4},"logging":"strict"}"#).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_loggate")).arg("ship").arg(&root).arg(&log).output().unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("no shipping section"));
    // With the section, the subcommand runs the drain loop to its end. The log
    // holds only its header, so nothing is sent and the unreachable server is
    // never contacted; the run must still finish cleanly and print its metrics.
    fs::write(&root, format!(r#"{{"identities":[],"destinations":[],"credentials":[],"grants":[],"limits":{{"requests":1,"chunk_bytes":4}},"logging":"strict",
        "shipping":{{"server":"https://localhost:1/","token_env":"LOGGATE_TEST_HYP_TOKEN","state_dir":"{}","poll_ms":100}}}}"#, state.display())).unwrap();
    let shipped = Command::new(env!("CARGO_BIN_EXE_loggate")).arg("ship").arg(&root).arg(&log)
        .env("LOGGATE_TEST_HYP_TOKEN", "hsa_0123456789abcdef_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq").output().unwrap();
    let stderr = String::from_utf8_lossy(&shipped.stderr);
    assert!(shipped.status.success(), "{stderr}");
    assert!(!stderr.contains("panicked"), "{stderr}");
    let stdout = String::from_utf8_lossy(&shipped.stdout);
    assert!(stdout.contains("loggate_shipping_enrolled 0\n"), "{stdout}");
    assert!(stdout.contains("loggate_shipping_exchanges_emitted_total 0\n"), "{stdout}");
    fs::remove_dir_all(&dir.0).unwrap();
}
