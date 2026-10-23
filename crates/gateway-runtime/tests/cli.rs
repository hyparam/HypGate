use std::{fs, io::{BufRead, BufReader, Read, Write}, net::TcpStream, process::{Child, Command, Stdio}, time::{Duration, SystemTime, UNIX_EPOCH}};

struct Process(Child);
impl Drop for Process { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }

#[test]
fn executable_starts_and_serves_health_with_real_configuration() {
    let dir = std::env::temp_dir().join(format!("soundgate-cli-{}-{}", std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir(&dir).unwrap();
    let root = dir.join("root.json"); let routes = dir.join("routes.json"); let log = dir.join("audit.log");
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
    drop(child); fs::remove_dir_all(dir).unwrap();
}
