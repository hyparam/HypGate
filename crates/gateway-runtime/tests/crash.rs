//! Process death leaves the OS running: this validates process-crash recovery,
//! not power loss, device caches, or the full filesystem durability assumption.
use gateway_runtime::{disk_log::{DiskLog, LogReader, ScanError}, transfer::{AuditLog, LogRecord, RecordKind}};
use std::{fs::{self, File}, io::{BufRead, BufReader, Write}, process::{Command, Stdio}, time::Duration};
mod common;
use common::{Process, TempDir};

#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("HYPGATE_CRASH_CHILD_LOG") else { return; };
    let mut log = DiskLog::create(std::path::Path::new(&path), 1, Duration::from_secs(5)).unwrap();
    for chunk in 1..=64u64 {
        let bytes = vec![chunk as u8; 64 * 1024];
        log.append(LogRecord { tenant: 7, request: 11, chunk, kind: RecordKind::Upload, bytes: &bytes }).unwrap();
        println!("HYPGATE_ACK {chunk}"); std::io::stdout().flush().unwrap();
        if std::env::var_os("HYPGATE_CRASH_PAUSE_AFTER_ACK").is_some() {
            loop { std::thread::park(); } // wait to be killed
        }
    }
    loop { std::thread::park(); } // wait to be killed
}

fn kill_and_scan(pause_after_ack: bool) {
    let dir = TempDir::new("hypgate-crash"); let path = dir.0.join("audit.log");
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "crash_child", "--nocapture"])
        .env("HYPGATE_CRASH_CHILD_LOG", &path).stdout(Stdio::piped()).stderr(Stdio::piped());
    if pause_after_ack { command.env("HYPGATE_CRASH_PAUSE_AFTER_ACK", "1"); }
    else { command.env_remove("HYPGATE_CRASH_PAUSE_AFTER_ACK"); }
    let mut child = Process(command.spawn().unwrap());
    let mut output = BufReader::new(child.0.stdout.take().unwrap());
    let target = if pause_after_ack { 1 } else { 3 };
    let mut acknowledged = 0;
    while acknowledged < target {
        let mut line = String::new();
        assert!(output.read_line(&mut line).unwrap() > 0, "writer exited before acknowledging records");
        if let Some((_, value)) = line.split_once("HYPGATE_ACK ") { acknowledged = value.trim().parse::<u64>().unwrap(); }
    }
    child.0.kill().unwrap(); let exit = child.0.wait().unwrap(); assert!(!exit.success());
    let before = fs::read(&path).unwrap();
    let mut reader = LogReader::new(File::open(&path).unwrap()).unwrap();
    let mut recovered = 0u64;
    loop {
        match reader.next_record() {
            Ok(Some(record)) => {
                recovered += 1;
                assert_eq!((record.tenant, record.request, record.chunk), (7, 11, recovered));
                assert_eq!(record.bytes, vec![recovered as u8; 64 * 1024]);
            }
            Ok(None) | Err(ScanError::Incomplete) => break,
            Err(e) => panic!("unexpected recovery error: {e:?}"),
        }
    }
    assert!(recovered >= acknowledged, "acknowledged records must survive process death");
    if pause_after_ack { assert_eq!(recovered, acknowledged); }
    assert!(reader.valid_end() <= before.len() as u64);
    // Recovery is read-only, and restart creates a new session instead of appending
    // or silently discarding an uncertain suffix in the old session.
    assert_eq!(fs::read(&path).unwrap(), before);
    assert!(DiskLog::create(&path, 1, Duration::from_secs(1)).is_err());
    let next = DiskLog::create(&dir.0.join("next.log"), 1, Duration::from_secs(1)).unwrap();
    assert_ne!(next.session(), reader.session());
}

#[test]
fn kill_after_ack_preserves_the_acknowledged_record() { kill_and_scan(true); }

#[test]
fn kill_during_following_appends_preserves_the_acknowledged_prefix() { kill_and_scan(false); }
