//! Guest workload for scripts/check_power_cut.py. ACKs leave the guest over serial.
use gateway_runtime::{disk_log::{DiskLog, LogReader, ScanError}, transfer::{AuditLog, LogRecord, RecordKind}};
use std::{fs::File, io::{self, Write}, time::Duration};
fn main() {
    let mode = std::env::args().nth(1).unwrap();
    let path = std::path::Path::new("/data/audit.log");
    if mode == "write" || mode == "pause" {
        let mut log = DiskLog::create(path, 1, Duration::from_secs(30)).unwrap();
        for chunk in 1..=1024u64 {
            let bytes = vec![chunk as u8; 64 * 1024];
            log.append(LogRecord { tenant: 7, request: 11, chunk, kind: RecordKind::Upload, bytes: &bytes }).unwrap();
            println!("POWER_ACK {chunk}"); io::stdout().flush().unwrap();
            if mode == "pause" { loop { std::thread::park(); } }
        }
        loop { std::thread::park(); }
    } else {
        let acknowledged: u64 = mode.parse().unwrap();
        let before = std::fs::read(path).unwrap();
        let mut reader = LogReader::new(File::open(path).unwrap()).unwrap();
        let mut recovered = 0;
        loop {
            match reader.next_record() {
                Ok(Some(record)) => {
                    recovered += 1;
                    assert_eq!((record.tenant, record.request, record.chunk), (7, 11, recovered));
                    assert_eq!(record.kind, RecordKind::Upload);
                    assert_eq!(record.bytes, vec![recovered as u8; 64 * 1024]);
                }
                Ok(None) | Err(ScanError::Incomplete) => break,
                Err(e) => panic!("recovery error: {e:?}"),
            }
        }
        assert!(recovered >= acknowledged);
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert!(DiskLog::create(path, 1, Duration::from_secs(5)).is_err());
        let next = DiskLog::create(std::path::Path::new("/data/next.log"), 1, Duration::from_secs(5)).unwrap();
        assert_ne!(next.session(), reader.session());
        println!("POWER_PASS acknowledged={acknowledged} recovered={recovered}");
    }
}
