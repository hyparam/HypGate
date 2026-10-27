//! Creates a synthetic audit log for the opt-in live S3 smoke test. No network access.
use gateway_runtime::{disk_log::DiskLog, transfer::{AuditLog, LogRecord, RecordKind}};
use gateway_core::metadata::{encode_request_start, encode_response_head, encode_completion};
use std::{path::Path, time::Duration};
fn main() {
    let path = std::env::args().nth(1).expect("log path");
    let mut log = DiskLog::create(Path::new(&path), 4, Duration::from_secs(5)).unwrap();
    let upload = br#"{"model":"s3-smoke-test","messages":[{"role":"user","content":"synthetic S3 shipper smoke test"}]}"#;
    let download = br#"{"model":"s3-smoke-test","content":[{"type":"text","text":"synthetic S3 shipper response"}]}"#;
    let start = encode_request_start(1_793_001_600_000, 1, b"https://api.anthropic.com/v1/messages").unwrap();
    let head = encode_response_head(1_793_001_600_100, 200).unwrap();
    let done = encode_completion(1_793_001_600_200, 0, upload.len() as u64, download.len() as u64).unwrap();
    for (chunk, kind, bytes) in [(0, RecordKind::RequestStart, start.as_slice()), (1, RecordKind::Upload, upload.as_slice()),
        (0, RecordKind::ResponseHead, head.as_slice()), (2, RecordKind::Download, download.as_slice()), (0, RecordKind::Completion, done.as_slice())] {
        log.append(LogRecord { tenant: 1, request: 1, chunk, kind, bytes }).unwrap();
    }
    log.shutdown(Duration::from_secs(5)).unwrap();
}
