//! Opt-in tests for scripts/check_storage.sh's private, size-limited ext4 image.
//! Never run these against an operator's normal log directory.
use gateway_runtime::{disk_log::{DiskLog, LogReader, ScanError}, transfer::{AuditLog, Direction, LogRecord}};
use std::{fs::{self, File}, io::Write, path::PathBuf, time::Duration};

fn fixture() -> PathBuf {
    assert!(cfg!(target_os = "linux"), "storage fixture requires Linux");
    let root = PathBuf::from(std::env::var_os("SOUNDGATE_STORAGE_TEST_DIR").expect("run scripts/check_storage.sh"));
    assert_eq!(fs::read(root.join(".soundgate-ext4-fixture")).unwrap(), b"soundgate-private-ext4-64MiB\n");
    root
}
struct TestDir(PathBuf);
impl Drop for TestDir { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn record(chunk: u64, bytes: &[u8]) -> LogRecord<'_> {
    LogRecord { tenant: 7, request: 11, chunk, direction: Direction::Upload, bytes }
}

#[tokio::test]
#[ignore = "requires the isolated ext4 fixture created by scripts/check_storage.sh"]
async fn filesystem_full_preserves_acknowledged_prefix_and_fails_closed() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let dir = TestDir(fixture().join("full-test")); fs::create_dir(&dir.0).unwrap();
        let path = dir.0.join("audit.log");
        let mut log = DiskLog::create(&path, 2, Duration::from_secs(5)).unwrap();
        let first = vec![17; 64 * 1024];
        log.append(record(1, &first)).await.unwrap();
        let session = log.session();
        let acknowledged_end = fs::metadata(&path).unwrap().len();

        // Bounded to 128 MiB even if the fixture was configured incorrectly.
        // Sync each block so delayed allocation cannot hide ENOSPC.
        let filler_path = dir.0.join("space-filler");
        let mut filler = File::create(&filler_path).unwrap();
        let block = vec![0; 1024 * 1024];
        let mut full = false;
        for _ in 0..128 {
            if let Err(error) = filler.write_all(&block).and_then(|()| filler.sync_all()) {
                assert_eq!(error.raw_os_error(), Some(28), "expected Linux ENOSPC: {error}");
                full = true; break;
            }
        }
        assert!(full, "private fixture did not fill within 128 MiB");
        drop(filler);
        assert!(log.append(record(2, &block)).await.is_err());
        assert!(!log.healthy());
        fs::remove_file(filler_path).unwrap();
        assert!(log.append(record(3, b"must not resume")).await.is_err());
        assert!(!log.healthy());
        log.shutdown(Duration::from_secs(2)).await.unwrap();
        let before = fs::read(&path).unwrap();
        assert!(before.len() as u64 >= acknowledged_end);
        let mut reader = LogReader::new(File::open(&path).unwrap()).unwrap();
        assert_eq!(reader.session(), session);
        let recovered = reader.next_record().unwrap().unwrap();
        assert_eq!((recovered.tenant, recovered.request, recovered.chunk), (7, 11, 1));
        assert_eq!(recovered.bytes, first);
        assert_eq!(reader.valid_end(), acknowledged_end);
        assert!(matches!(reader.next_record(), Ok(None) | Err(ScanError::Incomplete)));
        assert_eq!(reader.valid_end(), acknowledged_end);
        assert_eq!(fs::read(&path).unwrap(), before);

        assert!(DiskLog::create(&path, 1, Duration::from_secs(1)).is_err());
        let mut fresh = DiskLog::create(&dir.0.join("next.log"), 1, Duration::from_secs(5)).unwrap();
        assert_ne!(fresh.session(), session);
        fresh.append(record(1, b"fresh session")).await.unwrap();
        fresh.shutdown(Duration::from_secs(2)).await.unwrap();
        println!("ext4 ENOSPC: acknowledged prefix preserved, uncertain tail rejected, restart uses a fresh session");
    }).await.unwrap();
}

#[test]
#[ignore = "requires the isolated ext4 fixture remounted read-only by scripts/check_storage.sh"]
fn filesystem_read_only_refuses_logger_startup() {
    let path = fixture().join("readonly.log");
    let error = DiskLog::create(&path, 1, Duration::from_secs(1)).err().expect("read-only filesystem accepted creation");
    assert_eq!(error.raw_os_error(), Some(30), "expected Linux EROFS: {error}");
    assert!(!path.exists());
    println!("ext4 EROFS: logger startup refused without creating an audit file");
}
