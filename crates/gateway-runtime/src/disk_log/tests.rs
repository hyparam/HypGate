use super::*;
use std::{io::Cursor, sync::{Mutex, mpsc as blocking}, time::{SystemTime, UNIX_EPOCH}};

fn record(bytes: &[u8], chunk: u64) -> LogRecord<'_> {
    LogRecord { tenant: 1, request: 2, chunk, direction: Direction::Download, bytes }
}

#[tokio::test]
async fn strict_transfer_and_real_disk_records_have_identical_payloads() {
    use crate::{admission::Admission, transfer::copy_body};
    use gateway_core::policy::{Identity, Policy, Route};
    let route = || Route { tenant: 1, selector: 7, origin: 0, credential: 0 };
    let policy = Policy::validate(vec![Identity { tenant: 1, digest: vec![11; 32] }],
        vec![route()], vec![route()], 1, vec![1]).unwrap();
    let admission = Admission::new(policy, 1, 3, true);
    let mut request = admission.admit(&[11; 32], 7).unwrap();
    let dir = TempDir::new(); let path = dir.0.join("transfer.log");
    let mut log = DiskLog::create(&path, 1, Duration::from_secs(5)).unwrap();
    let input = b"data: hello\n\ndata: [DONE]\n\n";
    let mut output = Vec::new();
    let stats = copy_body(&mut request, &mut &input[..], &mut output, &mut log, Direction::Download).await.unwrap();
    assert_eq!(output, input);
    assert_eq!(stats.accepted_bytes, input.len() as u64);
    assert!(!stats.audit_gap);
    let mut reader = LogReader::new(File::open(path).unwrap()).unwrap();
    let mut recorded = Vec::new(); let mut expected_chunk = 1;
    while let Some(record) = reader.next_record().unwrap() {
        assert_eq!(record.request, request.request_id());
        assert_eq!(record.chunk, expected_chunk);
        assert_eq!(record.direction, Direction::Download);
        recorded.extend(record.bytes); expected_chunk += 1;
    }
    assert_eq!(recorded, input);
}
fn header() -> Vec<u8> {
    let mut h = FILE_MAGIC.to_vec(); h.extend_from_slice(&[7; 16]);
    h.extend_from_slice(&Sha256::digest(&h)); h
}
struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!("soundgate-log-{}-{}", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&p).unwrap(); Self(p)
    }
}
impl Drop for TempDir { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

#[tokio::test]
async fn actual_file_acknowledgments_are_readable_and_existing_files_are_not_overwritten() {
    let dir = TempDir::new(); let path = dir.0.join("traffic.log");
    let mut log = DiskLog::create(&path, 2, Duration::from_secs(5)).unwrap();
    log.append(record(b"data: hello\n\n", 1)).await.unwrap();
    log.append(record(b"data: [DONE]\n\n", 2)).await.unwrap();
    let mut reader = LogReader::new(File::open(&path).unwrap()).unwrap();
    assert_eq!(reader.session(), log.session());
    let first = reader.next_record().unwrap().unwrap();
    assert_eq!((first.tenant, first.request, first.chunk), (1, 2, 1));
    assert_eq!(first.bytes, b"data: hello\n\n");
    assert_eq!(reader.next_record().unwrap().unwrap().bytes, b"data: [DONE]\n\n");
    assert!(reader.next_record().unwrap().is_none());
    assert_eq!(reader.valid_end(), std::fs::metadata(&path).unwrap().len());
    assert!(DiskLog::create(&path, 2, Duration::from_secs(5)).is_err());
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn every_torn_record_tail_stops_at_the_last_complete_record() {
    let mut prefix = header(); prefix.extend(encode(record(b"first", 1)));
    let tail = encode(record(b"second", 2));
    for cut in 1..tail.len() {
        let mut file = prefix.clone(); file.extend_from_slice(&tail[..cut]);
        let mut reader = LogReader::new(Cursor::new(file)).unwrap();
        assert_eq!(reader.next_record().unwrap().unwrap().bytes, b"first");
        assert_eq!(reader.next_record(), Err(ScanError::Incomplete), "cut {cut}");
        assert_eq!(reader.valid_end(), prefix.len() as u64);
        assert!(reader.next_record().unwrap().is_none());
    }
    for cut in 0..FILE_HEADER {
        assert!(matches!(LogReader::new(Cursor::new(&header()[..cut])), Err(ScanError::Incomplete)));
    }
}

#[test]
fn corrupt_records_do_not_advance_the_valid_prefix_or_resynchronize() {
    let frame = encode(record(b"payload", 1));
    for offset in 0..frame.len() {
        let mut corrupted = frame.clone(); corrupted[offset] ^= 1;
        let mut file = header(); file.extend(corrupted); file.extend(encode(record(b"later", 2)));
        let mut reader = LogReader::new(Cursor::new(file)).unwrap();
        assert!(reader.next_record().is_err(), "offset {offset}");
        assert_eq!(reader.valid_end(), FILE_HEADER as u64);
        assert!(reader.next_record().unwrap().is_none());
    }
    let mut file = header(); file[8] ^= 1;
    assert!(matches!(LogReader::new(Cursor::new(file)), Err(ScanError::Corrupt)));
    let mut frame = encode(record(b"", 1)); frame[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    let mut file = header(); file.extend(frame);
    assert_eq!(LogReader::new(Cursor::new(file)).unwrap().next_record(), Err(ScanError::Corrupt));
}

struct Sink {
    bytes: Arc<Mutex<Vec<u8>>>,
    syncs: Arc<std::sync::atomic::AtomicUsize>,
    fail_write: bool,
    fail_sync: bool,
    gate: Option<(oneshot::Sender<()>, blocking::Receiver<()>)>,
}
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.fail_write { return Err(io::ErrorKind::StorageFull.into()); }
        let n = bytes.len().min(2); // exercise write_all partial-write accounting
        self.bytes.lock().unwrap().extend_from_slice(&bytes[..n]); Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl DurableWrite for Sink {
    fn sync(&mut self) -> io::Result<()> {
        self.syncs.fetch_add(1, Ordering::Relaxed);
        if let Some((entered, release)) = self.gate.take() {
            let _ = entered.send(()); let _ = release.recv();
        }
        if self.fail_sync { Err(io::ErrorKind::Other.into()) } else { Ok(()) }
    }
}
fn sink() -> Sink {
    Sink { bytes: Arc::new(Mutex::new(Vec::new())), syncs: Arc::default(),
        fail_write: false, fail_sync: false, gate: None }
}

#[tokio::test]
async fn write_and_sync_failures_never_acknowledge_and_poison_future_appends() {
    for fail_write in [true, false] {
        let mut file = sink(); file.fail_write = fail_write; file.fail_sync = !fail_write;
        let bytes = file.bytes.clone(); let syncs = file.syncs.clone();
        let mut log = DiskLog::start(file, 1, Duration::from_secs(1), [1; 16]).unwrap();
        assert!(log.append(record(b"first", 1)).await.is_err());
        assert!(!log.healthy());
        let length = bytes.lock().unwrap().len();
        assert!(log.append(record(b"second", 2)).await.is_err());
        assert_eq!(bytes.lock().unwrap().len(), length);
        assert_eq!(syncs.load(Ordering::Relaxed), if fail_write { 0 } else { 1 });
    }
}

#[tokio::test]
async fn blocked_disk_times_out_without_spawning_replacements() {
    let mut file = sink(); let syncs = file.syncs.clone();
    let (entered, started) = oneshot::channel(); let (release, wait) = blocking::channel();
    file.gate = Some((entered, wait));
    let mut log = DiskLog::start(file, 1, Duration::from_millis(20), [1; 16]).unwrap();
    let mut other = log.clone();
    let first = tokio::spawn(async move { log.append(record(b"first", 1)).await });
    started.await.unwrap();
    assert!(first.await.unwrap().is_err());
    assert!(!other.healthy());
    assert!(other.append(record(b"next", 2)).await.is_err());
    assert_eq!(syncs.load(Ordering::Relaxed), 1);
    release.send(()).unwrap();
}

#[tokio::test]
async fn queue_capacity_rejects_excess_work_before_allocation() {
    let mut file = sink(); let syncs = file.syncs.clone();
    let (entered, started) = oneshot::channel(); let (release, wait) = blocking::channel();
    file.gate = Some((entered, wait));
    let mut log = DiskLog::start(file, 1, Duration::from_secs(5), [1; 16]).unwrap();
    let mut first_log = log.clone(); let mut second_log = log.clone();
    let first = tokio::spawn(async move { first_log.append(record(b"first", 1)).await });
    started.await.unwrap();
    let second = tokio::spawn(async move { second_log.append(record(b"second", 2)).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while log.sender.capacity() != 0 { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert_eq!(log.append(record(b"third", 3)).await.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert!(log.healthy());
    release.send(()).unwrap();
    first.await.unwrap().unwrap(); second.await.unwrap().unwrap();
    assert_eq!(syncs.load(Ordering::Relaxed), 2);
}
