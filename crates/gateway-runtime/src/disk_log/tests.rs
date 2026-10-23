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
        while log.worker.lock().unwrap().sender.as_ref().unwrap().capacity() != 0 { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert_eq!(log.append(record(b"third", 3)).await.err().unwrap().kind(), io::ErrorKind::WouldBlock);
    assert!(log.healthy());
    release.send(()).unwrap();
    first.await.unwrap().unwrap(); second.await.unwrap().unwrap();
    assert_eq!(syncs.load(Ordering::Relaxed), 2);
}


#[tokio::test]
async fn shutdown_closes_all_clones_drains_admitted_jobs_and_joins() {
    let mut file = sink();
    let bytes = file.bytes.clone();
    let (entered, inside) = oneshot::channel();
    let (release, wait) = blocking::channel();
    file.gate = Some((entered, wait));
    let log = DiskLog::start(file, 2, Duration::from_secs(5), [0; 16]).unwrap();
    let mut first = log.clone();
    let first = tokio::spawn(async move { first.append(record(b"first", 1)).await });
    inside.await.unwrap();
    let mut second = log.clone();
    let second = tokio::spawn(async move { second.append(record(b"second", 2)).await });
    while log.worker.lock().unwrap().sender.as_ref().unwrap().capacity() != 1 {
        tokio::task::yield_now().await;
    }
    let closing = log.clone();
    let closing = tokio::spawn(async move { closing.shutdown(Duration::from_secs(2)).await });
    while log.healthy() { tokio::task::yield_now().await; }
    assert!(!closing.is_finished());
    assert!(log.clone().append(record(b"late", 3)).await.is_err());
    release.send(()).unwrap();
    first.await.unwrap().unwrap(); second.await.unwrap().unwrap(); closing.await.unwrap().unwrap();
    assert!(log.worker.lock().unwrap().thread.is_none());
    let mut expected = encode(record(b"first", 1)); expected.extend(encode(record(b"second", 2)));
    assert_eq!(*bytes.lock().unwrap(), expected);
    log.shutdown(Duration::from_secs(1)).await.unwrap();
}

#[tokio::test]
async fn shutdown_deadline_does_not_wait_for_stuck_sync_or_replace_worker() {
    let mut file = sink();
    let (entered, inside) = oneshot::channel();
    let (release, wait) = blocking::channel();
    file.gate = Some((entered, wait));
    let log = DiskLog::start(file, 1, Duration::from_secs(5), [0; 16]).unwrap();
    let mut pending = log.clone();
    let pending = tokio::spawn(async move { pending.append(record(b"pending", 1)).await });
    inside.await.unwrap();
    assert_eq!(log.shutdown(Duration::from_millis(20)).await.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(!log.healthy());
    assert!(log.worker.lock().unwrap().thread.is_some());
    assert!(log.clone().append(record(b"late", 2)).await.is_err());
    release.send(()).unwrap();
    // The already-running sync may still finish durably after timeout.
    pending.await.unwrap().unwrap();
    log.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(log.worker.lock().unwrap().thread.is_none());
}

// Errors are transient at the source so a scanner that incorrectly resumes could
// consume later bytes. Observe read calls as well as the reported valid offset.
struct FaultReader {
    bytes: Cursor<Vec<u8>>,
    fail_at: Option<u64>,
    interrupt_next: bool,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    fragment: usize,
}
impl Read for FaultReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.interrupt_next {
            self.interrupt_next = false;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.interrupt_next = true;
        if self.fail_at == Some(self.bytes.position()) {
            self.fail_at = None;
            return Err(io::ErrorKind::Other.into());
        }
        let before_fault = self.fail_at.map(|end| (end - self.bytes.position()) as usize).unwrap_or(usize::MAX);
        let n = out.len().min(self.fragment).min(before_fault);
        self.bytes.read(&mut out[..n])
    }
}

#[test]
fn scanner_retries_interruptions_and_fragmented_reads_without_changing_records() {
    let mut bytes = header();
    bytes.extend(encode(record(b"first", 1)));
    bytes.extend(encode(record(b"second", 2)));
    for fragment in [1, 2, 7, 33, 128] {
        let source = FaultReader { bytes: Cursor::new(bytes.clone()), fail_at: None,
            interrupt_next: true, calls: Arc::default(), fragment };
        let mut scanner = LogReader::new(source).unwrap();
        assert_eq!(scanner.next_record().unwrap().unwrap().bytes, b"first");
        assert_eq!(scanner.next_record().unwrap().unwrap().bytes, b"second");
        assert!(scanner.next_record().unwrap().is_none());
        assert_eq!(scanner.valid_end(), bytes.len() as u64);
        let calls = scanner.reader.calls.load(Ordering::Relaxed);
        assert!(scanner.next_record().unwrap().is_none());
        assert_eq!(scanner.reader.calls.load(Ordering::Relaxed), calls);
    }
}

#[test]
fn scanner_io_error_at_every_record_byte_preserves_prefix_and_stops_reading() {
    let mut bytes = header(); bytes.extend(encode(record(b"first", 1)));
    let prefix = bytes.len() as u64;
    bytes.extend(encode(record(b"second", 2)));
    for fail_at in prefix..=bytes.len() as u64 {
        let calls = Arc::default();
        let source = FaultReader { bytes: Cursor::new(bytes.clone()), fail_at: Some(fail_at),
            interrupt_next: true, calls, fragment: 7 };
        let mut scanner = LogReader::new(source).unwrap();
        assert_eq!(scanner.next_record().unwrap().unwrap().bytes, b"first");
        // A fault at the boundary after record two occurs on the following read.
        let expected_end = if fail_at == bytes.len() as u64 {
            assert_eq!(scanner.next_record().unwrap().unwrap().bytes, b"second");
            fail_at
        } else { prefix };
        assert_eq!(scanner.next_record(), Err(ScanError::Io), "fault at {fail_at}");
        assert_eq!(scanner.valid_end(), expected_end);
        let calls = scanner.reader.calls.load(Ordering::Relaxed);
        assert!(scanner.next_record().unwrap().is_none());
        assert_eq!(scanner.reader.calls.load(Ordering::Relaxed), calls);
        assert_eq!(scanner.valid_end(), expected_end);
    }
}


#[tokio::test]
async fn worker_panic_marks_health_failed_even_after_append_caller_is_canceled() {
    struct PanicSync { entered: Option<oneshot::Sender<()>>, release: blocking::Receiver<()> }
    impl Write for PanicSync {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { Ok(bytes.len()) }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    impl DurableWrite for PanicSync {
        fn sync(&mut self) -> io::Result<()> {
            self.entered.take().unwrap().send(()).unwrap();
            self.release.recv().unwrap();
            panic!("injected disk worker panic");
        }
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        let (entered, inside) = oneshot::channel();
        let (release, wait) = blocking::channel();
        let log = DiskLog::start(PanicSync { entered: Some(entered), release: wait },
            1, Duration::from_secs(60), [0; 16]).unwrap();
        let mut caller = log.clone();
        let caller = tokio::spawn(async move { caller.append(record(b"pending", 1)).await });
        inside.await.unwrap();
        caller.abort(); assert!(caller.await.err().unwrap().is_cancelled());
        assert!(log.healthy());
        release.send(()).unwrap();
        while !log.worker.lock().unwrap().thread.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
        // No live append observer or deadline was needed to detect worker death.
        assert!(!log.healthy());
        assert!(log.clone().append(record(b"later", 2)).await.is_err());
        assert_eq!(log.shutdown(Duration::from_secs(1)).await.unwrap_err().kind(), io::ErrorKind::Other);
        assert!(log.worker.lock().unwrap().thread.is_none());
    }).await.unwrap();
}
