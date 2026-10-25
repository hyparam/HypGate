use super::*;
use crate::{test_support::{TempDir, admission}, transfer::copy_body};
use std::{io::Cursor, sync::{Mutex, mpsc as blocking}};

fn record(bytes: &[u8], chunk: u64) -> LogRecord<'_> {
    LogRecord { tenant: 1, request: 2, chunk, kind: RecordKind::Download, bytes }
}

#[tokio::test]
async fn strict_transfer_and_real_disk_records_have_identical_payloads() {
    let admission = admission(1, 3, true);
    let mut request = admission.admit(&[11; 32], 7).unwrap();
    let dir = TempDir::new(); let path = dir.0.join("transfer.log");
    let mut log = DiskLog::create_with_payload_limit(&path, 1, Duration::from_secs(5), 3).unwrap();
    let input = b"data: hello\n\ndata: [DONE]\n\n";
    let mut output = Vec::new();
    let stats = copy_body(&mut request, &mut &input[..], &mut output, &mut log, Direction::Download).await.unwrap();
    assert_eq!(output, input);
    assert_eq!(stats.accepted_bytes(), input.len() as u64);
    assert!(!stats.audit_gap());
    let mut reader = LogReader::new(File::open(path).unwrap()).unwrap();
    let mut recorded = Vec::new(); let mut expected_chunk = 1;
    while let Some(record) = reader.next_record().unwrap() {
        assert_eq!(record.request, request.request_id());
        assert_eq!(record.chunk, expected_chunk);
        assert_eq!(record.direction(), Some(Direction::Download));
        recorded.extend(record.bytes); expected_chunk += 1;
    }
    assert_eq!(recorded, input);
}
fn header() -> Vec<u8> {
    let mut h = FILE_MAGIC.to_vec(); h.extend_from_slice(&[7; 16]);
    h.extend_from_slice(&Sha256::digest(&h)); h
}

#[tokio::test]
async fn maximum_record_roundtrips_and_excess_is_rejected_without_poisoning() {
    let dir = TempDir::new(); let path = dir.0.join("maximum.log");
    let mut log = DiskLog::create(&path, 1, Duration::from_secs(5)).unwrap();
    let payload: Vec<u8> = (0..MAX_RECORD_BYTES).map(|i| (i % 251) as u8).collect();
    // Exercise the maximum supported frame on the production worker stack.
    drop(log.append(record(&payload, 1)).await.unwrap());
    let excess = vec![0; MAX_RECORD_BYTES + 1];
    assert!(matches!(log.append(record(&excess, 2)).await, Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    assert!(log.healthy());
    drop(log.append(record(b"after", 2)).await.unwrap());
    log.shutdown(Duration::from_secs(5)).await.unwrap();
    let mut reader = LogReader::new(File::open(&path).unwrap()).unwrap();
    assert_eq!(reader.next_record().unwrap().unwrap().bytes, payload);
    let next = reader.next_record().unwrap().unwrap();
    assert_eq!(next.chunk, 2); assert_eq!(next.bytes, b"after");
    assert!(reader.next_record().unwrap().is_none());
    assert_eq!(reader.valid_end(), std::fs::metadata(path).unwrap().len());
}

#[tokio::test]
async fn actual_file_acknowledgments_are_readable_and_existing_files_are_not_overwritten() {
    let dir = TempDir::new(); let path = dir.0.join("traffic.log");
    let mut log = DiskLog::create(&path, 2, Duration::from_secs(5)).unwrap();
    let receipt = log.append(record(b"data: hello\n\n", 1)).await.unwrap();
    assert_eq!(receipt.session_id(), u128::from_le_bytes(log.session()));
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
async fn dropping_final_logger_handle_wakes_and_releases_idle_worker() {
    struct OwnedSink { file: Sink, done: Option<oneshot::Sender<()>> }
    impl Write for OwnedSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.file.write(bytes) }
        fn flush(&mut self) -> io::Result<()> { self.file.flush() }
    }
    impl DurableWrite for OwnedSink { fn sync(&mut self) -> io::Result<()> { self.file.sync() } }
    impl Drop for OwnedSink { fn drop(&mut self) { let _ = self.done.take().unwrap().send(()); } }
    let (done, released) = oneshot::channel();
    let mut log = DiskLog::start(OwnedSink { file: sink(), done: Some(done) }, 1, Duration::from_secs(2), [0; 16]).unwrap();
    drop(log.append(record(b"complete", 1)).await.unwrap());
    let last = log.clone(); drop(log);
    assert!(last.healthy());
    drop(last);
    tokio::time::timeout(Duration::from_secs(2), released).await.unwrap().unwrap();
}

#[tokio::test]
async fn poisoned_fixed_queue_refuses_logging_and_worker_can_shutdown() {
    let mut log = DiskLog::start(sink(), 1, Duration::from_secs(2), [0; 16]).unwrap();
    let queue = log.queue.0.clone();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        queue.panic_during_encoding();
    })).is_err());
    assert!(!log.healthy());
    assert!(matches!(log.append(record(b"refused", 1)).await, Err(error) if error.kind() == io::ErrorKind::BrokenPipe));
    log.shutdown(Duration::from_secs(2)).await.unwrap();
    assert!(log.thread.lock().unwrap().is_none());
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
async fn full_queue_parks_excess_work_before_allocation_and_serves_it_in_order() {
    let mut file = sink(); let syncs = file.syncs.clone(); let bytes = file.bytes.clone();
    let (entered, started) = oneshot::channel(); let (release, wait) = blocking::channel();
    file.gate = Some((entered, wait));
    let log = DiskLog::start(file, 1, Duration::from_secs(5), [1; 16]).unwrap();
    let mut first_log = log.clone(); let mut second_log = log.clone(); let mut third_log = log.clone();
    let first = tokio::spawn(async move { first_log.append(record(b"first", 1)).await });
    started.await.unwrap();
    let second = tokio::spawn(async move { second_log.append(record(b"second", 2)).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while log.queued_for_test() != 1 { tokio::task::yield_now().await; }
    }).await.unwrap();
    // The third append waits for a slot instead of failing; while it waits nothing
    // is reserved or encoded, and the logger stays healthy.
    let third = tokio::spawn(async move { third_log.append(record(b"third", 3)).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!third.is_finished());
    assert_eq!(log.queued_for_test(), 1);
    assert!(log.healthy());
    assert_eq!(syncs.load(Ordering::Relaxed), 1); // Only the blocked first sync.
    release.send(()).unwrap();
    first.await.unwrap().unwrap(); second.await.unwrap().unwrap(); third.await.unwrap().unwrap();
    assert_eq!(syncs.load(Ordering::Relaxed), 3);
    let mut expected = encode(record(b"first", 1));
    expected.extend(encode(record(b"second", 2))); expected.extend(encode(record(b"third", 3)));
    assert_eq!(*bytes.lock().unwrap(), expected);
    assert!(log.healthy());
}

#[tokio::test]
async fn slot_wait_is_bounded_by_the_deadline_and_poisons_health() {
    let mut file = sink(); let syncs = file.syncs.clone();
    let (entered, started) = oneshot::channel(); let (release, wait) = blocking::channel();
    file.gate = Some((entered, wait));
    let mut log = DiskLog::start(file, 1, Duration::from_millis(40), [1; 16]).unwrap();
    let mut first_log = log.clone(); let mut second_log = log.clone();
    let first = tokio::spawn(async move { first_log.append(record(b"first", 1)).await });
    started.await.unwrap();
    let second = tokio::spawn(async move { second_log.append(record(b"second", 2)).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while log.queued_for_test() != 1 { tokio::task::yield_now().await; }
    }).await.unwrap();
    // A worker that never frees a slot is indistinguishable from one that never
    // acknowledges: the waiting append fails at its deadline and health closes.
    let started_waiting = tokio::time::Instant::now();
    assert_eq!(log.append(record(b"third", 3)).await.err().unwrap().kind(), io::ErrorKind::BrokenPipe);
    assert!(started_waiting.elapsed() >= Duration::from_millis(40));
    assert!(!log.healthy());
    assert_eq!(log.queued_for_test(), 1);
    assert!(first.await.unwrap().is_err()); assert!(second.await.unwrap().is_err());
    assert_eq!(syncs.load(Ordering::Relaxed), 1);
    release.send(()).unwrap();
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
    while log.queued_for_test() != 1 {
        tokio::task::yield_now().await;
    }
    let closing = log.clone();
    let closing = tokio::spawn(async move { closing.shutdown(Duration::from_secs(2)).await });
    while log.healthy() { tokio::task::yield_now().await; }
    assert!(!closing.is_finished());
    assert!(log.clone().append(record(b"late", 3)).await.is_err());
    release.send(()).unwrap();
    first.await.unwrap().unwrap(); second.await.unwrap().unwrap(); closing.await.unwrap().unwrap();
    assert!(log.thread.lock().unwrap().is_none());
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
    assert!(log.thread.lock().unwrap().is_some());
    assert!(log.clone().append(record(b"late", 2)).await.is_err());
    release.send(()).unwrap();
    // The already-running sync may still finish durably after timeout.
    pending.await.unwrap().unwrap();
    log.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(log.thread.lock().unwrap().is_none());
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
        let call_count = source.calls.clone();
        let mut scanner = LogReader::new(source).unwrap();
        assert_eq!(scanner.next_record().unwrap().unwrap().bytes, b"first");
        assert_eq!(scanner.next_record().unwrap().unwrap().bytes, b"second");
        assert!(scanner.next_record().unwrap().is_none());
        assert_eq!(scanner.valid_end(), bytes.len() as u64);
        let calls = call_count.load(Ordering::Relaxed);
        assert!(scanner.next_record().unwrap().is_none());
        assert_eq!(call_count.load(Ordering::Relaxed), calls);
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
        let call_count = source.calls.clone();
        let mut scanner = LogReader::new(source).unwrap();
        assert_eq!(scanner.next_record().unwrap().unwrap().bytes, b"first");
        // A fault at the boundary after record two occurs on the following read.
        let expected_end = if fail_at == bytes.len() as u64 {
            assert_eq!(scanner.next_record().unwrap().unwrap().bytes, b"second");
            fail_at
        } else { prefix };
        assert_eq!(scanner.next_record(), Err(ScanError::Io), "fault at {fail_at}");
        assert_eq!(scanner.valid_end(), expected_end);
        let calls = call_count.load(Ordering::Relaxed);
        assert!(scanner.next_record().unwrap().is_none());
        assert_eq!(call_count.load(Ordering::Relaxed), calls);
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
        while !log.thread.lock().unwrap().as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
        // No live append observer or deadline was needed to detect worker death.
        assert!(!log.healthy());
        assert!(log.clone().append(record(b"later", 2)).await.is_err());
        assert_eq!(log.shutdown(Duration::from_secs(1)).await.unwrap_err().kind(), io::ErrorKind::Other);
        assert!(log.thread.lock().unwrap().is_none());
    }).await.unwrap();
}

#[tokio::test]
async fn canceling_append_callers_does_not_release_queued_or_active_frame_credit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut file = sink(); let syncs = file.syncs.clone(); let bytes = file.bytes.clone();
        let (entered, started) = oneshot::channel(); let (release, wait) = blocking::channel();
        file.gate = Some((entered, wait));
        let mut log = DiskLog::start(file, 1, Duration::from_secs(30), [1; 16]).unwrap();
        let mut first_log = log.clone(); let mut second_log = log.clone();
        let first = tokio::spawn(async move { first_log.append(record(b"active", 1)).await });
        started.await.unwrap();
        let second = tokio::spawn(async move { second_log.append(record(b"queued", 2)).await });
        while log.queued_for_test() != 1 { tokio::task::yield_now().await; }
        first.abort(); second.abort();
        assert!(first.await.err().unwrap().is_cancelled());
        assert!(second.await.err().unwrap().is_cancelled());
        // Aborting both callers must not free the slot occupied by their work.
        // The active worker still owns its first frame, and the queued frame
        // still owns the only channel credit even though both receipts will be lost.
        assert_eq!(log.queued_for_test(), 1);
        assert_eq!(syncs.load(Ordering::Relaxed), 1);
        assert!(log.healthy());
        // A further append waits behind the canceled callers' frames; it reserves
        // nothing until the worker frees the slot they still occupy.
        let mut excess_log = log.clone();
        let excess = tokio::spawn(async move { excess_log.append(record(b"excess", 3)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!excess.is_finished());
        assert_eq!(log.queued_for_test(), 1);
        assert_eq!(*bytes.lock().unwrap(), encode(record(b"active", 1)));
        release.send(()).unwrap();
        let receipt = excess.await.unwrap().unwrap();
        assert!(receipt.matches_record(Header { payload: 6, tenant: 1, request: 2,
            chunk: 3, kind: 1 }, b"excess"));
        while log.queued_for_test() != 0 { tokio::task::yield_now().await; }
        // The same worker continues. There is no retry of either canceled job;
        // a later caller receives only its own receipt.
        let receipt = log.append(record(b"later", 4)).await.unwrap();
        assert!(receipt.matches_record(Header { payload: 5, tenant: 1, request: 2,
            chunk: 4, kind: 1 }, b"later"));
        log.shutdown(Duration::from_secs(1)).await.unwrap();
        let mut expected = encode(record(b"active", 1));
        expected.extend(encode(record(b"queued", 2)));
        expected.extend(encode(record(b"excess", 3)));
        expected.extend(encode(record(b"later", 4)));
        assert_eq!(*bytes.lock().unwrap(), expected);
        assert_eq!(syncs.load(Ordering::Relaxed), 4);
    }).await.unwrap();
}

#[tokio::test]
async fn configured_record_limit_is_shared_by_clones_and_rejects_before_queueing() {
    let dir = TempDir::new(); let path = dir.0.join("limited.log");
    for invalid in [0, MAX_RECORD_BYTES + 1] {
        assert!(matches!(DiskLog::create_with_payload_limit(&path, 1, Duration::from_secs(5), invalid),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput));
        assert!(!path.exists());
    }
    let log = DiskLog::create_with_payload_limit(&path, 1, Duration::from_secs(5), 3).unwrap();
    let mut clone = log.clone();
    assert!(matches!(clone.append(record(b"four", 1)).await,
        Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    assert_eq!(log.queued_for_test(), 0); assert!(log.healthy());
    drop(clone.append(record(b"abc", 2)).await.unwrap());
    drop(clone);
    log.shutdown(Duration::from_secs(5)).await.unwrap();
    let mut reader = LogReader::new(File::open(&path).unwrap()).unwrap();
    let recovered = reader.next_record().unwrap().unwrap();
    assert_eq!(recovered.chunk, 2); assert_eq!(recovered.bytes, b"abc");
    assert!(reader.next_record().unwrap().is_none());
}

fn metadata_record(kind: RecordKind, request: u64, bytes: &[u8]) -> LogRecord<'_> {
    LogRecord { tenant: 1, request, chunk: 0, kind, bytes }
}
fn start_payload() -> Vec<u8> {
    gateway_core::metadata::encode_request_start(1_700_000_000_000, 7, b"https://localhost:8443/v1/messages").unwrap()
}
fn head_payload() -> Vec<u8> { gateway_core::metadata::encode_response_head(1_700_000_000_001, 200).unwrap() }
fn done_payload() -> Vec<u8> { gateway_core::metadata::encode_completion(1_700_000_000_002, 0, 15, 27).unwrap() }
// Rewrite a sealed frame's header byte and recompute the digest, so only the
// structural check can reject it.
fn resealed(mut frame: Vec<u8>, offset: usize, value: u8) -> Vec<u8> {
    frame[offset] = value;
    let body_len = frame.len() - 32;
    let digest: [u8; 32] = Sha256::digest(&frame[..body_len]).into();
    frame[body_len..].copy_from_slice(&digest); frame
}

#[tokio::test]
async fn metadata_records_roundtrip_through_disk_and_scanner() {
    use super::Metadata;
    let dir = TempDir::new(); let path = dir.0.join("metadata.log");
    let mut log = DiskLog::create_with_payload_limit(&path, 2, Duration::from_secs(5), 8210).unwrap();
    let (start, head, done) = (start_payload(), head_payload(), done_payload());
    for (kind, payload) in [(RecordKind::RequestStart, &start), (RecordKind::ResponseHead, &head), (RecordKind::Completion, &done)] {
        let receipt = log.append(metadata_record(kind, 2, payload)).await.unwrap();
        assert!(receipt.matches_record(Header { payload: payload.len() as u32, tenant: 1, request: 2, chunk: 0, kind: kind.id() }, payload));
    }
    log.shutdown(Duration::from_secs(5)).await.unwrap();
    let mut reader = LogReader::new(File::open(&path).unwrap()).unwrap();
    let records: Vec<_> = std::iter::from_fn(|| reader.next_record().unwrap()).collect();
    assert_eq!(records.iter().map(|r| (r.kind, r.chunk, r.direction())).collect::<Vec<_>>(),
        vec![(RecordKind::RequestStart, 0, None), (RecordKind::ResponseHead, 0, None), (RecordKind::Completion, 0, None)]);
    match records[0].metadata().unwrap() {
        Metadata::RequestStart(m) => {
            assert_eq!((m.time_ms, m.selector), (1_700_000_000_000, 7));
            assert_eq!(m.destination, b"https://localhost:8443/v1/messages");
        }
        other => panic!("{other:?}"),
    }
    match records[1].metadata().unwrap() {
        Metadata::ResponseHead(m) => assert_eq!((m.time_ms, m.status), (1_700_000_000_001, 200)),
        other => panic!("{other:?}"),
    }
    match records[2].metadata().unwrap() {
        Metadata::Completion(m) => assert_eq!((m.time_ms, m.outcome, m.upload_bytes, m.download_bytes), (1_700_000_000_002, 0, 15, 27)),
        other => panic!("{other:?}"),
    }
    assert_eq!(reader.valid_end(), std::fs::metadata(&path).unwrap().len());
}

#[test]
fn metadata_record_truncation_and_bit_flips_stop_the_scanner() {
    let (start, head, done) = (start_payload(), head_payload(), done_payload());
    for (kind, payload) in [(RecordKind::RequestStart, &start), (RecordKind::ResponseHead, &head), (RecordKind::Completion, &done)] {
        let mut prefix = header(); prefix.extend(encode(record(b"body", 1)));
        let tail = encode(metadata_record(kind, 2, payload));
        for cut in 1..tail.len() {
            let mut file = prefix.clone(); file.extend_from_slice(&tail[..cut]);
            let mut reader = LogReader::new(Cursor::new(file)).unwrap();
            assert_eq!(reader.next_record().unwrap().unwrap().bytes, b"body");
            assert_eq!(reader.next_record(), Err(ScanError::Incomplete), "{kind:?} cut {cut}");
            assert_eq!(reader.valid_end(), prefix.len() as u64);
            assert!(reader.next_record().unwrap().is_none());
        }
        for offset in 0..tail.len() {
            for bit in 0..8 {
                let mut corrupted = tail.clone(); corrupted[offset] ^= 1 << bit;
                let mut file = header(); file.extend(corrupted); file.extend(encode(record(b"later", 2)));
                let mut reader = LogReader::new(Cursor::new(file)).unwrap();
                assert!(reader.next_record().is_err(), "{kind:?} offset {offset} bit {bit}");
                assert_eq!(reader.valid_end(), FILE_HEADER as u64);
                assert!(reader.next_record().unwrap().is_none());
            }
        }
    }
}

#[test]
fn interleaved_kinds_from_two_requests_scan_in_order_and_unknown_kind_is_corrupt() {
    let (start, head, done) = (start_payload(), head_payload(), done_payload());
    let body = |request, chunk, kind, bytes| LogRecord { tenant: 1, request, chunk, kind, bytes };
    let sequence = [
        metadata_record(RecordKind::RequestStart, 2, &start), metadata_record(RecordKind::RequestStart, 3, &start),
        body(2, 1, RecordKind::Upload, b"ab"), body(3, 1, RecordKind::Upload, b"cd"),
        metadata_record(RecordKind::ResponseHead, 3, &head), metadata_record(RecordKind::ResponseHead, 2, &head),
        body(3, 2, RecordKind::Download, b"ef"), body(2, 2, RecordKind::Download, b"gh"),
        metadata_record(RecordKind::Completion, 3, &done), metadata_record(RecordKind::Completion, 2, &done),
    ];
    let mut file = header();
    let expected: Vec<_> = sequence.iter().map(|r| (r.request, r.chunk, r.kind, r.bytes.to_vec())).collect();
    for record in sequence { file.extend(encode(record)); }
    let mut reader = LogReader::new(Cursor::new(file.clone())).unwrap();
    let scanned: Vec<_> = std::iter::from_fn(|| reader.next_record().unwrap())
        .map(|r| (r.request, r.chunk, r.kind, r.bytes)).collect();
    assert_eq!(scanned, expected);
    assert_eq!(reader.valid_end(), file.len() as u64);
    // Kind 5 with a correct checksum is still structurally invalid: the scanner
    // stops before it and never resynchronizes on the valid record that follows.
    let unknown = resealed(encode(metadata_record(RecordKind::Completion, 2, &done)), 32, 5);
    assert_eq!(unknown[32], 5);
    let mut file = header(); file.extend(encode(record(b"first", 1)));
    let prefix = file.len() as u64;
    file.extend(unknown); file.extend(encode(record(b"after", 2)));
    let mut reader = LogReader::new(Cursor::new(file)).unwrap();
    assert_eq!(reader.next_record().unwrap().unwrap().bytes, b"first");
    assert_eq!(reader.next_record(), Err(ScanError::Corrupt));
    assert_eq!(reader.valid_end(), prefix);
    assert!(reader.next_record().unwrap().is_none());
    // Every recorded kind byte is accepted; the first unknown one is not.
    for kind in 0..=4u8 {
        let mut file = header(); file.extend(resealed(encode(record(b"abc", 1)), 32, kind));
        assert_eq!(LogReader::new(Cursor::new(file)).unwrap().next_record().unwrap().unwrap().kind.id(), kind);
    }
}

#[test]
fn malformed_metadata_payloads_scan_as_frames_but_do_not_decode() {
    // Framing and checksum are valid, so the record is returned; the verified
    // codec rejects the payload, and the scanner neither stops nor guesses.
    let mut oversized = start_payload(); oversized[16..18].copy_from_slice(&8193u16.to_le_bytes());
    let mut too_short = start_payload(); too_short.pop();
    let mut zero_length = start_payload(); zero_length[16..18].copy_from_slice(&0u16.to_le_bytes());
    let mut bad_status = head_payload(); bad_status[8..10].copy_from_slice(&99u16.to_le_bytes());
    let mut high_status = head_payload(); high_status[8..10].copy_from_slice(&1000u16.to_le_bytes());
    let mut bad_outcome = done_payload(); bad_outcome[8] = 8;
    let cases: [(RecordKind, &[u8]); 8] = [
        (RecordKind::RequestStart, &oversized), (RecordKind::RequestStart, &too_short), (RecordKind::RequestStart, &zero_length),
        (RecordKind::RequestStart, b""), (RecordKind::ResponseHead, &bad_status), (RecordKind::ResponseHead, &high_status),
        (RecordKind::ResponseHead, b"short"), (RecordKind::Completion, &bad_outcome),
    ];
    for (kind, payload) in cases {
        let mut file = header(); file.extend(encode(metadata_record(kind, 2, payload))); file.extend(encode(record(b"after", 1)));
        let mut reader = LogReader::new(Cursor::new(file.clone())).unwrap();
        let malformed = reader.next_record().unwrap().unwrap();
        assert_eq!((malformed.kind, malformed.bytes.as_slice()), (kind, payload));
        assert!(malformed.metadata().is_none(), "{kind:?} {payload:?}");
        assert_eq!(reader.next_record().unwrap().unwrap().bytes, b"after");
        assert_eq!(reader.valid_end(), file.len() as u64);
    }
    // Boundary values that the codecs accept decode through the scanner too.
    let longest = gateway_core::metadata::encode_request_start(0, 0, &vec![b'a'; 8192]).unwrap();
    assert_eq!(longest.len(), gateway_core::metadata::MAX_PAYLOAD);
    for (kind, payload) in [(RecordKind::RequestStart, longest), (RecordKind::ResponseHead, gateway_core::metadata::encode_response_head(0, 999).unwrap()),
        (RecordKind::Completion, gateway_core::metadata::encode_completion(0, 7, u64::MAX, u64::MAX).unwrap())] {
        let mut file = header(); file.extend(encode(metadata_record(kind, 2, &payload)));
        assert!(LogReader::new(Cursor::new(file)).unwrap().next_record().unwrap().unwrap().metadata().is_some());
    }
}
