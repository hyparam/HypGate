use super::*;
use crate::{test_support::{TempDir, admission, wait_until}, transfer::copy_body};
use std::{io::Cursor, sync::{Mutex, mpsc as blocking}, thread};

fn record(bytes: &[u8], chunk: u64) -> LogRecord<'_> {
    LogRecord { tenant: 1, request: 2, chunk, kind: RecordKind::Download, bytes }
}
const WAIT: Duration = Duration::from_secs(5);

#[test]
fn strict_transfer_and_real_disk_records_have_identical_payloads() { strict_transfer(false); }

#[test]
fn strict_transfer_spans_rotations_without_changing_receipt_identity() { strict_transfer(true); }

fn strict_transfer(rotate: bool) {
    let admission = admission(1, 3, true);
    let mut request = admission.admit(&[11; 32], 7).unwrap();
    let dir = TempDir::new(); let path = dir.0.join("transfer.log");
    let mut log = if rotate {
        DiskLog::create_rotating(&path, 1, WAIT, 3, Rotation { max_bytes: 124, ..Default::default() }).unwrap()
    } else { DiskLog::create_with_payload_limit(&path, 1, WAIT, 3).unwrap() };
    let input = b"data: hello\n\ndata: [DONE]\n\n";
    let mut output = Vec::new();
    let stats = copy_body(&mut request, &mut &input[..], &mut output, &mut log, Direction::Download).unwrap();
    assert_eq!(output, input);
    assert_eq!(stats.accepted_bytes(), input.len() as u64);
    assert!(!stats.audit_gap());
    let mut reader = SessionReader::open(&path).unwrap();
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
    let sum = sha256::digest(&h); h.extend_from_slice(&sum); h
}

#[test]
fn maximum_record_roundtrips_and_excess_is_rejected_without_poisoning() {
    let dir = TempDir::new(); let path = dir.0.join("maximum.log");
    let mut log = DiskLog::create(&path, 1, Duration::from_secs(5)).unwrap();
    let payload: Vec<u8> = (0..MAX_RECORD_BYTES).map(|i| (i % 251) as u8).collect();
    // Exercise the maximum supported frame on the production worker stack.
    drop(log.append(record(&payload, 1)).unwrap());
    let excess = vec![0; MAX_RECORD_BYTES + 1];
    assert!(matches!(log.append(record(&excess, 2)), Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    assert!(log.healthy());
    drop(log.append(record(b"after", 2)).unwrap());
    log.shutdown(Duration::from_secs(5)).unwrap();
    let mut reader = LogReader::new(File::open(&path).unwrap()).unwrap();
    assert_eq!(reader.next_record().unwrap().unwrap().bytes, payload);
    let next = reader.next_record().unwrap().unwrap();
    assert_eq!(next.chunk, 2); assert_eq!(next.bytes, b"after");
    assert!(reader.next_record().unwrap().is_none());
    assert_eq!(reader.valid_end(), std::fs::metadata(path).unwrap().len());
}

#[test]
fn actual_file_acknowledgments_are_readable_and_existing_files_are_not_overwritten() {
    let dir = TempDir::new(); let path = dir.0.join("traffic.log");
    let mut log = DiskLog::create(&path, 2, Duration::from_secs(5)).unwrap();
    let receipt = log.append(record(b"data: hello\n\n", 1)).unwrap();
    assert_eq!(receipt.session_id(), u128::from_le_bytes(log.session()));
    log.append(record(b"data: [DONE]\n\n", 2)).unwrap();
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
    gate: Option<(blocking::Sender<()>, blocking::Receiver<()>)>,
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
/// A sink whose first sync blocks until the returned sender fires; the
/// receiver reports that the sync has been entered.
fn gated_sink() -> (Sink, blocking::Receiver<()>, blocking::Sender<()>) {
    let mut file = sink();
    let (entered, started) = blocking::channel(); let (release, wait) = blocking::channel();
    file.gate = Some((entered, wait));
    (file, started, release)
}
/// Run an append on its own thread, returning a handle to its result.
fn append_on_thread(mut log: DiskLog, bytes: &'static [u8], chunk: u64) -> thread::JoinHandle<io::Result<AuditReceipt>> {
    thread::spawn(move || log.append(record(bytes, chunk)))
}

#[test]
fn dropping_final_logger_handle_wakes_and_releases_idle_worker() {
    struct OwnedSink { file: Sink, done: Option<blocking::Sender<()>> }
    impl Write for OwnedSink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.file.write(bytes) }
        fn flush(&mut self) -> io::Result<()> { self.file.flush() }
    }
    impl DurableWrite for OwnedSink { fn sync(&mut self) -> io::Result<()> { self.file.sync() } }
    impl Drop for OwnedSink { fn drop(&mut self) { let _ = self.done.take().unwrap().send(()); } }
    let (done, released) = blocking::channel();
    let mut log = DiskLog::start(OwnedSink { file: sink(), done: Some(done) }, 1, Duration::from_secs(2), [0; 16]).unwrap();
    drop(log.append(record(b"complete", 1)).unwrap());
    let last = log.clone(); drop(log);
    assert!(last.healthy());
    drop(last);
    released.recv_timeout(Duration::from_secs(2)).unwrap();
}

#[test]
fn poisoned_fixed_queue_refuses_logging_and_worker_can_shutdown() {
    let mut log = DiskLog::start(sink(), 1, Duration::from_secs(2), [0; 16]).unwrap();
    let queue = log.queue.0.clone();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        queue.panic_during_encoding();
    })).is_err());
    assert!(!log.healthy());
    assert!(matches!(log.append(record(b"refused", 1)), Err(error) if error.kind() == io::ErrorKind::BrokenPipe));
    log.shutdown(Duration::from_secs(2)).unwrap();
    assert!(log.thread.lock().unwrap().is_none());
}

#[test]
fn write_and_sync_failures_never_acknowledge_and_poison_future_appends() {
    for fail_write in [true, false] {
        let mut file = sink(); file.fail_write = fail_write; file.fail_sync = !fail_write;
        let bytes = file.bytes.clone(); let syncs = file.syncs.clone();
        let mut log = DiskLog::start(file, 1, Duration::from_secs(1), [1; 16]).unwrap();
        assert!(log.append(record(b"first", 1)).is_err());
        assert!(!log.healthy());
        let length = bytes.lock().unwrap().len();
        assert!(log.append(record(b"second", 2)).is_err());
        assert_eq!(bytes.lock().unwrap().len(), length);
        assert_eq!(syncs.load(Ordering::Relaxed), if fail_write { 0 } else { 1 });
    }
}

#[test]
fn blocked_disk_times_out_without_spawning_replacements() {
    let (file, started, release) = gated_sink(); let syncs = file.syncs.clone();
    let log = DiskLog::start(file, 1, Duration::from_millis(20), [1; 16]).unwrap();
    let mut other = log.clone();
    let first = append_on_thread(log, b"first", 1);
    started.recv_timeout(WAIT).unwrap();
    assert!(first.join().unwrap().is_err());
    assert!(!other.healthy());
    assert!(other.append(record(b"next", 2)).is_err());
    assert_eq!(syncs.load(Ordering::Relaxed), 1);
    release.send(()).unwrap();
}

#[test]
fn full_queue_parks_excess_work_before_allocation_and_serves_it_in_order() {
    let (file, started, release) = gated_sink(); let syncs = file.syncs.clone(); let bytes = file.bytes.clone();
    let log = DiskLog::start(file, 1, Duration::from_secs(5), [1; 16]).unwrap();
    let first = append_on_thread(log.clone(), b"first", 1);
    started.recv_timeout(WAIT).unwrap();
    let second = append_on_thread(log.clone(), b"second", 2);
    assert!(wait_until(Duration::from_secs(1), || log.queued_for_test() == 1));
    // The third append waits for a slot instead of failing; while it waits nothing
    // is reserved or encoded, and the logger stays healthy.
    let third = append_on_thread(log.clone(), b"third", 3);
    thread::sleep(Duration::from_millis(50));
    assert!(!third.is_finished());
    assert_eq!(log.queued_for_test(), 1);
    assert!(log.healthy());
    assert_eq!(syncs.load(Ordering::Relaxed), 1); // Only the blocked first sync.
    release.send(()).unwrap();
    first.join().unwrap().unwrap(); second.join().unwrap().unwrap(); third.join().unwrap().unwrap();
    assert_eq!(syncs.load(Ordering::Relaxed), 3);
    let mut expected = encode(record(b"first", 1));
    expected.extend(encode(record(b"second", 2))); expected.extend(encode(record(b"third", 3)));
    assert_eq!(*bytes.lock().unwrap(), expected);
    assert!(log.healthy());
}

#[test]
fn slot_wait_is_bounded_by_the_deadline_and_poisons_health() {
    let (file, started, release) = gated_sink(); let syncs = file.syncs.clone();
    let mut log = DiskLog::start(file, 1, Duration::from_millis(40), [1; 16]).unwrap();
    let first = append_on_thread(log.clone(), b"first", 1);
    started.recv_timeout(WAIT).unwrap();
    let second = append_on_thread(log.clone(), b"second", 2);
    assert!(wait_until(Duration::from_secs(1), || log.queued_for_test() == 1));
    // A worker that never frees a slot is indistinguishable from one that never
    // acknowledges: the waiting append fails at its deadline and health closes.
    let started_waiting = Instant::now();
    assert_eq!(log.append(record(b"third", 3)).err().unwrap().kind(), io::ErrorKind::BrokenPipe);
    assert!(started_waiting.elapsed() >= Duration::from_millis(40));
    assert!(!log.healthy());
    assert_eq!(log.queued_for_test(), 1);
    assert!(first.join().unwrap().is_err()); assert!(second.join().unwrap().is_err());
    assert_eq!(syncs.load(Ordering::Relaxed), 1);
    release.send(()).unwrap();
}

#[test]
fn shutdown_closes_all_clones_drains_admitted_jobs_and_joins() {
    let (file, inside, release) = gated_sink();
    let bytes = file.bytes.clone();
    let log = DiskLog::start(file, 2, Duration::from_secs(5), [0; 16]).unwrap();
    let first = append_on_thread(log.clone(), b"first", 1);
    inside.recv_timeout(WAIT).unwrap();
    let second = append_on_thread(log.clone(), b"second", 2);
    assert!(wait_until(WAIT, || log.queued_for_test() == 1));
    let closing_log = log.clone();
    let closing = thread::spawn(move || closing_log.shutdown(Duration::from_secs(2)));
    assert!(wait_until(WAIT, || !log.healthy()));
    assert!(!closing.is_finished());
    assert!(log.clone().append(record(b"late", 3)).is_err());
    release.send(()).unwrap();
    first.join().unwrap().unwrap(); second.join().unwrap().unwrap(); closing.join().unwrap().unwrap();
    assert!(log.thread.lock().unwrap().is_none());
    let mut expected = encode(record(b"first", 1)); expected.extend(encode(record(b"second", 2)));
    assert_eq!(*bytes.lock().unwrap(), expected);
    log.shutdown(Duration::from_secs(1)).unwrap();
}

#[test]
fn shutdown_deadline_does_not_wait_for_stuck_sync_or_replace_worker() {
    let (file, inside, release) = gated_sink();
    let log = DiskLog::start(file, 1, Duration::from_secs(5), [0; 16]).unwrap();
    let pending = append_on_thread(log.clone(), b"pending", 1);
    inside.recv_timeout(WAIT).unwrap();
    assert_eq!(log.shutdown(Duration::from_millis(20)).unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(!log.healthy());
    assert!(log.thread.lock().unwrap().is_some());
    assert!(log.clone().append(record(b"late", 2)).is_err());
    release.send(()).unwrap();
    // The already-running sync may still finish durably after timeout.
    pending.join().unwrap().unwrap();
    log.shutdown(Duration::from_secs(1)).unwrap();
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

#[test]
fn worker_panic_marks_health_failed_without_a_deadline_and_fails_the_waiting_caller() {
    struct PanicSync { entered: Option<blocking::Sender<()>>, release: blocking::Receiver<()> }
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
    let (entered, inside) = blocking::channel();
    let (release, wait) = blocking::channel();
    let log = DiskLog::start(PanicSync { entered: Some(entered), release: wait },
        1, Duration::from_secs(60), [0; 16]).unwrap();
    let caller = append_on_thread(log.clone(), b"pending", 1);
    inside.recv_timeout(WAIT).unwrap();
    assert!(log.healthy());
    release.send(()).unwrap();
    assert!(wait_until(WAIT, || log.thread.lock().unwrap().as_ref().unwrap().is_finished()));
    // Worker death is detected by its exit, not by any caller's deadline (60 s here).
    assert!(!log.healthy());
    assert!(caller.join().unwrap().is_err());
    assert!(log.clone().append(record(b"later", 2)).is_err());
    assert_eq!(log.shutdown(Duration::from_secs(1)).unwrap_err().kind(), io::ErrorKind::Other);
    assert!(log.thread.lock().unwrap().is_none());
}

#[test]
fn callers_that_give_up_do_not_release_queued_or_active_frame_credit() {
    // A caller whose deadline passes leaves its frame where it is: the active
    // worker still owns the first frame and the queued frame still occupies the
    // only slot. Giving up closes health, as any unacknowledged append does, so
    // nothing new is admitted. The in-flight sync still completes durably; the
    // queued frame is then refused rather than written into a log whose
    // acknowledgments can no longer be trusted, and nothing is retried.
    let (file, started, release) = gated_sink(); let syncs = file.syncs.clone(); let bytes = file.bytes.clone();
    let log = DiskLog::start(file, 1, Duration::from_millis(60), [1; 16]).unwrap();
    let first = append_on_thread(log.clone(), b"active", 1);
    started.recv_timeout(WAIT).unwrap();
    let second = append_on_thread(log.clone(), b"queued", 2);
    assert!(wait_until(WAIT, || log.queued_for_test() == 1));
    assert!(first.join().unwrap().is_err());
    assert!(second.join().unwrap().is_err());
    assert_eq!(log.queued_for_test(), 1);
    assert_eq!(syncs.load(Ordering::Relaxed), 1);
    assert!(!log.healthy());
    assert!(log.clone().append(record(b"excess", 3)).is_err());
    assert_eq!(log.queued_for_test(), 1);
    assert_eq!(*bytes.lock().unwrap(), encode(record(b"active", 1)));
    release.send(()).unwrap();
    log.shutdown(Duration::from_secs(2)).unwrap();
    assert_eq!(*bytes.lock().unwrap(), encode(record(b"active", 1)));
    assert_eq!(syncs.load(Ordering::Relaxed), 1);
    assert_eq!(log.queued_for_test(), 0);
}

#[test]
fn configured_record_limit_is_shared_by_clones_and_rejects_before_queueing() {
    let dir = TempDir::new(); let path = dir.0.join("limited.log");
    for invalid in [0, MAX_RECORD_BYTES + 1] {
        assert!(matches!(DiskLog::create_with_payload_limit(&path, 1, Duration::from_secs(5), invalid),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput));
        assert!(!path.exists());
    }
    let log = DiskLog::create_with_payload_limit(&path, 1, Duration::from_secs(5), 3).unwrap();
    let mut clone = log.clone();
    assert!(matches!(clone.append(record(b"four", 1)),
        Err(error) if error.kind() == io::ErrorKind::InvalidInput));
    assert_eq!(log.queued_for_test(), 0); assert!(log.healthy());
    drop(clone.append(record(b"abc", 2)).unwrap());
    drop(clone);
    log.shutdown(Duration::from_secs(5)).unwrap();
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
    let digest = sha256::digest(&frame[..body_len]);
    frame[body_len..].copy_from_slice(&digest); frame
}

#[test]
fn metadata_records_roundtrip_through_disk_and_scanner() {
    use super::Metadata;
    let dir = TempDir::new(); let path = dir.0.join("metadata.log");
    let mut log = DiskLog::create_with_payload_limit(&path, 2, Duration::from_secs(5), 8210).unwrap();
    let (start, head, done) = (start_payload(), head_payload(), done_payload());
    for (kind, payload) in [(RecordKind::RequestStart, &start), (RecordKind::ResponseHead, &head), (RecordKind::Completion, &done)] {
        let receipt = log.append(metadata_record(kind, 2, payload)).unwrap();
        assert!(receipt.matches_record(Header { payload: payload.len() as u32, tenant: 1, request: 2, chunk: 0, kind: kind.id() }, payload));
    }
    log.shutdown(Duration::from_secs(5)).unwrap();
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

#[test]
fn queued_batch_waits_for_shared_sync_and_closed_queue_drains() {
    struct Controlled {
        writes: Arc<std::sync::atomic::AtomicUsize>,
        entered: blocking::Sender<usize>, release: blocking::Receiver<()>,
    }
    impl Write for Controlled {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes.fetch_add(1, Ordering::Relaxed); Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> { Ok(()) }
    }
    impl DurableWrite for Controlled {
        fn sync(&mut self) -> io::Result<()> {
            self.entered.send(self.writes.load(Ordering::Relaxed)).unwrap();
            self.release.recv_timeout(WAIT).unwrap(); Ok(())
        }
    }
    let (entered, syncing) = blocking::channel();
    let (release, wait) = blocking::channel();
    let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let log = DiskLog::start(Controlled { writes, entered, release: wait }, 20, WAIT, [1; 16]).unwrap();
    let first = log.queue.0.enqueue(record(b"first", 0), Instant::now() + WAIT).unwrap();
    assert_eq!(syncing.recv_timeout(WAIT).unwrap(), 1);
    let mut replies = Vec::new();
    for id in 1..=20 { replies.push((id, log.queue.0.enqueue(record(b"batch", id), Instant::now() + WAIT).unwrap())); }
    log.queue.0.close();
    assert!(first.try_recv().is_err());
    release.send(()).unwrap();
    assert!(first.recv_timeout(WAIT).unwrap().is_some());
    assert_eq!(syncing.recv_timeout(WAIT).unwrap(), 17);
    // All sixteen writes have finished, but none has a durable receipt yet.
    assert!(replies.iter().all(|(_, rx)| matches!(rx.try_recv(), Err(blocking::TryRecvError::Empty))));
    // A canceled receiver cannot strand the batch or shift receipt identities.
    drop(replies.remove(0));
    release.send(()).unwrap();
    for (id, rx) in replies.drain(..15) {
        let receipt = rx.recv_timeout(WAIT).unwrap().unwrap();
        assert!(receipt.matches_record(record_header(&record(b"batch", id)), b"batch"));
    }
    assert_eq!(syncing.recv_timeout(WAIT).unwrap(), 21);
    assert!(replies.iter().all(|(_, rx)| matches!(rx.try_recv(), Err(blocking::TryRecvError::Empty))));
    release.send(()).unwrap();
    for (id, rx) in replies {
        let receipt = rx.recv_timeout(WAIT).unwrap().unwrap();
        assert!(receipt.matches_record(record_header(&record(b"batch", id)), b"batch"));
    }
    log.shutdown(WAIT).unwrap();
}

#[test]
fn shared_sync_spans_rotations_and_recovers_every_exact_frame() {
    use gateway_core::{disk_worker::Storage as StorageTrait, log_rotation::RotatingStorage};
    struct GatedRotation {
        inner: RotatingStorage<rotation::RotatingFile>,
        gate: Option<(blocking::Sender<()>, blocking::Receiver<()>)>,
        syncs: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl StorageTrait for GatedRotation {
        fn write_all(&mut self, bytes: &Vec<u8>) -> bool { self.inner.write_all(bytes) }
        fn sync(&mut self) -> bool {
            self.syncs.fetch_add(1, Ordering::Relaxed);
            if let Some((entered, release)) = self.gate.take() {
                entered.send(()).unwrap(); release.recv_timeout(WAIT).unwrap();
            }
            self.inner.sync()
        }
    }
    let dir = TempDir::new(); let path = dir.0.join("batched-rotation.log");
    let rotation = Rotation { max_bytes: 56 + 2 * 68, max_age: Duration::from_secs(60) };
    let session = [3; 16];
    let inner = RotatingStorage::new(rotation::RotatingFile::create(&path, session, rotation).unwrap(), u128::from_le_bytes(session), rotation.max_bytes);
    let (entered, syncing) = blocking::channel(); let (release, wait) = blocking::channel();
    let syncs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let log = DiskLog::start_storage(GatedRotation { inner, gate: Some((entered, wait)), syncs: syncs.clone() }, 16, WAIT, session, 3).unwrap();
    let first = log.queue.0.enqueue(record(b"abc", 0), Instant::now() + WAIT).unwrap();
    syncing.recv_timeout(WAIT).unwrap();
    let replies: Vec<_> = (1..=16).map(|id| log.queue.0.enqueue(record(b"abc", id), Instant::now() + WAIT).unwrap()).collect();
    log.queue.0.close(); release.send(()).unwrap();
    assert!(first.recv_timeout(WAIT).unwrap().is_some());
    for reply in replies { assert!(reply.recv_timeout(WAIT).unwrap().is_some()); }
    log.shutdown(WAIT).unwrap();
    // Segment sealing adds its own syncs; these are the two group-commit syncs.
    assert_eq!(syncs.load(Ordering::Relaxed), 2);
    let mut scanner = SessionReader::open(&path).unwrap();
    for chunk in 0..=16 {
        let recovered = scanner.next_record().unwrap().unwrap();
        assert_eq!(recovered.chunk, chunk); assert_eq!(recovered.bytes, b"abc");
    }
    assert!(scanner.next_record().unwrap().is_none());
    assert_eq!(scanner.segment(), 8);
}

#[test]
fn buffered_runtime_skips_sync_and_still_poison_on_write_failure() {
    for fail_write in [false, true] {
        let mut file = sink(); file.fail_write = fail_write; file.fail_sync = true;
        let bytes = file.bytes.clone(); let syncs = file.syncs.clone();
        let mut log = DiskLog::start_storage_with_durability(Storage(file), 16, WAIT, [1; 16], 4096, Durability::Buffered).unwrap();
        assert_eq!(log.durability(), Durability::Buffered);
        for id in 1..=20 {
            let result = log.append(record(b"written", id));
            if fail_write { assert!(result.is_err()); assert!(!log.healthy()); }
            else { assert!(!result.unwrap().is_durable()); }
        }
        assert_eq!(syncs.load(Ordering::Relaxed), 0);
        if !fail_write { assert!(!bytes.lock().unwrap().is_empty()); }
        log.shutdown(WAIT).unwrap();
    }
}

#[test]
fn buffered_rotation_recovers_all_written_records_after_clean_shutdown() {
    let dir = TempDir::new(); let path = dir.0.join("buffered-rotation.log");
    let rotation = Rotation { max_bytes: 56 + 2 * 68, max_age: Duration::from_secs(60) };
    let mut log = DiskLog::create_rotating_with_durability(&path, 16, WAIT, 3, rotation, Durability::Buffered).unwrap();
    for chunk in 0..17 { assert!(!log.append(record(b"abc", chunk)).unwrap().is_durable()); }
    log.shutdown(WAIT).unwrap();
    let mut scanner = SessionReader::open(&path).unwrap();
    for chunk in 0..17 {
        let recovered = scanner.next_record().unwrap().unwrap();
        assert_eq!(recovered.chunk, chunk); assert_eq!(recovered.bytes, b"abc");
    }
    assert!(scanner.next_record().unwrap().is_none()); assert_eq!(scanner.segment(), 8);
}

#[test]
fn exchange_expiry_bounds_queue_and_ack_waits_without_poisoning_log() {
    let (mut log, entered, release, _) = DiskLog::stalled_for_test(1, Duration::from_secs(5));
    // First append stalls in sync; the second fills the waiting queue; the
    // third cannot enqueue. Every call obeys the shorter exchange budget.
    for chunk in 1..=3 {
        let started = Instant::now();
        let result = log.append_until(record(b"abc", chunk), Some(started + Duration::from_millis(50)));
        assert!(matches!(result, Err(ref e) if e.kind() == io::ErrorKind::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(1));
        if chunk == 1 { entered.recv_timeout(Duration::from_secs(1)).unwrap(); }
        assert!(log.healthy(), "exchange expiry is not disk failure");
    }
    assert_eq!(log.queued_for_test(), 1);
    release.send(()).unwrap();
    log.append(record(b"after", 4)).unwrap();
    log.shutdown(Duration::from_secs(2)).unwrap();
}
