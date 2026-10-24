//! Bounded disk logging. Filesystem effects and checksum security are trusted,
//! not verified. A single worker owns the file; requests never choose its path.
use crate::transfer::{AuditLog, Direction, LogRecord};
use gateway_core::{audit_journal::AuditJournal as Journal, journal::DurableFrame};
use gateway_core::framing::{self, Header, RecordBody, RecordFrame};
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{self, Read, Write}, path::Path,
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::sync::oneshot;
mod queue;
use queue::Queue;

#[cfg(test)]
const FILE_MAGIC: &[u8; 8] = b"SGLOG001";
#[cfg(test)]
const FILE_HEADER: usize = 56; // magic + random session ID + checksum
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;
// Explicit reservation, independent of RUST_MIN_STACK. OS rounding, committed
// pages, and thread-local/kernel storage remain separate resource categories.
const WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;

type Completion = oneshot::Sender<Option<DurableFrame>>;
type Job = (RecordFrame, Completion);

/// Clones share one bounded queue and one worker. Never create replacement workers
/// to escape a stuck filesystem call. A timeout closes logging health permanently.
#[derive(Clone)]
pub struct DiskLog {
    worker: Arc<Mutex<Worker>>,
    healthy: Arc<AtomicBool>,
    deadline: Duration,
    session: [u8; 16],
    payload_limit: usize,
}

struct Worker { queue: Arc<Queue>, thread: Option<std::thread::JoinHandle<()>> }
impl Drop for Worker { fn drop(&mut self) { self.queue.close(); } }

// Health must not depend on an append caller surviving to observe failure.
struct UnhealthyOnExit(Arc<AtomicBool>, Arc<Queue>);
impl Drop for UnhealthyOnExit {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); self.1.abort(); }
}

trait DurableWrite: Write + Send + 'static { fn sync(&mut self) -> io::Result<()>; }
impl DurableWrite for File { fn sync(&mut self) -> io::Result<()> { self.sync_all() } }

impl DiskLog {
    /// Startup operation: creates a new file, syncs its header and parent directory,
    /// then starts one worker. Existing paths are never overwritten or appended to.
    pub fn create(path: &Path, queue_capacity: usize, deadline: Duration) -> io::Result<Self> {
        Self::create_with_payload_limit(path, queue_capacity, deadline, MAX_RECORD_BYTES)
    }

    /// Enforce the gateway's chunk budget before encoding any audit payload.
    pub fn create_with_payload_limit(path: &Path, queue_capacity: usize, deadline: Duration, payload_limit: usize) -> io::Result<Self> {
        if payload_limit == 0 || payload_limit > MAX_RECORD_BYTES
            || queue_capacity == 0 || queue_capacity > 1024 || deadline.is_zero()
            || deadline > Duration::from_secs(300) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut session = [0u8; 16];
        getrandom::fill(&mut session).map_err(|_| io::ErrorKind::Other)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        let mut header = framing::encode_session(&session);
        header.extend_from_slice(&Sha256::digest(&header));
        file.write_all(&header)?;
        file.sync_all()?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        Self::start_limited(file, queue_capacity, deadline, session, payload_limit)
    }

    #[cfg(test)]
    fn start<W: DurableWrite>(file: W, capacity: usize, deadline: Duration, session: [u8; 16]) -> io::Result<Self> {
        Self::start_limited(file, capacity, deadline, session, MAX_RECORD_BYTES)
    }

    fn start_limited<W: DurableWrite>(mut file: W, capacity: usize, deadline: Duration, session: [u8; 16], payload_limit: usize) -> io::Result<Self> {
        if payload_limit == 0 || payload_limit > MAX_RECORD_BYTES || capacity == 0 || capacity > 1024 { return Err(io::ErrorKind::InvalidInput.into()); }
        let queue = Arc::new(Queue::with_payload_limit(capacity, payload_limit));
        let receiver = queue.clone();
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_health = healthy.clone();
        let thread = std::thread::Builder::new().name("soundgate-audit".into()).stack_size(WORKER_STACK_BYTES).spawn(move || {
            let _health_on_exit = UnhealthyOnExit(worker_health.clone(), receiver.clone());
            let mut journal = Journal::new();
            while let Some((frame, done)) = receiver.recv() {
                let receipt = if worker_health.load(Ordering::Acquire) {
                    match journal.begin(frame.bytes().len() as u64) {
                        Some(ticket) if file.write_all(frame.bytes()).is_ok() && file.sync().is_ok() =>
                            journal.commit_frame(&ticket, frame),
                        _ => None,
                    }
                } else { None };
                if receipt.is_none() { journal.fail(); worker_health.store(false, Ordering::Release); }
                // A canceled caller may leave a durable but unsent record. It must
                // never cause the worker to retry or the gateway to replay traffic.
                let _ = done.send(receipt);
            }
        })?;
        Ok(Self { worker: Arc::new(Mutex::new(Worker { queue, thread: Some(thread) })),
            healthy, deadline, session, payload_limit })
    }

    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
            && self.worker.lock().map(|worker| worker.queue.is_open()).unwrap_or(false)
    }

    /// Close admission across all clones, drain queued jobs, and join the worker.
    /// A stuck syscall cannot be canceled; timeout never spawns a replacement.
    pub async fn shutdown(&self, deadline: Duration) -> io::Result<()> {
        if deadline.is_zero() || deadline > Duration::from_secs(300) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.worker.lock().unwrap().queue.close();
        let joined = tokio::time::timeout(deadline, async {
            loop {
                {
                    let mut worker = self.worker.lock().unwrap();
                    if worker.thread.as_ref().is_none_or(|thread| thread.is_finished()) {
                        if let Some(thread) = worker.thread.take() {
                            if thread.join().is_err() {
                                self.healthy.store(false, Ordering::Release);
                                return Err(io::ErrorKind::Other.into());
                            }
                        }
                        return Ok(());
                    }
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }).await;
        if joined.is_err() {
            self.healthy.store(false, Ordering::Release);
            return Err(io::ErrorKind::TimedOut.into());
        }
        joined.unwrap()
    }
    #[cfg(test)]
    pub(crate) fn inject_failure(&self) { self.healthy.store(false, Ordering::Release); }
    #[cfg(test)]
    pub(crate) fn stalled_for_test(capacity: usize, deadline: Duration) ->
        (Self, oneshot::Receiver<()>, std::sync::mpsc::Sender<()>, Arc<std::sync::atomic::AtomicUsize>)
    {
        struct Stalled {
            entered: Option<oneshot::Sender<()>>,
            release: std::sync::mpsc::Receiver<()>,
            writes: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Write for Stalled {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.writes.fetch_add(1, Ordering::Relaxed); Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        impl DurableWrite for Stalled {
            fn sync(&mut self) -> io::Result<()> {
                if let Some(entered) = self.entered.take() {
                    let _ = entered.send(());
                    let _ = self.release.recv();
                }
                Ok(())
            }
        }
        let (entered, started) = oneshot::channel();
        let (release, waiting) = std::sync::mpsc::channel();
        let writes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let log = Self::start(Stalled { entered: Some(entered), release: waiting, writes: writes.clone() },
            capacity, deadline, [0; 16]).unwrap();
        (log, started, release, writes)
    }
    #[cfg(test)]
    pub(crate) fn queued_for_test(&self) -> usize {
        let worker = self.worker.lock().unwrap();
        worker.queue.len()
    }
    pub fn session(&self) -> [u8; 16] { self.session }
}

impl AuditLog for DiskLog {
    async fn append(&mut self, record: LogRecord<'_>) -> io::Result<DurableFrame> {
        if !self.healthy() { return Err(io::ErrorKind::BrokenPipe.into()); }
        if record.bytes.len() > self.payload_limit || record.request == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Reserve queue space before allocating/copying a payload. Queued frames
        // plus the worker's one active frame bound retained log payloads.
        let completion = {
            // The queue lock serializes construction/insertion with shutdown.
            // Unlike an mpsc sender clone, this Arc cannot keep admission open
            // after Queue::close. Do not hold the worker mutex while encoding.
            let queue = self.worker.lock().map_err(|_| io::ErrorKind::BrokenPipe)?.queue.clone();
            let mut completion = None;
            queue.push_with(|| {
                let frame = encode_record(record);
                let (done, receive) = oneshot::channel();
                completion = Some(receive);
                (frame, done)
            }).map_err(|error| {
                if error.kind() == io::ErrorKind::BrokenPipe { self.healthy.store(false, Ordering::Release); }
                error
            })?;
            completion.expect("successful queue insertion constructed a job")
        };
        match tokio::time::timeout(self.deadline, completion).await {
            Ok(Ok(Some(receipt))) => Ok(receipt),
            _ => {
                self.healthy.store(false, Ordering::Release);
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
    }
}

fn encode_record(record: LogRecord<'_>) -> RecordFrame {
    // append checked the record bounds before queue reservation/allocation.
    let frame = RecordBody::new(Header { payload: record.bytes.len() as u32,
        tenant: record.tenant, request: record.request, chunk: record.chunk,
        direction: match record.direction { Direction::Upload => 0, Direction::Download => 1 },
    }, record.bytes).expect("validated log record");
    let checksum: [u8; 32] = Sha256::digest(frame.bytes()).into();
    frame.seal(&checksum)
}

#[cfg(test)]
fn encode(record: LogRecord<'_>) -> Vec<u8> { encode_record(record).bytes().clone() }

pub use gateway_core::recovery::ScanError;
#[derive(Debug, PartialEq, Eq)]
pub struct StoredRecord {
    pub tenant: u64,
    pub request: u64,
    pub chunk: u64,
    pub direction: Direction,
    pub bytes: Vec<u8>,
}

// Trusted implementation of the verified scanner's sequential byte-stream and
// checksum contracts. Verus does not verify std::io::Read or SHA-256.
struct ReadSource<R: Read> { reader: R }
impl<R: Read> gateway_core::recovery::Source for ReadSource<R> {
    fn read_exact(&mut self, length: usize) -> Result<Vec<u8>, gateway_core::recovery::ReadError> {
        use gateway_core::recovery::ReadError;
        let mut bytes = vec![0; length]; let mut filled = 0;
        while filled < length {
            match self.reader.read(&mut bytes[filled..]) {
                Ok(0) => return Err(if filled == 0 { ReadError::Eof } else { ReadError::Incomplete }),
                Ok(count) => filled += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(ReadError::Io),
            }
        }
        Ok(bytes)
    }
    fn checksum_valid(&self, header: &[u8], payload: &[u8], checksum: &[u8]) -> bool {
        let mut digest = Sha256::new(); digest.update(header); digest.update(payload);
        digest.finalize()[..] == *checksum
    }
}

/// Incremental, read-only recovery scanner. It never truncates files or replays
/// traffic. The core owns parsing, stop state, and valid-prefix advancement.
pub struct LogReader<R: Read> { scanner: gateway_core::recovery::Scanner<ReadSource<R>> }
impl<R: Read> LogReader<R> {
    pub fn new(reader: R) -> Result<Self, ScanError> {
        Ok(Self { scanner: gateway_core::recovery::Scanner::new(ReadSource { reader })? })
    }
    pub fn session(&self) -> [u8; 16] { self.scanner.session() }
    pub fn valid_end(&self) -> u64 { self.scanner.offset() }
    pub fn next_record(&mut self) -> Result<Option<StoredRecord>, ScanError> {
        let Some(record) = self.scanner.next_record()? else { return Ok(None); };
        let fields = record.header;
        Ok(Some(StoredRecord {
            tenant: fields.tenant, request: fields.request, chunk: fields.chunk,
            direction: if fields.direction == 0 { Direction::Upload } else { Direction::Download }, bytes: record.bytes,
        }))
    }
}

#[cfg(test)]
mod tests;
