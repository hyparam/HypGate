//! Bounded disk logging. Filesystem effects and checksum security are trusted,
//! not verified. A single worker owns the file; requests never choose its path.
use crate::transfer::{AuditLog, Direction, LogRecord, RecordKind};
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

struct Completion(oneshot::Sender<Option<DurableFrame>>);
impl gateway_core::disk_worker::Completion for Completion {
    fn complete(self, receipt: Option<DurableFrame>) {
        // Ownership goes to the request's reply channel, or the unsent value is
        // destroyed here. No worker-owned payload survives this synchronous call.
        let _ = self.0.send(receipt);
    }
}
#[cfg(test)]
impl Completion {
    fn send(self, receipt: Option<DurableFrame>) -> Result<(), Option<DurableFrame>> { self.0.send(receipt) }
}
type Job = (RecordFrame, Completion);

/// Clones share one bounded queue and one worker. Never create replacement workers
/// to escape a stuck filesystem call. A timeout closes logging health permanently.
#[derive(Clone)]
pub struct DiskLog {
    queue: Arc<SharedQueue>,
    thread: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
    healthy: Arc<AtomicBool>,
    deadline: Duration,
    session: [u8; 16],
    payload_limit: usize,
}

// Dropping the last clone closes admission so the worker exits once drained.
struct SharedQueue(Arc<Queue>);
impl Drop for SharedQueue { fn drop(&mut self) { self.0.close(); } }

// Health must not depend on an append caller surviving to observe failure.
struct UnhealthyOnExit(Arc<AtomicBool>, Arc<Queue>);
impl Drop for UnhealthyOnExit {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); self.1.abort(); }
}

trait DurableWrite: Write + Send + 'static { fn sync(&mut self) -> io::Result<()>; }
impl DurableWrite for File { fn sync(&mut self) -> io::Result<()> { self.sync_all() } }

// Trusted syscall bindings for the verified worker. Successful returns mean
// exact append and durable sync under the documented storage crash contract.
struct Storage<W>(W);
impl<W: DurableWrite> gateway_core::disk_worker::Storage for Storage<W> {
    fn write_all(&mut self, bytes: &Vec<u8>) -> bool { self.0.write_all(bytes).is_ok() }
    fn sync(&mut self) -> bool { self.0.sync().is_ok() }
}

impl DiskLog {
    /// Startup operation: creates a new file, syncs its header and parent directory,
    /// then starts one worker. Existing paths are never overwritten or appended to.
    pub fn create(path: &Path, queue_capacity: usize, deadline: Duration) -> io::Result<Self> {
        Self::create_with_payload_limit(path, queue_capacity, deadline, MAX_RECORD_BYTES)
    }

    /// Enforce the gateway's chunk budget before encoding any audit payload.
    // Effect site: the audit log file, created new at the operator's path.
    #[allow(clippy::disallowed_methods)]
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

    fn start_limited<W: DurableWrite>(file: W, capacity: usize, deadline: Duration, session: [u8; 16], payload_limit: usize) -> io::Result<Self> {
        if payload_limit == 0 || payload_limit > MAX_RECORD_BYTES || capacity == 0 || capacity > 1024 { return Err(io::ErrorKind::InvalidInput.into()); }
        let queue = Arc::new(Queue::with_payload_limit(capacity, payload_limit));
        let receiver = queue.clone();
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_health = healthy.clone();
        let thread = std::thread::Builder::new().name("soundgate-audit".into()).stack_size(WORKER_STACK_BYTES).spawn(move || {
            let _health_on_exit = UnhealthyOnExit(worker_health.clone(), receiver.clone());
            let mut journal = Journal::new(u128::from_le_bytes(session));
            let mut storage = Storage(file);
            let mut owner = gateway_core::disk_worker::DiskWorker::new(payload_limit, u128::from_le_bytes(session));
            while let Some(job) = receiver.recv(&mut owner) {
                let finished = owner.run(job, &mut journal, &mut storage, worker_health.load(Ordering::Acquire));
                if finished.failed() { worker_health.store(false, Ordering::Release); }
                // A canceled caller may leave a durable but unsent record. It must
                // never cause the worker to retry or the gateway to replay traffic.
                let released = finished.deliver();
                assert!(owner.release(released), "completed disk job owns active credit");
            }
        })?;
        Ok(Self { queue: Arc::new(SharedQueue(queue)), thread: Arc::new(Mutex::new(Some(thread))),
            healthy, deadline, session, payload_limit })
    }

    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire) && self.queue.0.is_open()
    }

    /// Close admission across all clones, drain queued jobs, and join the worker.
    /// A stuck syscall cannot be canceled; timeout never spawns a replacement.
    pub async fn shutdown(&self, deadline: Duration) -> io::Result<()> {
        if deadline.is_zero() || deadline > Duration::from_secs(300) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.queue.0.close();
        let joined = tokio::time::timeout(deadline, async {
            loop {
                {
                    let mut thread = self.thread.lock().unwrap();
                    if thread.as_ref().is_none_or(|thread| thread.is_finished()) {
                        if let Some(thread) = thread.take() {
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
    pub(crate) fn queued_for_test(&self) -> usize { self.queue.0.len() }
    pub fn session(&self) -> [u8; 16] { self.session }
}

impl AuditLog for DiskLog {
    fn session_id(&self) -> u128 { u128::from_le_bytes(self.session) }
    async fn append(&mut self, record: LogRecord<'_>) -> io::Result<DurableFrame> {
        if !self.healthy() { return Err(io::ErrorKind::BrokenPipe.into()); }
        if record.bytes.len() > self.payload_limit || record.request == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Reserve queue space before allocating/copying a payload. Queued frames
        // plus the worker's one active frame bound retained log payloads.
        // The queue lock serializes construction/insertion with shutdown.
        // Unlike an mpsc sender clone, this Arc cannot keep admission open
        // after Queue::close.
        let queue = self.queue.0.clone();
        // One deadline covers waiting for a free slot and waiting for the sync
        // acknowledgment: a worker that stops freeing slots fails the append and
        // poisons health exactly as a worker that stops acknowledging does.
        let outcome = tokio::time::timeout(self.deadline, async {
            let completion = queue.enqueue(record).await?;
            Ok::<_, io::Error>(completion.await.ok().flatten())
        }).await;
        match outcome {
            Ok(Ok(Some(receipt))) => Ok(receipt),
            // Only a verified-reservation refusal that the permit should have
            // prevented; the logger stays usable and nothing was lost.
            Ok(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => Err(error),
            _ => {
                self.healthy.store(false, Ordering::Release);
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
    }
}

fn record_header(record: &LogRecord<'_>) -> Header {
    Header { payload: record.bytes.len() as u32, tenant: record.tenant, request: record.request,
        chunk: record.chunk, kind: record.kind.id() }
}
fn seal_record(body: RecordBody) -> RecordFrame {
    let checksum: [u8; 32] = Sha256::digest(body.bytes()).into();
    body.seal(&checksum)
}
#[cfg(test)]
fn encode_record(record: LogRecord<'_>) -> RecordFrame {
    seal_record(RecordBody::new(record_header(&record), record.bytes).expect("valid test record"))
}

#[cfg(test)]
fn encode(record: LogRecord<'_>) -> Vec<u8> { encode_record(record).bytes().clone() }

pub use gateway_core::recovery::ScanError;
#[derive(Debug, PartialEq, Eq)]
pub struct StoredRecord {
    pub tenant: u64,
    pub request: u64,
    pub chunk: u64,
    pub kind: RecordKind,
    pub bytes: Vec<u8>,
}
/// Decoded metadata payload of a kind 2, 3, or 4 record.
#[derive(Debug, PartialEq, Eq)]
pub enum Metadata {
    RequestStart(gateway_core::metadata::RequestStart),
    ResponseHead(gateway_core::metadata::ResponseHead),
    Completion(gateway_core::metadata::Completion),
}
impl StoredRecord {
    /// Body direction of a body record; metadata records have none.
    pub fn direction(&self) -> Option<Direction> { self.kind.direction() }
    /// Decode a metadata payload with the verified codecs. `None` for body
    /// records and for a metadata record whose payload does not decode.
    pub fn metadata(&self) -> Option<Metadata> {
        use gateway_core::metadata::{decode_completion, decode_request_start, decode_response_head};
        match self.kind {
            RecordKind::Upload | RecordKind::Download => None,
            RecordKind::RequestStart => decode_request_start(&self.bytes).map(Metadata::RequestStart),
            RecordKind::ResponseHead => decode_response_head(&self.bytes).map(Metadata::ResponseHead),
            RecordKind::Completion => decode_completion(&self.bytes).map(Metadata::Completion),
        }
    }
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
    /// Continue a file whose header `new` already validated, from a byte offset
    /// an earlier reader reported as its valid end. The reader must already be
    /// positioned at that offset.
    pub fn resume(reader: R, session: [u8; 16], offset: u64) -> Result<Self, ScanError> {
        if offset < 56 { return Err(ScanError::Corrupt); }
        Ok(Self { scanner: gateway_core::recovery::Scanner::resume(ReadSource { reader }, session, offset) })
    }
    pub fn session(&self) -> [u8; 16] { self.scanner.session() }
    pub fn valid_end(&self) -> u64 { self.scanner.offset() }
    pub fn next_record(&mut self) -> Result<Option<StoredRecord>, ScanError> {
        let Some(record) = self.scanner.next_record()? else { return Ok(None); };
        let fields = record.header;
        // The verified decoder admits only kinds 0..=4, so this conversion is total.
        let kind = RecordKind::from_id(fields.kind).ok_or(ScanError::Corrupt)?;
        Ok(Some(StoredRecord {
            tenant: fields.tenant, request: fields.request, chunk: fields.chunk, kind, bytes: record.bytes,
        }))
    }
}

#[cfg(test)]
mod tests;
