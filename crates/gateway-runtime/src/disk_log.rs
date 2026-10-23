//! Bounded disk logging. Filesystem effects and checksum security are trusted,
//! not verified. A single worker owns the file; requests never choose its path.
use crate::transfer::{AuditLog, Direction, LogRecord};
use gateway_core::journal::Journal;
use gateway_core::framing::{self, Header};
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{self, Read, Write}, path::Path,
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::sync::{mpsc, oneshot};

const FILE_MAGIC: &[u8; 8] = b"SGLOG001";
const FILE_HEADER: usize = 56; // magic + random session ID + checksum
const RECORD_HEADER: usize = 33; // magic + length + tenant + request + chunk + direction
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

struct Job { frame: Vec<u8>, done: oneshot::Sender<bool> }

/// Clones share one bounded queue and one worker. Never create replacement workers
/// to escape a stuck filesystem call. A timeout closes logging health permanently.
#[derive(Clone)]
pub struct DiskLog {
    worker: Arc<Mutex<Worker>>,
    healthy: Arc<AtomicBool>,
    deadline: Duration,
    session: [u8; 16],
}

struct Worker { sender: Option<mpsc::Sender<Job>>, thread: Option<std::thread::JoinHandle<()>> }

// Health must not depend on an append caller surviving to observe failure.
struct UnhealthyOnExit(Arc<AtomicBool>);
impl Drop for UnhealthyOnExit {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

trait DurableWrite: Write + Send + 'static { fn sync(&mut self) -> io::Result<()>; }
impl DurableWrite for File { fn sync(&mut self) -> io::Result<()> { self.sync_all() } }

impl DiskLog {
    /// Startup operation: creates a new file, syncs its header and parent directory,
    /// then starts one worker. Existing paths are never overwritten or appended to.
    pub fn create(path: &Path, queue_capacity: usize, deadline: Duration) -> io::Result<Self> {
        if queue_capacity == 0 || queue_capacity > 1024 || deadline.is_zero()
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
        let mut header = Vec::with_capacity(FILE_HEADER);
        header.extend_from_slice(FILE_MAGIC);
        header.extend_from_slice(&session);
        header.extend_from_slice(&Sha256::digest(&header));
        file.write_all(&header)?;
        file.sync_all()?;
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        Self::start(file, queue_capacity, deadline, session)
    }

    fn start<W: DurableWrite>(mut file: W, capacity: usize, deadline: Duration, session: [u8; 16]) -> io::Result<Self> {
        let (sender, mut receiver) = mpsc::channel::<Job>(capacity);
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_health = healthy.clone();
        let thread = std::thread::Builder::new().name("soundgate-audit".into()).spawn(move || {
            let _health_on_exit = UnhealthyOnExit(worker_health.clone());
            let mut journal = Journal::new();
            while let Some(job) = receiver.blocking_recv() {
                let ok = worker_health.load(Ordering::Acquire) && match journal.begin(job.frame.len() as u64) {
                    Some(ticket) => file.write_all(&job.frame).is_ok()
                        && file.sync().is_ok()
                        && journal.record_durable(&ticket, &job.frame),
                    None => false,
                };
                if !ok { journal.fail(); worker_health.store(false, Ordering::Release); }
                // A canceled caller may leave a durable but unsent record. It must
                // never cause the worker to retry or the gateway to replay traffic.
                let _ = job.done.send(ok);
            }
        })?;
        Ok(Self { worker: Arc::new(Mutex::new(Worker { sender: Some(sender), thread: Some(thread) })),
            healthy, deadline, session })
    }

    pub fn healthy(&self) -> bool {
        self.healthy.load(Ordering::Acquire) && self.worker.lock().unwrap().sender.is_some()
    }

    /// Close admission across all clones, drain queued jobs, and join the worker.
    /// A stuck syscall cannot be canceled; timeout never spawns a replacement.
    pub async fn shutdown(&self, deadline: Duration) -> io::Result<()> {
        if deadline.is_zero() || deadline > Duration::from_secs(300) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.worker.lock().unwrap().sender.take();
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
        let sender = worker.sender.as_ref().unwrap();
        sender.max_capacity() - sender.capacity()
    }
    pub fn session(&self) -> [u8; 16] { self.session }
}

impl AuditLog for DiskLog {
    async fn append(&mut self, record: LogRecord<'_>) -> io::Result<()> {
        if !self.healthy() { return Err(io::ErrorKind::BrokenPipe.into()); }
        if record.bytes.len() > MAX_RECORD_BYTES || record.request == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        // Reserve queue space before allocating/copying a payload. Queued frames
        // plus the worker's one active frame bound retained log payloads.
        let completion = {
            // Serialize admission with shutdown. No sender or permit can escape
            // this section and keep the receiver open after shutdown closes it.
            let worker = self.worker.lock().unwrap();
            let sender = worker.sender.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
            let permit = sender.try_reserve().map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
                mpsc::error::TrySendError::Closed(_) => {
                    self.healthy.store(false, Ordering::Release);
                    io::ErrorKind::BrokenPipe
                },
            })?;
            let frame = encode(record);
            let (done, completion) = oneshot::channel();
            permit.send(Job { frame, done });
            completion
        };
        match tokio::time::timeout(self.deadline, completion).await {
            Ok(Ok(true)) => Ok(()),
            _ => {
                self.healthy.store(false, Ordering::Release);
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
    }
}

fn encode(record: LogRecord<'_>) -> Vec<u8> {
    // append checked the record bounds before queue reservation/allocation.
    let mut frame = framing::encode_payload(Header { payload: record.bytes.len() as u32,
        tenant: record.tenant, request: record.request, chunk: record.chunk,
        direction: match record.direction { Direction::Upload => 0, Direction::Download => 1 },
    }, record.bytes).expect("validated log record");
    frame.extend_from_slice(&Sha256::digest(&frame));
    frame
}

#[derive(Debug, PartialEq, Eq)]
pub enum ScanError { Io, Incomplete, Corrupt }
#[derive(Debug, PartialEq, Eq)]
pub struct StoredRecord {
    pub tenant: u64,
    pub request: u64,
    pub chunk: u64,
    pub direction: Direction,
    pub bytes: Vec<u8>,
}

/// Incremental, read-only recovery scanner. It never truncates files or replays
/// traffic. After any malformed record it stops permanently at the valid prefix.
pub struct LogReader<R> { reader: R, session: [u8; 16], cursor: framing::Cursor }
impl<R: Read> LogReader<R> {
    pub fn new(mut reader: R) -> Result<Self, ScanError> {
        let mut header = [0; FILE_HEADER];
        exact(&mut reader, &mut header)?;
        if &header[..8] != FILE_MAGIC || Sha256::digest(&header[..24])[..] != header[24..] {
            return Err(ScanError::Corrupt);
        }
        let session = header[8..24].try_into().unwrap();
        Ok(Self { reader, session, cursor: framing::Cursor::new(FILE_HEADER as u64) })
    }
    pub fn session(&self) -> [u8; 16] { self.session }
    pub fn valid_end(&self) -> u64 { self.cursor.offset() }

    pub fn next_record(&mut self) -> Result<Option<StoredRecord>, ScanError> {
        let Some(ticket) = self.cursor.begin() else { return Ok(None); };
        let mut header = [0u8; RECORD_HEADER];
        loop {
            match self.reader.read(&mut header[..1]) {
                Ok(0) => return Ok(None),
                Ok(_) => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(ScanError::Io),
            }
        }
        exact(&mut self.reader, &mut header[1..])?;
        let fields = framing::decode(&header).ok_or(ScanError::Corrupt)?;
        let size = fields.payload as usize;
        let mut bytes = vec![0; size];
        exact(&mut self.reader, &mut bytes)?;
        let mut checksum = [0u8; 32];
        exact(&mut self.reader, &mut checksum)?;
        let mut digest = Sha256::new(); digest.update(header); digest.update(&bytes);
        let record = self.cursor.accept_record(ticket, &header, bytes,
            digest.finalize()[..] == checksum).ok_or(ScanError::Corrupt)?;
        let fields = record.header;
        Ok(Some(StoredRecord {
            tenant: fields.tenant, request: fields.request, chunk: fields.chunk,
            direction: if fields.direction == 0 { Direction::Upload } else { Direction::Download }, bytes: record.bytes,
        }))
    }
}

fn exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<(), ScanError> {
    reader.read_exact(bytes).map_err(|e| if e.kind() == io::ErrorKind::UnexpectedEof {
        ScanError::Incomplete
    } else { ScanError::Io })
}

#[cfg(test)]
mod tests;
