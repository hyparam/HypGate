//! Bounded disk logging. Filesystem effects and checksum security are trusted,
//! not verified. A single worker owns the file; requests never choose its path.
use crate::transfer::{AuditLog, Direction, LogRecord};
use sha2::{Digest, Sha256};
use std::{fs::{File, OpenOptions}, io::{self, Read, Write}, path::Path,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::sync::{mpsc, oneshot};

const FILE_MAGIC: &[u8; 8] = b"SGLOG001";
const RECORD_MAGIC: &[u8; 4] = b"SGR1";
const FILE_HEADER: usize = 56; // magic + random session ID + checksum
const RECORD_HEADER: usize = 33; // magic + length + tenant + request + chunk + direction
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

struct Job { frame: Vec<u8>, done: oneshot::Sender<bool> }

/// Clones share one bounded queue and one worker. Never create replacement workers
/// to escape a stuck filesystem call. A timeout closes logging health permanently.
#[derive(Clone)]
pub struct DiskLog {
    sender: mpsc::Sender<Job>,
    healthy: Arc<AtomicBool>,
    deadline: Duration,
    session: [u8; 16],
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
        std::thread::Builder::new().name("soundgate-audit".into()).spawn(move || {
            while let Some(job) = receiver.blocking_recv() {
                let ok = worker_health.load(Ordering::Acquire)
                    && file.write_all(&job.frame).and_then(|()| file.sync()).is_ok();
                if !ok { worker_health.store(false, Ordering::Release); }
                // A canceled caller may leave a durable but unsent record. It must
                // never cause the worker to retry or the gateway to replay traffic.
                let _ = job.done.send(ok);
            }
        })?;
        Ok(Self { sender, healthy, deadline, session })
    }

    pub fn healthy(&self) -> bool { self.healthy.load(Ordering::Acquire) }
    #[cfg(test)]
    pub(crate) fn inject_failure(&self) { self.healthy.store(false, Ordering::Release); }
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
        let permit = self.sender.try_reserve().map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
            mpsc::error::TrySendError::Closed(_) => io::ErrorKind::BrokenPipe,
        })?;
        let frame = encode(record);
        let (done, completion) = oneshot::channel();
        permit.send(Job { frame, done });
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
    let mut frame = Vec::with_capacity(RECORD_HEADER + record.bytes.len() + 32);
    frame.extend_from_slice(RECORD_MAGIC);
    frame.extend_from_slice(&(record.bytes.len() as u32).to_le_bytes());
    frame.extend_from_slice(&record.tenant.to_le_bytes());
    frame.extend_from_slice(&record.request.to_le_bytes());
    frame.extend_from_slice(&record.chunk.to_le_bytes());
    frame.push(match record.direction { Direction::Upload => 0, Direction::Download => 1 });
    frame.extend_from_slice(record.bytes);
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
pub struct LogReader<R> { reader: R, session: [u8; 16], valid_end: u64, stopped: bool }
impl<R: Read> LogReader<R> {
    pub fn new(mut reader: R) -> Result<Self, ScanError> {
        let mut header = [0; FILE_HEADER];
        exact(&mut reader, &mut header)?;
        if &header[..8] != FILE_MAGIC || Sha256::digest(&header[..24])[..] != header[24..] {
            return Err(ScanError::Corrupt);
        }
        let session = header[8..24].try_into().unwrap();
        Ok(Self { reader, session, valid_end: FILE_HEADER as u64, stopped: false })
    }
    pub fn session(&self) -> [u8; 16] { self.session }
    pub fn valid_end(&self) -> u64 { self.valid_end }

    pub fn next_record(&mut self) -> Result<Option<StoredRecord>, ScanError> {
        if self.stopped { return Ok(None); }
        self.stopped = true;
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
        let size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        if &header[..4] != RECORD_MAGIC || size > MAX_RECORD_BYTES || header[32] > 1 {
            return Err(ScanError::Corrupt);
        }
        let mut bytes = vec![0; size];
        exact(&mut self.reader, &mut bytes)?;
        let mut checksum = [0u8; 32];
        exact(&mut self.reader, &mut checksum)?;
        let mut digest = Sha256::new(); digest.update(header); digest.update(&bytes);
        if digest.finalize()[..] != checksum { return Err(ScanError::Corrupt); }
        let request = u64::from_le_bytes(header[16..24].try_into().unwrap());
        if request == 0 { return Err(ScanError::Corrupt); }
        self.valid_end = self.valid_end.checked_add((RECORD_HEADER + size + 32) as u64).ok_or(ScanError::Corrupt)?;
        self.stopped = false;
        Ok(Some(StoredRecord {
            tenant: u64::from_le_bytes(header[8..16].try_into().unwrap()), request,
            chunk: u64::from_le_bytes(header[24..32].try_into().unwrap()),
            direction: if header[32] == 0 { Direction::Upload } else { Direction::Download }, bytes,
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
