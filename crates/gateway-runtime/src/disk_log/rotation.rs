//! Trusted filesystem segmentation of one logical journal. Record bytes across
//! segments, excluding their headers, implement Storage's append-only history.
use super::{ReadSource, ScanError, StoredRecord};
#[cfg(test)]
use super::LogReader;
use gateway_core::{recovery::{Source, SeekSource}, session_recovery::{Files, SessionScanner}};
use gateway_core::{framing, sha256};
use std::{fs::{File, OpenOptions}, io::{self, Read, Seek, SeekFrom, Write}, path::{Path, PathBuf}, time::{Duration, Instant}};

const HEADER_BYTES: u64 = 56;

#[derive(Clone, Copy, Debug)]
pub struct Rotation {
    /// Target total file size, including the header. A single larger record is
    /// kept whole in its own segment rather than split or refused.
    pub max_bytes: u64,
    /// Rotate on the next append after this age; idle files do not rotate.
    pub max_age: Duration,
}
impl Default for Rotation {
    fn default() -> Self { Self { max_bytes: 128 * 1024 * 1024, max_age: Duration::from_secs(24 * 60 * 60) } }
}
impl Rotation {
    pub(super) fn validate(self) -> io::Result<()> {
        if self.max_bytes <= HEADER_BYTES || self.max_age.is_zero() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
}

fn segment_path(base: &Path, index: u64) -> PathBuf {
    if index == 0 { return base.to_path_buf(); }
    let mut name = base.as_os_str().to_os_string();
    name.push(format!(".{index:06}"));
    PathBuf::from(name)
}

// Effect site: new audit segments under the operator's path, never overwritten.
#[allow(clippy::disallowed_methods)]
pub(super) fn create_segment(path: &Path, session: &[u8; 16]) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let mut header = framing::encode_session(session);
    let checksum = sha256::digest(&header);
    header.extend_from_slice(&checksum);
    file.write_all(&header)?;
    file.sync_all()?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(file)
}

pub(super) struct RotatingFile {
    file: File,
    base: PathBuf,
    opened: Instant,
    max_age: Duration,
}
impl RotatingFile {
    pub(super) fn create(base: &Path, session: [u8; 16], rotation: Rotation) -> io::Result<Self> {
        let file = create_segment(base, &session)?;
        Ok(Self { file, base: base.to_path_buf(), opened: Instant::now(), max_age: rotation.max_age })
    }
}
// Trusted effects only: the verified RotatingStorage decides whether to rotate,
// chooses the next index, and poisons itself on any failed operation.
impl gateway_core::log_rotation::SegmentIo for RotatingFile {
    fn expired(&self) -> bool { self.opened.elapsed() >= self.max_age }
    fn create_next(&mut self, session: u128, index: u64) -> bool {
        // The production worker already synced the preceding frame. This also
        // satisfies SegmentIo for callers that append more than once per sync:
        // syncing the active segment must cover every closed segment as well.
        if self.file.sync_all().is_err() { return false; }
        match create_segment(&segment_path(&self.base, index), &session.to_le_bytes()) {
            Ok(file) => { self.file = file; self.opened = Instant::now(); true }
            Err(_) => false,
        }
    }
    fn append(&mut self, bytes: &Vec<u8>) -> bool { self.file.write_all(bytes).is_ok() }
    fn sync(&mut self) -> bool { self.file.sync_all().is_ok() }
}

// The reader sees a fixed prefix captured from the opened descriptor. Bytes
// appended later are picked up by the core's next open, never mixed into this
// snapshot. Prior bytes must not be changed externally.
struct Snapshot { file: File, length: u64, position: u64 }
impl Source for Snapshot {
    fn read_exact(&mut self, length: usize) -> Result<Vec<u8>, gateway_core::recovery::ReadError> {
        let remaining = self.length.saturating_sub(self.position);
        let mut source = ReadSource { reader: (&mut self.file).take(remaining) };
        let result = Source::read_exact(&mut source, length);
        self.position = self.length.saturating_sub(source.reader.limit());
        result
    }
    fn checksum_valid(&self, header: &[u8], payload: &[u8], checksum: &[u8]) -> bool {
        let mut hasher = sha256::Hasher::new(); hasher.update(header); hasher.update(payload);
        hasher.finish() == checksum
    }
}
impl SeekSource for Snapshot {
    fn seek(&mut self, offset: u64) -> bool {
        if offset > self.length { return false; }
        match self.file.seek(SeekFrom::Start(offset)) {
            Ok(position) if position == offset => { self.position = offset; true }
            _ => false,
        }
    }
}
struct SegmentFiles { base: PathBuf }
impl Files for SegmentFiles {
    type Reader = Snapshot;
    fn open(&mut self, index: u64) -> Result<Option<Snapshot>, ScanError> {
        let file = match File::open(segment_path(&self.base, index)) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(ScanError::Io),
        };
        let length = file.metadata().map_err(|_| ScanError::Io)?.len();
        Ok(Some(Snapshot { file, length, position: 0 }))
    }
}

/// Verified traversal of a session's consecutive numbered segments. Filesystem
/// snapshot acquisition is trusted; the core parses, resumes, and selects files.
pub struct SessionReader { scanner: SessionScanner<SegmentFiles> }
impl SessionReader {
    pub fn open(base: &Path) -> Result<Self, ScanError> {
        Ok(Self { scanner: SessionScanner::new(SegmentFiles { base: base.to_path_buf() })? })
    }
    pub fn session(&self) -> [u8; 16] { self.scanner.session() }
    pub fn segment(&self) -> u64 { self.scanner.segment() }
    /// Physical offset within the current segment, including its header.
    pub fn valid_end(&self) -> u64 { self.scanner.offset() }
    pub fn next_record(&mut self) -> Result<Option<StoredRecord>, ScanError> {
        let Some(record) = self.scanner.next_record()? else { return Ok(None); };
        let fields = record.header;
        let kind = crate::transfer::RecordKind::from_id(fields.kind).ok_or(ScanError::Corrupt)?;
        Ok(Some(StoredRecord { tenant: fields.tenant, request: fields.request, chunk: fields.chunk,
            kind, bytes: record.bytes }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{disk_log::{DiskLog, MAX_RECORD_BYTES}, test_support::TempDir, transfer::{AuditLog, LogRecord, RecordKind}};
    const WAIT: Duration = Duration::from_secs(5);
    fn record(chunk: u64) -> LogRecord<'static> {
        LogRecord { tenant: 1, request: 2, chunk, kind: RecordKind::Download, bytes: b"abc" }
    }
    fn rotating(path: &Path, max_bytes: u64) -> DiskLog {
        DiskLog::create_rotating(path, 2, WAIT, MAX_RECORD_BYTES, Rotation { max_bytes, max_age: WAIT }).unwrap()
    }

    #[test]
    fn size_boundary_rotates_whole_frames_with_stable_receipts_and_private_files() {
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let mut log = rotating(&path, 56 + 2 * 68);
        for chunk in 1..=5 {
            let receipt = log.append(record(chunk)).unwrap();
            assert_eq!(receipt.session_id(), u128::from_le_bytes(log.session()));
        }
        log.shutdown(WAIT).unwrap();
        assert!(!segment_path(&path, 3).exists());
        for index in 0..3 {
            let file = segment_path(&path, index);
            assert_eq!(std::fs::metadata(&file).unwrap().len(), if index < 2 { 192 } else { 124 });
            let reader = LogReader::new(File::open(&file).unwrap()).unwrap();
            assert_eq!(reader.session(), log.session());
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(file).unwrap().permissions().mode() & 0o777, 0o600);
            }
        }
        let mut reader = SessionReader::open(&path).unwrap();
        for chunk in 1..=5 { assert_eq!(reader.next_record().unwrap().unwrap().chunk, chunk); }
        assert!(reader.next_record().unwrap().is_none());
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn stale_snapshot_recovers_late_predecessor_records_before_the_successor() {
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let mut log = rotating(&path, 56 + 2 * 68);
        log.append(record(1)).unwrap();
        let mut reader = SessionReader::open(&path).unwrap();
        // The reader's first file snapshot ends at record 1. Rotation leaves
        // record 2 in that file and record 3 in the newly discovered successor.
        log.append(record(2)).unwrap(); log.append(record(3)).unwrap();
        log.shutdown(WAIT).unwrap();
        for chunk in 1..=3 { assert_eq!(reader.next_record().unwrap().unwrap().chunk, chunk); }
        assert!(reader.next_record().unwrap().is_none());
        assert_eq!(reader.segment(), 1);
    }

    #[test]
    fn oversized_record_stays_whole_without_empty_leading_segment() {
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let mut log = rotating(&path, 57);
        log.append(record(1)).unwrap();
        assert!(!segment_path(&path, 1).exists());
        log.append(record(2)).unwrap();
        log.shutdown(WAIT).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 124);
        assert_eq!(std::fs::metadata(segment_path(&path, 1)).unwrap().len(), 124);
    }

    #[test]
    fn age_rotates_on_append_but_never_creates_empty_segments() {
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let mut file = RotatingFile::create(&path, [1; 16], Rotation::default()).unwrap();
        file.opened = Instant::now() - Duration::from_secs(86401);
        use gateway_core::disk_worker::Storage;
        let mut storage = gateway_core::log_rotation::RotatingStorage::new(file, u128::from_le_bytes([1; 16]), 128);
        assert!(storage.write_all(&b"first".to_vec())); assert!(storage.sync());
        assert!(!segment_path(&path, 1).exists());
        assert!(storage.write_all(&b"second".to_vec())); assert!(storage.sync());
        assert!(segment_path(&path, 1).exists());
        assert_eq!(&std::fs::read(path).unwrap()[56..], b"first");
    }

    #[test]
    fn rotation_collision_preserves_files_and_permanently_fails_logging() {
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let mut log = rotating(&path, 124);
        log.append(record(1)).unwrap();
        let before = std::fs::read(&path).unwrap();
        let next = segment_path(&path, 1);
        std::fs::write(&next, b"existing evidence").unwrap();
        assert!(log.append(record(2)).is_err());
        assert!(!log.healthy());
        std::fs::remove_file(&next).unwrap();
        assert!(log.append(record(3)).is_err());
        assert!(!next.exists());
        log.shutdown(WAIT).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), before);
    }

    #[test]
    fn follower_continues_after_eof_and_incomplete_next_header_without_duplicates() {
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let mut log = rotating(&path, 124);
        log.append(record(1)).unwrap();
        let mut reader = SessionReader::open(&path).unwrap();
        assert_eq!(reader.next_record().unwrap().unwrap().chunk, 1);
        assert!(reader.next_record().unwrap().is_none());
        log.append(record(2)).unwrap();
        log.shutdown(WAIT).unwrap();
        let next = segment_path(&path, 1);
        let bytes = std::fs::read(&next).unwrap();
        std::fs::write(&next, &bytes[..20]).unwrap();
        assert_eq!(reader.next_record(), Err(ScanError::Incomplete));
        assert_eq!(reader.segment(), 0);
        std::fs::write(&next, &bytes).unwrap();
        assert_eq!(reader.next_record().unwrap().unwrap().chunk, 2);
        assert_eq!(reader.segment(), 1);
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn reader_never_skips_a_torn_tail_or_accepts_a_different_session() {
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        let mut log = rotating(&path, 124);
        log.append(record(1)).unwrap(); log.append(record(2)).unwrap(); log.shutdown(WAIT).unwrap();
        let first = std::fs::read(&path).unwrap();
        std::fs::write(&path, &first[..first.len() - 1]).unwrap();
        let mut reader = SessionReader::open(&path).unwrap();
        assert_eq!(reader.next_record(), Err(ScanError::Incomplete));
        assert_eq!(reader.segment(), 0);
        std::fs::write(&path, first).unwrap();
        assert_eq!(reader.next_record().unwrap().unwrap().chunk, 1);
        let other = dir.0.join("other.log");
        let other_log = DiskLog::create(&other, 1, WAIT).unwrap(); other_log.shutdown(WAIT).unwrap();
        std::fs::copy(other, segment_path(&path, 1)).unwrap();
        assert_eq!(reader.next_record(), Err(ScanError::Corrupt));
        assert!(reader.next_record().unwrap().is_none());
    }

    #[test]
    fn invalid_rotation_limits_do_not_create_files() {
        let dir = TempDir::new(); let path = dir.0.join("audit.log");
        for rotation in [Rotation { max_bytes: 56, max_age: WAIT }, Rotation { max_bytes: 128, max_age: Duration::ZERO }] {
            assert!(DiskLog::create_rotating(&path, 1, WAIT, 3, rotation).is_err());
            assert!(!path.exists());
        }
    }
}
