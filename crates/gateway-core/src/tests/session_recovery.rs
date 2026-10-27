use crate::{framing::{Header, RecordBody}, recovery::{ReadError, ScanError, SeekSource, Source}, session_recovery::{Files, SessionScanner}, sha256};
use std::sync::{Arc, Mutex};

struct Snapshot { bytes: Vec<u8>, position: usize, fail_at: Option<usize> }
impl Source for Snapshot {
    fn read_exact(&mut self, length: usize) -> Result<Vec<u8>, ReadError> {
        if self.fail_at.is_some_and(|at| self.position >= at) { return Err(ReadError::Io); }
        let end = self.position.saturating_add(length).min(self.bytes.len());
        let out = self.bytes[self.position..end].to_vec(); self.position = end;
        if out.len() == length { Ok(out) }
        else if out.is_empty() { Err(ReadError::Eof) }
        else { Err(ReadError::Incomplete) }
    }
    fn checksum_valid(&self, header: &[u8], payload: &[u8], checksum: &[u8]) -> bool {
        let mut hash = sha256::Hasher::new(); hash.update(header); hash.update(payload);
        hash.finish() == checksum
    }
}
impl SeekSource for Snapshot {
    fn seek(&mut self, offset: u64) -> bool {
        if offset > self.bytes.len() as u64 { return false; }
        self.position = offset as usize; true
    }
}
struct State {
    files: Vec<Vec<u8>>, opens: Vec<u64>,
    // Rotation happens at the exact moment recovery discovers its successor.
    append_when_next_opens: Option<Vec<u8>>,
    fail_at: Option<usize>,
}
struct Archive(Arc<Mutex<State>>);
impl Files for Archive {
    type Reader = Snapshot;
    fn open(&mut self, index: u64) -> Result<Option<Snapshot>, ScanError> {
        let mut state = self.0.lock().unwrap(); state.opens.push(index);
        if index == 1 {
            if let Some(bytes) = state.append_when_next_opens.take() { state.files[0].extend(bytes); }
        }
        Ok(state.files.get(index as usize).map(|bytes| Snapshot { bytes: bytes.clone(), position: 0, fail_at: state.fail_at }))
    }
}
fn header(session: u8) -> Vec<u8> {
    let mut bytes = crate::framing::encode_session(&[session; 16]);
    bytes.extend(sha256::digest(&bytes)); bytes
}
fn frame(chunk: u64) -> Vec<u8> {
    let body = RecordBody::new(Header { payload: 3, tenant: 1, request: 2, chunk, kind: 1 }, b"abc").unwrap();
    let checksum: [u8; 32] = sha256::digest(body.bytes()).try_into().unwrap();
    body.seal(&checksum).bytes().clone()
}
fn file(session: u8, chunks: &[u64]) -> Vec<u8> {
    let mut bytes = header(session);
    for chunk in chunks { bytes.extend(frame(*chunk)); }
    bytes
}
fn reader(files: Vec<Vec<u8>>) -> (SessionScanner<Archive>, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State { files, opens: vec![], append_when_next_opens: None, fail_at: None }));
    (SessionScanner::new(Archive(state.clone())).unwrap(), state)
}

#[test]
fn discovering_successor_rechecks_the_sealed_predecessor_before_crossing() {
    let (mut reader, state) = reader(vec![file(7, &[1]), file(7, &[3])]);
    state.lock().unwrap().append_when_next_opens = Some(frame(2));
    for chunk in 1..=3 { assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, chunk); }
    assert!(reader.next_record().unwrap().is_none());
    assert_eq!(reader.segment(), 1);
    assert_eq!(state.lock().unwrap().opens[..3], [0, 1, 0]);
}

#[test]
fn every_torn_tail_stops_before_successor_and_resumes_without_duplicates() {
    let whole = file(7, &[1, 2]);
    for cut in 125..whole.len() {
        let (mut reader, state) = reader(vec![whole[..cut].to_vec(), file(7, &[3])]);
        assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, 1);
        assert_eq!(reader.next_record().err(), Some(ScanError::Incomplete));
        assert_eq!(reader.segment(), 0); assert_eq!(reader.offset(), 124);
        assert_eq!(state.lock().unwrap().opens, [0]);
        state.lock().unwrap().files[0] = whole.clone();
        assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, 2);
        assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, 3);
    }
}

#[test]
fn every_incomplete_successor_header_is_retryable_without_crossing() {
    let second = file(7, &[2]);
    for cut in 0..56 {
        let (mut reader, state) = reader(vec![file(7, &[1]), second[..cut].to_vec()]);
        assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, 1);
        assert_eq!(reader.next_record().err(), Some(ScanError::Incomplete));
        assert_eq!(reader.segment(), 0);
        state.lock().unwrap().files[1] = second.clone();
        assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, 2);
    }
}

#[test]
fn corrupt_tail_or_foreign_session_permanently_stops_all_file_effects() {
    let mut corrupt = file(7, &[1, 2]); *corrupt.last_mut().unwrap() ^= 1;
    for files in [vec![corrupt, file(7, &[3])], vec![file(7, &[1]), file(8, &[2])]] {
        let (mut reader, state) = reader(files);
        assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, 1);
        assert_eq!(reader.next_record().err(), Some(ScanError::Corrupt));
        assert_eq!(reader.segment(), 0);
        let opens = state.lock().unwrap().opens.clone();
        assert!(reader.next_record().unwrap().is_none());
        assert_eq!(state.lock().unwrap().opens, opens);
    }
}

#[test]
fn snapshot_io_failure_is_terminal_and_opens_no_later_files() {
    let (mut reader, state) = reader(vec![file(7, &[1]), file(7, &[2])]);
    assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, 1);
    // The next successor snapshot fails before reading its header.
    state.lock().unwrap().fail_at = Some(0);
    assert_eq!(reader.next_record().err(), Some(ScanError::Io));
    let opens = state.lock().unwrap().opens.clone();
    assert!(reader.next_record().unwrap().is_none());
    assert_eq!(state.lock().unwrap().opens, opens);
}

#[test]
fn empty_segments_and_late_growth_keep_order_and_resume_current_segment() {
    let (mut reader, state) = reader(vec![file(7, &[]), file(7, &[]), file(7, &[1])]);
    assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, 1);
    assert_eq!(reader.segment(), 2);
    assert!(reader.next_record().unwrap().is_none());
    state.lock().unwrap().files[2].extend(frame(2));
    assert_eq!(reader.next_record().unwrap().unwrap().header.chunk, 2);
    assert_eq!(reader.segment(), 2);
    assert!(reader.next_record().unwrap().is_none());
}
