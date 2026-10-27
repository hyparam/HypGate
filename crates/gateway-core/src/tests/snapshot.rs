use crate::{recovery::{ReadError, SeekSource, Source}, snapshot::{FileRead, Snapshot}, sha256};
use std::sync::{Arc, Mutex};
struct State {
    bytes: Vec<u8>, position: usize, fragment: usize, reads: Vec<usize>, seeks: Vec<u64>,
    fail_at: Option<usize>, fail_seek: bool, advance_on_error: bool,
}
struct File(Arc<Mutex<State>>);
impl FileRead for File {
    fn fill(&mut self, buffer: &mut Vec<u8>, max: usize) -> bool {
        let mut state = self.0.lock().unwrap(); state.reads.push(max);
        if state.fail_at.is_some_and(|at| state.position >= at) {
            if state.advance_on_error { state.position += max; }
            return false;
        }
        let end = (state.position + max.min(state.fragment)).min(state.bytes.len());
        if end == state.position { return false; }
        buffer.extend_from_slice(&state.bytes[state.position..end]); state.position = end;
        true
    }
    fn seek(&mut self, offset: u64) -> bool {
        let mut state = self.0.lock().unwrap(); state.seeks.push(offset);
        if state.fail_seek || offset > state.bytes.len() as u64 { return false; }
        state.position = offset as usize; true
    }
    fn checksum_valid(&self, header: &[u8], payload: &[u8], checksum: &[u8]) -> bool {
        let mut hash = sha256::Hasher::new(); hash.update(header); hash.update(payload);
        hash.finish() == checksum
    }
}
fn snapshot(length: u64, fragment: usize) -> (Snapshot<File>, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State { bytes: (0..64).collect(), position: 0, fragment,
        reads: vec![], seeks: vec![], fail_at: None, fail_seek: false, advance_on_error: false }));
    (Snapshot::new(File(state.clone()), length), state)
}

#[test]
fn every_short_snapshot_and_fragment_size_has_exact_extent_and_error_kind() {
    for length in 0..=32 {
        for fragment in 1..=8 {
            let (mut source, state) = snapshot(length, fragment);
            let result = source.read_exact(32);
            if length == 32 { assert_eq!(result.unwrap(), (0..32).collect::<Vec<_>>()); }
            else { assert_eq!(result.unwrap_err(), if length == 0 { ReadError::Eof } else { ReadError::Incomplete }); }
            assert_eq!(state.lock().unwrap().position, length as usize);
            let calls = state.lock().unwrap().reads.len();
            assert_eq!(source.read_exact(1).unwrap_err(), ReadError::Eof);
            assert_eq!(source.read_exact(0).unwrap(), Vec::<u8>::new());
            assert_eq!(state.lock().unwrap().reads.len(), calls);
        }
    }
}

#[test]
fn file_growth_never_leaks_past_snapshot_and_new_snapshot_can_read_it() {
    let (mut source, state) = snapshot(8, 3);
    assert_eq!(source.read_exact(5).unwrap(), [0, 1, 2, 3, 4]);
    assert_eq!(source.read_exact(8).unwrap_err(), ReadError::Incomplete);
    assert_eq!(state.lock().unwrap().position, 8);
    assert!(state.lock().unwrap().reads.iter().all(|n| *n <= 8));
    // An independently acquired newer view can see the later bytes.
    state.lock().unwrap().position = 0;
    let mut newer = Snapshot::new(File(state.clone()), 16);
    assert!(newer.seek(8));
    assert_eq!(newer.read_exact(8).unwrap(), [8, 9, 10, 11, 12, 13, 14, 15]);
    assert_eq!(newer.read_exact(1).unwrap_err(), ReadError::Eof);
}

#[test]
fn seek_bounds_are_checked_before_effect_and_failed_seek_keeps_cursor() {
    let (mut source, state) = snapshot(16, 3);
    assert_eq!(source.read_exact(4).unwrap(), [0, 1, 2, 3]);
    assert!(!source.seek(17)); assert!(!source.seek(u64::MAX));
    assert!(state.lock().unwrap().seeks.is_empty());
    state.lock().unwrap().fail_seek = true;
    assert!(!source.seek(8));
    state.lock().unwrap().fail_seek = false;
    assert_eq!(source.read_exact(2).unwrap(), [4, 5]);
    assert!(source.seek(16)); assert_eq!(source.read_exact(1).unwrap_err(), ReadError::Eof);
    assert!(source.seek(0)); assert_eq!(source.read_exact(2).unwrap(), [0, 1]);
}

#[test]
fn partial_read_then_io_error_keeps_the_actual_consumed_position() {
    let (mut source, state) = snapshot(16, 2);
    state.lock().unwrap().fail_at = Some(4);
    assert_eq!(source.read_exact(8).unwrap_err(), ReadError::Io);
    assert_eq!(state.lock().unwrap().position, 4);
    state.lock().unwrap().fail_at = None;
    assert_eq!(source.read_exact(2).unwrap_err(), ReadError::Io);
    assert!(source.seek(4));
    assert_eq!(source.read_exact(2).unwrap(), [4, 5]);
}

#[test]
fn read_error_with_unknown_cursor_movement_requires_seek_before_retry() {
    let (mut source, state) = snapshot(16, 2);
    state.lock().unwrap().fail_at = Some(4);
    state.lock().unwrap().advance_on_error = true;
    assert_eq!(source.read_exact(8).unwrap_err(), ReadError::Io);
    assert_eq!(state.lock().unwrap().position, 8);
    state.lock().unwrap().fail_at = None;
    let reads = state.lock().unwrap().reads.len();
    assert_eq!(source.read_exact(2).unwrap_err(), ReadError::Io);
    assert_eq!(state.lock().unwrap().reads.len(), reads);
    assert!(source.seek(4));
    assert_eq!(source.read_exact(2).unwrap(), [4, 5]);
}
