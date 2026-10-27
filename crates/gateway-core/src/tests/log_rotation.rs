use crate::{disk_worker::Storage, log_rotation::{RotatingStorage, SegmentIo}};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State { events: Vec<String>, fail: Option<&'static str>, expired: bool }
struct Disk(Arc<Mutex<State>>);
impl SegmentIo for Disk {
    fn expired(&self) -> bool { self.0.lock().unwrap().expired }
    fn seal(&mut self) -> bool {
        let mut state = self.0.lock().unwrap(); state.events.push("seal".into());
        state.fail != Some("seal")
    }
    fn create_next(&mut self, session: u128, index: u64) -> bool {
        let mut state = self.0.lock().unwrap();
        state.events.push(format!("create {session} {index}"));
        state.fail != Some("create")
    }
    fn append(&mut self, bytes: &Vec<u8>) -> bool {
        let mut state = self.0.lock().unwrap(); state.events.push(format!("append {}", bytes.len()));
        state.fail != Some("append")
    }
    fn sync(&mut self) -> bool {
        let mut state = self.0.lock().unwrap(); state.events.push("sync".into());
        state.fail != Some("sync")
    }
}

#[test]
fn rotation_policy_matches_wide_arithmetic_at_size_extremes() {
    for used in [56, 57, 124, 1024, u64::MAX - 1, u64::MAX] {
        for limit in [57, 124, 1024, u64::MAX] {
            for length in [0, 1, 68, u64::MAX - 56, u64::MAX] {
                for expired in [false, true] {
                    assert_eq!(RotatingStorage::<Disk>::should_rotate(used, limit, length, expired),
                        used > 56 && (u128::from(used) + u128::from(length) > u128::from(limit) || expired));
                }
            }
        }
    }
}

#[test]
fn rotation_preserves_session_and_orders_create_append_sync() {
    let state = Arc::new(Mutex::new(State::default()));
    let mut storage = RotatingStorage::new(Disk(state.clone()), 42, 124);
    for _ in 0..3 {
        assert!(storage.write_all(&vec![0; 68]));
        assert!(storage.sync());
    }
    assert_eq!(state.lock().unwrap().events, ["append 68", "sync", "seal", "create 42 1", "append 68", "sync", "seal", "create 42 2", "append 68", "sync"]);
}

#[test]
fn rotation_failures_permanently_stop_all_subsequent_effects() {
    for failure in ["seal", "create", "append", "sync"] {
        let state = Arc::new(Mutex::new(State::default()));
        let mut storage = RotatingStorage::new(Disk(state.clone()), 42, 124);
        assert!(storage.write_all(&vec![0; 68])); assert!(storage.sync());
        state.lock().unwrap().fail = Some(failure);
        let written = storage.write_all(&vec![1; 68]);
        if failure == "sync" { assert!(written); assert!(!storage.sync()); }
        else { assert!(!written); }
        let before = state.lock().unwrap().events.clone();
        assert!(!storage.write_all(&vec![2; 68])); assert!(!storage.sync());
        assert_eq!(state.lock().unwrap().events, before);
        if failure == "create" { assert_eq!(before.last().unwrap(), "create 42 1"); }
        if failure == "seal" { assert_eq!(before.last().unwrap(), "seal"); }
    }
}
