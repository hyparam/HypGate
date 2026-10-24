use gateway_core::mailbox::Mailbox;

#[test]
fn endpoint_closure_preserves_or_returns_the_exact_pending_value_and_never_reopens() {
    for receiver_first in [false, true] {
        let mut slot = Mailbox::new();
        assert!(!slot.is_closed()); assert!(!slot.is_full()); assert_eq!(slot.pop(), None);
        assert_eq!(slot.push(7), Ok(())); assert!(slot.is_full());
        assert_eq!(slot.push(8), Err(8));
        if receiver_first {
            assert_eq!(slot.close_receiver(), Some(7));
            assert_eq!(slot.pop(), None);
            slot.close_sender();
        } else {
            slot.close_sender(); slot.close_sender();
            assert!(slot.is_closed()); assert!(slot.is_full());
            assert_eq!(slot.push(8), Err(8));
            assert_eq!(slot.pop(), Some(7));
            assert_eq!(slot.close_receiver(), None);
        }
        assert!(slot.is_closed()); assert!(!slot.is_full());
        assert_eq!(slot.close_receiver(), None); slot.close_sender();
        assert_eq!(slot.push(9), Err(9)); assert_eq!(slot.pop(), None);
    }
}

#[test]
fn receiver_closure_returns_ownership_without_running_the_payload_destructor() {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    struct Payload(Arc<AtomicUsize>);
    impl Drop for Payload { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut slot = Mailbox::new();
    assert!(slot.push(Payload(dropped.clone())).is_ok());
    let returned = slot.close_receiver().unwrap();
    drop(slot);
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(returned);
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[test]
fn receiver_cleanup_keeps_charge_after_extraction_until_reported_destruction() {
    let mut slot = Mailbox::new();
    assert_eq!(slot.push(vec![7; 16_384]), Ok(()));
    slot.close_sender();
    let mut cleanup = slot.close_receiver_charged();
    assert!(!slot.is_full());
    assert_eq!(cleanup.retained_count(), 1);
    assert!(!cleanup.finish());
    let payload = cleanup.begin().unwrap();
    assert_eq!(payload, vec![7; 16_384]);
    assert_eq!(cleanup.retained_count(), 1);
    assert!(cleanup.begin().is_none());
    assert_eq!(cleanup.retained_count(), 1);
    assert!(slot.push(vec![8]).is_err());
    let mut repeated_close = slot.close_receiver_charged();
    assert_eq!(repeated_close.retained_count(), 0);
    assert!(repeated_close.begin().is_none());
    assert!(repeated_close.finish());
    assert_eq!(cleanup.retained_count(), 1);
    drop(payload);
    assert!(cleanup.finish());
    assert_eq!(cleanup.retained_count(), 0);
    assert!(!cleanup.finish());
}

#[test]
fn panicking_payload_destruction_never_reports_cleanup_completion() {
    struct Panics;
    impl Drop for Panics { fn drop(&mut self) { panic!("payload destructor"); } }
    let mut slot = Mailbox::new();
    assert!(slot.push(Panics).is_ok());
    let mut cleanup = slot.close_receiver_charged();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        drop(cleanup.begin());
        assert!(cleanup.finish());
    })).is_err());
    assert_eq!(cleanup.retained_count(), 1);
}
