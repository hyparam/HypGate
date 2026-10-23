use gateway_core::journal::Journal;

#[test]
fn acknowledgment_requires_complete_record_then_successful_sync() {
    let mut journal = Journal::new();
    assert!(journal.begin(0).is_none());
    let first = journal.begin(3).unwrap();
    assert!(journal.begin(1).is_none());
    assert!(!journal.acknowledge(&first));
    assert!(!journal.sync_succeeded());
    assert!(!journal.record_written(&first, &vec![1, 2]));
    assert!(journal.record_written(&first, &vec![1, 2, 3]));
    assert!(!journal.acknowledge(&first));
    assert!(journal.sync_succeeded());
    assert!(journal.acknowledge(&first));
    assert!(!journal.acknowledge(&first));
    assert!(journal.begin(u64::MAX).is_none());
    let second = journal.begin(2).unwrap();
    assert!(!journal.record_written(&first, &vec![1, 2, 3]));
    assert!(journal.record_written(&second, &vec![4, 5]));
    assert!(!journal.acknowledge(&second));
    assert!(journal.sync_succeeded());
    assert!(journal.acknowledge(&second));
}

#[test]
fn failure_prevents_new_records_sync_and_acknowledgment() {
    for fail_after_write in [false, true] {
        let mut journal = Journal::new();
        let ticket = journal.begin(1).unwrap();
        if fail_after_write { assert!(journal.record_written(&ticket, &vec![7])); }
        journal.fail();
        assert!(journal.begin(1).is_none());
        assert!(!journal.record_written(&ticket, &vec![7]));
        assert!(!journal.sync_succeeded());
        assert!(!journal.acknowledge(&ticket));
    }
}
