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

#[test]
fn durable_frame_commit_binds_one_complete_record_and_rejects_stale_tickets() {
    let mut journal = Journal::new();
    let first = journal.begin(3).unwrap();
    assert!(!journal.record_durable(&first, &vec![1, 2]));
    assert!(journal.record_durable(&first, &vec![1, 2, 3]));
    assert!(!journal.record_durable(&first, &vec![1, 2, 3]));
    let second = journal.begin(1).unwrap();
    assert!(!journal.record_durable(&first, &vec![1, 2, 3]));
    assert!(journal.record_durable(&second, &vec![4]));
    let third = journal.begin(1).unwrap();
    journal.fail();
    assert!(!journal.record_durable(&third, &vec![5]));

    let mut gap = Journal::new();
    let prior = gap.begin(1).unwrap();
    assert!(gap.record_written(&prior, &vec![7]));
    let next = gap.begin(1).unwrap();
    assert!(!gap.record_durable(&next, &vec![8]));
    assert!(!gap.sync_succeeded()); // rejected commit preserved the pending append
}

#[test]
fn typed_frame_commits_only_the_reserved_complete_record() {
    use gateway_core::framing::{Header, RecordBody};
    let frame = RecordBody::new(Header { payload: 3, tenant: 1, request: 2, chunk: 3, direction: 0 },
        &[4, 5, 6]).unwrap().seal(&[7; 32]);
    let mut wrong = Journal::new();
    let short = wrong.begin(frame.bytes().len() as u64 - 1).unwrap();
    assert!(!wrong.record_durable_frame(&short, &frame));
    let mut journal = Journal::new();
    let ticket = journal.begin(frame.bytes().len() as u64).unwrap();
    assert!(journal.record_durable_frame(&ticket, &frame));
    assert!(!journal.record_durable_frame(&ticket, &frame));
    let next = journal.begin(frame.bytes().len() as u64).unwrap();
    journal.fail();
    assert!(!journal.record_durable_frame(&next, &frame));
}
