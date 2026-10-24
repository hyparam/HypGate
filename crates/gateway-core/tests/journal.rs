use gateway_core::journal::Journal;

#[test]
fn acknowledgment_requires_complete_record_then_successful_sync() {
    let mut journal = Journal::new(0);
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
        let mut journal = Journal::new(0);
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
    let mut journal = Journal::new(0);
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

    let mut gap = Journal::new(0);
    let prior = gap.begin(1).unwrap();
    assert!(gap.record_written(&prior, &vec![7]));
    let next = gap.begin(1).unwrap();
    assert!(!gap.record_durable(&next, &vec![8]));
    assert!(!gap.sync_succeeded()); // rejected commit preserved the pending append
}

#[test]
fn typed_frame_commits_only_the_reserved_complete_record() {
    use gateway_core::framing::{Header, RecordBody};
    let frame = || RecordBody::new(Header { payload: 3, tenant: 1, request: 2, chunk: 3, direction: 0 },
        &[4, 5, 6]).unwrap().seal(&[7; 32]);
    let length = frame().bytes().len() as u64;
    let mut wrong = Journal::new(0);
    let short = wrong.begin(length - 1).unwrap();
    assert!(wrong.commit_frame(&short, frame()).is_none());
    let mut journal = Journal::new(0);
    let ticket = journal.begin(length).unwrap();
    assert!(journal.commit_frame(&ticket, frame()).is_some());
    assert!(journal.commit_frame(&ticket, frame()).is_none());
    let next = journal.begin(length).unwrap();
    journal.fail();
    assert!(journal.commit_frame(&next, frame()).is_none());
}

#[test]
fn durable_receipt_matches_exact_metadata_and_payload() {
    use gateway_core::framing::{Header, RecordBody};
    let header = || Header { payload: 3, tenant: 1, request: 2, chunk: 3, direction: 0 };
    let frame = RecordBody::new(header(), &[4, 5, 6]).unwrap().seal(&[7; 32]);
    let mut journal = Journal::new(0);
    let ticket = journal.begin(frame.bytes().len() as u64).unwrap();
    let receipt = journal.commit_frame(&ticket, frame).unwrap();
    assert!(receipt.matches_record(header(), &[4, 5, 6]));
    assert!(!receipt.matches_record(header(), &[6, 5, 4]));
    assert!(!receipt.matches_record(header(), &[4, 5]));
    let mut other = header(); other.chunk += 1;
    assert!(!receipt.matches_record(other, &[4, 5, 6]));
    let mut other = header(); other.direction = 2;
    assert!(!receipt.matches_record(other, &[4, 5, 6]));
}

#[test]
fn production_journal_preserves_order_and_rejects_stale_or_failed_commits() {
    use gateway_core::{audit_journal::AuditJournal, framing::{Header, RecordBody}};
    let frame = |chunk, bytes: &[u8]| RecordBody::new(Header {
        payload: bytes.len() as u32, tenant: 1, request: 2, chunk, direction: 0 }, bytes)
        .unwrap().seal(&[7; 32]);
    let mut journal = AuditJournal::new(0);
    let first = frame(1, b"first");
    let first_ticket = journal.begin(first.bytes().len() as u64).unwrap();
    assert!(journal.begin(1).is_none());
    let first_receipt = journal.commit_frame(&first_ticket, first).unwrap();
    let second = frame(2, b"second");
    let second_ticket = journal.begin(second.bytes().len() as u64).unwrap();
    assert!(journal.commit_frame(&first_ticket, frame(1, b"first")).is_none());
    let second_receipt = journal.commit_frame(&second_ticket, second).unwrap();
    assert!(first_receipt.matches_record(Header {
        payload: 5, tenant: 1, request: 2, chunk: 1, direction: 0 }, b"first"));
    assert!(second_receipt.matches_record(Header {
        payload: 6, tenant: 1, request: 2, chunk: 2, direction: 0 }, b"second"));
    let third = frame(3, b"third");
    let third_ticket = journal.begin(third.bytes().len() as u64).unwrap();
    journal.fail();
    assert!(journal.commit_frame(&third_ticket, third).is_none());
    assert!(journal.begin(1).is_none());
}

#[test]
fn tickets_from_another_session_cannot_write_commit_or_acknowledge() {
    let mut first = Journal::new(11);
    let mut second = Journal::new(12);
    let own = first.begin(3).unwrap();
    let foreign = second.begin(3).unwrap();
    assert_eq!(own.session_id(), 11);
    assert!(!first.record_written(&foreign, &vec![1, 2, 3]));
    assert!(!first.record_durable(&foreign, &vec![1, 2, 3]));
    assert!(first.record_written(&own, &vec![1, 2, 3]));
    assert!(first.sync_succeeded());
    assert!(!first.acknowledge(&foreign));
    assert!(first.acknowledge(&own));
    assert_eq!(first.session_id(), 11);
}

#[test]
fn identical_records_keep_their_distinct_journal_provenance() {
    use gateway_core::{audit_journal::AuditJournal, framing::{Header, RecordBody}};
    let header = || Header { payload: 3, tenant: 1, request: 2, chunk: 3, direction: 0 };
    for session in [0, 1, u128::MAX] {
        let frame = RecordBody::new(header(), b"abc").unwrap().seal(&[0; 32]);
        let mut journal = AuditJournal::new(session);
        let ticket = journal.begin(frame.bytes().len() as u64).unwrap();
        let receipt = journal.commit_frame(&ticket, frame).unwrap();
        assert_eq!(receipt.session_id(), session);
        assert!(receipt.matches_record(header(), b"abc"));
        assert_eq!(journal.session_id(), session);
    }
}
