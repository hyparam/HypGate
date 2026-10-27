use gateway_core::{audit_journal::AuditJournal, disk_worker::{Completion, Storage}, batch_worker::BatchWorker as DiskWorker,
    frame_queue::FrameQueue, framing::{Header, RecordBody, RecordFrame}, journal::DurableFrame};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Disk { bytes: Vec<u8>, stable: Vec<u8>, writes: usize, syncs: usize, fail_write: bool, fail_sync: bool, fail_write_at: Option<usize> }
impl Storage for Disk {
    fn write_all(&mut self, bytes: &Vec<u8>) -> bool {
        self.writes += 1;
        if self.fail_write || self.fail_write_at == Some(self.writes) { self.bytes.extend_from_slice(&bytes[..3]); return false; }
        self.bytes.extend_from_slice(bytes); true
    }
    fn sync(&mut self) -> bool {
        self.syncs += 1;
        if self.fail_sync { return false; }
        self.stable = self.bytes.clone(); true
    }
}
type Replies = Arc<Mutex<Vec<(u64, Option<DurableFrame>)>>>;
struct Reply { id: u64, replies: Replies }
impl Completion for Reply {
    fn complete(self, receipt: Option<DurableFrame>) { self.replies.lock().unwrap().push((self.id, receipt)); }
}
fn frame(id: u64) -> RecordFrame {
    RecordBody::new(Header { tenant: 1, request: 1, chunk: id, kind: 0, payload: 3 }, b"abc")
        .unwrap().seal(&[0; 32])
}
fn push(queue: &mut FrameQueue<Reply>, id: u64, replies: &Replies) {
    assert!(queue.push((frame(id), Reply { id, replies: replies.clone() })).is_ok());
}

#[test]
fn active_capacity_survives_io_and_receipt_delivery_until_matching_release() {
    let replies = Replies::default();
    let mut queue = FrameQueue::with_payload_limit(1, 3);
    let mut worker = DiskWorker::new(3, 1);
    let mut journal = AuditJournal::new(1);
    let mut disk = Disk::default();
    push(&mut queue, 1, &replies);
    let active = worker.take(&mut queue).unwrap();
    assert!(!worker.can_take()); assert!(!worker.can_take());
    // Queue credit can be reused, but the independent active credit cannot.
    push(&mut queue, 2, &replies);
    assert!(worker.take(&mut queue).is_none()); assert_eq!(queue.len(), 1);
    let finished = worker.run(active, &mut journal, &mut disk, true);
    assert!(!finished.failed());
    assert_eq!(disk.writes, 1); assert_eq!(disk.syncs, 1);
    assert_eq!(disk.stable, *frame(1).bytes());
    assert!(worker.take(&mut queue).is_none());
    let released = finished.deliver();
    assert!(worker.take(&mut queue).is_none());
    assert!(worker.release(released));
    assert!(worker.can_take());
    let active = worker.take(&mut queue).unwrap();
    let finished = worker.run(active, &mut journal, &mut disk, true);
    assert!(worker.release(finished.deliver()));
    let replies = replies.lock().unwrap();
    assert_eq!(replies.iter().map(|r| r.0).collect::<Vec<_>>(), vec![1, 2]);
    for (id, receipt) in replies.iter() {
        assert!(receipt.as_ref().unwrap().matches_record(Header {
            tenant: 1, request: 1, chunk: *id, kind: 0, payload: 3,
        }, b"abc"));
    }
}

#[test]
fn abandoned_active_or_finished_job_cannot_return_credit() {
    for finish in [false, true] {
        let replies = Replies::default();
        let mut queue = FrameQueue::with_payload_limit(1, 3);
        let mut worker = DiskWorker::new(3, 1);
        push(&mut queue, 1, &replies);
        let active = worker.take(&mut queue).unwrap();
        if finish {
            drop(worker.run(active, &mut AuditJournal::new(1), &mut Disk::default(), true));
        } else { drop(active); }
        push(&mut queue, 2, &replies);
        assert!(!worker.can_take());
        assert!(worker.take(&mut queue).is_none());
        assert_eq!(queue.len(), 1);
        assert!(replies.lock().unwrap().is_empty());
    }
}

#[test]
fn disabled_write_and_sync_failure_never_acknowledge_or_retry() {
    for mode in 0..3 {
        let replies = Replies::default();
        let mut queue = FrameQueue::with_payload_limit(1, 3);
        let mut worker = DiskWorker::new(3, 1);
        let mut journal = AuditJournal::new(1);
        let mut disk = Disk { fail_write: mode == 1, fail_sync: mode == 2, ..Disk::default() };
        for id in 1..=2 {
            push(&mut queue, id, &replies);
            let active = worker.take(&mut queue).unwrap();
            // The second attempt remains disabled by journal failure even when
            // the caller supplies true and the external faults have recovered.
            let finished = worker.run(active, &mut journal, &mut disk, mode != 0 || id == 2);
            assert!(finished.failed());
            assert!(worker.release(finished.deliver()));
            disk.fail_write = false; disk.fail_sync = false;
        }
        assert_eq!(disk.writes, usize::from(mode != 0));
        assert_eq!(disk.syncs, usize::from(mode == 2));
        assert!(replies.lock().unwrap().iter().all(|(_, receipt)| receipt.is_none()));
    }
}

#[test]
fn mismatched_payload_budget_does_not_dequeue_and_closed_queue_drains() {
    let replies = Replies::default();
    let mut queue = FrameQueue::with_payload_limit(1, 3);
    let mut small = DiskWorker::new(2, 1);
    push(&mut queue, 1, &replies);
    assert!(small.take(&mut queue).is_none());
    assert_eq!(queue.len(), 1); assert!(small.can_take());
    queue.close();
    let mut worker = DiskWorker::new(3, 1);
    let active = worker.take(&mut queue).unwrap();
    let finished = worker.run(active, &mut AuditJournal::new(1), &mut Disk::default(), true);
    assert!(worker.release(finished.deliver()));
    assert!(worker.take(&mut queue).is_none());
}

#[test]
fn completion_from_another_session_cannot_release_active_capacity() {
    let replies = Replies::default();
    let mut queue = FrameQueue::with_payload_limit(1, 3);
    let mut first = DiskWorker::new(3, 1);
    let mut second = DiskWorker::new(3, 2);
    push(&mut queue, 1, &replies);
    let one = first.take(&mut queue).unwrap();
    push(&mut queue, 2, &replies);
    let two = second.take(&mut queue).unwrap();
    let released = first.run(one, &mut AuditJournal::new(1), &mut Disk::default(), true).deliver();
    assert!(!second.release(released));
    assert!(!first.can_take()); assert!(!second.can_take());
    assert!(second.release(second.run(two, &mut AuditJournal::new(2), &mut Disk::default(), true).deliver()));
}

#[test]
fn mismatched_journal_session_fails_before_any_storage_effect() {
    let replies = Replies::default();
    let mut queue = FrameQueue::with_payload_limit(1, 3);
    let mut worker = DiskWorker::new(3, 1);
    let mut journal = AuditJournal::new(2);
    let mut disk = Disk::default();
    push(&mut queue, 1, &replies);
    let active = worker.take(&mut queue).unwrap();
    let finished = worker.run(active, &mut journal, &mut disk, true);
    assert!(finished.failed());
    assert_eq!((disk.writes, disk.syncs), (0, 0));
    assert!(worker.release(finished.deliver()));
    assert!(replies.lock().unwrap()[0].1.is_none());
    assert!(journal.begin(68).is_none());
}

#[test]
fn batches_are_bounded_fifo_and_share_one_sync_without_early_delivery() {
    let replies = Replies::default();
    let mut queue = FrameQueue::with_payload_limit(20, 3);
    let mut worker = DiskWorker::new(3, 1);
    let mut journal = AuditJournal::new(1);
    let mut disk = Disk::default();
    for id in 1..=20 { push(&mut queue, id, &replies); }
    queue.close();
    let first = worker.take(&mut queue).unwrap();
    assert_eq!(queue.len(), 4);
    let finished = worker.run(first, &mut journal, &mut disk, true);
    assert!(!finished.failed());
    assert_eq!((disk.writes, disk.syncs), (16, 1));
    assert!(replies.lock().unwrap().is_empty());
    assert!(worker.take(&mut queue).is_none());
    assert!(worker.release(finished.deliver()));
    let second = worker.take(&mut queue).unwrap();
    assert_eq!(queue.len(), 0);
    let finished = worker.run(second, &mut journal, &mut disk, true);
    assert!(!finished.failed()); assert!(worker.release(finished.deliver()));
    assert_eq!((disk.writes, disk.syncs), (20, 2));
    assert_eq!(disk.stable, (1..=20).flat_map(|id| frame(id).bytes().clone()).collect::<Vec<_>>());
    let replies = replies.lock().unwrap();
    assert_eq!(replies.iter().map(|r| r.0).collect::<Vec<_>>(), (1..=20).collect::<Vec<_>>());
    for (id, receipt) in replies.iter() {
        assert!(receipt.as_ref().unwrap().matches_record(Header { tenant: 1, request: 1, chunk: *id, kind: 0, payload: 3 }, b"abc"));
    }
}

#[test]
fn failed_batch_rejects_every_record_and_never_retries_partial_writes() {
    for fail_write_at in [Some(1), Some(2), Some(16), None] {
        let replies = Replies::default();
        let mut queue = FrameQueue::with_payload_limit(20, 3);
        let mut worker = DiskWorker::new(3, 1);
        let mut journal = AuditJournal::new(1);
        let mut disk = Disk { fail_write_at, fail_sync: fail_write_at.is_none(), ..Disk::default() };
        for id in 1..=20 { push(&mut queue, id, &replies); }
        let batch = worker.take(&mut queue).unwrap();
        let finished = worker.run(batch, &mut journal, &mut disk, true);
        assert!(finished.failed()); assert!(worker.release(finished.deliver()));
        let effects = (disk.writes, disk.syncs);
        assert_eq!(effects, (fail_write_at.unwrap_or(16), usize::from(fail_write_at.is_none())));
        disk.fail_write_at = None; disk.fail_sync = false;
        let batch = worker.take(&mut queue).unwrap();
        let finished = worker.run(batch, &mut journal, &mut disk, true);
        assert!(finished.failed()); assert!(worker.release(finished.deliver()));
        assert_eq!((disk.writes, disk.syncs), effects);
        let replies = replies.lock().unwrap();
        assert_eq!(replies.len(), 20);
        assert!(replies.iter().all(|(_, r)| r.is_none()));
    }
}
