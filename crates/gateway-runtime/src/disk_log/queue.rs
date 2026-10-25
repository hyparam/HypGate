//! Trusted mutex/condvar wrapper around the verified fixed-slot FIFO.
use super::{Job, Completion, DurableFrame, LogRecord};
use tokio::sync::{oneshot, Semaphore};
use gateway_core::frame_queue::FrameQueue;
use std::{io, sync::{Condvar, Mutex}};

/// `slots` holds one permit per free queue slot. A caller acquires a permit (in
/// arrival order) before reserving under the lock, forgets it once the slot is
/// charged, and the worker returns it when it pops the job. Closing the semaphore
/// wakes every waiting caller with an error instead of leaving it parked.
pub(super) struct Queue { state: Mutex<FrameQueue<Completion>>, ready: Condvar, slots: Semaphore }
// Only this module can mint a permit. Consuming it prevents a callback from
// constructing a second record through the same queue reservation.
struct EncodingPermit<'a> { state: &'a FrameQueue<Completion> }
impl EncodingPermit<'_> {
    fn encode(self, record: LogRecord<'_>) -> (Job, oneshot::Receiver<Option<DurableFrame>>) {
        let body = self.state.encode_reserved(super::record_header(&record), record.bytes)
            .expect("validated reserved audit record");
        let frame = super::seal_record(body);
        let (done, receive) = oneshot::channel();
        ((frame, Completion(done)), receive)
    }
}

struct WakeOnDrop<'a>(&'a Condvar);
impl Drop for WakeOnDrop<'_> { fn drop(&mut self) { self.0.notify_one(); } }
impl Queue {
    #[cfg(test)]
    pub(super) fn new(capacity: usize) -> Self { Self::with_payload_limit(capacity, super::MAX_RECORD_BYTES) }
    pub(super) fn with_payload_limit(capacity: usize, payload_limit: usize) -> Self {
        Self { state: Mutex::new(FrameQueue::with_payload_limit(capacity, payload_limit)), ready: Condvar::new(),
            slots: Semaphore::new(capacity) }
    }
    pub(super) fn is_open(&self) -> bool {
        self.state.lock().map(|state| !state.is_closed()).unwrap_or(false)
    }
    // The production interface admits a record, not arbitrary encoding code or
    // a core queue reference. Frame construction and receipt pairing stay here.
    // A full queue parks the caller until the worker frees a slot; the caller's
    // acknowledgment deadline bounds that wait. Nothing is allocated or encoded
    // while waiting, and a dropped waiter leaves no reservation behind.
    pub(super) async fn enqueue(&self, record: LogRecord<'_>) -> io::Result<oneshot::Receiver<Option<DurableFrame>>> {
        let permit = self.slots.acquire().await.map_err(|_| io::ErrorKind::BrokenPipe)?;
        let mut receive = None;
        self.push_with(|permit| {
            let (job, completion) = permit.encode(record);
            receive = Some(completion);
            job
        })?;
        // The slot is now charged in the verified queue; the worker's pop returns it.
        permit.forget();
        Ok(receive.expect("successful insertion constructed a receipt"))
    }
    fn push_with(&self, make: impl FnOnce(EncodingPermit<'_>) -> Job) -> io::Result<()> {
        // If construction panics, wake the worker after the mutex is poisoned
        // so it can observe failure instead of sleeping until shutdown.
        let _wake = WakeOnDrop(&self.ready);
        let mut state = self.state.lock().map_err(|_| io::ErrorKind::BrokenPipe)?;
        if state.is_closed() { return Err(io::ErrorKind::BrokenPipe.into()); }
        // Unreachable through `enqueue`, whose permit guarantees a free slot; the
        // verified reservation still decides, so a bookkeeping fault refuses
        // rather than overfills.
        if !state.reserve() { return Err(io::ErrorKind::WouldBlock.into()); }
        // Capacity is reserved before allocating the frame, under the same lock
        // as insertion and shutdown. A panic leaves the reservation charged
        // in poisoned state, which is never recovered for new admission.
        let job = make(EncodingPermit { state: &state });
        if state.finish_reserved(job).is_err() {
            state.close();
            self.slots.close();
            self.ready.notify_all();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
    pub(super) fn recv(&self, owner: &mut gateway_core::disk_worker::DiskWorker)
        -> Option<gateway_core::disk_worker::ActiveAppend<Completion>>
    {
        if !owner.can_take() { return None; }
        let job = {
            let mut state = self.state.lock().ok()?;
            loop {
                if let Some(job) = owner.take(&mut state) { break job; }
                // A nonempty queue refused by the owner means mismatched limits;
                // fail closed instead of waiting for an impossible dequeue.
                if state.is_closed() || state.len() != 0 { return None; }
                state = self.ready.wait(state).ok()?;
            }
        };
        // Every pop frees exactly one slot, after the lock is released.
        self.slots.add_permits(1);
        Some(job)
    }
    #[cfg(test)]
    fn recv_raw_for_test(&self) -> Option<Job> {
        let job = self.state.lock().ok()?.pop()?;
        self.slots.add_permits(1);
        Some(job)
    }
    pub(super) fn close(&self) {
        if let Ok(mut state) = self.state.lock() { state.close(); }
        // Waiting callers fail now rather than after their deadline.
        self.slots.close();
        self.ready.notify_all();
    }
    pub(super) fn abort(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.close();
            // Worker exit must close queued receipt senders even if a caller
            // still owns a DiskLog handle. Poison is never recovered to resume.
            while state.pop().is_some() {}
        }
        self.slots.close();
        self.ready.notify_all();
    }
    #[cfg(test)]
    pub(super) fn panic_during_encoding(&self) {
        let _ = self.push_with(|_| panic!("injected frame-construction panic"));
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize { self.state.lock().unwrap().len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn job(chunk: u64) -> Job {
        (super::super::encode_record(crate::transfer::LogRecord {
            tenant: 1, request: 1, chunk, kind: crate::transfer::RecordKind::Upload, bytes: b"record",
        }), Completion(tokio::sync::oneshot::channel().0))
    }
    #[tokio::test]
    async fn production_dequeue_requires_active_credit_and_delivery_returns_it() {
        use gateway_core::{disk_worker::DiskWorker, audit_journal::AuditJournal};
        let queue = Queue::with_payload_limit(1, 3);
        let mut owner = DiskWorker::new(3, 1);
        let mut journal = AuditJournal::new(0);
        // Disabled logging exercises ownership/delivery without a filesystem.
        struct Unused;
        impl super::super::DurableWrite for Unused { fn sync(&mut self) -> std::io::Result<()> { panic!("disabled sync"); } }
        impl std::io::Write for Unused {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { panic!("disabled write"); }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let mut storage = super::super::Storage(Unused);
        let record = |chunk| LogRecord { tenant: 1, request: 2, chunk,
            kind: super::super::RecordKind::Upload, bytes: b"abc" };
        let first = queue.enqueue(record(1)).await.unwrap();
        let active = queue.recv(&mut owner).unwrap();
        drop(first); // caller cancellation does not return active credit
        let second = queue.enqueue(record(2)).await.unwrap();
        assert!(queue.recv(&mut owner).is_none()); assert_eq!(queue.len(), 1);
        let finished = owner.run(active, &mut journal, &mut storage, false);
        assert!(queue.recv(&mut owner).is_none());
        assert!(owner.release(finished.deliver()));
        let active = queue.recv(&mut owner).unwrap();
        assert!(owner.release(owner.run(active, &mut journal, &mut storage, false).deliver()));
        assert!(second.await.unwrap().is_none());
        queue.close(); assert!(queue.recv(&mut owner).is_none());
    }
    #[tokio::test]
    async fn production_enqueue_preserves_pairing_waits_while_full_and_refuses_closed_before_encoding() {
        let queue = Queue::with_payload_limit(1, 3);
        let record = |bytes| LogRecord { tenant: 1, request: 2, chunk: 3,
            kind: super::super::RecordKind::Upload, bytes };
        let completion = queue.enqueue(record(b"abc")).await.unwrap();
        // A full queue parks the caller without constructing anything: encoding
        // this excessive payload would panic, so the wait must precede construction.
        assert!(tokio::time::timeout(Duration::from_millis(50), queue.enqueue(record(b"oversized"))).await.is_err());
        assert_eq!(queue.len(), 1);
        // A valid waiter is admitted as soon as the worker pops the first job, in order.
        let mut waiter = Box::pin(queue.enqueue(record(b"def")));
        assert!(tokio::time::timeout(Duration::from_millis(50), &mut waiter).await.is_err());
        let (frame, done) = queue.recv_raw_for_test().unwrap();
        assert_eq!(frame.bytes(), super::super::encode_record(record(b"abc")).bytes());
        assert!(done.send(None).is_ok());
        assert!(completion.await.unwrap().is_none());
        let second = waiter.await.unwrap();
        assert_eq!(queue.len(), 1);
        let (frame, done) = queue.recv_raw_for_test().unwrap();
        assert_eq!(frame.bytes(), super::super::encode_record(record(b"def")).bytes());
        assert!(done.send(None).is_ok());
        assert!(second.await.unwrap().is_none());
        queue.close();
        assert!(matches!(queue.enqueue(record(b"oversized")).await, Err(e) if e.kind() == io::ErrorKind::BrokenPipe));
        assert!(queue.recv_raw_for_test().is_none());
    }
    #[tokio::test]
    async fn closing_wakes_waiting_callers_without_constructing_their_jobs() {
        let queue = std::sync::Arc::new(Queue::with_payload_limit(1, 3));
        let record = |bytes| LogRecord { tenant: 1, request: 2, chunk: 3,
            kind: super::super::RecordKind::Upload, bytes };
        let _queued = queue.enqueue(record(b"abc")).await.unwrap();
        let waiting_queue = queue.clone();
        let waiter = tokio::spawn(async move {
            waiting_queue.enqueue(record(b"oversized")).await.map(|_| ()).unwrap_err().kind()
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiter.is_finished());
        queue.close();
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), waiter).await.unwrap().unwrap(), io::ErrorKind::BrokenPipe);
        // The admitted job survives closure; the waiter never reserved anything.
        assert_eq!(queue.len(), 1);
        assert!(queue.recv_raw_for_test().is_some()); assert!(queue.recv_raw_for_test().is_none());
    }
    #[tokio::test]
    async fn dropped_waiter_leaves_no_reservation_and_later_callers_proceed() {
        let queue = Queue::with_payload_limit(1, 3);
        let record = |bytes| LogRecord { tenant: 1, request: 2, chunk: 3,
            kind: super::super::RecordKind::Upload, bytes };
        let _queued = queue.enqueue(record(b"abc")).await.unwrap();
        drop(tokio::time::timeout(Duration::from_millis(20), queue.enqueue(record(b"def"))).await);
        assert_eq!(queue.len(), 1);
        assert!(queue.recv_raw_for_test().is_some());
        // The freed slot goes to the next caller, not to the canceled waiter.
        let later = tokio::time::timeout(Duration::from_secs(2), queue.enqueue(record(b"ghi"))).await.unwrap().unwrap();
        assert_eq!(queue.len(), 1);
        let (frame, done) = queue.recv_raw_for_test().unwrap();
        assert_eq!(frame.bytes(), super::super::encode_record(record(b"ghi")).bytes());
        assert!(done.send(None).is_ok()); assert!(later.await.unwrap().is_none());
    }
    #[test]
    fn full_and_closed_queues_never_construct_rejected_jobs_and_close_drains() {
        let queue = Queue::new(1);
        queue.push_with(|_| job(1)).unwrap();
        assert_eq!(queue.push_with(|_| panic!("full queue allocated a job")).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        queue.close();
        assert_eq!(queue.push_with(|_| panic!("closed queue allocated a job")).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(queue.recv_raw_for_test().is_some()); assert!(queue.recv_raw_for_test().is_none());
        assert!(!queue.is_open()); assert_eq!(queue.len(), 0);
    }
    #[tokio::test]
    async fn worker_exit_discards_queued_receipt_senders() {
        let queue = Queue::new(1);
        let (done, receive) = tokio::sync::oneshot::channel();
        queue.push_with(|_| { let (frame, _) = job(1); (frame, Completion(done)) }).unwrap();
        queue.abort();
        assert!(receive.await.is_err());
        assert!(queue.recv_raw_for_test().is_none()); assert_eq!(queue.len(), 0);
    }
    #[test]
    fn close_serializes_with_job_construction_and_preserves_admitted_job() {
        use std::{sync::{Arc, mpsc}, time::Duration};
        let queue = Arc::new(Queue::new(1));
        let (entered, inside) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let producer_queue = queue.clone();
        let producer = std::thread::spawn(move || producer_queue.push_with(|_| {
            entered.send(()).unwrap(); wait.recv().unwrap(); job(1)
        }));
        inside.recv_timeout(Duration::from_secs(2)).unwrap();
        let (closing, started) = mpsc::channel();
        let (closed, complete) = mpsc::channel();
        let closing_queue = queue.clone();
        let closer = std::thread::spawn(move || {
            closing.send(()).unwrap(); closing_queue.close(); closed.send(()).unwrap();
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(complete.recv_timeout(Duration::from_millis(20)), Err(mpsc::RecvTimeoutError::Timeout)));
        release.send(()).unwrap();
        producer.join().unwrap().unwrap();
        complete.recv_timeout(Duration::from_secs(2)).unwrap(); closer.join().unwrap();
        assert!(!queue.is_open()); assert_eq!(queue.len(), 1);
        assert_eq!(queue.push_with(|_| panic!("post-close construction")).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(queue.recv_raw_for_test().is_some()); assert!(queue.recv_raw_for_test().is_none());
    }
    #[test]
    fn construction_panic_permanently_closes_queue_admission() {
        let queue = Queue::new(1);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = queue.push_with(|_| panic!("injected encoding panic"));
        })).is_err());
        assert!(!queue.is_open());
        assert_eq!(queue.push_with(|_| panic!("poisoned queue constructed a job")).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(queue.recv_raw_for_test().is_none());
    }
}
