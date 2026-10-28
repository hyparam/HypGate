//! Trusted mutex/condvar wrapper around the verified fixed-slot FIFO.
use super::{Job, Completion, AuditReceipt, LogRecord};
use gateway_core::frame_queue::FrameQueue;
use std::{io, sync::{Condvar, Mutex, MutexGuard, mpsc}, time::Instant};

/// `space` is signalled whenever the worker frees a slot; a caller that finds
/// the queue full waits on it under the state lock until its deadline.
/// Closing wakes every waiting caller with an error instead of leaving it parked.
pub(super) struct Queue { state: Mutex<FrameQueue<Completion>>, ready: Condvar, space: Condvar }
// Only this module can mint a permit. Consuming it prevents a callback from
// constructing a second record through the same queue reservation.
struct EncodingPermit<'a> { state: &'a FrameQueue<Completion> }
impl EncodingPermit<'_> {
    /// `None` when the verified encoder refuses the record (over the payload
    /// limit or an invalid header); the caller then gives the reservation back.
    fn encode(self, record: LogRecord<'_>) -> Option<(Job, mpsc::Receiver<Option<AuditReceipt>>)> {
        let body = self.state.encode_reserved(super::record_header(&record), record.bytes)?;
        let frame = super::seal_record(body);
        let (done, receive) = mpsc::channel();
        Some(((frame, Completion(done)), receive))
    }
}

struct WakeOnDrop<'a>(&'a Condvar);
impl Drop for WakeOnDrop<'_> { fn drop(&mut self) { self.0.notify_one(); } }
impl Queue {
    #[cfg(test)]
    pub(super) fn new(capacity: usize) -> Self { Self::with_payload_limit(capacity, super::MAX_RECORD_BYTES) }
    pub(super) fn with_payload_limit(capacity: usize, payload_limit: usize) -> Self {
        Self { state: Mutex::new(FrameQueue::with_payload_limit(capacity, payload_limit)), ready: Condvar::new(), space: Condvar::new() }
    }
    pub(super) fn is_open(&self) -> bool {
        self.state.lock().map(|state| !state.is_closed()).unwrap_or(false)
    }
    // The production interface admits a record, not arbitrary encoding code or
    // a core queue reference. Frame construction and receipt pairing stay here.
    // A full queue parks the caller until the worker frees a slot or the
    // deadline passes. Nothing is allocated or encoded while waiting, and a
    // caller that gives up leaves no reservation behind.
    pub(super) fn enqueue(&self, record: LogRecord<'_>, deadline: Instant) -> io::Result<mpsc::Receiver<Option<AuditReceipt>>> {
        // If construction panics, wake the worker after the mutex is poisoned
        // so it can observe failure instead of sleeping until shutdown.
        let _wake = WakeOnDrop(&self.ready);
        let mut state = self.state.lock().map_err(|_| io::ErrorKind::BrokenPipe)?;
        loop {
            if state.is_closed() { return Err(io::ErrorKind::BrokenPipe.into()); }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() { return Err(io::ErrorKind::TimedOut.into()); }
            if !state.is_full() { break; }
            let (guard, _) = self.space.wait_timeout(state, left).map_err(|_| io::ErrorKind::BrokenPipe)?;
            state = guard;
        }
        let mut receive = None;
        Self::insert(&mut state, &self.space, &self.ready, |permit| {
            let (job, completion) = permit.encode(record)?;
            receive = Some(completion);
            Some(job)
        })?;
        receive.ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
    }
    /// One attempt without waiting: `WouldBlock` when full.
    #[cfg(test)]
    fn push_with(&self, make: impl FnOnce(EncodingPermit<'_>) -> Option<Job>) -> io::Result<()> {
        let _wake = WakeOnDrop(&self.ready);
        let mut state = self.state.lock().map_err(|_| io::ErrorKind::BrokenPipe)?;
        if state.is_closed() { return Err(io::ErrorKind::BrokenPipe.into()); }
        Self::insert(&mut state, &self.space, &self.ready, make)
    }
    fn insert(state: &mut MutexGuard<'_, FrameQueue<Completion>>, space: &Condvar, ready: &Condvar,
        make: impl FnOnce(EncodingPermit<'_>) -> Option<Job>) -> io::Result<()>
    {
        // The verified reservation decides; a bookkeeping fault refuses rather than overfills.
        if !state.reserve() { return Err(io::ErrorKind::WouldBlock.into()); }
        // Capacity is reserved before allocating the frame, under the same lock
        // as insertion and shutdown. A panic leaves the reservation charged
        // in poisoned state, which is never recovered for new admission.
        // A refused record gives its reservation back and is reported, not queued.
        let Some(job) = make(EncodingPermit { state }) else {
            state.cancel_reserved();
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if state.finish_reserved(job).is_err() {
            state.close();
            space.notify_all();
            ready.notify_all();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
    pub(super) fn recv(&self, owner: &mut gateway_core::batch_worker::BatchWorker)
        -> Option<gateway_core::batch_worker::ActiveBatch<Completion>>
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
        // A bounded dequeue frees several slots; wake their waiting producers.
        self.space.notify_all();
        Some(job)
    }
    #[cfg(test)]
    fn recv_raw_for_test(&self) -> Option<Job> {
        let job = self.state.lock().ok()?.pop()?;
        self.space.notify_one();
        Some(job)
    }
    pub(super) fn close(&self) {
        if let Ok(mut state) = self.state.lock() { state.close(); }
        // Waiting callers fail now rather than after their deadline.
        self.space.notify_all();
        self.ready.notify_all();
    }
    pub(super) fn abort(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.close();
            // Worker exit must close queued receipt senders even if a caller
            // still owns a DiskLog handle. Poison is never recovered to resume.
            while state.pop().is_some() {}
        }
        self.space.notify_all();
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
        }), Completion(mpsc::channel().0))
    }
    fn soon() -> Instant { Instant::now() + Duration::from_millis(50) }
    #[test]
    fn production_dequeue_requires_active_credit_and_delivery_returns_it() {
        use gateway_core::{batch_worker::BatchWorker, audit_receipt::BatchJournal as AuditJournal};
        let queue = Queue::with_payload_limit(1, 3);
        let mut owner = BatchWorker::new(3, 1);
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
        let first = queue.enqueue(record(1), soon()).unwrap();
        let active = queue.recv(&mut owner).unwrap();
        drop(first); // caller cancellation does not return active credit
        let second = queue.enqueue(record(2), soon()).unwrap();
        assert!(queue.recv(&mut owner).is_none()); assert_eq!(queue.len(), 1);
        let finished = owner.run(active, &mut journal, &mut storage, false);
        assert!(queue.recv(&mut owner).is_none());
        assert!(owner.release(finished.deliver()));
        let active = queue.recv(&mut owner).unwrap();
        assert!(owner.release(owner.run(active, &mut journal, &mut storage, false).deliver()));
        assert!(second.recv_timeout(Duration::from_secs(2)).unwrap().is_none());
        queue.close(); assert!(queue.recv(&mut owner).is_none());
    }
    #[test]
    fn production_enqueue_preserves_pairing_waits_while_full_and_refuses_closed_before_encoding() {
        let queue = std::sync::Arc::new(Queue::with_payload_limit(1, 3));
        let record = |bytes| LogRecord { tenant: 1, request: 2, chunk: 3,
            kind: super::super::RecordKind::Upload, bytes };
        let completion = queue.enqueue(record(b"abc"), soon()).unwrap();
        // A full queue parks the caller without constructing anything: encoding
        // this excessive payload would panic, so the wait must precede construction.
        assert_eq!(queue.enqueue(record(b"oversized"), soon()).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(queue.len(), 1);
        // A valid waiter is admitted as soon as the worker pops the first job.
        let waiting = queue.clone();
        let waiter = std::thread::spawn(move || waiting.enqueue(record(b"def"), Instant::now() + Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(30));
        assert!(!waiter.is_finished());
        let (frame, done) = queue.recv_raw_for_test().unwrap();
        assert_eq!(frame.bytes(), super::super::encode_record(record(b"abc")).bytes());
        assert!(done.send(None).is_ok());
        assert!(completion.recv_timeout(Duration::from_secs(2)).unwrap().is_none());
        let second = waiter.join().unwrap().unwrap();
        assert_eq!(queue.len(), 1);
        let (frame, done) = queue.recv_raw_for_test().unwrap();
        assert_eq!(frame.bytes(), super::super::encode_record(record(b"def")).bytes());
        assert!(done.send(None).is_ok());
        assert!(second.recv_timeout(Duration::from_secs(2)).unwrap().is_none());
        queue.close();
        assert!(matches!(queue.enqueue(record(b"oversized"), soon()), Err(e) if e.kind() == io::ErrorKind::BrokenPipe));
        assert!(queue.recv_raw_for_test().is_none());
    }
    #[test]
    fn closing_wakes_waiting_callers_without_constructing_their_jobs() {
        let queue = std::sync::Arc::new(Queue::with_payload_limit(1, 3));
        let record = |bytes| LogRecord { tenant: 1, request: 2, chunk: 3,
            kind: super::super::RecordKind::Upload, bytes };
        let _queued = queue.enqueue(record(b"abc"), soon()).unwrap();
        let waiting_queue = queue.clone();
        let waiter = std::thread::spawn(move || {
            waiting_queue.enqueue(record(b"oversized"), Instant::now() + Duration::from_secs(10)).map(|_| ()).unwrap_err().kind()
        });
        std::thread::sleep(Duration::from_millis(20));
        assert!(!waiter.is_finished());
        queue.close();
        assert_eq!(waiter.join().unwrap(), io::ErrorKind::BrokenPipe);
        // The admitted job survives closure; the waiter never reserved anything.
        assert_eq!(queue.len(), 1);
        assert!(queue.recv_raw_for_test().is_some()); assert!(queue.recv_raw_for_test().is_none());
    }
    #[test]
    fn expired_waiter_leaves_no_reservation_and_later_callers_proceed() {
        let queue = Queue::with_payload_limit(1, 3);
        let record = |bytes| LogRecord { tenant: 1, request: 2, chunk: 3,
            kind: super::super::RecordKind::Upload, bytes };
        let _queued = queue.enqueue(record(b"abc"), soon()).unwrap();
        assert_eq!(queue.enqueue(record(b"def"), Instant::now() + Duration::from_millis(20)).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(queue.len(), 1);
        assert!(queue.recv_raw_for_test().is_some());
        // The freed slot goes to the next caller, not to the expired waiter.
        let later = queue.enqueue(record(b"ghi"), Instant::now() + Duration::from_secs(2)).unwrap();
        assert_eq!(queue.len(), 1);
        let (frame, done) = queue.recv_raw_for_test().unwrap();
        assert_eq!(frame.bytes(), super::super::encode_record(record(b"ghi")).bytes());
        assert!(done.send(None).is_ok()); assert!(later.recv_timeout(Duration::from_secs(2)).unwrap().is_none());
    }
    #[test]
    fn full_and_closed_queues_never_construct_rejected_jobs_and_close_drains() {
        let queue = Queue::new(1);
        queue.push_with(|_| Some(job(1))).unwrap();
        assert_eq!(queue.push_with(|_| panic!("full queue allocated a job")).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        queue.close();
        assert_eq!(queue.push_with(|_| panic!("closed queue allocated a job")).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(queue.recv_raw_for_test().is_some()); assert!(queue.recv_raw_for_test().is_none());
        assert!(!queue.is_open()); assert_eq!(queue.len(), 0);
    }
    #[test]
    fn worker_exit_discards_queued_receipt_senders() {
        let queue = Queue::new(1);
        let (done, receive) = mpsc::channel();
        queue.push_with(|_| { let (frame, _) = job(1); Some((frame, Completion(done))) }).unwrap();
        queue.abort();
        assert!(receive.recv().is_err());
        assert!(queue.recv_raw_for_test().is_none()); assert_eq!(queue.len(), 0);
    }
    #[test]
    fn close_serializes_with_job_construction_and_preserves_admitted_job() {
        use std::sync::{Arc, mpsc};
        let queue = Arc::new(Queue::new(1));
        let (entered, inside) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let producer_queue = queue.clone();
        let producer = std::thread::spawn(move || producer_queue.push_with(|_| {
            entered.send(()).unwrap(); wait.recv().unwrap(); Some(job(1))
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
