//! Trusted mutex/condvar wrapper around the verified fixed-slot FIFO.
use super::{Job, Completion, DurableFrame, LogRecord};
use tokio::sync::oneshot;
use gateway_core::frame_queue::FrameQueue;
use std::{io, sync::{Condvar, Mutex}};

pub(super) struct Queue { state: Mutex<FrameQueue<Completion>>, ready: Condvar }
// Only this module can mint a permit. Consuming it prevents a callback from
// constructing a second record through the same queue reservation.
struct EncodingPermit<'a> { state: &'a FrameQueue<Completion> }
impl EncodingPermit<'_> {
    fn encode(self, record: LogRecord<'_>) -> (Job, oneshot::Receiver<Option<DurableFrame>>) {
        let body = self.state.encode_reserved(super::record_header(&record), record.bytes)
            .expect("validated reserved audit record");
        let frame = super::seal_record(body);
        let (done, receive) = oneshot::channel();
        ((frame, done), receive)
    }
}

struct WakeOnDrop<'a>(&'a Condvar);
impl Drop for WakeOnDrop<'_> { fn drop(&mut self) { self.0.notify_one(); } }
impl Queue {
    #[cfg(test)]
    pub(super) fn new(capacity: usize) -> Self { Self::with_payload_limit(capacity, super::MAX_RECORD_BYTES) }
    pub(super) fn with_payload_limit(capacity: usize, payload_limit: usize) -> Self {
        Self { state: Mutex::new(FrameQueue::with_payload_limit(capacity, payload_limit)), ready: Condvar::new() }
    }
    pub(super) fn is_open(&self) -> bool {
        self.state.lock().map(|state| !state.is_closed()).unwrap_or(false)
    }
    // The production interface admits a record, not arbitrary encoding code or
    // a core queue reference. Frame construction and receipt pairing stay here.
    pub(super) fn enqueue(&self, record: LogRecord<'_>) -> io::Result<oneshot::Receiver<Option<DurableFrame>>> {
        let mut receive = None;
        self.push_with(|permit| {
            let (job, completion) = permit.encode(record);
            receive = Some(completion);
            job
        })?;
        Ok(receive.expect("successful insertion constructed a receipt"))
    }
    fn push_with(&self, make: impl FnOnce(EncodingPermit<'_>) -> Job) -> io::Result<()> {
        // If construction panics, wake the worker after the mutex is poisoned
        // so it can observe failure instead of sleeping until shutdown.
        let _wake = WakeOnDrop(&self.ready);
        let mut state = self.state.lock().map_err(|_| io::ErrorKind::BrokenPipe)?;
        if state.is_closed() { return Err(io::ErrorKind::BrokenPipe.into()); }
        if !state.reserve() { return Err(io::ErrorKind::WouldBlock.into()); }
        // Capacity is reserved before allocating the frame, under the same lock
        // as insertion and shutdown. A panic leaves the reservation charged
        // in poisoned state, which is never recovered for new admission.
        let job = make(EncodingPermit { state: &state });
        if state.finish_reserved(job).is_err() {
            state.close();
            self.ready.notify_all();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
    pub(super) fn recv(&self) -> Option<Job> {
        let mut state = self.state.lock().ok()?;
        loop {
            if let Some(job) = state.pop() { return Some(job); }
            if state.is_closed() { return None; }
            state = self.ready.wait(state).ok()?;
        }
    }
    pub(super) fn close(&self) {
        if let Ok(mut state) = self.state.lock() { state.close(); }
        self.ready.notify_all();
    }
    pub(super) fn abort(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.close();
            // Worker exit must close queued receipt senders even if a caller
            // still owns a DiskLog handle. Poison is never recovered to resume.
            while state.pop().is_some() {}
        }
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
    fn job(chunk: u64) -> Job {
        (super::super::encode_record(crate::transfer::LogRecord {
            tenant: 1, request: 1, chunk, direction: crate::transfer::Direction::Upload, bytes: b"record",
        }), tokio::sync::oneshot::channel().0)
    }
    #[tokio::test]
    async fn production_enqueue_preserves_pairing_and_refuses_full_or_closed_before_encoding() {
        let queue = Queue::with_payload_limit(1, 3);
        let record = |bytes| LogRecord { tenant: 1, request: 2, chunk: 3,
            direction: super::super::Direction::Upload, bytes };
        let completion = queue.enqueue(record(b"abc")).unwrap();
        // If invoked, encoding this excessive payload would fail. Full/closed
        // rejection must precede construction through the production interface.
        assert!(matches!(queue.enqueue(record(b"oversized")), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
        let (frame, done) = queue.recv().unwrap();
        assert_eq!(frame.bytes(), super::super::encode_record(record(b"abc")).bytes());
        assert!(done.send(None).is_ok());
        assert!(completion.await.unwrap().is_none());
        queue.close();
        assert!(matches!(queue.enqueue(record(b"oversized")), Err(e) if e.kind() == io::ErrorKind::BrokenPipe));
        assert!(queue.recv().is_none());
    }
    #[test]
    fn full_and_closed_queues_never_construct_rejected_jobs_and_close_drains() {
        let queue = Queue::new(1);
        queue.push_with(|_| job(1)).unwrap();
        assert_eq!(queue.push_with(|_| panic!("full queue allocated a job")).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        queue.close();
        assert_eq!(queue.push_with(|_| panic!("closed queue allocated a job")).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(queue.recv().is_some()); assert!(queue.recv().is_none());
        assert!(!queue.is_open()); assert_eq!(queue.len(), 0);
    }
    #[tokio::test]
    async fn worker_exit_discards_queued_receipt_senders() {
        let queue = Queue::new(1);
        let (done, receive) = tokio::sync::oneshot::channel();
        queue.push_with(|_| { let (frame, _) = job(1); (frame, done) }).unwrap();
        queue.abort();
        assert!(receive.await.is_err());
        assert!(queue.recv().is_none()); assert_eq!(queue.len(), 0);
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
        assert!(queue.recv().is_some()); assert!(queue.recv().is_none());
    }
    #[test]
    fn construction_panic_permanently_closes_queue_admission() {
        let queue = Queue::new(1);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = queue.push_with(|_| panic!("injected encoding panic"));
        })).is_err());
        assert!(!queue.is_open());
        assert_eq!(queue.push_with(|_| panic!("poisoned queue constructed a job")).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(queue.recv().is_none());
    }
}
