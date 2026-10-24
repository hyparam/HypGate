//! Trusted mutex/condvar wrapper around the verified fixed-slot FIFO.
use super::{Job, Completion};
use gateway_core::frame_queue::FrameQueue;
use std::{io, sync::{Condvar, Mutex}};

pub(super) struct Queue { state: Mutex<FrameQueue<Completion>>, ready: Condvar }
struct WakeOnDrop<'a>(&'a Condvar);
impl Drop for WakeOnDrop<'_> { fn drop(&mut self) { self.0.notify_one(); } }
impl Queue {
    pub(super) fn new(capacity: usize) -> Self {
        Self { state: Mutex::new(FrameQueue::new(capacity)), ready: Condvar::new() }
    }
    pub(super) fn is_open(&self) -> bool {
        self.state.lock().map(|state| !state.is_closed()).unwrap_or(false)
    }
    pub(super) fn push_with(&self, make: impl FnOnce() -> Job) -> io::Result<()> {
        // If construction panics, wake the worker after the mutex is poisoned
        // so it can observe failure instead of sleeping until shutdown.
        let _wake = WakeOnDrop(&self.ready);
        let mut state = self.state.lock().map_err(|_| io::ErrorKind::BrokenPipe)?;
        if state.is_closed() { return Err(io::ErrorKind::BrokenPipe.into()); }
        if state.is_full() { return Err(io::ErrorKind::WouldBlock.into()); }
        // Capacity is checked before allocating the frame, under the same lock
        // as insertion and shutdown. No reservation can escape this section.
        if state.push(make()).is_err() {
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
    #[test]
    fn full_and_closed_queues_never_construct_rejected_jobs_and_close_drains() {
        let queue = Queue::new(1);
        queue.push_with(|| job(1)).unwrap();
        assert_eq!(queue.push_with(|| panic!("full queue allocated a job")).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        queue.close();
        assert_eq!(queue.push_with(|| panic!("closed queue allocated a job")).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(queue.recv().is_some()); assert!(queue.recv().is_none());
        assert!(!queue.is_open()); assert_eq!(queue.len(), 0);
    }
    #[tokio::test]
    async fn worker_exit_discards_queued_receipt_senders() {
        let queue = Queue::new(1);
        let (done, receive) = tokio::sync::oneshot::channel();
        queue.push_with(|| { let (frame, _) = job(1); (frame, done) }).unwrap();
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
        let producer = std::thread::spawn(move || producer_queue.push_with(|| {
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
        assert_eq!(queue.push_with(|| panic!("post-close construction")).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(queue.recv().is_some()); assert!(queue.recv().is_none());
    }
    #[test]
    fn construction_panic_permanently_closes_queue_admission() {
        let queue = Queue::new(1);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = queue.push_with(|| panic!("injected encoding panic"));
        })).is_err());
        assert!(!queue.is_open());
        assert_eq!(queue.push_with(|| panic!("poisoned queue constructed a job")).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert!(queue.recv().is_none());
    }
}
