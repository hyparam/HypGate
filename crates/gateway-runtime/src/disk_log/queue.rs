//! Trusted mutex/condvar wrapper around the verified fixed-slot FIFO.
use super::Job;
use gateway_core::fixed_queue::FixedQueue;
use std::{io, sync::{Condvar, Mutex}};

struct State { entries: FixedQueue<Job>, closed: bool }
pub(super) struct Queue { state: Mutex<State>, ready: Condvar }
struct WakeOnDrop<'a>(&'a Condvar);
impl Drop for WakeOnDrop<'_> { fn drop(&mut self) { self.0.notify_one(); } }
impl Queue {
    pub(super) fn new(capacity: usize) -> Self {
        Self { state: Mutex::new(State { entries: FixedQueue::new(capacity), closed: false }), ready: Condvar::new() }
    }
    pub(super) fn is_open(&self) -> bool {
        self.state.lock().map(|state| !state.closed).unwrap_or(false)
    }
    pub(super) fn push_with(&self, make: impl FnOnce() -> Job) -> io::Result<()> {
        // If construction panics, wake the worker after the mutex is poisoned
        // so it can observe failure instead of sleeping until shutdown.
        let _wake = WakeOnDrop(&self.ready);
        let mut state = self.state.lock().map_err(|_| io::ErrorKind::BrokenPipe)?;
        if state.closed { return Err(io::ErrorKind::BrokenPipe.into()); }
        if state.entries.is_full() { return Err(io::ErrorKind::WouldBlock.into()); }
        // Capacity is checked before allocating the frame, under the same lock
        // as insertion and shutdown. No reservation can escape this section.
        if state.entries.push(make()).is_err() {
            state.closed = true;
            self.ready.notify_all();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        Ok(())
    }
    pub(super) fn recv(&self) -> Option<Job> {
        let mut state = self.state.lock().ok()?;
        loop {
            if let Some(job) = state.entries.pop() { return Some(job); }
            if state.closed { return None; }
            state = self.ready.wait(state).ok()?;
        }
    }
    pub(super) fn close(&self) {
        if let Ok(mut state) = self.state.lock() { state.closed = true; }
        self.ready.notify_all();
    }
    pub(super) fn abort(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            // Worker exit must close queued receipt senders even if a caller
            // still owns a DiskLog handle. Poison is never recovered to resume.
            while state.entries.pop().is_some() {}
        }
        self.ready.notify_all();
    }
    #[cfg(test)]
    pub(super) fn len(&self) -> usize { self.state.lock().unwrap().entries.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn job(chunk: u64) -> Job {
        Job { frame: super::super::encode_record(crate::transfer::LogRecord {
            tenant: 1, request: 1, chunk, direction: crate::transfer::Direction::Upload, bytes: b"record",
        }), done: tokio::sync::oneshot::channel().0 }
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
        queue.push_with(|| { let mut value = job(1); value.done = done; value }).unwrap();
        queue.abort();
        assert!(receive.await.is_err());
        assert!(queue.recv().is_none()); assert_eq!(queue.len(), 0);
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
