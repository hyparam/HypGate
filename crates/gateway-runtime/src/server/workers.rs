//! Worker credits use verified registry transitions. Mutex serialization,
//! private key ownership, and field drop order remain trusted Rust. A worker
//! is the exchange a connection thread runs; its credit returns when the
//! thread's exchange and every stream it issued are gone.
use gateway_core::{task_credit::TaskCredit, http_worker::WorkerRegistry};
use std::{sync::{Arc, Condvar, Mutex}, time::Instant};
use super::leased::TaskLease;

pub(super) struct WorkerSlots { registry: Arc<Mutex<WorkerRegistry>>, drained: Condvar }

// Unregister and release under one mutex, then wake a drain observer.
pub(super) struct WorkerLease { slots: Arc<WorkerSlots>, credit: Option<TaskCredit>, http: crate::http_body::WorkerHttp }

impl TaskLease for WorkerLease {
    fn credit(&mut self) -> Option<&mut TaskCredit> { self.credit.as_mut() }
}

impl WorkerLease {
    pub(super) fn http(&self) -> crate::http_body::WorkerHttp { self.http.clone() }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        // Never recover poisoned state just to return credit.
        if let Ok(mut registry) = self.slots.registry.lock() {
            if let Some(credit) = self.credit.take() { registry.release_task(credit); }
        }
        self.slots.drained.notify_all();
    }
}

impl WorkerSlots {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        // Worker keys never create streams or allocate payload buffers.
        Arc::new(Self { registry: Arc::new(Mutex::new(WorkerRegistry::new(limit))), drained: Condvar::new() })
    }
    pub(super) fn healthy(&self) -> bool {
        self.registry.lock().is_ok_and(|registry| !registry.is_closed())
    }
    pub(super) fn close(&self) {
        if let Ok(mut registry) = self.registry.lock() { registry.close(); }
        self.drained.notify_all();
    }
    /// Wait until no worker holds credit, or `until` passes; true when drained.
    pub(super) fn wait_drained(&self, until: Instant) -> bool {
        let Ok(mut registry) = self.registry.lock() else { return false; };
        loop {
            if registry.usage().0 == 0 { return true; }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() { return false; }
            let Ok((guard, _)) = self.drained.wait_timeout(registry, left) else { return false; };
            registry = guard;
        }
    }
    pub(super) fn acquire(self: &Arc<Self>) -> Option<WorkerLease> {
        let mut registry = self.registry.lock().ok()?;
        let (credit, issuer) = registry.acquire()?;
        let http = crate::http_body::WorkerHttp::new(self.registry.clone(), issuer);
        drop(registry);
        Some(WorkerLease { slots: self.clone(), credit: Some(credit), http })
    }
    #[cfg(test)]
    pub(super) fn usage(&self) -> Option<(usize, usize)> {
        self.registry.lock().ok().map(|registry| registry.usage())
    }
    #[cfg(test)]
    pub(super) fn poison_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.registry.lock().unwrap();
            panic!("injected worker registry panic");
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, sync::atomic::{AtomicBool, Ordering}, time::Duration};

    #[test]
    fn captures_drop_before_worker_credit_returns() {
        struct Cleanup { slots: Arc<WorkerSlots>, dropped: Arc<AtomicBool> }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                assert_eq!(self.slots.usage(), Some((1, 1)));
                assert!(self.slots.acquire().is_none());
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
        let slots = WorkerSlots::new(1);
        let dropped = Arc::new(AtomicBool::new(false));
        let cleanup = Cleanup { slots: slots.clone(), dropped: dropped.clone() };
        let lease = slots.acquire().unwrap();
        super::super::leased::run(lease, move || drop(cleanup));
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(slots.usage(), Some((0, 1)));
        assert!(slots.acquire().is_some());
    }

    #[test]
    fn a_live_stream_keeps_the_credit_after_the_work_returns() {
        // A role that escapes the work (here through a channel) keeps the
        // worker's slot occupied until the stream is gone.
        let slots = WorkerSlots::new(1);
        let lease = slots.acquire().unwrap();
        let http = lease.http();
        let (send, receive) = std::sync::mpsc::channel();
        super::super::leased::run(lease, move || { send.send(http.input(&b"data"[..]).unwrap()).unwrap(); });
        let mut reader = receive.recv().unwrap();
        assert_eq!(slots.usage(), Some((1, 1)));
        assert!(slots.acquire().is_none());
        let mut byte = [0];
        reader.read_exact(&mut byte).unwrap();
        drop(reader);
        assert_eq!(slots.usage(), Some((1, 1)), "a stranded role is never silently recovered");
        assert!(slots.acquire().is_none());
    }

    #[test]
    fn a_panicking_exchange_strands_its_credit_and_closes_admission() {
        let slots = WorkerSlots::new(1);
        let lease = slots.acquire().unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::super::leased::run(lease, || panic!("injected exchange panic"));
        }));
        assert!(outcome.is_err());
        assert_eq!(slots.usage(), Some((1, 1)));
        assert!(!slots.healthy());
        assert!(slots.acquire().is_none());
    }

    #[test]
    fn concurrent_workers_hold_credit_until_their_threads_finish() {
        let slots = WorkerSlots::new(8);
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let blocked = Arc::new(Mutex::new(blocked));
        let (started, starts) = std::sync::mpsc::channel();
        let threads: Vec<_> = (0..8).map(|_| {
            let lease = slots.acquire().unwrap();
            let started = started.clone(); let blocked = blocked.clone();
            std::thread::spawn(move || super::super::leased::run(lease, move || {
                started.send(()).unwrap();
                let _ = blocked.lock().unwrap().recv();
            }))
        }).collect();
        for _ in 0..8 { starts.recv_timeout(Duration::from_secs(2)).unwrap(); }
        assert_eq!(slots.usage(), Some((8, 8)));
        for _ in 0..32 { assert!(slots.acquire().is_none()); }
        assert!(!slots.wait_drained(Instant::now() + Duration::from_millis(20)));
        drop(release);
        for thread in threads { thread.join().unwrap(); }
        assert!(slots.wait_drained(Instant::now() + Duration::from_secs(2)));
        assert_eq!(slots.usage(), Some((0, 8)));
        let leases: Vec<_> = (0..8).map(|_| slots.acquire().unwrap()).collect();
        assert!(slots.acquire().is_none());
        drop(leases);
        assert_eq!(slots.usage(), Some((0, 8)));
    }

    #[test]
    fn closing_refuses_new_workers_and_reports_unhealthy() {
        let slots = WorkerSlots::new(2);
        let lease = slots.acquire().unwrap();
        slots.close();
        assert!(!slots.healthy());
        assert!(slots.acquire().is_none());
        drop(lease);
        assert!(slots.wait_drained(Instant::now()));
    }
}
