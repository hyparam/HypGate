//! Worker credits use verified registry transitions. Mutex serialization, private
//! key ownership, field drop order, and task cancellation remain trusted Rust.
use gateway_core::resource::{RequestKey, ResourceAdmission};
use std::{future::Future, pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll}};
use tokio_util::task::{TaskTracker, task_tracker::TaskTrackerToken};

pub(super) struct WorkerSlots { registry: Mutex<ResourceAdmission> }

// Tracking must disappear before another worker can reuse this credit.
pub(super) struct WorkerLease { _tracked: TaskTrackerToken, _credit: WorkerCredit }
struct WorkerCredit { slots: Arc<WorkerSlots>, key: RequestKey }

// Unlike a lease local inside an async block, this field order also covers
// captured values in a never-polled or partly completed future.
struct WorkerTask<F> { work: Pin<Box<F>>, _lease: WorkerLease }
impl<F: Future<Output = ()>> Future for WorkerTask<F> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.get_mut().work.as_mut().poll(cx)
    }
}
impl WorkerLease {
    pub(super) fn spawn<F: Future<Output = ()> + Send + 'static>(self, work: F) -> tokio::task::JoinHandle<()> {
        tokio::spawn(WorkerTask { work: Box::pin(work), _lease: self })
    }
}

impl Drop for WorkerCredit {
    fn drop(&mut self) {
        // Never recover poisoned state just to return credit.
        if let Ok(mut registry) = self.slots.registry.lock() {
            let released = registry.release(&self.key);
            debug_assert!(released, "worker credit must own its registry slot");
        }
    }
}

impl WorkerSlots {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        // Worker keys never create streams or allocate payload buffers.
        Arc::new(Self { registry: Mutex::new(ResourceAdmission::new(limit, 0)) })
    }
    pub(super) fn healthy(&self) -> bool { !self.registry.is_poisoned() }
    pub(super) fn acquire(self: &Arc<Self>, tracker: &TaskTracker) -> Option<WorkerLease> {
        let key = self.registry.lock().ok()?.acquire()?;
        let credit = WorkerCredit { slots: self.clone(), key };
        Some(WorkerLease { _tracked: tracker.token(), _credit: credit })
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

    #[tokio::test]
    async fn concurrent_workers_hold_credit_until_task_cleanup() {
        let slots = WorkerSlots::new(8);
        let tracker = TaskTracker::new();
        let mut tasks = Vec::new();
        let (started, mut starts) = tokio::sync::mpsc::channel(8);
        for _ in 0..8 {
            let lease = slots.acquire(&tracker).unwrap();
            let started = started.clone();
            let worker = lease.spawn(async move {
                started.send(()).await.unwrap();
                std::future::pending::<()>().await;
            });
            tasks.push(worker);
        }
        for _ in 0..8 { starts.recv().await.unwrap(); }
        assert_eq!(slots.usage(), Some((8, 8)));
        assert_eq!(tracker.len(), 8);
        for _ in 0..32 { assert!(slots.acquire(&tracker).is_none()); }
        for task in &tasks { task.abort(); }
        for task in tasks { assert!(task.await.unwrap_err().is_cancelled()); }
        assert!(tracker.is_empty());
        assert_eq!(slots.usage(), Some((0, 8)));
        let leases: Vec<_> = (0..8).map(|_| slots.acquire(&tracker).unwrap()).collect();
        assert!(slots.acquire(&tracker).is_none());
        drop(leases);
        assert!(tracker.is_empty());
        assert_eq!(slots.usage(), Some((0, 8)));
    }

    #[tokio::test]
    async fn task_captures_drop_before_worker_credit_on_every_exit() {
        struct Cleanup { slots: Arc<WorkerSlots>, tracker: TaskTracker, dropped: Arc<std::sync::atomic::AtomicBool> }
        impl Drop for Cleanup {
            fn drop(&mut self) {
                assert_eq!(self.slots.usage(), Some((1, 1)));
                assert_eq!(self.tracker.len(), 1);
                assert!(self.slots.acquire(&self.tracker).is_none());
                self.dropped.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        for exit in 0..4 {
            let slots = WorkerSlots::new(1);
            let tracker = TaskTracker::new();
            let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let cleanup = Cleanup { slots: slots.clone(), tracker: tracker.clone(), dropped: dropped.clone() };
            let (started, running) = tokio::sync::oneshot::channel();
            let task = slots.acquire(&tracker).unwrap().spawn(async move {
                // Leave cleanup in the capture until after the suspension point.
                let _ = started.send(());
                if exit == 3 { panic!("injected worker panic"); }
                if exit != 0 { std::future::pending::<()>().await; }
                drop(cleanup);
            });
            if exit == 2 { running.await.unwrap(); }
            if exit == 1 || exit == 2 { task.abort(); }
            let result = task.await;
            if exit == 0 { result.unwrap(); }
            else if exit == 3 { assert!(result.unwrap_err().is_panic()); }
            else { assert!(result.unwrap_err().is_cancelled()); }
            assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
            assert!(tracker.is_empty());
            assert_eq!(slots.usage(), Some((0, 1)));
        }
    }
}
