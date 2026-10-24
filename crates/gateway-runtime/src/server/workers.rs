//! Worker credits use verified registry transitions. Mutex serialization, private
//! key ownership, field drop order, and task cancellation remain trusted Rust.
use gateway_core::{task_credit::TaskCredit, http_worker::WorkerRegistry};
use std::{future::Future, sync::{Arc, Mutex}};
use super::leased_task::{LeasedTask, TaskLease};
use tokio_util::task::{TaskTracker, task_tracker::TaskTrackerToken};

pub(super) struct WorkerSlots { registry: Arc<Mutex<WorkerRegistry>> }

// Unregister and release under one mutex: replacements cannot overlap tracking,
// and a drain observer can synchronize with completion of credit destruction.
pub(super) struct WorkerLease {
    tracked: Option<TaskTrackerToken>, slots: Arc<WorkerSlots>, credit: Option<TaskCredit>, http: crate::http_body::WorkerHttp,
}

impl TaskLease for WorkerLease {
    fn credit(&mut self) -> &mut TaskCredit { self.credit.as_mut().expect("live worker lease") }
}

impl WorkerLease {
    pub(super) fn http(&self) -> crate::http_body::WorkerHttp { self.http.clone() }
    pub(super) fn spawn<F: Future<Output = ()> + Send + 'static>(self, work: F) -> tokio::task::JoinHandle<()> {
        tokio::spawn(LeasedTask::new(work, self))
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        // Never recover poisoned state just to return credit.
        if let Ok(mut registry) = self.slots.registry.lock() {
            self.tracked.take();
            let credit = self.credit.take().expect("live worker lease");
            registry.release_task(credit);
        }
    }
}

impl WorkerSlots {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        // Worker keys never create streams or allocate payload buffers.
        Arc::new(Self { registry: Arc::new(Mutex::new(WorkerRegistry::new(limit))) })
    }
    pub(super) fn healthy(&self) -> bool {
        self.registry.lock().is_ok_and(|registry| !registry.is_closed())
    }
    pub(super) fn close(&self, tracker: &TaskTracker) {
        // The same mutex covers admission through tracker registration. Once
        // closed, a zero tracker cannot race with a late successful acquire.
        if let Ok(mut registry) = self.registry.lock() { registry.close(); }
        tracker.close();
    }
    pub(super) async fn wait_drained(&self, tracker: &TaskTracker) {
        tracker.wait().await;
        // A notified waiter may run before the notifying destructor returns.
        // Synchronize with the registry release protected by that same lock.
        let _guard = self.registry.lock();
    }
    pub(super) fn acquire(self: &Arc<Self>, tracker: &TaskTracker) -> Option<WorkerLease> {
        let mut registry = self.registry.lock().ok()?;
        let (credit, issuer) = registry.acquire()?;
        let http = crate::http_body::WorkerHttp::new(self.registry.clone(), issuer);
        let lease = WorkerLease { tracked: Some(tracker.token()), slots: self.clone(), credit: Some(credit), http };
        drop(registry);
        Some(lease)
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
    async fn canceled_worker_response_stays_owned_by_connection_until_its_cleanup() {
        use crate::server::connections::ConnectionSlots;
        use http_body_util::BodyExt;
        use tokio::io::AsyncWriteExt;
        let workers = WorkerSlots::new(1);
        let connections = ConnectionSlots::new(1);
        let tracker = TaskTracker::new();
        let connection_lease = connections.acquire().unwrap();
        let (writer, mut body) = connection_lease.responses().channel(4).unwrap();
        let worker_lease = workers.acquire(&tracker).unwrap();
        let mut writer = worker_lease.http().response_writer(writer).unwrap();
        let (sent, queued) = tokio::sync::oneshot::channel();
        let (release, drain) = tokio::sync::oneshot::channel();
        let (received, observed) = tokio::sync::oneshot::channel();
        let worker = worker_lease.spawn(async move {
            writer.write_all(b"data").await.unwrap();
            sent.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(writer);
        });
        let connection = tokio::spawn(connection_lease.task(async move {
            drain.await.unwrap();
            let frame = body.frame().await.unwrap().unwrap().into_data().unwrap();
            assert_eq!(frame.as_ref(), b"data");
            drop(frame);
            // Canceling the producer did not turn its incomplete response into
            // clean EOF, nor destroy the exact queued bytes before draining.
            assert_eq!(body.frame().await.unwrap().unwrap_err().kind(), std::io::ErrorKind::UnexpectedEof);
            received.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(body);
        }));
        queued.await.unwrap();
        assert_eq!(workers.usage(), Some((1, 1)));
        assert_eq!(connections.usage(), Some((1, 1)));
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        assert_eq!(workers.usage(), Some((0, 1)));
        assert!(tracker.is_empty());
        let replacement = workers.acquire(&tracker).unwrap();
        assert!(connections.acquire().is_none());
        release.send(()).unwrap();
        observed.await.unwrap();
        assert!(connections.acquire().is_none());
        connection.abort();
        assert!(connection.await.unwrap_err().is_cancelled());
        assert_eq!(connections.usage(), Some((0, 1)));
        drop(replacement);
        assert_eq!(workers.usage(), Some((0, 1)));
    }

    #[tokio::test]
    async fn actual_http_reader_destruction_precedes_worker_capacity_reuse() {
        use std::{pin::Pin, task::{Context, Poll}, sync::atomic::{AtomicBool, Ordering}};
        use bytes::Bytes;
        use tokio::io::AsyncReadExt;
        struct Source { slots: Arc<WorkerSlots>, tracker: TaskTracker, dropped: Arc<AtomicBool> }
        impl http_body::Body for Source {
            type Data = Bytes;
            type Error = std::io::Error;
            fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<http_body::Frame<Bytes>, std::io::Error>>> {
                Poll::Ready(Some(Ok(http_body::Frame::data(Bytes::from_static(b"data")))))
            }
        }
        impl Drop for Source {
            fn drop(&mut self) {
                assert_eq!(self.slots.usage(), Some((1, 1)));
                assert_eq!(self.tracker.len(), 1);
                assert!(self.slots.acquire(&self.tracker).is_none());
                self.dropped.store(true, Ordering::SeqCst);
            }
        }
        for polled in [false, true] {
            let slots = WorkerSlots::new(1);
            let tracker = TaskTracker::new();
            let dropped = Arc::new(AtomicBool::new(false));
            let lease = slots.acquire(&tracker).unwrap();
            let mut reader = lease.http().input(Source { slots: slots.clone(), tracker: tracker.clone(), dropped: dropped.clone() }).unwrap();
            let (ready, started) = tokio::sync::oneshot::channel();
            let work = async move {
                let mut first = [0];
                reader.read_exact(&mut first).await.unwrap(); // three copied bytes remain
                assert_eq!(first, [b'd']);
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
                drop(reader);
            };
            let task = LeasedTask::new(work, lease);
            if polled {
                let task = tokio::spawn(task);
                started.await.unwrap();
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else { drop(task); }
            assert!(dropped.load(Ordering::SeqCst));
            assert_eq!(slots.usage(), Some((0, 1)));
            assert!(tracker.is_empty());
        }
    }

    #[test]
    fn escaped_http_owners_keep_worker_capacity_after_task_cleanup() {
        use bytes::Bytes;
        use http_body_util::Full;
        for role in 0..4 {
            let slots = WorkerSlots::new(1);
            let tracker = TaskTracker::new();
            let lease = slots.acquire(&tracker).unwrap();
            let http = lease.http();
            let retained: Box<dyn std::any::Any> = match role {
                0 => Box::new(http.input(Full::new(Bytes::from_static(b"data"))).unwrap()),
                1 => Box::new(http.output(Full::new(Bytes::from_static(b"data"))).unwrap()),
                2 => Box::new(http.upload(4).unwrap()),
                _ => {
                    let (writer, body) = crate::http_body::channel(4);
                    Box::new((http.response_writer(writer).unwrap(), body))
                },
            };
            drop(LeasedTask::new(async {}, lease));
            assert_eq!(slots.registry.lock().unwrap().role_usage(role), 1);
            assert_eq!(slots.usage(), Some((1, 1)));
            assert!(!slots.healthy());
            assert!(slots.acquire(&tracker).is_none());
            drop(retained);
            assert_eq!(slots.registry.lock().unwrap().role_usage(role), 0);
            assert_eq!(slots.usage(), Some((1, 1)));
            assert!(slots.acquire(&tracker).is_none());
        }
    }

    #[test]
    fn panicking_capture_strands_worker_credit_and_closes_admission() {
        struct Capture;
        impl Drop for Capture {
            fn drop(&mut self) { panic!("injected capture cleanup panic"); }
        }
        let slots = WorkerSlots::new(1);
        let tracker = TaskTracker::new();
        let capture = Capture;
        let task = LeasedTask::new(async move { drop(capture); }, slots.acquire(&tracker).unwrap());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(task))).is_err());
        assert!(tracker.is_empty());
        assert_eq!(slots.usage(), Some((1, 1)));
        assert!(!slots.healthy());
        assert!(slots.acquire(&tracker).is_none());
    }

    #[test]
    fn never_polled_task_drops_captures_before_credit_and_tracking() {
        struct Capture(Arc<WorkerSlots>, TaskTracker);
        impl Drop for Capture {
            fn drop(&mut self) {
                assert_eq!(self.0.usage(), Some((1, 1)));
                assert_eq!(self.1.len(), 1);
                assert!(self.0.acquire(&self.1).is_none());
            }
        }
        let slots = WorkerSlots::new(1);
        let tracker = TaskTracker::new();
        let capture = Capture(slots.clone(), tracker.clone());
        let lease = slots.acquire(&tracker).unwrap();
        // No executor: this deterministically exercises destruction before poll.
        let task = LeasedTask::new(async move { drop(capture); }, lease);
        drop(task);
        assert!(tracker.is_empty());
        assert_eq!(slots.usage(), Some((0, 1)));
        assert!(slots.acquire(&tracker).is_some());
    }

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
