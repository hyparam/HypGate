//! Trusted task ownership: destroy the future before returning its lease.
use std::{future::Future, pin::Pin, task::{Context, Poll}};
use gateway_core::task_credit::TaskCredit;

pub(super) trait TaskLease {
    fn credit(&mut self) -> &mut TaskCredit;
}

// Keep fields private. Destruction explicitly gates release on completed future
// cleanup, including never-polled tasks. A panicking destructor strands capacity
// rather than reporting successful cleanup while unwinding.
pub(super) struct LeasedTask<F, L: TaskLease> {
    work: Option<Pin<Box<F>>>,
    lease: L,
}

impl<F, L: TaskLease> LeasedTask<F, L> {
    pub(super) fn new(work: F, mut lease: L) -> Self {
        assert!(lease.credit().start(), "fresh task reservation");
        Self { work: Some(Box::pin(work)), lease }
    }
}

impl<F, L: TaskLease> Drop for LeasedTask<F, L> {
    fn drop(&mut self) {
        assert!(self.lease.credit().begin_cleanup(), "live task credit");
        drop(self.work.take());
        // This is the trusted correspondence point: only normal return from
        // destruction may report that future-owned resources are gone.
        assert!(self.lease.credit().finish_cleanup(), "completed task cleanup");
    }
}

// Unit output prevents task-owned resources escaping through a task result.
impl<F: Future<Output = ()>, L: TaskLease + Unpin> Future for LeasedTask<F, L> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().work.as_mut().expect("live task future").as_mut().poll(cx)
    }
}
