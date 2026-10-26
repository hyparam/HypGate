//! Trusted thread ownership: a credit is released only after the work that
//! held it has returned and its captures are gone.
use gateway_core::task_credit::TaskCredit;

pub(super) trait TaskLease {
    fn credit(&mut self) -> &mut TaskCredit;
}

/// A lease whose credit is running. `finish` records the cleanup and returns
/// the credit; dropping it unfinished (the work panicked or was abandoned)
/// drops the lease with its credit still running, and the registry refuses
/// to reuse the slot: capacity is stranded rather than reported free.
pub(super) struct Started<L: TaskLease>(Option<L>);
impl<L: TaskLease> Started<L> {
    /// The work returned and its resources are gone: record the cleanup and
    /// return the credit. This is the trusted correspondence point between
    /// "the thread's resources are gone" and "the credit may return".
    pub(super) fn finish(mut self) {
        let mut lease = self.0.take().expect("started lease");
        let mut cleanup = lease.credit().begin_cleanup_with(())
            .unwrap_or_else(|_| panic!("live task credit"));
        let _ = cleanup.take();
        assert!(cleanup.finish(), "work returned");
        assert!(lease.credit().finish_cleanup_with(&cleanup), "completed task cleanup");
        drop(lease);
    }
}
/// Start the lease's credit; the caller finishes it when its work is done.
pub(super) fn start<L: TaskLease>(mut lease: L) -> Started<L> {
    assert!(lease.credit().start(), "fresh task reservation");
    Started(Some(lease))
}

/// Run `work` on this thread under `lease`. `work` owns its captures and
/// drops them before returning; only then is the credit's cleanup recorded.
pub(super) fn run<L: TaskLease>(lease: L, work: impl FnOnce()) {
    let started = start(lease);
    work();
    started.finish();
}
