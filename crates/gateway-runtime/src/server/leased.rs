//! Trusted thread ownership: a credit is released only after the work that
//! held it has returned and its captures are gone.
use gateway_core::task_credit::TaskCredit;

pub(super) trait TaskLease {
    /// The credit, until the lease's destructor has consumed it.
    fn credit(&mut self) -> Option<&mut TaskCredit>;
}

/// A lease whose credit is running. `finish` records the cleanup and returns
/// the credit; dropping it unfinished (the work panicked or was abandoned)
/// drops the lease with its credit still running, and the registry refuses
/// to reuse the slot: capacity is stranded rather than reported free.
pub(super) struct Started<L: TaskLease>(L);
impl<L: TaskLease> Started<L> {
    /// The work returned and its resources are gone: record the cleanup and
    /// return the credit. This is the trusted correspondence point between
    /// "the thread's resources are gone" and "the credit may return".
    ///
    /// A credit found outside its protocol is left as it is: the lease then
    /// drops it unfinished and the registry keeps the slot occupied. The
    /// debug assertions make such a fault fail tests.
    pub(super) fn finish(self) {
        let mut lease = self.0;
        let Some(credit) = lease.credit() else { return };
        let Ok(mut cleanup) = credit.begin_cleanup_with(()) else {
            debug_assert!(false, "live task credit");
            return;
        };
        let _ = cleanup.take();
        let finished = cleanup.finish();
        debug_assert!(finished, "work returned");
        let recorded = credit.finish_cleanup_with(&cleanup);
        debug_assert!(recorded, "completed task cleanup");
        drop(lease);
    }
}
/// Start the lease's credit; the caller finishes it when its work is done.
pub(super) fn start<L: TaskLease>(mut lease: L) -> Started<L> {
    if let Some(credit) = lease.credit() {
        let started = credit.start();
        debug_assert!(started, "fresh task reservation");
    }
    Started(lease)
}

/// Run `work` on this thread under `lease`. `work` owns its captures and
/// drops them before returning; only then is the credit's cleanup recorded.
pub(super) fn run<L: TaskLease>(lease: L, work: impl FnOnce()) {
    let started = start(lease);
    work();
    started.finish();
}
