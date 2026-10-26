//! Trusted thread ownership: a credit is released only after the work that
//! held it has returned and its captures are gone.
use gateway_core::task_credit::TaskCredit;

pub(super) trait TaskLease {
    fn credit(&mut self) -> &mut TaskCredit;
}

/// Run `work` on this thread under `lease`. `work` owns its captures and
/// drops them before returning; only then is the credit's cleanup recorded
/// and the lease dropped, which returns the credit. If `work` panics, the
/// lease is dropped while unwinding with its credit still running, and the
/// registry refuses to reuse the slot: capacity is stranded rather than
/// reported free. This is the trusted correspondence point between "the
/// thread's resources are gone" and "the credit may return".
pub(super) fn run<L: TaskLease>(mut lease: L, work: impl FnOnce()) {
    assert!(lease.credit().start(), "fresh task reservation");
    work();
    let mut cleanup = lease.credit().begin_cleanup_with(())
        .unwrap_or_else(|_| panic!("live task credit"));
    let _ = cleanup.take();
    assert!(cleanup.finish(), "work returned");
    assert!(lease.credit().finish_cleanup_with(&cleanup), "completed task cleanup");
    drop(lease);
}
