//! Connection credits bound the threads that parse heads for clients that may
//! never be admitted. A credit returns when the connection thread's work and
//! its captures are gone.
use gateway_core::{resource::ResourceAdmission, task_credit::TaskCredit};
use std::{sync::{Arc, Condvar, Mutex}, time::Instant};
use super::leased::TaskLease;

pub(super) struct ConnectionSlots { registry: Mutex<ResourceAdmission>, drained: Condvar, limit: usize }
pub(super) struct ConnectionLease { slots: Arc<ConnectionSlots>, credit: Option<TaskCredit> }

impl TaskLease for ConnectionLease {
    fn credit(&mut self) -> Option<&mut TaskCredit> { self.credit.as_mut() }
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.slots.registry.lock() {
            // A credit still running (the work panicked) is not releasable and stays occupied.
            if let Some(credit) = self.credit.take() { credit.release(&mut registry); }
        }
        self.slots.drained.notify_all();
    }
}
impl ConnectionSlots {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self { registry: Mutex::new(ResourceAdmission::new(limit, 0)), drained: Condvar::new(), limit })
    }
    pub(super) fn limit(&self) -> usize { self.limit }
    pub(super) fn acquire(self: &Arc<Self>) -> Option<ConnectionLease> {
        let key = self.registry.lock().ok()?.acquire()?;
        Some(ConnectionLease { slots: self.clone(), credit: Some(TaskCredit::new(key)) })
    }
    /// Wait until no connection holds credit, or `until` passes; true when drained.
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
    #[cfg(test)]
    pub(super) fn usage(&self) -> Option<(usize, usize)> {
        self.registry.lock().ok().map(|registry| registry.usage())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn captures_drop_before_connection_credit_on_normal_return() {
        struct Capture(Arc<ConnectionSlots>);
        impl Drop for Capture {
            fn drop(&mut self) {
                assert_eq!(self.0.usage(), Some((1, 1)));
                assert!(self.0.acquire().is_none());
            }
        }
        let slots = ConnectionSlots::new(1);
        let capture = Capture(slots.clone());
        super::super::leased::run(slots.acquire().unwrap(), move || drop(capture));
        assert_eq!(slots.usage(), Some((0, 1)));
        assert!(slots.acquire().is_some());
    }

    #[test]
    fn a_panicking_connection_strands_its_credit() {
        let slots = ConnectionSlots::new(1);
        let lease = slots.acquire().unwrap();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            super::super::leased::run(lease, || panic!("injected connection panic"));
        })).is_err());
        assert_eq!(slots.usage(), Some((1, 1)));
        assert!(slots.acquire().is_none());
    }

    #[test]
    fn a_never_started_lease_returns_its_credit() {
        let slots = ConnectionSlots::new(1);
        let lease = slots.acquire().unwrap();
        assert!(slots.acquire().is_none());
        drop(lease);
        assert_eq!(slots.usage(), Some((0, 1)));
        assert!(slots.acquire().is_some());
    }

    #[test]
    fn poisoned_connection_registry_never_reissues_credit() {
        let slots = ConnectionSlots::new(1);
        let lease = slots.acquire().unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = slots.registry.lock().unwrap();
            panic!("injected registry poison");
        }));
        drop(lease);
        assert!(slots.acquire().is_none());
        assert_eq!(slots.usage(), None);
    }

    #[test]
    fn drain_waits_for_the_last_connection_thread() {
        let slots = ConnectionSlots::new(1);
        let lease = slots.acquire().unwrap();
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || super::super::leased::run(lease, move || { let _ = blocked.recv(); }));
        assert!(!slots.wait_drained(Instant::now() + Duration::from_millis(20)));
        drop(release);
        assert!(slots.wait_drained(Instant::now() + Duration::from_secs(2)));
        thread.join().unwrap();
    }
}
