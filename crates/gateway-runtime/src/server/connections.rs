//! Shared connection credits survive canceled serve invocations until task cleanup.
use gateway_core::{task_credit::TaskCredit, http_connection::ResponseRegistry};
use std::{future::Future, sync::{Arc, Mutex}};
use super::leased_task::{LeasedTask, TaskLease};

pub(super) struct ConnectionSlots { registry: Arc<Mutex<ResponseRegistry>>, limit: usize }
pub(super) struct ConnectionLease { slots: Arc<ConnectionSlots>, credit: Option<TaskCredit>, responses: crate::http_body::ConnectionResponses }

impl TaskLease for ConnectionLease {
    fn credit(&mut self) -> &mut TaskCredit { self.credit.as_mut().expect("live connection lease") }
}

impl ConnectionLease {
    pub(super) fn responses(&self) -> crate::http_body::ConnectionResponses { self.responses.clone() }
    pub(super) fn task<F: Future<Output = ()>>(self, work: F) -> impl Future<Output = ()> {
        LeasedTask::new(work, self)
    }
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        if let Ok(mut registry) = self.slots.registry.lock() {
            let credit = self.credit.take().expect("live connection lease");
            // A retained or leaked response body independently forbids reuse.
            registry.release_task(credit);
        }
    }
}
impl ConnectionSlots {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self { registry: Arc::new(Mutex::new(ResponseRegistry::new(limit))), limit })
    }
    pub(super) fn limit(&self) -> usize { self.limit }
    pub(super) fn acquire(self: &Arc<Self>) -> Option<ConnectionLease> {
        let (credit, issuer) = self.registry.lock().ok()?.acquire()?;
        let responses = crate::http_body::ConnectionResponses::new(self.registry.clone(), issuer);
        Some(ConnectionLease { slots: self.clone(), credit: Some(credit), responses })
    }
    #[cfg(test)]
    pub(super) fn usage(&self) -> Option<(usize, usize)> {
        self.registry.lock().ok().map(|registry| registry.usage())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_cleanup_gates_connection_reuse_and_prevents_late_issuance() {
        let slots = ConnectionSlots::new(1);
        let lease = slots.acquire().unwrap();
        let responses = lease.responses();
        let (writer, body) = responses.channel(4).unwrap();
        assert!(responses.channel(4).is_none());
        let task = lease.task(async move { drop(body); });
        drop(task); // never polled; the actual body returns its permit
        assert_eq!(slots.usage(), Some((0, 1)));
        assert!(responses.channel(4).is_none());
        // An empty sender tail does not retain the receiver's connection credit.
        drop(writer);
        let replacement = slots.acquire().unwrap();
        assert!(responses.channel(4).is_none());
        let (writer, body) = replacement.responses().channel(4).unwrap();
        assert_eq!(slots.registry.lock().unwrap().response_count(), 1);
        drop(replacement.task(async move { drop(body); }));
        drop(writer);
        assert_eq!(slots.registry.lock().unwrap().response_count(), 0);
        assert_eq!(slots.usage(), Some((0, 1)));
    }

    #[test]
    fn escaped_response_strands_connection_even_after_task_cleanup() {
        let slots = ConnectionSlots::new(1);
        let lease = slots.acquire().unwrap();
        let responses = lease.responses();
        let (writer, body) = responses.channel(4).unwrap();
        drop(lease.task(async {}));
        assert_eq!(slots.registry.lock().unwrap().response_count(), 1);
        assert_eq!(slots.usage(), Some((1, 1)));
        assert!(slots.acquire().is_none());
        drop(body);
        drop(writer);
        assert_eq!(slots.registry.lock().unwrap().response_count(), 0);
        assert!(slots.acquire().is_none());
        assert!(responses.channel(4).is_none());
    }

    #[test]
    fn panicking_capture_strands_connection_credit() {
        struct Capture;
        impl Drop for Capture {
            fn drop(&mut self) { panic!("injected capture cleanup panic"); }
        }
        let slots = ConnectionSlots::new(1);
        let capture = Capture;
        let task = slots.acquire().unwrap().task(async move { drop(capture); });
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(task))).is_err());
        assert_eq!(slots.usage(), Some((1, 1)));
        assert!(slots.acquire().is_none());
    }

    #[test]
    fn never_polled_task_drops_captures_before_connection_credit() {
        struct Capture(Arc<ConnectionSlots>);
        impl Drop for Capture {
            fn drop(&mut self) {
                assert_eq!(self.0.usage(), Some((1, 1)));
                assert!(self.0.acquire().is_none());
            }
        }
        let slots = ConnectionSlots::new(1);
        let capture = Capture(slots.clone());
        let task = slots.acquire().unwrap().task(async move { drop(capture); });
        drop(task);
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

    #[tokio::test]
    async fn connection_captures_drop_before_credit_on_every_exit() {
        struct Capture(Arc<ConnectionSlots>);
        impl Drop for Capture {
            fn drop(&mut self) {
                assert_eq!(self.0.usage(), Some((1, 1)));
                assert!(self.0.acquire().is_none());
            }
        }
        for exit in 0..4 {
            let slots = ConnectionSlots::new(1);
            let capture = Capture(slots.clone());
            let (started, running) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(slots.acquire().unwrap().task(async move {
                let _ = started.send(());
                if exit == 3 { panic!("injected connection panic"); }
                if exit != 0 { std::future::pending::<()>().await; }
                drop(capture);
            }));
            if exit == 2 { running.await.unwrap(); }
            if exit == 1 || exit == 2 { task.abort(); }
            let result = task.await;
            if exit == 0 { result.unwrap(); }
            else if exit == 3 { assert!(result.unwrap_err().is_panic()); }
            else { assert!(result.unwrap_err().is_cancelled()); }
            assert_eq!(slots.usage(), Some((0, 1)));
            assert!(slots.acquire().is_some());
        }
    }
}
