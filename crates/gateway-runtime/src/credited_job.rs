//! Verified credits follow background work through queued replies. The request
//! adopts a successful result before its independent background credit returns.
use gateway_core::{resource::{RequestKey, ResourceAdmission}, task_credit::{TaskCredit, TaskResult}, thread_context::ThreadContext};
use std::{io, sync::{Arc, Mutex, mpsc}};
use tokio::sync::oneshot;

struct Credit { slots: Arc<Mutex<ResourceAdmission>>, state: Option<TaskCredit> }
impl Drop for Credit {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.slots.lock() {
            let state = self.state.take().expect("live job credit");
            let ready = state.can_release();
            let released = state.release(&mut slots);
            debug_assert_eq!(released, ready, "job credit belongs to its registry");
        }
    }
}

/// Owns a result still charged to its background registry. There is no raw value
/// extraction in production: adoption requires a live admitted request.
enum Payload<T> { Direct(T), Credited(TaskResult<T>) }
pub(crate) struct Reply<T> { value: Option<Payload<T>>, credit: Option<Credit> }
impl<T> std::fmt::Debug for Reply<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("CreditedReply") }
}
impl<T> Reply<T> {
    // Literal IP resolution performs no background work and creates one address
    // directly in the caller's request future, already charged to that request.
    pub(crate) fn direct(value: T) -> Self { Self { value: Some(Payload::Direct(value)), credit: None } }
    pub(crate) fn adopt(mut self, request: &mut crate::admission::Request<'_>) -> io::Result<T> {
        let value = match self.value.take().expect("owned reply value") {
            Payload::Direct(value) => value,
            Payload::Credited(value) => {
                let credit = self.credit.as_mut().expect("credited reply source");
                match request.adopt_background(credit.state.as_mut().expect("live reply credit"), value) {
                    Ok(value) => value,
                    Err(value) => {
                        self.value = Some(Payload::Credited(value));
                        return Err(io::ErrorKind::BrokenPipe.into());
                    },
                }
            },
        };
        // The exclusive request borrow is still live at the checked handoff.
        // Its outer owner outlives this synchronous transfer and subsequent I/O.
        drop(self.credit.take());
        Ok(value)
    }
    #[cfg(test)]
    pub(crate) fn into_inner_for_test(self) -> T {
        // Exercise the production handoff even when tests own the result directly.
        let admission = crate::test_support::admission(1, 4, false);
        let mut request = admission.admit(&[11; 32], 7).unwrap();
        self.adopt(&mut request).expect("test request adopts reply")
    }
}
impl<T> Drop for Reply<T> {
    fn drop(&mut self) {
        if let Some(credit) = self.credit.as_mut() {
            let state = credit.state.as_mut().expect("live reply credit");
            let mut cleanup = state.begin_cleanup_with(self.value.take())
                .unwrap_or_else(|_| panic!("live reply"));
            drop(cleanup.take());
            assert!(cleanup.finish(), "reply value destroyed");
            assert!(state.finish_cleanup_with(&cleanup), "reply cleanup belongs to credit");
        }
    }
}

pub(crate) type Sender<T> = oneshot::Sender<io::Result<Reply<T>>>;
trait Runnable: Send { fn run(self: Box<Self>, context: &mut ThreadContext); }
pub(crate) struct CreditedJob(Box<dyn Runnable>);
struct Job<T, F> { work: Option<F>, send: Option<Sender<T>>, credit: Option<Credit> }
impl<T: Send + 'static, F: FnOnce(&mut Sender<T>, &mut ThreadContext) -> Option<io::Result<T>> + Send + 'static> Runnable for Job<T, F> {
    fn run(mut self: Box<Self>, context: &mut ThreadContext) {
        let work = self.work.take().expect("job runs once");
        // FnOnce destroys its captures before returning or unwinding. Credit
        // remains in this owner throughout a blocked lookup or handshake poll.
        let result = work(self.send.as_mut().expect("job reply sender"), context);
        match result {
            Some(Ok(value)) => {
                let value = self.credit.as_mut().unwrap().state.as_mut().unwrap().finish_work_with(value)
                    .unwrap_or_else(|_| panic!("work and captures finished before creating reply"));
                let reply = Reply { value: Some(Payload::Credited(value)), credit: self.credit.take() };
                let _ = self.send.take().unwrap().send(Ok(reply));
            }
            Some(Err(error)) => { let _ = self.send.take().unwrap().send(Err(error)); }
            None => {},
        }
    }
}
impl<T, F> Drop for Job<T, F> {
    fn drop(&mut self) {
        if let Some(credit) = self.credit.as_mut() {
            let state = credit.state.as_mut().expect("live job credit");
            let mut cleanup = state.begin_cleanup_with((self.work.take(), self.send.take()))
                .unwrap_or_else(|_| panic!("live job"));
            drop(cleanup.take());
            // A queued capture destructor panic skips this and strands capacity.
            assert!(cleanup.finish(), "job captures destroyed");
            assert!(state.finish_cleanup_with(&cleanup), "job cleanup belongs to credit");
        }
    }
}
impl CreditedJob {
    pub(crate) fn new<T: Send + 'static>(slots: Arc<Mutex<ResourceAdmission>>, key: RequestKey,
        work: impl FnOnce(&mut Sender<T>, &mut ThreadContext) -> Option<io::Result<T>> + Send + 'static)
        -> (Self, oneshot::Receiver<io::Result<Reply<T>>>)
    {
        let mut state = TaskCredit::new(key);
        assert!(state.start(), "fresh job reservation");
        let (send, receive) = oneshot::channel();
        (Self(Box::new(Job { work: Some(work), send: Some(send),
            credit: Some(Credit { slots, state: Some(state) }) })), receive)
    }
    /// Run on the worker thread, which lends its context so the job may
    /// drive a future through a runtime handle but never enter a runtime.
    pub(crate) fn run(self, context: &mut ThreadContext) { self.0.run(context); }
}

const STACK_BYTES: usize = 2 * 1024 * 1024;

/// Fixed dedicated threads run credited jobs. Request cancellation cannot
/// return a running job's credit; the threads never hold runtime shutdown open.
/// Each thread owns its `ThreadContext`: it enters no runtime, so a job may
/// block on another runtime's handle.
pub(crate) struct JobPool { sender: mpsc::SyncSender<CreditedJob>, pub(crate) slots: Arc<Mutex<ResourceAdmission>> }
impl JobPool {
    pub(crate) fn new(name: &str, limit: usize, workers: usize) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<CreditedJob>(limit.max(1));
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..workers {
            let receiver = receiver.clone();
            crate::thread_runtime::spawn_fresh(std::thread::Builder::new().name(name.into()).stack_size(STACK_BYTES),
                move |mut context| loop {
                    let job = {
                        let Ok(receiver) = receiver.lock() else { break; };
                        receiver.recv()
                    };
                    let Ok(job) = job else { break; };
                    // A job panic drops its job/credit and closes the reply; it
                    // must not silently remove a worker from the fixed pool.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job.run(&mut context)));
                })?;
        }
        Ok(Self { sender, slots: Arc::new(Mutex::new(ResourceAdmission::new(limit, 0))) })
    }
    pub(crate) async fn submit<T: Send + 'static>(&self,
        work: impl FnOnce(&mut Sender<T>, &mut ThreadContext) -> Option<io::Result<T>> + Send + 'static) -> io::Result<Reply<T>>
    {
        let key = self.slots.lock().map_err(|_| io::Error::from(io::ErrorKind::Other))?
            .acquire().ok_or(io::ErrorKind::WouldBlock)?;
        let (job, receive) = CreditedJob::new(self.slots.clone(), key, work);
        self.sender.try_send(job).map_err(|error| io::Error::from(match error {
            mpsc::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
            mpsc::TrySendError::Disconnected(_) => io::ErrorKind::Other,
        }))?;
        receive.await.map_err(|_| io::Error::from(io::ErrorKind::Other))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_adoption_requires_live_request_and_preserves_value() {
        let admission = crate::test_support::admission(1, 4, false);
        for canceled in [false, true] {
            let mut request = admission.admit(&[11; 32], 7).unwrap();
            let slots = Arc::new(Mutex::new(ResourceAdmission::new(1, 0)));
            let key = slots.lock().unwrap().acquire().unwrap();
            let (job, mut receive) = CreditedJob::new(slots.clone(), key, |_, _| Some(Ok(vec![1, 2, 3])));
            job.run(&mut ThreadContext::fresh());
            let reply = receive.try_recv().unwrap().unwrap();
            assert_eq!(slots.lock().unwrap().usage(), (1, 1));
            if canceled { request.cancel(); }
            let result = reply.adopt(&mut request);
            if canceled { assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe); }
            else { assert_eq!(result.unwrap(), vec![1, 2, 3]); }
            assert_eq!(slots.lock().unwrap().usage(), (0, 1));
            assert_eq!(admission.usage().unwrap(), (1, 1));
            drop(request);
            assert_eq!(admission.usage().unwrap(), (0, 1));
        }
    }

    struct Capture(Arc<Mutex<ResourceAdmission>>);
    impl Drop for Capture {
        fn drop(&mut self) {
            let mut slots = self.0.lock().unwrap();
            assert_eq!(slots.usage(), (1, 1));
            assert!(slots.acquire().is_none());
        }
    }

    #[test]
    fn queued_running_and_reply_captures_drop_before_credit() {
        for exit in 0..4 {
            let slots = Arc::new(Mutex::new(ResourceAdmission::new(1, 0)));
            let key = slots.lock().unwrap().acquire().unwrap();
            let capture = Capture(slots.clone());
            let (job, mut receive) = CreditedJob::new(slots.clone(), key, move |_, _| {
                if exit == 2 { panic!("injected running job panic"); }
                Some(Ok(capture))
            });
            if exit == 3 { receive.close(); }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if exit == 0 { drop(job); } else { job.run(&mut ThreadContext::fresh()); }
            }));
            assert_eq!(result.is_err(), exit == 2);
            if exit == 1 {
                // Successful send alone is not cleanup: the unread reply retains
                // its own background credit even before the receiver is polled.
                assert_eq!(slots.lock().unwrap().usage(), (1, 1));
                let reply = receive.try_recv().unwrap().unwrap();
                assert_eq!(slots.lock().unwrap().usage(), (1, 1));
                drop(reply);
            }
            assert_eq!(slots.lock().unwrap().usage(), (0, 1));
        }
    }

    #[test]
    fn queued_and_reply_cleanup_panics_strand_credit() {
        struct Panics;
        impl Drop for Panics { fn drop(&mut self) { panic!("injected cleanup panic"); } }
        for delivered in [false, true] {
            let slots = Arc::new(Mutex::new(ResourceAdmission::new(1, 0)));
            let key = slots.lock().unwrap().acquire().unwrap();
            let capture = Panics;
            let (job, mut receive) = CreditedJob::new(slots.clone(), key, move |_, _| Some(Ok(capture)));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if delivered {
                    job.run(&mut ThreadContext::fresh());
                    drop(receive.try_recv().unwrap().unwrap());
                } else { drop(job); }
            }));
            assert!(result.is_err());
            assert_eq!(slots.lock().unwrap().usage(), (1, 1));
            assert!(slots.lock().unwrap().acquire().is_none());
        }
    }
}
