//! Verified credits follow background work through queued replies. The request
//! adopts a successful result before its independent background credit returns.
use gateway_core::{resource::{RequestKey, ResourceAdmission}, task_credit::{TaskCredit, TaskResult}};
use std::{io, sync::{Arc, Mutex, mpsc, atomic::{AtomicBool, Ordering}}, time::Duration};

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
    // directly on the caller's thread, already charged to that request.
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

/// The job's end of its reply. A job that finds the requester gone may skip
/// its work; a reply sent to a departed requester is destroyed with its credit.
pub(crate) struct Sender<T> { inner: mpsc::Sender<io::Result<Reply<T>>>, wanted: Arc<AtomicBool> }
impl<T> Sender<T> {
    pub(crate) fn is_closed(&self) -> bool { !self.wanted.load(Ordering::Acquire) }
    fn send(&self, value: io::Result<Reply<T>>) { let _ = self.inner.send(value); }
}
/// The requester's end: wait for the reply within a timeout. Dropping it
/// tells a queued job not to start; a job already running keeps its credit
/// until it finishes, and its late reply is destroyed.
pub(crate) struct Pending<T> { ready: Option<Reply<T>>, receive: Option<mpsc::Receiver<io::Result<Reply<T>>>>, wanted: Arc<AtomicBool> }
impl<T> Pending<T> {
    pub(crate) fn direct(value: T) -> Self { Self { ready: Some(Reply::direct(value)), receive: None, wanted: Arc::new(AtomicBool::new(true)) } }
    pub(crate) fn wait(mut self, timeout: Duration) -> io::Result<Reply<T>> {
        if let Some(reply) = self.ready.take() { return Ok(reply); }
        match self.receive.as_ref().expect("queued job").recv_timeout(timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut.into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other("job lost")),
        }
    }
}
impl<T> Drop for Pending<T> { fn drop(&mut self) { self.wanted.store(false, Ordering::Release); } }

trait Runnable: Send { fn run(self: Box<Self>); }
pub(crate) struct CreditedJob(Box<dyn Runnable>);
struct Job<T, F> { work: Option<F>, send: Option<Sender<T>>, credit: Option<Credit> }
impl<T: Send + 'static, F: FnOnce(&mut Sender<T>) -> Option<io::Result<T>> + Send + 'static> Runnable for Job<T, F> {
    fn run(mut self: Box<Self>) {
        let work = self.work.take().expect("job runs once");
        // FnOnce destroys its captures before returning or unwinding. Credit
        // remains in this owner throughout a blocked lookup.
        let result = work(self.send.as_mut().expect("job reply sender"));
        match result {
            Some(Ok(value)) => {
                let value = self.credit.as_mut().unwrap().state.as_mut().unwrap().finish_work_with(value)
                    .unwrap_or_else(|_| panic!("work and captures finished before creating reply"));
                let reply = Reply { value: Some(Payload::Credited(value)), credit: self.credit.take() };
                self.send.take().unwrap().send(Ok(reply));
            }
            Some(Err(error)) => { self.send.take().unwrap().send(Err(error)); }
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
        work: impl FnOnce(&mut Sender<T>) -> Option<io::Result<T>> + Send + 'static)
        -> (Self, Pending<T>)
    {
        let mut state = TaskCredit::new(key);
        assert!(state.start(), "fresh job reservation");
        let (inner, receive) = mpsc::channel();
        let wanted = Arc::new(AtomicBool::new(true));
        let send = Sender { inner, wanted: wanted.clone() };
        (Self(Box::new(Job { work: Some(work), send: Some(send), credit: Some(Credit { slots, state: Some(state) }) })),
            Pending { ready: None, receive: Some(receive), wanted })
    }
    /// Run on a pool thread.
    pub(crate) fn run(self) { self.0.run(); }
}

const STACK_BYTES: usize = 2 * 1024 * 1024;

/// Fixed dedicated threads run credited jobs. A requester that stops waiting
/// cannot return a running job's credit; the pool never grows to replace a
/// blocked thread.
pub(crate) struct JobPool { sender: mpsc::SyncSender<CreditedJob>, pub(crate) slots: Arc<Mutex<ResourceAdmission>> }
impl JobPool {
    pub(crate) fn new(name: &str, limit: usize, workers: usize) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<CreditedJob>(limit.max(1));
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..workers {
            let receiver = receiver.clone();
            std::thread::Builder::new().name(name.into()).stack_size(STACK_BYTES).spawn(move || loop {
                let job = {
                    let Ok(receiver) = receiver.lock() else { break; };
                    receiver.recv()
                };
                let Ok(job) = job else { break; };
                // A job panic drops its job/credit and closes the reply; it
                // must not silently remove a worker from the fixed pool.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job.run()));
            })?;
        }
        Ok(Self { sender, slots: Arc::new(Mutex::new(ResourceAdmission::new(limit, 0))) })
    }
    /// Queue a job; `WouldBlock` when the pool's credits are all taken.
    pub(crate) fn submit<T: Send + 'static>(&self,
        work: impl FnOnce(&mut Sender<T>) -> Option<io::Result<T>> + Send + 'static) -> io::Result<Pending<T>>
    {
        let key = self.slots.lock().map_err(|_| io::Error::from(io::ErrorKind::Other))?
            .acquire().ok_or(io::ErrorKind::WouldBlock)?;
        let (job, pending) = CreditedJob::new(self.slots.clone(), key, work);
        self.sender.try_send(job).map_err(|error| io::Error::from(match error {
            mpsc::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
            mpsc::TrySendError::Disconnected(_) => io::ErrorKind::Other,
        }))?;
        Ok(pending)
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
            let (job, pending) = CreditedJob::new(slots.clone(), key, |_| Some(Ok(vec![1, 2, 3])));
            job.run();
            let reply = pending.wait(Duration::from_secs(1)).unwrap();
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
            let (job, pending) = CreditedJob::new(slots.clone(), key, move |_| {
                if exit == 2 { panic!("injected running job panic"); }
                Some(Ok(capture))
            });
            let mut pending = Some(pending);
            if exit == 3 { drop(pending.take()); }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if exit == 0 { drop(job); } else { job.run(); }
            }));
            assert_eq!(result.is_err(), exit == 2);
            if exit == 1 {
                // Successful send alone is not cleanup: the unread reply retains
                // its own background credit until the requester takes it.
                assert_eq!(slots.lock().unwrap().usage(), (1, 1));
                let reply = pending.take().unwrap().wait(Duration::from_secs(1)).unwrap();
                assert_eq!(slots.lock().unwrap().usage(), (1, 1));
                drop(reply);
            }
            drop(pending);
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
            let (job, pending) = CreditedJob::new(slots.clone(), key, move |_| Some(Ok(capture)));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if delivered {
                    job.run();
                    drop(pending.wait(Duration::from_secs(1)).unwrap());
                } else { drop(job); }
            }));
            assert!(result.is_err());
            assert_eq!(slots.lock().unwrap().usage(), (1, 1));
            assert!(slots.lock().unwrap().acquire().is_none());
        }
    }

    #[test]
    fn a_departed_requester_lets_a_queued_job_skip_and_a_running_job_finish() {
        let pool = JobPool::new("test-jobs", 2, 1).unwrap();
        let (release, blocked) = mpsc::channel::<()>();
        let (started, running) = mpsc::channel();
        let first = pool.submit(move |_| { started.send(()).unwrap(); let _ = blocked.recv(); Some(Ok(1)) }).unwrap();
        running.recv_timeout(Duration::from_secs(2)).unwrap();
        let polled = Arc::new(AtomicBool::new(false));
        let observed = polled.clone();
        let queued = pool.submit(move |send| { if send.is_closed() { return None; } observed.store(true, Ordering::SeqCst); Some(Ok(2)) }).unwrap();
        assert_eq!(pool.slots.lock().unwrap().usage(), (2, 2));
        assert_eq!(pool.submit::<()>(|_| panic!("over budget")).err().expect("over budget").kind(), io::ErrorKind::WouldBlock);
        drop(queued); // stops waiting before the job starts
        assert_eq!(first.wait(Duration::from_millis(20)).unwrap_err().kind(), io::ErrorKind::TimedOut);
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while pool.slots.lock().unwrap().usage().0 != 0 { assert!(std::time::Instant::now() < deadline); std::thread::sleep(Duration::from_millis(5)); }
        assert!(!polled.load(Ordering::SeqCst), "a queued job whose requester left never ran");
        assert_eq!(pool.submit(|_| Some(Ok(7))).unwrap().wait(Duration::from_secs(1)).unwrap().into_inner_for_test(), 7);
    }
}
