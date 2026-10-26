//! Fixed handshake threads isolate synchronous certificate work from the I/O
//! executor. Cancellation retains credit until the current poll returns.
use crate::credited_job::{JobPool, Reply};
use std::{future::Future, io};
#[cfg(test)]
use gateway_core::resource::ResourceAdmission;
#[cfg(test)]
use std::sync::{Arc, Mutex, mpsc};
#[cfg(test)]
use tokio::sync::oneshot;

const LIMIT: usize = 32;
const WORKERS: usize = 4;
pub(super) struct Pool { jobs: JobPool }
impl Pool {
    pub(super) fn new() -> io::Result<Self> { Self::with_limits(LIMIT, WORKERS) }
    fn with_limits(limit: usize, workers: usize) -> io::Result<Self> {
        Ok(Self { jobs: JobPool::new("gateway-tls", limit, workers)? })
    }
    pub(super) async fn run<T: Send + 'static>(
        &self, future: impl Future<Output = io::Result<T>> + Send + 'static,
    ) -> io::Result<Reply<T>> {
        let runtime = tokio::runtime::Handle::current();
        self.jobs.submit(move |send, context| {
            // The socket stays registered with the caller's reactor. Only polling
            // the handshake moves threads; successful streams return to that caller.
            // The worker lends its context: it has entered no runtime of its own.
            crate::thread_runtime::block_on_handle(context, &runtime, async move {
                tokio::select! {
                    biased;
                    _ = send.closed() => None,
                    result = future => Some(result),
                }
            })
        }).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn blocked_poll_keeps_credit_without_blocking_executor_or_replacements() {
        let pool = Arc::new(Pool::with_limits(1, 1).unwrap());
        let (started, running) = oneshot::channel();
        let (release, blocked) = mpsc::channel::<()>();
        let task_pool = pool.clone();
        let task = tokio::spawn(async move {
            task_pool.run(async move {
                started.send(()).unwrap();
                let _ = blocked.recv();
                Ok(())
            }).await
        });
        tokio::time::timeout(Duration::from_secs(2), running).await.unwrap().unwrap();
        task.abort(); assert!(task.await.unwrap_err().is_cancelled());
        // Timers and other requests progress even during a non-cooperative poll.
        tokio::time::sleep(Duration::from_millis(10)).await;
        for _ in 0..32 {
            assert_eq!(pool.run::<()>(async { panic!("replacement work") }).await.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(pool.jobs.slots.lock().unwrap().usage(), (1, 1));
        drop(release);
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.jobs.slots.lock().unwrap().usage().0 != 0 { tokio::task::yield_now().await; }
        }).await.unwrap();
        assert_eq!(pool.run(async { Ok(7) }).await.unwrap().into_inner_for_test(), 7);
    }

    #[tokio::test]
    async fn panic_does_not_remove_worker() {
        let pool = Pool::with_limits(1, 1).unwrap();
        assert!(pool.run::<()>(async { panic!("injected verification panic") }).await.is_err());
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.jobs.slots.lock().unwrap().usage().0 != 0 { tokio::task::yield_now().await; }
            pool.run(async { Ok(()) }).await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn cancellation_destroys_handshake_state_before_reusing_credit() {
        struct State {
            slots: Arc<Mutex<ResourceAdmission>>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }
        impl Drop for State {
            fn drop(&mut self) {
                assert_eq!(self.slots.lock().unwrap().usage(), (1, 1));
                self.dropped.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let pool = Arc::new(Pool::with_limits(1, 1).unwrap());
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let state = State { slots: pool.jobs.slots.clone(), dropped: dropped.clone() };
        let task_pool = pool.clone();
        let (started, running) = oneshot::channel();
        let task = tokio::spawn(async move {
            task_pool.run(async move {
                started.send(()).unwrap();
                std::future::pending::<()>().await;
                drop(state); Ok(())
            }).await
        });
        running.await.unwrap(); task.abort(); assert!(task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.jobs.slots.lock().unwrap().usage().0 != 0 { tokio::task::yield_now().await; }
        }).await.unwrap();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn canceled_queued_handshake_is_never_polled() {
        let pool = Arc::new(Pool::with_limits(2, 1).unwrap());
        let (started, running) = oneshot::channel();
        let (release, blocked) = mpsc::channel::<()>();
        let task_pool = pool.clone();
        let first = tokio::spawn(async move {
            task_pool.run(async move {
                started.send(()).unwrap(); let _ = blocked.recv(); Ok(())
            }).await
        });
        running.await.unwrap();
        let task_pool = pool.clone();
        let polled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = polled.clone();
        let queued = tokio::spawn(async move {
            task_pool.run(async move {
                observed.store(true, std::sync::atomic::Ordering::SeqCst); Ok(())
            }).await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.jobs.slots.lock().unwrap().usage().0 != 2 { tokio::task::yield_now().await; }
        }).await.unwrap();
        queued.abort(); assert!(queued.await.unwrap_err().is_cancelled());
        drop(release); first.await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while pool.jobs.slots.lock().unwrap().usage().0 != 0 { tokio::task::yield_now().await; }
        }).await.unwrap();
        assert!(!polled.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn stalled_poll_does_not_hold_runtime_shutdown_open() {
        let (release, blocked) = mpsc::channel::<()>();
        let (finished, done) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async {
                let pool = Pool::with_limits(1, 1).unwrap();
                let (started, running) = oneshot::channel();
                let task = tokio::spawn(async move {
                    pool.run(async move {
                        started.send(()).unwrap(); let _ = blocked.recv(); Ok(())
                    }).await
                });
                tokio::time::timeout(Duration::from_secs(2), running).await.unwrap().unwrap();
                task.abort(); assert!(task.await.unwrap_err().is_cancelled());
            });
            drop(runtime); finished.send(()).unwrap();
        });
        let result = done.recv_timeout(Duration::from_secs(3));
        drop(release);
        thread.join().unwrap();
        result.expect("a stalled verifier must not hold runtime shutdown open");
    }
}
