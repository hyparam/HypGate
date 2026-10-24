//! Bounded blocking DNS work. Request cancellation cannot return a running
//! lookup's credit; dedicated threads do not hold Tokio runtime shutdown open.
use gateway_core::resource::ResourceAdmission;
use crate::credited_job::{CreditedJob as Job, Reply};
use std::{io, net::{IpAddr, SocketAddr, ToSocketAddrs}, sync::{Arc, Mutex, mpsc}};
#[cfg(test)]
use tokio::sync::oneshot;

const LOOKUPS: usize = 32;
const WORKERS: usize = 4;
const ADDRESSES: usize = 64;
const STACK_BYTES: usize = 2 * 1024 * 1024;

pub(super) struct Resolver { slots: Arc<Mutex<ResourceAdmission>>, sender: mpsc::SyncSender<Job> }
impl Resolver {
    pub(super) fn new() -> io::Result<Self> { Self::with_limit(LOOKUPS) }
    fn with_limit(limit: usize) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(limit.max(1));
        let receiver = Arc::new(Mutex::new(receiver));
        for _ in 0..WORKERS.min(limit) {
            let receiver = receiver.clone();
            std::thread::Builder::new().name("gateway-dns".into()).stack_size(STACK_BYTES)
                .spawn(move || loop {
                    let job = {
                        let Ok(receiver) = receiver.lock() else { break; };
                        receiver.recv()
                    };
                    let Ok(job) = job else { break; };
                    // A lookup panic drops its job/credit and closes the reply;
                    // it must not silently remove a worker from the fixed pool.
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job.run()));
                })?;
        }
        Ok(Self { slots: Arc::new(Mutex::new(ResourceAdmission::new(limit, 0))), sender })
    }
    pub(super) async fn resolve(&self, host: String, port: u16) -> io::Result<Reply<Vec<SocketAddr>>> {
        if let Ok(ip) = host.parse::<IpAddr>() { return Ok(Reply::direct(vec![SocketAddr::new(ip, port)])); }
        self.resolve_with(host, port, |host, port| {
            // The system resolver can allocate before returning its iterator.
            // Detach a bounded result instead of reusing that iterator's backing.
            bounded_addresses((host, port).to_socket_addrs()?)
        }).await
    }
    async fn resolve_with<F>(&self, host: String, port: u16, lookup: F) -> io::Result<Reply<Vec<SocketAddr>>>
        where F: FnOnce(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static,
    {
        let key = self.slots.lock().map_err(|_| io::Error::from(io::ErrorKind::Other))?
            .acquire().ok_or(io::ErrorKind::WouldBlock)?;
        let (job, receive) = Job::new(self.slots.clone(), key, move |send| {
            if send.is_closed() { return None; } // skip canceled queued work
            Some(lookup(&host, port))
        });
        self.sender.try_send(job).map_err(|error| io::Error::from(match error {
            mpsc::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
            mpsc::TrySendError::Disconnected(_) => io::ErrorKind::Other,
        }))?;
        receive.await.map_err(|_| io::Error::from(io::ErrorKind::Other))?
    }
}

fn bounded_addresses(input: impl Iterator<Item = SocketAddr>) -> io::Result<Vec<SocketAddr>> {
    let mut addresses = Vec::with_capacity(ADDRESSES);
    for address in input {
        if addresses.len() == ADDRESSES { return Err(io::ErrorKind::InvalidData.into()); }
        addresses.push(address);
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::atomic::{AtomicUsize, Ordering}, time::Duration};

    #[tokio::test]
    async fn canceled_lookups_keep_credit_until_blocking_work_finishes() {
        let resolver = Arc::new(Resolver::with_limit(5).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let (started, mut starts) = tokio::sync::mpsc::channel(4);
        let mut tasks = Vec::new(); let mut release = Vec::new();
        for _ in 0..4 {
            let resolver = resolver.clone(); let calls = calls.clone(); let started = started.clone();
            let (send, receive) = std::sync::mpsc::channel::<()>(); release.push(send);
            tasks.push(tokio::spawn(async move {
                resolver.resolve_with("blocked.example".into(), 443, move |_, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    started.blocking_send(()).unwrap();
                    let _ = receive.recv();
                    Ok(vec!["127.0.0.1:443".parse().unwrap()])
                }).await
            }));
        }
        for _ in 0..4 { tokio::time::timeout(Duration::from_secs(2), starts.recv()).await.unwrap().unwrap(); }
        let queued_resolver = resolver.clone(); let queued_calls = calls.clone();
        let queued = tokio::spawn(async move {
            queued_resolver.resolve_with("queued.example".into(), 443, move |_, _| {
                queued_calls.fetch_add(1, Ordering::SeqCst); Ok(Vec::new())
            }).await
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            while resolver.slots.lock().unwrap().usage().0 != 5 { tokio::task::yield_now().await; }
        }).await.unwrap();
        queued.abort(); assert!(queued.await.unwrap_err().is_cancelled());
        for task in tasks { task.abort(); assert!(task.await.unwrap_err().is_cancelled()); }
        for _ in 0..16 {
            assert_eq!(resolver.resolve_with("excess.example".into(), 443, |_, _| panic!("over budget"))
                .await.unwrap_err().kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(resolver.slots.lock().unwrap().usage(), (5, 5));
        assert_eq!(resolver.resolve("::1".into(), 8443).await.unwrap().into_inner_for_test(),
            vec!["[::1]:8443".parse::<SocketAddr>().unwrap()]);
        drop(release);
        tokio::time::timeout(Duration::from_secs(2), async {
            while resolver.slots.lock().unwrap().usage().0 != 0 { tokio::task::yield_now().await; }
        }).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4); // canceled queued job was skipped
        assert_eq!(resolver.resolve_with("later.example".into(), 8443, |_, port|
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])).await.unwrap().into_inner_for_test(),
            vec!["127.0.0.1:8443".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn stalled_lookup_does_not_block_tokio_runtime_shutdown() {
        let (release, blocked) = std::sync::mpsc::channel::<()>();
        let (started, running) = oneshot::channel();
        let (finished, done) = std::sync::mpsc::channel::<()>();
        let runtime = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async {
                let resolver = Resolver::with_limit(1).unwrap();
                let task = tokio::spawn(async move {
                    resolver.resolve_with("blocked.example".into(), 443, move |_, _| {
                        started.send(()).unwrap(); let _ = blocked.recv(); Ok(Vec::new())
                    }).await
                });
                tokio::time::timeout(Duration::from_secs(2), running).await.unwrap().unwrap();
                task.abort(); assert!(task.await.unwrap_err().is_cancelled());
            });
            drop(rt);
            finished.send(()).unwrap();
        });
        done.recv_timeout(Duration::from_secs(3)).expect("runtime must exit while DNS is still blocked");
        drop(release);
        runtime.join().unwrap();
    }

    #[tokio::test]
    async fn panicked_lookup_returns_credit_without_losing_the_pool_worker() {
        let resolver = Resolver::with_limit(1).unwrap();
        assert_eq!(resolver.resolve_with("panic.example".into(), 443, |_, _| panic!("injected DNS panic"))
            .await.unwrap_err().kind(), io::ErrorKind::Other);
        tokio::time::timeout(Duration::from_secs(2), async {
            while resolver.slots.lock().unwrap().usage().0 != 0 { tokio::task::yield_now().await; }
            assert_eq!(resolver.resolve_with("later.example".into(), 443, |_, _|
                Ok(vec!["127.0.0.1:443".parse().unwrap()])).await.unwrap().into_inner_for_test().len(), 1);
        }).await.unwrap();
    }

    #[test]
    fn address_results_are_detached_and_reject_excess_without_draining_iterator() {
        let address: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut oversized = Vec::with_capacity(4096);
        oversized.extend(std::iter::repeat_n(address, ADDRESSES));
        let result = bounded_addresses(oversized.into_iter()).unwrap();
        assert_eq!(result, vec![address; ADDRESSES]);
        assert_eq!(result.capacity(), ADDRESSES);
        let mut read = 0;
        let infinite = std::iter::from_fn(|| { read += 1; Some(address) });
        assert_eq!(bounded_addresses(infinite).unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(read, ADDRESSES + 1);
    }
}
