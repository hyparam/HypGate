//! Bounded blocking DNS work on fixed threads. A requester whose deadline
//! passes stops waiting; the lookup's credit returns when the lookup does.
use crate::credited_job::{JobPool, Pending};
use std::{io, net::{IpAddr, SocketAddr, ToSocketAddrs}};

const LOOKUPS: usize = 32;
const WORKERS: usize = 4;
const ADDRESSES: usize = 64;

pub(super) struct Resolver { jobs: JobPool }
impl Resolver {
    pub(super) fn new() -> io::Result<Self> { Self::with_limit(LOOKUPS) }
    fn with_limit(limit: usize) -> io::Result<Self> {
        Ok(Self { jobs: JobPool::new("gateway-dns", limit, WORKERS.min(limit))? })
    }
    // Effect site: the system resolver, for the host of a provider permit.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn resolve(&self, host: String, port: u16) -> io::Result<Pending<Vec<SocketAddr>>> {
        if let Ok(ip) = host.parse::<IpAddr>() { return Ok(Pending::direct(vec![SocketAddr::new(ip, port)])); }
        self.resolve_with(host, port, |host, port| {
            // The system resolver can allocate before returning its iterator.
            // Detach a bounded result instead of reusing that iterator's backing.
            bounded_addresses((host, port).to_socket_addrs()?)
        })
    }
    fn resolve_with<F>(&self, host: String, port: u16, lookup: F) -> io::Result<Pending<Vec<SocketAddr>>>
        where F: FnOnce(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + 'static,
    {
        self.jobs.submit(move |send| {
            if send.is_closed() { return None; } // skip work nobody waits for
            Some(lookup(&host, port))
        })
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
    use std::{sync::{Arc, mpsc, atomic::{AtomicUsize, Ordering}}, time::{Duration, Instant}};

    fn wait_idle(resolver: &Resolver) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while resolver.jobs.slots.lock().unwrap().usage().0 != 0 {
            assert!(Instant::now() < deadline, "pool did not drain");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn departed_lookups_keep_credit_until_blocking_work_finishes() {
        let resolver = Arc::new(Resolver::with_limit(5).unwrap());
        let calls = Arc::new(AtomicUsize::new(0));
        let (started, starts) = mpsc::channel();
        let mut pending = Vec::new(); let mut release = Vec::new();
        for _ in 0..4 {
            let calls = calls.clone(); let started = started.clone();
            let (send, receive) = mpsc::channel::<()>(); release.push(send);
            pending.push(resolver.resolve_with("blocked.example".into(), 443, move |_, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                started.send(()).unwrap();
                let _ = receive.recv();
                Ok(vec!["127.0.0.1:443".parse().unwrap()])
            }).unwrap());
        }
        for _ in 0..4 { starts.recv_timeout(Duration::from_secs(2)).unwrap(); }
        let queued_calls = calls.clone();
        let queued = resolver.resolve_with("queued.example".into(), 443, move |_, _| {
            queued_calls.fetch_add(1, Ordering::SeqCst); Ok(Vec::new())
        }).unwrap();
        assert_eq!(resolver.jobs.slots.lock().unwrap().usage(), (5, 5));
        drop(queued);
        for lookup in pending { assert_eq!(lookup.wait(Duration::from_millis(10)).unwrap_err().kind(), io::ErrorKind::TimedOut); }
        for _ in 0..16 {
            assert_eq!(resolver.resolve_with("excess.example".into(), 443, |_, _| panic!("over budget"))
                .err().expect("over budget").kind(), io::ErrorKind::WouldBlock);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        assert_eq!(resolver.jobs.slots.lock().unwrap().usage(), (5, 5));
        assert_eq!(resolver.resolve("::1".into(), 8443).unwrap().wait(Duration::ZERO).unwrap().into_inner_for_test(),
            vec!["[::1]:8443".parse::<SocketAddr>().unwrap()]);
        drop(release);
        wait_idle(&resolver);
        assert_eq!(calls.load(Ordering::SeqCst), 4); // the queued lookup nobody waited for was skipped
        assert_eq!(resolver.resolve_with("later.example".into(), 8443, |_, port|
            Ok(vec![SocketAddr::from(([127, 0, 0, 1], port))])).unwrap().wait(Duration::from_secs(2)).unwrap().into_inner_for_test(),
            vec!["127.0.0.1:8443".parse::<SocketAddr>().unwrap()]);
    }

    #[test]
    fn panicked_lookup_returns_credit_without_losing_the_pool_worker() {
        let resolver = Resolver::with_limit(1).unwrap();
        let pending = resolver.resolve_with("panic.example".into(), 443, |_, _| panic!("injected DNS panic")).unwrap();
        assert!(pending.wait(Duration::from_secs(2)).is_err());
        wait_idle(&resolver);
        assert_eq!(resolver.resolve_with("later.example".into(), 443, |_, _|
            Ok(vec!["127.0.0.1:443".parse().unwrap()])).unwrap().wait(Duration::from_secs(2)).unwrap().into_inner_for_test().len(), 1);
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
