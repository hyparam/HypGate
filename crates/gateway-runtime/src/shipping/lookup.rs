//! Bounded name resolution for the shipper. One long-lived thread performs
//! the blocking system lookup; the requester waits with its request deadline
//! and leaves on time. A lookup still running after its requester left holds
//! only this thread: the next request is buffered once, the one after that
//! fails at once, and a buffered request whose requester has left is skipped
//! rather than looked up. The thread is never replaced, and it exits when the
//! client that owns it is dropped.
use std::{io, net::{IpAddr, SocketAddr, ToSocketAddrs}, sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc}, thread, time::Duration};

/// The most addresses taken from one lookup.
const ADDRESSES: usize = 16;
const STACK_BYTES: usize = 256 * 1024;

type Answer = io::Result<Vec<SocketAddr>>;
struct Request { host: String, port: u16, reply: mpsc::Sender<Answer>, wanted: Arc<AtomicBool> }

/// Clears the requester's interest when it stops waiting, so a queued lookup is skipped.
struct Interest(Arc<AtomicBool>);
impl Drop for Interest { fn drop(&mut self) { self.0.store(false, Ordering::Release); } }

pub(super) struct Lookup { submit: mpsc::SyncSender<Request> }

impl Lookup {
    // Effect site: the system resolver, for the host of the configured
    // shipping server, on the shipper's one lookup thread.
    #[allow(clippy::disallowed_methods)]
    pub(super) fn new() -> io::Result<Self> {
        Self::with(|host, port| bounded((host, port).to_socket_addrs()?))
    }
    fn with<F>(lookup: F) -> io::Result<Self>
        where F: Fn(&str, u16) -> Answer + Send + 'static
    {
        let (submit, receive) = mpsc::sync_channel::<Request>(1);
        thread::Builder::new().name("hypgate-ship-dns".into()).stack_size(STACK_BYTES).spawn(move || {
            while let Ok(request) = receive.recv() {
                if !request.wanted.load(Ordering::Acquire) { continue; } // the requester left: skip the work
                let answer = lookup(&request.host, request.port);
                let _ = request.reply.send(answer); // a late answer to a departed requester is dropped here
            }
        })?;
        Ok(Self { submit })
    }
    /// The addresses for `host`, within `timeout`. A literal IP needs no thread.
    /// `WouldBlock` means the lookup thread is still busy with an earlier request.
    pub(super) fn resolve(&self, host: &str, port: u16, timeout: Duration) -> Answer {
        if let Ok(ip) = host.parse::<IpAddr>() { return Ok(vec![SocketAddr::new(ip, port)]); }
        let (reply, answer) = mpsc::channel();
        let wanted = Arc::new(AtomicBool::new(true));
        let _interest = Interest(wanted.clone());
        self.submit.try_send(Request { host: host.to_owned(), port, reply, wanted }).map_err(|e| match e {
            mpsc::TrySendError::Full(_) => io::Error::from(io::ErrorKind::WouldBlock),
            mpsc::TrySendError::Disconnected(_) => io::Error::from(io::ErrorKind::BrokenPipe),
        })?;
        match answer.recv_timeout(timeout) {
            Ok(answer) => answer,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut.into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
}

fn bounded(input: impl Iterator<Item = SocketAddr>) -> Answer {
    let addresses: Vec<SocketAddr> = input.take(ADDRESSES).collect();
    if addresses.is_empty() { return Err(io::ErrorKind::NotFound.into()); }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, atomic::AtomicUsize};

    #[test]
    fn literal_addresses_resolve_without_the_thread() {
        let lookup = Lookup::with(|_, _| panic!("no lookup for a literal")).unwrap();
        assert_eq!(lookup.resolve("127.0.0.1", 8443, Duration::ZERO).unwrap(), vec![SocketAddr::from(([127, 0, 0, 1], 8443))]);
        assert_eq!(lookup.resolve("::1", 1, Duration::ZERO).unwrap().len(), 1);
    }

    #[test]
    fn a_stalled_lookup_times_out_and_later_requests_fail_fast_until_it_returns() {
        let calls = Arc::new(AtomicUsize::new(0));
        let (release, stall) = mpsc::channel::<()>();
        let stall = Mutex::new(stall);
        let counted = calls.clone();
        let lookup = Lookup::with(move |host, port| {
            counted.fetch_add(1, Ordering::SeqCst);
            if host == "stall" { let _ = stall.lock().unwrap().recv(); }
            Ok(vec![SocketAddr::from(([10, 0, 0, 1], port))])
        }).unwrap();
        // The requester leaves at its deadline while the thread is still inside the lookup.
        assert_eq!(lookup.resolve("stall", 1, Duration::from_millis(20)).unwrap_err().kind(), io::ErrorKind::TimedOut);
        // One more request is buffered and also times out; the next fails at once.
        assert_eq!(lookup.resolve("queued", 2, Duration::from_millis(20)).unwrap_err().kind(), io::ErrorKind::TimedOut);
        let started = std::time::Instant::now();
        assert_eq!(lookup.resolve("refused", 3, Duration::from_secs(5)).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no second thread performs lookups");
        // When the stalled lookup returns, the departed request is skipped and a fresh one is served.
        release.send(()).unwrap();
        // Until the thread has drained the departed request, a new one is still refused at once; then it is served.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let answer = loop {
            match lookup.resolve("fresh", 4, Duration::from_secs(5)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock && std::time::Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                other => break other.unwrap(),
            }
        };
        assert_eq!(answer, vec![SocketAddr::from(([10, 0, 0, 1], 4))]);
        assert_eq!(calls.load(Ordering::SeqCst), 2, "the queued request whose requester left was not looked up");
    }
}
