//! Deadlines and cancellation over blocking sockets. A `Deadline` is an
//! instant; a `Timed` stream sets the socket timeout to the time left before
//! raw read and write, including rustls internal retries. The verified driver
//! prevents budget renewal and rejects late results; OS timeouts and scheduling
//! remain trusted. A `Cancel` lets another thread end
//! an exchange by shutting down its sockets, which makes the blocked thread's
//! next operation fail; the thread then reads the flag to tell cancellation
//! from a fault. There is no executor anywhere in this crate.
use std::{io::{self, Read, Write}, net::{Shutdown, TcpStream}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};

/// One immutable origin and end, shared by TCP and all TLS operations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline { origin: Instant, end: Instant }
impl Deadline {
    pub(crate) fn start(total: Duration) -> io::Result<Self> {
        let origin = Instant::now();
        Ok(Self { origin, end: origin.checked_add(total).ok_or(io::ErrorKind::InvalidInput)? })
    }
    fn budget(&self) -> u128 { self.end.duration_since(self.origin).as_nanos() }
    fn elapsed(&self) -> u128 { self.origin.elapsed().as_nanos() }
    pub(crate) fn remaining(&self) -> io::Result<Duration> {
        gateway_core::deadline::remaining(self.budget(), self.elapsed())
            .map(duration).ok_or_else(|| io::ErrorKind::TimedOut.into())
    }
    pub(crate) fn min(self, other: Deadline) -> Deadline { if self.end <= other.end { self } else { other } }
}

// A Duration's nanoseconds fit u128; the remaining budget cannot exceed the
// original Duration. Conversion preserves seconds and fractional nanoseconds.
fn duration(nanos: u128) -> Duration {
    Duration::new((nanos / 1_000_000_000) as u64, (nanos % 1_000_000_000) as u32)
}

/// Trusted binding for the verified per-operation driver. This closure is
/// at most one raw TcpStream read/write/flush, never a rustls operation.
struct SocketIo<'a, F> { socket: &'a TcpStream, deadline: Deadline, operation: F }
impl<T, F: FnMut(&TcpStream) -> io::Result<T>> gateway_core::deadline::Io for SocketIo<'_, F> {
    type Output = io::Result<T>;
    fn now(&mut self) -> u128 { self.deadline.elapsed() }
    fn perform(&mut self, budget: u128) -> Self::Output {
        let timeout = duration(budget);
        self.socket.set_read_timeout(Some(timeout))?;
        self.socket.set_write_timeout(Some(timeout))?;
        (self.operation)(self.socket)
    }
}

/// Only raw TCP implements this adapter's I/O. In particular, a TLS stream
/// cannot accidentally be wrapped here instead of wrapping its raw socket.
pub(crate) struct Timed<S> { inner: S, deadline: Deadline, expired: bool }
impl Timed<TcpStream> {
    pub(crate) fn new(inner: TcpStream, deadline: Deadline) -> Self { Self { inner, deadline, expired: false } }
    pub(crate) fn inner(&self) -> &TcpStream { &self.inner }
    pub(crate) fn into_inner(self) -> TcpStream { self.inner }
    pub(crate) fn expired(&self) -> bool { self.expired }
    fn operate<T>(&mut self, operation: impl FnMut(&TcpStream) -> io::Result<T>) -> io::Result<T> {
        let mut effect = SocketIo { socket: &self.inner, deadline: self.deadline, operation };
        let result = gateway_core::deadline::run(&mut effect, self.deadline.budget())
            .unwrap_or_else(|| Err(io::ErrorKind::TimedOut.into()));
        if let Err(e) = &result {
            if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) { self.expired = true; }
        }
        result
    }
}
impl Read for Timed<TcpStream> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> { self.operate(|mut socket| socket.read(out)) }
}
impl Write for Timed<TcpStream> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.operate(|mut socket| socket.write(bytes)) }
    fn flush(&mut self) -> io::Result<()> { self.operate(|mut socket| socket.flush()) }
}

/// TLS has no raw socket access: every internal retry crosses the verified
/// deadline driver. Outer checks also cover buffered plaintext and TLS CPU work.
pub(crate) struct Tls {
    inner: rustls::StreamOwned<rustls::ClientConnection, Timed<TcpStream>>,
    deadline: Deadline,
    expired: bool,
}
impl Tls {
    pub(crate) fn new(conn: rustls::ClientConnection, socket: TcpStream, deadline: Deadline) -> Self {
        Self { inner: rustls::StreamOwned::new(conn, Timed::new(socket, deadline)), deadline, expired: false }
    }
    pub(crate) fn expired(&self) -> bool { self.expired || self.inner.sock.expired() }
    fn check(&mut self) -> io::Result<()> {
        if self.deadline.remaining().is_err() { self.expired = true; Err(io::ErrorKind::TimedOut.into()) } else { Ok(()) }
    }
    fn note<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        self.check()?;
        if self.inner.sock.expired() { self.expired = true; return Err(io::ErrorKind::TimedOut.into()); }
        result
    }
    pub(crate) fn handshake(&mut self) -> io::Result<()> {
        self.check()?;
        while self.inner.conn.is_handshaking() {
            let step = self.inner.conn.complete_io(&mut self.inner.sock).map(|_| ());
            self.note(step)?;
        }
        self.check()
    }
}
impl Read for Tls {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.inner.read(out);
        self.note(result)
    }
}
impl Write for Tls {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        let result = self.inner.write(bytes);
        self.note(result)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        let result = self.inner.flush();
        self.note(result)
    }
}

/// Cooperative cancellation of one exchange. Sockets registered here are shut
/// down when it fires, so a thread blocked on them fails its current
/// operation; it then consults `is_cancelled` to attribute the failure.
#[derive(Clone, Default)]
pub(crate) struct Cancel(Arc<CancelState>);
#[derive(Default)]
struct CancelState { fired: AtomicBool, sockets: Mutex<Vec<TcpStream>> }
impl Cancel {
    pub(crate) fn new() -> Self { Self::default() }
    pub(crate) fn is_cancelled(&self) -> bool { self.0.fired.load(Ordering::Acquire) }
    /// Register a socket to shut down on cancellation. One already cancelled
    /// is shut down now.
    pub(crate) fn watch_socket(&self, socket: &TcpStream) -> io::Result<()> {
        let handle = socket.try_clone()?;
        let mut sockets = self.0.sockets.lock().map_err(|_| io::Error::other("cancel poisoned"))?;
        if self.is_cancelled() { let _ = handle.shutdown(Shutdown::Both); } else { sockets.push(handle); }
        Ok(())
    }
    /// Fire: every registered socket is shut down, and later registrations too.
    pub(crate) fn cancel(&self) {
        self.0.fired.store(true, Ordering::Release);
        if let Ok(mut sockets) = self.0.sockets.lock() {
            for socket in sockets.drain(..) { let _ = socket.shutdown(Shutdown::Both); }
        }
    }
    /// Forget the registered sockets without touching them; the exchange is over.
    pub(crate) fn release_sockets(&self) {
        if let Ok(mut sockets) = self.0.sockets.lock() { sockets.clear(); }
    }
}

/// One read, retried only when the call was interrupted before any byte moved.
pub(crate) fn read_uninterrupted<R: Read + ?Sized>(io: &mut R, out: &mut [u8]) -> io::Result<usize> {
    loop {
        match io.read(out) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}
/// One write, retried only when the call was interrupted before any byte moved.
pub(crate) fn write_uninterrupted<W: Write + ?Sized>(io: &mut W, bytes: &[u8]) -> io::Result<usize> {
    loop {
        match io.write(bytes) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn tls_handshake_and_application_record_trickles_expire() {
        for application in [false, true] {
            let (listener, config, roots) = crate::test_support::tls();
            let address = listener.local_addr().unwrap();
            let peer = std::thread::spawn(move || {
                if application {
                    let mut tls = crate::test_support::accept_tls(&listener, &config).unwrap();
                    crate::test_support::trickle_record(&mut tls.sock, 23);
                } else {
                    let (mut socket, _) = listener.accept().unwrap();
                    socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                    socket.read(&mut [0; 4096]).unwrap();
                    crate::test_support::trickle_record(&mut socket, 22);
                }
            });
            let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
            let conn = rustls::ClientConnection::new(Arc::new(config), rustls::pki_types::ServerName::try_from("localhost").unwrap()).unwrap();
            let started = Instant::now();
            let mut tls = Tls::new(conn, TcpStream::connect(address).unwrap(), Deadline::start(Duration::from_millis(300)).unwrap());
            let result = if application { tls.handshake().unwrap(); tls.read(&mut [0; 1]).map(|_| ()) } else { tls.handshake() };
            assert!(matches!(result, Err(ref e) if e.kind() == io::ErrorKind::TimedOut), "{result:?}");
            assert!(tls.expired());
            assert!(started.elapsed() < Duration::from_millis(900), "application={application}");
            drop(tls);
            peer.join().unwrap();
        }
    }

    #[test]
    fn cancelling_a_trickled_handshake_does_not_report_timeout() {
        let (listener, _, roots) = crate::test_support::tls();
        let address = listener.local_addr().unwrap();
        let cancel = Cancel::new();
        let signal = cancel.clone();
        let peer = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            socket.read(&mut [0; 4096]).unwrap();
            socket.write_all(&[22, 3, 3, 4, 0, 0]).unwrap();
            signal.cancel();
        });
        let config = rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let conn = rustls::ClientConnection::new(Arc::new(config), rustls::pki_types::ServerName::try_from("localhost").unwrap()).unwrap();
        let socket = TcpStream::connect(address).unwrap();
        cancel.watch_socket(&socket).unwrap();
        let mut tls = Tls::new(conn, socket, Deadline::start(Duration::from_secs(5)).unwrap());
        assert!(tls.handshake().is_err());
        assert!(cancel.is_cancelled());
        assert!(!tls.expired());
        peer.join().unwrap();
    }

    #[test]
    fn a_passed_deadline_is_timed_out_and_arming_remembers_it() {
        let deadline = Deadline::start(Duration::from_millis(1)).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(deadline.remaining().unwrap_err().kind(), io::ErrorKind::TimedOut);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut timed = Timed::new(socket, deadline);
        assert!(!timed.expired());
        assert_eq!(timed.read(&mut [0; 4]).unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(timed.expired());
    }

    #[test]
    fn a_read_that_outlives_the_deadline_times_out_without_data() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let mut timed = Timed::new(socket, Deadline::start(Duration::from_millis(50)).unwrap());
        let started = Instant::now();
        let error = timed.read(&mut [0; 4]).unwrap_err();
        assert!(matches!(error.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(timed.expired());
    }

    #[test]
    fn cancel_shuts_registered_sockets_and_those_registered_later() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let cancel = Cancel::new();
        cancel.watch_socket(&socket).unwrap();
        let reader = cancel.clone();
        let waiter = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            reader.cancel();
        });
        let mut timed = Timed::new(socket, Deadline::start(Duration::from_secs(5)).unwrap());
        // The blocked read ends with EOF or an error once the socket is shut down.
        let outcome = timed.read(&mut [0; 4]);
        assert!(matches!(outcome, Ok(0) | Err(_)), "{outcome:?}");
        waiter.join().unwrap();
        assert!(cancel.is_cancelled());
        let late = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        cancel.watch_socket(&late).unwrap();
        let mut late = Timed::new(late, Deadline::start(Duration::from_secs(5)).unwrap());
        assert!(matches!(late.read(&mut [0; 4]), Ok(0) | Err(_)));
    }
}
