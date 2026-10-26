//! Deadlines and cancellation over blocking sockets. A `Deadline` is an
//! instant; a `Timed` stream sets the socket timeout to the time left before
//! every read and write, so one deadline bounds a whole exchange and a peer
//! that trickles bytes cannot outlast it. A `Cancel` lets another thread end
//! an exchange by shutting down its sockets, which makes the blocked thread's
//! next operation fail; the thread then reads the flag to tell cancellation
//! from a fault. There is no executor anywhere in this crate.
use std::{io::{self, Read, Write}, net::{Shutdown, TcpStream}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};

/// The instant an operation must be finished by.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Deadline { end: Instant }
impl Deadline {
    pub(crate) fn start(total: Duration) -> io::Result<Self> {
        Ok(Self { end: Instant::now().checked_add(total).ok_or(io::ErrorKind::InvalidInput)? })
    }
    /// The time left, or `TimedOut` once none is.
    pub(crate) fn remaining(&self) -> io::Result<Duration> {
        let left = self.end.saturating_duration_since(Instant::now());
        if left.is_zero() { Err(io::ErrorKind::TimedOut.into()) } else { Ok(left) }
    }
    /// The nearer of two deadlines.
    pub(crate) fn min(self, other: Deadline) -> Deadline { Deadline { end: self.end.min(other.end) } }
}

/// A stream over one TCP socket whose timeouts can be set.
pub(crate) trait Socket: Read + Write { fn socket(&self) -> &TcpStream; }
impl Socket for TcpStream { fn socket(&self) -> &TcpStream { self } }
impl Socket for rustls::StreamOwned<rustls::ClientConnection, TcpStream> { fn socket(&self) -> &TcpStream { &self.sock } }
impl Socket for rustls::StreamOwned<rustls::ServerConnection, TcpStream> { fn socket(&self) -> &TcpStream { &self.sock } }

/// A stream under a deadline. Every read and write first sets the socket
/// timeout to the time left; a timeout is remembered so the caller can tell
/// it from a protocol fault after the fact.
pub(crate) struct Timed<S> { inner: S, deadline: Deadline, expired: bool }
impl<S: Socket> Timed<S> {
    pub(crate) fn new(inner: S, deadline: Deadline) -> Self { Self { inner, deadline, expired: false } }
    pub(crate) fn expired(&self) -> bool { self.expired }
    pub(crate) fn inner(&self) -> &S { &self.inner }
    pub(crate) fn into_inner(self) -> S { self.inner }
    /// Point the socket timeouts at the deadline; `TimedOut` once it has passed.
    pub(crate) fn arm(&mut self) -> io::Result<()> {
        match self.deadline.remaining() {
            Ok(left) => { self.inner.socket().set_read_timeout(Some(left))?; self.inner.socket().set_write_timeout(Some(left)) }
            Err(e) => { self.expired = true; Err(e) }
        }
    }
    fn note<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if let Err(e) = &result {
            if matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) { self.expired = true; }
        }
        result
    }
}
impl<S: Socket> Read for Timed<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> { self.arm()?; let result = self.inner.read(out); self.note(result) }
}
impl<S: Socket> Write for Timed<S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { self.arm()?; let result = self.inner.write(bytes); self.note(result) }
    fn flush(&mut self) -> io::Result<()> { self.arm()?; let result = self.inner.flush(); self.note(result) }
}
impl Timed<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    /// Drive the TLS handshake to completion under the deadline.
    pub(crate) fn handshake(&mut self) -> io::Result<()> {
        while self.inner.conn.is_handshaking() {
            self.arm()?;
            let step = self.inner.conn.complete_io(&mut self.inner.sock).map(|_| ());
            self.note(step)?;
        }
        Ok(())
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
