//! Termination signals end the gateway through the cooperative drain instead
//! of the kernel's default action. This is the executable's one C binding and
//! its only `unsafe`: `signal(2)` installs a handler that does nothing but
//! `write(2)` one byte to a socket pair, which is async-signal-safe, and a
//! thread reading the other end triggers `Shutdown`. Nothing is decided
//! here; the drain that follows is `server::serve`'s (docs/shutdown-proof.md).
//! A second signal during the drain is absorbed, the drain is bounded, and
//! SIGKILL stays available. `scripts/check_effect_sites.sh` pins this file as
//! the only place the runtime says `unsafe`.
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicI32, Ordering};

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;
/// `SIG_ERR`, `(void (*)(int)) -1`.
const SIG_ERR: usize = usize::MAX;
const STACK_BYTES: usize = 64 * 1024;

/// The writing end of the socket pair, once installed. Read only by the handler.
static WAKE: AtomicI32 = AtomicI32::new(-1);

extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
    fn write(fd: i32, buf: *const std::ffi::c_void, count: usize) -> isize;
}

extern "C" fn on_signal(_signum: i32) {
    let fd = WAKE.load(Ordering::Acquire);
    if fd < 0 { return; }
    let byte = 0u8;
    // SAFETY: `write` is async-signal-safe; `fd` is the writing end of a
    // socket pair that `on_termination` leaked, so it stays open for the life
    // of the process, and `byte` outlives the call.
    unsafe { write(fd, std::ptr::from_ref(&byte).cast(), 1); }
}

/// Run `then` on its own thread when SIGTERM or SIGINT first arrives. Call
/// once, before serving; later signals are absorbed.
// Effect site: the executable's one C binding, installing the termination
// signal handlers that make SIGTERM and SIGINT a cooperative drain.
pub(crate) fn on_termination(then: impl FnOnce() + Send + 'static) -> io::Result<()> {
    let (mut reader, writer) = UnixStream::pair()?;
    WAKE.store(writer.as_raw_fd(), Ordering::Release);
    std::mem::forget(writer); // the handler may fire at any later moment
    let handler = on_signal as extern "C" fn(i32) as usize;
    // SAFETY: `signal` is called with a valid signal number and a handler of
    // the C signature it expects; the handler touches only an atomic and
    // calls one async-signal-safe function.
    let installed = unsafe { signal(SIGTERM, handler) != SIG_ERR && signal(SIGINT, handler) != SIG_ERR };
    if !installed { return Err(io::Error::other("cannot install signal handlers")); }
    std::thread::Builder::new().name("loggate-signal".into()).stack_size(STACK_BYTES).spawn(move || {
        let mut byte = [0u8; 1];
        let _ = reader.read(&mut byte);
        then();
    })?;
    Ok(())
}
