//! The open-file limit must cover the connection limit. Each connection holds
//! at most `PER_CONNECTION` descriptors (docs/operational-limits.md), and the
//! rest of the process needs `RESERVE`, so before serving the gateway raises
//! its soft `RLIMIT_NOFILE` to that total when the hard limit allows and
//! refuses to start when it does not. Without this a default macOS soft limit
//! of 256 runs out of descriptors at about 60 connections. This is the
//! executable's second C binding: `getrlimit(2)` and `setrlimit(2)` on a
//! local struct, nothing retained. `scripts/check_effect_sites.sh` pins it
//! with signal.rs as the only places the runtime says `unsafe`.
use std::io;

/// Client socket, its cancel handle, write half, and reset probe; the
/// watcher's probe; the upstream socket and its cancel handle.
pub(crate) const PER_CONNECTION: u64 = 7;
/// Standard streams, listener, signal pair, audit segments and the shipper's
/// reader, shipper socket and state files, resolver lookups, and slack.
pub(crate) const RESERVE: u64 = 64;

#[cfg(target_os = "linux")]
const RLIMIT_NOFILE: i32 = 7;
#[cfg(not(target_os = "linux"))]
const RLIMIT_NOFILE: i32 = 8;

#[repr(C)]
struct Rlimit { cur: u64, max: u64 }

extern "C" {
    fn getrlimit(resource: i32, rlim: *mut Rlimit) -> i32;
    fn setrlimit(resource: i32, rlim: *const Rlimit) -> i32;
}

/// The descriptors `connections` need, or `None` on overflow.
pub(crate) fn needed(connections: usize) -> Option<u64> {
    u64::try_from(connections).ok()?.checked_mul(PER_CONNECTION)?.checked_add(RESERVE)
}

/// Make the soft open-file limit at least `needed`, raising it within the hard
/// limit if necessary. Returns the soft limit now in force.
// Effect site: reads and raises this process's own open-file limit, once at startup.
pub(crate) fn ensure(needed: u64) -> io::Result<u64> {
    let mut limit = Rlimit { cur: 0, max: 0 };
    // SAFETY: `limit` is a live, writable struct with the C layout of
    // `struct rlimit` (two 64-bit `rlim_t` on the supported targets).
    if unsafe { getrlimit(RLIMIT_NOFILE, &mut limit) } != 0 { return Err(io::Error::last_os_error()); }
    if limit.cur >= needed { return Ok(limit.cur); }
    if limit.max < needed {
        return Err(io::Error::other(format!("open-file limit {} (hard {}) is below the {needed} descriptors needed", limit.cur, limit.max)));
    }
    let raised = Rlimit { cur: needed, max: limit.max };
    // SAFETY: `raised` is a live struct with the C layout of `struct rlimit`,
    // only read by the call.
    if unsafe { setrlimit(RLIMIT_NOFILE, &raised) } != 0 { return Err(io::Error::last_os_error()); }
    Ok(needed)
}
