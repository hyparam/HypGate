//! The permit for entering an async runtime on a thread. A Tokio runtime may
//! be built and blocked on only from a thread that has entered no runtime;
//! doing otherwise is a dynamic precondition of the library that panics at
//! run time. This module turns that thread-local fact into an affine token:
//! a `ThreadContext` is minted once at a thread's birth, entering a runtime
//! consumes it and returns a `RuntimeEntry`, and leaving the runtime gives
//! the context back. With the two minting sites and the two entry sites
//! pinned in the runtime crate, a nested entry has no token to spend and is
//! a compile error rather than a panic. The depth is ghost state: the token
//! costs nothing at run time.
use vstd::prelude::*;
verus! {
/// A thread that has entered no runtime. Private field: only `fresh`, whose
/// call sites the runtime pins, and `RuntimeEntry::exit` produce one.
pub struct ThreadContext { depth: Ghost<nat> }
/// A thread with exactly one runtime entered; it holds the thread's context
/// until `exit`.
pub struct RuntimeEntry { depth: Ghost<nat> }
impl ThreadContext {
    pub closed spec fn depth(&self) -> nat { self.depth@ }
    /// The permit means the thread is at nesting depth zero.
    pub open spec fn valid(&self) -> bool { self.depth() == 0 }
    /// The context of a thread at its birth. The claim that the calling
    /// thread has entered no runtime is the runtime crate's, made at exactly
    /// two sites: the process main thread and the body of a spawned thread.
    pub fn fresh() -> (out: Self)
        ensures out.valid(),
    { ThreadContext { depth: Ghost(0nat) } }
    /// Enter a runtime. The context is consumed, so until `RuntimeEntry::exit`
    /// nothing on this thread can enter another.
    pub fn enter(self) -> (out: RuntimeEntry)
        requires self.valid(),
        ensures out.valid(), out.depth() == self.depth() + 1,
    { RuntimeEntry { depth: Ghost(self.depth@ + 1) } }
}
impl RuntimeEntry {
    pub closed spec fn depth(&self) -> nat { self.depth@ }
    /// An entry means exactly one runtime is entered on the thread.
    pub open spec fn valid(&self) -> bool { self.depth() == 1 }
    /// Leave the runtime and give the thread its context back.
    pub fn exit(self) -> (out: ThreadContext)
        requires self.valid(),
        ensures out.valid(), out.depth() + 1 == self.depth(),
    { ThreadContext { depth: Ghost((self.depth@ - 1) as nat) } }
}
}
