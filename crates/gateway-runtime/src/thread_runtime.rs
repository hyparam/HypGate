//! Runtime entry under the verified thread-context permit
//! (`gateway_core::thread_context`). Tokio panics when a runtime is built or
//! blocked on from a thread that already has one entered. Every such site in
//! this crate lives here and spends a `ThreadContext`, which exists only on
//! a thread that has entered no runtime: `main` mints one for the process
//! thread, `spawn_fresh` mints one for each new OS thread, and nothing else
//! may call the constructor (clippy `disallowed-methods`,
//! `scripts/check_effect_sites.sh`). The trusted claims are the two minting
//! sites and Tokio's own precondition; the token discipline is types.
use gateway_core::thread_context::{RuntimeEntry, ThreadContext};
use std::{future::Future, io, marker::PhantomData};

/// A Tokio runtime entered on the thread that gave up its context. It is not
/// `Send`, so it stays on that thread, where no other runtime can be entered
/// while it exists.
pub struct EnteredRuntime { runtime: tokio::runtime::Runtime, entry: RuntimeEntry, _thread: PhantomData<*const ()> }

impl EnteredRuntime {
    /// Build a current-thread runtime, spending the thread's context. A build
    /// failure enters nothing and hands the context back.
    // Effect site: the only runtime construction; the thread's permit is consumed.
    #[allow(clippy::disallowed_methods)]
    pub fn current_thread(context: ThreadContext) -> Result<Self, (ThreadContext, io::Error)> {
        match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => Ok(Self { runtime, entry: context.enter(), _thread: PhantomData }),
            Err(error) => Err((context, error)),
        }
    }
    /// Run a future to completion on this runtime. Sound because `self` is
    /// pinned to the thread whose context it holds.
    // Effect site: the only `Runtime::block_on`.
    #[allow(clippy::disallowed_methods)]
    pub fn block_on<F: Future>(&self, future: F) -> F::Output { self.runtime.block_on(future) }
    /// Shut the runtime down and give the thread its context back.
    pub fn leave(self) -> ThreadContext { drop(self.runtime); self.entry.exit() }
}

/// Drive a future on another runtime, through its handle, from a thread that
/// has entered no runtime of its own. The borrowed context is the evidence,
/// and it is held for the whole call.
// Effect site: the only `Handle::block_on`.
#[allow(clippy::disallowed_methods)]
pub fn block_on_handle<F: Future>(context: &mut ThreadContext, handle: &tokio::runtime::Handle, future: F) -> F::Output {
    let _held = context;
    handle.block_on(future)
}

/// Start an OS thread whose body receives the thread's own fresh context.
// Effect site: a new OS thread has entered no runtime; the only `ThreadContext::fresh` outside `main`.
#[allow(clippy::disallowed_methods)]
pub fn spawn_fresh<R: Send + 'static>(builder: std::thread::Builder, body: impl FnOnce(ThreadContext) -> R + Send + 'static)
    -> io::Result<std::thread::JoinHandle<R>> {
    builder.spawn(move || body(ThreadContext::fresh()))
}
