# Thread context permit

Tokio panics when a runtime is built or blocked on from a thread that already
has a runtime entered. That is a precondition of a trusted library, checked at
run time against thread-local state, and nothing in the type system saw it:
`loggate ship` built the shipper's runtime on the thread that was already
running the executable's and panicked at startup. This page records how that
class of fault is now excluded by types, what is proved, and what is trusted.

## The permit

`gateway_core::thread_context` defines two affine tokens with ghost depth:

- `ThreadContext`: the thread has entered no runtime (depth zero).
- `RuntimeEntry`: exactly one runtime is entered on the thread (depth one).

`ThreadContext::fresh` mints a context, `ThreadContext::enter` consumes it and
returns an entry, and `RuntimeEntry::exit` consumes the entry and returns a
context. Both structs have private fields, so these are the only producers.
Entering a runtime spends the thread's one context; while the entry exists
there is no context to spend on another.

## The sites

Every runtime entry in `gateway-runtime` is in `thread_runtime.rs` and spends
a token:

| Site | Takes | Does |
| --- | --- | --- |
| `EnteredRuntime::current_thread` | `ThreadContext` by value | Builds the current-thread runtime and holds the `RuntimeEntry`; the type is not `Send`, so it stays on the thread whose context it holds |
| `EnteredRuntime::block_on` | `&self` | The only `Runtime::block_on` |
| `block_on_handle` | `&mut ThreadContext` | The only `Handle::block_on`: drives a future on another runtime from a thread that has entered none, holding the borrow for the call |
| `spawn_fresh` | a `std::thread::Builder` and a body | Starts an OS thread and hands its body a fresh context |
| `main::main` | nothing | Mints the process thread's context |

`clippy.toml` disallows `Builder::build`, `Runtime::block_on`,
`Handle::block_on`, `block_in_place`, and `ThreadContext::fresh` everywhere
else, and `scripts/check_effect_sites.sh` pins the five sites beside the
socket, file, and secret sites. The script also refuses `#[tokio::main]` in
the runtime source, since the macro would enter a runtime outside the lint's
reach; the executable enters its runtime explicitly.

Who holds a context today: the executable's main thread, spent on the gateway
runtime or, for `loggate ship`, on the shipping loop's runtime; the shipper
thread, spent on its own runtime; each credited-job worker thread in the DNS
and TLS handshake pools, kept for the thread's life and lent to each job, which
is how a handshake job may block on the gateway runtime's handle. Threads
started without `spawn_fresh`, such as the audit log worker, hold no context
and so cannot enter a runtime at all.

## Proved, typed, trusted

Proved (Verus, `thread_context.rs`): a fresh context has depth zero, entering
yields depth one, exiting returns depth zero; three mutations in
`scripts/check_mutations.py` guard those postconditions.

Typed (Rust ownership and the private constructors): a context is spent by at
most one entry, an entry is pinned to its thread, and a thread that holds no
context cannot enter a runtime. The lint and the pinned-site script are what
make the constructor and the Tokio calls unreachable elsewhere.

Trusted: that the process main thread and a newly spawned OS thread have
entered no runtime, which is what the two minting sites claim; and that Tokio
panics on runtime construction and `block_on` only when a runtime is already
entered on the thread, so that the permit's meaning matches the library's
precondition. Tokio's own internals are outside the proof, as before.

## What it does not cover

The permit tracks runtime entry, not every panicking precondition of every
dependency. Mutex poisoning and indexing are handled separately (poison is
observed and fails readiness; the shipping adapters deny indexing by lint).
Other dynamic preconditions of Tokio or Hyper, for example calling
`Handle::current` outside a runtime, remain run-time checks; the approach here
is the template for turning any of them into a typed permit if they matter.
