//! A registered resource scope always cleans up after its body returns,
//! independently of the body's output (including every Result::Err).
//! The adapter binds registration and destruction; unwinding is outside Verus.
use vstd::prelude::*;

verus! {
pub trait Effects {
    type Output;
    spec fn active(&self) -> bool;
    spec fn cleanups(&self) -> nat;
    fn body(&mut self) -> Self::Output
        requires old(self).active(),
        ensures final(self).active(), final(self).cleanups() == old(self).cleanups();
    fn cleanup(&mut self)
        requires old(self).active(),
        ensures !final(self).active(), final(self).cleanups() == old(self).cleanups() + 1;
}

/// There is no output-dependent early return between work and cleanup.
pub fn run<E: Effects>(effects: &mut E) -> (out: E::Output)
    requires old(effects).active(),
    ensures !final(effects).active(), final(effects).cleanups() == old(effects).cleanups() + 1,
{
    let output = effects.body();
    effects.cleanup();
    output
}
}
