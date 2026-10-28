//! Deadline mediation for every primitive socket operation, including calls
//! made inside TLS. Time is nanoseconds from one immutable runtime origin.
//! Clock sampling, timeout installation and primitive I/O are trusted effects;
//! this does not prove OS scheduling or that an arbitrary effect terminates.
use vstd::prelude::*;

verus! {
/// Exact remaining budget: repeated calls never create a fresh deadline.
pub fn remaining(end: u128, now: u128) -> (out: Option<u128>)
    ensures
        out is Some <==> now < end,
        out is Some ==> out.unwrap() > 0 && now + out.unwrap() == end,
{
    if now < end { Some(end - now) } else { None }
}

/// A deadline lineage: descendants may shorten the end, never renew the root.
/// All times are measured from the same origin supplied by the adapter.
#[derive(Clone, Copy, Debug)]
pub struct Budget { root: u128, end: u128 }
impl Budget {
    pub closed spec fn root(&self) -> u128 { self.root }
    pub closed spec fn end(&self) -> u128 { self.end }
    pub open spec fn valid(&self) -> bool { self.end() <= self.root() }

    pub fn new(end: u128) -> (out: Self)
        ensures out.valid(), out.root() == end, out.end() == end,
    { Self { root: end, end } }

    /// Overflow cannot renew a deadline; the ancestor remains the upper bound.
    pub fn limit(&self, now: u128, duration: u128) -> (out: Self)
        requires self.valid(),
        ensures out.valid(), out.root() == self.root(), out.end() <= self.end(),
            out.end() == if now + duration < self.end() { now + duration } else { self.end() as int },
    {
        let end = if now < self.end && duration < self.end - now { now + duration } else { self.end };
        Self { root: self.root, end }
    }

    pub fn remaining(&self, now: u128) -> (out: Option<u128>)
        requires self.valid(),
        ensures out.is_some() == (now < self.end()),
            out is Some ==> now + out.unwrap() == self.end() && now + out.unwrap() <= self.root(),
    { remaining(self.end, now) }

    pub fn end_value(&self) -> (out: u128) ensures out == self.end(), { self.end }

    /// Every descendant operation is capped by both its end and its ancestor.
    /// The I/O effect is still trusted to honor the supplied timeout.
    pub fn run<I: Io>(&self, io: &mut I) -> (out: Option<I::Output>)
        requires self.valid(),
        ensures old(io).calls() <= final(io).calls() <= old(io).calls() + 1,
            old(io).clock() >= self.end() ==> final(io).calls() == old(io).calls(),
            final(io).calls() > old(io).calls() ==> final(io).last_start() < self.end()
                && final(io).last_start() + final(io).last_budget() == self.end()
                && final(io).last_start() + final(io).last_budget() <= self.root(),
            out is Some ==> final(io).clock() < self.end() && final(io).clock() < self.root(),
            out is None ==> final(io).clock() >= self.end(),
    { run(io, self.end) }
}

/// One primitive operation attempt, not a TLS operation containing hidden retries.
/// `calls` counts attempts, including timeout-installation failures before I/O.
/// The ghost observations make the driver's mediation guarantee explicit.
pub trait Io {
    type Output;
    spec fn clock(&self) -> u128;
    spec fn calls(&self) -> nat;
    spec fn last_start(&self) -> u128;
    spec fn last_budget(&self) -> u128;

    fn now(&mut self) -> (out: u128)
        ensures out == final(self).clock(), final(self).clock() >= old(self).clock(),
            final(self).calls() == old(self).calls(),
            final(self).last_start() == old(self).last_start(),
            final(self).last_budget() == old(self).last_budget();

    fn perform(&mut self, budget: u128) -> (out: Self::Output)
        requires budget > 0,
        ensures final(self).calls() == old(self).calls() + 1,
            final(self).last_start() == old(self).clock(),
            final(self).last_budget() == budget,
            final(self).clock() >= old(self).clock();
}

/// Check, perform at most one primitive I/O with the exact remaining budget,
/// then check again. Even a successful late effect is rejected. None means
/// deadline expiry, not that no bytes moved (there must be no replay).
pub fn run<I: Io>(io: &mut I, end: u128) -> (out: Option<I::Output>)
    ensures
        old(io).calls() <= final(io).calls() <= old(io).calls() + 1,
        old(io).clock() >= end ==> final(io).calls() == old(io).calls(),
        final(io).calls() > old(io).calls() ==>
            final(io).last_start() < end
            && final(io).last_budget() > 0
            && final(io).last_start() + final(io).last_budget() == end,
        out is Some ==> final(io).calls() == old(io).calls() + 1 && final(io).clock() < end,
        out is None ==> final(io).clock() >= end,
{
    let start = io.now();
    match remaining(end, start) {
        None => None,
        Some(budget) => {
            let result = io.perform(budget);
            let finish = io.now();
            if finish < end { Some(result) } else { None }
        }
    }
}

/// Composition across any two retries using the same end: a later start can
/// only reduce the allowance. Trickle input cannot renew the budget.
pub proof fn retries_do_not_extend(end: u128, first: u128, later: u128)
    requires first <= later < end,
    ensures 0 < end - later <= end - first,
        later + (end - later) == end,
{}
}
