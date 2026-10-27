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
