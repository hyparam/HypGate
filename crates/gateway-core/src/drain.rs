//! Closeable worker admission: closure preserves outstanding credits and makes
//! their occupancy a decreasing drain rank. Scheduler fairness is external.
use vstd::prelude::*;
use crate::resource::{ResourceAdmission, RequestKey};

verus! {
pub struct DrainRegistry { registry: ResourceAdmission, closed: bool }
impl DrainRegistry {
    pub closed spec fn state(&self) -> ResourceAdmission { self.registry }
    pub open spec fn valid(&self) -> bool { self.state().valid() }
    pub closed spec fn closed(&self) -> bool { self.closed }
    pub open spec fn remaining(&self) -> nat { crate::resource::occupied(self.state().entries()) }
    pub open spec fn limit(&self) -> nat { self.state().limit() }
    pub open spec fn owns(&self, key: &RequestKey) -> bool { self.state().owns(key) }

    pub fn new(limit: usize) -> (out: Self)
        ensures out.valid(), !out.closed(), out.remaining() == 0, out.limit() == limit,
    {
        Self { registry: ResourceAdmission::new(limit, 0), closed: false }
    }
    pub fn is_closed(&self) -> (out: bool)
        ensures out == self.closed(),
    { self.closed }
    pub fn usage(&self) -> (out: (usize, usize))
        requires self.valid(),
        ensures out.0 == self.remaining(), out.1 == self.limit(), out.0 <= out.1,
    { self.registry.usage() }
    pub fn close(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).closed(),
            final(self).remaining() == old(self).remaining(),
            final(self).limit() == old(self).limit(),
            final(self).state() == old(self).state(),
    { self.closed = true; }
    pub fn acquire(&mut self) -> (out: Option<RequestKey>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).closed() == old(self).closed(),
            final(self).limit() == old(self).limit(),
            final(self).remaining() <= final(self).limit(),
            final(self).state().per_request() == old(self).state().per_request(),
            match out {
                Some(key) => !old(self).closed() && !key.stream_claimed()
                    && final(self).owns(&key)
                    && final(self).remaining() == old(self).remaining() + 1
                    && final(self).state().next_id() == old(self).state().next_id() + 1
                    && key.id() == old(self).state().next_id()
                    && old(self).state().entries()[key.slot() as int] == 0
                    && (forall|i: int| 0 <= i < old(self).limit() && i != key.slot()
                        ==> #[trigger] final(self).state().entries()[i] == old(self).state().entries()[i]),
                None => *final(self) == *old(self) && (old(self).closed()
                    || old(self).state().next_id() == u64::MAX
                    || forall|i: int| 0 <= i < old(self).limit()
                        ==> #[trigger] old(self).state().entries()[i] != 0),
            },
    {
        let out = if self.closed { None } else { self.registry.acquire() };
        proof { self.registry.layout(); crate::resource::occupied_bound(self.registry.entries()); }
        out
    }
    pub fn release(&mut self, key: &RequestKey) -> (out: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).closed() == old(self).closed(),
            final(self).limit() == old(self).limit(),
            out == (!key.stream_claimed() && old(self).owns(key)),
            final(self).state().next_id() == old(self).state().next_id(),
            final(self).state().per_request() == old(self).state().per_request(),
            out ==> final(self).remaining() + 1 == old(self).remaining()
                && !final(self).owns(key)
                && (forall|i: int| 0 <= i < old(self).limit() && i != key.slot()
                    ==> #[trigger] final(self).state().entries()[i] == old(self).state().entries()[i]),
            !out ==> *final(self) == *old(self),
    { self.registry.release(key) }
}

// A finite trace of successful releases after closure has this exact rank.
// The runtime correspondence and eventual scheduling of each owner destruction
// are separate obligations; this theorem does not assume a wall-clock bound.
pub proof fn drain_trace_rank(states: Seq<nat>)
    requires states.len() > 0,
        forall|i: int| 0 <= i < states.len() - 1 ==> #[trigger] states[i + 1] + 1 == states[i],
    ensures states.last() + states.len() - 1 == states[0],
        states.len() <= states[0] + 1,
        states.len() == states[0] + 1 ==> states.last() == 0,
    decreases states.len(),
{
    if states.len() > 1 {
        let prefix = states.subrange(0, states.len() as int - 1);
        drain_trace_rank(prefix);
        assert(states[states.len() as int - 2 + 1] + 1 == states[states.len() as int - 2]);
        assert(prefix.last() == states[states.len() as int - 2]);
    }
}
}
