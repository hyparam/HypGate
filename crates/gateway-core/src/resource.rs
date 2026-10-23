use vstd::prelude::*;
use crate::policy::AuthorizedRequest;
use crate::stream::StreamChunk;

verus! {

// Keys are scoped to one ResourceAdmission instance. Production will use one registry.
pub struct RequestKey { slot: usize, id: u64, stream_claimed: bool }
pub struct ResourceAdmission {
    slots: Vec<u64>,
    next: u64,
    per_request: usize,
}

impl RequestKey {
    pub closed spec fn stream_claimed(&self) -> bool { self.stream_claimed }
    pub closed spec fn slot(&self) -> nat { self.slot as nat }
    pub closed spec fn id(&self) -> u64 { self.id }
    pub fn owner(&self) -> (out: u64)
        ensures out == self.id(),
    { self.id }
}

impl ResourceAdmission {
    pub closed spec fn entries(&self) -> Seq<u64> { self.slots@ }
    pub closed spec fn next_id(&self) -> u64 { self.next }
    pub closed spec fn limit(&self) -> nat { self.slots.len() as nat }
    pub closed spec fn per_request(&self) -> nat { self.per_request as nat }
    pub closed spec fn owns(&self, key: &RequestKey) -> bool {
        key.slot < self.slots.len() && key.id != 0 && self.slots@[key.slot as int] == key.id
    }
    pub closed spec fn valid(&self) -> bool {
        self.next > 0
        && (forall|i: int| 0 <= i < self.slots.len() ==> #[trigger] self.slots@[i] < self.next)
        && (forall|i: int, j: int| 0 <= i < j < self.slots.len()
            && self.slots@[i] != 0 && self.slots@[j] != 0
            ==> self.slots@[i] != self.slots@[j])
    }

    pub fn new(request_limit: usize, per_request: usize) -> (a: Self)
        ensures a.valid(), a.limit() == request_limit, a.per_request() == per_request,
            a.next_id() == 1,
            forall|i: int| 0 <= i < a.limit() ==> #[trigger] a.entries()[i] == 0,
    {
        let mut slots = Vec::new();
        while slots.len() < request_limit
            invariant slots.len() <= request_limit,
                forall|i: int| 0 <= i < slots.len() ==> #[trigger] slots@[i] == 0,
            decreases request_limit - slots.len(),
        { slots.push(0u64); }
        ResourceAdmission { slots, next: 1, per_request }
    }

    pub fn acquire(&mut self) -> (out: Option<RequestKey>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            final(self).per_request() == old(self).per_request(),
            match out {
                Some(key) => final(self).owns(&key) && !key.stream_claimed() && key.id() == old(self).next_id()
                    && final(self).next_id() == old(self).next_id() + 1
                    && old(self).entries()[key.slot() as int] == 0
                    && (forall|i: int| 0 <= i < old(self).limit() && i != key.slot()
                        ==> #[trigger] final(self).entries()[i] == old(self).entries()[i]),
                None => *final(self) == *old(self) && (old(self).next_id() == u64::MAX
                    || forall|i: int| 0 <= i < old(self).limit() ==> #[trigger] old(self).entries()[i] != 0),
            },
    {
        if self.next == u64::MAX { return None; }
        let mut i: usize = 0;
        while i < self.slots.len()
            invariant self.valid(), *self == *old(self), self.next < u64::MAX,
                i <= self.slots.len(),
                forall|j: int| 0 <= j < i ==> #[trigger] self.slots@[j] != 0,
            decreases self.slots.len() - i,
        {
            if self.slots[i] == 0 {
                let id = self.next;
                self.slots.set(i, id);
                self.next = self.next + 1;
                return Some(RequestKey { slot: i, id, stream_claimed: false });
            }
            i = i + 1;
        }
        None
    }

    pub fn capacity(&self, key: &RequestKey) -> (out: Option<usize>)
        requires self.valid(),
        ensures match out {
            Some(n) => self.owns(key) && n == self.per_request(),
            None => !self.owns(key),
        },
    {
        if key.slot >= self.slots.len() || key.id == 0 || self.slots[key.slot] != key.id {
            return None;
        }
        Some(self.per_request)
    }

    // One initial stream per reserved key, bound to the authorized request ID.
    pub fn authorized_stream(&self, key: &mut RequestKey, authority: &AuthorizedRequest, strict: bool)
        -> (out: Option<StreamChunk>)
        requires self.valid(), authority.valid(),
        ensures final(key).slot() == old(key).slot(), final(key).id() == old(key).id(),
            match out {
                Some(stream) => self.owns(final(key)) && !old(key).stream_claimed()
                    && final(key).stream_claimed() && stream.valid()
                    && stream.owner() == authority.request() && stream.owner() == final(key).id()
                    && stream.capacity() == self.per_request() && stream.body().len() == 0
                    && stream.strict() == strict && !stream.closed() && !stream.pending(),
                None => *final(key) == *old(key) && (old(key).stream_claimed()
                    || old(key).id() != authority.request() || !self.owns(old(key))),
            },
    {
        if key.stream_claimed || key.id != authority.request_id() { return None; }
        match self.capacity(key) {
            Some(capacity) => {
                let stream = StreamChunk::new(key.id, Vec::new(), capacity, strict);
                key.stream_claimed = true;
                stream
            },
            None => None,
        }
    }

    // The adapter must stop and dispose of request work before returning its credit.
    pub fn release(&mut self, key: &RequestKey) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            final(self).per_request() == old(self).per_request(),
            final(self).next_id() == old(self).next_id(),
            ok ==> old(self).owns(key) && !final(self).owns(key)
                && final(self).entries()[key.slot() as int] == 0
                && (forall|i: int| 0 <= i < old(self).limit() && i != key.slot()
                    ==> #[trigger] final(self).entries()[i] == old(self).entries()[i]),
            !ok ==> !old(self).owns(key) && *final(self) == *old(self),
    {
        if key.slot >= self.slots.len() || key.id == 0 || self.slots[key.slot] != key.id {
            return false;
        }
        self.slots.set(key.slot, 0);
        true
    }
}
}
