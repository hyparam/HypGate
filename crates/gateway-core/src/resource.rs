use vstd::prelude::*;
use crate::policy::AuthorizedRequest;
use crate::stream::StreamChunk;

verus! {

// Normalized configuration limits; this budget covers one payload chunk per slot,
// not HTTP/TLS/log queues, allocator overhead, or whole-process memory.
pub fn validate_limits(requests: usize, chunk_bytes: usize) -> (ok: bool)
    ensures ok == (0 < requests <= 65536 && 0 < chunk_bytes <= 1048576
        && (requests as int) * (chunk_bytes as int) <= 134217728),
{
    if requests == 0 || requests > 65536 || chunk_bytes == 0 || chunk_bytes > 1048576 { return false; }
    assert((requests as int) * (chunk_bytes as int) <= 68719476736) by(nonlinear_arith)
        requires 0 <= requests <= 65536, 0 <= chunk_bytes <= 1048576;
    let total = (requests as u64) * (chunk_bytes as u64);
    total <= 134217728
}

pub open spec fn occupied(slots: Seq<u64>) -> nat
    decreases slots.len(),
{
    if slots.len() == 0 { 0 } else {
        occupied(slots.subrange(0, slots.len() as int - 1))
            + if slots[slots.len() as int - 1] == 0 { 0nat } else { 1nat }
    }
}

// Ghost snapshots of at most one retained stream per registry slot.
pub open spec fn retained_payload(streams: Seq<Option<StreamChunk>>) -> nat
    decreases streams.len(),
{
    if streams.len() == 0 { 0 } else {
        retained_payload(streams.subrange(0, streams.len() as int - 1))
            + match streams[streams.len() as int - 1] { Some(s) => s.body().len(), None => 0nat }
    }
}

pub open spec fn streams_bound(slots: Seq<u64>, streams: Seq<Option<StreamChunk>>, capacity: nat) -> bool {
    streams.len() == slots.len()
        && forall|i: int| 0 <= i < streams.len() ==> match #[trigger] streams[i] {
            Some(s) => slots[i] != 0 && s.owner() == slots[i] && s.valid() && s.capacity() <= capacity,
            None => true,
        }
}

// Preservation rules for the ghost ownership map. These do not assume that
// the next map is valid; they derive it from the prior map and one local event.
pub proof fn reserve_preserves_streams(slots: Seq<u64>, streams: Seq<Option<StreamChunk>>,
    capacity: nat, index: int, owner: u64)
    requires streams_bound(slots, streams, capacity), 0 <= index < slots.len(),
        slots[index] == 0, owner != 0,
    ensures streams_bound(slots.update(index, owner), streams, capacity),
        streams[index].is_none(),
{
    assert(streams[index].is_none());
    assert forall|i: int| 0 <= i < streams.len() implies match #[trigger] streams[i] {
        Some(s) => slots.update(index, owner)[i] != 0
            && s.owner() == slots.update(index, owner)[i] && s.valid() && s.capacity() <= capacity,
        None => true,
    } by { }
}

pub proof fn replace_preserves_streams(slots: Seq<u64>, streams: Seq<Option<StreamChunk>>,
    capacity: nat, index: int, stream: StreamChunk)
    requires streams_bound(slots, streams, capacity), 0 <= index < slots.len(),
        slots[index] != 0, stream.valid(), stream.owner() == slots[index], stream.capacity() <= capacity,
    ensures streams_bound(slots, streams.update(index, Some(stream)), capacity),
{
    assert forall|i: int| 0 <= i < streams.len() implies match
        #[trigger] streams.update(index, Some(stream))[i] {
        Some(s) => slots[i] != 0 && s.owner() == slots[i] && s.valid() && s.capacity() <= capacity,
        None => true,
    } by { }
}

pub proof fn retire_preserves_streams(slots: Seq<u64>, streams: Seq<Option<StreamChunk>>,
    capacity: nat, index: int)
    requires streams_bound(slots, streams, capacity), 0 <= index < slots.len(),
    ensures streams_bound(slots.update(index, 0), streams.update(index, None), capacity),
{
    assert forall|i: int| 0 <= i < streams.len() implies match
        #[trigger] streams.update(index, None)[i] {
        Some(s) => slots.update(index, 0)[i] != 0
            && s.owner() == slots.update(index, 0)[i] && s.valid() && s.capacity() <= capacity,
        None => true,
    } by { }
}

proof fn bound_payload(slots: Seq<u64>, streams: Seq<Option<StreamChunk>>, capacity: nat)
    requires streams_bound(slots, streams, capacity),
    ensures occupied(slots) <= slots.len(), retained_payload(streams) <= occupied(slots) * capacity,
    decreases slots.len(),
{
    if slots.len() > 0 {
        let last = slots.len() as int - 1;
        let before_slots = slots.subrange(0, last);
        let before_streams = streams.subrange(0, last);
        assert(streams_bound(before_slots, before_streams, capacity));
        bound_payload(before_slots, before_streams, capacity);
        let bytes = match streams[last] { Some(s) => s.body().len(), None => 0nat };
        match streams[last] { Some(s) => { s.payload_within_capacity(); }, None => {} }
        assert(bytes <= capacity);
        if slots[last] == 0 {
            assert(bytes == 0);
        } else {
            assert(retained_payload(before_streams) + bytes <= (occupied(before_slots) + 1) * capacity)
                by(nonlinear_arith)
                requires retained_payload(before_streams) <= occupied(before_slots) * capacity,
                    bytes <= capacity;
        }
    }
}

// Changing one slot changes occupancy only by that slot's zero/nonzero status.
proof fn occupied_update(slots: Seq<u64>, index: int, value: u64)
    requires 0 <= index < slots.len(),
    ensures occupied(slots.update(index, value)) + (if slots[index] == 0 { 0nat } else { 1nat })
        == occupied(slots) + (if value == 0 { 0nat } else { 1nat }),
    decreases slots.len(),
{
    let last = slots.len() as int - 1;
    if index == last {
        assert(slots.update(index, value).subrange(0, last) =~= slots.subrange(0, last));
    } else {
        occupied_update(slots.subrange(0, last), index, value);
        assert(slots.update(index, value).subrange(0, last)
            =~= slots.subrange(0, last).update(index, value));
    }
}

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

    pub proof fn layout(&self)
        ensures self.entries().len() == self.limit(),
    {}

    pub proof fn ownership_facts(&self, key: &RequestKey)
        requires self.owns(key),
        ensures key.slot() < self.limit(), key.id() != 0,
            self.entries()[key.slot() as int] == key.id(),
    {}

    // Conditional composition theorem. The runtime must maintain the mapping
    // of owned streams to live slots; async ownership itself is not proved here.
    pub proof fn logical_payload_bound(&self, streams: Seq<Option<StreamChunk>>)
        requires self.valid(), streams_bound(self.entries(), streams, self.per_request()),
        ensures retained_payload(streams) <= occupied(self.entries()) * self.per_request(),
            retained_payload(streams) <= self.limit() * self.per_request(),
            self.limit() * self.per_request() <= 134217728 ==> retained_payload(streams) <= 134217728,
    {
        bound_payload(self.entries(), streams, self.per_request());
        assert(occupied(self.entries()) * self.per_request() <= self.limit() * self.per_request())
            by(nonlinear_arith)
            requires occupied(self.entries()) <= self.limit(), 0 <= self.per_request();
    }

    pub fn new(request_limit: usize, per_request: usize) -> (a: Self)
        ensures a.valid(), a.limit() == request_limit, a.per_request() == per_request,
            a.next_id() == 1, occupied(a.entries()) == 0,
            streams_bound(a.entries(), Seq::new(request_limit as nat, |i: int| None::<StreamChunk>), a.per_request()),
            crate::owned_accounting::owners_match(a.entries(),
                Seq::new(request_limit as nat, |i: int| None::<crate::owned_stream::OwnedStream>), a.per_request()),
            forall|i: int| 0 <= i < a.limit() ==> #[trigger] a.entries()[i] == 0,
    {
        let mut slots = Vec::new();
        while slots.len() < request_limit
            invariant slots.len() <= request_limit, occupied(slots@) == 0,
                forall|i: int| 0 <= i < slots.len() ==> #[trigger] slots@[i] == 0,
            decreases request_limit - slots.len(),
        {
            let ghost previous = slots@;
            slots.push(0u64);
            proof { assert(slots@.subrange(0, slots.len() as int - 1) =~= previous); }
        }
        ResourceAdmission { slots, next: 1, per_request }
    }

    pub fn usage(&self) -> (out: (usize, usize))
        ensures out.0 == occupied(self.entries()), out.1 == self.limit(), out.0 <= out.1,
    {
        let mut i: usize = 0;
        let mut active: usize = 0;
        while i < self.slots.len()
            invariant i <= self.slots.len(), active <= i,
                active == occupied(self.slots@.subrange(0, i as int)),
            decreases self.slots.len() - i,
        {
            if self.slots[i] != 0 { active = active + 1; }
            proof {
                assert(self.slots@.subrange(0, i as int + 1).subrange(0, i as int)
                    =~= self.slots@.subrange(0, i as int));
            }
            i = i + 1;
        }
        proof { assert(self.slots@.subrange(0, i as int) =~= self.slots@); }
        (active, self.slots.len())
    }

    pub fn acquire(&mut self) -> (out: Option<RequestKey>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            final(self).per_request() == old(self).per_request(),
            forall|streams: Seq<Option<StreamChunk>>|
                #[trigger] streams_bound(old(self).entries(), streams, old(self).per_request())
                ==> streams_bound(final(self).entries(), streams, final(self).per_request()),
            forall|owners: Seq<Option<crate::owned_stream::OwnedStream>>|
                #[trigger] crate::owned_accounting::owners_match(old(self).entries(), owners, old(self).per_request())
                ==> crate::owned_accounting::owners_match(final(self).entries(), owners, final(self).per_request()),
            match out {
                Some(key) => final(self).owns(&key) && !key.stream_claimed() && key.id() == old(self).next_id()
                    && final(self).next_id() == old(self).next_id() + 1
                    && occupied(final(self).entries()) == occupied(old(self).entries()) + 1
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
                proof {
                    occupied_update(self.slots@, i as int, id);
                    assert forall|streams: Seq<Option<StreamChunk>>|
                        #[trigger] streams_bound(self.slots@, streams, self.per_request as nat)
                        implies streams_bound(self.slots@.update(i as int, id), streams, self.per_request as nat)
                    by { reserve_preserves_streams(self.slots@, streams, self.per_request as nat, i as int, id); }
                    assert forall|owners: Seq<Option<crate::owned_stream::OwnedStream>>|
                        #[trigger] crate::owned_accounting::owners_match(self.slots@, owners, self.per_request as nat)
                        implies crate::owned_accounting::owners_match(self.slots@.update(i as int, id), owners, self.per_request as nat)
                    by { crate::owned_accounting::reserve_owner_slot(self.slots@, owners, self.per_request as nat, i as int, id); }
                }
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
                    && stream.strict() == strict && !stream.closed() && !stream.pending()
                    && (forall|streams: Seq<Option<StreamChunk>>|
                        #[trigger] streams_bound(self.entries(), streams, self.per_request())
                        ==> streams_bound(self.entries(), streams.update(final(key).slot() as int, Some(stream)), self.per_request())),
                None => *final(key) == *old(key) && (old(key).stream_claimed()
                    || old(key).id() != authority.request() || !self.owns(old(key))),
            },
    {
        if key.stream_claimed || key.id != authority.request_id() { return None; }
        match self.capacity(key) {
            Some(capacity) => {
                let stream = StreamChunk::new(key.id, Vec::new(), capacity, strict);
                key.stream_claimed = true;
                proof {
                    if let Some(ref s) = stream {
                        assert forall|streams: Seq<Option<StreamChunk>>|
                            #[trigger] streams_bound(self.entries(), streams, self.per_request())
                            implies streams_bound(self.entries(), streams.update(key.slot as int, Some(*s)), self.per_request())
                        by { replace_preserves_streams(self.entries(), streams, self.per_request(), key.slot as int, *s); }
                    }
                }
                stream
            },
            None => None,
        }
    }

    // Consume the owned stream before the caller can expose the released slot.
    // External effects must already be stopped; registry identity remains scoped.
    pub fn release_stream(&mut self, key: &RequestKey, stream: StreamChunk) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            final(self).per_request() == old(self).per_request(),
            final(self).next_id() == old(self).next_id(),
            ok ==> (forall|owners: Seq<Option<crate::owned_stream::OwnedStream>>|
                #[trigger] crate::owned_accounting::owners_match(old(self).entries(), owners, old(self).per_request())
                ==> crate::owned_accounting::owners_match(final(self).entries(),
                    owners.update(key.slot() as int, None), final(self).per_request())),
            ok ==> (forall|streams: Seq<Option<StreamChunk>>|
                #[trigger] streams_bound(old(self).entries(), streams, old(self).per_request())
                ==> streams_bound(final(self).entries(), streams.update(key.slot() as int, None), final(self).per_request())),
            ok == (key.stream_claimed() && stream.owner() == key.id() && old(self).owns(key)),
            ok ==> !final(self).owns(key)
                && occupied(final(self).entries()) + 1 == occupied(old(self).entries())
                && final(self).entries()[key.slot() as int] == 0
                && (forall|i: int| 0 <= i < old(self).limit() && i != key.slot()
                    ==> #[trigger] final(self).entries()[i] == old(self).entries()[i]),
            !ok ==> *final(self) == *old(self),
    {
        if !key.stream_claimed || stream.owner_id() != key.id { return false; }
        self.release_slot(key)
    }

    // Only an unclaimed reservation can return credit without consuming a stream.
    pub fn release(&mut self, key: &RequestKey) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            final(self).per_request() == old(self).per_request(),
            final(self).next_id() == old(self).next_id(),
            ok ==> (forall|owners: Seq<Option<crate::owned_stream::OwnedStream>>|
                #[trigger] crate::owned_accounting::owners_match(old(self).entries(), owners, old(self).per_request())
                ==> crate::owned_accounting::owners_match(final(self).entries(),
                    owners.update(key.slot() as int, None), final(self).per_request())),
            ok ==> (forall|streams: Seq<Option<StreamChunk>>|
                #[trigger] streams_bound(old(self).entries(), streams, old(self).per_request())
                ==> streams_bound(final(self).entries(), streams.update(key.slot() as int, None), final(self).per_request())),
            ok == (!key.stream_claimed() && old(self).owns(key)),
            ok ==> !final(self).owns(key)
                && occupied(final(self).entries()) + 1 == occupied(old(self).entries())
                && final(self).entries()[key.slot() as int] == 0
                && (forall|i: int| 0 <= i < old(self).limit() && i != key.slot()
                    ==> #[trigger] final(self).entries()[i] == old(self).entries()[i]),
            !ok ==> *final(self) == *old(self),
    {
        if key.stream_claimed { return false; }
        self.release_slot(key)
    }

    // Private primitive: claimed reservations must pass through release_stream.
    fn release_slot(&mut self, key: &RequestKey) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            final(self).per_request() == old(self).per_request(),
            final(self).next_id() == old(self).next_id(),
            ok ==> (forall|owners: Seq<Option<crate::owned_stream::OwnedStream>>|
                #[trigger] crate::owned_accounting::owners_match(old(self).entries(), owners, old(self).per_request())
                ==> crate::owned_accounting::owners_match(final(self).entries(),
                    owners.update(key.slot() as int, None), final(self).per_request())),
            ok ==> (forall|streams: Seq<Option<StreamChunk>>|
                #[trigger] streams_bound(old(self).entries(), streams, old(self).per_request())
                ==> streams_bound(final(self).entries(), streams.update(key.slot() as int, None), final(self).per_request())),
            ok ==> old(self).owns(key) && !final(self).owns(key)
                && occupied(final(self).entries()) + 1 == occupied(old(self).entries())
                && final(self).entries()[key.slot() as int] == 0
                && (forall|i: int| 0 <= i < old(self).limit() && i != key.slot()
                    ==> #[trigger] final(self).entries()[i] == old(self).entries()[i]),
            !ok ==> !old(self).owns(key) && *final(self) == *old(self),
    {
        if key.slot >= self.slots.len() || key.id == 0 || self.slots[key.slot] != key.id {
            return false;
        }
        proof {
            occupied_update(self.slots@, key.slot as int, 0);
            assert forall|streams: Seq<Option<StreamChunk>>|
                #[trigger] streams_bound(self.slots@, streams, self.per_request as nat)
                implies streams_bound(self.slots@.update(key.slot as int, 0), streams.update(key.slot as int, None), self.per_request as nat)
            by { retire_preserves_streams(self.slots@, streams, self.per_request as nat, key.slot as int); }
            assert forall|owners: Seq<Option<crate::owned_stream::OwnedStream>>|
                #[trigger] crate::owned_accounting::owners_match(self.slots@, owners, self.per_request as nat)
                implies crate::owned_accounting::owners_match(self.slots@.update(key.slot as int, 0),
                    owners.update(key.slot as int, None), self.per_request as nat)
            by { crate::owned_accounting::retire_owner_slot(self.slots@, owners, self.per_request as nat, key.slot as int); }
        }
        self.slots.set(key.slot, 0);
        true
    }
}
}
