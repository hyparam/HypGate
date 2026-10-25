//! Production audit-frame FIFO with completion associations and byte accounting.
use vstd::prelude::*;
use crate::{fixed_queue::FixedQueue, framing::RecordFrame};

verus! {
// Every queued frame is canonical and within the configured payload limit.
pub open spec fn items_bounded<T>(items: Seq<(RecordFrame, T)>, limit: nat) -> bool {
    forall|i: int| 0 <= i < items.len() ==> (#[trigger] items[i]).0.valid() && items[i].0.payload().len() <= limit
}
proof fn items_bounded_push<T>(items: Seq<(RecordFrame, T)>, limit: nat, item: (RecordFrame, T))
    requires items_bounded(items, limit), item.0.valid(), item.0.payload().len() <= limit,
    ensures items_bounded(items.push(item), limit),
{
    assert forall|i: int| 0 <= i < items.push(item).len() implies
        (#[trigger] items.push(item)[i]).0.valid() && items.push(item)[i].0.payload().len() <= limit by {
        if i < items.len() { assert(items.push(item)[i] == items[i]); } else { assert(items.push(item)[i] == item); }
    }
}
proof fn items_bounded_drop_first<T>(items: Seq<(RecordFrame, T)>, limit: nat)
    requires items_bounded(items, limit), items.len() > 0,
    ensures items_bounded(items.drop_first(), limit),
{
    assert forall|i: int| 0 <= i < items.drop_first().len() implies
        (#[trigger] items.drop_first()[i]).0.valid() && items.drop_first()[i].0.payload().len() <= limit by {
        assert(items.drop_first()[i] == items[i + 1]);
    }
}

pub struct FrameQueue<T> { queue: FixedQueue<(RecordFrame, T)>, payload_limit: usize, reserved: bool }
impl<T> FrameQueue<T> {
    pub fn payload_capacity(&self) -> (out: usize)
        ensures out == self.payload_limit(),
    { self.payload_limit }
    pub closed spec fn reserved(&self) -> bool { self.reserved }
    pub open spec fn charged_slots(&self) -> nat { self.items().len() + if self.reserved() { 1nat } else { 0nat } }
    pub closed spec fn items(&self) -> Seq<(RecordFrame, T)> { self.queue.contents() }
    pub closed spec fn payload_limit(&self) -> nat { self.payload_limit as nat }
    pub closed spec fn capacity(&self) -> nat { self.queue.capacity() }
    pub closed spec fn closed(&self) -> bool { self.queue.closed() }
    pub open spec fn frames(&self) -> Seq<RecordFrame> {
        self.items().map(|i: int, item: (RecordFrame, T)| item.0)
    }
    pub closed spec fn valid(&self) -> bool {
        self.payload_limit <= 1048576 && self.queue.valid()
            && (!self.reserved || self.items().len() < self.capacity())
            && items_bounded(self.items(), self.payload_limit())
    }
    pub fn new(capacity: usize) -> (out: Self)
        requires capacity > 0,
        ensures out.valid(), !out.reserved(), out.capacity() == capacity, !out.closed(), out.items().len() == 0, out.payload_limit() == 1048576,
    { Self::with_payload_limit(capacity, 1048576) }
    pub fn with_payload_limit(capacity: usize, payload_limit: usize) -> (out: Self)
        requires capacity > 0, payload_limit <= 1048576,
        ensures out.valid(), !out.reserved(), out.capacity() == capacity, !out.closed(), out.items().len() == 0,
            out.payload_limit() == payload_limit,
    { Self { queue: FixedQueue::new(capacity), payload_limit, reserved: false } }
    // One synchronous producer may encode while holding the adapter's mutex.
    // No second producer or direct push may consume that reserved slot.
    pub fn reserve(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).items() == old(self).items(),
            final(self).capacity() == old(self).capacity(), final(self).payload_limit() == old(self).payload_limit(),
            final(self).closed() == old(self).closed(),
            ok == (!old(self).reserved() && !old(self).closed() && old(self).items().len() < old(self).capacity()),
            final(self).reserved() == (old(self).reserved() || ok),
    {
        proof { self.queue.occupancy_bound(); }
        if self.reserved || self.queue.is_closed() || self.queue.is_full() { return false; }
        self.reserved = true;
        true
    }
    // The trusted adapter invokes this once per synchronous reservation, under
    // its mutex. This contract bounds the returned body, not callback multiplicity.
    pub fn encode_reserved(&self, header: crate::framing::Header, payload: &[u8])
        -> (out: Option<crate::framing::RecordBody>)
        requires self.valid(),
        ensures match out {
            Some(body) => self.reserved() && !self.closed() && body.valid()
                && body.header() == header && body.payload() == payload@
                && body.payload().len() <= self.payload_limit(),
            None => !self.reserved() || self.closed() || payload.len() > self.payload_limit()
                || !crate::framing::valid(header) || header.payload != payload.len(),
        },
    {
        if !self.reserved || self.queue.is_closed() || payload.len() > self.payload_limit { return None; }
        crate::framing::RecordBody::new(header, payload)
    }
    pub fn finish_reserved(&mut self, item: (RecordFrame, T)) -> (out: Result<(), (RecordFrame, T)>)
        requires old(self).valid(), old(self).reserved(), item.0.valid(),
        ensures final(self).valid(), !final(self).reserved(),
            final(self).capacity() == old(self).capacity(), final(self).payload_limit() == old(self).payload_limit(),
            final(self).closed() == old(self).closed(),
            match out {
                Ok(()) => !old(self).closed() && item.0.payload().len() <= old(self).payload_limit()
                    && final(self).items() == old(self).items().push(item),
                Err(returned) => returned == item && final(self).items() == old(self).items()
                    && (old(self).closed() || item.0.payload().len() > old(self).payload_limit()),
            },
    {
        self.reserved = false;
        self.push(item)
    }
    pub proof fn encoding_and_queued_bound(&self, encoding_bytes: nat)
        requires self.valid(), encoding_bytes <= self.payload_limit() + 65,
            !self.reserved() ==> encoding_bytes == 0,
        ensures crate::buffer_accounting::byte_sum(crate::buffer_accounting::frame_bytes(self.frames()))
            + encoding_bytes <= self.capacity() * (self.payload_limit() + 65),
    {
        self.frame_layout();
        crate::buffer_accounting::bounded_frames(self.frames(), self.frames().len(), self.payload_limit());
        crate::buffer_accounting::bounded_sum(crate::buffer_accounting::frame_bytes(self.frames()), self.frames().len(), self.payload_limit() + 65);
        assert(self.frames().len() * (self.payload_limit() + 65) + encoding_bytes
            <= self.capacity() * (self.payload_limit() + 65)) by(nonlinear_arith)
            requires self.frames().len() == self.items().len(), self.charged_slots() <= self.capacity(),
                self.charged_slots() == self.items().len() + if self.reserved() { 1nat } else { 0nat },
                encoding_bytes <= self.payload_limit() + 65, !self.reserved() ==> encoding_bytes == 0;
    }
    pub fn len(&self) -> (out: usize)
        requires self.valid(),
        ensures out == self.items().len(), out <= self.capacity(),
    { self.queue.len() }
    pub fn is_full(&self) -> (out: bool)
        requires self.valid(),
        ensures out == (self.items().len() == self.capacity()),
    { self.queue.is_full() }
    pub fn is_closed(&self) -> (out: bool)
        requires self.valid(),
        ensures out == self.closed(),
    { self.queue.is_closed() }
    pub fn close(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).reserved() == old(self).reserved(), final(self).payload_limit() == old(self).payload_limit(), final(self).closed(), final(self).capacity() == old(self).capacity(),
            final(self).items() == old(self).items(),
    { self.queue.close(); }
    pub fn push(&mut self, item: (RecordFrame, T)) -> (out: Result<(), (RecordFrame, T)>)
        requires old(self).valid(), item.0.valid(),
        ensures final(self).valid(), final(self).reserved() == old(self).reserved(), final(self).payload_limit() == old(self).payload_limit(), final(self).capacity() == old(self).capacity(),
            final(self).closed() == old(self).closed(),
            match out {
                Ok(()) => !old(self).reserved() && item.0.payload().len() <= old(self).payload_limit() && !old(self).closed() && old(self).items().len() < old(self).capacity()
                    && final(self).items() == old(self).items().push(item),
                Err(returned) => returned == item && final(self).items() == old(self).items()
                    && (old(self).reserved() || old(self).closed() || old(self).items().len() == old(self).capacity()
                        || item.0.payload().len() > old(self).payload_limit()),
            },
    {
        if self.reserved { return Err(item); }
        proof { item.0.retained_size(); }
        if item.0.bytes().len() > self.payload_limit + 65 { return Err(item); }
        let out = self.queue.push(item);
        proof {
            self.queue.occupancy_bound();
            if out.is_ok() { items_bounded_push(old(self).items(), self.payload_limit(), item); }
        }
        out
    }
    pub fn pop(&mut self) -> (out: Option<(RecordFrame, T)>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).reserved() == old(self).reserved(), final(self).payload_limit() == old(self).payload_limit(), final(self).capacity() == old(self).capacity(),
            final(self).closed() == old(self).closed(),
            match out {
                Some(item) => item.0.payload().len() <= old(self).payload_limit() && item.0.valid() && old(self).items().len() > 0
                    && item == old(self).items()[0] && final(self).items() == old(self).items().drop_first(),
                None => old(self).items().len() == 0 && final(self).items() == old(self).items(),
            },
    {
        let out = self.queue.pop();
        proof { if out.is_some() { items_bounded_drop_first(old(self).items(), self.payload_limit()); } }
        out
    }
    // Projects the actual retained frames, without another runtime collection or
    // a caller-supplied count. Completion handles are deliberately not duplicated.
    pub proof fn frame_layout(&self)
        requires self.valid(),
        ensures self.frames().len() == self.items().len(), self.frames().len() <= self.capacity(),
            forall|i: int| 0 <= i < self.frames().len() ==> #[trigger] self.frames()[i].valid()
                && self.frames()[i].payload().len() <= self.payload_limit(),
    {
        self.queue.occupancy_bound();
        assert forall|i: int| 0 <= i < self.frames().len() implies #[trigger] self.frames()[i].valid()
            && self.frames()[i].payload().len() <= self.payload_limit() by {
            assert(self.items()[i].0.valid());
            assert(self.frames()[i] == self.items()[i].0);
            self.frames()[i].canonical();
        }
    }
}
}
