//! Production audit-frame FIFO with completion associations and byte accounting.
use vstd::prelude::*;
use crate::{fixed_queue::FixedQueue, framing::RecordFrame};

verus! {
pub struct FrameQueue<T> { queue: FixedQueue<(RecordFrame, T)>, payload_limit: usize, reserved: bool }
impl<T> FrameQueue<T> {
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
            && (!self.reserved || self.items().len() < self.capacity()) && (forall|i: int| 0 <= i < self.items().len()
            ==> (#[trigger] self.items()[i].0.valid() && self.items()[i].0.payload().len() <= self.payload_limit()))
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
    {
        self.queue.close();
        assert(!self.reserved || self.items().len() < self.capacity());
        assert forall|i: int| 0 <= i < self.items().len() implies (#[trigger] self.items()[i].0.valid() && self.items()[i].0.payload().len() <= self.payload_limit()) by {
            assert(self.items()[i] == old(self).items()[i]);
        }
        assert(self.queue.valid());
        assert(self.payload_limit <= 1048576);
        assert(self.valid());
    }
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
        proof { item.0.canonical(); crate::framing::encoded_header_roundtrip(item.0.header()); }
        if item.0.bytes().len() > self.payload_limit + 65 { return Err(item); }
        let out = self.queue.push(item);
        proof { self.queue.occupancy_bound(); }
        assert forall|i: int| 0 <= i < self.items().len() implies (#[trigger] self.items()[i].0.valid() && self.items()[i].0.payload().len() <= self.payload_limit()) by {
            if i < old(self).items().len() {
                assert(old(self).items()[i].0.valid());
                assert(self.items()[i] == old(self).items()[i]);
            } else { assert(self.items()[i] == item); }
        }
        assert(self.charged_slots() <= self.capacity());
        assert(!self.reserved);
        assert(self.queue.valid());
        assert(self.payload_limit <= 1048576);
        assert(self.valid());
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
        assert(self.items().len() > 0 ==> self.items()[0].0.valid());
        let out = self.queue.pop();
        assert forall|i: int| 0 <= i < self.items().len() implies (#[trigger] self.items()[i].0.valid() && self.items()[i].0.payload().len() <= self.payload_limit()) by {
            assert(old(self).items()[i + 1].0.valid());
            assert(self.items()[i] == old(self).items()[i + 1]);
        }
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
    pub proof fn accounted_frame_bytes(&self)
        requires self.valid(),
        ensures crate::buffer_accounting::bounded(crate::buffer_accounting::frame_bytes(self.frames()), self.capacity(), self.payload_limit() + 65),
            crate::buffer_accounting::byte_sum(crate::buffer_accounting::frame_bytes(self.frames())) <= self.capacity() * (self.payload_limit() + 65),
    {
        self.frame_layout();
        crate::buffer_accounting::bounded_frames(self.frames(), self.capacity(), self.payload_limit());
        crate::buffer_accounting::bounded_sum(crate::buffer_accounting::frame_bytes(self.frames()), self.capacity(), self.payload_limit() + 65);
    }
}
}
