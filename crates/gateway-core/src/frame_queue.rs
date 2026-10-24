//! Production audit-frame FIFO with completion associations and byte accounting.
use vstd::prelude::*;
use crate::{fixed_queue::FixedQueue, framing::RecordFrame};

verus! {
pub struct FrameQueue<T> { queue: FixedQueue<(RecordFrame, T)> }
impl<T> FrameQueue<T> {
    pub closed spec fn items(&self) -> Seq<(RecordFrame, T)> { self.queue.contents() }
    pub closed spec fn capacity(&self) -> nat { self.queue.capacity() }
    pub closed spec fn closed(&self) -> bool { self.queue.closed() }
    pub open spec fn frames(&self) -> Seq<RecordFrame> {
        self.items().map(|i: int, item: (RecordFrame, T)| item.0)
    }
    pub closed spec fn valid(&self) -> bool {
        self.queue.valid() && forall|i: int| 0 <= i < self.items().len()
            ==> #[trigger] self.items()[i].0.valid()
    }
    pub fn new(capacity: usize) -> (out: Self)
        requires capacity > 0,
        ensures out.valid(), out.capacity() == capacity, !out.closed(), out.items().len() == 0,
    { Self { queue: FixedQueue::new(capacity) } }
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
        ensures final(self).valid(), final(self).closed(), final(self).capacity() == old(self).capacity(),
            final(self).items() == old(self).items(),
    {
        self.queue.close();
        assert forall|i: int| 0 <= i < self.items().len() implies #[trigger] self.items()[i].0.valid() by {
            assert(self.items()[i] == old(self).items()[i]);
        }
    }
    pub fn push(&mut self, item: (RecordFrame, T)) -> (out: Result<(), (RecordFrame, T)>)
        requires old(self).valid(), item.0.valid(),
        ensures final(self).valid(), final(self).capacity() == old(self).capacity(),
            final(self).closed() == old(self).closed(),
            match out {
                Ok(()) => !old(self).closed() && old(self).items().len() < old(self).capacity()
                    && final(self).items() == old(self).items().push(item),
                Err(returned) => returned == item && final(self).items() == old(self).items()
                    && (old(self).closed() || old(self).items().len() == old(self).capacity()),
            },
    {
        let out = self.queue.push(item);
        assert forall|i: int| 0 <= i < self.items().len() implies #[trigger] self.items()[i].0.valid() by {
            if i < old(self).items().len() { assert(self.items()[i] == old(self).items()[i]); }
        }
        out
    }
    pub fn pop(&mut self) -> (out: Option<(RecordFrame, T)>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).capacity() == old(self).capacity(),
            final(self).closed() == old(self).closed(),
            match out {
                Some(item) => item.0.valid() && old(self).items().len() > 0
                    && item == old(self).items()[0] && final(self).items() == old(self).items().drop_first(),
                None => old(self).items().len() == 0 && final(self).items() == old(self).items(),
            },
    {
        let out = self.queue.pop();
        assert forall|i: int| 0 <= i < self.items().len() implies #[trigger] self.items()[i].0.valid() by {
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
                && self.frames()[i].payload().len() <= 1048576,
    {
        self.queue.occupancy_bound();
        assert forall|i: int| 0 <= i < self.frames().len() implies #[trigger] self.frames()[i].valid()
            && self.frames()[i].payload().len() <= 1048576 by {
            assert(self.frames()[i] == self.items()[i].0);
            self.frames()[i].canonical();
        }
    }
    pub proof fn accounted_frame_bytes(&self)
        requires self.valid(),
        ensures crate::buffer_accounting::bounded(crate::buffer_accounting::frame_bytes(self.frames()), self.capacity(), 1048576 + 65),
            crate::buffer_accounting::byte_sum(crate::buffer_accounting::frame_bytes(self.frames())) <= self.capacity() * (1048576 + 65),
    {
        self.frame_layout();
        crate::buffer_accounting::bounded_frames(self.frames(), self.capacity(), 1048576);
        crate::buffer_accounting::bounded_sum(crate::buffer_accounting::frame_bytes(self.frames()), self.capacity(), 1048576 + 65);
    }
}
}
