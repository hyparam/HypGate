//! Fixed-slot FIFO storage. Synchronization and allocation success are external.
use vstd::prelude::*;

verus! {
pub open spec fn position(head: int, offset: int, capacity: int) -> int {
    if offset < capacity - head { head + offset } else { offset - (capacity - head) }
}

pub struct FixedQueue<T> { slots: Vec<Option<T>>, head: usize, used: usize }
impl<T> FixedQueue<T> {
    pub closed spec fn capacity(&self) -> nat { self.slots@.len() }
    pub closed spec fn contents(&self) -> Seq<T> {
        Seq::new(self.used as nat, |i: int| self.slots@[position(self.head as int, i, self.capacity() as int)]->Some_0)
    }
    pub closed spec fn valid(&self) -> bool {
        self.slots.len() > 0 && self.head < self.slots.len() && self.used <= self.slots.len()
            && forall|i: int| 0 <= i < self.slots.len() ==> (
                self.slots@[position(self.head as int, i, self.slots.len() as int)].is_some() == (i < self.used))
    }
    pub fn new(capacity: usize) -> (out: Self)
        requires capacity > 0,
        ensures out.valid(), out.capacity() == capacity, out.contents() == Seq::<T>::empty(),
    {
        let mut slots: Vec<Option<T>> = Vec::with_capacity(capacity);
        while slots.len() < capacity
            invariant slots.len() <= capacity,
                forall|i: int| 0 <= i < slots.len() ==> slots@[i].is_none(),
            decreases capacity - slots.len(),
        { slots.push(None); }
        Self { slots, head: 0, used: 0 }
    }
    pub fn len(&self) -> (out: usize)
        requires self.valid(),
        ensures out == self.contents().len(), out <= self.capacity(),
    { self.used }
    pub fn is_full(&self) -> (out: bool)
        requires self.valid(),
        ensures out == (self.contents().len() == self.capacity()),
    { self.used == self.slots.len() }

    pub fn push(&mut self, value: T) -> (out: Result<(), T>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).capacity() == old(self).capacity(),
            match out {
                Ok(()) => old(self).contents().len() < old(self).capacity()
                    && final(self).contents() == old(self).contents().push(value),
                Err(v) => v == value && old(self).contents().len() == old(self).capacity()
                    && final(self).contents() == old(self).contents(),
            },
    {
        if self.used == self.slots.len() { return Err(value); }
        let index = if self.used < self.slots.len() - self.head {
            self.head + self.used
        } else { self.used - (self.slots.len() - self.head) };
        self.slots.set(index, Some(value));
        self.used += 1;
        assert forall|i: int| 0 <= i < self.slots.len() implies
            self.slots@[position(self.head as int, i, self.slots.len() as int)].is_some() == (i < self.used) by {
            assert(position(self.head as int, i, self.slots.len() as int) == index <==> i == old(self).used);
        }
        assert(self.contents() =~= old(self).contents().push(value));
        Ok(())
    }
    pub fn pop(&mut self) -> (out: Option<T>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).capacity() == old(self).capacity(),
            match out {
                Some(value) => old(self).contents().len() > 0 && value == old(self).contents()[0]
                    && final(self).contents() == old(self).contents().drop_first(),
                None => old(self).contents().len() == 0 && final(self).contents() == old(self).contents(),
            },
    {
        if self.used == 0 { return None; }
        assert(position(self.head as int, 0, self.slots.len() as int) == self.head);
        assert(self.slots@[self.head as int].is_some());
        let mut value = None;
        core::mem::swap(&mut value, &mut self.slots[self.head]);
        assert(value == Some(old(self).contents()[0]));
        self.head = if self.head == self.slots.len() - 1 { 0 } else { self.head + 1 };
        self.used -= 1;
        assert forall|i: int| 0 <= i < self.slots.len() implies
            self.slots@[position(self.head as int, i, self.slots.len() as int)].is_some() == (i < self.used) by {
            if i < self.slots.len() - 1 {
                assert(position(self.head as int, i, self.slots.len() as int)
                    == position(old(self).head as int, i + 1, self.slots.len() as int));
            } else {
                assert(position(self.head as int, i, self.slots.len() as int) == old(self).head);
            }
        }
        assert(self.contents() =~= old(self).contents().drop_first());
        value
    }
}
}
