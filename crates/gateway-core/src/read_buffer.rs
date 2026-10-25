//! Reader-owned payload: consumed prefixes stay charged until the whole copy is released.
use vstd::prelude::*;
use vstd::slice::{slice_subrange, slice_to_vec};

verus! {
pub struct ReadBuffer { bytes: Vec<u8>, offset: usize, limit: usize }
impl ReadBuffer {
    pub closed spec fn valid(&self) -> bool {
        self.offset <= self.bytes.len() && self.bytes.len() <= self.limit
            && (self.offset == self.bytes.len() ==> self.bytes.len() == 0)
    }
    pub closed spec fn backing(&self) -> Seq<u8> { self.bytes@ }
    pub closed spec fn position(&self) -> nat { self.offset as nat }
    pub closed spec fn limit(&self) -> nat { self.limit as nat }
    pub open spec fn remaining(&self) -> Seq<u8> {
        self.backing().subrange(self.position() as int, self.backing().len() as int)
    }
    pub fn new(limit: usize) -> (out: Self)
        ensures out.valid(), out.backing().len() == 0, out.limit() == limit,
    { Self { bytes: Vec::new(), offset: 0, limit } }
    pub fn len(&self) -> (out: usize)
        requires self.valid(),
        ensures out == self.remaining().len(),
    { self.bytes.len() - self.offset }
    pub fn is_empty(&self) -> (out: bool)
        requires self.valid(),
        ensures out == (self.remaining().len() == 0),
    { self.len() == 0 }
    pub fn retained_bytes(&self) -> (out: usize)
        requires self.valid(),
        ensures out == self.backing().len(), out <= self.limit(),
            out >= self.remaining().len(),
    { self.bytes.len() }
    pub fn load(&mut self, bytes: &[u8]) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            ok == (old(self).remaining().len() == 0 && bytes.len() <= old(self).limit()),
            ok ==> final(self).backing() == bytes@ && final(self).position() == 0,
            !ok ==> *final(self) == *old(self),
    {
        if !self.is_empty() || bytes.len() > self.limit { return false; }
        self.bytes = slice_to_vec(bytes);
        self.offset = 0;
        true
    }
    pub fn peek(&self, count: usize) -> (out: &[u8])
        requires self.valid(), count <= self.remaining().len(),
        ensures out@ == self.remaining().subrange(0, count as int),
    { slice_subrange(self.bytes.as_slice(), self.offset, self.offset + count) }
    pub fn consume(&mut self, count: usize) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).limit() == old(self).limit(),
            ok == (count <= old(self).remaining().len()),
            !ok ==> *final(self) == *old(self),
            ok ==> final(self).remaining() == old(self).remaining().subrange(count as int, old(self).remaining().len() as int),
            ok && count < old(self).remaining().len() ==> final(self).backing() == old(self).backing(),
            ok && count == old(self).remaining().len() ==> final(self).backing().len() == 0,
    {
        if count > self.len() { return false; }
        self.offset += count;
        if self.offset == self.bytes.len() {
            self.bytes = Vec::new();
            self.offset = 0;
        }
        true
    }
}
}
