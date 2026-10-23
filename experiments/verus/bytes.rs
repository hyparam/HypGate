use vstd::prelude::*;

verus! {
// One bounded chunk, owned by one request. No network or disk assumptions hidden here.
pub struct Chunk {
    id: u64,
    bytes: Vec<u8>,
    sent: usize,
    durable: usize,
    strict: bool,
    closed: bool,
    history: Ghost<Seq<u8>>,
}

impl Chunk {
    pub closed spec fn valid(&self) -> bool {
        self.sent <= self.bytes.len()
        && self.durable <= self.bytes.len()
        && (self.strict ==> self.sent <= self.durable)
        && self.history@ == self.bytes@.subrange(0, self.sent as int)
    }

    pub closed spec fn body(&self) -> Seq<u8> { self.bytes@ }
    pub closed spec fn position(&self) -> nat { self.sent as nat }
    pub closed spec fn is_strict(&self) -> bool { self.strict }
    pub closed spec fn is_closed(&self) -> bool { self.closed }
    pub closed spec fn owner(&self) -> u64 { self.id }

    pub fn new(id: u64, bytes: Vec<u8>, capacity: usize, strict: bool) -> (out: Option<Self>)
        ensures match out {
            Some(c) => c.valid() && c.body() == bytes@ && c.position() == 0
                && c.owner() == id && c.body().len() <= capacity
                && c.is_strict() == strict && !c.is_closed(),
            None => bytes.len() > capacity,
        },
    {
        if bytes.len() > capacity { return None; }
        proof { assert(bytes@.subrange(0, 0) =~= Seq::<u8>::empty()); }
        Some(Chunk { id, bytes, sent: 0, durable: 0, strict, closed: false, history: Ghost(Seq::empty()) })
    }

    pub fn acknowledge(&mut self, id: u64, end: usize) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).body() == old(self).body(),
                final(self).owner() == old(self).owner(),
                final(self).is_strict() == old(self).is_strict(),
                final(self).position() == old(self).position(),
                ok ==> id == old(self).owner(),
                id != old(self).owner() ==> *final(self) == *old(self),
    {
        if self.closed || id != self.id || end < self.durable || end > self.bytes.len() {
            return false;
        }
        self.durable = end;
        true
    }

    // This returns the actual next byte, rather than just authorizing a count.
    pub fn next(&mut self, id: u64) -> (out: Option<u8>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).body() == old(self).body(),
                final(self).owner() == old(self).owner(),
                final(self).is_strict() == old(self).is_strict(),
                old(self).is_closed() ==> out.is_none(),
                match out {
                    Some(b) => id == old(self).owner()
                        && old(self).position() < old(self).body().len()
                        && b == old(self).body()[old(self).position() as int]
                        && final(self).position() == old(self).position() + 1,
                    None => final(self).position() == old(self).position(),
                },
                id != old(self).owner() ==> *final(self) == *old(self),
    {
        if self.closed || id != self.id || self.sent == self.bytes.len()
            || (self.strict && self.sent == self.durable) { return None; }
        let byte = self.bytes[self.sent];
        self.sent = self.sent + 1;
        proof {
            assert(self.history@.push(byte) =~= self.bytes@.subrange(0, self.sent as int));
        }
        self.history = Ghost(self.history@.push(byte));
        Some(byte)
    }

    pub fn fail_log(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).body() == old(self).body(),
                final(self).position() == old(self).position(),
                final(self).owner() == old(self).owner(),
                final(self).is_strict() == old(self).is_strict(),
                old(self).is_strict() ==> final(self).is_closed(),
    {
        if self.strict { self.closed = true; }
    }
}
}

fn main() {
    assert!(Chunk::new(99, vec![1, 2], 1, true).is_none());
    let mut a = Chunk::new(10, vec![0, 255, 42], 3, true).unwrap();
    let mut b = Chunk::new(20, vec![7, 8], 3, false).unwrap();
    assert_eq!(a.next(10), None);
    assert!(!a.acknowledge(20, 3));
    assert!(a.acknowledge(10, 2));
    assert_eq!(a.next(20), None);
    assert_eq!(a.next(10), Some(0));
    assert_eq!(b.next(20), Some(7));
    assert_eq!(a.next(10), Some(255));
    assert_eq!(a.next(10), None);
    a.fail_log();
    assert!(!a.acknowledge(10, 3));
    assert_eq!(a.next(10), None);
    b.fail_log();
    assert_eq!(b.next(20), Some(8));
    assert_eq!(b.next(20), None);
    println!("interleaved byte-preservation and owner checks passed");
}
