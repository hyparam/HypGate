use vstd::prelude::*;
use vstd::slice::slice_subrange;

verus! {

// Owners must be unique across live stream instances; allocation is a later layer.
pub struct Ticket { owner: u64, generation: u64 }

pub struct StreamChunk {
    owner: u64,
    bytes: Vec<u8>,
    capacity: usize,
    chunk: u64,
    prefix: Ghost<Seq<u8>>,
    sent: usize,
    durable: usize,
    offered: usize,
    generation: u64,
    pending: bool,
    strict: bool,
    failed: bool,
    closed: bool,
    history: Ghost<Seq<u8>>,
}

impl Ticket {
    pub closed spec fn owner(&self) -> u64 { self.owner }
    pub closed spec fn generation(&self) -> u64 { self.generation }
}

impl StreamChunk {
    // Read-only payload view for the logger; transport still needs a write ticket.
    pub fn log_bytes(&self) -> (out: &[u8])
        ensures out@ == self.body(),
    { self.bytes.as_slice() }

    pub fn chunk_id(&self) -> (out: u64)
        ensures out == self.chunk(),
    { self.chunk }

    pub fn is_closed(&self) -> (out: bool)
        ensures out == self.closed(),
    { self.closed }

    pub closed spec fn valid(&self) -> bool {
        self.sent <= self.offered <= self.bytes.len()
        && self.bytes.len() <= self.capacity
        && self.durable <= self.bytes.len()
        && (self.strict ==> self.offered <= self.durable)
        && (!self.pending ==> self.offered == self.sent)
        && (self.strict && self.failed ==> self.closed)
        && self.history@ == self.prefix@ + self.bytes@.subrange(0, self.sent as int)
    }

    pub closed spec fn chunk(&self) -> u64 { self.chunk }
    pub closed spec fn capacity(&self) -> nat { self.capacity as nat }
    pub closed spec fn input(&self) -> Seq<u8> { self.prefix@ + self.bytes@ }
    pub closed spec fn completed(&self) -> Seq<u8> { self.history@ }
    pub closed spec fn body(&self) -> Seq<u8> { self.bytes@ }
    pub closed spec fn position(&self) -> nat { self.sent as nat }
    pub closed spec fn end(&self) -> nat { self.offered as nat }
    pub closed spec fn durable(&self) -> nat { self.durable as nat }
    pub closed spec fn owner(&self) -> u64 { self.owner }
    pub closed spec fn generation(&self) -> u64 { self.generation }
    pub closed spec fn pending(&self) -> bool { self.pending }
    pub closed spec fn closed(&self) -> bool { self.closed }
    pub closed spec fn strict(&self) -> bool { self.strict }
    pub closed spec fn failed(&self) -> bool { self.failed }
    pub closed spec fn matches(&self, t: &Ticket) -> bool {
        self.pending && t.owner == self.owner && t.generation == self.generation
    }

    pub fn new(owner: u64, bytes: Vec<u8>, capacity: usize, strict: bool) -> (out: Option<Self>)
        ensures match out {
            Some(s) => s.valid() && s.body() == bytes@ && s.body().len() <= capacity
                && s.capacity() == capacity && s.chunk() == 0
                && s.input() == bytes@ && s.completed() == Seq::<u8>::empty()
                && s.position() == 0 && s.end() == 0 && s.durable() == 0
                && s.generation() == 0 && s.owner() == owner && s.strict() == strict
                && !s.pending() && !s.closed() && !s.failed(),
            None => bytes.len() > capacity,
        },
    {
        if bytes.len() > capacity { return None; }
        proof { assert(bytes@.subrange(0, 0) =~= Seq::<u8>::empty()); }
        Some(StreamChunk { owner, bytes, capacity, chunk: 0, prefix: Ghost(Seq::empty()), sent: 0, durable: 0, offered: 0,
            generation: 0, pending: false, strict, failed: false, closed: false,
            history: Ghost(Seq::empty()) })
    }

    // The adapter must supply a truthful durable-prefix acknowledgment for this owner.
    pub fn acknowledge(&mut self, owner: u64, chunk: u64, end: usize) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            final(self).body() == old(self).body(),
            final(self).chunk() == old(self).chunk(), final(self).capacity() == old(self).capacity(),
            final(self).input() == old(self).input(),
            final(self).completed() == old(self).completed(), final(self).owner() == old(self).owner(),
            final(self).position() == old(self).position(), final(self).strict() == old(self).strict(),
            final(self).generation() == old(self).generation(),
            final(self).closed() == old(self).closed(), final(self).failed() == old(self).failed(),
            final(self).pending() == old(self).pending(), final(self).end() == old(self).end(),
            ok ==> final(self).durable() == end && end >= old(self).durable()
                && owner == old(self).owner() && chunk == old(self).chunk(),
            ok == (!old(self).closed() && !old(self).failed() && owner == old(self).owner()
                && chunk == old(self).chunk() && old(self).durable() <= end <= old(self).body().len()),
            !ok ==> *final(self) == *old(self),
    {
        if self.closed || self.failed || owner != self.owner || chunk != self.chunk
            || end < self.durable || end > self.bytes.len() { return false; }
        self.durable = end;
        true
    }

    // A reservation does not advance the completed offset.
    pub fn prepare(&mut self, max: usize) -> (out: Option<Ticket>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).body() == old(self).body(),
            final(self).chunk() == old(self).chunk(), final(self).capacity() == old(self).capacity(),
            final(self).input() == old(self).input(),
            final(self).completed() == old(self).completed(),
            final(self).position() == old(self).position(), final(self).owner() == old(self).owner(),
            final(self).strict() == old(self).strict(),
            final(self).durable() == old(self).durable(),
            final(self).closed() == old(self).closed(), final(self).failed() == old(self).failed(),
            match out {
                Some(t) => final(self).matches(&t) && !old(self).pending() && !old(self).closed()
                    && final(self).end() > final(self).position()
                    && final(self).end() - final(self).position() <= max
                    && final(self).generation() == old(self).generation() + 1,
                None => *final(self) == *old(self) && (old(self).closed() || old(self).pending()
                    || max == 0 || old(self).generation() == u64::MAX
                    || old(self).position() == (if old(self).strict() { old(self).durable() } else { old(self).body().len() })),
            },
    {
        if self.closed || self.pending || max == 0 || self.generation == u64::MAX {
            return None;
        }
        let limit = if self.strict { self.durable } else { self.bytes.len() };
        let available = limit - self.sent;
        if available == 0 { return None; }
        let count = if max < available { max } else { available };
        self.offered = self.sent + count;
        self.generation = self.generation + 1;
        self.pending = true;
        Some(Ticket { owner: self.owner, generation: self.generation })
    }

    // A borrowed view: no payload copy or per-byte iteration in the core.
    pub fn pending_bytes<'a>(&'a self, t: &Ticket) -> (out: Option<&'a [u8]>)
        requires self.valid(),
        ensures match out {
            Some(bytes) => self.matches(t) && !self.closed()
                && bytes@ == self.body().subrange(self.position() as int, self.end() as int),
            None => !self.matches(t) || self.closed(),
        },
    {
        if self.closed || !self.pending || t.owner != self.owner || t.generation != self.generation {
            return None;
        }
        Some(slice_subrange(self.bytes.as_slice(), self.sent, self.offered))
    }

    // The adapter reports the number accepted by its one write call, not client delivery.
    // Completion remains valid after cancellation for an already issued write.
    pub fn complete(&mut self, t: &Ticket, count: usize) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).body() == old(self).body(),
            final(self).chunk() == old(self).chunk(), final(self).capacity() == old(self).capacity(),
            final(self).input() == old(self).input(),
            final(self).owner() == old(self).owner(), final(self).strict() == old(self).strict(),
            final(self).closed() == old(self).closed(), final(self).failed() == old(self).failed(),
            final(self).durable() == old(self).durable(),
            final(self).generation() == old(self).generation(),
            ok ==> old(self).matches(t) && !final(self).pending()
                && count <= old(self).end() - old(self).position()
                && final(self).position() == old(self).position() + count
                && final(self).completed() == old(self).completed()
                    + old(self).body().subrange(old(self).position() as int, (old(self).position() + count) as int),
            ok == (old(self).matches(t) && count <= old(self).end() - old(self).position()),
            !ok ==> *final(self) == *old(self),
    {
        if !self.pending || t.owner != self.owner || t.generation != self.generation
            || count > self.offered - self.sent { return false; }
        let ghost start = self.sent;
        self.sent = self.sent + count;
        let ghost suffix = self.bytes@.subrange(start as int, self.sent as int);
        proof { assert(self.history@ + suffix =~= self.prefix@ + self.bytes@.subrange(0, self.sent as int)); }
        self.history = Ghost(self.history@ + suffix);
        self.offered = self.sent;
        self.pending = false;
        true
    }

    // Only a fully completed chunk can be replaced. Ticket generations never reset.
    pub fn advance(&mut self, bytes: Vec<u8>) -> (out: Option<u64>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).owner() == old(self).owner(),
            final(self).strict() == old(self).strict(), final(self).failed() == old(self).failed(),
            final(self).capacity() == old(self).capacity(),
            final(self).generation() == old(self).generation(),
            final(self).completed() == old(self).completed(),
            match out {
                Some(chunk) => chunk == final(self).chunk() && chunk == old(self).chunk() + 1
                    && old(self).position() == old(self).body().len()
                    && !old(self).pending() && !old(self).closed()
                    && final(self).body() == bytes@ && final(self).input() == old(self).input() + bytes@
                    && final(self).position() == 0 && final(self).end() == 0
                    && final(self).durable() == 0 && !final(self).pending() && !final(self).closed(),
                None => *final(self) == *old(self) && (old(self).closed() || old(self).pending()
                    || old(self).position() != old(self).body().len()
                    || bytes.len() > old(self).capacity() || old(self).chunk() == u64::MAX),
            },
    {
        if self.closed || self.pending || self.sent != self.bytes.len()
            || bytes.len() > self.capacity || self.chunk == u64::MAX { return None; }
        proof {
            assert(self.bytes@.subrange(0, self.sent as int) =~= self.bytes@);
            assert(bytes@.subrange(0, 0) =~= Seq::<u8>::empty());
        }
        self.prefix = Ghost(self.history@);
        self.bytes = bytes;
        self.sent = 0;
        self.offered = 0;
        self.durable = 0;
        self.chunk = self.chunk + 1;
        Some(self.chunk)
    }

    // Release completed payload storage before allocating the next input chunk.
    pub fn discard_completed(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            final(self).owner() == old(self).owner(), final(self).capacity() == old(self).capacity(),
            final(self).chunk() == old(self).chunk(), final(self).generation() == old(self).generation(),
            final(self).strict() == old(self).strict(), final(self).failed() == old(self).failed(),
            final(self).closed() == old(self).closed(), final(self).pending() == old(self).pending(),
            final(self).input() == old(self).input(), final(self).completed() == old(self).completed(),
            ok ==> !old(self).closed() && !old(self).pending()
                && old(self).position() == old(self).body().len()
                && final(self).body().len() == 0 && final(self).position() == 0
                && final(self).end() == 0 && final(self).durable() == 0,
            ok == (!old(self).closed() && !old(self).pending() && old(self).position() == old(self).body().len()),
            !ok ==> *final(self) == *old(self),
    {
        if self.closed || self.pending || self.bytes.len() != self.sent { return false; }
        proof { assert(self.bytes@.subrange(0, self.sent as int) =~= self.bytes@); }
        self.prefix = Ghost(self.history@);
        self.bytes = Vec::new();
        self.sent = 0;
        self.offered = 0;
        self.durable = 0;
        true
    }

    pub fn cancel(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).closed(),
            final(self).body() == old(self).body(),
            final(self).chunk() == old(self).chunk(), final(self).capacity() == old(self).capacity(),
            final(self).input() == old(self).input(),
            final(self).completed() == old(self).completed(), final(self).owner() == old(self).owner(),
            final(self).position() == old(self).position(), final(self).strict() == old(self).strict(),
            final(self).pending() == old(self).pending(), final(self).end() == old(self).end(),
            final(self).durable() == old(self).durable(), final(self).failed() == old(self).failed(),
            final(self).generation() == old(self).generation(),
    { self.closed = true; }

    pub fn fail_log(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).failed(),
            final(self).body() == old(self).body(),
            final(self).chunk() == old(self).chunk(), final(self).capacity() == old(self).capacity(),
            final(self).input() == old(self).input(),
            final(self).completed() == old(self).completed(), final(self).owner() == old(self).owner(),
            final(self).position() == old(self).position(), final(self).strict() == old(self).strict(),
            final(self).pending() == old(self).pending(), final(self).end() == old(self).end(),
            final(self).durable() == old(self).durable(),
            final(self).generation() == old(self).generation(),
            old(self).strict() ==> final(self).closed(),
            !old(self).strict() ==> final(self).closed() == old(self).closed(),
    {
        self.failed = true;
        if self.strict { self.closed = true; }
    }
}
}
