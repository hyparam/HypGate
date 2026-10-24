use vstd::prelude::*;
use vstd::slice::slice_subrange;
use crate::{framing::Header, policy::AuthorizedRequest};

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

// Abstract stream state. Transition postconditions equate whole views, so the
// fields a transition leaves alone are stated once by struct update.
pub struct Model {
    pub owner: u64,
    pub capacity: nat,
    pub strict: bool,
    pub chunk: u64,
    pub body: Seq<u8>,
    pub input: Seq<u8>,
    pub completed: Seq<u8>,
    pub position: nat,
    pub end: nat,
    pub durable: nat,
    pub generation: u64,
    pub pending: bool,
    pub closed: bool,
    pub failed: bool,
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

    // Bind the audit metadata and borrowed payload in one checked operation.
    // Authority and stream must be scoped to the same admission instance.
    pub fn audit_record<'a>(&'a self, authority: &AuthorizedRequest, direction: u8)
        -> (out: Option<(Header, &'a [u8])>)
        requires self.valid(), authority.valid(),
        ensures match out {
            Some((h, bytes)) => self.auditable(authority, direction) && crate::framing::valid(h)
                && h == self.audit_header(authority.tenant(), direction) && bytes@ == self.body(),
            None => !self.auditable(authority, direction),
        },
    {
        if self.closed || self.failed || self.owner == 0
            || self.owner != authority.request_id() || self.bytes.len() > 1048576
            || direction > 1 { return None; }
        Some((Header { payload: self.bytes.len() as u32, tenant: authority.tenant_id(),
            request: self.owner, chunk: self.chunk, direction }, self.bytes.as_slice()))
    }

    pub fn capacity_bytes(&self) -> (out: usize)
        ensures out == self.capacity(),
    { self.capacity }

    pub fn owner_id(&self) -> (out: u64)
        ensures out == self.owner(),
    { self.owner }

    pub fn chunk_id(&self) -> (out: u64)
        ensures out == self.chunk(),
    { self.chunk }

    pub fn requires_audit(&self) -> (out: bool)
        ensures out == self.strict(),
    { self.strict }

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

    pub proof fn payload_within_capacity(&self)
        requires self.valid(),
        ensures self.body().len() <= self.capacity(), self.position() <= self.end() <= self.body().len(),
            self.strict() ==> self.end() <= self.durable(),
    {}

    pub closed spec fn model(&self) -> Model {
        Model { owner: self.owner, capacity: self.capacity as nat, strict: self.strict, chunk: self.chunk,
            body: self.bytes@, input: self.prefix@ + self.bytes@, completed: self.history@,
            position: self.sent as nat, end: self.offered as nat, durable: self.durable as nat,
            generation: self.generation, pending: self.pending, closed: self.closed, failed: self.failed }
    }
    pub open spec fn chunk(&self) -> u64 { self.model().chunk }
    pub open spec fn capacity(&self) -> nat { self.model().capacity }
    pub open spec fn input(&self) -> Seq<u8> { self.model().input }
    pub open spec fn completed(&self) -> Seq<u8> { self.model().completed }
    pub open spec fn body(&self) -> Seq<u8> { self.model().body }
    pub open spec fn position(&self) -> nat { self.model().position }
    pub open spec fn end(&self) -> nat { self.model().end }
    pub open spec fn durable(&self) -> nat { self.model().durable }
    pub open spec fn owner(&self) -> u64 { self.model().owner }
    pub open spec fn generation(&self) -> u64 { self.model().generation }
    pub open spec fn pending(&self) -> bool { self.model().pending }
    pub open spec fn closed(&self) -> bool { self.model().closed }
    pub open spec fn strict(&self) -> bool { self.model().strict }
    pub open spec fn failed(&self) -> bool { self.model().failed }
    pub open spec fn matches(&self, t: &Ticket) -> bool {
        self.pending() && t.owner() == self.owner() && t.generation() == self.generation()
    }

    // The current chunk may be audited for this authority in this direction.
    pub open spec fn auditable(&self, authority: &AuthorizedRequest, direction: u8) -> bool {
        !self.closed() && !self.failed() && self.owner() != 0 && self.owner() == authority.request()
            && self.body().len() <= 1048576 && direction <= 1
    }
    pub open spec fn audit_header(&self, tenant: u64, direction: u8) -> Header {
        Header { payload: self.body().len() as u32, tenant, request: self.owner(), chunk: self.chunk(), direction }
    }
    // The canonical record for the current chunk, as a journal receipt must carry it.
    pub open spec fn audit_frame(&self, tenant: u64, direction: u8, checksum: Seq<u8>) -> Seq<u8> {
        crate::framing::encoding(self.audit_header(tenant, direction)) + self.body() + checksum
    }

    // Transition relations shared by this core and the owning wrapper.
    pub open spec fn acknowledged(pre: Self, post: Self, owner: u64, chunk: u64, end: nat, ok: bool) -> bool {
        ok == (!pre.closed() && !pre.failed() && owner == pre.owner() && chunk == pre.chunk()
            && pre.durable() <= end <= pre.body().len())
        && if ok { post.model() == Model { durable: end, ..pre.model() } } else { post == pre }
    }
    pub open spec fn receipt_acknowledged(pre: Self, post: Self, authority: &AuthorizedRequest,
        journal: &crate::journal_binding::JournalBinding, direction: u8, receipt: &crate::journal::DurableFrame, ok: bool) -> bool
    {
        ok == (journal.session() == Some(receipt.session()) && pre.auditable(authority, direction)
            && receipt.record() == pre.audit_frame(authority.tenant(), direction, receipt.checksum()))
        && if ok {
            post.model() == Model { durable: pre.body().len(), ..pre.model() }
                && receipt.acknowledged() == receipt.prefix() + pre.audit_frame(authority.tenant(), direction, receipt.checksum())
        } else { post == pre }
    }
    pub open spec fn prepared(pre: Self, post: Self, max: usize, out: Option<Ticket>) -> bool {
        match out {
            Some(t) => !pre.pending() && !pre.closed() && post.matches(&t)
                && pre.position() < post.end() <= pre.position() + max
                && post.model() == Model { end: post.end(), generation: (pre.generation() + 1) as u64, pending: true, ..pre.model() },
            None => post == pre && (pre.closed() || pre.pending() || max == 0 || pre.generation() == u64::MAX
                || pre.position() == (if pre.strict() { pre.durable() } else { pre.body().len() })),
        }
    }
    pub open spec fn completed_write(pre: Self, post: Self, t: &Ticket, count: usize, ok: bool) -> bool {
        ok == (pre.matches(t) && count <= pre.end() - pre.position())
        && if ok {
            post.model() == Model { position: (pre.position() + count) as nat, end: (pre.position() + count) as nat, pending: false,
                completed: pre.completed() + pre.body().subrange(pre.position() as int, (pre.position() + count) as int),
                ..pre.model() }
        } else { post == pre }
    }
    pub open spec fn advanced(pre: Self, post: Self, bytes: Seq<u8>, out: Option<u64>) -> bool {
        match out {
            Some(chunk) => !pre.pending() && !pre.closed() && pre.position() == pre.body().len()
                && chunk == pre.chunk() + 1
                && post.model() == Model { chunk, body: bytes, input: pre.input() + bytes,
                    position: 0, end: 0, durable: 0, ..pre.model() },
            None => post == pre && (pre.closed() || pre.pending() || pre.position() != pre.body().len()
                || bytes.len() > pre.capacity() || pre.chunk() == u64::MAX),
        }
    }
    pub open spec fn discarded(pre: Self, post: Self, ok: bool) -> bool {
        ok == (!pre.closed() && !pre.pending() && pre.position() == pre.body().len())
        && if ok { post.model() == Model { body: Seq::empty(), position: 0, end: 0, durable: 0, ..pre.model() } }
        else { post == pre }
    }
    pub open spec fn cancelled(pre: Self, post: Self) -> bool {
        post.model() == Model { closed: true, ..pre.model() }
    }
    pub open spec fn log_failed(pre: Self, post: Self) -> bool {
        post.model() == Model { failed: true, closed: pre.closed() || pre.strict(), ..pre.model() }
    }

    pub(crate) fn new(owner: u64, bytes: Vec<u8>, capacity: usize, strict: bool) -> (out: Option<Self>)
        ensures match out {
            Some(s) => s.valid() && s.model() == Model { owner, capacity: capacity as nat, strict, chunk: 0,
                body: bytes@, input: bytes@, completed: Seq::empty(), position: 0, end: 0, durable: 0,
                generation: 0, pending: false, closed: false, failed: false },
            None => bytes.len() > capacity,
        },
    {
        if bytes.len() > capacity { return None; }
        proof { assert(bytes@.subrange(0, 0) =~= Seq::<u8>::empty()); }
        Some(StreamChunk { owner, bytes, capacity, chunk: 0, prefix: Ghost(Seq::empty()), sent: 0, durable: 0, offered: 0,
            generation: 0, pending: false, strict, failed: false, closed: false,
            history: Ghost(Seq::empty()) })
    }

    // Adapters acknowledge only through journal receipts; the raw transition stays crate-private.
    pub(crate) fn acknowledge(&mut self, owner: u64, chunk: u64, end: usize) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), Self::acknowledged(*old(self), *final(self), owner, chunk, end as nat, ok),
    {
        if self.closed || self.failed || owner != self.owner || chunk != self.chunk
            || end < self.durable || end > self.bytes.len() { return false; }
        self.durable = end;
        true
    }

    pub fn acknowledge_receipt(&mut self, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding, direction: u8,
        receipt: &crate::journal::DurableFrame) -> (ok: bool)
        requires old(self).valid(), authority.valid(), receipt.valid(),
        ensures final(self).valid(),
            Self::receipt_acknowledged(*old(self), *final(self), authority, journal, direction, receipt, ok),
    {
        if !journal.accepts(receipt) { return false; }
        let (header, bytes) = match self.audit_record(authority, direction) {
            Some(record) => record, None => return false,
        };
        if !receipt.matches_record(header, bytes) { return false; }
        proof {
            assert(receipt.prefix() + self.audit_frame(authority.tenant(), direction, receipt.checksum())
                =~= receipt.prefix() + crate::framing::encoding(header) + bytes@ + receipt.checksum());
        }
        self.acknowledge(self.owner, self.chunk, self.bytes.len())
    }

    // A reservation does not advance the completed offset.
    pub fn prepare(&mut self, max: usize) -> (out: Option<Ticket>)
        requires old(self).valid(),
        ensures final(self).valid(), Self::prepared(*old(self), *final(self), max, out),
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
        ensures final(self).valid(), Self::completed_write(*old(self), *final(self), t, count, ok),
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
        ensures final(self).valid(), Self::advanced(*old(self), *final(self), bytes@, out),
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
        ensures final(self).valid(), Self::discarded(*old(self), *final(self), ok),
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
        ensures final(self).valid(), Self::cancelled(*old(self), *final(self)),
    { self.closed = true; }

    pub fn fail_log(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), Self::log_failed(*old(self), *final(self)),
    {
        self.failed = true;
        if self.strict { self.closed = true; }
    }
}
}
