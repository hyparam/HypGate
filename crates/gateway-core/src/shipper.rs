//! Verified shipper state machine. Everything the cloud shipper decides lives
//! here: which records become which exchanges, which exchanges go into the next
//! batch, what request to send next and with which credential, how to interpret
//! the server's reply, and how long to wait. The runtime only performs the
//! returned action: read a record, send a request to the one configured server,
//! sleep, or checkpoint. A request carries a path and a body but no host, so the
//! only destination any body can reach is the client built from the configured
//! server. The operator token is private to the machine and appears in exactly
//! one place: the body of a bootstrap request.
//!
//! The machine keeps a ghost history of every projected exchange since the
//! checkpoint it started from. The queue is always the unresolved suffix of
//! that history, an ingest body is exactly the concatenation of the next queued
//! exchanges, and an acknowledgment pops exactly the exchanges that body held.
use vstd::prelude::*;
use crate::batch_builder::{MAX_BYTES, MAX_ROWS};
use crate::enrollment::{throttle_delay, transport_delay, Enrollment, Recovery};
use crate::exchange_assembler::{Assembler, Exchange};
#[allow(unused_imports)] // FLUSH appears only in proof histories.
use crate::exchange_assembler::FLUSH;
use crate::framing::{append, Header};
use crate::upload_cursor::UploadCursor;

verus! {
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Path { Bootstrap, Refresh, Ingest }

/// An outgoing request. No host: the runtime client already knows the server.
pub struct Request { pub path: Path, pub bearer: Option<Vec<u8>>, pub body: Vec<u8>, pub batch_id: Option<Vec<u8>> }

/// What the runtime should do next.
pub enum Action { Read, Send(Request), Sleep(u64), Poisoned, Idle, Stopped }

/// A server-issued credential parsed by the runtime from a bootstrap or refresh reply.
pub struct Credential { pub jwt: Vec<u8>, pub expires_at: u64 }

/// A server reply as the runtime saw it. `revocation` is true for the two
/// permanent error codes; `credential` is present on a successful enrollment.
pub struct Reply { pub status: u16, pub retry_after: Option<u64>, pub revocation: bool, pub credential: Option<Credential> }

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Outcome { Acknowledged(u64), Poisoned, Isolating, Enrolled, Unenrolled, Revoked, Deferred(u64), Nothing }

/// One projected exchange: its NDJSON rows, each followed by a newline, and
/// the row count.
pub struct Pending {
    body: Vec<u8>, rows: usize,
    #[allow(dead_code)] // Source identity retained for the proof.
    source: Ghost<u64>,
}
impl Pending {
    pub closed spec fn body(&self) -> Seq<u8> { self.body@ }
    pub closed spec fn rows(&self) -> nat { self.rows as nat }
    /// The request id of the exchange this projection came from.
    pub closed spec fn source(&self) -> u64 { self.source@ }
}

pub open spec fn concat_bodies(s: Seq<Pending>) -> Seq<u8>
    decreases s.len(),
{
    if s.len() == 0 { Seq::empty() } else { concat_bodies(s.drop_last()) + s.last().body() }
}

/// An exchange the assembler emitted, numbered in emission order. The runtime
/// projects it and hands the token back to `enqueue`; tokens cannot be made or
/// copied elsewhere and a refused one is returned, so every projected exchange
/// is queued in emission order as long as the runtime never drops a token.
pub struct Emitted { exchange: Exchange, index: u64 }
impl Emitted {
    pub closed spec fn index(&self) -> u64 { self.index }
    pub closed spec fn exchange_value(&self) -> Exchange { self.exchange }
    pub open spec fn request(&self) -> u64 { self.exchange_value().request_id() }
    pub fn exchange(&self) -> (out: &Exchange) ensures *out == self.exchange_value(), { &self.exchange }
    pub fn position(&self) -> (out: u64) ensures out == self.index(), { self.index }
}

// FNV-1a over the batch body: a cheap content binding for the batch id that the
// core can compute itself. Distinctness of ids rests on the index range; the
// checksum only ties a resent id to the same bytes.
pub const FNV_OFFSET: u64 = 0xcbf29ce484222325;
pub const FNV_PRIME: u128 = 0x100000001b3;
pub const WORD: u128 = 0x1_0000_0000_0000_0000;

pub open spec fn fnv_step(h: u64, b: u8) -> u64 {
    ((((h ^ (b as u64)) as u128) * FNV_PRIME) as int % (WORD as int)) as u64
}
pub open spec fn fnv(s: Seq<u8>) -> u64
    decreases s.len(),
{
    if s.len() == 0 { FNV_OFFSET } else { fnv_step(fnv(s.drop_last()), s.last()) }
}
pub fn checksum(bytes: &[u8]) -> (out: u64)
    ensures out == fnv(bytes@),
{
    let mut h: u64 = FNV_OFFSET;
    let mut i: usize = 0;
    while i < bytes.len()
        invariant i <= bytes.len(), h == fnv(bytes@.subrange(0, i as int)),
        decreases bytes.len() - i,
    {
        let mixed: u128 = ((h ^ (bytes[i] as u64)) as u128) * FNV_PRIME;
        let reduced: u128 = mixed % WORD;
        h = reduced as u64;
        proof {
            assert(bytes@.subrange(0, i as int + 1).drop_last() =~= bytes@.subrange(0, i as int));
            assert(bytes@.subrange(0, i as int + 1).last() == bytes@[i as int]);
        }
        i = i + 1;
    }
    proof { assert(bytes@.subrange(0, bytes.len() as int) =~= bytes@); }
    h
}

// `{"bootstrap_token":"` and `"}` around the JSON-escaped token.
pub open spec fn bootstrap_prefix() -> Seq<u8> {
    seq![123u8, 34, 98, 111, 111, 116, 115, 116, 114, 97, 112, 95, 116, 111, 107, 101, 110, 34, 58, 34]
}
pub open spec fn bootstrap_suffix() -> Seq<u8> { seq![34u8, 125] }
pub open spec fn escaped(s: Seq<u8>) -> Seq<u8>
    decreases s.len(),
{
    if s.len() == 0 { Seq::empty() }
    else {
        escaped(s.drop_last()) + (if s.last() == 34 || s.last() == 92 { seq![92u8, s.last()] } else { seq![s.last()] })
    }
}
pub open spec fn bootstrap_body(token: Seq<u8>) -> Seq<u8> { bootstrap_prefix() + escaped(token) + bootstrap_suffix() }

fn build_bootstrap_body(token: &[u8]) -> (out: Vec<u8>)
    ensures out@ == bootstrap_body(token@),
{
    let mut out: Vec<u8> = Vec::new();
    out.push(123); out.push(34); out.push(98); out.push(111); out.push(111); out.push(116); out.push(115);
    out.push(116); out.push(114); out.push(97); out.push(112); out.push(95); out.push(116); out.push(111);
    out.push(107); out.push(101); out.push(110); out.push(34); out.push(58); out.push(34);
    proof { assert(out@ =~= bootstrap_prefix()); }
    let ghost prefix = out@;
    let mut i: usize = 0;
    while i < token.len()
        invariant i <= token.len(), out@ == prefix + escaped(token@.subrange(0, i as int)),
        decreases token.len() - i,
    {
        let b = token[i];
        if b == 34 || b == 92 { out.push(92); }
        out.push(b);
        proof {
            assert(token@.subrange(0, i as int + 1).drop_last() =~= token@.subrange(0, i as int));
            assert(token@.subrange(0, i as int + 1).last() == token@[i as int]);
            assert(out@ =~= prefix + escaped(token@.subrange(0, i as int + 1)));
        }
        i = i + 1;
    }
    proof { assert(token@.subrange(0, token.len() as int) =~= token@); }
    out.push(34); out.push(125);
    proof { assert(out@ =~= bootstrap_body(token@)); }
    out
}

fn copy_bytes(bytes: &[u8]) -> (out: Vec<u8>)
    ensures out@ == bytes@,
{
    let mut out: Vec<u8> = Vec::new();
    append(&mut out, bytes);
    out
}

fn bump(attempt: u32) -> (out: u32) ensures out >= attempt, { if attempt < u32::MAX { attempt + 1 } else { attempt } }

pub struct Machine {
    token: Vec<u8>,
    session: [u8; 16],
    max_open: usize,
    max_bytes: usize,
    assembler: Assembler,
    cursor: UploadCursor,
    enrollment: Enrollment,
    jwt: Option<Vec<u8>>,
    queue: Vec<Pending>,
    history: Ghost<Seq<Pending>>,
    /// Every (kind, request) the assembler has seen, flushes included.
    inputs: Ghost<Seq<(u8, u64)>>,
    /// The request id of every emitted exchange, in emission order.
    emissions: Ghost<Seq<u64>>,
    /// Exchanges the checkpoint says the server already holds; the cursor starts there.
    skip: u64,
    /// Exchanges the assembler has emitted, including skipped ones.
    emitted: u64,
    awaiting: Option<Path>,
    force_refresh: bool,
    read_failed: bool,
    at_end: bool,
    delay: u64,
    throttle_attempt: u32,
    transport_attempt: u32,
    enroll_attempt: u32,
    /// After a rejected batch: one exchange per batch until a batch succeeds.
    isolate: bool,
}

impl Machine {
    pub closed spec fn token(&self) -> Seq<u8> { self.token@ }
    pub closed spec fn session(&self) -> Seq<u8> { self.session@ }
    pub closed spec fn max_open(&self) -> nat { self.max_open as nat }
    pub closed spec fn max_bytes(&self) -> nat { self.max_bytes as nat }
    pub closed spec fn skip(&self) -> u64 { self.skip }
    pub closed spec fn emitted(&self) -> u64 { self.emitted }
    pub closed spec fn history(&self) -> Seq<Pending> { self.history@ }
    pub closed spec fn inputs(&self) -> Seq<(u8, u64)> { self.inputs@ }
    pub closed spec fn emissions(&self) -> Seq<u64> { self.emissions@ }
    pub closed spec fn queue(&self) -> Seq<Pending> { self.queue@ }
    pub closed spec fn resolved(&self) -> u64 { self.cursor.resolved() }
    pub closed spec fn poisoned(&self) -> u64 { self.cursor.poisoned() }
    /// Exchanges counted by the cursor: skip plus every enqueued projection.
    pub closed spec fn counted(&self) -> u64 { self.cursor.emitted() }
    pub closed spec fn in_flight(&self) -> Option<crate::upload_cursor::InFlight> { self.cursor.in_flight() }
    pub closed spec fn awaiting(&self) -> Option<Path> { self.awaiting }
    pub closed spec fn enrollment(&self) -> Enrollment { self.enrollment }
    pub closed spec fn jwt(&self) -> Option<Seq<u8>> { match self.jwt { Some(v) => Some(v@), None => None } }
    pub closed spec fn delay(&self) -> u64 { self.delay }
    pub closed spec fn read_failed(&self) -> bool { self.read_failed }
    pub closed spec fn at_end(&self) -> bool { self.at_end }
    pub closed spec fn force_refresh(&self) -> bool { self.force_refresh }
    pub closed spec fn open_count(&self) -> nat { self.assembler.open_count() }
    pub open spec fn stopped(&self) -> bool { self.enrollment().stopped() }
    pub open spec fn enrolled(&self) -> bool { self.enrollment().enrolled_until().is_some() }
    pub open spec fn can_upload(&self, now: u64) -> bool {
        match self.enrollment().enrolled_until() { Some(e) => now < e, None => false }
    }
    /// Emitted exchanges whose projection has not been enqueued yet.
    pub open spec fn outstanding(&self) -> int {
        if self.emitted() > self.counted() { self.emitted() - self.counted() } else { 0 }
    }
    pub open spec fn room(&self) -> bool { self.queue().len() + self.outstanding() < self.max_open() }
    pub open spec fn wants(&self) -> bool { !self.read_failed() && !self.at_end() && self.room() }

    pub closed spec fn valid(&self) -> bool {
        self.assembler.valid() && self.cursor.valid() && 0 < self.max_open
            && self.assembler.max_open() == self.max_open as nat
            && self.assembler.max_bytes() == self.max_bytes as nat
            && self.cursor.emitted() == self.skip + self.history@.len()
            && self.skip <= self.cursor.resolved()
            && self.queue@ == self.history@.subrange((self.cursor.resolved() - self.skip) as int, self.history@.len() as int)
            && (self.emitted < self.skip ==> self.history@.len() == 0)
            && (self.emitted >= self.skip ==> self.cursor.emitted() <= self.emitted)
            && self.queue@.len() + self.outstanding() <= self.max_open
            && (self.cursor.in_flight().is_some() <==> self.awaiting == Some(Path::Ingest))
            && (self.jwt.is_some() <==> self.enrollment.enrolled_until().is_some())
            && self.delay <= crate::enrollment::MAX_DELAY_SECONDS
            // Emission numbering is the functional spec applied to the inputs.
            && self.assembler.open_requests() == crate::exchange_assembler::open_after(self.inputs@, self.max_open as nat)
            && self.emissions@ == crate::exchange_assembler::emitted_requests(self.inputs@, self.max_open as nat)
            && self.emissions@.len() >= self.emitted
            && (!self.read_failed ==> self.emissions@.len() == self.emitted)
            && (forall|j: int| 0 <= j < self.history@.len()
                ==> (#[trigger] self.history@[j]).source() == self.emissions@[self.skip + j])
    }

    /// The replay theorem's machine half: emission numbering is a function of
    /// the inputs alone, and every queued or resolved projection at history
    /// position j came from the exchange numbered skip + j. Two runs over the
    /// same records therefore number the same exchanges identically, so a
    /// restart that skips the checkpointed count skips exactly the exchanges
    /// the earlier run resolved.
    pub proof fn replay_numbering(&self)
        requires self.valid(),
        ensures self.emissions() == crate::exchange_assembler::emitted_requests(self.inputs(), self.max_open()),
            self.emissions().len() >= self.emitted(),
            !self.read_failed() ==> self.emissions().len() == self.emitted(),
            forall|j: int| 0 <= j < self.history().len()
                ==> (#[trigger] self.history()[j]).source() == self.emissions()[self.skip() + j],
            self.skip() + self.history().len() == self.counted(),
    {}

    /// What a valid machine guarantees about its counters, for callers outside this module.
    pub proof fn valid_bounds(&self)
        requires self.valid(),
        ensures self.emitted() >= self.skip() ==> self.counted() <= self.emitted(),
            self.emitted() < self.skip() ==> self.counted() == self.skip(),
            self.skip() <= self.resolved() <= self.counted(),
            self.queue().len() == self.counted() - self.resolved(),
    {
        self.cursor.bounds();
    }

    /// Everything that progress-neutral operations leave alone.
    pub open spec fn same_progress(&self, other: &Self) -> bool {
        self.history() == other.history() && self.queue() == other.queue()
            && self.resolved() == other.resolved() && self.counted() == other.counted()
            && self.poisoned() == other.poisoned() && self.in_flight() == other.in_flight()
            && self.awaiting() == other.awaiting() && self.skip() == other.skip()
            && self.token() == other.token() && self.session() == other.session()
            && self.max_open() == other.max_open() && self.max_bytes() == other.max_bytes()
    }
    /// Progress-neutral and input-neutral.
    pub open spec fn same_inputs(&self, other: &Self) -> bool {
        self.inputs() == other.inputs() && self.emissions() == other.emissions()
    }
    pub open spec fn same_credential(&self, other: &Self) -> bool {
        self.enrollment() == other.enrollment() && self.jwt() == other.jwt() && self.delay() == other.delay()
    }

    /// Start from a checkpoint: `resolved` exchanges of this session are already
    /// on the server and will be skipped when the log is replayed.
    pub fn new(token: Vec<u8>, session: [u8; 16], max_open: usize, max_bytes: usize, resolved: u64, poisoned: u64) -> (out: Self)
        requires 0 < max_open,
        ensures out.valid(), out.token() == token@, out.session() == session@, out.max_open() == max_open,
            out.max_bytes() == max_bytes, out.skip() == resolved, out.resolved() == resolved, out.counted() == resolved,
            out.poisoned() == poisoned, out.emitted() == 0, out.history().len() == 0, out.queue().len() == 0,
            out.inputs().len() == 0, out.emissions().len() == 0,
            out.awaiting().is_none(), !out.stopped(), !out.enrolled(), out.jwt().is_none(), out.delay() == 0,
            !out.read_failed(), !out.at_end(), out.open_count() == 0,
    {
        let cursor = match UploadCursor::restore(resolved, resolved, poisoned) { Some(c) => c, None => { proof { assert(false); } UploadCursor::restore(0, 0, 0).unwrap() } };
        proof { assert(Seq::<Pending>::empty().subrange(0, 0) =~= Seq::<Pending>::empty()); }
        Machine { token, session, max_open, max_bytes, assembler: Assembler::new(max_open, max_bytes), cursor,
            enrollment: Enrollment::new(), jwt: None, queue: Vec::new(), history: Ghost(Seq::empty()),
            inputs: Ghost(Seq::empty()), emissions: Ghost(Seq::empty()), skip: resolved,
            emitted: 0, awaiting: None, force_refresh: false, read_failed: false, at_end: false, delay: 0,
            throttle_attempt: 0, transport_attempt: 0, enroll_attempt: 0, isolate: false }
    }

    /// Adopt a credential saved from an earlier run. Expired or stopped: refused.
    pub fn adopt_identity(&mut self, jwt: Vec<u8>, expires_at: u64, now: u64) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).same_progress(old(self)), final(self).emitted() == old(self).emitted(),
            final(self).same_inputs(old(self)),
            final(self).wants() == old(self).wants(), final(self).delay() == old(self).delay(),
            ok == (!old(self).stopped() && now < expires_at),
            ok ==> final(self).enrollment().state() == (crate::enrollment::State::Enrolled { expires_at }) && final(self).jwt() == Some(jwt@),
            !ok ==> final(self).same_credential(old(self)),
    {
        if !self.enrollment.enrolled(expires_at, now) { return false; }
        self.jwt = Some(jwt);
        true
    }

    pub fn has_room(&self) -> (out: bool) ensures out == self.room(), {
        let outstanding = if self.emitted > self.cursor.counts().0 { self.emitted - self.cursor.counts().0 } else { 0 };
        outstanding < self.max_open as u64 && self.queue.len() < self.max_open - outstanding as usize
    }
    pub fn wants_records(&self) -> (out: bool) ensures out == self.wants(), {
        let outstanding = if self.emitted > self.cursor.counts().0 { self.emitted - self.cursor.counts().0 } else { 0 };
        !self.read_failed && !self.at_end && outstanding < self.max_open as u64 && self.queue.len() < self.max_open - outstanding as usize
    }
    pub fn end_of_log(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).same_progress(old(self)), final(self).same_credential(old(self)),
            final(self).same_inputs(old(self)),
            final(self).emitted() == old(self).emitted(), final(self).at_end(), final(self).read_failed() == old(self).read_failed(),
    { self.at_end = true; }
    pub fn log_failed(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).same_progress(old(self)), final(self).same_credential(old(self)),
            final(self).same_inputs(old(self)),
            final(self).emitted() == old(self).emitted(), final(self).read_failed(),
    { self.read_failed = true; }

    // Number an emitted exchange; exchanges below the checkpoint are dropped.
    // The caller has already pushed the input and the matching emission.
    fn number(&mut self, exchange: Exchange) -> (out: Option<Emitted>)
        requires old(self).valid_except_count(), old(self).room(), !old(self).read_failed,
            old(self).emissions@.len() == old(self).emitted + 1,
            old(self).emissions@ == old(self).emissions@.drop_last().push(exchange.request_id()),
        ensures final(self).valid(), final(self).same_progress(old(self)), final(self).same_credential(old(self)),
            final(self).same_inputs(old(self)), final(self).at_end() == old(self).at_end(),
            match out {
                Some(t) => t.index() == old(self).emitted() && old(self).emitted() >= old(self).skip()
                    && final(self).emitted() == old(self).emitted() + 1 && t.exchange_value() == exchange
                    && final(self).read_failed() == old(self).read_failed()
                    && t.request() == final(self).emissions()[t.index() as int],
                None => (final(self).emitted() == old(self).emitted() + 1 && old(self).emitted() < old(self).skip()
                        && final(self).read_failed() == old(self).read_failed())
                    || (final(self).emitted() == old(self).emitted() && final(self).read_failed()),
            },
    {
        if self.emitted == u64::MAX { self.read_failed = true; return None; }
        let index = self.emitted;
        self.emitted = self.emitted + 1;
        if index < self.skip { return None; }
        Some(Emitted { exchange, index })
    }

    // `valid` with the emission count one ahead of `emitted`: the state between
    // recording an emission and numbering it.
    spec fn valid_except_count(&self) -> bool {
        self.assembler.valid() && self.cursor.valid() && 0 < self.max_open
            && self.assembler.max_open() == self.max_open as nat
            && self.assembler.max_bytes() == self.max_bytes as nat
            && self.cursor.emitted() == self.skip + self.history@.len()
            && self.skip <= self.cursor.resolved()
            && self.queue@ == self.history@.subrange((self.cursor.resolved() - self.skip) as int, self.history@.len() as int)
            && (self.emitted < self.skip ==> self.history@.len() == 0)
            && (self.emitted >= self.skip ==> self.cursor.emitted() <= self.emitted)
            && self.queue@.len() + self.outstanding() <= self.max_open
            && (self.cursor.in_flight().is_some() <==> self.awaiting == Some(Path::Ingest))
            && (self.jwt.is_some() <==> self.enrollment.enrolled_until().is_some())
            && self.delay <= crate::enrollment::MAX_DELAY_SECONDS
            && self.assembler.open_requests() == crate::exchange_assembler::open_after(self.inputs@, self.max_open as nat)
            && self.emissions@ == crate::exchange_assembler::emitted_requests(self.inputs@, self.max_open as nat)
            && (forall|j: int| 0 <= j < self.history@.len()
                ==> (#[trigger] self.history@[j]).source() == self.emissions@[self.skip + j])
    }

    /// Admit one scanned record. An exchange that completes, is orphaned, or is
    /// evicted comes back as a token to project and enqueue.
    pub fn admit(&mut self, header: Header, payload: &[u8]) -> (out: Option<Emitted>)
        requires old(self).valid(), old(self).wants(), crate::framing::valid(header), header.payload == payload.len(),
        ensures final(self).valid(), final(self).same_progress(old(self)), final(self).same_credential(old(self)),
            !final(self).at_end(),
            final(self).inputs() == old(self).inputs().push((header.kind, header.request)),
            final(self).emissions() == crate::exchange_assembler::emitted_requests(final(self).inputs(), old(self).max_open()),
            match out {
                Some(t) => t.index() == old(self).emitted() && old(self).emitted() >= old(self).skip()
                    && final(self).emitted() == old(self).emitted() + 1 && t.exchange_value().valid(old(self).max_bytes())
                    && !final(self).read_failed() && t.request() == final(self).emissions()[t.index() as int],
                None => (final(self).emitted() == old(self).emitted() + 1 && old(self).emitted() < old(self).skip()
                        && !final(self).read_failed())
                    || final(self).emitted() == old(self).emitted(),
            },
    {
        let ghost before = self.inputs@;
        let ghost open = self.assembler.open_requests();
        let out = self.assembler.admit(header, payload);
        self.inputs = Ghost(before.push((header.kind, header.request)));
        proof {
            assert(self.inputs@.drop_last() =~= before);
            assert(self.inputs@.last() == (header.kind, header.request));
        }
        match out {
            None => {
                proof { assert(self.emissions@ == crate::exchange_assembler::emitted_requests(self.inputs@, self.max_open as nat)); }
                None
            }
            Some(exchange) => {
                self.emissions = Ghost(self.emissions@.push(exchange.request_id()));
                proof { assert(self.emissions@.drop_last() =~= old(self).emissions@); }
                self.number(exchange)
            }
        }
    }

    /// Emit the oldest open exchange as incomplete (end of a finished log).
    pub fn flush(&mut self) -> (out: Option<Emitted>)
        requires old(self).valid(), old(self).room(), !old(self).read_failed(),
        ensures final(self).valid(), final(self).same_progress(old(self)), final(self).same_credential(old(self)),
            final(self).at_end() == old(self).at_end(),
            final(self).inputs() == old(self).inputs().push((FLUSH, 0)),
            final(self).emissions() == crate::exchange_assembler::emitted_requests(final(self).inputs(), old(self).max_open()),
            match out {
                Some(t) => t.index() == old(self).emitted() && old(self).emitted() >= old(self).skip()
                    && final(self).emitted() == old(self).emitted() + 1 && t.exchange_value().is_incomplete()
                    && t.request() == final(self).emissions()[t.index() as int],
                None => (final(self).emitted() == old(self).emitted() + 1 && old(self).emitted() < old(self).skip())
                    || (final(self).emitted() == old(self).emitted() && (old(self).open_count() == 0 || final(self).read_failed())),
            },
    {
        let ghost before = self.inputs@;
        let out = self.assembler.evict_oldest();
        self.inputs = Ghost(before.push((FLUSH, 0)));
        proof {
            assert(self.inputs@.drop_last() =~= before);
            assert(self.inputs@.last() == (FLUSH, 0u64));
        }
        match out {
            None => {
                proof { assert(self.emissions@ == crate::exchange_assembler::emitted_requests(self.inputs@, self.max_open as nat)); }
                None
            }
            Some(exchange) => {
                self.emissions = Ghost(self.emissions@.push(exchange.request_id()));
                proof { assert(self.emissions@.drop_last() =~= old(self).emissions@); }
                self.number(exchange)
            }
        }
    }

    /// Queue the projection of an emitted exchange. Tokens are numbered in
    /// emission order and accepted only in that order.
    pub fn enqueue(&mut self, token: Emitted, body: Vec<u8>, rows: usize) -> (out: Result<(), Emitted>)
        requires old(self).valid(), token.index() < old(self).emitted(),
            token.request() == old(self).emissions()[token.index() as int],
        ensures final(self).valid(), final(self).same_credential(old(self)), final(self).emitted() == old(self).emitted(),
            final(self).same_inputs(old(self)),
            final(self).resolved() == old(self).resolved(), final(self).poisoned() == old(self).poisoned(),
            final(self).in_flight() == old(self).in_flight(), final(self).awaiting() == old(self).awaiting(),
            final(self).skip() == old(self).skip(), final(self).token() == old(self).token(),
            final(self).session() == old(self).session(), final(self).max_open() == old(self).max_open(),
            final(self).max_bytes() == old(self).max_bytes(), final(self).at_end() == old(self).at_end(),
            final(self).read_failed() == old(self).read_failed(),
            out.is_ok() == (token.index() == old(self).counted()),
            out.is_ok() ==> final(self).counted() == old(self).counted() + 1
                && final(self).history().len() == old(self).history().len() + 1
                && final(self).history() == old(self).history().push(final(self).history().last())
                && final(self).history().last().body() == body@ && final(self).history().last().rows() == rows
                && final(self).history().last().source() == token.request()
                && final(self).queue() == old(self).queue().push(final(self).history().last()),
            // A refused token comes back untouched, so nothing is lost.
            match out {
                Err(t) => t.index() == token.index() && t.exchange_value() == token.exchange_value()
                    && final(self).history() == old(self).history() && final(self).queue() == old(self).queue()
                    && final(self).counted() == old(self).counted(),
                Ok(()) => true,
            },
    {
        proof { old(self).cursor.bounds(); }
        let (counted, _resolved, _) = self.cursor.counts();
        if token.index != counted { return Err(token); }
        let _ok = self.cursor.emit(1);
        proof { assert(_ok); self.cursor.bounds(); }
        let pending = Pending { body, rows, source: Ghost(token.exchange.request_id()) };
        let ghost before = self.history@;
        let ghost start = (_resolved - self.skip) as int;
        self.queue.push(pending);
        self.history = Ghost(before.push(pending));
        proof {
            assert(self.history@.subrange(start, self.history@.len() as int)
                =~= before.subrange(start, before.len() as int).push(pending));
        }
        Ok(())
    }

    // Drop the first `count` queued exchanges.
    fn pop_front(&mut self, count: usize)
        requires count <= old(self).queue@.len(),
        ensures final(self).queue@ == old(self).queue@.subrange(count as int, old(self).queue@.len() as int),
            final(self).token == old(self).token, final(self).session == old(self).session,
            final(self).max_open == old(self).max_open, final(self).max_bytes == old(self).max_bytes,
            final(self).assembler == old(self).assembler, final(self).cursor == old(self).cursor,
            final(self).enrollment == old(self).enrollment, final(self).jwt == old(self).jwt,
            final(self).history == old(self).history, final(self).skip == old(self).skip,
            final(self).inputs == old(self).inputs, final(self).emissions == old(self).emissions,
            final(self).emitted == old(self).emitted, final(self).awaiting == old(self).awaiting,
            final(self).force_refresh == old(self).force_refresh, final(self).read_failed == old(self).read_failed,
            final(self).at_end == old(self).at_end, final(self).delay == old(self).delay,
            final(self).throttle_attempt == old(self).throttle_attempt,
            final(self).transport_attempt == old(self).transport_attempt,
            final(self).enroll_attempt == old(self).enroll_attempt, final(self).isolate == old(self).isolate,
    {
        let mut i: usize = 0;
        while i < count
            invariant i <= count, count <= old(self).queue@.len(),
                self.queue@ == old(self).queue@.subrange(i as int, old(self).queue@.len() as int),
                self.token == old(self).token, self.session == old(self).session,
                self.max_open == old(self).max_open, self.max_bytes == old(self).max_bytes,
                self.assembler == old(self).assembler, self.cursor == old(self).cursor,
                self.enrollment == old(self).enrollment, self.jwt == old(self).jwt,
                self.history == old(self).history, self.skip == old(self).skip,
                self.inputs == old(self).inputs, self.emissions == old(self).emissions,
                self.emitted == old(self).emitted, self.awaiting == old(self).awaiting,
                self.force_refresh == old(self).force_refresh, self.read_failed == old(self).read_failed,
                self.at_end == old(self).at_end, self.delay == old(self).delay,
                self.throttle_attempt == old(self).throttle_attempt,
                self.transport_attempt == old(self).transport_attempt,
                self.enroll_attempt == old(self).enroll_attempt, self.isolate == old(self).isolate,
            decreases count - i,
        {
            let ghost before = self.queue@;
            self.queue.remove(0);
            proof {
                before.remove_ensures(0);
                assert(self.queue@ =~= old(self).queue@.subrange(i as int + 1, old(self).queue@.len() as int));
            }
            i = i + 1;
        }
    }

    /// Choose the next action. Called only when no request is outstanding.
    pub fn next(&mut self, now: u64) -> (out: Action)
        requires old(self).valid(), old(self).awaiting().is_none(),
        ensures final(self).valid(), final(self).history() == old(self).history(), final(self).same_inputs(old(self)),
            final(self).emitted() == old(self).emitted(), final(self).skip() == old(self).skip(),
            final(self).counted() == old(self).counted(),
            final(self).token() == old(self).token(), final(self).session() == old(self).session(),
            final(self).enrollment() == old(self).enrollment(), final(self).jwt() == old(self).jwt(),
            final(self).read_failed() == old(self).read_failed(),
            match out {
                Action::Stopped => old(self).stopped() && *final(self) == *old(self),
                Action::Sleep(d) => !old(self).stopped() && d == old(self).delay() && 1 <= d <= crate::enrollment::MAX_DELAY_SECONDS
                    && final(self).delay() == 0 && final(self).queue() == old(self).queue()
                    && final(self).resolved() == old(self).resolved() && final(self).awaiting().is_none(),
                Action::Read => !old(self).stopped() && old(self).delay() == 0 && old(self).wants() && *final(self) == *old(self),
                Action::Idle => !old(self).stopped() && old(self).delay() == 0 && !old(self).wants()
                    && old(self).queue().len() == 0 && final(self).queue().len() == 0
                    && final(self).resolved() == old(self).resolved() && final(self).awaiting().is_none(),
                Action::Send(r) => !old(self).stopped() && old(self).delay() == 0 && !old(self).wants()
                    && old(self).queue().len() > 0 && final(self).queue() == old(self).queue()
                    && final(self).resolved() == old(self).resolved() && final(self).awaiting() == Some(r.path)
                    && match r.path {
                        Path::Bootstrap => r.body@ == bootstrap_body(old(self).token()) && r.bearer.is_none()
                            && r.batch_id.is_none() && old(self).enrollment().state() == crate::enrollment::State::Unenrolled
                            && final(self).in_flight().is_none(),
                        Path::Refresh => r.body@.len() == 0 && r.batch_id.is_none() && old(self).enrolled()
                            && (match r.bearer { Some(b) => Some(b@) == old(self).jwt(), None => false })
                            && final(self).in_flight().is_none(),
                        Path::Ingest => old(self).can_upload(now) && !old(self).force_refresh() && r.body@.len() <= MAX_BYTES
                            && (match r.bearer { Some(b) => Some(b@) == old(self).jwt(), None => false })
                            && match final(self).in_flight() {
                                Some(b) => b.first() == old(self).resolved() && b.first() < b.end()
                                    && b.end() <= old(self).counted()
                                    && r.body@ == concat_bodies(old(self).history().subrange(
                                        (b.first() - old(self).skip()) as int, (b.end() - old(self).skip()) as int))
                                    && b.id() == crate::shipping_identity::batch_id_encoding(old(self).session(), b.first(), b.end(), fnv(r.body@))
                                    && (match r.batch_id { Some(id) => id@ == b.id(), None => false }),
                                None => false,
                            },
                    },
                Action::Poisoned => !old(self).stopped() && old(self).delay() == 0 && !old(self).wants()
                    && old(self).queue().len() > 0 && old(self).can_upload(now)
                    && final(self).resolved() == old(self).resolved() + 1
                    && final(self).queue() == old(self).queue().drop_first() && final(self).awaiting().is_none()
                    && final(self).poisoned() >= old(self).poisoned()
                    && (old(self).queue()[0].rows() > MAX_ROWS || old(self).queue()[0].body().len() > MAX_BYTES),
            },
            // Pending work with a usable credential is always sent or poisoned.
            (!old(self).stopped() && old(self).delay() == 0 && !old(self).wants() && old(self).queue().len() > 0
                && !old(self).force_refresh()
                && (match old(self).enrollment().enrolled_until() { Some(e) => e > now + crate::enrollment::RENEWAL_WINDOW_SECONDS, None => false }))
                ==> (match out { Action::Send(r) => r.path == Path::Ingest, Action::Poisoned => true, _ => false }),
    {
        proof { old(self).cursor.bounds(); }
        if self.enrollment.is_stopped() { return Action::Stopped; }
        if self.delay > 0 {
            let d = self.delay;
            self.delay = 0;
            self.at_end = false;
            return Action::Sleep(d);
        }
        if self.wants_records() { return Action::Read; }
        if self.queue.len() == 0 { self.at_end = false; return Action::Idle; }
        if self.enrollment.needs_bootstrap() {
            self.awaiting = Some(Path::Bootstrap);
            let body = build_bootstrap_body(self.token.as_slice());
            return Action::Send(Request { path: Path::Bootstrap, bearer: None, body, batch_id: None });
        }
        if self.force_refresh || self.enrollment.needs_refresh(now) {
            let bearer = match &self.jwt { Some(jwt) => copy_bytes(jwt.as_slice()), None => { proof { assert(false); } Vec::new() } };
            self.awaiting = Some(Path::Refresh);
            return Action::Send(Request { path: Path::Refresh, bearer: Some(bearer), body: Vec::new(), batch_id: None });
        }
        // Enrolled and outside the renewal window, so the credential is unexpired.
        proof { assert(self.can_upload(now)); }
        let limit: usize = if self.isolate { 1 } else { self.queue.len() };
        let mut count: usize = 0;
        let mut rows: usize = 0;
        let mut bytes: usize = 0;
        while count < limit
            invariant count <= limit, limit <= self.queue@.len(), rows <= MAX_ROWS, bytes <= MAX_BYTES,
                bytes == concat_bodies(self.queue@.subrange(0, count as int)).len(), count == 0 ==> rows == 0,
            ensures count <= limit, bytes <= MAX_BYTES, bytes == concat_bodies(self.queue@.subrange(0, count as int)).len(),
                count == 0 ==> rows == 0,
                count < limit ==> self.queue@[count as int].rows() + rows > MAX_ROWS
                    || self.queue@[count as int].body().len() + bytes > MAX_BYTES,
            decreases limit - count,
        {
            let p = &self.queue[count];
            if p.rows > MAX_ROWS - rows || p.body.len() > MAX_BYTES - bytes { break; }
            rows = rows + p.rows;
            bytes = bytes + p.body.len();
            proof {
                assert(self.queue@.subrange(0, count as int + 1).drop_last() =~= self.queue@.subrange(0, count as int));
                assert(self.queue@.subrange(0, count as int + 1).last() == self.queue@[count as int]);
            }
            count = count + 1;
        }
        if count == 0 {
            // The front exchange can never be sent on its own: poison it unsent.
            let _opened = self.cursor.open_batch(1, &self.session, 0);
            proof { assert(_opened); self.cursor.bounds(); }
            let _poisoned = self.cursor.poison();
            proof { assert(_poisoned); self.cursor.bounds(); }
            self.pop_front(1);
            self.at_end = false;
            proof {
                assert(self.queue@ =~= self.history@.subrange((self.cursor.resolved() - self.skip) as int, self.history@.len() as int));
                assert(self.queue@ =~= old(self).queue@.drop_first());
            }
            return Action::Poisoned;
        }
        let mut body: Vec<u8> = Vec::new();
        let mut i: usize = 0;
        proof { assert(self.queue@.subrange(0, 0) =~= Seq::<Pending>::empty()); }
        while i < count
            invariant i <= count, count <= self.queue@.len(), body@ == concat_bodies(self.queue@.subrange(0, i as int)),
                self.queue@ == old(self).queue@,
            decreases count - i,
        {
            append(&mut body, self.queue[i].body.as_slice());
            proof {
                assert(self.queue@.subrange(0, i as int + 1).drop_last() =~= self.queue@.subrange(0, i as int));
                assert(self.queue@.subrange(0, i as int + 1).last() == self.queue@[i as int]);
            }
            i = i + 1;
        }
        let sum = checksum(body.as_slice());
        let _opened = self.cursor.open_batch(count as u64, &self.session, sum);
        proof { assert(_opened); self.cursor.bounds(); }
        let id = match self.cursor.current() { Some(b) => copy_bytes(b.batch_id().as_slice()), None => { proof { assert(false); } Vec::new() } };
        let bearer = match &self.jwt { Some(jwt) => copy_bytes(jwt.as_slice()), None => { proof { assert(false); } Vec::new() } };
        self.awaiting = Some(Path::Ingest);
        proof {
            let start = (old(self).cursor.resolved() - self.skip) as int;
            assert(self.history@.subrange(start, start + count as int) =~= self.queue@.subrange(0, count as int));
        }
        Action::Send(Request { path: Path::Ingest, bearer: Some(bearer), body, batch_id: Some(id) })
    }

    fn throttle(&mut self, retry_after: Option<u64>) -> (out: u64)
        ensures 1 <= out <= crate::enrollment::MAX_DELAY_SECONDS, final(self).delay == out,
            final(self).token == old(self).token, final(self).session == old(self).session,
            final(self).max_open == old(self).max_open, final(self).max_bytes == old(self).max_bytes,
            final(self).assembler == old(self).assembler, final(self).cursor == old(self).cursor,
            final(self).enrollment == old(self).enrollment, final(self).jwt == old(self).jwt,
            final(self).queue == old(self).queue, final(self).history == old(self).history,
            final(self).inputs == old(self).inputs, final(self).emissions == old(self).emissions,
            final(self).skip == old(self).skip, final(self).emitted == old(self).emitted,
            final(self).awaiting == old(self).awaiting, final(self).force_refresh == old(self).force_refresh,
            final(self).read_failed == old(self).read_failed, final(self).at_end == old(self).at_end,
            final(self).isolate == old(self).isolate,
    {
        let delay = throttle_delay(self.throttle_attempt, retry_after);
        self.throttle_attempt = bump(self.throttle_attempt);
        self.delay = delay;
        delay
    }
    fn transport_failure(&mut self) -> (out: u64)
        ensures 1 <= out <= crate::enrollment::MAX_DELAY_SECONDS, final(self).delay == out,
            final(self).token == old(self).token, final(self).session == old(self).session,
            final(self).max_open == old(self).max_open, final(self).max_bytes == old(self).max_bytes,
            final(self).assembler == old(self).assembler, final(self).cursor == old(self).cursor,
            final(self).enrollment == old(self).enrollment, final(self).jwt == old(self).jwt,
            final(self).queue == old(self).queue, final(self).history == old(self).history,
            final(self).inputs == old(self).inputs, final(self).emissions == old(self).emissions,
            final(self).skip == old(self).skip, final(self).emitted == old(self).emitted,
            final(self).awaiting == old(self).awaiting, final(self).force_refresh == old(self).force_refresh,
            final(self).read_failed == old(self).read_failed, final(self).at_end == old(self).at_end,
            final(self).isolate == old(self).isolate,
    {
        let delay = transport_delay(self.transport_attempt);
        self.transport_attempt = bump(self.transport_attempt);
        self.delay = delay;
        delay
    }
    fn enroll_backoff(&mut self) -> (out: u64)
        ensures 1 <= out <= crate::enrollment::MAX_DELAY_SECONDS, final(self).delay == out,
            final(self).token == old(self).token, final(self).session == old(self).session,
            final(self).max_open == old(self).max_open, final(self).max_bytes == old(self).max_bytes,
            final(self).assembler == old(self).assembler, final(self).cursor == old(self).cursor,
            final(self).enrollment == old(self).enrollment, final(self).jwt == old(self).jwt,
            final(self).queue == old(self).queue, final(self).history == old(self).history,
            final(self).inputs == old(self).inputs, final(self).emissions == old(self).emissions,
            final(self).skip == old(self).skip, final(self).emitted == old(self).emitted,
            final(self).awaiting == old(self).awaiting, final(self).force_refresh == old(self).force_refresh,
            final(self).read_failed == old(self).read_failed, final(self).at_end == old(self).at_end,
            final(self).isolate == old(self).isolate,
    {
        let delay = throttle_delay(self.enroll_attempt, None);
        self.enroll_attempt = bump(self.enroll_attempt);
        self.delay = delay;
        delay
    }
    fn revoke(&mut self)
        ensures final(self).enrollment.stopped(), final(self).jwt.is_none(), final(self).delay == old(self).delay,
            final(self).token == old(self).token, final(self).session == old(self).session,
            final(self).max_open == old(self).max_open, final(self).max_bytes == old(self).max_bytes,
            final(self).assembler == old(self).assembler, final(self).cursor == old(self).cursor,
            final(self).queue == old(self).queue, final(self).history == old(self).history,
            final(self).inputs == old(self).inputs, final(self).emissions == old(self).emissions,
            final(self).skip == old(self).skip, final(self).emitted == old(self).emitted,
            final(self).awaiting == old(self).awaiting, final(self).force_refresh == old(self).force_refresh,
            final(self).read_failed == old(self).read_failed, final(self).at_end == old(self).at_end,
            final(self).isolate == old(self).isolate,
    {
        self.enrollment.revoked();
        self.jwt = None;
    }

    /// Absorb the reply to the outstanding request.
    pub fn reply(&mut self, now: u64, reply: Reply) -> (out: Outcome)
        requires old(self).valid(), old(self).awaiting().is_some(),
        ensures final(self).valid(), final(self).awaiting().is_none(), final(self).in_flight().is_none(),
            final(self).history() == old(self).history(), final(self).emitted() == old(self).emitted(),
            final(self).counted() == old(self).counted(),
            final(self).same_inputs(old(self)),
            final(self).skip() == old(self).skip(), final(self).token() == old(self).token(),
            final(self).session() == old(self).session(), final(self).read_failed() == old(self).read_failed(),
            !final(self).at_end(),
            // Enrollment replies never move progress.
            old(self).awaiting() != Some(Path::Ingest) ==> final(self).queue() == old(self).queue()
                && final(self).resolved() == old(self).resolved() && final(self).poisoned() == old(self).poisoned(),
            // An accepted ingest resolves exactly the batch that was in flight.
            old(self).awaiting() == Some(Path::Ingest) && (reply.status == 200 || reply.status == 202)
                ==> (match old(self).in_flight() {
                    Some(b) => out == Outcome::Acknowledged((b.end() - b.first()) as u64) && final(self).resolved() == b.end()
                        && final(self).queue() == old(self).queue().subrange((b.end() - b.first()) as int, old(self).queue().len() as int)
                        && final(self).poisoned() == old(self).poisoned(),
                    None => false,
                }),
            // Any other ingest reply resolves nothing, except a rejection of a
            // single-exchange batch, which poisons exactly that exchange.
            old(self).awaiting() == Some(Path::Ingest) && !(reply.status == 200 || reply.status == 202)
                ==> (if out == Outcome::Poisoned {
                        final(self).resolved() == old(self).resolved() + 1
                            && final(self).queue() == old(self).queue().drop_first()
                            && (reply.status == 400 || reply.status == 413 || reply.status == 415 || reply.status == 422)
                    } else {
                        final(self).resolved() == old(self).resolved() && final(self).queue() == old(self).queue()
                            && final(self).poisoned() == old(self).poisoned()
                    }),
            // A credential is adopted only from a 200 with an unexpired expiry.
            final(self).enrolled() && !old(self).enrolled()
                ==> reply.status == 200 && (match reply.credential {
                    Some(c) => now < c.expires_at && final(self).jwt() == Some(c.jwt@)
                        && final(self).enrollment().state() == (crate::enrollment::State::Enrolled { expires_at: c.expires_at }),
                    None => false,
                }),
            // Revocation stops the machine for good; nothing else does.
            final(self).stopped() == (old(self).stopped() || (reply.status == 403 && reply.revocation)),
            out == Outcome::Revoked ==> final(self).stopped(),
            out == Outcome::Isolating ==> (match old(self).in_flight() { Some(b) => b.end() - b.first() > 1, None => false }),
            // Every deferral is a bounded wait.
            (match out { Outcome::Deferred(d) => 1 <= d <= crate::enrollment::MAX_DELAY_SECONDS && final(self).delay() == d, _ => true }),
    {
        let path = match self.awaiting { Some(p) => p, None => { proof { assert(false); } Path::Ingest } };
        if path == Path::Ingest { self.reply_ingest(reply) } else { self.reply_enrollment(now, path == Path::Bootstrap, reply) }
    }

    fn reply_ingest(&mut self, reply: Reply) -> (out: Outcome)
        requires old(self).valid(), old(self).awaiting() == Some(Path::Ingest),
        ensures final(self).valid(), final(self).awaiting().is_none(), final(self).in_flight().is_none(),
            final(self).history() == old(self).history(), final(self).emitted() == old(self).emitted(),
            final(self).counted() == old(self).counted(),
            final(self).same_inputs(old(self)),
            final(self).skip() == old(self).skip(), final(self).token() == old(self).token(),
            final(self).session() == old(self).session(), final(self).read_failed() == old(self).read_failed(),
            !final(self).at_end(),
            (reply.status == 200 || reply.status == 202)
                ==> (match old(self).in_flight() {
                    Some(b) => out == Outcome::Acknowledged((b.end() - b.first()) as u64) && final(self).resolved() == b.end()
                        && final(self).queue() == old(self).queue().subrange((b.end() - b.first()) as int, old(self).queue().len() as int)
                        && final(self).poisoned() == old(self).poisoned(),
                    None => false,
                }),
            !(reply.status == 200 || reply.status == 202)
                ==> (if out == Outcome::Poisoned {
                        final(self).resolved() == old(self).resolved() + 1
                            && final(self).queue() == old(self).queue().drop_first()
                            && (reply.status == 400 || reply.status == 413 || reply.status == 415 || reply.status == 422)
                    } else {
                        final(self).resolved() == old(self).resolved() && final(self).queue() == old(self).queue()
                            && final(self).poisoned() == old(self).poisoned()
                    }),
            final(self).enrolled() ==> old(self).enrolled(),
            final(self).stopped() == (old(self).stopped() || (reply.status == 403 && reply.revocation)),
            out == Outcome::Revoked ==> final(self).stopped(),
            out == Outcome::Isolating ==> (match old(self).in_flight() { Some(b) => b.end() - b.first() > 1, None => false }),
            (match out { Outcome::Deferred(d) => 1 <= d <= crate::enrollment::MAX_DELAY_SECONDS && final(self).delay() == d, _ => true }),
    {
        proof { old(self).cursor.bounds(); }
        self.awaiting = None;
        self.at_end = false;
        let (first, end) = match self.cursor.current() { Some(b) => b.range(), None => { proof { assert(false); } (0, 0) } };
        let count = end - first;
        proof { assert(count <= self.queue@.len()); }
        match reply.status {
            200 | 202 => {
                let id = match self.cursor.current() { Some(b) => copy_bytes(b.batch_id().as_slice()), None => { proof { assert(false); } Vec::new() } };
                let _ok = self.cursor.acknowledge(id.as_slice());
                proof { assert(_ok); self.cursor.bounds(); }
                self.pop_front(count as usize);
                self.enrollment.uploaded();
                self.throttle_attempt = 0;
                self.transport_attempt = 0;
                self.isolate = false;
                proof {
                    assert(self.queue@ =~= self.history@.subrange((self.cursor.resolved() - self.skip) as int, self.history@.len() as int));
                }
                Outcome::Acknowledged(count)
            }
            401 => {
                self.cursor.abandon();
                match self.enrollment.rejected() {
                    Recovery::Refresh => { self.force_refresh = true; Outcome::Nothing }
                    Recovery::Bootstrap => { self.jwt = None; self.force_refresh = false; Outcome::Unenrolled }
                    Recovery::Stop => Outcome::Nothing,
                }
            }
            403 => {
                self.cursor.abandon();
                if reply.revocation { self.revoke(); Outcome::Revoked }
                else { Outcome::Deferred(self.throttle(None)) }
            }
            400 | 413 | 415 | 422 => {
                if count > 1 {
                    self.cursor.abandon();
                    self.isolate = true;
                    Outcome::Isolating
                } else {
                    let _poisoned = self.cursor.poison();
                    proof { assert(_poisoned); self.cursor.bounds(); }
                    self.pop_front(1);
                    proof {
                        assert(self.queue@ =~= self.history@.subrange((self.cursor.resolved() - self.skip) as int, self.history@.len() as int));
                        assert(self.queue@ =~= old(self).queue@.drop_first());
                    }
                    Outcome::Poisoned
                }
            }
            429 | 503 => { self.cursor.abandon(); Outcome::Deferred(self.throttle(reply.retry_after)) }
            _ => { self.cursor.abandon(); Outcome::Deferred(self.transport_failure()) }
        }
    }

    fn reply_enrollment(&mut self, now: u64, bootstrap: bool, reply: Reply) -> (out: Outcome)
        requires old(self).valid(), old(self).awaiting().is_some(), old(self).awaiting() != Some(Path::Ingest),
        ensures final(self).valid(), final(self).awaiting().is_none(), final(self).in_flight().is_none(),
            final(self).history() == old(self).history(), final(self).emitted() == old(self).emitted(),
            final(self).counted() == old(self).counted(),
            final(self).same_inputs(old(self)),
            final(self).skip() == old(self).skip(), final(self).token() == old(self).token(),
            final(self).session() == old(self).session(), final(self).read_failed() == old(self).read_failed(),
            !final(self).at_end(), final(self).queue() == old(self).queue(),
            final(self).resolved() == old(self).resolved(), final(self).poisoned() == old(self).poisoned(),
            final(self).enrolled() && !old(self).enrolled()
                ==> reply.status == 200 && (match reply.credential {
                    Some(c) => now < c.expires_at && final(self).jwt() == Some(c.jwt@)
                        && final(self).enrollment().state() == (crate::enrollment::State::Enrolled { expires_at: c.expires_at }),
                    None => false,
                }),
            final(self).stopped() == (old(self).stopped() || (reply.status == 403 && reply.revocation)),
            out == Outcome::Revoked ==> final(self).stopped(),
            out != Outcome::Isolating && out != Outcome::Poisoned,
            (match out { Outcome::Deferred(d) => 1 <= d <= crate::enrollment::MAX_DELAY_SECONDS && final(self).delay() == d, _ => true }),
    {
        proof { old(self).cursor.bounds(); }
        self.awaiting = None;
        self.at_end = false;
        match reply.status {
            200 => match reply.credential {
                Some(credential) => {
                    if self.enrollment.enrolled(credential.expires_at, now) {
                        self.jwt = Some(credential.jwt);
                        self.enroll_attempt = 0;
                        self.force_refresh = false;
                        Outcome::Enrolled
                    } else {
                        Outcome::Deferred(self.enroll_backoff())
                    }
                }
                None => Outcome::Deferred(self.enroll_backoff()),
            },
            403 if reply.revocation => { self.revoke(); Outcome::Revoked }
            401 | 400 | 403 => {
                if bootstrap { Outcome::Deferred(self.enroll_backoff()) }
                else {
                    self.enrollment.refresh_rejected();
                    self.jwt = None;
                    self.force_refresh = false;
                    Outcome::Unenrolled
                }
            }
            429 | 503 => Outcome::Deferred(self.throttle(reply.retry_after)),
            _ => Outcome::Deferred(self.transport_failure()),
        }
    }

    pub fn progress(&self) -> (out: (u64, u64))
        ensures out.0 == self.resolved(), out.1 == self.poisoned(),
    { let (_, resolved, poisoned) = self.cursor.counts(); (resolved, poisoned) }
    pub fn queue_len(&self) -> (out: usize) ensures out == self.queue().len(), { self.queue.len() }
    pub fn open_exchanges(&self) -> (out: usize) ensures out == self.open_count(), { self.assembler.open_exchanges() }
    pub fn emitted_count(&self) -> (out: u64) ensures out == self.emitted(), { self.emitted }
    pub fn is_stopped(&self) -> (out: bool) ensures out == self.stopped(), { self.enrollment.is_stopped() }
    pub fn is_enrolled(&self, now: u64) -> (out: bool) ensures out == self.can_upload(now), { self.enrollment.can_upload(now) }
    pub fn has_read_failed(&self) -> (out: bool) ensures out == self.read_failed(), { self.read_failed }
    pub fn exchange_cap(&self) -> (out: usize) ensures out == self.max_bytes(), { self.max_bytes }
    pub fn session_id(&self) -> (out: &[u8; 16]) ensures out@ == self.session(), { &self.session }
}
}
