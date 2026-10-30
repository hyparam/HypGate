//! Verified body-copy machine. One request body, in one direction, moves from
//! a reader through the audit log to a writer in a fixed order: read a chunk,
//! append its record, release it to the writer through the authorization gate
//! one ticket at a time, flush, read again. The runtime performs each effect
//! the machine names and reports the result back; it makes no decision of its
//! own. The machine is checked to count exactly the bytes the writer accepted,
//! to release bytes only through the authorization gate, to issue every chunk's audit record
//! unless the log already failed, to close the stream on every failure, and to
//! finish only on a clean end of input with nothing pending.
use vstd::prelude::*;
use crate::{framing::Header, audit_receipt::AuditReceipt, journal_binding::JournalBinding, owned_stream::OwnedStream,
    policy::AuthorizedRequest, resolved_route::ResolvedRoute, stream::Ticket, submission::AuthorizedWrite};

verus! {
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Failure { Read, Write, WriteZero, Flush, Log, InvalidState, CounterExhausted }

/// What the runtime does next. `Read` fills the stream's buffer, `Audit`
/// appends the record the machine hands out, `Write` passes the gated bytes to
/// the writer, `Flush` flushes it.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Action { Read, Audit, Write, Flush, Done, Failed(Failure) }

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
enum Phase { NeedRead, Reading, Filled, Auditing, Audited, Writing, NeedFlush, Done, Failed }

/// The exact borrowed bytes released by the gate, together with their ticket
/// and the source/receipt evidence at release. Its fields cannot be replaced.
pub struct Delivery<'a> {
    write: AuthorizedWrite, bytes: &'a [u8], owner: Ghost<OwnedStream>, journal: Ghost<JournalBinding>,
}
impl<'a> Delivery<'a> {
    pub closed spec fn write_value(&self) -> AuthorizedWrite { self.write }
    pub closed spec fn bytes_value(&self) -> Seq<u8> { self.bytes@ }
    pub closed spec fn permits(&self, authority: &AuthorizedRequest, direction: u8) -> bool {
        self.write.delivers(&self.owner@, authority, &self.journal@, direction, self.bytes@)
    }
    pub fn bytes(&self) -> (out: &[u8]) ensures out@ == self.bytes_value(), { self.bytes }
    pub fn into_write(self) -> (out: AuthorizedWrite) ensures out == self.write_value(), { self.write }
}

pub struct BodyCopy {
    direction: u8,
    accepted: u64,
    phase: Phase,
    failure: Option<Failure>,
    gap: bool,
    #[allow(dead_code)] // Ghost: the completed length when the copy began.
    start: Ghost<nat>,
    #[allow(dead_code)] // Ghost: the ticket of the write in flight.
    ticket: Ghost<Ticket>,
}

impl BodyCopy {
    pub closed spec fn direction(&self) -> u8 { self.direction }
    pub closed spec fn accepted(&self) -> u64 { self.accepted }
    pub closed spec fn start(&self) -> nat { self.start@ }
    pub closed spec fn gap(&self) -> bool { self.gap }
    pub closed spec fn ticket(&self) -> Ticket { self.ticket@ }
    pub closed spec fn is_done(&self) -> bool { self.phase == Phase::Done }
    pub closed spec fn needs_read(&self) -> bool { self.phase == Phase::NeedRead }
    pub closed spec fn reading(&self) -> bool { self.phase == Phase::Reading }
    pub closed spec fn filled(&self) -> bool { self.phase == Phase::Filled }
    pub closed spec fn auditing(&self) -> bool { self.phase == Phase::Auditing }
    pub closed spec fn audited(&self) -> bool { self.phase == Phase::Audited }
    pub closed spec fn writing(&self) -> bool { self.phase == Phase::Writing }
    pub closed spec fn needs_flush(&self) -> bool { self.phase == Phase::NeedFlush }
    pub closed spec fn failure(&self) -> Option<Failure> {
        if self.phase == Phase::Failed {
            match self.failure { Some(f) => Some(f), None => Some(Failure::InvalidState) }
        } else { None }
    }
    pub open spec fn same_copy(&self, prior: &Self) -> bool {
        self.direction() == prior.direction() && self.start() == prior.start()
    }

    /// Every byte the writer accepted since this copy began is counted once.
    pub open spec fn counted(&self, stream: &OwnedStream) -> bool {
        self.accepted() as nat + self.start() == stream.state().completed().len()
    }

    pub closed spec fn valid(&self, stream: &OwnedStream) -> bool {
        let st = stream.state();
        stream.valid() && self.direction <= 1 && st.capacity() > 0 && self.counted(stream)
        && match self.phase {
            Phase::NeedRead => stream.read_bytes().len() == 0 && !st.pending() && st.position() == st.body().len() && !st.closed(),
            Phase::Reading => stream.read_bytes().len() > 0 && !st.pending() && st.body().len() == 0 && st.position() == 0 && !st.closed(),
            Phase::Filled | Phase::Auditing => stream.read_bytes().len() == 0 && !st.pending() && st.position() == 0
                && st.body().len() > 0 && st.chunk() > 0 && !st.closed(),
            Phase::Audited => stream.read_bytes().len() == 0 && !st.pending() && st.position() < st.body().len() && !st.closed(),
            Phase::Writing => stream.read_bytes().len() == 0 && st.matches(&self.ticket@) && !st.closed(),
            Phase::NeedFlush => stream.read_bytes().len() == 0 && !st.pending() && st.position() == st.body().len() && !st.closed(),
            Phase::Done => stream.read_bytes().len() == 0 && !st.pending() && st.position() == st.body().len(),
            Phase::Failed => st.closed(),
        }
    }

    pub proof fn state_evidence(&self, stream: &OwnedStream)
        requires self.valid(stream),
        ensures stream.valid(), stream.state().valid(), self.direction() <= 1,
            (self.needs_read() || self.needs_flush() || self.is_done()) ==> stream.state().position() == stream.state().body().len(),
    { stream.payload_bound(); }
    pub proof fn stable_phases(&self)
        ensures (self.needs_read() || self.filled() || self.audited() || self.needs_flush() || self.is_done() || self.failure().is_some())
            ==> !self.reading() && !self.auditing() && !self.writing(),
    {}
    pub proof fn failure_closes(&self, stream: &OwnedStream)
        requires self.valid(stream), self.failure().is_some(),
        ensures stream.state().closed(),
    {}
    pub fn direction_id(&self) -> (out: u8) ensures out == self.direction(), { self.direction }
    pub fn accepted_bytes(&self) -> (out: u64)
        ensures out == self.accepted(),
    { self.accepted }

    /// True when the log failed for this request during or before the copy.
    pub fn audit_gap(&self) -> (out: bool)
        ensures out == self.gap(),
    { self.gap }

    pub fn is_finished(&self) -> (out: bool)
        ensures out == self.is_done(),
    { self.phase == Phase::Done }

    /// Begin copying one direction over a stream with no chunk in flight.
    pub fn begin(stream: &OwnedStream, direction: u8) -> (out: Option<Self>)
        requires stream.valid(),
        ensures match out {
            Some(copy) => copy.valid(stream) && copy.needs_read() && copy.accepted() == 0
                && copy.direction() == direction && copy.start() == stream.state().completed().len(),
            None => direction > 1 || stream.state().closed() || stream.state().capacity() == 0
                || stream.read_bytes().len() > 0 || stream.state().pending()
                || stream.state().position() != stream.state().body().len(),
        },
    {
        proof { stream.payload_bound(); }
        if direction > 1 || stream.stream().is_closed() || stream.stream().capacity_bytes() == 0
            || stream.has_read_buffer() || stream.stream().is_pending() || stream.stream().unsent() != 0 { return None; }
        Some(BodyCopy { direction, accepted: 0, phase: Phase::NeedRead, failure: None, gap: false,
            start: Ghost(stream.state().completed().len()), ticket: Ghost(arbitrary()) })
    }

    pub fn next(&self) -> (out: Action)
        ensures (out == Action::Done) == self.is_done(),
            (out == Action::Read) == (self.needs_read() || self.reading()),
            (out == Action::Audit) == (self.filled() || self.auditing()),
            (out == Action::Write) == (self.audited() || self.writing()),
            (out == Action::Flush) == self.needs_flush(),
            match out { Action::Failed(f) => self.failure() == Some(f), _ => self.failure().is_none() },
    {
        match self.phase {
            Phase::NeedRead | Phase::Reading => Action::Read,
            Phase::Filled | Phase::Auditing => Action::Audit,
            Phase::Audited | Phase::Writing => Action::Write,
            Phase::NeedFlush => Action::Flush,
            Phase::Done => Action::Done,
            Phase::Failed => match self.failure { Some(f) => Action::Failed(f), None => Action::Failed(Failure::InvalidState) },
        }
    }

    // Every failure closes the stream, so no later copy or write can use it.
    fn fail(&mut self, stream: &mut OwnedStream, failure: Failure)
        requires old(stream).valid(), old(self).direction() <= 1, old(stream).state().capacity() > 0,
            old(self).counted(old(stream)),
        ensures final(self).valid(final(stream)), final(self).failure() == Some(failure),
            final(self).accepted() == old(self).accepted(), final(self).same_copy(old(self)),
            final(stream).key() == old(stream).key(),
            final(stream).state().input() == old(stream).state().input(),
            final(stream).state().completed() == old(stream).state().completed(),
            final(stream).state().body() == old(stream).state().body(),
            final(stream).state().position() == old(stream).state().position(),
    {
        stream.cancel();
        self.phase = Phase::Failed;
        self.failure = Some(failure);
    }

    /// Hand the stream's buffer to the reader. False only when the stream
    /// refused, which closes the copy as an invalid state.
    pub fn begin_read(&mut self, stream: &mut OwnedStream) -> (ok: bool)
        requires old(self).valid(old(stream)), old(self).needs_read(),
        ensures final(self).valid(final(stream)), final(self).accepted() == old(self).accepted(),
            final(self).same_copy(old(self)), final(stream).key() == old(stream).key(),
            final(stream).state().input() == old(stream).state().input(),
            final(stream).state().completed() == old(stream).state().completed(),
            ok ==> final(self).reading(), !ok ==> final(self).failure() == Some(Failure::InvalidState),
    {
        if stream.begin_read() { self.phase = Phase::Reading; true }
        else { self.fail(stream, Failure::InvalidState); false }
    }

    /// The buffer the reader fills. Its length cannot change, and only its
    /// contents may; the stream and the copy stay valid under that premise.
    pub fn read_buffer<'a>(&self, stream: &'a mut OwnedStream) -> (out: &'a mut [u8])
        requires self.valid(old(stream)), self.reading(),
        ensures out@ == old(stream).read_bytes(), final(out)@ == final(stream).read_bytes(),
            final(stream).state() == old(stream).state(), final(stream).key() == old(stream).key(),
            final(out)@.len() == out@.len() ==> self.valid(final(stream)),
    { stream.read_buffer() }

    /// The reader's result: `None` is a read error, zero is the end of input,
    /// otherwise the filled prefix becomes the next chunk.
    pub fn finish_read(&mut self, stream: &mut OwnedStream, length: Option<usize>)
        requires old(self).valid(old(stream)), old(self).reading(),
        ensures final(self).valid(final(stream)), final(self).accepted() == old(self).accepted(),
            final(self).same_copy(old(self)), final(stream).key() == old(stream).key(),
            final(stream).state().completed() == old(stream).state().completed(),
            final(self).failure().is_none() ==> final(stream).state().input() == old(stream).state().input()
                + old(stream).read_bytes().take(length.unwrap() as int),
            match length {
                None => final(self).failure() == Some(Failure::Read),
                Some(n) => if n == 0 {
                    final(self).is_done() && final(self).gap() == final(stream).state().failed()
                        && final(stream).state() == old(stream).state()
                } else {
                    (final(self).filled() && final(stream).state().body() == old(stream).read_bytes().subrange(0, n as int)
                        && final(stream).state().chunk() == old(stream).state().chunk() + 1)
                    || final(self).failure() == Some(Failure::InvalidState)
                },
            },
    {
        match length {
            None => self.fail(stream, Failure::Read),
            Some(n) => {
                if !stream.finish_read(n) { self.fail(stream, Failure::InvalidState); return; }
                if n == 0 { self.gap = stream.stream().is_failed(); self.phase = Phase::Done; }
                else { self.phase = Phase::Filled; }
            }
        }
    }

    /// The record to append for the filled chunk: the chunk's canonical body
    /// header for this request and direction, and its exact bytes. `None` with
    /// the copy still valid means the log already failed for this request, so
    /// the chunk goes unaudited (availability mode only: a strict stream is
    /// closed by a log failure and cannot reach this point).
    pub fn audit_record<'a>(&mut self, stream: &'a mut OwnedStream, authority: &AuthorizedRequest,
        journal: &mut JournalBinding, session: u128) -> (out: Option<(Header, &'a [u8])>)
        requires old(self).valid(old(stream)), old(self).filled(), authority.valid(),
        ensures final(self).valid(final(stream)), final(self).accepted() == old(self).accepted(),
            final(self).same_copy(old(self)), final(stream).key() == old(stream).key(),
            final(stream).state().input() == old(stream).state().input(),
            final(stream).state().completed() == old(stream).state().completed(),
            match out {
                Some((header, bytes)) => final(self).auditing() && *final(stream) == *old(stream)
                    && final(journal).session() == Some(session)
                    && final(stream).state().auditable(authority, old(self).direction())
                    && crate::framing::valid(header)
                    && header == final(stream).state().audit_header(authority.tenant(), old(self).direction())
                    && bytes@ == final(stream).state().body() && header.payload == bytes.len(),
                None => (final(self).audited() && *final(stream) == *old(stream) && final(stream).state().failed())
                    || final(self).failure() == Some(Failure::InvalidState),
            },
    {
        proof { stream.payload_bound(); }
        if stream.stream().is_failed() { self.phase = Phase::Audited; return None; }
        if !journal.bind(session) { self.fail(stream, Failure::InvalidState); return None; }
        if stream.owner_id() == 0 || stream.owner_id() != authority.request_id()
            || stream.stream().capacity_bytes() > 1048576 { self.fail(stream, Failure::InvalidState); return None; }
        self.phase = Phase::Auditing;
        match stream.stream().audit_record(authority, self.direction) {
            Some(record) => Some(record),
            None => { proof { assert(false); } None }
        }
    }

    /// The logger's reply for the record handed out by `audit_record`. A
    /// missing receipt marks the request log-failed: strict mode closes the
    /// copy, availability mode continues unaudited. A receipt that does not
    /// match the chunk is an invalid state.
    pub fn finish_audit(&mut self, stream: &mut OwnedStream, authority: &AuthorizedRequest,
        journal: &JournalBinding, receipt: Option<&AuditReceipt>)
        requires old(self).valid(old(stream)), old(self).auditing(), authority.valid(),
            match receipt { Some(r) => r.valid(), None => true },
        ensures final(self).valid(final(stream)), final(self).accepted() == old(self).accepted(),
            final(self).same_copy(old(self)), final(stream).key() == old(stream).key(),
            final(stream).state().input() == old(stream).state().input(),
            final(stream).state().completed() == old(stream).state().completed(),
            match receipt {
                None => final(stream).state().failed()
                    && if old(stream).state().strict() { final(self).failure() == Some(Failure::Log) }
                        else { final(self).audited() },
                Some(_) => final(self).audited() || final(self).failure() == Some(Failure::InvalidState),
            },
            final(self).audited() && receipt.is_some() ==> final(stream).audited_for(authority, journal)
                && final(stream).audit_direction() == old(self).direction()
                && final(stream).state().logged() == final(stream).state().body().len(),
    {
        match receipt {
            None => {
                stream.fail_log();
                if stream.stream().requires_audit() { self.phase = Phase::Failed; self.failure = Some(Failure::Log); }
                else { self.phase = Phase::Audited; }
            }
            Some(receipt) => {
                if stream.acknowledge_receipt(authority, journal, self.direction, receipt) { self.phase = Phase::Audited; }
                else { self.fail(stream, Failure::InvalidState); }
            }
        }
    }

    /// Reserve the next range of the chunk and release it through the
    /// authorization gate: the resolved route's `write_bytes` in production,
    /// or the ticket alone for an embedder with no route. The bytes are
    /// exactly the reserved range of this request's stream, in strict mode
    /// covered by a matching logged receipt. The ticket comes back with the
    /// bytes and must be returned to `finish_write`.
    pub fn write_bytes<'a, D, C>(&mut self, stream: &'a mut OwnedStream, authority: &AuthorizedRequest,
        journal: &JournalBinding, route: Option<&ResolvedRoute<'_, D, C>>) -> (out: Option<Delivery<'a>>)
        requires old(self).valid(old(stream)), old(self).audited(), authority.valid(),
        ensures final(self).valid(final(stream)), final(self).accepted() == old(self).accepted(),
            final(self).same_copy(old(self)), final(stream).key() == old(stream).key(),
            final(stream).state().input() == old(stream).state().input(),
            final(stream).state().completed() == old(stream).state().completed(),
            final(stream).state().body() == old(stream).state().body(),
            final(stream).state().position() == old(stream).state().position(),
            match out {
                Some(delivery) => final(self).writing() && delivery.write_value().ticket() == final(self).ticket()
                    && delivery.write_value().delivers(final(stream), authority, journal, old(self).direction(), delivery.bytes_value())
                    && delivery.permits(authority, old(self).direction())
                    && delivery.bytes_value().len() > 0 && authority.grants(delivery.write_value().route())
                    && match route { Some(route) => route.bound_to(authority) && delivery.write_value().route() == route.route(), None => true },
                None => final(self).failure() == Some(Failure::InvalidState),
            },
    {
        proof { stream.payload_bound(); }
        let bound = match route { Some(route) => route.matches(authority), None => true };
        if !bound { self.fail(stream, Failure::InvalidState); return None; }
        let max = stream.stream().unsent();
        let write = match AuthorizedWrite::prepare(stream, authority, journal, self.direction, max) {
            Some(write) => write,
            None => { self.fail(stream, Failure::InvalidState); return None; }
        };
        self.ticket = Ghost(write.ticket());
        self.phase = Phase::Writing;
        proof { stream.payload_bound(); stream.state().payload_within_capacity(); }
        let ghost released = *stream;
        let bytes = match route {
            Some(route) => route.write_bytes(&write, stream, authority, journal, self.direction),
            None => write.bytes(stream, authority, journal, self.direction),
        };
        match bytes {
            Some(bytes) => Some(Delivery { write, bytes, owner: Ghost(released), journal: Ghost(*journal) }),
            None => { proof { assert(false); } None }
        }
    }

    /// The writer's result for the range it was given: `None` is a write
    /// error, zero bytes is no progress, otherwise the accepted count is
    /// recorded and the copy continues with the rest of the chunk or flushes.
    pub fn finish_write(&mut self, stream: &mut OwnedStream, write: &AuthorizedWrite, count: Option<usize>)
        requires old(self).valid(old(stream)), old(self).writing(), write.ticket() == old(self).ticket(),
        ensures final(self).valid(final(stream)), final(self).same_copy(old(self)),
            final(stream).key() == old(stream).key(),
            final(stream).state().input() == old(stream).state().input(),
            final(self).failure().is_none() ==> count.is_some()
                && final(stream).state().completed() == old(stream).state().completed()
                    + old(stream).state().body().subrange(old(stream).state().position() as int, (old(stream).state().position() + count.unwrap()) as int),
            match count {
                None => final(self).failure() == Some(Failure::Write) && final(self).accepted() == old(self).accepted(),
                Some(n) => if n == 0 {
                    final(self).failure() == Some(Failure::WriteZero) && final(self).accepted() == old(self).accepted()
                } else {
                    (final(self).accepted() == old(self).accepted() + n && (final(self).audited() || final(self).needs_flush()))
                    || ((final(self).failure() == Some(Failure::InvalidState) || final(self).failure() == Some(Failure::CounterExhausted))
                        && final(self).accepted() == old(self).accepted())
                },
            },
    {
        proof { stream.payload_bound(); stream.state().payload_within_capacity(); }
        let n = match count {
            None => { self.fail(stream, Failure::Write); return; }
            Some(n) => n,
        };
        if self.accepted > u64::MAX - (n as u64) { self.fail(stream, Failure::CounterExhausted); return; }
        if !write.complete(stream, n) { self.fail(stream, Failure::InvalidState); return; }
        self.accepted = self.accepted + (n as u64);
        if n == 0 { self.fail(stream, Failure::WriteZero); return; }
        proof { stream.payload_bound(); }
        if stream.stream().unsent() == 0 { self.phase = Phase::NeedFlush; } else { self.phase = Phase::Audited; }
    }

    pub fn finish_flush(&mut self, stream: &mut OwnedStream, ok: bool)
        requires old(self).valid(old(stream)), old(self).needs_flush(),
        ensures final(self).valid(final(stream)), final(self).accepted() == old(self).accepted(),
            final(self).same_copy(old(self)), final(stream).key() == old(stream).key(),
            final(stream).state().input() == old(stream).state().input(),
            final(stream).state().completed() == old(stream).state().completed(),
            ok ==> final(self).needs_read() && *final(stream) == *old(stream),
            !ok ==> final(self).failure() == Some(Failure::Flush),
    {
        if ok { self.phase = Phase::NeedRead; } else { self.fail(stream, Failure::Flush); }
    }
}
}
