//! One credited disk operation, with verified queue-to-worker ownership and
//! write/sync/commit/delivery ordering. Syscalls and reply delivery are adapters.
use vstd::prelude::*;
use crate::{audit_journal::AuditJournal, frame_queue::FrameQueue, framing::RecordFrame, journal::DurableFrame};

verus! {
// The implementation owns one logical journal, initialized with its session
// header (or headers for rotated segments). These histories model record bytes. Failed writes may leave a partial
// suffix; the journal then fails permanently and performs no further writes.
pub trait Storage {
    spec fn valid(&self) -> bool;
    spec fn written(&self) -> Seq<u8>;
    spec fn stable(&self) -> Seq<u8>;
    fn write_all(&mut self, bytes: &Vec<u8>) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).stable() == old(self).stable(),
            ok ==> final(self).written() == old(self).written() + bytes@;
    fn sync(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).written() == old(self).written(),
            ok ==> final(self).stable() == final(self).written();
}

// Consumes the sender and receipt. The adapter must transfer the receipt into
// the request-owned reply channel, or destroy it, before returning. It may not
// retain a worker-owned copy or spawn detached delivery work.
pub trait Completion: Sized {
    fn complete(self, receipt: Option<DurableFrame>)
        requires match receipt { Some(r) => r.valid(), None => true };
}

pub struct DiskWorker {
    busy: bool,
    next: u64,
    payload_limit: usize,
    session: u128,
    active: Ghost<Option<RecordFrame>>,
}
pub struct ActiveAppend<C> { frame: RecordFrame, completion: C, generation: u64, session: u128 }
pub struct FinishedAppend<C> { receipt: Option<DurableFrame>, completion: C, generation: u64, session: u128 }
/// Only completed delivery produces an active-slot release token.
/// ```compile_fail,E0451
/// let _ = gateway_core::disk_worker::ReleasedAppend { generation: 1, session: 1 };
/// ```
pub struct ReleasedAppend { generation: u64, session: u128 }
impl ReleasedAppend {
    pub closed spec fn generation(&self) -> u64 { self.generation }
    pub closed spec fn session(&self) -> u128 { self.session }
}

impl DiskWorker {
    pub closed spec fn session(&self) -> u128 { self.session }
    pub closed spec fn busy(&self) -> bool { self.busy }
    pub closed spec fn next(&self) -> u64 { self.next }
    pub closed spec fn payload_limit(&self) -> nat { self.payload_limit as nat }
    pub closed spec fn frame(&self) -> Option<RecordFrame> { self.active@ }
    pub open spec fn owns<C>(&self, job: &ActiveAppend<C>) -> bool {
        self.busy() && self.session() == job.session() && self.next() == job.generation() + 1 && self.frame() == Some(job.frame())
    }
    pub open spec fn owns_finished<C>(&self, job: &FinishedAppend<C>) -> bool {
        self.busy() && self.session() == job.session() && self.next() == job.generation() + 1
            && match job.receipt() {
                Some(receipt) => receipt.session() == self.session() && self.frame().is_some() && receipt.record() == self.frame().unwrap().contents(),
                None => true,
            }
    }
    pub closed spec fn valid(&self) -> bool {
        self.next > 0 && self.payload_limit <= 1048576
            && self.busy == self.active@.is_some()
            && match self.active@ {
                Some(f) => self.next > 1 && f.valid() && f.payload().len() <= self.payload_limit,
                None => true,
            }
    }
    pub fn new(payload_limit: usize, session: u128) -> (out: Self)
        requires payload_limit <= 1048576,
        ensures out.valid(), !out.busy(), out.next() == 1, out.payload_limit() == payload_limit, out.session() == session,
    { Self { busy: false, next: 1, payload_limit, session, active: Ghost(None) } }
    pub fn is_busy(&self) -> (out: bool)
        ensures out == self.busy(),
    { self.busy }
    pub open spec fn available(&self) -> bool { !self.busy() && self.next() < u64::MAX }
    pub fn can_take(&self) -> (out: bool)
        ensures out == self.available(),
    { !self.busy && self.next < u64::MAX }

    pub fn take<C>(&mut self, queue: &mut FrameQueue<C>) -> (out: Option<ActiveAppend<C>>)
        requires old(self).valid(), old(queue).valid(),
        ensures final(self).valid(), final(queue).valid(),
            final(self).payload_limit() == old(self).payload_limit(), final(self).session() == old(self).session(),
            final(queue).capacity() == old(queue).capacity(), final(queue).reserved() == old(queue).reserved(),
            final(queue).payload_limit() == old(queue).payload_limit(), final(queue).closed() == old(queue).closed(),
            match out {
                Some(job) => !old(self).busy() && job.valid()
                    && final(self).owns(&job)
                    && job.generation() == old(self).next() && final(self).next() == old(self).next() + 1
                    && final(self).busy() && final(self).frame() == Some(job.frame())
                    && job.frame().payload().len() <= final(self).payload_limit()
                    && old(queue).items().len() > 0
                    && (job.frame(), job.completion()) == old(queue).items()[0]
                    && final(queue).items() == old(queue).items().drop_first(),
                None => *final(self) == *old(self) && final(queue).items() == old(queue).items()
                    && (old(self).busy() || old(self).next() == u64::MAX || old(queue).items().len() == 0
                        || old(queue).payload_limit() > old(self).payload_limit()),
            },
    {
        if self.busy || self.next == u64::MAX || queue.payload_capacity() > self.payload_limit { return None; }
        match queue.pop() {
            Some((frame, completion)) => {
                let generation = self.next;
                self.next += 1;
                self.busy = true;
                self.active = Ghost(Some(frame));
                Some(ActiveAppend { frame, completion, generation, session: self.session })
            }
            None => None,
        }
    }

    pub fn release(&mut self, token: ReleasedAppend) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).next() == old(self).next(),
            final(self).payload_limit() == old(self).payload_limit(), final(self).session() == old(self).session(),
            ok == (old(self).busy() && token.session() == old(self).session() && token.generation() == old(self).next() - 1),
            ok ==> !final(self).busy() && final(self).frame().is_none(),
            !ok ==> *final(self) == *old(self),
    {
        if !self.busy || token.session != self.session || token.generation != self.next - 1 { return false; }
        self.busy = false;
        self.active = Ghost(None);
        true
    }

    pub fn run<C: Completion, S: Storage>(&self, job: ActiveAppend<C>, journal: &mut AuditJournal,
        storage: &mut S, enabled: bool) -> (out: FinishedAppend<C>)
        requires self.valid(), self.owns(&job), job.valid(), old(journal).valid(), old(storage).valid(),
            !old(journal).failed() ==> old(storage).written() == old(journal).history(),
        ensures job.ran(*old(journal), *final(journal), *old(storage), *final(storage), enabled, out),
            self.owns_finished(&out),
    { job.run(journal, storage, enabled) }

    pub proof fn queued_and_active_bound<C>(&self, queue: &FrameQueue<C>, encoding_bytes: nat)
        requires self.valid(), queue.valid(), queue.payload_limit() <= self.payload_limit(),
            encoding_bytes <= queue.payload_limit() + 65, !queue.reserved() ==> encoding_bytes == 0,
        ensures crate::buffer_accounting::byte_sum(crate::buffer_accounting::frame_bytes(queue.frames()))
            + encoding_bytes + match self.frame() { Some(f) => f.contents().len(), None => 0nat }
            <= (queue.capacity() + 1) * (self.payload_limit() + 65),
    {
        queue.encoding_and_queued_bound(encoding_bytes);
        if let Some(frame) = self.frame() { frame.retained_size(); }
        assert(queue.capacity() * (queue.payload_limit() + 65) <= queue.capacity() * (self.payload_limit() + 65))
            by(nonlinear_arith) requires queue.payload_limit() <= self.payload_limit();
        assert((queue.capacity() + 1) * (self.payload_limit() + 65)
            == queue.capacity() * (self.payload_limit() + 65) + self.payload_limit() + 65) by(nonlinear_arith);
    }
}

impl<C> ActiveAppend<C> {
    pub closed spec fn valid(&self) -> bool { self.frame.valid() }
    pub closed spec fn frame(&self) -> RecordFrame { self.frame }
    pub closed spec fn completion(&self) -> C { self.completion }
    pub closed spec fn generation(&self) -> u64 { self.generation }
    pub closed spec fn session(&self) -> u128 { self.session }
    // Outcome of running this append: a receipt only after write and sync of the
    // exact frame under the matching journal; otherwise the journal fails and
    // storage was left alone whenever the attempt was refused up front.
    pub open spec fn ran<S: Storage>(&self, journal_before: AuditJournal, journal: AuditJournal,
        storage_before: S, storage: S, enabled: bool, out: FinishedAppend<C>) -> bool
    {
        journal.session() == journal_before.session() && journal.valid() && storage.valid() && out.valid()
        && ((!enabled || journal_before.failed() || journal_before.session() != self.session()) ==> storage == storage_before)
        && out.generation() == self.generation() && out.session() == self.session() && out.completion() == self.completion()
        && match out.receipt() {
            Some(receipt) => receipt.session() == self.session() && receipt.session() == journal_before.session()
                && enabled && !journal_before.failed() && !journal.failed()
                && receipt.record() == self.frame().contents()
                && receipt.acknowledged() == journal.history()
                && journal.history() == journal_before.history() + self.frame().contents()
                && storage.written() == journal.history() && storage.stable() == journal.history(),
            None => journal.failed() && journal.history() == journal_before.history(),
        }
    }
}
impl<C: Completion> ActiveAppend<C> {
    fn run<S: Storage>(self, journal: &mut AuditJournal, storage: &mut S, enabled: bool)
        -> (out: FinishedAppend<C>)
        requires self.valid(), old(journal).valid(), old(storage).valid(),
            !old(journal).failed() ==> old(storage).written() == old(journal).history(),
        ensures self.ran(*old(journal), *final(journal), *old(storage), *final(storage), enabled, out),
    {
        let mut receipt = None;
        if enabled && journal.session_id() == self.session {
            if let Some(ticket) = journal.begin(self.frame.bytes().len() as u64) {
                if storage.write_all(self.frame.bytes()) && storage.sync() {
                    receipt = journal.commit_frame(&ticket, self.frame);
                }
            }
        }
        if receipt.is_none() { journal.fail(); }
        FinishedAppend { receipt, completion: self.completion, generation: self.generation, session: self.session }
    }
}
impl<C> FinishedAppend<C> {
    pub closed spec fn valid(&self) -> bool {
        match self.receipt { Some(r) => r.valid() && r.session() == self.session, None => true }
    }
    pub closed spec fn receipt(&self) -> Option<DurableFrame> { self.receipt }
    pub closed spec fn completion(&self) -> C { self.completion }
    pub closed spec fn generation(&self) -> u64 { self.generation }
    pub closed spec fn session(&self) -> u128 { self.session }
    pub fn failed(&self) -> (out: bool)
        ensures out == self.receipt().is_none(),
    { self.receipt.is_none() }
}
impl<C: Completion> FinishedAppend<C> {
    pub fn deliver(self) -> (out: ReleasedAppend)
        requires self.valid(),
        ensures out.generation() == self.generation(), out.session() == self.session(),
    {
        self.completion.complete(self.receipt);
        ReleasedAppend { generation: self.generation, session: self.session }
    }
}
}
