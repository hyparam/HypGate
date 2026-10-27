//! Bounded group commit. Frames stay separate for rotation; durable batches share one sync.
use vstd::prelude::*;
use crate::{audit_receipt::{AuditReceipt, BatchJournal}, disk_worker::Storage,
    frame_queue::FrameQueue, framing::RecordFrame};

verus! {
pub const MAX_BATCH: usize = 16;
pub trait Completion: Sized {
    fn complete(self, receipt: Option<AuditReceipt>)
        requires match receipt { Some(r) => r.valid(), None => true };
}

pub open spec fn bytes<C>(jobs: Seq<(RecordFrame, C)>) -> Seq<u8>
    decreases jobs.len(),
{
    if jobs.len() == 0 { Seq::empty() }
    else { jobs[0].0.contents() + bytes(jobs.drop_first()) }
}
pub open spec fn prefix(a: Seq<u8>, b: Seq<u8>) -> bool {
    a.len() <= b.len() && b.take(a.len() as int) == a
}
pub open spec fn replies_match<C>(jobs: Seq<(RecordFrame, C)>, replies: Seq<(Option<AuditReceipt>, C)>,
    session: u128, acknowledged: Seq<u8>) -> bool
{
    jobs.len() == replies.len() && forall|i: int| 0 <= i < jobs.len() ==>
        (#[trigger] replies[i]).1 == jobs[i].1 && match replies[i].0 {
            Some(r) => r.valid() && r.session() == session && r.record() == jobs[i].0.contents()
                && prefix(r.acknowledged(), acknowledged),
            None => true,
        }
}

pub struct BatchWorker { busy: bool, next: u64, session: u128, limit: usize, active: Ghost<Seq<RecordFrame>> }
pub struct ActiveBatch<C> { jobs: Vec<(RecordFrame, C)>, generation: u64, session: u128 }
pub struct FinishedBatch<C> { replies: Vec<(Option<AuditReceipt>, C)>, failed: bool, generation: u64, session: u128 }
/// Only synchronous delivery of the entire batch returns its credit.
pub struct ReleasedBatch { generation: u64, session: u128 }

impl ReleasedBatch {
    pub closed spec fn generation(&self) -> u64 { self.generation }
    pub closed spec fn session(&self) -> u128 { self.session }
}
impl BatchWorker {
    pub closed spec fn valid(&self) -> bool {
        self.next > 0 && self.limit <= 1048576 && self.active@.len() <= MAX_BATCH
            && self.busy == (self.active@.len() > 0)
            && (self.busy ==> self.next > 1)
            && forall|i: int| 0 <= i < self.active@.len() ==> #[trigger] self.active@[i].valid()
                && self.active@[i].payload().len() <= self.limit
    }
    pub closed spec fn busy(&self) -> bool { self.busy }
    pub closed spec fn next(&self) -> u64 { self.next }
    pub closed spec fn session(&self) -> u128 { self.session }
    pub closed spec fn limit(&self) -> nat { self.limit as nat }
    pub closed spec fn active(&self) -> Seq<RecordFrame> { self.active@ }
    pub open spec fn owns<C>(&self, batch: &ActiveBatch<C>) -> bool {
        self.busy() && batch.session() == self.session() && batch.generation() + 1 == self.next()
            && self.active() == batch.jobs().map(|i: int, job: (RecordFrame, C)| job.0)
    }
    pub fn new(limit: usize, session: u128) -> (out: Self)
        requires limit <= 1048576,
        ensures out.valid(), !out.busy(), out.limit() == limit, out.session() == session,
    { Self { busy: false, next: 1, session, limit, active: Ghost(Seq::empty()) } }
    pub fn can_take(&self) -> (ok: bool)
        ensures ok == (!self.busy() && self.next() < u64::MAX),
    { !self.busy && self.next < u64::MAX }
    pub fn take<C>(&mut self, queue: &mut FrameQueue<C>) -> (out: Option<ActiveBatch<C>>)
        requires old(self).valid(), old(queue).valid(),
        ensures final(self).valid(), final(queue).valid(),
            final(self).session() == old(self).session(), final(self).limit() == old(self).limit(),
            final(queue).capacity() == old(queue).capacity(), final(queue).payload_limit() == old(queue).payload_limit(),
            final(queue).reserved() == old(queue).reserved(), final(queue).closed() == old(queue).closed(),
            match out {
                Some(batch) => batch.valid() && final(self).owns(&batch)
                    && batch.jobs() + final(queue).items() == old(queue).items()
                    && batch.jobs().len() <= MAX_BATCH,
                None => *final(self) == *old(self) && final(queue).items() == old(queue).items(),
            },
    {
        if !self.can_take() || queue.payload_capacity() > self.limit || queue.len() == 0 { return None; }
        let mut jobs = Vec::with_capacity(MAX_BATCH);
        while jobs.len() < MAX_BATCH && queue.len() > 0
            invariant self.valid(), !self.busy, self.next < u64::MAX,
                queue.valid(), queue.payload_limit() <= self.limit,
                queue.capacity() == old(queue).capacity(), queue.payload_limit() == old(queue).payload_limit(),
                queue.reserved() == old(queue).reserved(), queue.closed() == old(queue).closed(),
                jobs.len() <= MAX_BATCH, crate::frame_queue::items_bounded(jobs@, self.limit as nat),
                jobs@ + queue.items() == old(queue).items(),
            decreases MAX_BATCH - jobs.len(),
        {
            let ghost before = queue.items();
            let item = queue.pop().unwrap();
            proof {
                assert(before =~= seq![item] + queue.items());
                assert forall|i: int| 0 <= i < jobs@.push(item).len() implies
                    (#[trigger] jobs@.push(item)[i]).0.valid() && jobs@.push(item)[i].0.payload().len() <= self.limit by {
                    if i < jobs.len() { assert(jobs@.push(item)[i] == jobs@[i]); }
                }
            }
            jobs.push(item);
            proof { assert(jobs@ + queue.items() =~= old(queue).items()); }
        }
        let generation = self.next;
        self.next += 1; self.busy = true;
        self.active = Ghost(jobs@.map(|i: int, job: (RecordFrame, C)| job.0));
        Some(ActiveBatch { jobs, generation, session: self.session })
    }
    pub fn run<C, S: Storage>(&self, batch: ActiveBatch<C>, journal: &mut BatchJournal,
        storage: &mut S, enabled: bool) -> (out: FinishedBatch<C>)
        requires self.valid(), self.owns(&batch), batch.valid(), old(journal).valid(), old(storage).valid(),
            !old(journal).failed() ==> old(storage).written() == old(journal).history(),
        ensures final(journal).valid(), final(storage).valid(), out.valid(),
            final(journal).session() == old(journal).session(),
            out.generation() == batch.generation(), out.session() == batch.session(),
            replies_match(batch.jobs(), out.replies(), batch.session(), final(storage).written()),
            final(journal).requires_sync() == old(journal).requires_sync(),
            forall|i: int| 0 <= i < out.replies().len() ==> match (#[trigger] out.replies()[i]).0 {
                Some(r) => r.durable() == old(journal).requires_sync()
                    && (r.durable() ==> prefix(r.acknowledged(), final(storage).stable())),
                None => true,
            },
            !final(journal).failed() ==> final(storage).written() == final(journal).history(),
            out.has_failed() == final(journal).failed(),
            (!enabled || old(journal).failed() || batch.session() != old(journal).session()) ==> *final(storage) == *old(storage),
    {
        let ghost original_jobs = batch.jobs@;
        proof { assert(original_jobs.skip(0) =~= original_jobs); }
        let mut accepted = false;
        if enabled && journal.session_id() == batch.session && !journal.is_failed() {
            if write_frames(&batch.jobs, 0, storage) { accepted = !journal.sync_required() || storage.sync(); }
        }
        if !accepted { journal.fail(); }
        let replies = finish(batch.jobs, journal, Ghost(storage.written()), accepted);
        proof {
            if batch.session != journal.session() {
                assert forall|i: int| 0 <= i < replies.len() implies (#[trigger] replies@[i]).0.is_none() by {}
            }
        }
        FinishedBatch { replies, failed: journal.is_failed(), generation: batch.generation, session: batch.session }
    }
    pub fn release(&mut self, token: ReleasedBatch) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).session() == old(self).session(), final(self).limit() == old(self).limit(),
            final(self).next() == old(self).next(),
            ok == (old(self).busy() && token.session() == old(self).session() && token.generation() == old(self).next() - 1),
            ok ==> !final(self).busy(), !ok ==> *final(self) == *old(self),
    {
        if !self.busy || token.session != self.session || token.generation != self.next - 1 { return false; }
        self.busy = false; self.active = Ghost(Seq::empty()); true
    }
    pub proof fn queued_and_active_bound<C>(&self, queue: &FrameQueue<C>, encoding_bytes: nat)
        requires self.valid(), queue.valid(), queue.payload_limit() <= self.limit(),
            encoding_bytes <= queue.payload_limit() + 65, !queue.reserved() ==> encoding_bytes == 0,
        ensures crate::buffer_accounting::byte_sum(crate::buffer_accounting::frame_bytes(queue.frames())) + encoding_bytes
            + crate::buffer_accounting::byte_sum(crate::buffer_accounting::frame_bytes(self.active()))
            <= (queue.capacity() + MAX_BATCH) * (self.limit() + 65),
    {
        queue.encoding_and_queued_bound(encoding_bytes);
        assert forall|i: int| 0 <= i < self.active().len() implies #[trigger] self.active()[i].valid()
            && self.active()[i].payload().len() <= self.limit() by {
            assert(self.active@[i].valid());
        }
        crate::buffer_accounting::bounded_frames(self.active(), MAX_BATCH as nat, self.limit());
        crate::buffer_accounting::bounded_sum(crate::buffer_accounting::frame_bytes(self.active()), MAX_BATCH as nat, self.limit() + 65);
        assert(queue.capacity() * (queue.payload_limit() + 65) <= queue.capacity() * (self.limit() + 65))
            by(nonlinear_arith) requires queue.payload_limit() <= self.limit();
        assert(queue.capacity() * (self.limit() + 65) + MAX_BATCH * (self.limit() + 65)
            == (queue.capacity() + MAX_BATCH) * (self.limit() + 65)) by(nonlinear_arith);
    }
}
impl<C> ActiveBatch<C> {
    pub closed spec fn jobs(&self) -> Seq<(RecordFrame, C)> { self.jobs@ }
    pub closed spec fn generation(&self) -> u64 { self.generation }
    pub closed spec fn session(&self) -> u128 { self.session }
    pub closed spec fn valid(&self) -> bool { 0 < self.jobs.len() <= MAX_BATCH && crate::frame_queue::items_bounded(self.jobs@, 1048576) }
}

// Borrow the frames: no second payload buffer, and one storage append per frame
// so segment rotation never splits a record or treats a whole batch as a frame.
fn write_frames<C, S: Storage>(jobs: &Vec<(RecordFrame, C)>, at: usize, storage: &mut S) -> (ok: bool)
    requires at <= jobs.len(), old(storage).valid(),
    ensures final(storage).valid(), final(storage).stable() == old(storage).stable(),
        ok ==> final(storage).written() == old(storage).written() + bytes(jobs@.skip(at as int)),
    decreases jobs.len() - at,
{
    if at == jobs.len() { return true; }
    if !storage.write_all(jobs[at].0.bytes()) { return false; }
    let ok = write_frames(jobs, at + 1, storage);
    proof {
        assert(jobs@.skip(at as int).drop_first() =~= jobs@.skip((at + 1) as int));
        assert(jobs@.skip(at as int)[0] == jobs@[at as int]);
    }
    ok
}

// The storage has already written the group and, in durable mode, synced it. Advancing the journal one
// frame at a time issues receipts for prefixes of that same acknowledged byte string.
fn finish<C>(mut jobs: Vec<(RecordFrame, C)>, journal: &mut BatchJournal, stable: Ghost<Seq<u8>>, _accepted: bool)
    -> (out: Vec<(Option<AuditReceipt>, C)>)
    requires old(journal).valid(), crate::frame_queue::items_bounded(jobs@, 1048576),
        _accepted ==> stable@ == old(journal).history() + bytes(jobs@),
        !_accepted ==> old(journal).failed(),
    ensures final(journal).valid(), final(journal).session() == old(journal).session(),
        replies_match(jobs@, out@, old(journal).session(), stable@),
        !final(journal).failed() ==> final(journal).history() == stable@,
        old(journal).failed() ==> final(journal).failed(),
        final(journal).requires_sync() == old(journal).requires_sync(),
        forall|i: int| 0 <= i < out.len() ==> match (#[trigger] out@[i]).0 {
            Some(r) => r.durable() == old(journal).requires_sync(), None => true,
        },
        old(journal).failed() ==> forall|i: int| 0 <= i < out.len() ==> (#[trigger] out@[i]).0.is_none(),
    decreases jobs.len(),
{
    if jobs.len() == 0 { return Vec::with_capacity(MAX_BATCH); }
    let ghost original = jobs@;
    let ghost before = journal.history();
    let (frame, completion) = jobs.remove(0);
    let ghost saved_frame = frame;
    proof {
        assert(jobs@ =~= original.drop_first());
        assert(frame == original[0].0);
        assert(bytes(original) == frame.contents() + bytes(jobs@));
    }
    let mut receipt = None;
    if !journal.is_failed() {
        receipt = journal.commit(frame);
    }
    if receipt.is_none() { journal.fail(); }
    let ghost head_receipt = receipt;
    proof {
        if let Some(r) = head_receipt {
            assert(journal.history() == before + saved_frame.contents());
            assert(stable@ =~= journal.history() + bytes(jobs@));
            assert(stable@.take(r.acknowledged().len() as int) =~= r.acknowledged());
            assert(prefix(r.acknowledged(), stable@));
        }
    }
    let continuing = !journal.is_failed();
    let mut tail = finish(jobs, journal, stable, continuing);
    tail.insert(0, (receipt, completion));
    proof {
        assert forall|i: int| 0 <= i < original.len() implies
            (#[trigger] tail@[i]).1 == original[i].1 && match tail@[i].0 {
                Some(r) => r.valid() && r.session() == journal.session() && r.record() == original[i].0.contents()
                    && prefix(r.acknowledged(), stable@),
                None => true,
            } by {
            if i > 0 { assert(tail@[i] == tail@.drop_first()[i - 1]); }
        }
    }
    tail
}
impl<C> FinishedBatch<C> {
    pub closed spec fn replies(&self) -> Seq<(Option<AuditReceipt>, C)> { self.replies@ }
    pub closed spec fn generation(&self) -> u64 { self.generation }
    pub closed spec fn session(&self) -> u128 { self.session }
    pub closed spec fn has_failed(&self) -> bool { self.failed }
    pub closed spec fn valid(&self) -> bool {
        self.replies.len() <= MAX_BATCH && forall|i: int| 0 <= i < self.replies.len() ==> match (#[trigger] self.replies@[i]).0 {
            Some(r) => r.valid(), None => true,
        }
    }
    pub fn failed(&self) -> (out: bool) ensures out == self.has_failed(), { self.failed }
}
impl<C: Completion> FinishedBatch<C> {
    pub fn deliver(mut self) -> (out: ReleasedBatch)
        requires self.valid(),
        ensures out.generation() == self.generation(), out.session() == self.session(),
    {
        while self.replies.len() > 0
            invariant self.valid(),
            decreases self.replies.len(),
        {
            let (receipt, completion) = self.replies.remove(0);
            completion.complete(receipt);
        }
        ReleasedBatch { generation: self.generation, session: self.session }
    }
}
}
