//! Production journal: every acknowledged byte belongs to a canonical frame.
use vstd::prelude::*;
use crate::{framing::RecordFrame, journal::{Append, DurableFrame, Journal}};

verus! {
pub open spec fn encoded_frames(frames: Seq<RecordFrame>) -> Seq<u8>
    decreases frames.len(),
{
    if frames.len() == 0 { Seq::empty() }
    else { encoded_frames(frames.drop_last()) + frames.last().contents() }
}

pub struct AuditJournal { inner: Journal, frames: Ghost<Seq<RecordFrame>> }
impl AuditJournal {
    pub closed spec fn frames(&self) -> Seq<RecordFrame> { self.frames@ }
    pub closed spec fn history(&self) -> Seq<u8> { self.inner.history() }
    pub closed spec fn failed(&self) -> bool { self.inner.failed() }
    pub closed spec fn idle(&self) -> bool { self.inner.idle() }
    pub closed spec fn matches(&self, ticket: &Append) -> bool { self.inner.matches(ticket) }
    pub closed spec fn valid(&self) -> bool {
        self.inner.valid() && self.inner.acked() == self.inner.history()
            && self.inner.stable() == self.inner.history()
            && self.inner.history() == encoded_frames(self.frames@)
            && forall|i: int| 0 <= i < self.frames@.len() ==> #[trigger] self.frames@[i].valid()
    }
    pub fn new() -> (out: Self)
        ensures out.valid(), out.frames() == Seq::<RecordFrame>::empty(),
            out.history() == Seq::<u8>::empty(), !out.failed(),
    { AuditJournal { inner: Journal::new(), frames: Ghost(Seq::empty()) } }

    pub fn begin(&mut self, length: u64) -> (out: Option<Append>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).frames() == old(self).frames(),
            final(self).history() == old(self).history(), final(self).failed() == old(self).failed(),
            out.is_some() == (!old(self).failed() && old(self).idle()
                && 0 < length && length <= u64::MAX - old(self).history().len()),
            match out {
                Some(ticket) => final(self).matches(&ticket),
                None => *final(self) == *old(self),
            },
    {
        proof { self.inner.prefix_lengths(); }
        self.inner.begin(length)
    }

    pub fn commit_frame(&mut self, ticket: &Append, frame: RecordFrame) -> (out: Option<DurableFrame>)
        requires old(self).valid(), frame.valid(),
        ensures final(self).valid(),
            out.is_some() == (!old(self).failed() && old(self).matches(ticket)
                && frame.contents().len() == ticket.end() - ticket.start()),
            match out {
                Some(receipt) => receipt.valid() && receipt.acknowledged() == final(self).history()
                    && final(self).frames() == old(self).frames().push(frame)
                    && final(self).history() == old(self).history() + frame.contents()
                    && !final(self).failed(),
                None => *final(self) == *old(self),
            },
    {
        proof { self.inner.prefix_lengths(); }
        let ghost saved = frame;
        let receipt = match self.inner.commit_frame(ticket, frame) {
            Some(receipt) => receipt, None => return None,
        };
        self.frames = Ghost(self.frames@.push(saved));
        proof {
            assert(self.frames@.drop_last() =~= old(self).frames@);
            assert(self.frames@.last() == saved);
            assert forall|i: int| 0 <= i < self.frames@.len() implies #[trigger] self.frames@[i].valid() by {
                if i < old(self).frames@.len() { assert(self.frames@[i] == old(self).frames@[i]); }
            }
        }
        Some(receipt)
    }

    pub fn fail(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).failed(),
            final(self).history() == old(self).history(), final(self).frames() == old(self).frames(),
    { self.inner.fail(); }

    pub proof fn reconstruct_acknowledged<R: crate::recovery::Source>(&self,
        data: Seq<u8>, states: Seq<crate::recovery::Scanner<R>>,
        results: Seq<Result<Option<crate::framing::RecoveredRecord>, crate::recovery::ScanError>>)
        requires self.valid(), 56 + self.history().len() <= data.len(),
            56 + self.history().len() <= u64::MAX,
            data.subrange(56, (56 + self.history().len()) as int) == self.history(),
            forall|i: int| 0 <= i < self.frames().len() ==> R::digest(crate::framing::encoding(self.frames()[i].header())
                + self.frames()[i].payload()) == #[trigger] self.frames()[i].checksum(),
            states.len() == self.frames().len() + 1, results.len() == self.frames().len(),
            states[0].position() == 56, !states[0].stopped(),
            forall|i: int| 0 <= i < states.len() ==> #[trigger] states[i].valid()
                && states[i].data() == data && states[i].io_errors() == states[0].io_errors(),
            forall|i: int| 0 <= i < results.len() ==>
                crate::recovery::scanner_step(&states[i], &states[i + 1], results[i]),
        ensures !states.last().stopped(), states.last().position() == 56 + self.history().len(),
            forall|i: int| 0 <= i < results.len() ==> match #[trigger] results[i] {
                Ok(Some(record)) => record.header == self.frames()[i].header()
                    && record.bytes@ == self.frames()[i].payload(),
                _ => false,
            },
    {
        crate::recovery::reconstruct_prefix::<R>(self.frames(), data, 56, states, results);
    }

    pub proof fn acknowledged_frames_survive(&self, recovered: Seq<u8>)
        requires self.valid(), recovered.len() >= self.history().len(),
            recovered.subrange(0, self.history().len() as int) == self.history(),
        ensures recovered.subrange(0, encoded_frames(self.frames()).len() as int)
            == encoded_frames(self.frames()),
    {}
}
}
