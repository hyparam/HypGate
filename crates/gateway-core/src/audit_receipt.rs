//! Receipt strength is explicit: written bytes need not survive a system crash.
use vstd::prelude::*;
use crate::framing::RecordFrame;

verus! {
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability { Durable, Buffered }

pub struct AuditReceipt {
    session: u128, frame: RecordFrame, durable: bool, prefix: Ghost<Seq<u8>>,
}
impl AuditReceipt {
    pub closed spec fn session(&self) -> u128 { self.session }
    pub closed spec fn valid(&self) -> bool { self.frame.valid() }
    pub closed spec fn durable(&self) -> bool { self.durable }
    pub closed spec fn prefix(&self) -> Seq<u8> { self.prefix@ }
    pub closed spec fn acknowledged(&self) -> Seq<u8> { self.prefix@ + self.frame.contents() }
    pub closed spec fn checksum(&self) -> Seq<u8> { self.frame.checksum() }
    pub closed spec fn record(&self) -> Seq<u8> { self.frame.contents() }
    pub closed spec fn header(&self) -> crate::framing::Header { self.frame.header() }
    pub closed spec fn payload(&self) -> Seq<u8> { self.frame.payload() }
    pub closed spec fn payload_len(&self) -> nat { self.frame.payload().len() }
    pub fn session_id(&self) -> (out: u128) ensures out == self.session(), { self.session }
    pub fn is_durable(&self) -> (out: bool) ensures out == self.durable(), { self.durable }
    pub proof fn canonical(&self)
        requires self.valid(),
        ensures self.record() == crate::framing::encoding(self.header()) + self.payload() + self.checksum(),
            crate::framing::valid(self.header()), self.header().payload == self.payload().len(), self.checksum().len() == 32,
    { self.frame.canonical(); }
    pub proof fn retained_size(&self)
        requires self.valid(), ensures self.record().len() == self.payload_len() + 65,
    { self.frame.retained_size(); }
    pub fn matches_record(&self, h: crate::framing::Header, payload: &[u8]) -> (ok: bool)
        requires self.valid(),
        ensures ok == (crate::framing::valid(h) && h.payload == payload.len()
            && self.record() == crate::framing::encoding(h) + payload@ + self.checksum()),
            ok ==> self.acknowledged() == self.prefix() + crate::framing::encoding(h) + payload@ + self.checksum(),
    {
        let ok = self.frame.matches_record(h, payload);
        proof { assert((self.prefix() + (crate::framing::encoding(h) + payload@ + self.checksum()))
            =~= (self.prefix() + crate::framing::encoding(h) + payload@ + self.checksum())); }
        ok
    }
    // Only the original durable journal can supply this conversion's inputs.
    pub(crate) fn from_durable_parts(session: u128, frame: RecordFrame, prefix: Ghost<Seq<u8>>) -> (out: Self)
        requires frame.valid(),
        ensures out.valid(), out.durable(), out.session() == session, out.record() == frame.contents(),
            out.prefix() == prefix@,
    { Self { session, frame, durable: true, prefix } }
}

/// Canonical acknowledged history, not an assertion that all bytes are stable.
/// The batch worker proves the selected storage condition before each commit.
pub struct BatchJournal {
    session: u128, length: u64, failed: bool, durability: Durability,
    frames: Ghost<Seq<RecordFrame>>,
}
impl BatchJournal {
    pub closed spec fn session(&self) -> u128 { self.session }
    pub closed spec fn history(&self) -> Seq<u8> { crate::audit_journal::encoded_frames(self.frames@) }
    pub closed spec fn failed(&self) -> bool { self.failed }
    pub closed spec fn requires_sync(&self) -> bool { self.durability is Durable }
    pub closed spec fn valid(&self) -> bool {
        self.length == self.history().len() && forall|i: int| 0 <= i < self.frames@.len() ==> #[trigger] self.frames@[i].valid()
    }
    pub fn new(session: u128) -> (out: Self)
        ensures out.valid(), out.session() == session, !out.failed(), out.history().len() == 0, out.requires_sync(),
    { Self::with_durability(session, Durability::Durable) }
    pub fn with_durability(session: u128, durability: Durability) -> (out: Self)
        ensures out.valid(), out.session() == session, !out.failed(), out.history().len() == 0,
            out.requires_sync() == (durability is Durable),
    { Self { session, length: 0, failed: false, durability, frames: Ghost(Seq::empty()) } }
    pub fn session_id(&self) -> (out: u128) ensures out == self.session(), { self.session }
    pub fn is_failed(&self) -> (out: bool) ensures out == self.failed(), { self.failed }
    pub fn sync_required(&self) -> (out: bool) ensures out == self.requires_sync(), { matches!(self.durability, Durability::Durable) }
    pub fn fail(&mut self)
        ensures final(self).failed(), final(self).history() == old(self).history(), final(self).session() == old(self).session(),
            final(self).requires_sync() == old(self).requires_sync(), final(self).valid() == old(self).valid(),
    { self.failed = true; }
    pub fn commit(&mut self, frame: RecordFrame) -> (out: Option<AuditReceipt>)
        requires old(self).valid(), frame.valid(),
        ensures final(self).valid(), final(self).session() == old(self).session(), final(self).failed() == old(self).failed(),
            final(self).requires_sync() == old(self).requires_sync(),
            out.is_some() == (!old(self).failed() && frame.contents().len() <= u64::MAX - old(self).history().len()),
            match out {
                Some(r) => r.valid() && r.session() == old(self).session() && r.durable() == old(self).requires_sync()
                    && r.record() == frame.contents() && r.prefix() == old(self).history()
                    && r.acknowledged() == final(self).history()
                    && final(self).history() == old(self).history() + frame.contents(),
                None => *final(self) == *old(self),
            },
    {
        if self.failed || frame.bytes().len() as u64 > u64::MAX - self.length { return None; }
        let ghost prefix = self.history();
        self.length += frame.bytes().len() as u64;
        self.frames = Ghost(self.frames@.push(frame));
        proof {
            assert(self.frames@.drop_last() =~= old(self).frames@);
            assert forall|i: int| 0 <= i < self.frames@.len() implies #[trigger] self.frames@[i].valid() by {
                if i < old(self).frames@.len() { assert(self.frames@[i] == old(self).frames@[i]); }
            }
        }
        Some(AuditReceipt { session: self.session, frame, durable: self.sync_required(), prefix: Ghost(prefix) })
    }
}
}
