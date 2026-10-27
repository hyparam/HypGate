//! Verified rotation adapter for the disk worker's logical append-only storage.
//! The filesystem supplies SegmentIo; headers are excluded from byte histories.
use vstd::prelude::*;
use crate::disk_worker::Storage;
use crate::segment_protocol::{self, Event};

verus! {
/// Trusted filesystem contract. Creating the next segment durably establishes
/// its header and directory entry, preserves all prior bytes, and never reuses
/// a path. The session remains immutable across every operation.
pub trait SegmentIo {
    spec fn valid(&self) -> bool;
    spec fn session(&self) -> u128;
    spec fn index(&self) -> u64;
    spec fn current_bytes(&self) -> nat;
    spec fn written(&self) -> Seq<u8>;
    spec fn stable(&self) -> Seq<u8>;
    spec fn trace(&self) -> Seq<Event>;
    fn expired(&self) -> bool;
    /// Sync the current segment before it can become a predecessor. The
    /// published logical stable prefix is unchanged until explicit sync.
    fn seal(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).session() == old(self).session(),
            final(self).index() == old(self).index(), final(self).current_bytes() == old(self).current_bytes(),
            final(self).written() == old(self).written(), final(self).stable() == old(self).stable(),
            final(self).trace() == old(self).trace().push(Event::Seal(old(self).index(), ok));
    fn create_next(&mut self, session: u128, index: u64) -> (ok: bool)
        requires old(self).valid(), session == old(self).session(),
            old(self).index() < u64::MAX, index == old(self).index() + 1,
        ensures final(self).valid(), final(self).session() == old(self).session(),
            final(self).written() == old(self).written(), final(self).stable() == old(self).stable(),
            ok ==> final(self).index() == index && final(self).current_bytes() == 0,
            !ok ==> final(self).index() == old(self).index(),
            final(self).trace() == old(self).trace().push(Event::Create(index, ok));
    fn append(&mut self, bytes: &Vec<u8>) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).session() == old(self).session(),
            final(self).index() == old(self).index(), final(self).stable() == old(self).stable(),
            ok ==> final(self).written() == old(self).written() + bytes@
                && final(self).current_bytes() == old(self).current_bytes() + bytes.len(),
            final(self).trace() == old(self).trace().push(Event::Append(old(self).index(), ok));
    fn sync(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).session() == old(self).session(),
            final(self).index() == old(self).index(), final(self).current_bytes() == old(self).current_bytes(),
            final(self).written() == old(self).written(),
            ok ==> final(self).stable() == final(self).written(),
            final(self).trace() == old(self).trace().push(Event::Sync(old(self).index(), ok));
}

pub struct RotatingStorage<I: SegmentIo> {
    io: I,
    session: u128,
    index: u64,
    used: u64,
    limit: u64,
    failed: bool,
}
impl<I: SegmentIo> RotatingStorage<I> {
    pub closed spec fn session(&self) -> u128 { self.session }
    pub closed spec fn index(&self) -> u64 { self.index }
    pub closed spec fn used(&self) -> u64 { self.used }
    pub closed spec fn failed(&self) -> bool { self.failed }
    pub closed spec fn trace(&self) -> Seq<Event> { self.io.trace() }
    pub proof fn writer_protocol(&self)
        requires self.valid(),
        ensures segment_protocol::run(self.trace()).is_some(),
            forall|at: int| 0 <= at < self.trace().len() && self.trace()[at] is Create
                ==> at > 0 && self.trace()[at - 1] == Event::Seal((self.trace()[at]->Create_0 - 1) as u64, true),
    {
        assert forall|at: int| 0 <= at < self.trace().len() && self.trace()[at] is Create
            implies at > 0 && self.trace()[at - 1] == Event::Seal((self.trace()[at]->Create_0 - 1) as u64, true) by {
            segment_protocol::creation_follows_seal(self.trace(), at);
        }
    }
    pub fn new(io: I, session: u128, limit: u64) -> (out: Self)
        requires io.valid(), io.session() == session, io.index() == 0,
            io.current_bytes() == 0, io.written() == Seq::<u8>::empty(), io.stable() == Seq::<u8>::empty(),
            limit > 56, io.trace() == Seq::<Event>::empty(),
        ensures out.valid(), out.written() == Seq::<u8>::empty(), out.stable() == Seq::<u8>::empty(),
            out.session() == session, out.index() == 0, out.used() == 56, !out.failed(),
    { Self { io, session, index: 0, used: 56, limit, failed: false } }

    /// Policy uses remaining space to avoid overflow. Empty segments accept a
    /// whole oversized frame; subsequent frames rotate before they are written.
    pub fn should_rotate(used: u64, limit: u64, length: u64, expired: bool) -> (yes: bool)
        requires used >= 56, limit > 56,
        ensures yes == (used > 56 && (used + length > limit || expired)),
    { used > 56 && (used > limit || length > limit - used || expired) }
}

impl<I: SegmentIo> Storage for RotatingStorage<I> {
    closed spec fn valid(&self) -> bool {
        self.io.valid() && self.io.session() == self.session && self.io.index() == self.index
            && self.used >= 56 && self.limit > 56
            && (!self.failed ==> self.io.current_bytes() == self.used - 56)
            && segment_protocol::run(self.io.trace()).is_some()
            && segment_protocol::run(self.io.trace()).unwrap().index == self.index
            && (!self.failed ==> !segment_protocol::run(self.io.trace()).unwrap().failed
                && !segment_protocol::run(self.io.trace()).unwrap().sealed)
    }
    closed spec fn written(&self) -> Seq<u8> { self.io.written() }
    closed spec fn stable(&self) -> Seq<u8> { self.io.stable() }

    fn write_all(&mut self, bytes: &Vec<u8>) -> (ok: bool)
        ensures final(self).session() == old(self).session(),
            final(self).index() == old(self).index() || final(self).index() == old(self).index() + 1,
            old(self).failed() ==> !ok && final(self).written() == old(self).written()
                && final(self).trace() == old(self).trace(),
            !ok ==> final(self).failed(),
    {
        if self.failed { return false; }
        let length = bytes.len() as u64;
        if length > u64::MAX - 56 { self.failed = true; return false; }
        let expired = self.io.expired();
        if Self::should_rotate(self.used, self.limit, length, expired) {
            if self.index == u64::MAX { self.failed = true; return false; }
            let next = self.index + 1;
            let ghost before_seal = self.io.trace();
            let sealed = self.io.seal();
            proof { segment_protocol::push(before_seal, Event::Seal(self.index, sealed)); }
            if !sealed { self.failed = true; return false; }
            let ghost before_create = self.io.trace();
            let created = self.io.create_next(self.session, next);
            proof { segment_protocol::push(before_create, Event::Create(next, created)); }
            if !created { self.failed = true; return false; }
            self.index = next;
            self.used = 56;
        }
        let ghost before_append = self.io.trace();
        let appended = self.io.append(bytes);
        proof { segment_protocol::push(before_append, Event::Append(self.index, appended)); }
        if !appended { self.failed = true; return false; }
        self.used += length;
        true
    }
    fn sync(&mut self) -> (ok: bool)
        ensures final(self).session() == old(self).session(), final(self).index() == old(self).index(),
            old(self).failed() ==> !ok && final(self).trace() == old(self).trace(), !ok ==> final(self).failed(),
    {
        if self.failed { return false; }
        let ghost before_sync = self.io.trace();
        let ok = self.io.sync();
        proof { segment_protocol::push(before_sync, Event::Sync(self.index, ok)); }
        if !ok { self.failed = true; }
        ok
    }
}
}
