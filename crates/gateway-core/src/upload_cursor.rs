//! Verified progress accounting for shipped exchanges. Exchanges are numbered in
//! emission order. The resolved count only moves forward, only to the end of the
//! batch currently in flight, and only through an acknowledgment naming that
//! batch's id or an explicit poison decision. Abandoning or retrying a batch
//! changes nothing, so a crash between send and checkpoint re-sends the same
//! range under the same id.
use vstd::prelude::*;
use crate::shipping_identity::batch_id;
use crate::framing::equal_bytes;

verus! {
pub struct InFlight { first: u64, end: u64, id: Vec<u8> }
impl InFlight {
    pub closed spec fn first(&self) -> u64 { self.first }
    pub closed spec fn end(&self) -> u64 { self.end }
    pub closed spec fn id(&self) -> Seq<u8> { self.id@ }
    pub fn batch_id(&self) -> (out: &Vec<u8>) ensures out@ == self.id(), { &self.id }
    pub fn range(&self) -> (out: (u64, u64)) ensures out.0 == self.first(), out.1 == self.end(), { (self.first, self.end) }
}

pub struct UploadCursor { emitted: u64, resolved: u64, poisoned: u64, in_flight: Option<InFlight> }

impl UploadCursor {
    pub closed spec fn emitted(&self) -> u64 { self.emitted }
    pub closed spec fn resolved(&self) -> u64 { self.resolved }
    pub closed spec fn poisoned(&self) -> u64 { self.poisoned }
    pub closed spec fn in_flight(&self) -> Option<InFlight> { self.in_flight }
    pub closed spec fn valid(&self) -> bool {
        self.resolved <= self.emitted && match self.in_flight {
            Some(b) => b.first == self.resolved && b.first < b.end && b.end <= self.emitted && b.id@.len() == 40,
            None => true,
        }
    }

    /// What a valid cursor guarantees, for callers outside this module.
    pub proof fn bounds(&self)
        requires self.valid(),
        ensures self.resolved() <= self.emitted(), match self.in_flight() {
            Some(b) => b.first() == self.resolved() && b.first() < b.end() && b.end() <= self.emitted() && b.id().len() == 40,
            None => true,
        },
    {}

    /// Restore from a checkpoint; a batch that was in flight is forgotten and
    /// will be rebuilt from the same exchanges under the same id.
    pub fn restore(emitted: u64, resolved: u64, poisoned: u64) -> (out: Option<Self>)
        ensures match out {
            Some(c) => resolved <= emitted && c.valid() && c.emitted() == emitted && c.resolved() == resolved
                && c.poisoned() == poisoned && c.in_flight().is_none(),
            None => resolved > emitted,
        },
    {
        if resolved > emitted { return None; }
        Some(UploadCursor { emitted, resolved, poisoned, in_flight: None })
    }

    pub fn counts(&self) -> (out: (u64, u64, u64))
        ensures out.0 == self.emitted(), out.1 == self.resolved(), out.2 == self.poisoned(),
    { (self.emitted, self.resolved, self.poisoned) }

    pub fn pending(&self) -> (out: u64)
        requires self.valid(),
        ensures out == self.emitted() - self.resolved(),
    { self.emitted - self.resolved }

    pub fn current(&self) -> (out: Option<&InFlight>)
        ensures match out { Some(b) => self.in_flight() == Some(*b), None => self.in_flight().is_none() },
    { self.in_flight.as_ref() }

    /// Count newly emitted exchanges. Fails only at the u64 limit.
    pub fn emit(&mut self, count: u64) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).resolved() == old(self).resolved(),
            final(self).poisoned() == old(self).poisoned(), final(self).in_flight() == old(self).in_flight(),
            ok == (old(self).emitted() + count <= u64::MAX),
            ok ==> final(self).emitted() == old(self).emitted() + count,
            !ok ==> *final(self) == *old(self),
    {
        if count > u64::MAX - self.emitted { return false; }
        self.emitted = self.emitted + count;
        true
    }

    /// Open a batch over the next `count` unresolved exchanges. The id binds the
    /// session, the exchange index range, and the body checksum.
    pub fn open_batch(&mut self, count: u64, session: &[u8; 16], checksum: u64) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).emitted() == old(self).emitted(),
            final(self).resolved() == old(self).resolved(), final(self).poisoned() == old(self).poisoned(),
            ok == (old(self).in_flight().is_none() && 0 < count && count <= old(self).emitted() - old(self).resolved()),
            ok ==> match final(self).in_flight() {
                Some(b) => b.first() == old(self).resolved() && b.end() == old(self).resolved() + count
                    && b.id() == crate::shipping_identity::batch_id_encoding(session@, old(self).resolved(),
                        (old(self).resolved() + count) as u64, checksum),
                None => false,
            },
            !ok ==> *final(self) == *old(self),
    {
        if self.in_flight.is_some() || count == 0 || count > self.emitted - self.resolved { return false; }
        let id = batch_id(session, self.resolved, self.resolved + count, checksum);
        self.in_flight = Some(InFlight { first: self.resolved, end: self.resolved + count, id });
        true
    }

    /// A 202 for exactly the in-flight batch id resolves its range.
    pub fn acknowledge(&mut self, id: &[u8]) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).emitted() == old(self).emitted(),
            final(self).poisoned() == old(self).poisoned(),
            ok == match old(self).in_flight() { Some(b) => b.id() == id@, None => false },
            ok ==> final(self).in_flight().is_none()
                && final(self).resolved() == old(self).in_flight().unwrap().end(),
            !ok ==> *final(self) == *old(self),
    {
        let matched = match &self.in_flight { Some(b) => equal_bytes(b.id.as_slice(), id), None => false };
        if !matched { return false; }
        let batch = self.in_flight.take().unwrap();
        self.resolved = batch.end;
        true
    }

    /// Give up on the in-flight batch without resolving anything.
    pub fn abandon(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).emitted() == old(self).emitted(),
            final(self).resolved() == old(self).resolved(), final(self).poisoned() == old(self).poisoned(),
            final(self).in_flight().is_none(),
    { self.in_flight = None; }

    /// The server rejected the in-flight batch as malformed: skip its range and
    /// count it, so the shipper neither retries forever nor loses its place.
    pub fn poison(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).emitted() == old(self).emitted(),
            ok == old(self).in_flight().is_some(),
            ok ==> final(self).in_flight().is_none()
                && final(self).resolved() == old(self).in_flight().unwrap().end()
                && final(self).poisoned() == (if old(self).poisoned() == u64::MAX { u64::MAX } else { (old(self).poisoned() + 1) as u64 }),
            !ok ==> *final(self) == *old(self),
    {
        let Some(batch) = self.in_flight.take() else { return false; };
        self.resolved = batch.end;
        self.poisoned = if self.poisoned == u64::MAX { u64::MAX } else { self.poisoned + 1 };
        true
    }
}
}
