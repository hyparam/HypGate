use vstd::prelude::*;
use crate::framing::RecordFrame;

verus! {

// One journal per exclusively owned file. Offsets exclude its already-synced
// session header. Tickets never leave the single disk worker.
pub struct Append { session: u128, start: u64, end: u64 }
impl Append {
    pub closed spec fn session(&self) -> u128 { self.session }
    pub fn session_id(&self) -> (out: u128) ensures out == self.session(), { self.session }
    pub closed spec fn start(&self) -> u64 { self.start }
    pub closed spec fn end(&self) -> u64 { self.end }
}
// Only a successful journal commit issues this receipt. It owns the immutable
// frame so consumers can check exact bytes without a collision assumption.
pub struct DurableFrame { session: u128, frame: RecordFrame, #[allow(dead_code)] prefix: Ghost<Seq<u8>> }
impl DurableFrame {
    pub fn into_receipt(self) -> (out: crate::audit_receipt::AuditReceipt)
        requires self.valid(),
        ensures out.valid(), out.durable(), out.session() == self.session(), out.record() == self.record(),
            out.prefix() == self.prefix(),
    { crate::audit_receipt::AuditReceipt::from_durable_parts(self.session, self.frame, self.prefix) }

    pub closed spec fn session(&self) -> u128 { self.session }
    pub fn session_id(&self) -> (out: u128) ensures out == self.session(), { self.session }
    pub closed spec fn valid(&self) -> bool { self.frame.valid() }
    pub closed spec fn prefix(&self) -> Seq<u8> { self.prefix@ }
    pub closed spec fn acknowledged(&self) -> Seq<u8> { self.prefix@ + self.frame.contents() }
    pub closed spec fn checksum(&self) -> Seq<u8> { self.frame.checksum() }
    pub closed spec fn record(&self) -> Seq<u8> { self.frame.contents() }
    pub closed spec fn header(&self) -> crate::framing::Header { self.frame.header() }
    pub closed spec fn payload(&self) -> Seq<u8> { self.frame.payload() }
    pub closed spec fn payload_len(&self) -> nat { self.frame.payload().len() }
    pub proof fn canonical(&self)
        requires self.valid(),
        ensures self.record() == crate::framing::encoding(self.header()) + self.payload() + self.checksum(),
            crate::framing::valid(self.header()), self.header().payload == self.payload().len(),
            self.checksum().len() == 32,
    { self.frame.canonical() }
    pub proof fn retained_size(&self)
        requires self.valid(),
        ensures self.record().len() == self.payload_len() + 65,
    { self.frame.retained_size() }
    pub fn matches_record(&self, h: crate::framing::Header, payload: &[u8]) -> (ok: bool)
        requires self.valid(),
        ensures ok == (crate::framing::valid(h) && h.payload == payload.len()
                && self.record() == crate::framing::encoding(h) + payload@ + self.checksum()),
            ok ==> self.acknowledged() == self.prefix()
            + crate::framing::encoding(h) + payload@ + self.checksum(),
    {
        let ok = self.frame.matches_record(h, payload);
        proof {
            assert((self.prefix() + (crate::framing::encoding(h) + payload@ + self.checksum()))
                =~= (self.prefix() + crate::framing::encoding(h) + payload@ + self.checksum()));
        }
        ok
    }
}
pub struct Journal {
    session: u128,
    written: u64,
    durable: u64,
    acknowledged: u64,
    pending: u64,
    failed: bool,
    bytes: Ghost<Seq<u8>>,
}

impl Journal {
    pub closed spec fn session(&self) -> u128 { self.session }
    pub fn session_id(&self) -> (out: u128) ensures out == self.session(), { self.session }
    pub closed spec fn written_len(&self) -> u64 { self.written }
    pub closed spec fn durable_len(&self) -> u64 { self.durable }
    pub closed spec fn acked_len(&self) -> u64 { self.acknowledged }
    pub closed spec fn idle(&self) -> bool { self.pending == 0 }
    pub closed spec fn valid(&self) -> bool {
        self.acknowledged <= self.durable <= self.written
        && self.bytes@.len() == self.written
        && (self.pending == 0 || self.pending > self.written)
    }
    pub closed spec fn history(&self) -> Seq<u8> { self.bytes@ }
    pub closed spec fn stable(&self) -> Seq<u8> { self.bytes@.subrange(0, self.durable as int) }
    pub closed spec fn acked(&self) -> Seq<u8> { self.bytes@.subrange(0, self.acknowledged as int) }
    pub closed spec fn failed(&self) -> bool { self.failed }
    pub closed spec fn matches(&self, t: &Append) -> bool {
        t.session == self.session && t.start == self.written && t.end == self.pending && t.end > t.start
    }

    pub proof fn prefix_lengths(&self)
        requires self.valid(),
        ensures self.history().len() == self.written_len(), self.acked().len() == self.acked_len(),
    {}

    pub fn new(session: u128) -> (j: Self)
        ensures j.session() == session, j.valid(), j.history() == Seq::<u8>::empty(), j.acked() == Seq::<u8>::empty(), j.stable() == Seq::<u8>::empty(), !j.failed(),
    {
        Journal { session, written: 0, durable: 0, acknowledged: 0, pending: 0, failed: false, bytes: Ghost(Seq::empty()) }
    }

    pub fn is_failed(&self) -> (out: bool) ensures out == self.failed(), { self.failed }

    pub fn begin(&mut self, length: u64) -> (out: Option<Append>)
        requires old(self).valid(),
        ensures final(self).session() == old(self).session(), final(self).valid(), final(self).history() == old(self).history(),
            final(self).stable() == old(self).stable(), final(self).acked() == old(self).acked(),
            final(self).failed() == old(self).failed(),
            out.is_some() <==> (!old(self).failed() && old(self).idle()
                && 0 < length && length <= u64::MAX - old(self).written_len()),
            match out { Some(t) => old(self).idle() && final(self).matches(&t) && t.end() - t.start() == length && !final(self).failed(),
                None => *final(self) == *old(self) },
    {
        if self.failed || self.pending != 0 || length == 0 || length > u64::MAX - self.written { return None; }
        self.pending = self.written + length;
        Some(Append { session: self.session, start: self.written, end: self.pending })
    }

    // Called only after write_all successfully reports the exact frame written.
    pub fn record_written(&mut self, t: &Append, bytes: &Vec<u8>) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).session() == old(self).session(), final(self).valid(), final(self).stable() == old(self).stable(),
            final(self).acked() == old(self).acked(), final(self).acked_len() == old(self).acked_len(),
            final(self).failed() == old(self).failed(),
            ok <==> (!old(self).failed() && old(self).matches(t)
                && bytes@.len() == t.end() - t.start()),
            ok ==> old(self).matches(t) && final(self).history() == old(self).history() + bytes@
                && final(self).written_len() == t.end() && final(self).idle() && !final(self).failed(),
            !ok ==> *final(self) == *old(self),
    {
        if self.failed || t.session != self.session || t.start != self.written || t.end != self.pending
            || t.end <= t.start || bytes.len() as u64 != t.end - t.start { return false; }
        let ghost previous = self.bytes@;
        self.bytes = Ghost(self.bytes@ + bytes@);
        self.written = t.end;
        self.pending = 0;
        proof {
            assert(self.bytes@.subrange(0, self.durable as int) =~= previous.subrange(0, self.durable as int));
            assert(self.bytes@.subrange(0, self.acknowledged as int) =~= previous.subrange(0, self.acknowledged as int));
        }
        true
    }

    // This event asserts a successful sync syscall, not a theorem about the OS.
    pub fn sync_succeeded(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).session() == old(self).session(), final(self).valid(), final(self).history() == old(self).history(),
            final(self).written_len() == old(self).written_len(), final(self).idle() == old(self).idle(),
            final(self).acked() == old(self).acked(), final(self).acked_len() == old(self).acked_len(),
            final(self).failed() == old(self).failed(),
            ok <==> (!old(self).failed() && old(self).idle()),
            ok ==> old(self).idle() && final(self).stable() == final(self).history() && !final(self).failed(),
            !ok ==> *final(self) == *old(self),
    {
        if self.failed || self.pending != 0 { return false; }
        self.durable = self.written;
        true
    }

    pub fn acknowledge(&mut self, t: &Append) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).session() == old(self).session(), final(self).valid(), final(self).history() == old(self).history(),
            final(self).written_len() == old(self).written_len(), final(self).idle() == old(self).idle(),
            final(self).stable() == old(self).stable(), final(self).failed() == old(self).failed(),
            ok <==> (!old(self).failed() && t.session() == old(self).session() && t.start() == old(self).acked_len()
                && t.end() > t.start() && t.end() <= old(self).durable_len()),
            ok ==> final(self).acked_len() == t.end() && t.start() == old(self).acked_len()
                && t.end() > t.start() && !final(self).failed(),
            !ok ==> *final(self) == *old(self),
    {
        if self.failed || t.session != self.session || t.start != self.acknowledged || t.end <= t.start || self.durable < t.end { return false; }
        self.acknowledged = t.end;
        true
    }

    // Trusted caller reports successful write_all AND sync for these exact bytes.
    // Compose the events so success binds the acknowledged prefix to the frame.
    pub fn record_durable(&mut self, t: &Append, bytes: &Vec<u8>) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).session() == old(self).session(), final(self).valid(),
            ok == (!old(self).failed() && old(self).matches(t)
                && old(self).acked_len() == old(self).written_len()
                && bytes@.len() == t.end() - t.start()),
            ok ==> final(self).history() == old(self).history() + bytes@
                && final(self).acked() == old(self).history() + bytes@
                && final(self).stable() == final(self).history()
                && final(self).acked_len() == t.end() && final(self).idle()
                && !final(self).failed(),
            !ok ==> *final(self) == *old(self),
    {
        if t.session != self.session || t.start != self.written || self.failed || t.end != self.pending
            || t.end <= t.start || t.end - t.start != bytes.len() as u64
            || self.acknowledged != self.written { return false; }
        let _written = self.record_written(t, bytes);
        assert(_written);
        let _synced = self.sync_succeeded();
        assert(_synced);
        let _acknowledged = self.acknowledge(t);
        assert(_acknowledged);
        proof { assert(self.acked() =~= self.history()); }
        true
    }

    // The receipt owns the committed frame, so its acknowledged bytes are the
    // prior history followed by exactly that canonical header, payload, and checksum.
    pub fn commit_frame(&mut self, t: &Append, frame: RecordFrame) -> (out: Option<DurableFrame>)
        requires old(self).valid(), frame.valid(),
        ensures final(self).session() == old(self).session(), final(self).valid(),
            out.is_some() == (!old(self).failed() && old(self).matches(t)
                && old(self).acked_len() == old(self).written_len()
                && frame.contents().len() == t.end() - t.start()),
            match out {
            Some(receipt) => receipt.session() == old(self).session() && receipt.valid() && receipt.record() == frame.contents()
                && receipt.prefix() == old(self).history()
                && receipt.acknowledged() == final(self).acked()
                && final(self).acked() == final(self).history()
                && final(self).history() == old(self).history() + frame.contents()
                && final(self).stable() == final(self).history() && !final(self).failed(),
            None => *final(self) == *old(self),
        },
    {
        let ghost prefix = self.history();
        proof { frame.canonical(); }
        if !self.record_durable(t, frame.bytes()) { return None; }
        Some(DurableFrame { session: self.session, frame, prefix: Ghost(prefix) })
    }

    pub fn fail(&mut self)
        requires old(self).valid(),
        ensures final(self).session() == old(self).session(), final(self).valid(), final(self).failed(), final(self).history() == old(self).history(),
            final(self).stable() == old(self).stable(), final(self).acked() == old(self).acked(),
    { self.failed = true; }

    // Conditional crash theorem: if the storage model preserves the synced byte
    // prefix, every byte authorized for acknowledgment is preserved exactly.
    // Scanner correctness and real storage behavior are separate obligations.
    pub proof fn acknowledged_prefix_survives(&self, recovered: Seq<u8>)
        requires self.valid(), recovered.len() >= self.stable().len(),
            recovered.subrange(0, self.stable().len() as int) == self.stable(),
        ensures recovered.len() >= self.acked().len(),
            recovered.subrange(0, self.acked().len() as int) == self.acked(),
    {
        assert(recovered.subrange(0, self.acknowledged as int) =~= self.acked());
    }
}
}
