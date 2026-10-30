use vstd::prelude::*;
use crate::resource::{RequestKey, ResourceAdmission};
use crate::policy::AuthorizedRequest;
use crate::stream::{StreamChunk, Ticket};

verus! {
/// Private ownership pair. No extraction, cloning, or mutable stream reference.
/// Raw stream construction and key-borrowing claim/release are internal to the
/// core. External callers must use this consuming ownership boundary.
///
/// ```compile_fail,E0624
/// let _ = gateway_core::stream::StreamChunk::new(1, vec![], 1, false);
/// ```
///
/// ```compile_fail,E0624
/// fn claim_raw(registry: &gateway_core::resource::ResourceAdmission,
///     key: &mut gateway_core::resource::RequestKey,
///     authority: &gateway_core::policy::AuthorizedRequest<'_>) {
///     registry.authorized_stream(key, authority, false);
/// }
/// ```
///
/// ```compile_fail,E0624
/// fn release_raw(registry: &mut gateway_core::resource::ResourceAdmission,
///     key: &gateway_core::resource::RequestKey, stream: gateway_core::stream::StreamChunk) {
///     registry.release_stream(key, stream);
/// }
/// ```
///
/// ```compile_fail
/// fn replace_owned_stream(owner: &mut gateway_core::owned_stream::OwnedStream) {
///     owner.stream().advance(vec![1]);
/// }
/// ```
///
/// ```compile_fail
/// fn complete_while_read_borrow_is_live(owner: &mut gateway_core::owned_stream::OwnedStream) {
///     let buffer = owner.read_buffer();
///     owner.finish_read(1);
///     buffer[0] = 7;
/// }
/// ```
pub struct OwnedStream { key: RequestKey, stream: StreamChunk, read_buffer: Vec<u8>, audit_session: Option<u128>, audit_tenant: u64, audit_direction: u8, audit_durable: bool, audit: Ghost<Option<crate::audit_receipt::AuditReceipt>> }
impl OwnedStream {
    pub closed spec fn audit_durable(&self) -> bool { self.audit_durable }
    pub closed spec fn audit_session(&self) -> Option<u128> { self.audit_session }
    pub closed spec fn audit_tenant(&self) -> u64 { self.audit_tenant }
    pub fn recorded_direction(&self) -> (out: u8)
        ensures out == self.audit_direction(),
    { self.audit_direction }
    pub closed spec fn audit_direction(&self) -> u8 { self.audit_direction }
    pub closed spec fn receipt(&self) -> Option<crate::audit_receipt::AuditReceipt> { self.audit@ }
    pub closed spec fn audit_valid(&self) -> bool {
        match self.audit_session {
            None => self.audit@.is_none(),
            Some(session) => self.audit@.is_some() && {
                let r = self.audit@.unwrap();
                r.valid() && r.durable() == self.audit_durable && r.session() == session && self.audit_direction <= 1
                && self.state().body().len() <= 1048576
                && r.record() == self.state().audit_frame(self.audit_tenant, self.audit_direction, r.checksum())
            },
        }
    }
    pub open spec fn audited_for(&self, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding) -> bool {
        self.audit_session().is_some() && self.audit_session() == journal.session() && self.audit_tenant() == authority.tenant()
            && self.state().owner() == authority.request() && (!journal.requires_sync() || self.audit_durable())
    }
    pub fn is_audited_for(&self, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding) -> (ok: bool)
        requires self.valid(), authority.valid(),
        ensures ok == self.audited_for(authority, journal),
    {
        self.audit_session.is_some() && journal.matches_session(self.audit_session)
            && self.audit_tenant == authority.tenant_id() && self.stream.owner_id() == authority.request_id()
            && journal.accepts_durability(self.audit_durable)
    }
    pub proof fn durable_receipt_evidence(&self, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding)
        requires self.valid(), self.audited_for(authority, journal), journal.requires_sync(),
        ensures self.receipt().is_some(), self.receipt().unwrap().durable(),
    {}
    pub proof fn receipt_evidence(&self)
        requires self.valid(), self.audit_session().is_some(),
        ensures self.receipt().is_some(), self.receipt().unwrap().valid(), self.state().body().len() <= 1048576,
            Some(self.receipt().unwrap().session()) == self.audit_session(),
            self.receipt().unwrap().record()
                == self.state().audit_frame(self.audit_tenant(), self.audit_direction(), self.receipt().unwrap().checksum()),
    {}
    // Strict-mode evidence is always a body record: its canonical header decodes
    // to the current chunk's header for the recorded body direction, so a
    // metadata record (kind 2 to 4) can never be the receipt behind a write ticket.
    pub proof fn receipt_is_body_record(&self)
        requires self.valid(), self.audit_session().is_some(),
        ensures self.receipt().is_some(), crate::framing::body_kind(self.audit_direction()),
            crate::framing::decoded(self.receipt().unwrap().record().subrange(0, 33))
                == Some(self.state().audit_header(self.audit_tenant(), self.audit_direction())),
            self.state().audit_header(self.audit_tenant(), self.audit_direction()).kind == self.audit_direction(),
    {
        let header = self.state().audit_header(self.audit_tenant(), self.audit_direction());
        let receipt = self.receipt().unwrap();
        receipt.canonical();
        crate::framing::encoding_decodes(header);
        crate::framing::encoding_decodes(receipt.header());
        // Both canonical prefixes are the first 33 record bytes, so the header
        // encodings coincide; injectivity then identifies the headers.
        assert(receipt.record().subrange(0, 33) =~= crate::framing::encoding(receipt.header()));
        assert(receipt.record().subrange(0, 33) =~= crate::framing::encoding(header));
    }
    pub closed spec fn state(&self) -> StreamChunk { self.stream }
    pub closed spec fn read_bytes(&self) -> Seq<u8> { self.read_buffer@ }
    pub closed spec fn key(&self) -> RequestKey { self.key }
    pub closed spec fn valid(&self) -> bool {
        self.audit_valid() && self.key.stream_claimed() && self.stream.valid() && self.stream.owner() == self.key.id()
            && self.stream.body().len() + self.read_buffer.len() <= self.stream.capacity()
            && (self.read_buffer.len() > 0 ==> self.stream.body().len() == 0)
    }
    // Stream transitions leave the key and read buffer alone; most leave the audit evidence too.
    pub open spec fn same_owner(&self, prior: &Self) -> bool {
        self.key() == prior.key() && self.read_bytes() == prior.read_bytes()
    }
    pub open spec fn same_audit(&self, prior: &Self) -> bool {
        self.audit_session() == prior.audit_session() && self.audit_tenant() == prior.audit_tenant()
            && self.audit_durable() == prior.audit_durable() && self.audit_direction() == prior.audit_direction() && self.receipt() == prior.receipt()
    }
    pub open spec fn unaudited(&self) -> bool { self.audit_session().is_none() && self.receipt().is_none() }
    // The stream state after a successful reservation of `ticket`.
    pub open spec fn prepared_state(pre: Self, post: Self, max: usize, ticket: Ticket) -> bool {
        StreamChunk::prepared(pre.state(), post.state(), max, Some(ticket))
    }
    // Any change to the retained chunk invalidates its journal receipt.
    fn clear_audit(&mut self)
        ensures final(self).unaudited(), final(self).key() == old(self).key(), final(self).state() == old(self).state(),
            final(self).read_bytes() == old(self).read_bytes(),
    { self.audit_session = None; self.audit = Ghost(None); }

    pub proof fn payload_bound(&self)
        requires self.valid(),
        ensures self.state().valid(), self.state().body().len() + self.read_bytes().len() <= self.state().capacity(),
            self.read_bytes().len() > 0 ==> self.state().body().len() == 0,
    {}

    pub fn claim(registry: &ResourceAdmission, mut key: RequestKey,
        authority: &AuthorizedRequest, strict: bool) -> (out: Result<Self, RequestKey>)
        requires registry.valid(), authority.valid(),
        ensures match out {
            Ok(owned) => owned.valid() && registry.owns(&owned.key())
                && owned.key().slot() == key.slot() && owned.key().id() == key.id()
                && owned.state().capacity() == registry.per_request()
                && owned.state().owner() == authority.request()
                && owned.state().body().len() == 0 && owned.state().strict() == strict
                && owned.read_bytes().len() == 0 && !owned.state().closed() && !owned.state().pending()
                && owned.state().position() == 0
                && (forall|owners: Seq<Option<OwnedStream>>|
                    #[trigger] crate::owned_accounting::owners_match(registry.entries(), owners, registry.per_request())
                    ==> crate::owned_accounting::owners_match(registry.entries(),
                        owners.update(owned.key().slot() as int, Some(owned)), registry.per_request())),
            Err(returned) => returned == key && (key.stream_claimed()
                || key.id() != authority.request() || !registry.owns(&key)),
        },
    {
        match registry.authorized_stream(&mut key, authority, strict) {
            Some(stream) => {
                proof { stream.payload_within_capacity(); }
                let owned = OwnedStream { key, stream, read_buffer: Vec::new(), audit_session: None, audit_tenant: 0, audit_direction: 0, audit_durable: false, audit: Ghost(None) };
                proof {
                    assert forall|owners: Seq<Option<OwnedStream>>|
                        #[trigger] crate::owned_accounting::owners_match(registry.entries(), owners, registry.per_request())
                        implies crate::owned_accounting::owners_match(registry.entries(),
                            owners.update(owned.key().slot() as int, Some(owned)), registry.per_request())
                    by { crate::owned_accounting::replace_owner(registry.entries(), owners,
                        registry.per_request(), owned.key().slot() as int, owned); }
                }
                Ok(owned)
            },
            None => Err(key),
        }
    }

    pub fn stream(&self) -> (out: &StreamChunk)
        ensures *out == self.state(), self.valid() ==> out.valid(),
    { &self.stream }

    pub fn has_read_buffer(&self) -> (out: bool)
        ensures out == (self.read_bytes().len() > 0),
    { self.read_buffer.len() > 0 }

    pub fn is_live(&self, registry: &ResourceAdmission) -> (out: bool)
        requires self.valid(), registry.valid(),
        ensures out == (registry.owns(&self.key()) && !self.state().closed()),
    { registry.capacity(&self.key).is_some() && !self.stream.is_closed() }

    pub proof fn owner_evidence(&self)
        requires self.valid(),
        ensures self.state().owner() == self.key().id(),
    {}
    pub fn owner_id(&self) -> (out: u64)
        requires self.valid(),
        ensures out == self.key().id(), out == self.state().owner(),
    { self.stream.owner_id() }

    pub fn retire(self, registry: &mut ResourceAdmission) -> (ok: bool)
        requires self.valid(), old(registry).valid(),
        ensures ResourceAdmission::released(*old(registry), *final(registry), &self.key(), ok),
            ok == old(registry).owns(&self.key()),
    { registry.release_stream(&self.key, self.stream) }

    pub fn begin_read(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            ok == (old(self).read_bytes().len() == 0 && old(self).state().capacity() > 0
                && !old(self).state().closed() && !old(self).state().pending()
                && old(self).state().position() == old(self).state().body().len()),
            ok ==> StreamChunk::discarded(old(self).state(), final(self).state(), true)
                && final(self).read_bytes().len() == old(self).state().capacity() && final(self).unaudited(),
            !ok ==> *final(self) == *old(self),
    {
        if !self.read_buffer.is_empty() || self.stream.capacity_bytes() == 0 { return false; }
        if !self.stream.discard_completed() { return false; }
        self.clear_audit();
        let capacity = self.stream.capacity_bytes();
        self.read_buffer = Vec::with_capacity(capacity);
        self.read_buffer.resize(capacity, 0);
        true
    }

    // Rust's slice borrow cannot resize the backing vector. The vstd slice
    // projection exposes future contents abstractly, so the preservation
    // postcondition explicitly states the length obligation at this boundary.
    pub fn read_buffer(&mut self) -> (out: &mut [u8])
        requires old(self).valid(),
        ensures out@ == old(self).read_bytes(), final(out)@ == final(self).read_bytes(),
            final(self).state() == old(self).state(), final(self).key() == old(self).key(),
            final(self).same_audit(old(self)),
            final(out)@.len() == out@.len() ==> final(self).valid(),
    { self.read_buffer.as_mut_slice() }

    pub fn finish_read(&mut self, length: usize) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            ok == (old(self).read_bytes().len() > 0 && length <= old(self).read_bytes().len()
                && (length == 0 || (!old(self).state().closed() && !old(self).state().pending()
                    && old(self).state().position() == old(self).state().body().len()
                    && length <= old(self).state().capacity() && old(self).state().chunk() < u64::MAX))),
            ok ==> final(self).read_bytes().len() == 0
                && final(self).state().body() == old(self).read_bytes().subrange(0, length as int),
            ok && length > 0 ==> final(self).unaudited() && StreamChunk::advanced(old(self).state(), final(self).state(),
                old(self).read_bytes().subrange(0, length as int), Some((old(self).state().chunk() + 1) as u64)),
            !ok || length == 0 ==> final(self).state() == old(self).state(),
            length == 0 ==> final(self).same_audit(old(self)),
    {
        if self.read_buffer.is_empty() || length > self.read_buffer.len() { return false; }
        let mut bytes = Vec::new();
        core::mem::swap(&mut bytes, &mut self.read_buffer);
        bytes.truncate(length);
        if length == 0 { return true; }
        self.clear_audit();
        self.stream.advance(bytes).is_some()
    }

    pub fn advance(&mut self, bytes: Vec<u8>) -> (out: Option<u64>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).same_owner(old(self)),
            old(self).read_bytes().len() == 0 ==> StreamChunk::advanced(old(self).state(), final(self).state(), bytes@, out),
            old(self).read_bytes().len() != 0 ==> out.is_none(),
            out.is_some() ==> final(self).unaudited(),
            out.is_none() ==> final(self).state() == old(self).state() && final(self).same_audit(old(self)),
    {
        if !self.read_buffer.is_empty() { return None; }
        let out = self.stream.advance(bytes);
        if out.is_some() { self.clear_audit(); }
        proof { self.stream.payload_within_capacity(); }
        out
    }

    pub fn discard_completed(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).same_owner(old(self)),
            StreamChunk::discarded(old(self).state(), final(self).state(), ok),
            ok ==> final(self).unaudited(), !ok ==> final(self).same_audit(old(self)),
    {
        let ok = self.stream.discard_completed();
        if ok { self.clear_audit(); }
        ok
    }

    pub fn prepare(&mut self, max: usize) -> (out: Option<Ticket>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).same_owner(old(self)), final(self).same_audit(old(self)),
            StreamChunk::prepared(old(self).state(), final(self).state(), max, out),
    { self.stream.prepare(max) }

    pub fn complete(&mut self, t: &Ticket, count: usize) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).same_owner(old(self)), final(self).same_audit(old(self)),
            StreamChunk::completed_write(old(self).state(), final(self).state(), t, count, ok),
    { self.stream.complete(t, count) }

    pub fn cancel(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).same_owner(old(self)), final(self).same_audit(old(self)),
            StreamChunk::cancelled(old(self).state(), final(self).state()),
    { self.stream.cancel() }

    pub fn fail_log(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).same_owner(old(self)), final(self).same_audit(old(self)),
            StreamChunk::log_failed(old(self).state(), final(self).state()),
    { self.stream.fail_log() }

    pub fn acknowledge_receipt(&mut self, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding, direction: u8, receipt: &crate::audit_receipt::AuditReceipt) -> (ok: bool)
        requires old(self).valid(), authority.valid(), receipt.valid(),
        ensures final(self).valid(), final(self).same_owner(old(self)),
            StreamChunk::receipt_acknowledged(old(self).state(), final(self).state(), authority, journal, direction, receipt, ok),
            ok ==> final(self).audited_for(authority, journal) && final(self).receipt() == Some(*receipt)
                && final(self).audit_direction() == direction,
            !ok ==> final(self).same_audit(old(self)),
    {
        let ok = self.stream.acknowledge_receipt(authority, journal, direction, receipt);
        if ok {
            self.audit_session = Some(receipt.session_id());
            self.audit_tenant = authority.tenant_id();
            self.audit_direction = direction;
            self.audit_durable = receipt.is_durable();
            self.audit = Ghost(Some(*receipt));
        }
        ok
    }
}
}
