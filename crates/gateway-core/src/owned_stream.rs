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
pub struct OwnedStream { key: RequestKey, stream: StreamChunk, read_buffer: Vec<u8>, audit_session: Option<u128>, audit_tenant: u64, audit_direction: u8, audit: Ghost<Option<crate::journal::DurableFrame>> }
impl OwnedStream {
    pub closed spec fn audit_session(&self) -> Option<u128> { self.audit_session }
    pub closed spec fn audit_tenant(&self) -> u64 { self.audit_tenant }
    pub fn recorded_direction(&self) -> (out: u8)
        ensures out == self.audit_direction(),
    { self.audit_direction }
    pub closed spec fn audit_direction(&self) -> u8 { self.audit_direction }
    pub closed spec fn receipt(&self) -> Option<crate::journal::DurableFrame> { self.audit@ }
    pub closed spec fn audit_valid(&self) -> bool {
        match self.audit_session {
            None => self.audit@.is_none(),
            Some(session) => self.audit@.is_some() && {
                let r = self.audit@.unwrap();
                r.valid() && r.session() == session && self.audit_direction <= 1
                && self.state().body().len() <= 1048576
                && r.record() == crate::framing::encoding(crate::framing::Header {
                    payload: self.state().body().len() as u32, tenant: self.audit_tenant,
                    request: self.state().owner(), chunk: self.state().chunk(), direction: self.audit_direction })
                    + self.state().body() + r.checksum()
            },
        }
    }
    pub open spec fn audited_for(&self, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding) -> bool {
        self.audit_session().is_some() && self.audit_session() == journal.session() && self.audit_tenant() == authority.tenant()
            && self.state().owner() == authority.request()
    }
    pub fn is_audited_for(&self, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding) -> (ok: bool)
        requires self.valid(), authority.valid(),
        ensures ok == self.audited_for(authority, journal),
    {
        self.audit_session.is_some() && journal.matches_session(self.audit_session)
            && self.audit_tenant == authority.tenant_id() && self.stream.owner_id() == authority.request_id()
    }
    pub proof fn receipt_evidence(&self)
        requires self.valid(), self.audit_session().is_some(),
        ensures self.receipt().is_some(), self.receipt().unwrap().valid(), self.state().body().len() <= 1048576,
            Some(self.receipt().unwrap().session()) == self.audit_session(),
            self.receipt().unwrap().record() == crate::framing::encoding(crate::framing::Header {
                payload: self.state().body().len() as u32, tenant: self.audit_tenant(),
                request: self.state().owner(), chunk: self.state().chunk(), direction: self.audit_direction() })
                + self.state().body() + self.receipt().unwrap().checksum(),
    {}
    pub closed spec fn state(&self) -> StreamChunk { self.stream }
    pub closed spec fn read_bytes(&self) -> Seq<u8> { self.read_buffer@ }
    pub closed spec fn key(&self) -> RequestKey { self.key }
    pub closed spec fn valid(&self) -> bool {
        self.audit_valid() && self.key.stream_claimed() && self.stream.valid() && self.stream.owner() == self.key.id()
            && self.stream.body().len() + self.read_buffer.len() <= self.stream.capacity()
            && (self.read_buffer.len() > 0 ==> self.stream.body().len() == 0)
    }

    pub proof fn payload_bound(&self)
        requires self.valid(),
        ensures self.state().body().len() + self.read_bytes().len() <= self.state().capacity(),
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
                let owned = OwnedStream { key, stream, read_buffer: Vec::new(), audit_session: None, audit_tenant: 0, audit_direction: 0, audit: Ghost(None) };
                proof {
                    registry.layout(); registry.ownership_facts(&owned.key());
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

    pub fn is_live(&self, registry: &ResourceAdmission) -> (out: bool)
        requires self.valid(), registry.valid(),
        ensures out == (registry.owns(&self.key()) && !self.state().closed()),
    { registry.capacity(&self.key).is_some() && !self.stream.is_closed() }

    pub fn owner_id(&self) -> (out: u64)
        requires self.valid(),
        ensures out == self.key().id(), out == self.state().owner(),
    { self.stream.owner_id() }

    pub fn retire(mut self, registry: &mut ResourceAdmission) -> (ok: bool)
        requires self.valid(), old(registry).valid(),
        ensures final(registry).valid(),
            final(registry).limit() == old(registry).limit(),
            final(registry).per_request() == old(registry).per_request(),
            final(registry).next_id() == old(registry).next_id(),
            ok == old(registry).owns(&self.key()),
            ok ==> (forall|streams: Seq<Option<StreamChunk>>|
                #[trigger] crate::resource::streams_bound(old(registry).entries(), streams, old(registry).per_request())
                ==> crate::resource::streams_bound(final(registry).entries(),
                    streams.update(self.key().slot() as int, None), final(registry).per_request())),
            ok ==> (forall|owners: Seq<Option<OwnedStream>>|
                #[trigger] crate::owned_accounting::owners_match(old(registry).entries(), owners, old(registry).per_request())
                ==> crate::owned_accounting::owners_match(final(registry).entries(),
                    owners.update(self.key().slot() as int, None), final(registry).per_request())),
            ok ==> !final(registry).owns(&self.key())
                && crate::resource::occupied(final(registry).entries()) + 1
                    == crate::resource::occupied(old(registry).entries()),
            !ok ==> *final(registry) == *old(registry),
    {
        self.read_buffer = Vec::new();
        let ok = registry.release_stream(&self.key, self.stream);
        ok
    }

    pub fn begin_read(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            final(self).state().owner() == old(self).state().owner(),
            final(self).state().capacity() == old(self).state().capacity(),
            final(self).state().completed() == old(self).state().completed(),
            final(self).state().strict() == old(self).state().strict(),
            final(self).state().failed() == old(self).state().failed(),
            final(self).state().closed() == old(self).state().closed(),
            final(self).state().generation() == old(self).state().generation(),
            final(self).state().input() == old(self).state().input(),
            final(self).state().chunk() == old(self).state().chunk(),
            ok == (old(self).read_bytes().len() == 0 && old(self).state().capacity() > 0
                && !old(self).state().closed() && !old(self).state().pending()
                && old(self).state().position() == old(self).state().body().len()),
            ok ==> final(self).state().body().len() == 0
                && final(self).read_bytes().len() == old(self).state().capacity(),
            !ok ==> *final(self) == *old(self),
    {
        if !self.read_buffer.is_empty() || self.stream.capacity_bytes() == 0 { return false; }
        if !self.stream.discard_completed() { return false; }
        self.audit_session = None; self.audit = Ghost(None);
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
            final(out)@.len() == out@.len() ==> final(self).valid(),
    { self.read_buffer.as_mut_slice() }

    pub fn finish_read(&mut self, length: usize) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            final(self).state().owner() == old(self).state().owner(),
            final(self).state().capacity() == old(self).state().capacity(),
            final(self).state().completed() == old(self).state().completed(),
            final(self).state().strict() == old(self).state().strict(),
            final(self).state().failed() == old(self).state().failed(),
            final(self).state().closed() == old(self).state().closed(),
            final(self).state().generation() == old(self).state().generation(),
            ok == (old(self).read_bytes().len() > 0 && length <= old(self).read_bytes().len()
                && (length == 0 || (!old(self).state().closed() && !old(self).state().pending()
                    && old(self).state().position() == old(self).state().body().len()
                    && length <= old(self).state().capacity() && old(self).state().chunk() < u64::MAX))),
            ok ==> final(self).read_bytes().len() == 0
                && final(self).state().body() == old(self).read_bytes().subrange(0, length as int),
            ok && length > 0 ==> final(self).state().chunk() == old(self).state().chunk() + 1
                && final(self).state().input() == old(self).state().input()
                    + old(self).read_bytes().subrange(0, length as int),
            !ok || length == 0 ==> final(self).state() == old(self).state(),
    {
        if self.read_buffer.is_empty() || length > self.read_buffer.len() { return false; }
        let mut bytes = Vec::new();
        core::mem::swap(&mut bytes, &mut self.read_buffer);
        bytes.truncate(length);
        if length == 0 { return true; }
        self.audit_session = None; self.audit = Ghost(None);
        self.stream.advance(bytes).is_some()
    }

    pub fn advance(&mut self, bytes: Vec<u8>) -> (out: Option<u64>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            final(self).read_bytes() == old(self).read_bytes(), final(self).state().valid(), final(self).state().owner() == old(self).state().owner(),
            final(self).state().strict() == old(self).state().strict(), final(self).state().failed() == old(self).state().failed(),
            final(self).state().capacity() == old(self).state().capacity(),
            final(self).state().generation() == old(self).state().generation(),
            final(self).state().completed() == old(self).state().completed(),
            match out {
                Some(chunk) => chunk == final(self).state().chunk() && chunk == old(self).state().chunk() + 1
                    && old(self).state().position() == old(self).state().body().len()
                    && !old(self).state().pending() && !old(self).state().closed()
                    && final(self).state().body() == bytes@ && final(self).state().input() == old(self).state().input() + bytes@
                    && final(self).state().position() == 0 && final(self).state().end() == 0
                    && final(self).state().durable() == 0 && !final(self).state().pending() && !final(self).state().closed(),
                None => final(self).state() == old(self).state() && (old(self).state().closed() || old(self).state().pending()
                    || old(self).state().position() != old(self).state().body().len()
                    || bytes.len() > old(self).state().capacity() || old(self).state().chunk() == u64::MAX
                    || old(self).read_bytes().len() != 0),
            },
    {
        if !self.read_buffer.is_empty() { return None; }
        let out = self.stream.advance(bytes);
        if out.is_some() { self.audit_session = None; self.audit = Ghost(None); }
        proof { self.stream.payload_within_capacity(); }
        out
    }

    pub fn discard_completed(&mut self) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            final(self).read_bytes() == old(self).read_bytes(), final(self).state().valid(),
            final(self).state().owner() == old(self).state().owner(), final(self).state().capacity() == old(self).state().capacity(),
            final(self).state().chunk() == old(self).state().chunk(), final(self).state().generation() == old(self).state().generation(),
            final(self).state().strict() == old(self).state().strict(), final(self).state().failed() == old(self).state().failed(),
            final(self).state().closed() == old(self).state().closed(), final(self).state().pending() == old(self).state().pending(),
            final(self).state().input() == old(self).state().input(), final(self).state().completed() == old(self).state().completed(),
            ok ==> !old(self).state().closed() && !old(self).state().pending()
                && old(self).state().position() == old(self).state().body().len()
                && final(self).state().body().len() == 0 && final(self).state().position() == 0
                && final(self).state().end() == 0 && final(self).state().durable() == 0,
            ok == (!old(self).state().closed() && !old(self).state().pending() && old(self).state().position() == old(self).state().body().len()),
            !ok ==> final(self).state() == old(self).state(),
    {
        let ok = self.stream.discard_completed();
        if ok { self.audit_session = None; self.audit = Ghost(None); }
        ok
    }

    pub fn prepare(&mut self, max: usize) -> (out: Option<Ticket>)
        requires old(self).valid(),
        ensures final(self).audit_session() == old(self).audit_session(),
            final(self).audit_tenant() == old(self).audit_tenant(), final(self).audit_direction() == old(self).audit_direction(), final(self).receipt() == old(self).receipt(),
            final(self).valid(), final(self).key() == old(self).key(),
            final(self).read_bytes() == old(self).read_bytes(), final(self).state().valid(), final(self).state().body() == old(self).state().body(),
            final(self).state().chunk() == old(self).state().chunk(), final(self).state().capacity() == old(self).state().capacity(),
            final(self).state().input() == old(self).state().input(),
            final(self).state().completed() == old(self).state().completed(),
            final(self).state().position() == old(self).state().position(), final(self).state().owner() == old(self).state().owner(),
            final(self).state().strict() == old(self).state().strict(),
            final(self).state().durable() == old(self).state().durable(),
            final(self).state().closed() == old(self).state().closed(), final(self).state().failed() == old(self).state().failed(),
            match out {
                Some(t) => final(self).state().matches(&t) && !old(self).state().pending() && !old(self).state().closed()
                    && final(self).state().end() > final(self).state().position()
                    && final(self).state().end() - final(self).state().position() <= max
                    && final(self).state().generation() == old(self).state().generation() + 1,
                None => final(self).state() == old(self).state() && (old(self).state().closed() || old(self).state().pending()
                    || max == 0 || old(self).state().generation() == u64::MAX
                    || old(self).state().position() == (if old(self).state().strict() { old(self).state().durable() } else { old(self).state().body().len() })),
            },
    { self.stream.prepare(max) }

    pub fn complete(&mut self, t: &Ticket, count: usize) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            final(self).read_bytes() == old(self).read_bytes(), final(self).state().valid(), final(self).state().body() == old(self).state().body(),
            final(self).state().chunk() == old(self).state().chunk(), final(self).state().capacity() == old(self).state().capacity(),
            final(self).state().input() == old(self).state().input(),
            final(self).state().owner() == old(self).state().owner(), final(self).state().strict() == old(self).state().strict(),
            final(self).state().closed() == old(self).state().closed(), final(self).state().failed() == old(self).state().failed(),
            final(self).state().durable() == old(self).state().durable(),
            final(self).state().generation() == old(self).state().generation(),
            ok ==> old(self).state().matches(t) && !final(self).state().pending()
                && count <= old(self).state().end() - old(self).state().position()
                && final(self).state().position() == old(self).state().position() + count
                && final(self).state().completed() == old(self).state().completed()
                    + old(self).state().body().subrange(old(self).state().position() as int, (old(self).state().position() + count) as int),
            ok == (old(self).state().matches(t) && count <= old(self).state().end() - old(self).state().position()),
            !ok ==> final(self).state() == old(self).state(),
    { self.stream.complete(t, count) }

    pub fn cancel(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            final(self).read_bytes() == old(self).read_bytes(), final(self).state().valid(), final(self).state().closed(),
            final(self).state().body() == old(self).state().body(),
            final(self).state().chunk() == old(self).state().chunk(), final(self).state().capacity() == old(self).state().capacity(),
            final(self).state().input() == old(self).state().input(),
            final(self).state().completed() == old(self).state().completed(), final(self).state().owner() == old(self).state().owner(),
            final(self).state().position() == old(self).state().position(), final(self).state().strict() == old(self).state().strict(),
            final(self).state().pending() == old(self).state().pending(), final(self).state().end() == old(self).state().end(),
            final(self).state().durable() == old(self).state().durable(), final(self).state().failed() == old(self).state().failed(),
            final(self).state().generation() == old(self).state().generation(),
    { self.stream.cancel() }

    pub fn fail_log(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            final(self).read_bytes() == old(self).read_bytes(), final(self).state().valid(), final(self).state().failed(),
            final(self).state().body() == old(self).state().body(),
            final(self).state().chunk() == old(self).state().chunk(), final(self).state().capacity() == old(self).state().capacity(),
            final(self).state().input() == old(self).state().input(),
            final(self).state().completed() == old(self).state().completed(), final(self).state().owner() == old(self).state().owner(),
            final(self).state().position() == old(self).state().position(), final(self).state().strict() == old(self).state().strict(),
            final(self).state().pending() == old(self).state().pending(), final(self).state().end() == old(self).state().end(),
            final(self).state().durable() == old(self).state().durable(),
            final(self).state().generation() == old(self).state().generation(),
            old(self).state().strict() ==> final(self).state().closed(),
            !old(self).state().strict() ==> final(self).state().closed() == old(self).state().closed(),
    { self.stream.fail_log() }

    pub fn acknowledge_receipt(&mut self, authority: &AuthorizedRequest, journal: &crate::journal_binding::JournalBinding, direction: u8, receipt: &crate::journal::DurableFrame) -> (ok: bool)
        requires old(self).valid(), authority.valid(), receipt.valid(),
        ensures final(self).valid(), final(self).key() == old(self).key(),
            final(self).read_bytes() == old(self).read_bytes(), final(self).state().valid(),
            ok == (journal.session() == Some(receipt.session()) && !old(self).state().closed() && !old(self).state().failed() && old(self).state().owner() != 0
                && old(self).state().owner() == authority.request() && old(self).state().body().len() <= 1048576
                && direction <= 1 && receipt.record() == crate::framing::encoding(crate::framing::Header {
                    payload: old(self).state().body().len() as u32, tenant: authority.tenant(),
                    request: old(self).state().owner(), chunk: old(self).state().chunk(), direction })
                    + old(self).state().body() + receipt.checksum()),
            final(self).state().body() == old(self).state().body(), final(self).state().owner() == old(self).state().owner(),
            final(self).state().chunk() == old(self).state().chunk(), final(self).state().input() == old(self).state().input(),
            final(self).state().completed() == old(self).state().completed(), final(self).state().position() == old(self).state().position(),
            final(self).state().end() == old(self).state().end(), final(self).state().pending() == old(self).state().pending(),
            final(self).state().generation() == old(self).state().generation(), final(self).state().strict() == old(self).state().strict(),
            final(self).state().closed() == old(self).state().closed(), final(self).state().failed() == old(self).state().failed(),
            final(self).state().capacity() == old(self).state().capacity(),
            final(self).state().completed() == old(self).state().completed(),
            final(self).state().strict() == old(self).state().strict(),
            final(self).state().failed() == old(self).state().failed(),
            final(self).state().closed() == old(self).state().closed(),
            final(self).state().generation() == old(self).state().generation(),
            ok ==> final(self).audited_for(authority, journal) && final(self).receipt() == Some(*receipt),
            ok ==> final(self).state().durable() == old(self).state().body().len()
                && receipt.acknowledged() == receipt.prefix()
                    + crate::framing::encoding(crate::framing::Header { payload: old(self).state().body().len() as u32,
                        tenant: authority.tenant(), request: old(self).state().owner(),
                        chunk: old(self).state().chunk(), direction })
                    + old(self).state().body() + receipt.checksum(),
            !ok ==> final(self).state() == old(self).state(),
    {
        let ok = self.stream.acknowledge_receipt(authority, journal, direction, receipt);
        if ok {
            self.audit_session = Some(receipt.session_id());
            self.audit_tenant = authority.tenant_id();
            self.audit_direction = direction;
            self.audit = Ghost(Some(*receipt));
        }
        ok
    }
}
}
