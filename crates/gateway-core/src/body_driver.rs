//! Production body-copy loop. The adapter performs only primitive effects;
//! ordering, authorization, receipt checks and exact successful byte transfer live here.
use vstd::prelude::*;
use crate::{body_copy::{Action, BodyCopy, Failure, Delivery}, request_context::{Context, TransferIdentity, TransferKey},
    owned_stream::OwnedStream, journal_binding::JournalBinding,
    framing::Header, audit_receipt::AuditReceipt, policy::Route};

verus! {
pub ghost enum Call {
    Read(Seq<u8>, Option<usize>), Audit(Header, Seq<u8>),
    Write(Seq<u8>, Option<usize>, u64, Route, u8), Flush(bool),
}
pub open spec fn read_bytes(call: Call) -> Seq<u8> {
    match call { Call::Read(bytes, Some(_)) => bytes, _ => Seq::empty() }
}
pub open spec fn written_bytes(call: Call) -> Seq<u8> {
    match call { Call::Write(bytes, Some(n), _, _, _) => bytes.take(n as int), _ => Seq::empty() }
}
pub open spec fn received(calls: Seq<Call>) -> Seq<u8>
    decreases calls.len(),
{
    if calls.len() == 0 { Seq::empty() } else { received(calls.drop_last()) + read_bytes(calls.last()) }
}
pub open spec fn written(calls: Seq<Call>) -> Seq<u8>
    decreases calls.len(),
{
    if calls.len() == 0 { Seq::empty() } else { written(calls.drop_last()) + written_bytes(calls.last()) }
}
pub open spec fn writes_succeeded(calls: Seq<Call>) -> bool {
    forall|i: int| 0 <= i < calls.len() ==> match #[trigger] calls[i] {
        Call::Write(_, count, _, _, _) => count.is_some(), _ => true,
    }
}
pub proof fn append_bytes(calls: Seq<Call>, call: Call)
    ensures written(calls.push(call)) == written(calls) + written_bytes(call),
        writes_succeeded(calls.push(call)) == (writes_succeeded(calls) && match call { Call::Write(_, n, _, _, _) => n.is_some(), _ => true }),
{
    assert(calls.push(call).drop_last() =~= calls);
    if writes_succeeded(calls.push(call)) {
        assert forall|i: int| 0 <= i < calls.len() implies match #[trigger] calls[i] { Call::Write(_, n, _, _, _) => n.is_some(), _ => true } by {
            assert(calls.push(call)[i] == calls[i]);
        }
    }
}
pub open spec fn accepted(calls: Seq<Call>) -> nat
    decreases calls.len(),
{
    if calls.len() == 0 { 0 } else { accepted(calls.drop_last()) + match calls.last() {
        Call::Write(bytes, Some(n), _, _, _) => if n <= bytes.len() { n as nat } else { 0 }, _ => 0,
    } }
}
pub open spec fn call_belongs(call: Call, request: u64, route: Route, direction: u8) -> bool {
    match call {
        Call::Write(_, _, r, grant, d) => r == request && grant == route && d == direction,
        Call::Audit(h, _) => h.request == request && h.tenant == route.tenant && h.kind == direction,
        _ => true,
    }
}
pub open spec fn belongs(calls: Seq<Call>, request: u64, route: Route, direction: u8) -> bool {
    forall|i: int| 0 <= i < calls.len() ==> call_belongs(#[trigger] calls[i], request, route, direction)
}
proof fn append_call(before: Seq<Call>, trace: Seq<Call>, call: Call, request: u64, route: Route, direction: u8)
    requires belongs(trace, request, route, direction), call_belongs(call, request, route, direction),
    ensures received(trace.push(call)) == received(trace) + read_bytes(call),
        written(trace.push(call)) == written(trace) + written_bytes(call),
        belongs(trace.push(call), request, route, direction), before + trace.push(call) == (before + trace).push(call),
        accepted(trace.push(call)) == accepted(trace) + match call {
            Call::Write(bytes, Some(n), _, _, _) => if n <= bytes.len() { n as nat } else { 0 }, _ => 0,
        },
        accepted((before + trace).push(call)) == accepted(before + trace) + match call {
            Call::Write(bytes, Some(n), _, _, _) => if n <= bytes.len() { n as nat } else { 0 }, _ => 0,
        },
{ assert(trace.push(call).drop_last() =~= trace);
  assert(before + trace.push(call) =~= (before + trace).push(call));
  assert((before + trace).push(call).drop_last() =~= before + trace); }

/// Read/Write return the actual result. A returned write count is within the
/// supplied slice, as required by Rust's Write contract. Receipt truth and
/// physical reader/writer/journal selection remain adapter obligations.
pub trait Effects {
    spec fn valid(&self) -> bool;
    open spec fn anchor(&self) -> Seq<u8> { Seq::empty() }
    spec fn calls(&self) -> Seq<Call>;
    fn read(&mut self, buffer: &mut [u8]) -> (out: Option<usize>)
        requires old(self).valid(),
        ensures final(self).anchor() == old(self).anchor(), final(self).valid(), final(buffer)@.len() == old(buffer)@.len(),
            out.is_some() ==> out.unwrap() <= old(buffer).len(),
            final(self).calls() == old(self).calls().push(Call::Read(match out { Some(n) => final(buffer)@.take(n as int), None => Seq::empty() }, out));
    fn session(&self) -> u128 requires self.valid();
    fn audit(&mut self, header: Header, bytes: &[u8]) -> (out: Option<AuditReceipt>)
        requires old(self).valid(), crate::framing::valid(header), header.payload == bytes.len(),
        ensures final(self).anchor() == old(self).anchor(), final(self).valid(), out.is_some() ==> out.unwrap().valid(),
            final(self).calls() == old(self).calls().push(Call::Audit(header, bytes@));
    fn write(&mut self, context: &Context, delivery: &Delivery, direction: u8) -> (out: Option<usize>)
        requires old(self).valid(), context.valid(), delivery.permits(&context.authority_value(), direction),
        ensures final(self).anchor() == old(self).anchor(), final(self).valid(), out.is_some() ==> out.unwrap() <= delivery.bytes_value().len(),
            final(self).calls() == old(self).calls().push(Call::Write(delivery.bytes_value(), out, context.authority_value().request(), context.authority_value().binding(), direction));
    fn flush(&mut self) -> (out: bool)
        requires old(self).valid(),
        ensures final(self).anchor() == old(self).anchor(), final(self).valid(), final(self).calls() == old(self).calls().push(Call::Flush(out));
}

/// A completion can only be produced by this verified production loop.
pub ghost struct CopySummary { pub identity: TransferIdentity, pub direction: u8, pub accepted: u64, pub calls: Seq<Call>, pub wire: Option<Seq<u8>> }
impl CopySummary {
    pub open spec fn valid(&self) -> bool {
        self.direction <= 1 && belongs(self.calls, self.identity.request, self.identity.route, self.direction)
            && (self.wire.is_some() ==> crate::http1_chunked::chunks_ok(self.wire.unwrap(), received(self.calls)))
            && self.accepted == written(self.calls).len() && writes_succeeded(self.calls) && accepted(self.calls) == self.accepted && received(self.calls) == written(self.calls)
    }
    pub open spec fn matches(&self, identity: TransferIdentity, direction: u8) -> bool {
        self.valid() && self.identity == identity && self.direction == direction
    }
}
pub struct Completed { copy: BodyCopy, key: TransferKey, trace: Ghost<Seq<Call>> }
impl Completed {
    pub closed spec fn copy(&self) -> BodyCopy { self.copy }
    pub closed spec fn identity(&self) -> TransferIdentity { self.key.identity() }
    pub open spec fn request(&self) -> u64 { self.identity().request }
    pub open spec fn route(&self) -> Route { self.identity().route }
    pub closed spec fn trace(&self) -> Seq<Call> { self.trace@ }
    pub open spec fn summary(&self) -> CopySummary {
        CopySummary { identity: self.identity(), direction: self.copy().direction(), accepted: self.copy().accepted(), calls: self.trace(), wire: None }
    }
    pub closed spec fn valid(&self) -> bool { self.copy.is_done() && self.summary().valid() }
    pub open spec fn accepted(&self) -> u64 { self.copy().accepted() }
    pub open spec fn is_done(&self) -> bool { self.copy().is_done() }
    pub proof fn evidence(&self)
        requires self.valid(), ensures self.summary().valid(), self.is_done(),
    {}
    pub fn accepted_bytes(&self) -> (out: u64) ensures out == self.accepted(), { self.copy.accepted_bytes() }
    pub fn audit_gap(&self) -> bool { self.copy.audit_gap() }
    pub fn is_finished(&self) -> (out: bool) ensures out == self.is_done(), { self.copy.is_finished() }
    pub fn matches(&self, key: &TransferKey, direction: u8) -> (out: bool)
        requires self.valid(), ensures out == self.summary().matches(key.identity(), direction),
    { self.key.same(key) && self.copy.direction_id() == direction }
    pub fn body_copy(&self) -> (out: &BodyCopy)
        requires self.valid(), ensures *out == self.copy(), out.is_done(),
    { &self.copy }
    pub fn into_copy(self) -> (out: BodyCopy)
        requires self.valid(), ensures out == self.copy(), out.is_done(),
    { self.copy }
}

/// May run indefinitely for an infinite source or a blocked external call.
/// Every normal successful return is a clean EOF with exactly the accepted
/// effect count, under one request's authorization for the entire loop. The
/// concatenated accepted write prefixes equal the returned read bytes in order.
#[verifier::exec_allows_no_decreases_clause]
#[verifier::rlimit(100)]
pub fn copy<E: Effects>(context: &Context, expected: &TransferKey, owner: &mut OwnedStream, journal: &mut JournalBinding,
    effects: &mut E, direction: u8) -> (out: Result<Completed, Failure>)
    requires context.valid(), old(owner).valid(), old(effects).valid(),
    ensures final(effects).anchor() == old(effects).anchor(), final(effects).valid(), final(owner).valid(), final(owner).key() == old(owner).key(),
        context.transfer_identity() != expected.identity() ==> final(effects).calls() == old(effects).calls()
            && match out { Err(failure) => failure == Failure::InvalidState, _ => false },
        match out {
            Ok(done) => done.valid() && done.identity() == expected.identity() && done.identity() == context.transfer_identity() && done.request() == context.authority_value().request()
                && done.route() == context.authority_value().binding() && done.copy().direction() == direction
                && done.copy().valid(final(owner))
                && final(effects).calls() == old(effects).calls() + done.trace()
                && done.copy().accepted() == accepted(final(effects).calls()) - accepted(old(effects).calls()),
            Err(_) => final(owner).state().closed(),
        },
{
    let key = context.transfer_key();
    if !key.same(expected) { owner.cancel(); return Err(Failure::InvalidState); }
    let authority = context.authority();
    proof { context.transfer_evidence(); }
    if owner.owner_id() != authority.request_id() { owner.cancel(); return Err(Failure::InvalidState); }
    let mut copy = match BodyCopy::begin(owner, direction) {
        Some(copy) => copy, None => { owner.cancel(); return Err(Failure::InvalidState); }
    };
    let ghost base = effects.calls();
    let ghost mut trace = Seq::<Call>::empty();
    let ghost initial = owner.state().input();
    proof { authority.binding_tenant(); copy.state_evidence(owner); owner.state().data_partition(); }
    loop
        invariant copy.start() == initial.len(), effects.anchor() == old(effects).anchor(), effects.valid(), context.valid(), key.identity() == expected.identity(), key.identity() == context.transfer_identity(),
            key.identity().request == authority.request(), key.identity().route == authority.binding(), authority.valid(), authority.tenant() == authority.binding().tenant, *authority == context.authority_value(), copy.valid(owner), copy.direction() == direction,
            owner.key() == old(owner).key(), owner.key().id() == authority.request(),
            copy.needs_read() || copy.filled() || copy.audited() || copy.needs_flush() || copy.is_done() || copy.failure().is_some(),
            effects.calls() == base + trace, base == old(effects).calls(),
            belongs(trace, authority.request(), authority.binding(), direction),
            copy.failure().is_none() ==> writes_succeeded(trace),
            copy.failure().is_none() ==> owner.state().input() == initial + received(trace)
                && owner.state().completed() == initial + written(trace),
            copy.failure().is_none() ==> accepted(trace) == copy.accepted()
                && accepted(effects.calls()) == accepted(base) + copy.accepted(),
    {
        proof { copy.state_evidence(owner); copy.stable_phases(); owner.owner_evidence(); }
        match copy.next() {
            Action::Read => {
                if copy.begin_read(owner) {
                    let buffer = copy.read_buffer(owner);
                    let length = effects.read(buffer);
                    let ghost bytes = match length { Some(n) => buffer@.take(n as int), None => Seq::empty() };
                    let ghost call = Call::Read(bytes, length);
                    proof { append_call(base, trace, call, authority.request(), authority.binding(), direction); }
                    proof { trace = trace.push(call); }
                    copy.finish_read(owner, length);
                    proof {
                        assert(copy.failure().is_none() ==> owner.state().input() =~= initial + received(trace));
                        assert(copy.failure().is_none() ==> owner.state().completed() =~= initial + written(trace));
                    }
                }
            }
            Action::Audit => {
                let session = effects.session();
                if let Some((header, bytes)) = copy.audit_record(owner, authority, journal, session) {
                    let ghost call = Call::Audit(header, bytes@);
                    let receipt = effects.audit(header, bytes);
                    proof { append_call(base, trace, call, authority.request(), authority.binding(), direction); }
                    proof { trace = trace.push(call); }
                    copy.finish_audit(owner, authority, journal, receipt.as_ref());
                }
            }
            Action::Write => {
                if let Some(delivery) = context.write_bytes(&mut copy, owner, journal) {
                    let ghost given = delivery.bytes_value();
                    let count = effects.write(context, &delivery, direction);
                    let ghost call = Call::Write(given, count, authority.request(), authority.binding(), direction);
                    proof { append_call(base, trace, call, authority.request(), authority.binding(), direction); }
                    proof { trace = trace.push(call); }
                    let write = delivery.into_write();
                    proof {
                        copy.state_evidence(owner); owner.state().payload_within_capacity();
                        assert(given == owner.state().body().subrange(owner.state().position() as int, owner.state().end() as int));
                        if count.is_some() {
                            assert(given.take(count.unwrap() as int) =~= owner.state().body().subrange(owner.state().position() as int, (owner.state().position() + count.unwrap()) as int));
                        }
                    }
                    copy.finish_write(owner, &write, count);
                    proof {
                        assert(copy.failure().is_none() ==> owner.state().input() =~= initial + received(trace));
                        assert(copy.failure().is_none() ==> owner.state().completed() =~= initial + written(trace));
                    }
                }
            }
            Action::Flush => {
                let ok = effects.flush();
                proof { append_call(base, trace, Call::Flush(ok), authority.request(), authority.binding(), direction); }
                proof { trace = trace.push(Call::Flush(ok)); }
                copy.finish_flush(owner, ok);
            }
            Action::Done => {
                proof {
                    owner.state().data_partition();
                    assert(received(trace).len() == written(trace).len());
                    assert forall|i: int| 0 <= i < received(trace).len() implies received(trace)[i] == written(trace)[i] by {
                        assert((initial + received(trace))[initial.len() + i] == (initial + written(trace))[initial.len() + i]);
                    }
                    assert(received(trace) =~= written(trace));
                }
                return Ok(Completed { copy, key, trace: Ghost(trace) });
            }
            Action::Failed(failure) => { proof { copy.failure_closes(owner); } return Err(failure); },
        }
    }
}
}
