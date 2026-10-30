//! Production body-copy loop. The adapter performs only primitive effects;
//! ordering, authorization, receipt checks and successful byte counts live here.
use vstd::prelude::*;
use crate::{body_copy::{Action, BodyCopy, Failure, Delivery}, request_context::Context,
    owned_stream::OwnedStream, journal_binding::JournalBinding,
    framing::Header, audit_receipt::AuditReceipt, policy::Route};

verus! {
pub ghost enum Call {
    Read(Option<usize>), Audit(Header, Seq<u8>),
    Write(Seq<u8>, Option<usize>, u64, Route, u8), Flush(bool),
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
    ensures belongs(trace.push(call), request, route, direction), before + trace.push(call) == (before + trace).push(call),
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
    spec fn calls(&self) -> Seq<Call>;
    fn read(&mut self, buffer: &mut [u8]) -> (out: Option<usize>)
        ensures final(buffer)@.len() == old(buffer)@.len(),
            out.is_some() ==> out.unwrap() <= old(buffer).len(),
            final(self).calls() == old(self).calls().push(Call::Read(out));
    fn session(&self) -> u128;
    fn audit(&mut self, header: Header, bytes: &[u8]) -> (out: Option<AuditReceipt>)
        requires crate::framing::valid(header), header.payload == bytes.len(),
        ensures out.is_some() ==> out.unwrap().valid(),
            final(self).calls() == old(self).calls().push(Call::Audit(header, bytes@));
    fn write(&mut self, context: &Context, delivery: &Delivery, direction: u8) -> (out: Option<usize>)
        requires context.valid(), delivery.permits(&context.authority_value(), direction),
        ensures out.is_some() ==> out.unwrap() <= delivery.bytes_value().len(),
            final(self).calls() == old(self).calls().push(Call::Write(delivery.bytes_value(), out, context.authority_value().request(), context.authority_value().binding(), direction));
    fn flush(&mut self) -> (out: bool)
        ensures final(self).calls() == old(self).calls().push(Call::Flush(out));
}

/// A completion can only be produced by this verified production loop.
pub struct Completed { copy: BodyCopy, request: u64, route: Route, trace: Ghost<Seq<Call>> }
impl Completed {
    pub closed spec fn copy(&self) -> BodyCopy { self.copy }
    pub closed spec fn request(&self) -> u64 { self.request }
    pub closed spec fn route(&self) -> Route { self.route }
    pub closed spec fn trace(&self) -> Seq<Call> { self.trace@ }
    pub closed spec fn valid(&self) -> bool {
        self.copy.is_done() && belongs(self.trace@, self.request, self.route, self.copy.direction())
            && accepted(self.trace@) == self.copy.accepted()
    }
    pub fn into_copy(self) -> (out: BodyCopy)
        requires self.valid(), ensures out == self.copy(), out.is_done(),
    { self.copy }
}

/// May run indefinitely for an infinite source or a blocked external call.
/// Every normal successful return is a clean EOF with exactly the accepted
/// effect count, under one request's authorization for the entire loop.
#[verifier::exec_allows_no_decreases_clause]
#[verifier::rlimit(100)]
pub fn copy<E: Effects>(context: &Context, owner: &mut OwnedStream, journal: &mut JournalBinding,
    effects: &mut E, direction: u8) -> (out: Result<Completed, Failure>)
    requires context.valid(), old(owner).valid(),
    ensures final(owner).valid(), final(owner).key() == old(owner).key(),
        match out {
            Ok(done) => done.valid() && done.request() == context.authority_value().request()
                && done.route() == context.authority_value().binding() && done.copy().direction() == direction
                && done.copy().valid(final(owner))
                && final(effects).calls() == old(effects).calls() + done.trace()
                && done.copy().accepted() == accepted(final(effects).calls()) - accepted(old(effects).calls()),
            Err(_) => final(owner).state().closed(),
        },
{
    let authority = context.authority();
    if owner.owner_id() != authority.request_id() { owner.cancel(); return Err(Failure::InvalidState); }
    let mut copy = match BodyCopy::begin(owner, direction) {
        Some(copy) => copy, None => { owner.cancel(); return Err(Failure::InvalidState); }
    };
    let ghost base = effects.calls();
    let ghost mut trace = Seq::<Call>::empty();
    proof { authority.binding_tenant(); }
    loop
        invariant context.valid(), authority.valid(), authority.tenant() == authority.binding().tenant, *authority == context.authority_value(), copy.valid(owner), copy.direction() == direction,
            owner.key() == old(owner).key(), owner.key().id() == authority.request(),
            copy.needs_read() || copy.filled() || copy.audited() || copy.needs_flush() || copy.is_done() || copy.failure().is_some(),
            effects.calls() == base + trace, base == old(effects).calls(),
            belongs(trace, authority.request(), authority.binding(), direction),
            copy.failure().is_none() ==> accepted(trace) == copy.accepted()
                && accepted(effects.calls()) == accepted(base) + copy.accepted(),
    {
        proof { copy.state_evidence(owner); copy.stable_phases(); owner.owner_evidence(); }
        match copy.next() {
            Action::Read => {
                if copy.begin_read(owner) {
                    let length = effects.read(copy.read_buffer(owner));
                    proof { append_call(base, trace, Call::Read(length), authority.request(), authority.binding(), direction); }
                    proof { trace = trace.push(Call::Read(length)); }
                    copy.finish_read(owner, length);
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
                    copy.finish_write(owner, &write, count);
                }
            }
            Action::Flush => {
                let ok = effects.flush();
                proof { append_call(base, trace, Call::Flush(ok), authority.request(), authority.binding(), direction); }
                proof { trace = trace.push(Call::Flush(ok)); }
                copy.finish_flush(owner, ok);
            }
            Action::Done => {
                return Ok(Completed { copy, request: authority.request_id(), route: authority.route(), trace: Ghost(trace) });
            }
            Action::Failed(failure) => { proof { copy.failure_closes(owner); } return Err(failure); },
        }
    }
}
}
