//! The production composition of authorization-gated body copying and HTTP
//! chunk framing. Only primitive reader, audit and socket effects are external.
use vstd::prelude::*;
use crate::{body_driver::{self, Call, Completed, Effects}, body_copy::{Delivery, Failure},
    request_context::{Context, TransferKey}, owned_stream::OwnedStream,
    journal_binding::JournalBinding, framing::Header, audit_receipt::AuditReceipt,
    sink::{ChunkWriter, FlushSink}, http1_exchange::ChunkStream};

verus! {
struct Adapter<E, S> { io: E, writer: ChunkWriter<S>, calls: Ghost<Seq<Call>> }
impl<E: Effects, S: FlushSink> Effects for Adapter<E, S> {
    closed spec fn anchor(&self) -> Seq<u8> { self.writer.base() }
    closed spec fn calls(&self) -> Seq<Call> { self.calls@ }
    closed spec fn valid(&self) -> bool {
        self.io.valid() && self.writer.inv() && !self.writer.ended()
            && (body_driver::writes_succeeded(self.calls@) ==> !self.writer.failed()
                && self.writer.body() == body_driver::written(self.calls@))
    }
    fn read(&mut self, buffer: &mut [u8]) -> (out: Option<usize>) {
        let out = self.io.read(buffer);
        proof { let call = Call::Read(match out { Some(n) => buffer@.take(n as int), None => Seq::empty() }, out); body_driver::append_bytes(self.calls@, call); self.calls@ = self.calls@.push(call); }
        out
    }
    fn session(&self) -> u128 { self.io.session() }
    fn audit(&mut self, header: Header, bytes: &[u8]) -> (out: Option<AuditReceipt>) {
        let out = self.io.audit(header, bytes);
        proof { let call = Call::Audit(header, bytes@); body_driver::append_bytes(self.calls@, call); self.calls@ = self.calls@.push(call); }
        out
    }
    fn write(&mut self, context: &Context, delivery: &Delivery, direction: u8) -> (out: Option<usize>) {
        let bytes = delivery.bytes();
        let count = if self.writer.has_failed() { None } else if bytes.len() == 0 { Some(0) }
            else { match self.writer.write(bytes) { Ok(()) => Some(bytes.len()), Err(_) => None } };
        proof { let call = Call::Write(bytes@, count, context.authority_value().request(), context.authority_value().binding(), direction); body_driver::append_bytes(self.calls@, call); self.calls@ = self.calls@.push(call); }
        proof { assert(bytes@.take(bytes.len() as int) =~= bytes@); }
        count
    }
    fn flush(&mut self) -> (out: bool) {
        let ok = self.writer.flush();
        proof { let call = Call::Flush(ok); body_driver::append_bytes(self.calls@, call); self.calls@ = self.calls@.push(call); }
        ok
    }
}

/// A sealed pair: the body completion and the stream actually used to write it.
/// Rejection can discard success, but no caller can replace either component.
pub struct Framed {
    copied: Result<Completed, Failure>, stream: ChunkStream, sent: Ghost<Seq<u8>>,
    rejection: Option<crate::exchange_driver::Failure>,
}
impl Framed {
    pub closed spec fn result(&self) -> Result<Completed, crate::exchange_driver::Failure> {
        match self.rejection { Some(e) => Err(e), None => match self.copied {
            Ok(c) => Ok(c), Err(e) => Err(if e == Failure::Log { crate::exchange_driver::Failure::Log } else { crate::exchange_driver::Failure::Io }),
        } }
    }
    pub closed spec fn stream(&self) -> ChunkStream { self.stream }
    pub closed spec fn sent(&self) -> Seq<u8> { self.sent@ }
    pub closed spec fn valid(&self) -> bool {
        self.stream.valid() && !self.stream.ended() && self.sent@.is_prefix_of(self.stream.out())
            && match self.result() { Ok(c) => c.valid() && self.stream.body() == body_driver::received(c.trace())
                && self.sent@ == self.stream.out(), Err(_) => true }
    }
    pub open spec fn summary(&self) -> Option<body_driver::CopySummary> {
        match self.result() { Ok(c) => Some(body_driver::CopySummary { wire: Some(self.sent()), ..c.summary() }), Err(_) => None }
    }
    pub proof fn evidence(&self)
        requires self.valid(),
        ensures self.summary().is_some() ==> self.summary().unwrap().valid(),
            self.result().is_ok() ==> self.result().unwrap().valid(),
    {
        if self.result().is_ok() { self.result().unwrap().evidence(); self.stream.framing_evidence(); }
    }
    pub fn failed(stream: ChunkStream, failure: crate::exchange_driver::Failure) -> (out: Self)
        requires stream.valid(), !stream.ended(), stream.out().len() == 0,
        ensures out.valid(), out.result() == Err(failure), out.sent().len() == 0,
    { Self { copied: Err(Failure::InvalidState), stream, sent: Ghost(Seq::empty()), rejection: Some(failure) } }
    pub fn body_failure(&self) -> (out: Option<Failure>)
    { match &self.copied { Ok(_) => None, Err(e) => Some(*e) } }
    pub fn reject(&mut self, failure: crate::exchange_driver::Failure)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).result() == Err(failure), final(self).sent() == old(self).sent(),
            final(self).stream() == old(self).stream(),
    { self.rejection = Some(failure); }
    pub fn into_parts(self) -> (out: (Result<Completed, crate::exchange_driver::Failure>, ChunkStream))
        requires self.valid(),
        ensures out.0 == self.result(), out.1 == self.stream(),
            self.summary().is_some() ==> self.summary().unwrap().valid(), out.1.valid(), !out.1.ended(),
            out.0.is_ok() ==> out.0.unwrap().valid() && out.1.body() == body_driver::received(out.0.unwrap().trace())
                && self.sent() == out.1.out(),
    {
        proof { self.evidence(); }
        let result = match self.rejection { Some(e) => Err(e), None => match self.copied {
            Ok(c) => Ok(c), Err(Failure::Log) => Err(crate::exchange_driver::Failure::Log), Err(_) => Err(crate::exchange_driver::Failure::Io),
        } };
        (result, self.stream)
    }
}

pub fn copy<E: Effects, S: FlushSink>(context: &Context, expected: &TransferKey, owner: &mut OwnedStream,
    journal: &mut JournalBinding, io: E, sink: S, stream: ChunkStream, direction: u8) -> (out: (Framed, S))
    requires context.valid(), old(owner).valid(), io.valid(), stream.valid(), !stream.ended(),
        stream.out().len() == 0, stream.body().len() == 0,
    ensures out.0.valid(), final(owner).valid(), final(owner).key() == old(owner).key(),
        out.1.accepted() == sink.accepted() + out.0.sent(),
        out.0.result().is_ok() ==> out.0.result().unwrap().identity() == expected.identity()
            && out.0.result().unwrap().copy().direction() == direction,
{
    proof { assert(stream.out() =~= Seq::<u8>::empty()); assert(stream.body() =~= Seq::<u8>::empty()); }
    let mut adapter = Adapter { io, writer: ChunkWriter::new(sink, stream), calls: Ghost(Seq::empty()) };
    proof { assert(adapter.valid()); }
    let copied = body_driver::copy(context, expected, owner, journal, &mut adapter, direction);
    proof {
        assert(adapter.valid());
        if copied.is_ok() { copied.unwrap().evidence(); assert(adapter.calls@ =~= copied.unwrap().trace()); }
    }
    proof { adapter.writer.wire_evidence(); }
    let ghost sent = adapter.writer.sent();
    let (sink, stream) = adapter.writer.into_parts();
    (Framed { copied, stream, sent: Ghost(sent), rejection: None }, sink)
}
/// Fixed responses have no chunk writer; streamed responses carry the sealed pair.
pub enum Downloaded { Fixed(Result<Completed, crate::exchange_driver::Failure>), Stream(Framed) }
impl Downloaded {
    pub open spec fn valid(&self) -> bool {
        match self { Self::Fixed(r) => r.is_ok() ==> r.unwrap().valid(), Self::Stream(f) => f.valid() }
    }
    pub open spec fn result(&self) -> Result<Completed, crate::exchange_driver::Failure> {
        match self { Self::Fixed(r) => *r, Self::Stream(f) => f.result() }
    }
    pub open spec fn sent(&self) -> Seq<u8> {
        match self { Self::Fixed(_) => Seq::empty(), Self::Stream(f) => f.sent() }
    }
    pub open spec fn summary(&self) -> Option<body_driver::CopySummary> {
        match self { Self::Fixed(r) => crate::exchange_driver::copy_summary(*r), Self::Stream(f) => f.summary() }
    }
    pub open spec fn streamed(&self) -> bool { self is Stream }
    pub fn into_parts(self) -> (out: (Result<Completed, crate::exchange_driver::Failure>, crate::exchange_driver::Body))
        requires self.valid(),
        ensures out.0 == self.result(),
            out.0.is_ok() ==> out.0.unwrap().valid(),
            match out.1 { crate::exchange_driver::Body::Fixed => !self.streamed(),
                crate::exchange_driver::Body::Stream(stream) => self.streamed() && stream.valid() && !stream.ended()
                    && (out.0.is_ok() ==> stream.out() == self.sent() && self.summary().unwrap().valid()) },
    {
        match self {
            Self::Fixed(r) => (r, crate::exchange_driver::Body::Fixed),
            Self::Stream(f) => { let (r, stream) = f.into_parts(); (r, crate::exchange_driver::Body::Stream(stream)) }
        }
    }
}

}
