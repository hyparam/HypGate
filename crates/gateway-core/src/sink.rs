//! The writing driver over a byte sink: a loop that hands a byte string to
//! the sink until every byte is accepted, and a chunk writer that frames
//! each piece through the verified `ChunkStream` before handing it over. The
//! sink is a trait the runtime implements over its socket; the drivers are
//! proved against it: the pieces the sink accepted, concatenated, are exactly
//! the bytes given, in order, nothing skipped, nothing sent twice, and a
//! failure leaves a proper prefix handed over. Moving a byte from the sink
//! into the socket remains the runtime's effect.
use vstd::prelude::*;
use vstd::slice::slice_subrange;
use crate::http1_exchange::ChunkStream;

verus! {

/// What one offer of bytes did: the sink took the first `n`, or took nothing
/// because the peer closed, or failed.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Put { Wrote(usize), Closed, Failed }

/// The socket as the drivers see it: `put` accepts a non-empty prefix of
/// `bytes` and says how long it is, or accepts nothing.
pub trait Sink {
    fn put(&mut self, bytes: &[u8]) -> (out: Put)
        requires bytes.len() >= 1,
        ensures match out { Put::Wrote(n) => 1 <= n <= bytes.len(), _ => true };
}

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum WriteError { Closed, Failed }

/// The outcome of a write: `sent` is the concatenation of the prefixes the
/// sink accepted, in the order they were offered.
pub struct Written { pub result: Result<(), WriteError>, pub sent: Ghost<Seq<u8>> }

/// Hand `bytes` to the sink until all are accepted.
pub fn write_all<S: Sink>(sink: &mut S, bytes: &[u8]) -> (out: Written)
    ensures
        out.result is Ok ==> out.sent@ == bytes@,
        out.result is Err ==> out.sent@ == bytes@.subrange(0, out.sent@.len() as int) && out.sent@.len() < bytes@.len(),
{
    let mut offset: usize = 0;
    let ghost mut sent: Seq<u8> = Seq::empty();
    while offset < bytes.len()
        invariant offset <= bytes.len(), sent == bytes@.subrange(0, offset as int),
        decreases bytes.len() - offset,
    {
        let piece = slice_subrange(bytes, offset, bytes.len());
        match sink.put(piece) {
            Put::Wrote(n) => {
                proof {
                    assert(sent + piece@.subrange(0, n as int) =~= bytes@.subrange(0, offset + n));
                    sent = sent + piece@.subrange(0, n as int);
                }
                offset = offset + n;
            }
            Put::Closed => return Written { result: Err(WriteError::Closed), sent: Ghost(sent) },
            Put::Failed => return Written { result: Err(WriteError::Failed), sent: Ghost(sent) },
        }
    }
    proof { assert(bytes@.subrange(0, bytes@.len() as int) =~= bytes@); }
    Written { result: Ok(()), sent: Ghost(sent) }
}

/// A body written as chunks: each `write` is one chunk handed whole to the
/// sink, and `finish` hands over the last chunk. The bytes the sink accepted
/// are always a prefix of the stream's output, equal to it while no write
/// has failed.
/// The sink is public so the runtime can flush it; the proof does not depend on its state.
pub struct ChunkWriter<S> { pub sink: S, stream: ChunkStream, sent: Ghost<Seq<u8>>, failed: bool }

impl<S: Sink> ChunkWriter<S> {
    /// The bytes the sink accepted so far.
    pub closed spec fn sent(&self) -> Seq<u8> { self.sent@ }
    /// The bytes framed so far.
    pub closed spec fn framed(&self) -> Seq<u8> { self.stream.out() }
    /// The body given so far.
    pub closed spec fn body(&self) -> Seq<u8> { self.stream.body() }
    pub closed spec fn ended(&self) -> bool { self.stream.ended() }
    pub closed spec fn failed(&self) -> bool { self.failed }
    pub closed spec fn inv(&self) -> bool {
        &&& self.stream.valid()
        &&& self.sent@.len() <= self.stream.out().len()
        &&& self.sent@ == self.stream.out().subrange(0, self.sent@.len() as int)
        &&& !self.failed ==> self.sent@ == self.stream.out()
    }

    pub fn new(sink: S, stream: ChunkStream) -> (out: Self)
        requires stream.valid(), stream.out() == Seq::<u8>::empty(),
        ensures out.inv(), !out.failed(), out.ended() == stream.ended(), out.body() == stream.body(), out.sent() == Seq::<u8>::empty(),
    {
        proof { assert(stream.out().subrange(0, 0) =~= Seq::<u8>::empty()); }
        ChunkWriter { sink, stream, sent: Ghost(Seq::empty()), failed: false }
    }

    pub fn is_ended(&self) -> (out: bool) ensures out == self.ended() { self.stream.is_ended() }
    pub fn has_failed(&self) -> (out: bool) ensures out == self.failed() { self.failed }

    /// One chunk of `data`. After a failure nothing more is offered.
    pub fn write(&mut self, data: &[u8]) -> (out: Result<(), WriteError>)
        requires old(self).inv(), !old(self).ended(), !old(self).failed(), data.len() >= 1,
        ensures final(self).inv(), !final(self).ended(), final(self).body() == old(self).body() + data@,
            final(self).framed() == old(self).framed() + crate::http1_chunked::chunk_bytes(data@),
            out is Ok ==> !final(self).failed() && final(self).sent() == final(self).framed(),
            out is Err ==> final(self).failed(),
    {
        let bytes = self.stream.frame(data);
        let written = write_all(&mut self.sink, &bytes);
        self.note(Ghost(bytes@), written)
    }

    /// The last chunk; the body is complete.
    pub fn finish(&mut self) -> (out: Result<(), WriteError>)
        requires old(self).inv(), !old(self).ended(), !old(self).failed(),
        ensures final(self).inv(), final(self).ended(), final(self).body() == old(self).body(),
            final(self).framed() == old(self).framed() + crate::http1_chunked::last_chunk_bytes(),
            crate::http1_chunked::chunked_ok(final(self).framed(), final(self).body()),
            out is Ok ==> !final(self).failed() && final(self).sent() == final(self).framed(),
            out is Err ==> final(self).failed(),
    {
        let bytes = self.stream.end();
        let written = write_all(&mut self.sink, &bytes);
        self.note(Ghost(bytes@), written)
    }

    fn note(&mut self, framed: Ghost<Seq<u8>>, written: Written) -> (out: Result<(), WriteError>)
        requires old(self).stream.valid(), !old(self).failed, old(self).stream.out() == old(self).sent@ + framed@,
            written.result is Ok ==> written.sent@ == framed@,
            written.result is Err ==> written.sent@.len() <= framed@.len() && written.sent@ == framed@.subrange(0, written.sent@.len() as int),
        ensures final(self).inv(), final(self).stream == old(self).stream, out == written.result,
            out is Ok ==> !final(self).failed,
            out is Err ==> final(self).failed,
    {
        proof {
            let all = self.stream.out();
            let now = self.sent@ + written.sent@;
            assert(now =~= all.subrange(0, now.len() as int));
        }
        self.sent = Ghost(self.sent@ + written.sent@);
        match written.result {
            Ok(unit) => Ok(unit),
            Err(e) => { self.failed = true; Err(e) }
        }
    }

    /// The sink and the stream back, for the machine that issued the stream.
    pub fn into_parts(self) -> (out: (S, ChunkStream))
        ensures out.1.valid() == self.inv() || out.1.valid(), out.1.ended() == self.ended(), out.1.body() == self.body(), out.1.out() == self.framed(),
    { (self.sink, self.stream) }
}

} // verus!
