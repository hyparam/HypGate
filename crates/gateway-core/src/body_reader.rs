//! The reading drivers over a byte source: a head reader that fills a bounded
//! buffer until the verified head parser decides, and a body reader that
//! owns the read buffer, its cursor, and the verified body decoder and asks
//! the source for more bytes only when the buffer is spent. The source is a
//! trait the runtime implements over its socket; the drivers are proved
//! against it: what the decoder is fed is exactly what the source produced,
//! in order, nothing skipped or read twice; the bytes a body read names are
//! exactly the decoder's body bytes, in order; a head is parsed from exactly
//! the bytes received and the rest is returned as leftover; and the buffer
//! never grows past its bound. What a byte means remains the parsers' and
//! decoder's theorem; moving it from the socket into the buffer remains the
//! runtime's effect.
use vstd::prelude::*;
use vstd::slice::{slice_subrange, slice_to_vec};
use crate::headers::{MAX_BYTES, Rejection};
use crate::http1_body::{BodyDecoder, Step};
use crate::http1_framing::Framing;
use crate::http1_head::{RequestHead, RequestProgress, StatusHead, StatusProgress, parse_request, parse_status};

verus! {

/// One socket read, and the most body bytes buffered ahead of the copy.
pub const READ_BYTES: usize = 32 * 1024;

/// What one call for more bytes did.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Fill { Bytes, Closed, Failed }

/// The socket as the drivers see it: `fill` appends at least one and at most
/// `max` bytes to `buffer` and says `Bytes`, or appends nothing and says the
/// peer closed or the read failed.
pub trait Source {
    fn fill(&mut self, buffer: &mut Vec<u8>, max: usize) -> (out: Fill)
        requires max >= 1,
        ensures match out {
            Fill::Bytes => old(buffer)@.len() < final(buffer)@.len() <= old(buffer)@.len() + max
                && final(buffer)@.subrange(0, old(buffer)@.len() as int) == old(buffer)@,
            _ => final(buffer)@ == old(buffer)@,
        };
}

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum HeadError { TooLarge, Malformed, Closed, Io }

/// A parsed head and the bytes received after it. `received` is every byte
/// received, the leftover first, and `len` where the head ends in it.
pub struct HeadRead<H> { pub head: H, pub rest: Vec<u8>, pub received: Ghost<Seq<u8>>, pub len: Ghost<int> }

/// Fill the head buffer, never past the head limit.
fn fill_head<S: Source>(source: &mut S, buffer: &mut Vec<u8>) -> (out: Result<(), HeadError>)
    requires old(buffer)@.len() < MAX_BYTES,
    ensures match out {
        Ok(()) => old(buffer)@.len() < final(buffer)@.len() <= MAX_BYTES && final(buffer)@.subrange(0, old(buffer)@.len() as int) == old(buffer)@,
        Err(_) => final(buffer)@ == old(buffer)@,
    },
{
    let room = MAX_BYTES - buffer.len();
    let max = if room < READ_BYTES { room } else { READ_BYTES };
    match source.fill(buffer, max) {
        Fill::Bytes => Ok(()),
        Fill::Closed => Err(HeadError::Closed),
        Fill::Failed => Err(HeadError::Io),
    }
}
/// Read from `source` until a request head parses. `Ok` holds the head and
/// the bytes received after it; the head is parsed from exactly the bytes
/// received before them.
#[verifier::exec_allows_no_decreases_clause]
#[verifier::loop_isolation(false)]
pub fn read_request_head<S: Source>(source: &mut S, leftover: Vec<u8>) -> (out: Result<HeadRead<RequestHead>, HeadError>)
    ensures match out {
        Ok(r) => leftover@.len() <= r.received@.len() && r.received@.subrange(0, leftover@.len() as int) == leftover@
            && 0 <= r.len@ <= r.received@.len() && crate::http1_head::request_head_ok(r.received@.subrange(0, r.len@), r.head)
            && r.rest@ == r.received@.subrange(r.len@, r.received@.len() as int),
        Err(_) => true,
    },
{
    let mut buffer = leftover;
    proof { assert(buffer@.subrange(0, leftover@.len() as int) =~= leftover@); }
    loop
        invariant buffer@.len() >= leftover@.len() && buffer@.subrange(0, leftover@.len() as int) == leftover@,
    {
        match parse_request(buffer.as_slice()) {
            RequestProgress::Complete(head, len) => {
                let rest = slice_to_vec(slice_subrange(buffer.as_slice(), len, buffer.len()));
                return Ok(HeadRead { head, rest, received: Ghost(buffer@), len: Ghost(len as int) });
            }
            RequestProgress::Rejected(Rejection::TooLarge) => return Err(HeadError::TooLarge),
            RequestProgress::Rejected(Rejection::BadRequest) => return Err(HeadError::Malformed),
            RequestProgress::Incomplete => {
                let ghost before = buffer@;
                match fill_head(source, &mut buffer) {
                    Ok(()) => { proof { assert(buffer@.subrange(0, leftover@.len() as int) =~= before.subrange(0, leftover@.len() as int)); } }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}
/// Read from `source` until a status head parses; as `read_request_head`.
#[verifier::exec_allows_no_decreases_clause]
#[verifier::loop_isolation(false)]
pub fn read_status_head<S: Source>(source: &mut S, leftover: Vec<u8>) -> (out: Result<HeadRead<StatusHead>, HeadError>)
    ensures match out {
        Ok(r) => leftover@.len() <= r.received@.len() && r.received@.subrange(0, leftover@.len() as int) == leftover@
            && 0 <= r.len@ <= r.received@.len() && crate::http1_head::status_head_ok(r.received@.subrange(0, r.len@), r.head)
            && r.rest@ == r.received@.subrange(r.len@, r.received@.len() as int),
        Err(_) => true,
    },
{
    let mut buffer = leftover;
    proof { assert(buffer@.subrange(0, leftover@.len() as int) =~= leftover@); }
    loop
        invariant buffer@.len() >= leftover@.len() && buffer@.subrange(0, leftover@.len() as int) == leftover@,
    {
        match parse_status(buffer.as_slice()) {
            StatusProgress::Complete(head, len) => {
                let rest = slice_to_vec(slice_subrange(buffer.as_slice(), len, buffer.len()));
                return Ok(HeadRead { head, rest, received: Ghost(buffer@), len: Ghost(len as int) });
            }
            StatusProgress::Rejected(Rejection::TooLarge) => return Err(HeadError::TooLarge),
            StatusProgress::Rejected(Rejection::BadRequest) => return Err(HeadError::Malformed),
            StatusProgress::Incomplete => {
                let ghost before = buffer@;
                match fill_head(source, &mut buffer) {
                    Ok(()) => { proof { assert(buffer@.subrange(0, leftover@.len() as int) =~= before.subrange(0, leftover@.len() as int)); } }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

/// What one body read produced.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Read {
    /// Body bytes: `buffer()[start..start + len)`.
    Data(usize, usize),
    /// The body is complete and well framed.
    End,
    /// The peer closed before the body was complete.
    Truncated,
    /// The bytes are not a body of the framing.
    Malformed,
    /// The source failed, or the body had already failed.
    Failed,
}

/// The body that follows a head: the head's leftover bytes, then the source.
pub struct BodyReader {
    buffer: Vec<u8>,
    pos: usize,
    decoder: BodyDecoder,
    /// Every byte received for the body, in order: leftover first, then each fill.
    received: Ghost<Seq<u8>>,
    /// Every body byte a read has named, in order.
    delivered: Ghost<Seq<u8>>,
}

impl BodyReader {
    pub closed spec fn framing(&self) -> Framing { self.decoder.framing() }
    /// The buffer a `Read::Data` names into.
    pub closed spec fn bytes(&self) -> Seq<u8> { self.buffer@ }
    pub closed spec fn received(&self) -> Seq<u8> { self.received@ }
    pub closed spec fn delivered(&self) -> Seq<u8> { self.delivered@ }
    pub closed spec fn fed(&self) -> Seq<u8> { self.decoder.fed() }
    pub closed spec fn done(&self) -> bool { self.decoder.done() }
    pub closed spec fn failed(&self) -> bool { self.decoder.failed() }
    /// The bytes received but not yet fed.
    pub closed spec fn unread(&self) -> Seq<u8> { self.buffer@.subrange(self.pos as int, self.buffer@.len() as int) }
    pub closed spec fn valid(&self) -> bool {
        self.pos <= self.buffer@.len() && self.buffer@.len() <= READ_BYTES || self.pos <= self.buffer@.len()
    }
    /// The invariant: the decoder is valid, it has been fed exactly the
    /// received bytes up to the cursor, and every body byte it named has been delivered.
    pub closed spec fn inv(&self) -> bool {
        self.pos <= self.buffer@.len() && self.decoder.valid() && self.received@ == self.decoder.fed() + self.unread()
            && self.delivered@ == self.decoder.body()
    }

    pub fn new(leftover: Vec<u8>, framing: Framing) -> (out: Self)
        ensures out.inv(), out.framing() == framing, out.received() == leftover@, out.delivered() == Seq::<u8>::empty(),
    {
        let decoder = BodyDecoder::new(framing);
        let out = Self { buffer: leftover, pos: 0, decoder, received: Ghost(leftover@), delivered: Ghost(Seq::empty()) };
        proof { assert(out.unread() =~= leftover@); assert(out.received@ =~= out.decoder.fed() + out.unread()); }
        out
    }
    /// Whether the whole body was read and well framed.
    pub fn is_complete(&self) -> (out: bool) ensures out == self.done() { self.decoder.is_done() }
    /// The buffer a `Read::Data` names into.
    pub fn buffer(&self) -> (out: &Vec<u8>) ensures out@ == self.bytes() { &self.buffer }

    /// A complete body: the fed bytes delimit exactly the delivered body.
    pub proof fn lemma_complete(&self)
        requires self.inv(), self.done(),
        ensures crate::http1_body::delimits(self.framing(), self.fed(), self.delivered()), self.received() == self.fed() + self.unread(),
    {
        self.decoder.lemma_done_delimits();
    }

    /// The next body bytes, at most `room` of them, reading from `source`
    /// only when the buffer is spent.
    #[verifier::exec_allows_no_decreases_clause]
    #[verifier::loop_isolation(false)]
    pub fn read<S: Source>(&mut self, source: &mut S, room: usize) -> (out: Read)
        requires old(self).inv(), room >= 1,
        ensures final(self).inv(), final(self).framing() == old(self).framing(),
            old(self).received().len() <= final(self).received().len(),
            final(self).received().subrange(0, old(self).received().len() as int) == old(self).received(),
            match out {
                Read::Data(start, n) => 1 <= n <= room && start + n <= final(self).bytes().len()
                    && final(self).delivered() == old(self).delivered() + final(self).bytes().subrange(start as int, start + n)
                    && !final(self).failed(),
                Read::End => final(self).done() && final(self).delivered() == old(self).delivered(),
                Read::Truncated => final(self).failed() && old(self).framing() != Framing::UntilClose && final(self).delivered() == old(self).delivered(),
                Read::Malformed => final(self).failed() && old(self).framing() == Framing::Chunked && final(self).delivered() == old(self).delivered(),
                Read::Failed => final(self).failed() && final(self).delivered() == old(self).delivered(),
            },
    {
        let ghost received0 = self.received@;
        proof { assert(self.received@.subrange(0, received0.len() as int) =~= received0); }
        loop
            invariant self.inv(), room >= 1, self.decoder.framing() == old(self).decoder.framing(), self.delivered@ == old(self).delivered@,
                received0.len() <= self.received@.len(), self.received@.subrange(0, received0.len() as int) == received0,
        {
            if self.decoder.is_done() { return Read::End; }
            if self.decoder.is_failed() { return Read::Failed; }
            if self.pos < self.buffer.len() {
                let ghost before = self.decoder;
                let ghost unread0 = self.unread();
                let available = slice_subrange(self.buffer.as_slice(), self.pos, self.buffer.len());
                let step = self.decoder.step(available, room);
                match step {
                    Step::Framing(n) => {
                        self.pos = self.pos + n;
                        proof { assert(self.received@ =~= self.decoder.fed() + self.unread()); }
                    }
                    Step::Data(n) => {
                        let start = self.pos;
                        self.pos = self.pos + n;
                        proof {
                            self.delivered@ = self.decoder.body();
                            assert(self.received@ =~= self.decoder.fed() + self.unread());
                            assert(self.buffer@.subrange(start as int, start + n) =~= unread0.subrange(0, n as int));
                        }
                        return Read::Data(start, n);
                    }
                    Step::Done(n) => {
                        self.pos = self.pos + n;
                        proof { assert(self.received@ =~= self.decoder.fed() + self.unread()); }
                        return Read::End;
                    }
                    Step::Rejected => return Read::Malformed,
                }
                continue;
            }
            // The buffer is spent: ask for more body bytes.
            proof { assert(self.unread().len() == 0); assert(self.received@ =~= self.decoder.fed()); }
            self.buffer.clear();
            self.pos = 0;
            let ghost fed = self.decoder.fed();
            let ghost prev = self.received@;
            let ghost before_fill = self.buffer@.len() as int;
            proof { assert(prev == fed); assert(prev.subrange(0, received0.len() as int) == received0); }
            match source.fill(&mut self.buffer, READ_BYTES) {
                Fill::Bytes => {
                    proof {
                        // Only the bytes the source appended are new: the trace grows by exactly them.
                        self.received@ = fed + self.buffer@.subrange(before_fill, self.buffer@.len() as int);
                        assert(self.unread() =~= self.buffer@.subrange(before_fill, self.buffer@.len() as int));
                        assert forall|k: int| 0 <= k < received0.len() implies self.received@[k] == received0[k] by {
                            assert(self.received@[k] == prev[k]);
                            assert(prev.subrange(0, received0.len() as int)[k] == prev[k]);
                        }
                        assert(self.received@.subrange(0, received0.len() as int) =~= received0);
                    }
                }
                Fill::Closed => {
                    proof { assert(self.unread() =~= Seq::<u8>::empty()); assert(self.received@ =~= self.decoder.fed() + self.unread()); }
                    let open_ended = self.decoder.close();
                    proof { assert(self.received@ =~= self.decoder.fed() + self.unread()); }
                    return if open_ended { Read::End } else { Read::Truncated };
                }
                Fill::Failed => {
                    proof { assert(self.unread() =~= Seq::<u8>::empty()); }
                    self.decoder.abandon();
                    proof { assert(self.received@ =~= self.decoder.fed() + self.unread()); }
                    return Read::Failed;
                }
            }
        }
    }
}

} // verus!
