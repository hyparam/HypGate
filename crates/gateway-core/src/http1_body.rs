//! Verified body delimiting. A message body arrives on the wire delimited by
//! the framing its head selected: a Content-Length count, chunked transfer
//! coding, or the bytes until the connection closes. The decoder here is the
//! bookkeeping that turns wire bytes into body bytes under that framing: how
//! many of the buffered bytes are body, how many are chunk framing, when the
//! body is complete, and what a closed connection means. It keeps a ghost
//! history of the bytes it consumed (`fed`) and the body bytes it emitted
//! (`body`); its invariant says that when it reports the body complete, the
//! consumed bytes are exactly one body of the framing whose data is exactly
//! the emitted bytes (`delimits`): a fixed-length body consumed exactly its
//! count, a chunked body is a well-formed chunked coding of the data, and a
//! read-to-close body is the bytes read. Every data step takes all it can,
//! bounded by the room the caller offers, so a caller that copies the
//! reported bytes forwards the body with nothing added, dropped, or reordered.
//! The runtime adapter owns the socket and the buffer; it asks this decoder
//! what each buffered byte is and copies only what a data step names.
use vstd::prelude::*;
use vstd::slice::slice_subrange;
use crate::http1_chunked::{self, ChunkDecoder};
use crate::http1_framing::Framing;

verus! {
/// What one call consumed from the front of the input.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Step {
    /// This many chunk framing bytes; no body bytes.
    Framing(usize),
    /// This many body bytes, which are the consumed bytes themselves.
    Data(usize),
    /// The final chunk framing byte; the body is complete.
    Done(usize),
    /// The input is not a body of the framing; nothing was consumed.
    Rejected,
}

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
enum Mode { Length, Chunked, UntilClose, Done, Failed }

/// `fed` is one complete body of `framing` whose data is `body`.
pub open spec fn delimits(framing: Framing, fed: Seq<u8>, body: Seq<u8>) -> bool {
    match framing {
        Framing::Length(n) => fed == body && fed.len() == n,
        Framing::Chunked => http1_chunked::chunked_ok(fed, body),
        Framing::UntilClose => fed == body,
    }
}

/// The most a data step can take: what is owed, what is buffered, and what the caller has room for.
pub open spec fn take(owed: nat, len: nat, room: nat) -> nat {
    if owed <= len && owed <= room { owed } else if len <= room { len } else { room }
}

pub struct BodyDecoder {
    #[allow(dead_code)] // Read by Verus specifications.
    framing: Framing,
    mode: Mode,
    chunked: ChunkDecoder,
    remaining: u64,
    // Ghost history.
    #[allow(dead_code)] // Read by Verus specifications.
    seen: Ghost<Seq<u8>>,
    #[allow(dead_code)] // Read by Verus specifications.
    out: Ghost<Seq<u8>>,
}

impl BodyDecoder {
    pub closed spec fn framing(&self) -> Framing { self.framing }
    /// Every wire byte consumed so far.
    pub closed spec fn fed(&self) -> Seq<u8> { self.seen@ }
    /// Every body byte emitted so far.
    pub closed spec fn body(&self) -> Seq<u8> { self.out@ }
    pub closed spec fn done(&self) -> bool { self.mode == Mode::Done }
    pub closed spec fn failed(&self) -> bool { self.mode == Mode::Failed }
    /// Body bytes still owed by a Content-Length framing; meaningful before the body is done.
    pub closed spec fn owed(&self) -> nat { self.remaining as nat }

    pub closed spec fn valid(&self) -> bool {
        match self.mode {
            Mode::Length => match self.framing {
                Framing::Length(n) => self.seen@ == self.out@ && self.seen@.len() + self.remaining == n && self.remaining >= 1,
                _ => false,
            },
            Mode::Chunked => self.framing == Framing::Chunked && self.chunked.valid() && !self.chunked.done()
                && !self.chunked.failed() && self.chunked.fed() == self.seen@ && self.chunked.body() == self.out@,
            Mode::UntilClose => self.framing == Framing::UntilClose && self.seen@ == self.out@,
            Mode::Done => delimits(self.framing, self.seen@, self.out@),
            Mode::Failed => true,
        }
    }

    /// A decoder for a body framed as `framing`; an empty fixed-length body is complete at once.
    pub fn new(framing: Framing) -> (out: Self)
        ensures out.valid(), out.framing() == framing, out.fed() == Seq::<u8>::empty(), out.body() == Seq::<u8>::empty(),
            !out.failed(), out.done() == (framing == Framing::Length(0)),
    {
        let (mode, remaining) = match framing {
            Framing::Length(n) => if n == 0 { (Mode::Done, 0) } else { (Mode::Length, n) },
            Framing::Chunked => (Mode::Chunked, 0),
            Framing::UntilClose => (Mode::UntilClose, 0),
        };
        Self { framing, mode, chunked: ChunkDecoder::new(), remaining, seen: Ghost(Seq::empty()), out: Ghost(Seq::empty()) }
    }
    pub fn is_done(&self) -> (out: bool) ensures out == self.done() { self.mode == Mode::Done }
    pub fn is_failed(&self) -> (out: bool) ensures out == self.failed() { self.mode == Mode::Failed }

    /// A complete body is exactly one body of the framing with exactly the emitted data.
    pub proof fn lemma_done_delimits(&self)
        requires self.valid(), self.done(),
        ensures delimits(self.framing(), self.fed(), self.body()),
    {}

    /// What one `step` establishes: the decoder stays valid under the same
    /// framing, the consumed bytes and emitted body grow exactly as the step
    /// reports, a data step takes all it can within the caller's room, a
    /// fixed-length body is done exactly when its count is consumed, only
    /// chunked framing has framing bytes or a rejection, and a chunked body
    /// completes only from its last framing byte.
    pub open spec fn step_ok(before: Self, after: Self, input: Seq<u8>, room: nat, out: Step) -> bool {
        after.valid() && after.framing() == before.framing() && match out {
            Step::Framing(n) => n == 1 && after.fed() == before.fed() + input.subrange(0, 1) && after.body() == before.body()
                && !after.done() && !after.failed() && before.framing() == Framing::Chunked,
            Step::Data(n) => 1 <= n <= input.len() && n <= room && after.fed() == before.fed() + input.subrange(0, n as int)
                && after.body() == before.body() + input.subrange(0, n as int) && !after.failed()
                && match before.framing() {
                    Framing::Length(_) => n == take(before.owed(), input.len(), room) && after.done() == (before.owed() == n),
                    Framing::UntilClose => n == take(input.len(), input.len(), room) && !after.done(),
                    Framing::Chunked => !after.done(),
                },
            Step::Done(n) => n == 1 && after.fed() == before.fed() + input.subrange(0, 1) && after.body() == before.body()
                && after.done() && before.framing() == Framing::Chunked,
            Step::Rejected => after.failed() && after.fed() == before.fed() && after.body() == before.body()
                && before.framing() == Framing::Chunked,
        }
    }

    /// Consume from the front of `input`, emitting at most `room` body bytes.
    pub fn step(&mut self, input: &[u8], room: usize) -> (out: Step)
        requires old(self).valid(), !old(self).done(), !old(self).failed(), input.len() >= 1, room >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, room as nat, out),
    {
        match self.mode {
            Mode::Length => {
                let mut n = input.len();
                if room < n { n = room; }
                if self.remaining < n as u64 { n = self.remaining as usize; }
                self.remaining = self.remaining - n as u64;
                proof {
                    self.seen@ = self.seen@ + input@.subrange(0, n as int);
                    self.out@ = self.out@ + input@.subrange(0, n as int);
                }
                if self.remaining == 0 { self.mode = Mode::Done; }
                Step::Data(n)
            }
            Mode::UntilClose => {
                let n = if room < input.len() { room } else { input.len() };
                proof {
                    self.seen@ = self.seen@ + input@.subrange(0, n as int);
                    self.out@ = self.out@ + input@.subrange(0, n as int);
                }
                Step::Data(n)
            }
            Mode::Chunked => {
                // Offer at most what the caller can take, so a data step fits.
                let window = if room < input.len() { slice_subrange(input, 0, room) } else { input };
                match self.chunked.feed(window) {
                    http1_chunked::Step::Framing(n) => {
                        proof {
                            assert(window@.subrange(0, n as int) =~= input@.subrange(0, n as int));
                            self.seen@ = self.seen@ + input@.subrange(0, n as int);
                        }
                        Step::Framing(n)
                    }
                    http1_chunked::Step::Data(n) => {
                        proof {
                            assert(window@.subrange(0, n as int) =~= input@.subrange(0, n as int));
                            self.seen@ = self.seen@ + input@.subrange(0, n as int);
                            self.out@ = self.out@ + input@.subrange(0, n as int);
                        }
                        Step::Data(n)
                    }
                    http1_chunked::Step::Done(n) => {
                        proof {
                            assert(window@.subrange(0, n as int) =~= input@.subrange(0, n as int));
                            self.seen@ = self.seen@ + input@.subrange(0, n as int);
                        }
                        self.mode = Mode::Done;
                        Step::Done(n)
                    }
                    http1_chunked::Step::Rejected => { self.mode = Mode::Failed; Step::Rejected }
                }
            }
            Mode::Done | Mode::Failed => { assert(false); Step::Rejected }
        }
    }

    /// The connection closed before the body was complete: that is the end of
    /// a read-to-close body and a truncation of any other.
    pub fn close(&mut self) -> (out: bool)
        requires old(self).valid(), !old(self).done(), !old(self).failed(),
        ensures final(self).valid(), final(self).framing() == old(self).framing(), final(self).fed() == old(self).fed(),
            final(self).body() == old(self).body(), out == (old(self).framing() == Framing::UntilClose),
            final(self).done() == out, final(self).failed() == !out,
    {
        match self.mode {
            Mode::UntilClose => { self.mode = Mode::Done; true }
            _ => { self.mode = Mode::Failed; false }
        }
    }

    /// The wire failed: nothing more can be decoded.
    pub fn abandon(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).framing() == old(self).framing(), final(self).fed() == old(self).fed(),
            final(self).body() == old(self).body(), final(self).failed(),
    {
        self.mode = Mode::Failed;
    }
}
} // verus!
