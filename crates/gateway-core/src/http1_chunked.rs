//! Verified chunked transfer coding. The decoder is a byte-level state
//! machine with a ghost history of the bytes it consumed and the body bytes
//! it emitted; its invariant says the consumed bytes are complete chunks of
//! exactly the emitted body followed by the partial chunk the state names.
//! So when it reports the end of the body, the bytes it consumed are one
//! well-formed chunked body (`chunked_ok`) whose data is exactly the bytes it
//! emitted: nothing is added, dropped, or reordered, and a body with a
//! malformed size line, a bad chunk delimiter, or trailer fields is refused
//! rather than guessed at. The converse, that a well-formed body is never
//! refused and finishes exactly at its end, is `complete::lemma_complete`,
//! so the decoder accepts exactly the grammar. The encoder writes the chunk
//! framing the specification names, and each chunk it writes is proved to be
//! a chunk of that grammar.
use vstd::prelude::*;
use crate::http1_head::{CR, LF};

verus! {
pub const SEMICOLON: u8 = 59;
/// Chunk sizes are spelled in at most sixteen hex digits: every `u64`, nothing larger.
pub const MAX_SIZE_DIGITS: u8 = 16;
/// A size line, digits and any extension, is at most this long, so the framing
/// between two data steps is bounded and a reader's loop over it terminates.
pub const MAX_SIZE_LINE: usize = 1024;

pub open spec fn is_hex(b: u8) -> bool { (48 <= b <= 57) || (65 <= b <= 70) || (97 <= b <= 102) }
pub open spec fn hex_val(b: u8) -> nat {
    if 48 <= b <= 57 { (b - 48) as nat } else if 65 <= b <= 70 { (b - 55) as nat } else { (b - 87) as nat }
}
pub open spec fn all_hex(s: Seq<u8>) -> bool { forall|k: int| 0 <= k < s.len() ==> is_hex(#[trigger] s[k]) }
/// The value of a hex digit string, most significant first.
pub open spec fn hex_value(s: Seq<u8>) -> nat
    decreases s.len(),
{
    if s.len() == 0 { 0 } else { hex_value(s.drop_last()) * 16 + hex_val(s.last()) }
}
pub open spec fn pow16(d: nat) -> nat
    decreases d,
{
    if d == 0 { 1 } else { pow16((d - 1) as nat) * 16 }
}
/// The lowercase hex digit for `d < 16`.
pub open spec fn hex_digit(d: nat) -> u8 { if d < 10 { (48 + d) as u8 } else { (87 + d) as u8 } }
/// The shortest lowercase hex spelling of `n`.
pub open spec fn hex_digits(n: nat) -> Seq<u8>
    decreases n,
{
    if n < 16 { seq![hex_digit(n)] } else { hex_digits(n / 16).push(hex_digit(n % 16)) }
}

/// A size line without its CRLF: `hexlen` hex digits spelling `n`, then either
/// nothing or `;` and extension bytes, which are accepted and ignored.
pub open spec fn size_split(line: Seq<u8>, n: nat, hexlen: int) -> bool {
    1 <= hexlen <= MAX_SIZE_DIGITS && hexlen <= line.len() && line.len() <= MAX_SIZE_LINE
        && all_hex(line.subrange(0, hexlen)) && hex_value(line.subrange(0, hexlen)) == n
        && (hexlen == line.len() || (line[hexlen] == SEMICOLON && forall|k: int| hexlen < k < line.len() ==> crate::http1_head::is_value_byte(#[trigger] line[k])))
}
pub open spec fn size_line_ok(line: Seq<u8>, n: nat) -> bool { exists|hexlen: int| #[trigger] size_split(line, n, hexlen) }
/// One chunk of `data.len() >= 1` bytes: size line, CRLF, the data, CRLF.
/// Opaque: the run-of-chunks lemmas treat it as an atom; `reveal` where its body matters.
#[verifier::opaque]
pub open spec fn chunk_ok(bytes: Seq<u8>, data: Seq<u8>) -> bool {
    exists|e: int| #[trigger] crate::http1_head::crlf_at(bytes, e) && crate::http1_head::clean(bytes.subrange(0, e))
        && size_line_ok(bytes.subrange(0, e), data.len()) && data.len() >= 1
        && bytes.len() == e + 2 + data.len() + 2 && bytes.subrange(e + 2, e + 2 + data.len()) == data
        && crate::http1_head::crlf_at(bytes, e + 2 + data.len())
}
/// Zero or more chunks whose data concatenates to `body`.
pub open spec fn chunks_ok(bytes: Seq<u8>, body: Seq<u8>) -> bool
    decreases bytes.len(),
{
    (bytes.len() == 0 && body.len() == 0)
        || exists|k: int, n: int| 0 < k <= bytes.len() && 0 < n <= body.len()
            && #[trigger] chunk_ok(bytes.subrange(0, k), body.subrange(0, n)) && chunks_ok(bytes.skip(k), body.skip(n))
}
/// The last chunk: a size line spelling zero, CRLF, and the empty line. No trailers.
pub open spec fn last_chunk_ok(bytes: Seq<u8>) -> bool {
    exists|e: int| #[trigger] crate::http1_head::crlf_at(bytes, e) && crate::http1_head::clean(bytes.subrange(0, e))
        && size_line_ok(bytes.subrange(0, e), 0) && bytes.len() == e + 4 && crate::http1_head::crlf_at(bytes, e + 2)
}
/// A complete chunked body for `body`.
pub open spec fn chunked_ok(bytes: Seq<u8>, body: Seq<u8>) -> bool {
    exists|k: int| 0 <= k <= bytes.len() && #[trigger] chunks_ok(bytes.subrange(0, k), body) && last_chunk_ok(bytes.skip(k))
}

// ---- decoder ---------------------------------------------------------------

/// Where the decoder is in the chunk in progress. Public so the completeness
/// theorem can name it; the fields it governs stay private.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Phase { Size, Ext, SizeCr, Data, DataCr, DataLf, LastCr, LastLf, Done, Failed }

/// What one call consumed from the front of the input.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Step {
    /// One framing byte; no body bytes.
    Framing(usize),
    /// This many body bytes, which are the consumed bytes themselves.
    Data(usize),
    /// The final framing byte; the body is complete.
    Done(usize),
    /// The input is not a chunked body; nothing was consumed.
    Rejected,
}

pub struct ChunkDecoder {
    phase: Phase,
    size: u64,
    digits: u8,
    remaining: u64,
    line_len: usize,
    // Ghost history.
    done_bytes: Ghost<Seq<u8>>,
    done_body: Ghost<Seq<u8>>,
    line: Ghost<Seq<u8>>,
    partial: Ghost<Seq<u8>>,
}

impl ChunkDecoder {
    /// Every byte consumed so far.
    pub closed spec fn fed(&self) -> Seq<u8> { self.done_bytes@ + self.tail() }
    /// Every body byte emitted so far.
    pub closed spec fn body(&self) -> Seq<u8> { self.done_body@ + self.partial@ }
    pub closed spec fn done(&self) -> bool { self.phase == Phase::Done }
    pub closed spec fn failed(&self) -> bool { self.phase == Phase::Failed }
    pub closed spec fn phase(&self) -> Phase { self.phase }
    /// Data bytes still owed to the chunk in progress; meaningful in `Phase::Data`.
    pub closed spec fn pending(&self) -> nat { self.remaining as nat }
    /// Whether the next byte is accepted in the current phase. The decoder
    /// rejects exactly when this is false, and the completeness theorem shows
    /// it is true for every byte of a well-formed chunked body.
    pub closed spec fn accepts(&self, b: u8) -> bool {
        match self.phase {
            Phase::Size => (is_hex(b) && self.digits < MAX_SIZE_DIGITS) || ((b == SEMICOLON || b == CR) && self.digits >= 1),
            Phase::Ext => b == CR || (crate::http1_head::is_value_byte(b) && self.line@.len() < MAX_SIZE_LINE),
            Phase::SizeCr => b == LF,
            Phase::Data => true,
            Phase::DataCr => b == CR,
            Phase::DataLf => b == LF,
            Phase::LastCr => b == CR,
            Phase::LastLf => b == LF,
            Phase::Done | Phase::Failed => false,
        }
    }
    /// How many input bytes a step consumed.
    pub open spec fn consumed(out: Step) -> nat {
        match out { Step::Framing(n) => n as nat, Step::Data(n) => n as nat, Step::Done(n) => n as nat, Step::Rejected => 0 }
    }
    /// The bytes of the chunk in progress, by phase.
    spec fn tail(&self) -> Seq<u8> {
        let line = self.line@;
        let crlf = seq![CR, LF];
        match self.phase {
            Phase::Size | Phase::Ext => line,
            Phase::SizeCr => line + seq![CR],
            Phase::Data | Phase::DataCr => line + crlf + self.partial@,
            Phase::DataLf => line + crlf + self.partial@ + seq![CR],
            Phase::LastCr => line + crlf,
            Phase::LastLf => line + crlf + seq![CR],
            Phase::Done => line + crlf + crlf,
            Phase::Failed => Seq::<u8>::empty(),
        }
    }
    /// The size line in progress has `digits` hex digits spelling `size`,
    /// and after them nothing (`ext` false) or a semicolon and extension bytes.
    spec fn line_shape(&self, ext: bool) -> bool {
        let line = self.line@;
        let d = self.digits as int;
        self.line_len == line.len() && line.len() <= MAX_SIZE_LINE
            && d <= MAX_SIZE_DIGITS && d <= line.len() && all_hex(line.subrange(0, d)) && hex_value(line.subrange(0, d)) == self.size
            && if ext { d < line.len() && line[d] == SEMICOLON && forall|k: int| d < k < line.len() ==> crate::http1_head::is_value_byte(#[trigger] line[k]) }
               else { d == line.len() }
    }
    /// Framing bytes the decoder may consume before its next data step,
    /// completion, or rejection. Every framing step lowers it, so a loop that
    /// feeds the decoder until it names data terminates.
    pub closed spec fn framing_budget(&self) -> nat {
        match self.phase {
            Phase::Size | Phase::Ext => (MAX_SIZE_LINE + 4 - self.line@.len()) as nat,
            Phase::SizeCr => 3nat,
            Phase::Data => 0nat,
            Phase::DataCr => (MAX_SIZE_LINE + 6) as nat,
            Phase::DataLf => (MAX_SIZE_LINE + 5) as nat,
            Phase::LastCr => 2nat,
            Phase::LastLf => 1nat,
            Phase::Done | Phase::Failed => 0nat,
        }
    }
    pub closed spec fn valid(&self) -> bool {
        chunks_ok(self.done_bytes@, self.done_body@)
        && match self.phase {
            Phase::Size => self.line_shape(false) && self.partial@.len() == 0,
            Phase::Ext => self.line_shape(true) && self.digits >= 1 && self.partial@.len() == 0,
            Phase::SizeCr => (self.line_shape(false) || self.line_shape(true)) && self.digits >= 1 && self.partial@.len() == 0,
            Phase::Data => (self.line_shape(false) || self.line_shape(true)) && self.digits >= 1 && self.size >= 1
                && 1 <= self.remaining <= self.size && self.partial@.len() == self.size - self.remaining,
            Phase::DataCr | Phase::DataLf => (self.line_shape(false) || self.line_shape(true)) && self.digits >= 1 && self.size >= 1
                && self.partial@.len() == self.size,
            Phase::LastCr | Phase::LastLf | Phase::Done => (self.line_shape(false) || self.line_shape(true)) && self.digits >= 1 && self.size == 0
                && self.partial@.len() == 0,
            Phase::Failed => true,
        }
    }

    pub fn new() -> (out: Self)
        ensures out.valid(), out.fed() == Seq::<u8>::empty(), out.body() == Seq::<u8>::empty(), !out.done(), !out.failed(),
    {
        let out = ChunkDecoder { phase: Phase::Size, size: 0, digits: 0, remaining: 0, line_len: 0,
            done_bytes: Ghost(Seq::empty()), done_body: Ghost(Seq::empty()), line: Ghost(Seq::empty()), partial: Ghost(Seq::empty()) };
        proof {
            assert(out.line@.subrange(0, 0) =~= Seq::<u8>::empty());
            assert(out.fed() =~= Seq::<u8>::empty());
            assert(out.body() =~= Seq::<u8>::empty());
        }
        out
    }
    pub fn is_done(&self) -> (out: bool) ensures out == self.done() { self.phase == Phase::Done }
    pub fn is_failed(&self) -> (out: bool) ensures out == self.failed() { self.phase == Phase::Failed }

    /// A finished decoder consumed one chunked body for exactly the body it emitted.
    pub proof fn lemma_done_is_chunked(&self)
        requires self.valid(), self.done(),
        ensures chunked_ok(self.fed(), self.body()),
    {
        let fed = self.fed();
        let k = self.done_bytes@.len() as int;
        assert(fed.subrange(0, k) =~= self.done_bytes@);
        assert(fed.skip(k) =~= self.tail());
        assert(self.body() =~= self.done_body@);
        let tail = self.tail();
        let e = self.line@.len() as int;
        assert(tail[e] == CR && tail[e + 1] == LF && tail[e + 2] == CR && tail[e + 3] == LF);
        assert(tail.subrange(0, e) =~= self.line@);
        self.lemma_line_is_size_line();
        assert(crate::http1_head::crlf_at(tail, e));
        assert(crate::http1_head::crlf_at(tail, e + 2));
        assert(last_chunk_ok(tail));
        assert(chunked_ok(fed, self.body()));
    }

    /// After a chunk's final LF, the chunk in progress is a chunk of the grammar
    /// and extends the finished history.
    proof fn lemma_fold_chunk(&self)
        requires self.valid(), self.phase == Phase::DataLf,
        ensures ({
            let chunk = self.line@ + seq![CR, LF] + self.partial@ + seq![CR, LF];
            chunk_ok(chunk, self.partial@) && chunks_ok(self.done_bytes@ + chunk, self.done_body@ + self.partial@)
        }),
    {
        reveal(chunk_ok);
        let chunk = self.line@ + seq![CR, LF] + self.partial@ + seq![CR, LF];
        self.lemma_line_is_size_line();
        let e = self.line@.len() as int;
        let n = self.partial@.len() as int;
        assert(chunk.subrange(0, e) =~= self.line@);
        assert(chunk[e] == CR && chunk[e + 1] == LF);
        assert(chunk.subrange(e + 2, e + 2 + n) =~= self.partial@);
        assert(chunk[e + 2 + n] == CR && chunk[e + 3 + n] == LF);
        assert(crate::http1_head::crlf_at(chunk, e));
        assert(crate::http1_head::crlf_at(chunk, e + 2 + n));
        assert(chunk_ok(chunk, self.partial@));
        lemma_chunks_append(self.done_bytes@, self.done_body@, chunk, self.partial@);
    }

    /// With at least one digit, the line in progress is a size line for `size`, clean of breaks.
    proof fn lemma_line_is_size_line(&self)
        requires self.digits >= 1, self.line_shape(false) || self.line_shape(true),
        ensures size_line_ok(self.line@, self.size as nat), crate::http1_head::clean(self.line@),
    {
        let line = self.line@;
        let d = self.digits as int;
        assert(size_split(line, self.size as nat, d));
        assert forall|k: int| 0 <= k < line.len() implies !crate::http1_head::is_break(#[trigger] line[k]) by {
            if k < d { assert(line.subrange(0, d)[k] == line[k]); assert(is_hex(line[k])); }
        }
    }

    /// What one `feed` call establishes: the decoder stays valid, the
    /// consumed bytes and emitted body grow exactly as the step reports, a
    /// data step takes all it can, the body completes only from the last LF,
    /// and a rejection happens exactly when the phase does not accept the byte.
    pub open spec fn step_ok(before: Self, after: Self, input: Seq<u8>, out: Step) -> bool {
        after.valid() && match out {
            Step::Framing(n) => n == 1 && after.fed() == before.fed() + input.subrange(0, 1) && after.body() == before.body()
                && !after.done() && !after.failed() && before.phase() != Phase::LastLf
                && after.framing_budget() < before.framing_budget(),
            Step::Data(n) => 1 <= n <= input.len() && after.fed() == before.fed() + input.subrange(0, n as int)
                && after.body() == before.body() + input.subrange(0, n as int) && !after.done() && !after.failed()
                && before.phase() == Phase::Data && n == if before.pending() < input.len() { before.pending() } else { input.len() as nat },
            Step::Done(n) => n == 1 && after.fed() == before.fed() + input.subrange(0, 1) && after.body() == before.body()
                && after.done() && chunked_ok(after.fed(), after.body()) && before.phase() == Phase::LastLf,
            Step::Rejected => after.failed() && !before.accepts(input[0]),
        }
    }

    /// Consume from the front of `input`: one framing byte, or a run of data bytes.
    pub fn feed(&mut self, input: &[u8]) -> (out: Step)
        requires old(self).valid(), !old(self).done(), !old(self).failed(), input.len() >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, out),
    {
        match self.phase {
            Phase::Size => self.step_size(input),
            Phase::Ext => self.step_ext(input),
            Phase::SizeCr => self.step_size_cr(input),
            Phase::Data => self.step_data(input),
            Phase::DataCr => self.step_data_cr(input),
            Phase::DataLf => self.step_data_lf(input),
            Phase::LastCr => self.step_last_cr(input),
            Phase::LastLf => self.step_last_lf(input),
            Phase::Done | Phase::Failed => self.reject(),
        }
    }

    fn step_size(&mut self, input: &[u8]) -> (out: Step)
        requires old(self).valid(), old(self).phase == Phase::Size, input.len() >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, out),
    {
        let b = input[0];
        let ghost one = input@.subrange(0, 1);
        proof { assert(one =~= seq![b]); }
        if is_hex_byte(b) {
            if self.digits >= MAX_SIZE_DIGITS { return self.reject(); }
            proof {
                assert(self.line@.subrange(0, self.digits as int) =~= self.line@);
                lemma_hex_value_bound(self.line@);
                lemma_pow16_values();
                lemma_pow16_monotone(self.digits as nat, 15);
                assert(self.size < pow16(15));
            }
            let v = hex_byte_val(b);
            let ghost before = *self;
            self.size = self.size * 16 + v;
            self.digits = self.digits + 1;
            self.line_len = self.line_len + 1;
            self.line = Ghost(before.line@.push(b));
            proof {
                let d = before.digits as int;
                assert(self.line@.subrange(0, d + 1) =~= self.line@);
                assert(self.line@.drop_last() =~= before.line@);
                assert(before.line@.subrange(0, d) =~= before.line@);
                assert forall|k: int| 0 <= k < d + 1 implies is_hex(#[trigger] self.line@[k]) by {
                    if k < d { assert(self.line@[k] == before.line@[k]); } else { assert(self.line@[k] == b); }
                }
                assert(hex_value(self.line@) == hex_value(before.line@) * 16 + hex_val(b));
                assert(self.line_shape(false));
                assert(self.fed() =~= before.fed() + one);
                assert(self.valid());
                assert(Self::step_ok(before, *self, input@, Step::Framing(1)));
            }
            Step::Framing(1)
        } else if b == SEMICOLON {
            if self.digits == 0 { return self.reject(); }
            let ghost before = *self;
            self.phase = Phase::Ext;
            self.line_len = self.line_len + 1;
            self.line = Ghost(before.line@.push(b));
            proof {
                let d = before.digits as int;
                assert(before.line@.subrange(0, d) =~= before.line@);
                assert(self.line@.subrange(0, d) =~= before.line@);
                assert(self.line@[d] == SEMICOLON);
                assert(self.line_shape(true));
                assert(self.fed() =~= before.fed() + one);
                assert(self.valid());
                assert(Self::step_ok(before, *self, input@, Step::Framing(1)));
            }
            Step::Framing(1)
        } else if b == CR {
            if self.digits == 0 { return self.reject(); }
            let ghost before = *self;
            self.phase = Phase::SizeCr;
            proof {
                assert(self.fed() =~= before.fed() + one);
                assert(self.valid());
                assert(Self::step_ok(before, *self, input@, Step::Framing(1)));
            }
            Step::Framing(1)
        } else { self.reject() }
    }

    fn step_ext(&mut self, input: &[u8]) -> (out: Step)
        requires old(self).valid(), old(self).phase == Phase::Ext, input.len() >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, out),
    {
        let b = input[0];
        let ghost one = input@.subrange(0, 1);
        proof { assert(one =~= seq![b]); }
        if b == CR {
            let ghost before = *self;
            self.phase = Phase::SizeCr;
            proof { assert(self.fed() =~= before.fed() + one); }
            Step::Framing(1)
        } else if crate::http1_head::value_byte_exec(b) {
            if self.line_len >= MAX_SIZE_LINE { return self.reject(); }
            let ghost before = *self;
            self.line_len = self.line_len + 1;
            self.line = Ghost(before.line@.push(b));
            proof {
                let d = before.digits as int;
                assert(self.line@.subrange(0, d) =~= before.line@.subrange(0, d));
                assert(self.fed() =~= before.fed() + one);
            }
            Step::Framing(1)
        } else { self.reject() }
    }

    fn step_size_cr(&mut self, input: &[u8]) -> (out: Step)
        requires old(self).valid(), old(self).phase == Phase::SizeCr, input.len() >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, out),
    {
        let b = input[0];
        let ghost one = input@.subrange(0, 1);
        proof { assert(one =~= seq![b]); }
        if b != LF { return self.reject(); }
        let ghost before = *self;
        if self.size == 0 { self.phase = Phase::LastCr; } else { self.phase = Phase::Data; self.remaining = self.size; }
        proof { assert(self.fed() =~= before.fed() + one); }
        Step::Framing(1)
    }

    fn step_data(&mut self, input: &[u8]) -> (out: Step)
        requires old(self).valid(), old(self).phase == Phase::Data, input.len() >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, out),
    {
        let n: usize = if self.remaining < input.len() as u64 { self.remaining as usize } else { input.len() };
        let ghost before = *self;
        self.remaining = self.remaining - n as u64;
        self.partial = Ghost(before.partial@ + input@.subrange(0, n as int));
        if self.remaining == 0 { self.phase = Phase::DataCr; }
        proof {
            assert(self.fed() =~= before.fed() + input@.subrange(0, n as int));
            assert(self.body() =~= before.body() + input@.subrange(0, n as int));
        }
        Step::Data(n)
    }

    fn step_data_cr(&mut self, input: &[u8]) -> (out: Step)
        requires old(self).valid(), old(self).phase == Phase::DataCr, input.len() >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, out),
    {
        let b = input[0];
        let ghost one = input@.subrange(0, 1);
        proof { assert(one =~= seq![b]); }
        if b != CR { return self.reject(); }
        let ghost before = *self;
        self.phase = Phase::DataLf;
        proof { assert(self.fed() =~= before.fed() + one); }
        Step::Framing(1)
    }

    fn step_data_lf(&mut self, input: &[u8]) -> (out: Step)
        requires old(self).valid(), old(self).phase == Phase::DataLf, input.len() >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, out),
    {
        let b = input[0];
        let ghost one = input@.subrange(0, 1);
        proof { assert(one =~= seq![b]); }
        if b != LF { return self.reject(); }
        let ghost before = *self;
        // The chunk is complete: fold it into the finished history.
        let ghost chunk = before.line@ + seq![CR, LF] + before.partial@ + seq![CR, LF];
        proof { before.lemma_fold_chunk(); }
        self.phase = Phase::Size;
        self.size = 0;
        self.digits = 0;
        self.line_len = 0;
        self.done_bytes = Ghost(before.done_bytes@ + chunk);
        self.done_body = Ghost(before.done_body@ + before.partial@);
        self.line = Ghost(Seq::empty());
        self.partial = Ghost(Seq::empty());
        proof {
            assert(self.line@.subrange(0, 0) =~= Seq::<u8>::empty());
            assert(self.fed() =~= before.fed() + one);
            assert(self.body() =~= before.body());
        }
        Step::Framing(1)
    }

    fn step_last_cr(&mut self, input: &[u8]) -> (out: Step)
        requires old(self).valid(), old(self).phase == Phase::LastCr, input.len() >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, out),
    {
        let b = input[0];
        let ghost one = input@.subrange(0, 1);
        proof { assert(one =~= seq![b]); }
        if b != CR { return self.reject(); }
        let ghost before = *self;
        self.phase = Phase::LastLf;
        proof { assert(self.fed() =~= before.fed() + one); }
        Step::Framing(1)
    }

    fn step_last_lf(&mut self, input: &[u8]) -> (out: Step)
        requires old(self).valid(), old(self).phase == Phase::LastLf, input.len() >= 1,
        ensures Self::step_ok(*old(self), *final(self), input@, out),
    {
        let b = input[0];
        let ghost one = input@.subrange(0, 1);
        proof { assert(one =~= seq![b]); }
        if b != LF { return self.reject(); }
        let ghost before = *self;
        self.phase = Phase::Done;
        proof {
            assert(self.fed() =~= before.fed() + one);
            self.lemma_done_is_chunked();
        }
        Step::Done(1)
    }

    fn reject(&mut self) -> (out: Step)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).failed(), out == Step::Rejected,
    {
        self.phase = Phase::Failed;
        Step::Rejected
    }
}

fn is_hex_byte(b: u8) -> (out: bool) ensures out == is_hex(b) { (b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102) }
fn hex_byte_val(b: u8) -> (out: u64)
    requires is_hex(b),
    ensures out == hex_val(b), out < 16,
{
    if b >= 48 && b <= 57 { (b - 48) as u64 } else if b >= 65 && b <= 70 { (b - 55) as u64 } else { (b - 87) as u64 }
}

/// A hex string's value is below sixteen to its length.
proof fn lemma_hex_value_bound(s: Seq<u8>)
    requires all_hex(s),
    ensures hex_value(s) < pow16(s.len()),
    decreases s.len(),
{
    if s.len() > 0 {
        assert(all_hex(s.drop_last()));
        lemma_hex_value_bound(s.drop_last());
        assert(hex_val(s.last()) < 16);
        assert(hex_value(s.drop_last()) * 16 + 16 <= pow16(s.drop_last().len()) * 16) by (nonlinear_arith)
            requires hex_value(s.drop_last()) < pow16(s.drop_last().len());
    }
}
proof fn lemma_pow16_monotone(a: nat, b: nat)
    requires a <= b,
    ensures pow16(a) <= pow16(b),
    decreases b - a,
{
    if a < b { lemma_pow16_monotone(a, (b - 1) as nat); }
}
proof fn lemma_pow16_values()
    ensures pow16(15) == 0x1000000000000000, pow16(16) == 0x10000000000000000,
{
    assert(pow16(15) == 0x1000000000000000) by (compute_only);
    assert(pow16(16) == 0x10000000000000000) by (compute_only);
}

/// A chunk has some bytes and some data.
proof fn lemma_chunk_lengths(chunk: Seq<u8>, data: Seq<u8>)
    requires chunk_ok(chunk, data),
    ensures chunk.len() >= 1, data.len() >= 1,
{
    reveal(chunk_ok);
    let e = choose|e: int| #[trigger] crate::http1_head::crlf_at(chunk, e) && crate::http1_head::clean(chunk.subrange(0, e))
        && size_line_ok(chunk.subrange(0, e), data.len()) && data.len() >= 1
        && chunk.len() == e + 2 + data.len() + 2 && chunk.subrange(e + 2, e + 2 + data.len()) == data
        && crate::http1_head::crlf_at(chunk, e + 2 + data.len());
}
/// One chunk is a run of chunks.
pub proof fn lemma_chunks_single(chunk: Seq<u8>, data: Seq<u8>)
    requires chunk_ok(chunk, data),
    ensures chunks_ok(chunk, data),
{
    lemma_chunk_lengths(chunk, data);
    let k = chunk.len() as int;
    let n = data.len() as int;
    assert(chunk.subrange(0, k) =~= chunk);
    assert(data.subrange(0, n) =~= data);
    assert(chunk.skip(k) =~= Seq::<u8>::empty());
    assert(data.skip(n) =~= Seq::<u8>::empty());
    assert(chunks_ok(Seq::<u8>::empty(), Seq::<u8>::empty()));
    assert(chunk_ok(chunk.subrange(0, k), data.subrange(0, n)));
}
/// Appending a chunk to a run of chunks gives a run of chunks.
pub proof fn lemma_chunks_append(bytes: Seq<u8>, body: Seq<u8>, chunk: Seq<u8>, data: Seq<u8>)
    requires chunks_ok(bytes, body), chunk_ok(chunk, data),
    ensures chunks_ok(bytes + chunk, body + data),
    decreases bytes.len(),
{
    if bytes.len() == 0 {
        assert(body.len() == 0);
        assert(bytes + chunk =~= chunk);
        assert(body + data =~= data);
        lemma_chunks_single(chunk, data);
    } else {
        let (k, n) = choose|k: int, n: int| 0 < k <= bytes.len() && 0 < n <= body.len()
            && #[trigger] chunk_ok(bytes.subrange(0, k), body.subrange(0, n)) && chunks_ok(bytes.skip(k), body.skip(n));
        lemma_chunks_append(bytes.skip(k), body.skip(n), chunk, data);
        let all = bytes + chunk;
        let whole = body + data;
        assert(all.subrange(0, k) =~= bytes.subrange(0, k));
        assert(whole.subrange(0, n) =~= body.subrange(0, n));
        assert(all.skip(k) =~= bytes.skip(k) + chunk);
        assert(whole.skip(n) =~= body.skip(n) + data);
        assert(chunk_ok(all.subrange(0, k), whole.subrange(0, n)));
        assert(chunks_ok(all.skip(k), whole.skip(n)));
    }
}

// ---- encoder ---------------------------------------------------------------

/// The framing the gateway writes for one chunk of data: size, CRLF, data, CRLF.
pub open spec fn chunk_bytes(data: Seq<u8>) -> Seq<u8> { hex_digits(data.len()) + seq![CR, LF] + data + seq![CR, LF] }
/// The last chunk the gateway writes.
pub open spec fn last_chunk_bytes() -> Seq<u8> { seq![48u8, CR, LF, CR, LF] }

/// The hex size line and CRLF for a chunk of `len` bytes.
pub fn write_chunk_header(len: usize, out: &mut Vec<u8>)
    ensures final(out)@ == old(out)@ + hex_digits(len as nat) + seq![CR, LF],
{
    // Least significant digit first, then reversed onto the output.
    let mut digits: Vec<u8> = Vec::new();
    let mut n: usize = len;
    if n < 16 {
        out.push(hex_digit_exec(n as u64));
        proof { assert(out@ =~= old(out)@ + hex_digits(len as nat)); }
    } else {
        while n >= 16
            invariant hex_digits(len as nat) == hex_digits(n as nat) + rev(digits@),
            decreases n,
        {
            let d = hex_digit_exec((n % 16) as u64);
            proof {
                assert(hex_digits(n as nat) == hex_digits((n / 16) as nat).push(hex_digit((n % 16) as nat)));
                assert(hex_digits((n / 16) as nat).push(d) + rev(digits@) =~= hex_digits((n / 16) as nat) + rev(digits@.push(d)));
            }
            digits.push(d);
            n = n / 16;
        }
        let d = hex_digit_exec(n as u64);
        proof {
            assert(hex_digits(n as nat) == seq![hex_digit(n as nat)]);
            assert(seq![d] + rev(digits@) =~= rev(digits@.push(d)));
        }
        digits.push(d);
        proof { assert(hex_digits(len as nat) == rev(digits@)); }
        let mut i: usize = digits.len();
        while i > 0
            invariant i <= digits.len(), out@ == old(out)@ + rev(digits@).subrange(0, digits.len() - i),
            decreases i,
        {
            out.push(digits[i - 1]);
            proof {
                assert(rev(digits@)[digits.len() - i] == digits@[i - 1]);
                assert(old(out)@ + rev(digits@).subrange(0, digits.len() - i) + seq![digits@[i - 1]] =~= old(out)@ + rev(digits@).subrange(0, digits.len() - i + 1));
            }
            i = i - 1;
        }
        proof { assert(rev(digits@).subrange(0, digits.len() as int) =~= rev(digits@)); }
    }
    out.push(CR); out.push(LF);
    proof { assert(out@ =~= old(out)@ + hex_digits(len as nat) + seq![CR, LF]); }
}
/// The CRLF after a chunk's data.
pub fn write_chunk_end(out: &mut Vec<u8>)
    ensures final(out)@ == old(out)@ + seq![CR, LF],
{
    out.push(CR); out.push(LF);
    proof { assert(out@ =~= old(out)@ + seq![CR, LF]); }
}
/// `0` CRLF CRLF: the last chunk and the empty line.
pub fn write_last_chunk(out: &mut Vec<u8>)
    ensures final(out)@ == old(out)@ + last_chunk_bytes(),
{
    out.push(48); out.push(CR); out.push(LF); out.push(CR); out.push(LF);
    proof { assert(out@ =~= old(out)@ + last_chunk_bytes()); }
}
fn hex_digit_exec(d: u64) -> (out: u8)
    requires d < 16,
    ensures out == hex_digit(d as nat),
{
    if d < 10 { (48 + d) as u8 } else { (87 + d) as u8 }
}
pub open spec fn rev(s: Seq<u8>) -> Seq<u8> { Seq::new(s.len(), |i: int| s[s.len() - 1 - i]) }

/// The gateway's chunk framing is a chunk of the grammar the decoder accepts.
pub proof fn lemma_chunk_bytes_ok(data: Seq<u8>)
    requires 1 <= data.len() <= u64::MAX,
    ensures chunk_ok(chunk_bytes(data), data),
{
    reveal(chunk_ok);
    let n = data.len() as nat;
    let line = hex_digits(n);
    lemma_hex_digits_shape(n);
    lemma_pow16_values();
    lemma_hex_digits_lower(n);
    if line.len() > 16 {
        lemma_pow16_monotone(16, (line.len() - 1) as nat);
        assert(n >= pow16(16));
        assert(false);
    }
    let bytes = chunk_bytes(data);
    let e = line.len() as int;
    assert(bytes.subrange(0, e) =~= line);
    assert(bytes[e] == CR && bytes[e + 1] == LF);
    assert(crate::http1_head::crlf_at(bytes, e));
    assert forall|k: int| 0 <= k < line.len() implies !crate::http1_head::is_break(#[trigger] line[k]) by { assert(is_hex(line[k])); }
    assert(line.subrange(0, e) =~= line);
    assert(size_split(line, n, e));
    assert(bytes.subrange(e + 2, e + 2 + data.len()) =~= data);
    assert(bytes[e + 2 + data.len()] == CR && bytes[e + 3 + data.len()] == LF);
    assert(crate::http1_head::crlf_at(bytes, e + 2 + data.len()));
}
/// The last chunk the gateway writes is the grammar's last chunk.
pub proof fn lemma_last_chunk_bytes_ok()
    ensures last_chunk_ok(last_chunk_bytes()),
{
    let bytes = last_chunk_bytes();
    assert(bytes.subrange(0, 1) =~= seq![48u8]);
    assert(seq![48u8].subrange(0, 1) =~= seq![48u8]);
    assert(seq![48u8].drop_last() =~= Seq::<u8>::empty());
    assert(seq![48u8].last() == 48u8);
    assert(hex_value(Seq::<u8>::empty()) == 0);
    assert(hex_value(seq![48u8]) == 0);
    assert(size_split(seq![48u8], 0, 1));
    assert(crate::http1_head::crlf_at(bytes, 1));
    assert(crate::http1_head::crlf_at(bytes, 3));
}
/// Hex digits are hex and spell their number.
proof fn lemma_hex_digits_shape(n: nat)
    ensures hex_digits(n).len() >= 1, all_hex(hex_digits(n)), hex_value(hex_digits(n)) == n,
    decreases n,
{
    if n < 16 {
        let s = hex_digits(n);
        assert(s =~= seq![hex_digit(n)]);
        assert(s.drop_last() =~= Seq::<u8>::empty());
        assert(s.last() == hex_digit(n));
        assert(hex_value(Seq::<u8>::empty()) == 0);
        assert(hex_val(hex_digit(n)) == n);
    } else {
        lemma_hex_digits_shape(n / 16);
        let d = hex_digits(n / 16);
        let s = hex_digits(n);
        assert(s == d.push(hex_digit(n % 16)));
        assert(s.drop_last() =~= d);
        assert(s.last() == hex_digit(n % 16));
        assert(hex_val(hex_digit(n % 16)) == n % 16);
        assert(hex_value(s) == hex_value(d) * 16 + n % 16);
        assert(n == (n / 16) * 16 + n % 16) by (nonlinear_arith);
    }
}
/// A nonzero number is at least sixteen to one less than its digit count.
proof fn lemma_hex_digits_lower(n: nat)
    requires n >= 1,
    ensures hex_digits(n).len() >= 1, n >= pow16((hex_digits(n).len() - 1) as nat),
    decreases n,
{
    if n >= 16 {
        lemma_hex_digits_lower(n / 16);
        let inner = hex_digits(n / 16).len();
        assert(hex_digits(n).len() == inner + 1);
        let q = n / 16;
        let base = pow16((inner - 1) as nat);
        assert(pow16(inner as nat) == base * 16);
        assert(16 * q <= n);
        assert(q >= base);
        assert(16 * q >= 16 * base) by (nonlinear_arith) requires q >= base;
        assert(n >= pow16(inner as nat));
    }
}
}

mod complete;
