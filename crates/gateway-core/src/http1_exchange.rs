//! Verified HTTP/1.1 exchange machines. The codec modules prove what the
//! bytes of a head, a framing field, and a chunked body mean; this module
//! proves the gateway's own decisions about an exchange, so the runtime
//! performs them instead of making them:
//!
//! - which status answers which refusal or fault (`refusal_status`,
//!   `failure_status`), and when a `100 Continue` is due (`wants_continue`);
//! - how an upstream status is classified (`upstream_status`): interim,
//!   refused protocol switch, bodiless, or framed by its fields;
//! - the response a connection writes (`Connection`): at most one head, only
//!   while nothing else has been written, always with `Connection: close`
//!   and framing matching the body, except that 204/304 have neither a body
//!   nor framing headers; a streamed body ends cleanly only through
//!   the last chunk;
//! - the request the transport writes (`Upstream`): one head with the
//!   verified projection's fields plus chunked framing and `Connection:
//!   close`, then chunks, then the last chunk;
//! - the chunked body both of them stream (`ChunkStream`): the bytes handed
//!   out are one well-formed chunked encoding of exactly the frames given.
//!
//! The runtime writes the returned bytes in the order it receives them;
//! that ordering, and the sockets themselves, remain trusted.
use vstd::prelude::*;
use crate::exchange_lifecycle::Fault;
use crate::headers::{Field, MAX_BYTES, MAX_FIELDS};
use crate::http1_chunked::{write_chunk_end, write_chunk_header, write_last_chunk};
use crate::http1_framing::{Framing, framing};
use crate::http1_head::value_byte_exec;
use crate::http1_write::{wire_ok, write_request_head, write_status_head};

verus! {
// ---- decisions ------------------------------------------------------------

/// Why a request is refused before any provider contact.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Refusal {
    /// The head exceeded 32 KiB or 100 fields.
    HeadTooLarge,
    /// The head, its framing, or its route or token did not parse.
    Malformed,
    /// The token is unknown or not granted this route.
    Unauthorized,
    /// Only POST reaches a provider.
    MethodNotAllowed,
    /// No request slot, no worker, no response permit, or strict logging is unavailable.
    Unavailable,
}
/// The status answering a refusal. Total, and every value is one the
/// gateway means: 431, 400, 401, 405, or 503.
pub fn refusal_status(refusal: Refusal) -> (out: u16)
    ensures out == refusal_status_spec(refusal),
{
    match refusal {
        Refusal::HeadTooLarge => 431,
        Refusal::Malformed => 400,
        Refusal::Unauthorized => 401,
        Refusal::MethodNotAllowed => 405,
        Refusal::Unavailable => 503,
    }
}
pub open spec fn refusal_status_spec(refusal: Refusal) -> u16 {
    match refusal {
        Refusal::HeadTooLarge => 431,
        Refusal::Malformed => 400,
        Refusal::Unauthorized => 401,
        Refusal::MethodNotAllowed => 405,
        Refusal::Unavailable => 503,
    }
}
/// The status answering a failed exchange before its response head: a passed
/// deadline is 504, every other fault is 502.
pub fn failure_status(fault: Fault) -> (out: u16)
    ensures out == (if fault == Fault::Timeout { 504u16 } else { 502u16 }),
{
    if fault == Fault::Timeout { 504 } else { 502 }
}

pub const EXPECT: [u8; 6] = *b"expect";
pub const CONTINUE: [u8; 12] = *b"100-continue";
/// Some Expect field says `100-continue`, in any case.
pub open spec fn expects_continue(fields: Seq<Field>) -> bool {
    exists|i: int| 0 <= i < fields.len() && #[trigger] fields[i].name@ == EXPECT@ && crate::headers::lower_seq(fields[i].value@) == CONTINUE@
}
/// Whether the request asked for `100 Continue` before sending its body.
pub fn wants_continue(fields: &Vec<Field>) -> (out: bool)
    ensures out == expects_continue(fields@),
{
    let mut i: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(),
            forall|j: int| 0 <= j < i ==> !(#[trigger] fields@[j].name@ == EXPECT@ && crate::headers::lower_seq(fields@[j].value@) == CONTINUE@),
        decreases fields.len() - i,
    {
        if crate::headers::eq(fields[i].name.as_slice(), EXPECT.as_slice()) {
            let lower = crate::headers::lowercase(fields[i].value.as_slice());
            if crate::headers::eq(lower.as_slice(), CONTINUE.as_slice()) { return true; }
        }
        i = i + 1;
    }
    false
}

/// What an upstream status head means for the exchange.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum UpstreamStatus {
    /// A 1xx other than 101: skip it and read the next head.
    Interim,
    /// 101, or a head whose framing is ambiguous or unsupported: fail the exchange.
    Refused,
    /// 204 or 304: the status is forwarded and no body follows.
    Bodiless,
    /// A final status whose body is framed as given.
    Framed(Framing),
}
/// Classify an upstream status with its fields. Total.
pub fn upstream_status(status: u16, fields: &Vec<Field>) -> (out: UpstreamStatus)
    ensures
        status == 101 ==> out == UpstreamStatus::Refused,
        (status < 200 && status != 101) ==> out == UpstreamStatus::Interim,
        (status == 204 || status == 304) ==> out == UpstreamStatus::Bodiless,
        (status >= 200 && status != 204 && status != 304) ==> (match out {
            UpstreamStatus::Framed(f) => crate::http1_framing::framing_spec_ok(fields@, f),
            UpstreamStatus::Refused => crate::http1_framing::framing_spec_refused(fields@),
            _ => false,
        }),
{
    if status == 101 { return UpstreamStatus::Refused; }
    if status < 200 { return UpstreamStatus::Interim; }
    if status == 204 || status == 304 { return UpstreamStatus::Bodiless; }
    match framing(fields, false) {
        Ok(f) => UpstreamStatus::Framed(f),
        Err(_) => UpstreamStatus::Refused,
    }
}

// ---- framing fields --------------------------------------------------------

pub const CONNECTION: [u8; 10] = *b"connection";
pub const CLOSE: [u8; 5] = *b"close";
pub const TRANSFER_ENCODING: [u8; 17] = *b"transfer-encoding";
pub const CHUNKED: [u8; 7] = *b"chunked";
pub const CONTENT_LENGTH: [u8; 14] = *b"content-length";
pub open spec fn is_close(f: Field) -> bool { f.name@ == CONNECTION@ && f.value@ == CLOSE@ }
pub open spec fn is_chunked(f: Field) -> bool { f.name@ == TRANSFER_ENCODING@ && f.value@ == CHUNKED@ }
pub open spec fn is_length(f: Field, n: nat) -> bool { f.name@ == CONTENT_LENGTH@ && f.value@ == crate::inbound::decimal(n) }
fn close_field() -> (out: Field) ensures is_close(out) {
    Field { name: slice_to_vec(CONNECTION.as_slice()), value: slice_to_vec(CLOSE.as_slice()), sensitive: false }
}
fn chunked_field() -> (out: Field) ensures is_chunked(out) {
    Field { name: slice_to_vec(TRANSFER_ENCODING.as_slice()), value: slice_to_vec(CHUNKED.as_slice()), sensitive: false }
}
fn length_field(n: usize) -> (out: Field) ensures is_length(out, n as nat) {
    Field { name: slice_to_vec(CONTENT_LENGTH.as_slice()), value: decimal_bytes(n as u64), sensitive: false }
}
fn slice_to_vec(s: &[u8]) -> (out: Vec<u8>) ensures out@ == s@ { vstd::slice::slice_to_vec(s) }
pub open spec fn rev(s: Seq<u8>) -> Seq<u8> { Seq::new(s.len(), |i: int| s[s.len() - 1 - i]) }
/// The canonical decimal of `n`.
pub fn decimal_bytes(n: u64) -> (out: Vec<u8>)
    ensures out@ == crate::inbound::decimal(n as nat),
{
    let mut digits: Vec<u8> = Vec::new();
    let ghost original = n as nat;
    let mut n = n;
    proof { assert(rev(digits@) =~= Seq::<u8>::empty()); }
    while n >= 10
        invariant crate::inbound::decimal(original) == crate::inbound::decimal(n as nat) + rev(digits@),
        decreases n,
    {
        let d = (48 + n % 10) as u8;
        proof {
            assert(crate::inbound::decimal(n as nat) == crate::inbound::decimal((n / 10) as nat).push(d));
            assert(crate::inbound::decimal((n / 10) as nat).push(d) + rev(digits@) =~= crate::inbound::decimal((n / 10) as nat) + rev(digits@.push(d)));
        }
        digits.push(d);
        n = n / 10;
    }
    let d = (48 + n) as u8;
    proof {
        assert(crate::inbound::decimal(n as nat) == seq![d]);
        assert(seq![d] + rev(digits@) =~= rev(digits@.push(d)));
    }
    digits.push(d);
    let mut out: Vec<u8> = Vec::new();
    let mut i: usize = digits.len();
    while i > 0
        invariant i <= digits.len(), out@ == rev(digits@).subrange(0, digits.len() - i),
        decreases i,
    {
        out.push(digits[i - 1]);
        proof {
            assert(rev(digits@)[digits.len() - i] == digits@[i - 1]);
            assert(rev(digits@).subrange(0, digits.len() - i) + seq![digits@[i - 1]] =~= rev(digits@).subrange(0, digits.len() - i + 1));
        }
        i = i - 1;
    }
    proof { assert(rev(digits@).subrange(0, digits.len() as int) =~= rev(digits@)); }
    out
}

/// Every byte of a reason phrase is a value byte.
fn reason_fits(reason: &[u8]) -> (out: bool)
    ensures out == crate::http1_write::reason_ok(reason@),
{
    let mut k: usize = 0;
    while k < reason.len()
        invariant k <= reason.len(), forall|j: int| 0 <= j < k ==> crate::http1_head::is_value_byte(#[trigger] reason@[j]),
        decreases reason.len() - k,
    {
        if !value_byte_exec(reason[k]) { return false; }
        k = k + 1;
    }
    true
}

// ---- chunked body stream ---------------------------------------------------

/// A streamed body: each `frame` yields one chunk, `end` yields the last
/// chunk, and the bytes yielded so far are always a run of chunks of exactly
/// the frames given; after `end` they are one complete chunked body.
pub struct ChunkStream { ended: bool, out: Ghost<Seq<u8>>, body: Ghost<Seq<u8>> }
impl ChunkStream {
    /// Every byte yielded so far.
    pub closed spec fn out(&self) -> Seq<u8> { self.out@ }
    /// Every frame byte given so far.
    pub closed spec fn body(&self) -> Seq<u8> { self.body@ }
    pub closed spec fn ended(&self) -> bool { self.ended }
    pub closed spec fn valid(&self) -> bool {
        if self.ended { crate::http1_chunked::chunked_ok(self.out@, self.body@) } else { crate::http1_chunked::chunks_ok(self.out@, self.body@) }
    }
    pub fn new() -> (out: Self)
        ensures out.valid(), !out.ended(), out.out() == Seq::<u8>::empty(), out.body() == Seq::<u8>::empty(),
    { ChunkStream { ended: false, out: Ghost(Seq::empty()), body: Ghost(Seq::empty()) } }
    pub fn is_ended(&self) -> (out: bool) ensures out == self.ended() { self.ended }
    /// One chunk for `data`.
    pub fn frame(&mut self, data: &[u8]) -> (bytes: Vec<u8>)
        requires old(self).valid(), !old(self).ended(), data.len() >= 1,
        ensures final(self).valid(), !final(self).ended(), bytes@ == crate::http1_chunked::chunk_bytes(data@),
            final(self).out() == old(self).out() + bytes@, final(self).body() == old(self).body() + data@,
    {
        let mut bytes: Vec<u8> = Vec::new();
        write_chunk_header(data.len(), &mut bytes);
        let mut k: usize = 0;
        while k < data.len()
            invariant k <= data.len(), bytes@ == crate::http1_chunked::hex_digits(data@.len()) + seq![crate::http1_head::CR, crate::http1_head::LF] + data@.subrange(0, k as int),
            decreases data.len() - k,
        {
            bytes.push(data[k]);
            proof { assert(bytes@ =~= crate::http1_chunked::hex_digits(data@.len()) + seq![crate::http1_head::CR, crate::http1_head::LF] + data@.subrange(0, k as int + 1)); }
            k = k + 1;
        }
        proof { assert(data@.subrange(0, data@.len() as int) =~= data@); }
        write_chunk_end(&mut bytes);
        proof {
            assert(bytes@ =~= crate::http1_chunked::chunk_bytes(data@));
            crate::http1_chunked::lemma_chunk_bytes_ok(data@);
            crate::http1_chunked::lemma_chunks_append(self.out@, self.body@, bytes@, data@);
        }
        self.out = Ghost(self.out@ + bytes@);
        self.body = Ghost(self.body@ + data@);
        bytes
    }
    /// The last chunk; the body is complete.
    pub fn end(&mut self) -> (bytes: Vec<u8>)
        requires old(self).valid(), !old(self).ended(),
        ensures final(self).valid(), final(self).ended(), bytes@ == crate::http1_chunked::last_chunk_bytes(),
            final(self).out() == old(self).out() + bytes@, final(self).body() == old(self).body(),
            crate::http1_chunked::chunked_ok(final(self).out(), final(self).body()),
    {
        let mut bytes: Vec<u8> = Vec::new();
        write_last_chunk(&mut bytes);
        proof {
            let all = self.out@ + bytes@;
            let k = self.out@.len() as int;
            assert(all.subrange(0, k) =~= self.out@);
            assert(all.skip(k) =~= bytes@);
            crate::http1_chunked::lemma_last_chunk_bytes_ok();
            assert(crate::http1_chunked::chunked_ok(all, self.body@));
        }
        self.out = Ghost(self.out@ + bytes@);
        self.ended = true;
        bytes
    }
}

// ---- the connection's response -----------------------------------------------

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
enum Phase { Open, Streaming, Done, Aborted }

/// The head fields the writers add: the given fields, then `Connection: close`,
/// then the framing field.
pub open spec fn head_fields_ok(all: Seq<Field>, given: Seq<Field>, chunked: bool, length: nat) -> bool {
    all.len() == given.len() + 2 && all.take(given.len() as int) == given
        && is_close(all[given.len() as int])
        && (if chunked { is_chunked(all[given.len() as int + 1]) } else { is_length(all[given.len() as int + 1], length) })
}

/// No Content-Length or Transfer-Encoding on a bodiless forwarded response.
/// A 304 length would describe the selected representation, which this writer
/// does not know, so it omits the optional field rather than inventing zero.
pub open spec fn no_framing(fields: Seq<Field>) -> bool {
    forall|i: int| 0 <= i < fields.len() ==> #[trigger] fields[i].name@ != CONTENT_LENGTH@
        && fields[i].name@ != TRANSFER_ENCODING@
}
pub open spec fn fixed_head_fields_ok(all: Seq<Field>, given: Seq<Field>, status: u16, length: nat) -> bool {
    if status == 204 || status == 304 {
        length == 0 && no_framing(all) && all.len() == given.len() + 1
            && all.take(given.len() as int) == given && is_close(all[given.len() as int])
    } else { head_fields_ok(all, given, false, length) }
}

/// What one connection has written: at most one response head, and after it
/// either the fixed body it announced or a stream of chunks.
pub struct Connection {
    phase: Phase,
    interim: bool,
    out: Ghost<Seq<u8>>,
    head: Ghost<Seq<u8>>,
    status: Ghost<u16>,
    reason: Ghost<Seq<u8>>,
    fields: Ghost<Seq<Field>>,
}
pub open spec fn continue_reason() -> Seq<u8> { seq![67u8, 111u8, 110u8, 116u8, 105u8, 110u8, 117u8, 101u8] }
/// The interim response, `HTTP/1.1 100 Continue` and the empty line.
pub open spec fn continue_bytes() -> Seq<u8> { crate::http1_write::status_head_bytes(100, continue_reason(), Seq::<Field>::empty()) }

impl Connection {
    pub closed spec fn out(&self) -> Seq<u8> { self.out@ }
    pub closed spec fn head(&self) -> Seq<u8> { self.head@ }
    pub closed spec fn status(&self) -> u16 { self.status@ }
    pub closed spec fn head_fields(&self) -> Seq<Field> { self.fields@ }
    pub closed spec fn open(&self) -> bool { self.phase == Phase::Open }
    pub closed spec fn streaming(&self) -> bool { self.phase == Phase::Streaming }
    pub closed spec fn done(&self) -> bool { self.phase == Phase::Done }
    pub closed spec fn aborted(&self) -> bool { self.phase == Phase::Aborted }
    pub closed spec fn interim_sent(&self) -> bool { self.interim }
    /// A head has been written: the status, reason, and fields it carries are
    /// well formed and within the parser's limits, and the fields end with
    /// `Connection: close` and a framing field (only `Connection` for 204/304).
    pub closed spec fn headed(&self) -> bool { self.phase == Phase::Streaming || self.phase == Phase::Done }
    pub closed spec fn valid(&self) -> bool {
        (self.headed() ==> (
            200 <= self.status@ <= 599 && crate::http1_write::reason_ok(self.reason@) && crate::http1_write::fields_wire_ok(self.fields@)
            && self.fields@.len() <= MAX_FIELDS && self.head@.len() <= MAX_BYTES
            && self.head@ == crate::http1_write::status_head_bytes(self.status@, self.reason@, self.fields@)
            && (if self.status@ == 204 || self.status@ == 304 {
                self.phase == Phase::Done && self.fields@.len() >= 1
                    && is_close(self.fields@[self.fields@.len() - 1]) && no_framing(self.fields@)
            } else { self.fields@.len() >= 2 && is_close(self.fields@[self.fields@.len() - 2]) })
            && (self.phase == Phase::Streaming ==> is_chunked(self.fields@[self.fields@.len() - 1]))))
    }
    pub fn new() -> (out: Self)
        ensures out.valid(), out.open(), !out.interim_sent(), out.out() == Seq::<u8>::empty(),
    {
        Connection { phase: Phase::Open, interim: false, out: Ghost(Seq::empty()), head: Ghost(Seq::empty()),
            status: Ghost(0), reason: Ghost(Seq::empty()), fields: Ghost(Seq::empty()) }
    }
    pub fn is_open(&self) -> (out: bool) ensures out == self.open() { self.phase == Phase::Open }
    pub fn is_streaming(&self) -> (out: bool) ensures out == self.streaming() { self.phase == Phase::Streaming }
    pub fn is_done(&self) -> (out: bool) ensures out == self.done() { self.phase == Phase::Done }

    /// `HTTP/1.1 100 Continue`, once, before any response head.
    pub fn interim_continue(&mut self) -> (out: Option<Vec<u8>>)
        requires old(self).valid(),
        ensures final(self).valid(), match out {
            Some(bytes) => old(self).open() && !old(self).interim_sent() && bytes@ == continue_bytes()
                && final(self).open() && final(self).interim_sent() && final(self).out() == old(self).out() + bytes@,
            None => *final(self) == *old(self) && (!old(self).open() || old(self).interim_sent()),
        },
    {
        if self.phase != Phase::Open || self.interim { return None; }
        let mut reason: Vec<u8> = Vec::new();
        reason.push(67); reason.push(111); reason.push(110); reason.push(116); reason.push(105); reason.push(110); reason.push(117); reason.push(101);
        proof { assert(reason@ =~= continue_reason()); }
        let empty: Vec<Field> = Vec::new();
        let mut bytes: Vec<u8> = Vec::new();
        write_status_head(100, reason.as_slice(), &empty, &mut bytes);
        self.interim = true;
        self.out = Ghost(self.out@ + bytes@);
        Some(bytes)
    }

    /// The whole response for a body known in full: the head with
    /// `Connection: close` and, except for 204/304, `Content-Length`, then the
    /// body. Refused for statuses outside 200 to 599, a body or framing fields
    /// on 204/304, unwritable fields or reason, or a head over parser limits.
    pub fn respond_fixed(&mut self, status: u16, reason: &[u8], fields: Vec<Field>, body: &[u8]) -> (out: Option<Vec<u8>>)
        requires old(self).valid(),
        ensures final(self).valid(), match out {
            Some(bytes) => old(self).open() && final(self).done() && !final(self).open() && !final(self).streaming() && 200 <= status <= 599
                && ((status == 204 || status == 304) ==> body@.len() == 0)
                && final(self).status() == status && fixed_head_fields_ok(final(self).head_fields(), fields@, status, body@.len())
                && final(self).head() == crate::http1_write::status_head_bytes(status, reason@, final(self).head_fields())
                && bytes@ == final(self).head() + body@ && final(self).out() == old(self).out() + bytes@,
            None => final(self).open() == old(self).open() && final(self).out() == old(self).out(),
        },
    {
        if self.phase != Phase::Open || status < 200 || status > 599 { return None; }
        if status == 204 || status == 304 {
            if body.len() > 0 || crate::headers::has(&fields, CONTENT_LENGTH.as_slice())
                || crate::headers::has(&fields, TRANSFER_ENCODING.as_slice()) { return None; }
        }
        if !reason_fits(reason) { return None; }
        let ghost given = fields@;
        let mut all = fields;
        all.push(close_field());
        if status != 204 && status != 304 { all.push(length_field(body.len())); }
        if !wire_ok(&all) || all.len() > MAX_FIELDS { return None; }
        let mut bytes: Vec<u8> = Vec::new();
        write_status_head(status, reason, &all, &mut bytes);
        if bytes.len() > MAX_BYTES { return None; }
        proof { assert(all@.take(given.len() as int) =~= given); }
        self.head = Ghost(bytes@);
        self.status = Ghost(status);
        self.reason = Ghost(reason@);
        self.fields = Ghost(all@);
        let mut k: usize = 0;
        let ghost head = bytes@;
        while k < body.len()
            invariant k <= body.len(), bytes@ == head + body@.subrange(0, k as int),
            decreases body.len() - k,
        {
            bytes.push(body[k]);
            proof { assert(bytes@ =~= head + body@.subrange(0, k as int + 1)); }
            k = k + 1;
        }
        proof { assert(body@.subrange(0, body@.len() as int) =~= body@); }
        self.phase = Phase::Done;
        self.out = Ghost(self.out@ + bytes@);
        Some(bytes)
    }

    /// The head of a streamed response, with `Connection: close` and
    /// `Transfer-Encoding: chunked`, and the stream its chunks go through.
    /// Refused for statuses outside 200 to 599, for 204 and 304, which carry
    /// no body, and for unwritable fields or an oversized head.
    pub fn respond_stream(&mut self, status: u16, reason: &[u8], fields: Vec<Field>) -> (out: Option<(Vec<u8>, ChunkStream)>)
        requires old(self).valid(),
        ensures final(self).valid(), match out {
            Some(pair) => old(self).open() && final(self).streaming() && !final(self).open() && !final(self).done() && 200 <= status <= 599 && status != 204 && status != 304
                && final(self).status() == status && head_fields_ok(final(self).head_fields(), fields@, true, 0)
                && final(self).head() == crate::http1_write::status_head_bytes(status, reason@, final(self).head_fields())
                && pair.0@ == final(self).head() && final(self).out() == old(self).out() + pair.0@
                && pair.1.valid() && !pair.1.ended() && pair.1.out() == Seq::<u8>::empty() && pair.1.body() == Seq::<u8>::empty(),
            None => final(self).open() == old(self).open() && final(self).out() == old(self).out(),
        },
    {
        if self.phase != Phase::Open || status < 200 || status > 599 || status == 204 || status == 304 { return None; }
        if !reason_fits(reason) { return None; }
        let ghost given = fields@;
        let mut all = fields;
        all.push(close_field());
        all.push(chunked_field());
        if !wire_ok(&all) || all.len() > MAX_FIELDS { return None; }
        let mut bytes: Vec<u8> = Vec::new();
        write_status_head(status, reason, &all, &mut bytes);
        if bytes.len() > MAX_BYTES { return None; }
        proof { assert(all@.take(given.len() as int) =~= given); }
        self.head = Ghost(bytes@);
        self.status = Ghost(status);
        self.reason = Ghost(reason@);
        self.fields = Ghost(all@);
        self.phase = Phase::Streaming;
        self.out = Ghost(self.out@ + bytes@);
        Some((bytes, ChunkStream::new()))
    }

    /// The stream ended cleanly: the connection is done.
    pub fn finish(&mut self, _stream: ChunkStream)
        requires old(self).valid(), old(self).streaming(), _stream.valid(), _stream.ended(),
        ensures final(self).valid(), final(self).done(), !final(self).open(), !final(self).streaming(), final(self).out() == old(self).out() + _stream.out(),
            final(self).head() == old(self).head(), final(self).status() == old(self).status(), final(self).head_fields() == old(self).head_fields(),
            crate::http1_chunked::chunked_ok(_stream.out(), _stream.body()),
    {
        self.phase = Phase::Done;
        self.out = Ghost(self.out@ + _stream.out());
    }

    /// The exchange failed: whatever was written stays as it is, nothing is
    /// added, and in particular no last chunk. A truncated stream is never a
    /// clean end.
    pub fn abort(&mut self)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).aborted(), !final(self).open(), !final(self).streaming(), final(self).out() == old(self).out(),
    {
        self.phase = Phase::Aborted;
    }

    /// A written head parses back as the status and fields it carries.
    pub proof fn lemma_head_well_formed(&self)
        requires self.valid(), self.headed(),
        ensures forall|head: crate::http1_head::StatusHead| head.status == self.status() && head.fields@ == self.head_fields()
            ==> crate::http1_head::status_head_ok(self.head(), head),
    {
        crate::http1_write::lemma_status_roundtrip(self.status@, self.reason@, self.fields@);
    }
}

// ---- the transport's request -----------------------------------------------

/// The bytes of `POST`, the only method the transport sends.
pub open spec fn post() -> Seq<u8> { seq![80u8, 79u8, 83u8, 84u8] }
fn post_bytes() -> (out: Vec<u8>) ensures out@ == post() {
    let mut v: Vec<u8> = Vec::new(); v.push(80); v.push(79); v.push(83); v.push(84);
    proof { assert(v@ =~= post()); }
    v
}

/// What one upstream connection has been sent: one request head with chunked
/// framing and `Connection: close`, then the upload stream.
pub struct Upstream {
    sent_head: bool,
    out: Ghost<Seq<u8>>,
    head: Ghost<Seq<u8>>,
    path: Ghost<Seq<u8>>,
    fields: Ghost<Seq<Field>>,
}
impl Upstream {
    pub closed spec fn out(&self) -> Seq<u8> { self.out@ }
    pub closed spec fn head(&self) -> Seq<u8> { self.head@ }
    pub closed spec fn path(&self) -> Seq<u8> { self.path@ }
    pub closed spec fn head_fields(&self) -> Seq<Field> { self.fields@ }
    pub closed spec fn sent(&self) -> bool { self.sent_head }
    pub closed spec fn valid(&self) -> bool {
        self.sent_head ==> (
            crate::http1_write::method_ok(post()) && crate::http1_write::target_ok(self.path@) && crate::http1_write::fields_wire_ok(self.fields@)
            && self.fields@.len() <= MAX_FIELDS && self.head@.len() <= MAX_BYTES
            && self.head@ == crate::http1_write::request_head_bytes(post(), self.path@, self.fields@)
            && self.fields@.len() >= 2 && is_chunked(self.fields@[self.fields@.len() - 2]) && is_close(self.fields@[self.fields@.len() - 1]))
    }
    pub fn new() -> (out: Self)
        ensures out.valid(), !out.sent(), out.out() == Seq::<u8>::empty(),
    { Upstream { sent_head: false, out: Ghost(Seq::empty()), head: Ghost(Seq::empty()), path: Ghost(Seq::empty()), fields: Ghost(Seq::empty()) } }

    /// The request head: `POST path HTTP/1.1`, the given fields, then
    /// `Transfer-Encoding: chunked` and `Connection: close`, and the stream the
    /// upload goes through. Refused for a target that is not origin-form, for
    /// unwritable fields, or for an oversized head.
    pub fn request(&mut self, path: &[u8], fields: Vec<Field>) -> (out: Option<(Vec<u8>, ChunkStream)>)
        requires old(self).valid(),
        ensures final(self).valid(), match out {
            Some(pair) => !old(self).sent() && final(self).sent() && final(self).path() == path@
                && final(self).head_fields().len() == fields@.len() + 2 && final(self).head_fields().take(fields@.len() as int) == fields@
                && is_chunked(final(self).head_fields()[fields@.len() as int]) && is_close(final(self).head_fields().last())
                && final(self).head() == crate::http1_write::request_head_bytes(post(), path@, final(self).head_fields())
                && pair.0@ == final(self).head() && final(self).out() == old(self).out() + pair.0@
                && pair.1.valid() && !pair.1.ended() && pair.1.out() == Seq::<u8>::empty() && pair.1.body() == Seq::<u8>::empty(),
            None => final(self).sent() == old(self).sent() && final(self).out() == old(self).out(),
        },
    {
        if self.sent_head { return None; }
        if path.len() == 0 || path[0] != 47 || !all_vchar(path) { return None; }
        let ghost given = fields@;
        let mut all = fields;
        all.push(chunked_field());
        all.push(close_field());
        if !wire_ok(&all) || all.len() > MAX_FIELDS { return None; }
        let mut bytes: Vec<u8> = Vec::new();
        let method = post_bytes();
        write_request_head(method.as_slice(), path, &all, &mut bytes);
        if bytes.len() > MAX_BYTES { return None; }
        proof {
            assert(all@.take(given.len() as int) =~= given);
            assert forall|k: int| 0 <= k < post().len() implies crate::headers::is_tchar(#[trigger] post()[k]) by {}
        }
        self.sent_head = true;
        self.head = Ghost(bytes@);
        self.path = Ghost(path@);
        self.fields = Ghost(all@);
        self.out = Ghost(self.out@ + bytes@);
        Some((bytes, ChunkStream::new()))
    }

    /// The upload ended cleanly: the request is complete.
    pub fn finish(&mut self, _stream: ChunkStream)
        requires old(self).valid(), old(self).sent(), _stream.valid(), _stream.ended(),
        ensures final(self).valid(), final(self).out() == old(self).out() + _stream.out(), final(self).head() == old(self).head(),
            crate::http1_chunked::chunked_ok(_stream.out(), _stream.body()),
    {
        self.out = Ghost(self.out@ + _stream.out());
    }

    /// A written request head parses back as `POST path` with its fields.
    pub proof fn lemma_head_well_formed(&self)
        requires self.valid(), self.sent(),
        ensures forall|head: crate::http1_head::RequestHead| head.method@ == post() && head.target@ == self.path() && head.fields@ == self.head_fields()
            ==> crate::http1_head::request_head_ok(self.head(), head),
    {
        crate::http1_write::lemma_request_roundtrip(post(), self.path@, self.fields@);
    }
}

fn all_vchar(s: &[u8]) -> (out: bool)
    ensures out == forall|k: int| 0 <= k < s.len() ==> crate::http1_head::is_vchar(#[trigger] s@[k]),
{
    let mut k: usize = 0;
    while k < s.len()
        invariant k <= s.len(), forall|j: int| 0 <= j < k ==> crate::http1_head::is_vchar(#[trigger] s@[j]),
        decreases s.len() - k,
    {
        if !(s[k] >= 33 && s[k] <= 126) { return false; }
        k = k + 1;
    }
    true
}
}
