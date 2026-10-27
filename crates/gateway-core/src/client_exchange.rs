//! Verified driver for one request from the shipper to the HypAware server:
//! the client side of an HTTP/1.1 exchange over a connection the runtime
//! opened. The runtime supplies the wire (one socket read appends, one socket
//! write takes a prefix); this driver decides everything else: the head and
//! body are written once and in that order, status heads are read until a
//! final one with at most `MAX_INTERIM_HEADS` interim ones skipped, a head
//! whose framing is ambiguous is refused, and the reply body is read under
//! the verified body reader until it is complete, never past the cap. What
//! comes back is a parsed head and a body that is exactly one body of that
//! head's framing, or a fault naming the step that failed.
use vstd::prelude::*;
use vstd::slice::slice_subrange;
use crate::body_reader::{BodyReader, HeadRead, Read, Source, read_status_head};
use crate::exchange_driver::MAX_INTERIM_HEADS;
use crate::http1_exchange::{UpstreamStatus, upstream_status};
use crate::http1_framing::Framing;
use crate::http1_head::StatusHead;
use crate::sink::{Sink, write_all};

verus! {
/// The most reply body bytes read in one go.
pub const ROOM: usize = 4096;

/// Which step of the exchange failed.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum ClientFault {
    /// The wire took only a prefix of the request.
    Send,
    /// No status head could be read: closed, too large, malformed, or failed.
    Head,
    /// The server switched protocols, sent too many interim heads, or framed the body ambiguously.
    Refused,
    /// The body was declared or grew larger than the cap.
    TooLarge,
    /// The body stopped early, was not a body of its framing, or the wire failed.
    Body,
}

/// A reply: the final status head and its whole body.
pub struct Reply { pub head: StatusHead, pub body: Vec<u8> }

/// The exchange's outcome and the bytes it handed to the wire.
pub struct Exchanged { pub result: Result<Reply, ClientFault>, pub sent: Ghost<Seq<u8>> }

/// `head` was parsed from the first `len` of the `received` bytes.
pub open spec fn parsed_head(received: Seq<u8>, len: int, head: StatusHead) -> bool {
    0 <= len <= received.len() && crate::http1_head::status_head_ok(received.subrange(0, len), head)
}
/// A reply the driver returns: a final status (2xx and up) parsed from the
/// bytes received, a body within the cap that is empty after 204 or 304 and
/// otherwise exactly one body of the framing the head's fields select.
pub open spec fn reply_ok(r: Reply, cap: nat) -> bool {
    r.head.status >= 200 && r.body@.len() <= cap
        && (exists|received: Seq<u8>, len: int| #[trigger] parsed_head(received, len, r.head))
        && if r.head.status == 204 || r.head.status == 304 { r.body@.len() == 0 } else {
            exists|f: Framing, fed: Seq<u8>| #[trigger] crate::http1_framing::framing_spec_ok(r.head.fields@, f) && #[trigger] crate::http1_body::delimits(f, fed, r.body@)
        }
}

fn append(out: &mut Vec<u8>, bytes: &[u8])
    ensures final(out)@ == old(out)@ + bytes@,
{
    let mut i: usize = 0;
    while i < bytes.len()
        invariant i <= bytes.len(), out@ == old(out)@ + bytes@.subrange(0, i as int),
        decreases bytes.len() - i,
    {
        out.push(bytes[i]);
        proof { assert(old(out)@ + bytes@.subrange(0, i as int + 1) =~= (old(out)@ + bytes@.subrange(0, i as int)).push(bytes@[i as int])); }
        i = i + 1;
    }
    proof { assert(bytes@.subrange(0, bytes.len() as int) =~= bytes@); }
}

/// Read status heads until a final one, skipping at most `MAX_INTERIM_HEADS`
/// interim ones. The framing comes with it: none after 204 or 304.
#[verifier::loop_isolation(false)]
fn final_head<W: Source>(wire: &mut W) -> (out: Result<(HeadRead<StatusHead>, Framing), ClientFault>)
    ensures match out {
        Ok((read, framing)) => parsed_head(read.received@, read.len@, read.head) && read.head.status >= 200
            && if read.head.status == 204 || read.head.status == 304 { framing == Framing::Length(0) } else { crate::http1_framing::framing_spec_ok(read.head.fields@, framing) },
        Err(fault) => fault == ClientFault::Head || fault == ClientFault::Refused,
    },
{
    let mut leftover: Vec<u8> = Vec::new();
    let mut interim: u32 = 0;
    loop
        invariant interim <= MAX_INTERIM_HEADS,
        decreases MAX_INTERIM_HEADS - interim,
    {
        let read = match read_status_head(wire, leftover) { Ok(read) => read, Err(_) => return Err(ClientFault::Head) };
        match upstream_status(read.head.status, &read.head.fields) {
            UpstreamStatus::Interim => {
                if interim == MAX_INTERIM_HEADS { return Err(ClientFault::Refused); }
                interim = interim + 1;
                leftover = read.rest;
            }
            UpstreamStatus::Refused => return Err(ClientFault::Refused),
            UpstreamStatus::Bodiless => return Ok((read, Framing::Length(0))),
            UpstreamStatus::Framed(framing) => return Ok((read, framing)),
        }
    }
}

/// Send `head` then `body`, and read the reply, whose body may have at most
/// `cap` bytes. The bytes handed to the wire are exactly the request, in
/// order, unless the wire stopped taking them, and then they are a proper
/// prefix of it.
#[verifier::loop_isolation(false)]
pub fn exchange<W: Source + Sink>(wire: &mut W, head: &[u8], body: &[u8], cap: usize) -> (out: Exchanged)
    ensures
        match out.result {
            Err(ClientFault::Send) => out.sent@.len() < head@.len() + body@.len()
                && out.sent@ == (head@ + body@).subrange(0, out.sent@.len() as int),
            _ => out.sent@ == head@ + body@,
        },
        match out.result { Ok(r) => reply_ok(r, cap as nat), Err(_) => true },
{
    let written = write_all(wire, head);
    match written.result {
        Err(_) => {
            proof { assert(written.sent@ =~= (head@ + body@).subrange(0, written.sent@.len() as int)); }
            return Exchanged { result: Err(ClientFault::Send), sent: written.sent };
        }
        Ok(()) => {}
    }
    let written = write_all(wire, body);
    let ghost sent = head@ + written.sent@;
    match written.result {
        Err(_) => {
            proof { assert(sent =~= (head@ + body@).subrange(0, sent.len() as int)); }
            return Exchanged { result: Err(ClientFault::Send), sent: Ghost(sent) };
        }
        Ok(()) => {}
    }
    proof { assert(sent == head@ + body@); }
    let (read, framing) = match final_head(wire) { Ok(found) => found, Err(fault) => return Exchanged { result: Err(fault), sent: Ghost(sent) } };
    match framing { Framing::Length(n) => if n > cap as u64 { return Exchanged { result: Err(ClientFault::TooLarge), sent: Ghost(sent) }; }, _ => {} }
    let mut reader = BodyReader::new(read.rest, framing);
    let mut out: Vec<u8> = Vec::new();
    loop
        invariant reader.inv(), reader.framing() == framing, out@ == reader.delivered(), out@.len() <= cap,
        decreases cap - out@.len(),
    {
        match reader.read(wire, ROOM) {
            Read::Data(start, n) => {
                if n > cap - out.len() { return Exchanged { result: Err(ClientFault::TooLarge), sent: Ghost(sent) }; }
                let buffer = reader.buffer();
                let _len = buffer.len(); // a usize, so `start + n` (at most it) cannot overflow
                proof { assert(start + n <= _len); }
                let piece = slice_subrange(buffer.as_slice(), start, start + n);
                append(&mut out, piece);
            }
            Read::End => {
                proof {
                    reader.lemma_complete();
                    assert(parsed_head(read.received@, read.len@, read.head));
                    assert(crate::http1_body::delimits(framing, reader.fed(), out@));
                }
                return Exchanged { result: Ok(Reply { head: read.head, body: out }), sent: Ghost(sent) };
            }
            Read::Truncated | Read::Malformed | Read::Failed => return Exchanged { result: Err(ClientFault::Body), sent: Ghost(sent) },
        }
    }
}

} // verus!
