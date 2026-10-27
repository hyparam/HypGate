//! Verified S3 request orchestration, UTC formatting, and transport refinement.
use vstd::prelude::*;
use crate::{s3, s3_config::Config, calendar, framing::append, headers::Field, shipper::{Path, Request, Reply}};
use vstd::slice::slice_to_vec;

verus! {
pub open spec fn two(n: u64) -> Seq<u8> { seq![(48 + n / 10) as u8, (48 + n % 10) as u8] }
pub open spec fn date_text(c: calendar::Civil) -> Seq<u8> {
    two(c.year / 100) + two(c.year % 100) + two(c.month as u64) + two(c.day as u64) + b"T"@
        + two(c.hour as u64) + two(c.minute as u64) + two(c.second as u64) + b"Z"@
}
fn push_two(out: &mut Vec<u8>, n: u64)
    requires n < 100,
    ensures final(out)@ == old(out)@ + two(n),
{
    out.push((48 + n / 10) as u8); out.push((48 + n % 10) as u8);
    proof { assert(out@ =~= old(out)@ + two(n)); }
}
/// UTC YYYYMMDDTHHMMSSZ for the exact supplied Unix milliseconds; reject years beyond four digits.
pub fn date(ms: u64) -> (out: Option<Vec<u8>>)
    ensures match out { Some(bytes) => bytes@ == date_text(calendar::civil_of(ms)) && bytes.len() == 16 && calendar::civil_of(ms).year <= 9999,
        None => calendar::civil_of(ms).year > 9999 },
{
    let c = calendar::civil(ms);
    if c.year > 9999 { return None; }
    let mut out = Vec::new();
    push_two(&mut out, c.year / 100); push_two(&mut out, c.year % 100);
    push_two(&mut out, c.month as u64); push_two(&mut out, c.day as u64); append(&mut out, b"T");
    push_two(&mut out, c.hour as u64); push_two(&mut out, c.minute as u64); push_two(&mut out, c.second as u64); append(&mut out, b"Z");
    proof { assert(out@ =~= date_text(c)); }
    Some(out)
}
/// Complete request headers; the socket adapter sends this exact wire head and body.
pub struct Put { pub method: Vec<u8>, pub authority: Vec<u8>, pub path: Vec<u8>, pub headers: Vec<Field>, pub body: Vec<u8> }
pub open spec fn header_view(h: Seq<Field>) -> Seq<(Seq<u8>, Seq<u8>, bool)> {
    h.map(|i: int, f: Field| (f.name@, f.value@, f.sensitive))
}
pub open spec fn fields(c: Config, date: Seq<u8>, auth: Seq<u8>, hash: Seq<u8>, length: nat) -> Seq<(Seq<u8>, Seq<u8>, bool)> {
    seq![(b"host"@, c.authority@, false), (b"connection"@, b"close"@, false),
        (b"content-length"@, crate::inbound::decimal(length), false),
        (b"authorization"@, auth, true), (b"x-amz-content-sha256"@, hash, false),
        (b"x-amz-date"@, date, false), (b"content-type"@, b"application/x-ndjson"@, false)]
        + (if c.session_token.len() == 0 { Seq::empty() } else { seq![(b"x-amz-security-token"@, c.session_token@, true)] })
}
fn field(name: &[u8], value: Vec<u8>, sensitive: bool) -> (out: Field)
    ensures out.name@ == name@, out.value@ == value@, out.sensitive == sensitive,
{ Field { name: slice_to_vec(name), value, sensitive } }

pub open spec fn path(c: Config, batch: Seq<u8>, body: Seq<u8>) -> Seq<u8> {
    c.prefix@ + crate::shipping_identity::hex_encoding(batch) + seq![45u8]
        + crate::shipping_identity::hex_encoding(crate::sha256::hash(body)) + b".ndjson"@
}
pub open spec fn signed(c: Config, path: Seq<u8>, date: Seq<u8>, body: Seq<u8>) -> Seq<u8> {
    let hash = crate::shipping_identity::hex_encoding(crate::sha256::hash(body));
    s3::authorization(c.access_key@, s3::scope(date.subrange(0, 8), c.region@), c.session_token@,
        s3::hmac(s3::signing_key(c.secret_key@, date.subrange(0, 8), c.region@),
            s3::string_to_sign(date, s3::scope(date.subrange(0, 8), c.region@), s3::canonical(c.authority@, path, date, c.session_token@, hash))))
}
pub open spec fn put_matches(c: Config, request: Request, ms: u64, put: Put) -> bool {
    request.path == Path::Ingest && request.batch_id.is_some() && c.valid() && calendar::civil_of(ms).year <= 9999
        && put.method@ == b"PUT"@ && put.authority@ == c.authority@ && put.body@ == request.body@
        && put.path@ == path(c, request.batch_id.unwrap()@, request.body@)
        && header_view(put.headers@) == fields(c, date_text(calendar::civil_of(ms)), signed(c, put.path@, date_text(calendar::civil_of(ms)), request.body@), crate::shipping_identity::hex_encoding(crate::sha256::hash(request.body@)), request.body.len() as nat)
}
pub open spec fn can_put(c: Config, request: Request, ms: u64) -> bool {
    c.valid() && request.path == Path::Ingest && request.batch_id.is_some() && request.batch_id.unwrap().len() <= 1024
        && request.body.len() <= 4194304 && calendar::civil_of(ms).year <= 9999
}
pub fn prepare(c: &Config, request: Request, ms: u64) -> (out: Option<Put>)
    ensures match out { Some(p) => can_put(*c, request, ms) && put_matches(*c, request, ms, p), None => !can_put(*c, request, ms) },
{
    if !c.is_valid() || request.path != Path::Ingest || request.body.len() > 4194304 { return None; }
    let batch = match &request.batch_id { Some(b) => b, None => return None };
    if batch.len() > 1024 { return None; }
    let date = match date(ms) { Some(d) => d, None => return None };
    let path = s3::object_path(c.prefix.as_slice(), batch.as_slice(), request.body.as_slice());
    let signed = s3::sign(c.authority.as_slice(), path.as_slice(), date.as_slice(), c.region.as_slice(),
        c.access_key.as_slice(), c.secret_key.as_slice(), c.session_token.as_slice(), request.body.as_slice());
    let ghost expected = fields(*c, date@, signed.authorization@, signed.payload_hash@, request.body.len() as nat);
    let mut headers = Vec::new();
    headers.push(field(b"host", c.authority.clone(), false));
    headers.push(field(b"connection", slice_to_vec(b"close"), false));
    headers.push(field(b"content-length", crate::http1_exchange::decimal_bytes(request.body.len() as u64), false));
    headers.push(field(b"authorization", signed.authorization, true));
    headers.push(field(b"x-amz-content-sha256", signed.payload_hash, false));
    headers.push(field(b"x-amz-date", date, false));
    headers.push(field(b"content-type", slice_to_vec(b"application/x-ndjson"), false));
    if c.session_token.len() != 0 { headers.push(field(b"x-amz-security-token", c.session_token.clone(), true)); }
    proof { assert(header_view(headers@) =~= expected); }
    Some(Put { method: slice_to_vec(b"PUT"), authority: c.authority.clone(), path, headers, body: request.body })
}
#[derive(PartialEq, Eq, Structural, Copy, Clone)]
pub struct Response { pub status: u16, pub retry_after: Option<u64> }
/// The sole S3 network effect. Status zero represents a transport/framing failure.
/// The OS/TLS adapter must send these bytes to the configured authority and report its reply.
pub trait Transport {
    spec fn puts(&self) -> Seq<Put>;
    spec fn replies(&self) -> Seq<Response>;
    fn put(&mut self, request: Put) -> (out: Response)
        ensures final(self).puts() == old(self).puts().push(request), final(self).replies() == old(self).replies().push(out);
    fn milliseconds(&mut self) -> (ms: u64)
        ensures final(self).puts() == old(self).puts(), final(self).replies() == old(self).replies();
}
pub open spec fn reply_policy(path: Path, reply: Reply) -> bool {
    if path == Path::Ingest {
        (reply.status == 0 || reply.status == 200 || reply.status == 503) && reply.credential.is_none() && !reply.revocation
    } else {
        reply.status == 200 && reply.credential.is_some() && reply.credential.unwrap().jwt@ == b"s3"@
            && reply.credential.unwrap().expires_at == u64::MAX && !reply.revocation && reply.retry_after.is_none()
    }
}
/// Local activation or exactly one correctly signed PUT; transport errors never become acknowledgments.
pub fn send<T: Transport>(c: &Config, io: &mut T, request: Request, ms: u64) -> (out: Reply)
    ensures reply_policy(request.path, out),
        if can_put(*c, request, ms) {
            final(io).puts().len() == old(io).puts().len() + 1
                && final(io).puts().drop_last() == old(io).puts() && put_matches(*c, request, ms, final(io).puts().last())
                && final(io).replies().len() == old(io).replies().len() + 1
                && final(io).replies().drop_last() == old(io).replies()
                && (out.status == 200 <==> final(io).replies().last().status == 200)
                && out.retry_after == final(io).replies().last().retry_after
        } else {
            final(io).puts() == old(io).puts() && final(io).replies() == old(io).replies()
                && (request.path == Path::Ingest ==> out.status == 0)
        },
{
    if request.path != Path::Ingest { return s3::activation(); }
    match prepare(c, request, ms) {
        None => s3::upload_reply(0, None),
        Some(put) => {
            let response = io.put(put);
            s3::upload_reply(response.status, response.retry_after)
        }
    }
}
} // verus!

