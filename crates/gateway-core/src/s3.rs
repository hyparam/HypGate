//! S3 Signature Version 4 and the S3 interpretation of the shared shipper protocol.
//! SHA-256, HMAC, canonical bytes, object names, and reply classification are executable proofs.
use vstd::prelude::*;
use crate::{framing::append, sha256, shipping_identity::hex};

verus! {
pub open spec fn pad(key: Seq<u8>, byte: u8) -> Seq<u8> {
    Seq::new(64, |i: int| (if i < key.len() { key[i] } else { 0u8 }) ^ byte)
}
#[verifier::opaque]
pub open spec fn hmac(key: Seq<u8>, message: Seq<u8>) -> Seq<u8> {
    let k = if key.len() > 64 { sha256::hash(key) } else { key };
    sha256::hash(pad(k, 0x5c) + sha256::hash(pad(k, 0x36) + message))
}
fn padded(key: &[u8], byte: u8) -> (out: Vec<u8>)
    requires key.len() <= 64,
    ensures out@ == pad(key@, byte), out.len() == 64,
{
    let mut out = Vec::new();
    let mut i: usize = 0;
    while i < 64
        invariant i <= 64, out@ == pad(key@, byte).take(i as int), key.len() <= 64,
        decreases 64 - i,
    {
        out.push((if i < key.len() { key[i] } else { 0u8 }) ^ byte);
        i += 1;
        proof { assert(out@ =~= pad(key@, byte).take(i as int)); }
    }
    proof { assert(out@ =~= pad(key@, byte)); }
    out
}
pub fn mac(key: &[u8], message: &[u8]) -> (out: Vec<u8>)
    requires key.len() <= 1048576, message.len() <= 16777216,
    ensures out@ == hmac(key@, message@), out.len() == 32,
{
    proof { reveal(hmac); }
    let k = if key.len() > 64 { sha256::digest(key) } else { vstd::slice::slice_to_vec(key) };
    let mut inner = padded(k.as_slice(), 0x36);
    append(&mut inner, message);
    let digest = sha256::digest(inner.as_slice());
    let mut outer = padded(k.as_slice(), 0x5c);
    append(&mut outer, digest.as_slice());
    sha256::digest(outer.as_slice())
}
/// Unencoded path prefixes only: no percent escapes, dot segments, query, or header injection.
pub open spec fn safe(s: Seq<u8>, slash: bool) -> bool {
    s.len() > 0 && s.len() <= 1024 && forall|i: int| 0 <= i < s.len() ==>
        (65 <= #[trigger] s[i] <= 90 || 97 <= s[i] <= 122 || 48 <= s[i] <= 57 || s[i] == 45 || s[i] == 95 || (slash && s[i] == 47))
}
pub fn safe_exec(s: &[u8], slash: bool) -> (ok: bool)
    ensures ok == safe(s@, slash),
{
    if s.len() == 0 || s.len() > 1024 { return false; }
    let mut i: usize = 0;
    while i < s.len()
        invariant i <= s.len(), forall|j: int| 0 <= j < i ==> (65 <= #[trigger] s[j] <= 90 || 97 <= s[j] <= 122 || 48 <= s[j] <= 57 || s[j] == 45 || s[j] == 95 || (slash && s[j] == 47)),
        decreases s.len() - i,
    {
        let b = s[i];
        if !((65 <= b && b <= 90) || (97 <= b && b <= 122) || (48 <= b && b <= 57) || b == 45 || b == 95 || (slash && b == 47)) { return false; }
        i += 1;
    }
    true
}
/// Object identity includes the batch identity and the full payload hash.
pub fn object_path(prefix: &[u8], batch: &[u8], body: &[u8]) -> (out: Vec<u8>)
    requires body.len() <= 16777216, batch.len() <= 1024,
    ensures out@ == prefix@ + crate::shipping_identity::hex_encoding(batch@) + seq![45u8]
        + crate::shipping_identity::hex_encoding(sha256::hash(body@)) + b".ndjson"@,
{
    let mut out = vstd::slice::slice_to_vec(prefix);
    append(&mut out, hex(batch).as_slice()); out.push(45);
    append(&mut out, hex(sha256::digest(body).as_slice()).as_slice());
    append(&mut out, b".ndjson");
    out
}
/// Only a successful PUT resolves a batch. All S3 errors retry, never poison or enroll.
pub fn upload_reply(status: u16, retry_after: Option<u64>) -> (out: crate::shipper::Reply)
    ensures out.status == (if status == 200 { 200u16 } else if status == 429 || status == 503 { 503u16 } else { 0u16 }),
        out.retry_after == retry_after, !out.revocation, out.credential.is_none(),
{
    crate::shipper::Reply { status: if status == 200 { 200 } else if status == 429 || status == 503 { 503 } else { 0 },
        retry_after, revocation: false, credential: None }
}
/// Local activation of configured AWS credentials; never sent to S3 or persisted as an identity.
pub fn activation() -> (out: crate::shipper::Reply)
    ensures out.status == 200, out.credential.is_some(),
        out.credential.unwrap().jwt@ == b"s3"@, out.credential.unwrap().expires_at == u64::MAX,
        !out.revocation, out.retry_after.is_none(),
{
    crate::shipper::Reply { status: 200, retry_after: None, revocation: false,
        credential: Some(crate::shipper::Credential { jwt: vstd::slice::slice_to_vec(b"s3"), expires_at: u64::MAX }) }
}
pub open spec fn names(token: Seq<u8>) -> Seq<u8> {
    b"host;x-amz-content-sha256;x-amz-date"@ + (if token.len() == 0 { Seq::empty() } else { b";x-amz-security-token"@ })
}
pub open spec fn canonical(host: Seq<u8>, path: Seq<u8>, date: Seq<u8>, token: Seq<u8>, hash: Seq<u8>) -> Seq<u8> {
    b"PUT\n"@ + path + b"\n\nhost:"@ + host + b"\nx-amz-content-sha256:"@ + hash + b"\nx-amz-date:"@ + date + b"\n"@
        + (if token.len() == 0 { Seq::empty() } else { b"x-amz-security-token:"@ + token + b"\n"@ })
        + b"\n"@ + names(token) + b"\n"@ + hash
}
pub open spec fn scope(day: Seq<u8>, region: Seq<u8>) -> Seq<u8> { day + b"/"@ + region + b"/s3/aws4_request"@ }
pub open spec fn signing_key(secret: Seq<u8>, day: Seq<u8>, region: Seq<u8>) -> Seq<u8> {
    hmac(hmac(hmac(hmac(b"AWS4"@ + secret, day), region), b"s3"@), b"aws4_request"@)
}
pub open spec fn string_to_sign(date: Seq<u8>, scope: Seq<u8>, canonical: Seq<u8>) -> Seq<u8> {
    b"AWS4-HMAC-SHA256\n"@ + date + b"\n"@ + scope + b"\n"@ + crate::shipping_identity::hex_encoding(sha256::hash(canonical))
}
pub open spec fn authorization(access: Seq<u8>, scope: Seq<u8>, token: Seq<u8>, signature: Seq<u8>) -> Seq<u8> {
    b"AWS4-HMAC-SHA256 Credential="@ + access + b"/"@ + scope + b", SignedHeaders="@ + names(token)
        + b", Signature="@ + crate::shipping_identity::hex_encoding(signature)
}
fn signed_names(token: &[u8]) -> (out: Vec<u8>)
    ensures out@ == names(token@), out.len() <= 128,
{
    let mut out = vstd::slice::slice_to_vec(b"host;x-amz-content-sha256;x-amz-date");
    if token.len() != 0 { append(&mut out, b";x-amz-security-token"); }
    out
}
fn canonical_request(host: &[u8], path: &[u8], date: &[u8], token: &[u8], hash: &[u8]) -> (out: Vec<u8>)
    requires host.len() <= 4096, path.len() <= 4096, date.len() == 16, token.len() <= 16384, hash.len() == 64,
    ensures out@ == canonical(host@, path@, date@, token@, hash@), out.len() <= 32768,
{
    let mut out = vstd::slice::slice_to_vec(b"PUT\n");
    append(&mut out, path); append(&mut out, b"\n\nhost:"); append(&mut out, host);
    append(&mut out, b"\nx-amz-content-sha256:"); append(&mut out, hash);
    append(&mut out, b"\nx-amz-date:"); append(&mut out, date); append(&mut out, b"\n");
    let ghost before_token = out@;
    if token.len() != 0 { append(&mut out, b"x-amz-security-token:"); append(&mut out, token); append(&mut out, b"\n"); }
    proof { assert(out@ =~= before_token + (if token.len() == 0 { Seq::empty() } else { b"x-amz-security-token:"@ + token@ + b"\n"@ })); }
    append(&mut out, b"\n"); append(&mut out, signed_names(token).as_slice()); append(&mut out, b"\n"); append(&mut out, hash);
    proof { assert(out@ =~= canonical(host@, path@, date@, token@, hash@)); }
    out
}
pub struct Signed { pub authorization: Vec<u8>, pub payload_hash: Vec<u8> }
/// SigV4 for a PUT with no query. Date is UTC YYYYMMDDTHHMMSSZ supplied by the clock adapter.
#[verifier::rlimit(20)]
pub fn sign(host: &[u8], path: &[u8], date: &[u8], region: &[u8], access: &[u8], secret: &[u8], token: &[u8], body: &[u8]) -> (out: Signed)
    requires host.len() <= 4096, path.len() <= 4096, date.len() == 16, region.len() <= 1024,
        access.len() <= 1024, secret.len() <= 512, token.len() <= 16384, body.len() <= 16777216,
    ensures out.payload_hash@ == crate::shipping_identity::hex_encoding(sha256::hash(body@)),
        out.authorization@ == authorization(access@, scope(date@.subrange(0, 8), region@), token@,
            hmac(signing_key(secret@, date@.subrange(0, 8), region@),
                string_to_sign(date@, scope(date@.subrange(0, 8), region@), canonical(host@, path@, date@, token@, out.payload_hash@)))),
{
    let day = vstd::slice::slice_subrange(date, 0, 8);
    let payload_hash = hex(sha256::digest(body).as_slice());
    let request = canonical_request(host, path, date, token, payload_hash.as_slice());
    let mut scope_bytes = vstd::slice::slice_to_vec(day);
    append(&mut scope_bytes, b"/"); append(&mut scope_bytes, region); append(&mut scope_bytes, b"/s3/aws4_request");
    let mut key = vstd::slice::slice_to_vec(b"AWS4"); append(&mut key, secret);
    let k_date = mac(key.as_slice(), day);
    let k_region = mac(k_date.as_slice(), region);
    let k_service = mac(k_region.as_slice(), b"s3");
    let k_signing = mac(k_service.as_slice(), b"aws4_request");
    let mut message = vstd::slice::slice_to_vec(b"AWS4-HMAC-SHA256\n");
    append(&mut message, date); append(&mut message, b"\n"); append(&mut message, scope_bytes.as_slice()); append(&mut message, b"\n");
    append(&mut message, hex(sha256::digest(request.as_slice()).as_slice()).as_slice());
    proof { assert(message@ =~= string_to_sign(date@, scope(day@, region@), request@)); }
    let signature = mac(k_signing.as_slice(), message.as_slice());
    let mut auth = vstd::slice::slice_to_vec(b"AWS4-HMAC-SHA256 Credential=");
    append(&mut auth, access); append(&mut auth, b"/"); append(&mut auth, scope_bytes.as_slice());
    append(&mut auth, b", SignedHeaders="); append(&mut auth, signed_names(token).as_slice());
    append(&mut auth, b", Signature="); append(&mut auth, hex(signature.as_slice()).as_slice());
    proof { assert(auth@ =~= authorization(access@, scope(day@, region@), token@, signature@)); }
    Signed { authorization: auth, payload_hash }
}

} // verus!
