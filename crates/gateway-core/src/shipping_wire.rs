//! Verified reading of what the HypAware server sends back, and the head of
//! what the shipper sends it. The shipper machine (`shipper`) decides which
//! request goes next and how to act on a reply's status; this module is the
//! bytes-to-meaning layer around it: the `sub` and `exp` claims of the
//! credential the server issues (read without verifying the signature, which
//! the server checks on every request), the credential document itself, the
//! two error codes that mean revocation, the `Retry-After` delta, and the
//! request head for a machine request. Each reader is sound: it never
//! reports a claim, code, or delay the bytes do not carry. The revocation
//! and `Retry-After` readers are also complete, so a mutation that stops
//! them recognising a valid reply fails its proof.
use vstd::prelude::*;
use vstd::slice::{slice_subrange, slice_to_vec};
use crate::base64url::decode;
use crate::headers::{Field, eq};
use crate::http1_exchange::decimal_bytes;
use crate::http1_write::{wire_ok, write_request_head};
#[allow(unused_imports)] // Named only in specifications.
use crate::json::{self, Value};
use crate::shipper::{Path, Request};
use crate::shipping_identity::hex;

verus! {
/// The most bytes a credential may have, before and after splitting.
pub const MAX_JWT_BYTES: usize = 16 * 1024;
/// The most bytes a gateway id (`sub`) may have; it must not be empty.
pub const MAX_SUBJECT_BYTES: usize = 128;
pub const DOT: u8 = 46;
pub const SUB: [u8; 3] = *b"sub";
pub const EXP: [u8; 3] = *b"exp";
pub const JWT: [u8; 3] = *b"jwt";
pub const EXPIRES_AT: [u8; 10] = *b"expires_at";
pub const ERROR: [u8; 5] = *b"error";
pub const REVOKED: [u8; 21] = *b"service_token_revoked";
pub const DISABLED: [u8; 24] = *b"service_account_disabled";
pub const RETRY_AFTER: [u8; 11] = *b"retry-after";
pub const POST: [u8; 4] = *b"POST";
pub const BOOTSTRAP: [u8; 22] = *b"/v1/identity/bootstrap";
pub const REFRESH: [u8; 20] = *b"/v1/identity/refresh";
pub const INGEST: [u8; 16] = *b"/v1/ingest/proxy";
pub const HOST: [u8; 4] = *b"host";
pub const CONNECTION: [u8; 10] = *b"connection";
pub const CLOSE: [u8; 5] = *b"close";
pub const CONTENT_LENGTH: [u8; 14] = *b"content-length";
pub const CONTENT_TYPE: [u8; 12] = *b"content-type";
pub const AUTHORIZATION: [u8; 13] = *b"authorization";
pub const BEARER: [u8; 7] = *b"Bearer ";
pub const JSON_TYPE: [u8; 16] = *b"application/json";
pub const NDJSON_TYPE: [u8; 20] = *b"application/x-ndjson";
pub const BATCH_ID: [u8; 14] = *b"x-hyp-batch-id";

// ---- members of a parsed document ---------------------------------------------

/// Some member of `v` named `key` holds the string `s`.
pub open spec fn member_str(v: Value, key: Seq<u8>, s: Seq<u8>) -> bool {
    exists|k: int| 0 <= k < crate::json::members_of(v).len() && #[trigger] crate::json::members_of(v)[k].key@ == key
        && crate::json::members_of(v)[k].value is Str && crate::json::members_of(v)[k].value->Str_0@ == s
}
/// Some member of `v` named `key` holds the canonical decimal of `n`.
pub open spec fn member_u64(v: Value, key: Seq<u8>, n: u64) -> bool {
    exists|k: int| 0 <= k < crate::json::members_of(v).len() && #[trigger] crate::json::members_of(v)[k].key@ == key
        && crate::json::members_of(v)[k].value is Number && crate::json::members_of(v)[k].value->Number_0@ == crate::inbound::decimal(n as nat)
}
/// `key` names at most one member of `v`.
pub open spec fn unique_key(v: Value, key: Seq<u8>) -> bool {
    forall|i: int, j: int| 0 <= i < j < crate::json::members_of(v).len() && #[trigger] crate::json::members_of(v)[i].key@ == key
        ==> #[trigger] crate::json::members_of(v)[j].key@ != key
}

/// Two values the reader cannot tell apart have the same members: the same
/// keys in the same order, with values that are again the same.
proof fn lemma_same_members(xs: Seq<json::Member>, ys: Seq<json::Member>)
    requires crate::json::same_members(xs, ys),
    ensures xs.len() == ys.len(),
        forall|k: int| 0 <= k < xs.len() ==> #[trigger] xs[k].key@ == ys[k].key@ && crate::json::same(xs[k].value, ys[k].value),
    decreases xs.len(),
{
    if xs.len() > 0 {
        lemma_same_members(xs.drop_first(), ys.drop_first());
        assert forall|k: int| 0 <= k < xs.len() implies #[trigger] xs[k].key@ == ys[k].key@ && crate::json::same(xs[k].value, ys[k].value) by {
            if k > 0 {
                assert(xs.drop_first()[k - 1] == xs[k]);
                assert(ys.drop_first()[k - 1] == ys[k]);
            }
        }
    }
}

// ---- the claims of a compact JWS ------------------------------------------------

/// `s` has exactly two dots, at `i` and `j`.
pub open spec fn two_dots(s: Seq<u8>, i: int, j: int) -> bool {
    0 <= i < j < s.len() && s[i] == DOT && s[j] == DOT
        && forall|k: int| 0 <= k < s.len() && k != i && k != j ==> #[trigger] s[k] != DOT
}
/// The base64url segment `segment` decodes to a JSON object whose `sub` is
/// `sub` (one to `MAX_SUBJECT_BYTES` bytes) and whose `exp` is `exp`.
pub open spec fn payload_claims(segment: Seq<u8>, sub: Seq<u8>, exp: u64) -> bool {
    exists|bytes: Seq<u8>, v: Value| crate::base64url::encoded(bytes) == crate::base64url::stripped(segment) && #[trigger] crate::json::document(bytes, v)
        && member_str(v, SUB@, sub) && 1 <= sub.len() <= MAX_SUBJECT_BYTES && member_u64(v, EXP@, exp)
}
/// `jwt` is a compact JWS of at most `MAX_JWT_BYTES` whose payload carries these claims.
pub open spec fn claims(jwt: Seq<u8>, sub: Seq<u8>, exp: u64) -> bool {
    jwt.len() <= MAX_JWT_BYTES
        && exists|i: int, j: int| #[trigger] two_dots(jwt, i, j) && payload_claims(jwt.subrange(i + 1, j), sub, exp)
}

/// The claims the shipper keeps: which gateway it is, and when to renew.
pub struct Claims { pub subject: Vec<u8>, pub expires: u64 }

/// The `sub` and `exp` claims of a compact JWS, read without verifying the
/// signature. Sound: a result is always a claim the token carries.
#[verifier::loop_isolation(false)]
pub fn jws_claims(jwt: &[u8]) -> (out: Option<Claims>)
    ensures match out { Some(c) => claims(jwt@, c.subject@, c.expires), None => true },
{
    if jwt.len() > MAX_JWT_BYTES { return None; }
    let mut first: Option<usize> = None;
    let mut second: Option<usize> = None;
    let mut k: usize = 0;
    while k < jwt.len()
        invariant k <= jwt.len(),
            match first {
                None => second is None && forall|m: int| 0 <= m < k ==> #[trigger] jwt@[m] != DOT,
                Some(i) => i < k && jwt@[i as int] == DOT && match second {
                    None => forall|m: int| 0 <= m < k && m != i ==> #[trigger] jwt@[m] != DOT,
                    Some(j) => i < j < k && jwt@[j as int] == DOT
                        && forall|m: int| 0 <= m < k && m != i && m != j ==> #[trigger] jwt@[m] != DOT,
                },
            },
        decreases jwt.len() - k,
    {
        if jwt[k] == DOT {
            match (first, second) {
                (None, _) => first = Some(k),
                (Some(_), None) => second = Some(k),
                (Some(_), Some(_)) => return None,
            }
        }
        k = k + 1;
    }
    let (i, j) = match (first, second) { (Some(i), Some(j)) => (i, j), _ => return None };
    let segment = slice_subrange(jwt, i + 1, j);
    let bytes = match decode(segment) { Some(bytes) => bytes, None => return None };
    let value = match json::parse(bytes.as_slice()) { Some(value) => value, None => return None };
    let subject = match value.get(SUB.as_slice()) { Some(v) => match v.as_str() { Some(s) => s, None => return None }, None => return None };
    if subject.len() < 1 || subject.len() > MAX_SUBJECT_BYTES { return None; }
    let expires = match value.get(EXP.as_slice()) { Some(v) => match v.as_u64() { Some(n) => n, None => return None }, None => return None };
    proof {
        assert(two_dots(jwt@, i as int, j as int));
        assert(member_str(value, SUB@, subject@));
        assert(member_u64(value, EXP@, expires));
        assert(crate::json::document(bytes@, value));
        assert(payload_claims(segment@, subject@, expires));
        assert(segment@ == jwt@.subrange(i + 1, j as int));
    }
    Some(Claims { subject: subject.clone(), expires })
}

// ---- the issued credential ---------------------------------------------------

/// A credential the server issued: the token, the gateway id it names, and
/// when it expires, the earlier of the document's `expires_at` and the token's `exp`.
pub struct Issued { pub jwt: Vec<u8>, pub subject: Vec<u8>, pub expires_at: u64 }

pub open spec fn issued_ok(body: Seq<u8>, jwt: Seq<u8>, subject: Seq<u8>, expires_at: u64) -> bool {
    exists|v: Value, e: u64, exp: u64| #[trigger] crate::json::document(body, v) && member_str(v, JWT@, jwt)
        && #[trigger] member_u64(v, EXPIRES_AT@, e) && #[trigger] claims(jwt, subject, exp)
        && expires_at == (if e <= exp { e } else { exp })
}

/// The credential in a bootstrap or refresh reply body. Sound: the token,
/// subject, and expiry are the document's and the token's own.
pub fn issued(body: &[u8]) -> (out: Option<Issued>)
    ensures match out { Some(i) => issued_ok(body@, i.jwt@, i.subject@, i.expires_at), None => true },
{
    let value = match json::parse(body) { Some(value) => value, None => return None };
    let jwt = match value.get(JWT.as_slice()) { Some(v) => match v.as_str() { Some(s) => s, None => return None }, None => return None };
    let e = match value.get(EXPIRES_AT.as_slice()) { Some(v) => match v.as_u64() { Some(n) => n, None => return None }, None => return None };
    let c = match jws_claims(jwt.as_slice()) { Some(c) => c, None => return None };
    let expires_at = if e <= c.expires { e } else { c.expires };
    proof {
        assert(crate::json::document(body@, value));
        assert(member_str(value, JWT@, jwt@));
        assert(member_u64(value, EXPIRES_AT@, e));
        assert(claims(jwt@, c.subject@, c.expires));
    }
    Some(Issued { jwt: jwt.clone(), subject: c.subject, expires_at })
}

// ---- revocation --------------------------------------------------------------------

/// The two error codes after which the credential is gone for good.
pub open spec fn revoked_code(s: Seq<u8>) -> bool { s == REVOKED@ || s == DISABLED@ }
/// `body` is a document whose (unique) `error` member is a revocation code.
pub open spec fn revocation_reply(body: Seq<u8>, v: Value, s: Seq<u8>) -> bool {
    crate::json::document(body, v) && member_str(v, ERROR@, s) && revoked_code(s)
}

/// The member of `v` that `member_str` names.
spec fn error_member(v: Value, s: Seq<u8>) -> int {
    choose|k: int| 0 <= k < crate::json::members_of(v).len() && #[trigger] crate::json::members_of(v)[k].key@ == ERROR@
        && crate::json::members_of(v)[k].value is Str && crate::json::members_of(v)[k].value->Str_0@ == s
}
/// A value the same as `v` has the same members, key for key.
proof fn lemma_same_value_members(w: Value, v: Value)
    requires crate::json::same(w, v),
    ensures crate::json::members_of(w).len() == crate::json::members_of(v).len(),
        forall|k: int| 0 <= k < crate::json::members_of(v).len() ==> #[trigger] crate::json::members_of(w)[k].key@ == crate::json::members_of(v)[k].key@
            && crate::json::same(crate::json::members_of(w)[k].value, crate::json::members_of(v)[k].value),
{
    match w {
        Value::Object(xs) => { lemma_same_members(xs@, v->Object_0@); }
        _ => { assert(crate::json::members_of(w) =~= Seq::<json::Member>::empty()); assert(crate::json::members_of(v) =~= Seq::<json::Member>::empty()); }
    }
}
/// With `key` unique in `v`, the member named `key` that the reader found in
/// the same value `w` is the member `k` of `v`.
proof fn lemma_unique_pick(w: Value, v: Value, key: Seq<u8>, f: int, k: int)
    requires crate::json::same(w, v), unique_key(v, key),
        0 <= f < crate::json::members_of(w).len(), crate::json::members_of(w)[f].key@ == key,
        0 <= k < crate::json::members_of(v).len(), crate::json::members_of(v)[k].key@ == key,
    ensures f == k, crate::json::same(crate::json::members_of(w)[k].value, crate::json::members_of(v)[k].value),
{
    lemma_same_value_members(w, v);
    if f < k { assert(crate::json::members_of(v)[f].key@ == key); assert(crate::json::members_of(v)[k].key@ != key); }
    if k < f { assert(crate::json::members_of(v)[f].key@ != key); }
}

/// Whether a reply body names a revocation. Sound: true only when the
/// document carries one of the two codes. Complete for the documents the
/// reader accepts whose `error` key is unique: such a document with a
/// revocation code is never missed.
pub fn revocation(body: &[u8]) -> (out: bool)
    ensures
        out ==> exists|v: Value, s: Seq<u8>| #[trigger] revocation_reply(body@, v, s),
        forall|v: Value, s: Seq<u8>| #[trigger] revocation_reply(body@, v, s) && crate::json::depth(v) <= crate::json::MAX_DEPTH && unique_key(v, ERROR@) ==> out,
{
    let value = match json::parse(body) {
        Some(value) => value,
        None => {
            // The reader is complete: no accepted document is `body`.
            proof {
                assert forall|v: Value, s: Seq<u8>| #[trigger] revocation_reply(body@, v, s) && crate::json::depth(v) <= crate::json::MAX_DEPTH && unique_key(v, ERROR@) implies false by {
                    assert(crate::json::document(body@, v));
                }
            }
            return false;
        }
    };
    let member = match value.get(ERROR.as_slice()) {
        Some(member) => member,
        None => {
            proof {
                assert forall|v: Value, s: Seq<u8>| #[trigger] revocation_reply(body@, v, s) && crate::json::depth(v) <= crate::json::MAX_DEPTH && unique_key(v, ERROR@) implies false by {
                    let k = error_member(v, s);
                    lemma_same_value_members(value, v);
                    assert(crate::json::members_of(value)[k].key@ == ERROR@);
                }
            }
            return false;
        }
    };
    let code = match member.as_str() {
        Some(code) => code,
        None => {
            proof {
                assert forall|v: Value, s: Seq<u8>| #[trigger] revocation_reply(body@, v, s) && crate::json::depth(v) <= crate::json::MAX_DEPTH && unique_key(v, ERROR@) implies false by {
                    let k = error_member(v, s);
                    let f = choose|f: int| 0 <= f < crate::json::members_of(value).len() && #[trigger] crate::json::members_of(value)[f].key@ == ERROR@
                        && crate::json::members_of(value)[f].value == *member;
                    lemma_unique_pick(value, v, ERROR@, f, k);
                }
            }
            return false;
        }
    };
    let out = eq(code.as_slice(), REVOKED.as_slice()) || eq(code.as_slice(), DISABLED.as_slice());
    proof {
        if out {
            let f = choose|f: int| 0 <= f < crate::json::members_of(value).len() && #[trigger] crate::json::members_of(value)[f].key@ == ERROR@
                && crate::json::members_of(value)[f].value == *member;
            assert(member_str(value, ERROR@, code@));
            assert(revocation_reply(body@, value, code@));
        }
        assert forall|v: Value, s: Seq<u8>| #[trigger] revocation_reply(body@, v, s) && crate::json::depth(v) <= crate::json::MAX_DEPTH && unique_key(v, ERROR@) implies out by {
            let k = error_member(v, s);
            let f = choose|f: int| 0 <= f < crate::json::members_of(value).len() && #[trigger] crate::json::members_of(value)[f].key@ == ERROR@
                && crate::json::members_of(value)[f].value == *member;
            lemma_unique_pick(value, v, ERROR@, f, k);
            assert(code@ == s);
        }
    }
    out
}

// ---- Retry-After ---------------------------------------------------------------

pub open spec fn blank(b: u8) -> bool { b == 32 || b == 9 }
/// `value` is `n` written in decimal digits, with blanks around it.
pub open spec fn delta_seconds(value: Seq<u8>, n: u64) -> bool {
    exists|a: int, b: int| #[trigger] digits_at(value, a, b) && crate::inbound::value_of(value.subrange(a, b)) == n as nat
}
/// Bytes `[a, b)` of `value` are one or more digits and every other byte is a blank.
pub open spec fn digits_at(value: Seq<u8>, a: int, b: int) -> bool {
    0 <= a < b <= value.len() && crate::inbound::all_digits(value.subrange(a, b))
        && (forall|k: int| 0 <= k < a ==> blank(#[trigger] value[k]))
        && (forall|k: int| b <= k < value.len() ==> blank(#[trigger] value[k]))
}
/// Field `i` is the first one named `name`.
pub open spec fn first_named(fields: Seq<Field>, i: int, name: Seq<u8>) -> bool {
    0 <= i < fields.len() && fields[i].name@ == name && forall|j: int| 0 <= j < i ==> #[trigger] fields[j].name@ != name
}

/// A digit string's value is at least the value of any prefix.
proof fn lemma_prefix_value(d: Seq<u8>, i: int)
    requires 0 <= i <= d.len(), crate::inbound::all_digits(d),
    ensures crate::inbound::value_of(d) >= crate::inbound::value_of(d.subrange(0, i)),
    decreases d.len(),
{
    if i == d.len() {
        assert(d.subrange(0, i) =~= d);
    } else {
        assert(d.drop_last() =~= d.subrange(0, d.len() - 1));
        assert(crate::inbound::all_digits(d.drop_last()));
        lemma_prefix_value(d.drop_last(), i);
        assert(d.drop_last().subrange(0, i) =~= d.subrange(0, i));
    }
}

/// The delta-seconds a field value carries, if it is one.
#[verifier::loop_isolation(false)]
fn delta(value: &[u8]) -> (out: Option<u64>)
    ensures match out { Some(n) => delta_seconds(value@, n), None => forall|n: u64| !delta_seconds(value@, n) },
{
    let mut a: usize = 0;
    while a < value.len() && (value[a] == 32 || value[a] == 9)
        invariant a <= value.len(), forall|k: int| 0 <= k < a ==> blank(#[trigger] value@[k]),
        decreases value.len() - a,
    { a = a + 1; }
    if a == value.len() {
        // Every byte is a blank: there is no digit to find.
        proof {
            assert forall|n: u64| !delta_seconds(value@, n) by {
                if delta_seconds(value@, n) {
                    let (x, y) = choose|x: int, y: int| #[trigger] digits_at(value@, x, y) && crate::inbound::value_of(value@.subrange(x, y)) == n as nat;
                    assert(crate::inbound::is_digit(value@.subrange(x, y)[0]));
                    assert(blank(value@[x]));
                }
            }
        }
        return None;
    }
    let mut b: usize = value.len();
    while b > a + 1 && (value[b - 1] == 32 || value[b - 1] == 9)
        invariant a + 1 <= b <= value.len(), forall|k: int| b <= k < value.len() ==> blank(#[trigger] value@[k]),
        decreases b,
    { b = b - 1; }
    // Any digit run with blanks around it is exactly [a, b).
    proof {
        assert forall|x: int, y: int| #[trigger] digits_at(value@, x, y) implies x == a && y == b by {
            assert(crate::inbound::is_digit(value@.subrange(x, y)[0]));
            assert(value@.subrange(x, y)[0] == value@[x]);
            assert(crate::inbound::is_digit(value@.subrange(x, y)[y - x - 1]));
            assert(value@.subrange(x, y)[y - x - 1] == value@[y - 1]);
            if x < a { assert(blank(value@[x])); }
            if a < x { assert(blank(value@[a as int])); }
            if b < y { assert(blank(value@[y - 1])); }
            if y < b { assert(!blank(value@[b as int - 1])); assert(b - 1 >= y); }
        }
    }
    let digits = slice_subrange(value, a, b);
    let mut acc: u64 = 0;
    let mut i: usize = 0;
    while i < digits.len()
        invariant i <= digits.len(), digits@ == value@.subrange(a as int, b as int),
            crate::inbound::all_digits(digits@.subrange(0, i as int)), acc == crate::inbound::value_of(digits@.subrange(0, i as int)),
        decreases digits.len() - i,
    {
        let c = digits[i];
        if c < 48 || c > 57 {
            proof {
                assert forall|n: u64| !delta_seconds(value@, n) by {
                    if delta_seconds(value@, n) {
                        let (x, y) = choose|x: int, y: int| #[trigger] digits_at(value@, x, y) && crate::inbound::value_of(value@.subrange(x, y)) == n as nat;
                        assert(crate::inbound::is_digit(digits@[i as int]));
                    }
                }
            }
            return None;
        }
        let d = (c - 48) as u64;
        proof {
            assert(digits@.subrange(0, i as int + 1).drop_last() =~= digits@.subrange(0, i as int));
            assert(crate::inbound::all_digits(digits@.subrange(0, i as int + 1)));
        }
        if acc > (u64::MAX - d) / 10 {
            proof {
                assert forall|n: u64| !delta_seconds(value@, n) by {
                    if delta_seconds(value@, n) {
                        let (x, y) = choose|x: int, y: int| #[trigger] digits_at(value@, x, y) && crate::inbound::value_of(value@.subrange(x, y)) == n as nat;
                        let step = digits@.subrange(0, i as int + 1);
                        assert(crate::inbound::value_of(step) == acc * 10 + d);
                        lemma_prefix_value(digits@, i as int + 1);
                        assert(acc * 10 + d <= u64::MAX);
                        assert(acc <= (u64::MAX - d) / 10) by (nonlinear_arith) requires acc * 10 + d <= u64::MAX, d < 10;
                    }
                }
            }
            return None;
        }
        proof { assert(acc * 10 <= u64::MAX - d) by (nonlinear_arith) requires acc <= (u64::MAX - d) / 10; }
        acc = acc * 10 + d;
        i = i + 1;
    }
    proof {
        assert(digits@.subrange(0, digits.len() as int) =~= digits@);
        assert(digits_at(value@, a as int, b as int));
    }
    Some(acc)
}

/// The `Retry-After` delta of a reply, from its first `retry-after` field.
#[verifier::loop_isolation(false)]
pub fn retry_after(fields: &Vec<Field>) -> (out: Option<u64>)
    ensures match out {
        Some(n) => exists|i: int| #[trigger] first_named(fields@, i, RETRY_AFTER@) && delta_seconds(fields@[i].value@, n),
        None => forall|i: int, n: u64| first_named(fields@, i, RETRY_AFTER@) ==> !#[trigger] delta_seconds(fields@[i].value@, n),
    },
{
    let mut i: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(), forall|j: int| 0 <= j < i ==> #[trigger] fields@[j].name@ != RETRY_AFTER@,
        decreases fields.len() - i,
    {
        if eq(fields[i].name.as_slice(), RETRY_AFTER.as_slice()) {
            let out = delta(fields[i].value.as_slice());
            proof {
                assert(first_named(fields@, i as int, RETRY_AFTER@));
                assert forall|x: int| #[trigger] first_named(fields@, x, RETRY_AFTER@) implies x == i by {
                    if x < i { assert(fields@[x].name@ != RETRY_AFTER@); }
                    if i < x { assert(fields@[i as int].name@ != RETRY_AFTER@); }
                }
            }
            return out;
        }
        i = i + 1;
    }
    None
}

// ---- the request head ------------------------------------------------------------

/// The path each machine request goes to.
pub open spec fn path_of(path: Path) -> Seq<u8> {
    match path { Path::Bootstrap => BOOTSTRAP@, Path::Refresh => REFRESH@, Path::Ingest => INGEST@ }
}
pub open spec fn field_is(f: Field, name: Seq<u8>, value: Seq<u8>) -> bool { f.name@ == name && f.value@ == value }
pub open spec fn batch_id_of(r: Request) -> Seq<u8> { match r.batch_id { Some(id) => id@, None => Seq::empty() } }
/// How many fields precede the path-specific ones: host, connection, content-length, and the bearer if any.
pub open spec fn common_fields(r: Request) -> int { if r.bearer is Some { 4 } else { 3 } }
/// The fields of a machine request, in order: `host` is the configured
/// server, the connection closes, the length is the body's, the credential
/// is sent as a bearer (marked sensitive), and the content type and batch id
/// say what the body is.
pub open spec fn head_fields_ok(fields: Seq<Field>, authority: Seq<u8>, r: Request) -> bool {
    let n = common_fields(r);
    field_is(fields[0], HOST@, authority) && field_is(fields[1], CONNECTION@, CLOSE@)
        && field_is(fields[2], CONTENT_LENGTH@, crate::inbound::decimal(r.body@.len()))
        && (r.bearer is Some ==> field_is(fields[3], AUTHORIZATION@, BEARER@ + r.bearer.unwrap()@) && fields[3].sensitive)
        && match r.path {
            Path::Bootstrap => fields.len() == n + 1 && field_is(fields[n], CONTENT_TYPE@, JSON_TYPE@),
            Path::Refresh => fields.len() == n,
            Path::Ingest => fields.len() == n + 2 && field_is(fields[n], CONTENT_TYPE@, NDJSON_TYPE@)
                && field_is(fields[n + 1], BATCH_ID@, crate::shipping_identity::hex_encoding(batch_id_of(r))),
        }
}
/// Every byte of the target is visible ASCII, so the request line is one line.
pub open spec fn target_ok(target: Seq<u8>) -> bool {
    target.len() >= 1 && target[0] == 47 && forall|k: int| 0 <= k < target.len() ==> 33 <= #[trigger] target[k] <= 126
}
/// `bytes` is a request head for `r` to the server at `authority`: a POST
/// to the request's path with exactly the fields above, all wire-safe.
pub open spec fn request_head_ok(bytes: Seq<u8>, authority: Seq<u8>, r: Request) -> bool {
    exists|fields: Seq<Field>| #[trigger] head_fields_ok(fields, authority, r) && crate::http1_write::fields_wire_ok(fields)
        && target_ok(path_of(r.path)) && bytes == crate::http1_write::request_head_bytes(POST@, path_of(r.path), fields)
}

fn field(name: &[u8], value: Vec<u8>, sensitive: bool) -> (out: Field)
    ensures out.name@ == name@, out.value == value, out.sensitive == sensitive,
{
    Field { name: slice_to_vec(name), value, sensitive }
}
fn concat(a: &[u8], b: &[u8]) -> (out: Vec<u8>)
    ensures out@ == a@ + b@,
{
    let mut out = slice_to_vec(a);
    let mut i: usize = 0;
    while i < b.len()
        invariant i <= b.len(), out@ == a@ + b@.subrange(0, i as int),
        decreases b.len() - i,
    {
        out.push(b[i]);
        proof { assert(a@ + b@.subrange(0, i as int + 1) =~= (a@ + b@.subrange(0, i as int)).push(b@[i as int])); }
        i = i + 1;
    }
    proof { assert(b@.subrange(0, b.len() as int) =~= b@); }
    out
}
#[verifier::loop_isolation(false)]
fn target_ok_exec(target: &[u8]) -> (out: bool)
    ensures out == target_ok(target@),
{
    if target.len() == 0 || target[0] != 47 { return false; }
    let mut k: usize = 0;
    while k < target.len()
        invariant k <= target.len(), forall|m: int| 0 <= m < k ==> 33 <= #[trigger] target@[m] <= 126,
        decreases target.len() - k,
    {
        if target[k] < 33 || target[k] > 126 { return false; }
        k = k + 1;
    }
    true
}

/// The request head for a machine request, or nothing when a value cannot
/// be written on the wire (the configured authority is checked at startup
/// and the token by the issuing rule, so a refusal here means a value that
/// did not pass those).
pub fn request_head(authority: &[u8], r: &Request) -> (out: Option<Vec<u8>>)
    ensures match out { Some(bytes) => request_head_ok(bytes@, authority@, *r), None => true },
{
    let mut fields: Vec<Field> = Vec::new();
    fields.push(field(HOST.as_slice(), slice_to_vec(authority), false));
    fields.push(field(CONNECTION.as_slice(), slice_to_vec(CLOSE.as_slice()), false));
    fields.push(field(CONTENT_LENGTH.as_slice(), decimal_bytes(r.body.len() as u64), false));
    match &r.bearer {
        Some(token) => fields.push(field(AUTHORIZATION.as_slice(), concat(BEARER.as_slice(), token.as_slice()), true)),
        None => {}
    }
    let target: &[u8] = match r.path {
        Path::Bootstrap => {
            fields.push(field(CONTENT_TYPE.as_slice(), slice_to_vec(JSON_TYPE.as_slice()), false));
            BOOTSTRAP.as_slice()
        }
        Path::Refresh => REFRESH.as_slice(),
        Path::Ingest => {
            fields.push(field(CONTENT_TYPE.as_slice(), slice_to_vec(NDJSON_TYPE.as_slice()), false));
            let encoded_id = match &r.batch_id {
                Some(id) => hex(id.as_slice()),
                None => { let none: Vec<u8> = Vec::new(); hex(none.as_slice()) }
            };
            proof { assert(encoded_id@ == crate::shipping_identity::hex_encoding(batch_id_of(*r))); }
            fields.push(field(BATCH_ID.as_slice(), encoded_id, false));
            INGEST.as_slice()
        }
    };
    if !wire_ok(&fields) || !target_ok_exec(target) { return None; }
    let mut out: Vec<u8> = Vec::new();
    write_request_head(POST.as_slice(), target, &fields, &mut out);
    proof {
        assert(field_is(fields@[0], HOST@, authority@));
        assert(field_is(fields@[1], CONNECTION@, CLOSE@));
        assert(field_is(fields@[2], CONTENT_LENGTH@, crate::inbound::decimal(r.body@.len())));
        assert(r.bearer is Some ==> field_is(fields@[3], AUTHORIZATION@, BEARER@ + r.bearer.unwrap()@) && fields@[3].sensitive);
        assert(r.path is Refresh ==> fields@.len() == common_fields(*r));
        assert(r.path is Bootstrap ==> fields@.len() == common_fields(*r) + 1 && field_is(fields@[common_fields(*r)], CONTENT_TYPE@, JSON_TYPE@));
        assert(r.path is Ingest ==> fields@.len() == common_fields(*r) + 2 && field_is(fields@[common_fields(*r)], CONTENT_TYPE@, NDJSON_TYPE@));
        assert(r.path is Ingest ==> field_is(fields@[common_fields(*r) + 1], BATCH_ID@, crate::shipping_identity::hex_encoding(batch_id_of(*r))));
        assert(head_fields_ok(fields@, authority@, *r));
        assert(out@ =~= crate::http1_write::request_head_bytes(POST@, path_of(r.path), fields@));
    }
    Some(out)
}

} // verus!
