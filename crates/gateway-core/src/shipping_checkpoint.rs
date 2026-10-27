//! Checkpoint codecs and exact S3 destination binding. No hashing assumption is needed for scope identity.
use vstd::prelude::*;
use vstd::bytes::*;
#[allow(unused_imports)]
use crate::{config_schema as schema, json::{self, Value, Member}, framing::append, s3_config::Config, shipping_identity::hex, shipper::Machine};
use schema::{K_SESSION, K_RESOLVED, K_POISONED, K_MAX_OPEN_EXCHANGES, K_MAX_EXCHANGE_BYTES};

verus! {
#[derive(Debug, PartialEq, Eq)]
pub struct Checkpoint { pub session: Vec<u8>, pub resolved: u64, pub poisoned: u64, pub max_open_exchanges: usize, pub max_exchange_bytes: usize }
pub open spec fn shape(v: Value) -> bool {
    schema::object_ok(v, schema::Schema::Checkpoint)
        && schema::has_key(v, K_SESSION@) && schema::at(v, K_SESSION@) is Str
        && schema::has_key(v, K_RESOLVED@) && schema::is_u64(schema::at(v, K_RESOLVED@))
        && schema::has_key(v, K_POISONED@) && schema::is_u64(schema::at(v, K_POISONED@))
        && schema::has_key(v, K_MAX_OPEN_EXCHANGES@) && schema::is_usize(schema::at(v, K_MAX_OPEN_EXCHANGES@))
        && schema::has_key(v, K_MAX_EXCHANGE_BYTES@) && schema::is_usize(schema::at(v, K_MAX_EXCHANGE_BYTES@))
}
pub open spec fn reads(v: Value, c: Checkpoint) -> bool {
    c.session@ == schema::text_of(schema::at(v, K_SESSION@)) && c.resolved == schema::u64_of(schema::at(v, K_RESOLVED@))
        && c.poisoned == schema::u64_of(schema::at(v, K_POISONED@))
        && c.max_open_exchanges == schema::u64_of(schema::at(v, K_MAX_OPEN_EXCHANGES@))
        && c.max_exchange_bytes == schema::u64_of(schema::at(v, K_MAX_EXCHANGE_BYTES@))
}
pub fn parse(v: &Value) -> (out: Option<Checkpoint>)
    ensures match out { Some(c) => shape(*v) && reads(*v, c), None => !shape(*v) },
{
    if schema::object(v, schema::Schema::Checkpoint).is_none() { return None; }
    let session = match schema::required_str(v, K_SESSION.as_slice()) { Some(x) => x, None => return None };
    let resolved = match schema::required_u64(v, K_RESOLVED.as_slice()) { Some(x) => x, None => return None };
    let poisoned = match schema::required_u64(v, K_POISONED.as_slice()) { Some(x) => x, None => return None };
    let max_open_exchanges = match schema::required_usize(v, K_MAX_OPEN_EXCHANGES.as_slice()) { Some(x) => x, None => return None };
    let max_exchange_bytes = match schema::required_usize(v, K_MAX_EXCHANGE_BYTES.as_slice()) { Some(x) => x, None => return None };
    Some(Checkpoint { session, resolved, poisoned, max_open_exchanges, max_exchange_bytes })
}
fn push_member(ms: &mut Vec<Member>, key: &[u8], value: Value)
    requires json::well_formed_members(old(ms)@), json::well_formed(value),
    ensures final(ms).len() == old(ms).len() + 1, final(ms)@.drop_last() == old(ms)@,
        final(ms)@.last().key@ == key@, final(ms)@.last().value == value, json::well_formed_members(final(ms)@),
{
    ms.push(Member { key: vstd::slice::slice_to_vec(key), value });
    proof { assert(ms@.drop_last() =~= old(ms)@); }
}
/// Exactly the five checkpoint fields, all accepted by the verified JSON writer.
pub fn value(c: &Checkpoint) -> (out: Value)
    ensures json::well_formed(out), shape(out), reads(out, *c),
{
    let mut ms = Vec::new();
    push_member(&mut ms, K_SESSION.as_slice(), Value::Str(c.session.clone()));
    push_member(&mut ms, K_RESOLVED.as_slice(), Value::from_u64(c.resolved));
    push_member(&mut ms, K_POISONED.as_slice(), Value::from_u64(c.poisoned));
    push_member(&mut ms, K_MAX_OPEN_EXCHANGES.as_slice(), Value::from_u64(c.max_open_exchanges as u64));
    push_member(&mut ms, K_MAX_EXCHANGE_BYTES.as_slice(), Value::from_u64(c.max_exchange_bytes as u64));
    let out = Value::Object(ms);
    proof {
        let fields = json::members_of(out);
        reveal(K_RESOLVED); reveal(K_POISONED); reveal(K_MAX_OPEN_EXCHANGES); reveal(K_MAX_EXCHANGE_BYTES);
        assert(K_RESOLVED@[0] == 114 && K_POISONED@[0] == 112);
        assert(K_MAX_OPEN_EXCHANGES@[4] == 111 && K_MAX_EXCHANGE_BYTES@[4] == 101);
        assert(fields[0].key@ == K_SESSION@); assert(fields[1].key@ == K_RESOLVED@); assert(fields[2].key@ == K_POISONED@);
        assert(fields[3].key@ == K_MAX_OPEN_EXCHANGES@); assert(fields[4].key@ == K_MAX_EXCHANGE_BYTES@);
        assert(fields[1].key@[0] != fields[2].key@[0]); assert(fields[3].key@[4] != fields[4].key@[4]);
        assert(schema::distinct_keys(out)) by {
            assert forall|i: int, j: int| 0 <= i < j < fields.len() implies #[trigger] fields[i].key@ != #[trigger] fields[j].key@ by {
                if i == 1 && j == 2 { assert(fields[i].key@[0] != fields[j].key@[0]); }
                else if i == 3 && j == 4 { assert(fields[i].key@[4] != fields[j].key@[4]); }
                else { assert(fields[i].key.len() != fields[j].key.len()); }
            }
        }
        assert forall|i: int| 0 <= i < fields.len() implies schema::key_allowed(schema::Schema::Checkpoint, #[trigger] fields[i].key@) by {}
        assert(schema::at(out, K_SESSION@) == fields[0].value);
        assert(schema::at(out, K_RESOLVED@) == fields[1].value);
        assert(schema::at(out, K_POISONED@) == fields[2].value);
        assert(schema::at(out, K_MAX_OPEN_EXCHANGES@) == fields[3].value);
        assert(schema::at(out, K_MAX_EXCHANGE_BYTES@) == fields[4].value);
        schema::lemma_u64_of(fields[1].value, c.resolved);
        schema::lemma_u64_of(fields[2].value, c.poisoned);
        schema::lemma_u64_of(fields[3].value, c.max_open_exchanges as u64);
        schema::lemma_u64_of(fields[4].value, c.max_exchange_bytes as u64);
        assert(schema::has_key(out, K_SESSION@)); assert(schema::has_key(out, K_RESOLVED@)); assert(schema::has_key(out, K_POISONED@));
        assert(schema::has_key(out, K_MAX_OPEN_EXCHANGES@)); assert(schema::has_key(out, K_MAX_EXCHANGE_BYTES@));
        reveal_with_fuel(json::well_formed_members, 6);
    }
    out
}
/// Length-prefixed components plus the fixed-width log session: injective, unlike a hash fingerprint.
pub open spec fn scope(authority: Seq<u8>, prefix: Seq<u8>, region: Seq<u8>, session: Seq<u8>) -> Seq<u8> {
    spec_u64_to_le_bytes(authority.len() as u64) + spec_u64_to_le_bytes(prefix.len() as u64) + spec_u64_to_le_bytes(region.len() as u64)
        + authority + prefix + region + session
}
pub open spec fn identity_spec(c: Config, session: Seq<u8>) -> Seq<u8> {
    b"s3-v2:"@ + crate::shipping_identity::hex_encoding(scope(c.authority@, c.prefix@, c.region@, session))
}
pub fn identity(c: &Config, session: &[u8; 16]) -> (out: Vec<u8>)
    ensures out@ == identity_spec(*c, session@),
{
    let mut raw = Vec::new();
    append(&mut raw, u64_to_le_bytes(c.authority.len() as u64).as_slice());
    append(&mut raw, u64_to_le_bytes(c.prefix.len() as u64).as_slice());
    append(&mut raw, u64_to_le_bytes(c.region.len() as u64).as_slice());
    append(&mut raw, c.authority.as_slice()); append(&mut raw, c.prefix.as_slice()); append(&mut raw, c.region.as_slice()); append(&mut raw, session.as_slice());
    let mut out = vstd::slice::slice_to_vec(b"s3-v2:"); append(&mut out, hex(raw.as_slice()).as_slice()); out
}
pub proof fn identity_injective(a: Config, b: Config, s: Seq<u8>, t: Seq<u8>)
    requires a.valid(), b.valid(), s.len() == 16, t.len() == 16, identity_spec(a, s) == identity_spec(b, t),
    ensures a.authority@ == b.authority@, a.prefix@ == b.prefix@, a.region@ == b.region@, s == t,
{
    let x = scope(a.authority@, a.prefix@, a.region@, s);
    let y = scope(b.authority@, b.prefix@, b.region@, t);
    assert(identity_spec(a, s).subrange(6, identity_spec(a, s).len() as int) =~= crate::shipping_identity::hex_encoding(x));
    assert(identity_spec(b, t).subrange(6, identity_spec(b, t).len() as int) =~= crate::shipping_identity::hex_encoding(y));
    assert(crate::shipping_identity::hex_encoding(x) =~= crate::shipping_identity::hex_encoding(y));
    crate::shipping_identity::hex_injective(x, y);
    lemma_auto_spec_u64_to_from_le_bytes();
    assert(x.subrange(0, 8) =~= spec_u64_to_le_bytes(a.authority.len() as u64));
    assert(y.subrange(0, 8) =~= spec_u64_to_le_bytes(b.authority.len() as u64));
    assert(x.subrange(8, 16) =~= spec_u64_to_le_bytes(a.prefix.len() as u64));
    assert(y.subrange(8, 16) =~= spec_u64_to_le_bytes(b.prefix.len() as u64));
    assert(x.subrange(16, 24) =~= spec_u64_to_le_bytes(a.region.len() as u64));
    assert(y.subrange(16, 24) =~= spec_u64_to_le_bytes(b.region.len() as u64));
    assert(a.authority.len() == b.authority.len()); assert(a.prefix.len() == b.prefix.len()); assert(a.region.len() == b.region.len());
    let i = 24 + a.authority.len() as int;
    let j = i + a.prefix.len() as int;
    let k = j + a.region.len() as int;
    assert(x.subrange(24, i) =~= a.authority@); assert(y.subrange(24, i) =~= b.authority@);
    assert(x.subrange(i, j) =~= a.prefix@); assert(y.subrange(i, j) =~= b.prefix@);
    assert(x.subrange(j, k) =~= a.region@); assert(y.subrange(j, k) =~= b.region@);
    assert(x.subrange(k, x.len() as int) =~= s); assert(y.subrange(k, y.len() as int) =~= t);
}
/// A checkpoint from any other endpoint, prefix, region, or log session cannot be accepted.
pub proof fn foreign_scope_rejected(a: Config, b: Config, s: Seq<u8>, t: Seq<u8>, saved: Checkpoint, open: usize, bytes: usize)
    requires a.valid(), b.valid(), s.len() == 16, t.len() == 16, saved.session@ == identity_spec(a, s),
        a.authority@ != b.authority@ || a.prefix@ != b.prefix@ || a.region@ != b.region@ || s != t,
    ensures !matches(saved, identity_spec(b, t), open, bytes),
{
    if saved.session@ == identity_spec(b, t) { identity_injective(a, b, s, t); }
}
pub open spec fn matches(c: Checkpoint, identity: Seq<u8>, open: usize, bytes: usize) -> bool {
    c.session@ == identity && c.max_open_exchanges == open && c.max_exchange_bytes == bytes
}
pub fn select(c: &Option<Checkpoint>, identity: &[u8], open: usize, bytes: usize) -> (out: (u64, u64))
    ensures out == (match c { Some(c) => if matches(*c, identity@, open, bytes) { (c.resolved, c.poisoned) } else { (0, 0) }, None => (0, 0) }),
{
    match c {
        Some(c) => if crate::headers::eq(c.session.as_slice(), identity) && c.max_open_exchanges == open && c.max_exchange_bytes == bytes {
            (c.resolved, c.poisoned)
        } else { (0, 0) },
        None => (0, 0),
    }
}
/// A checkpoint count always comes from the actual machine, never from an adapter's counter.
pub fn capture(_machine: &Machine, identity: &[u8], open: usize, bytes: usize, resolved: u64, poisoned: u64) -> (out: Checkpoint)
    requires resolved == _machine.resolved(), poisoned == _machine.poisoned(),
    ensures matches(out, identity@, open, bytes), out.resolved == _machine.resolved(), out.poisoned == _machine.poisoned(),
{
    Checkpoint { session: vstd::slice::slice_to_vec(identity), resolved, poisoned, max_open_exchanges: open, max_exchange_bytes: bytes }
}
} // verus!
