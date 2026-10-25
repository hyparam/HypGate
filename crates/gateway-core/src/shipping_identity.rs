//! Verified fixed-width identities for shipped exchanges, messages, parts, and
//! batches. Each is a concatenation of fixed-width fields, so distinct inputs
//! always give distinct byte strings; the runtime hex-encodes them. This is what
//! makes the server's batch ledger and `part_id` dedup sound across retries and
//! restarts: the same exchange always carries the same identifiers.
use vstd::prelude::*;
use vstd::bytes::*;
use crate::framing::append;

verus! {
pub const EXCHANGE_KEY_LEN: usize = 24;
pub const MESSAGE_KEY_LEN: usize = 28;
pub const PART_KEY_LEN: usize = 32;
pub const BATCH_ID_LEN: usize = 40;

pub open spec fn exchange_key_encoding(session: Seq<u8>, request: u64) -> Seq<u8> {
    session + spec_u64_to_le_bytes(request)
}
pub open spec fn message_key_encoding(session: Seq<u8>, request: u64, message: u32) -> Seq<u8> {
    exchange_key_encoding(session, request) + spec_u32_to_le_bytes(message)
}
pub open spec fn part_key_encoding(session: Seq<u8>, request: u64, message: u32, part: u32) -> Seq<u8> {
    message_key_encoding(session, request, message) + spec_u32_to_le_bytes(part)
}
pub open spec fn batch_id_encoding(session: Seq<u8>, first: u64, end: u64, checksum: u64) -> Seq<u8> {
    session + spec_u64_to_le_bytes(first) + spec_u64_to_le_bytes(end) + spec_u64_to_le_bytes(checksum)
}

pub proof fn exchange_key_injective(s1: Seq<u8>, r1: u64, s2: Seq<u8>, r2: u64)
    requires s1.len() == 16, s2.len() == 16,
        exchange_key_encoding(s1, r1) == exchange_key_encoding(s2, r2),
    ensures s1 == s2, r1 == r2,
{
    lemma_auto_spec_u64_to_from_le_bytes();
    let e1 = exchange_key_encoding(s1, r1); let e2 = exchange_key_encoding(s2, r2);
    assert(e1.subrange(0, 16) =~= s1); assert(e2.subrange(0, 16) =~= s2);
    assert(e1.subrange(16, 24) =~= spec_u64_to_le_bytes(r1)); assert(e2.subrange(16, 24) =~= spec_u64_to_le_bytes(r2));
}

pub proof fn message_key_injective(s1: Seq<u8>, r1: u64, m1: u32, s2: Seq<u8>, r2: u64, m2: u32)
    requires s1.len() == 16, s2.len() == 16,
        message_key_encoding(s1, r1, m1) == message_key_encoding(s2, r2, m2),
    ensures s1 == s2, r1 == r2, m1 == m2,
{
    lemma_auto_spec_u32_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes();
    let e1 = message_key_encoding(s1, r1, m1); let e2 = message_key_encoding(s2, r2, m2);
    assert(e1.subrange(0, 24) =~= exchange_key_encoding(s1, r1)); assert(e2.subrange(0, 24) =~= exchange_key_encoding(s2, r2));
    exchange_key_injective(s1, r1, s2, r2);
    assert(e1.subrange(24, 28) =~= spec_u32_to_le_bytes(m1)); assert(e2.subrange(24, 28) =~= spec_u32_to_le_bytes(m2));
}

pub proof fn part_key_injective(s1: Seq<u8>, r1: u64, m1: u32, p1: u32, s2: Seq<u8>, r2: u64, m2: u32, p2: u32)
    requires s1.len() == 16, s2.len() == 16,
        part_key_encoding(s1, r1, m1, p1) == part_key_encoding(s2, r2, m2, p2),
    ensures s1 == s2, r1 == r2, m1 == m2, p1 == p2,
{
    lemma_auto_spec_u32_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes();
    let e1 = part_key_encoding(s1, r1, m1, p1); let e2 = part_key_encoding(s2, r2, m2, p2);
    assert(e1.subrange(0, 28) =~= message_key_encoding(s1, r1, m1)); assert(e2.subrange(0, 28) =~= message_key_encoding(s2, r2, m2));
    message_key_injective(s1, r1, m1, s2, r2, m2);
    assert(e1.subrange(28, 32) =~= spec_u32_to_le_bytes(p1)); assert(e2.subrange(28, 32) =~= spec_u32_to_le_bytes(p2));
}

pub proof fn batch_id_injective(s1: Seq<u8>, f1: u64, e1: u64, c1: u64, s2: Seq<u8>, f2: u64, e2: u64, c2: u64)
    requires s1.len() == 16, s2.len() == 16,
        batch_id_encoding(s1, f1, e1, c1) == batch_id_encoding(s2, f2, e2, c2),
    ensures s1 == s2, f1 == f2, e1 == e2, c1 == c2,
{
    lemma_auto_spec_u64_to_from_le_bytes();
    let b1 = batch_id_encoding(s1, f1, e1, c1); let b2 = batch_id_encoding(s2, f2, e2, c2);
    assert(b1.subrange(0, 16) =~= s1); assert(b2.subrange(0, 16) =~= s2);
    assert(b1.subrange(16, 24) =~= spec_u64_to_le_bytes(f1)); assert(b2.subrange(16, 24) =~= spec_u64_to_le_bytes(f2));
    assert(b1.subrange(24, 32) =~= spec_u64_to_le_bytes(e1)); assert(b2.subrange(24, 32) =~= spec_u64_to_le_bytes(e2));
    assert(b1.subrange(32, 40) =~= spec_u64_to_le_bytes(c1)); assert(b2.subrange(32, 40) =~= spec_u64_to_le_bytes(c2));
}

pub fn exchange_key(session: &[u8; 16], request: u64) -> (out: Vec<u8>)
    ensures out@ == exchange_key_encoding(session@, request), out@.len() == 24,
{
    let mut bytes = Vec::with_capacity(24);
    append(&mut bytes, session.as_slice());
    append(&mut bytes, u64_to_le_bytes(request).as_slice());
    bytes
}

pub fn message_key(session: &[u8; 16], request: u64, message: u32) -> (out: Vec<u8>)
    ensures out@ == message_key_encoding(session@, request, message), out@.len() == 28,
{
    let mut bytes = exchange_key(session, request);
    append(&mut bytes, u32_to_le_bytes(message).as_slice());
    bytes
}

pub fn part_key(session: &[u8; 16], request: u64, message: u32, part: u32) -> (out: Vec<u8>)
    ensures out@ == part_key_encoding(session@, request, message, part), out@.len() == 32,
{
    let mut bytes = message_key(session, request, message);
    append(&mut bytes, u32_to_le_bytes(part).as_slice());
    bytes
}

/// Session, index range of the exchanges in the batch, and a checksum of the
/// batch body. A retried or re-sent batch computes the identical id.
pub fn batch_id(session: &[u8; 16], first: u64, end: u64, checksum: u64) -> (out: Vec<u8>)
    ensures out@ == batch_id_encoding(session@, first, end, checksum), out@.len() == 40,
{
    let mut bytes = Vec::with_capacity(40);
    append(&mut bytes, session.as_slice());
    append(&mut bytes, u64_to_le_bytes(first).as_slice());
    append(&mut bytes, u64_to_le_bytes(end).as_slice());
    append(&mut bytes, u64_to_le_bytes(checksum).as_slice());
    bytes
}
}
