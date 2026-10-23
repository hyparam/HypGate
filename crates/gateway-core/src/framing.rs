use vstd::prelude::*;
use vstd::bytes::*;
use vstd::slice::slice_subrange;

verus! {
pub struct Header {
    pub payload: u32,
    pub tenant: u64,
    pub request: u64,
    pub chunk: u64,
    pub direction: u8,
}
pub open spec fn valid(h: Header) -> bool { h.payload <= 1048576 && h.request != 0 && h.direction <= 1 }
pub open spec fn encoding(h: Header) -> Seq<u8> {
    seq![83u8, 71u8, 82u8, 49u8] + spec_u32_to_le_bytes(h.payload)
        + spec_u64_to_le_bytes(h.tenant) + spec_u64_to_le_bytes(h.request)
        + spec_u64_to_le_bytes(h.chunk) + seq![h.direction]
}
pub open spec fn decoded(bytes: Seq<u8>) -> Option<Header> {
    if bytes.len() != 33 || bytes[0] != 83 || bytes[1] != 71 || bytes[2] != 82 || bytes[3] != 49 {
        None
    } else {
        let h = Header { payload: spec_u32_from_le_bytes(bytes.subrange(4, 8)),
            tenant: spec_u64_from_le_bytes(bytes.subrange(8, 16)),
            request: spec_u64_from_le_bytes(bytes.subrange(16, 24)),
            chunk: spec_u64_from_le_bytes(bytes.subrange(24, 32)), direction: bytes[32] };
        if valid(h) { Some(h) } else { None }
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
        i = i + 1;
        proof { assert(bytes@.subrange(0, i as int) =~= bytes@.subrange(0, i as int - 1).push(bytes@[i as int - 1])); }
    }
}

pub fn encode(h: Header) -> (out: Option<Vec<u8>>)
    ensures match out {
        Some(bytes) => valid(h) && bytes@ == encoding(h) && bytes.len() == 33 && decoded(bytes@) == Some(h),
        None => !valid(h),
    },
{
    if h.payload > 1048576 || h.request == 0 || h.direction > 1 { return None; }
    proof { lemma_auto_spec_u32_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut bytes = Vec::new();
    bytes.push(83); bytes.push(71); bytes.push(82); bytes.push(49);
    append(&mut bytes, u32_to_le_bytes(h.payload).as_slice());
    append(&mut bytes, u64_to_le_bytes(h.tenant).as_slice());
    append(&mut bytes, u64_to_le_bytes(h.request).as_slice());
    append(&mut bytes, u64_to_le_bytes(h.chunk).as_slice());
    bytes.push(h.direction);
    proof {
        assert(bytes@.subrange(4, 8) =~= spec_u32_to_le_bytes(h.payload));
        assert(bytes@.subrange(8, 16) =~= spec_u64_to_le_bytes(h.tenant));
        assert(bytes@.subrange(16, 24) =~= spec_u64_to_le_bytes(h.request));
        assert(bytes@.subrange(24, 32) =~= spec_u64_to_le_bytes(h.chunk));
    }
    Some(bytes)
}

pub fn decode(bytes: &[u8]) -> (out: Option<Header>)
    ensures out == decoded(bytes@), match out { Some(h) => valid(h) && encoding(h) == bytes@, None => true },
{
    if bytes.len() != 33 || bytes[0] != 83 || bytes[1] != 71 || bytes[2] != 82 || bytes[3] != 49 { return None; }
    let payload = u32_from_le_bytes(slice_subrange(bytes, 4, 8));
    let tenant = u64_from_le_bytes(slice_subrange(bytes, 8, 16));
    let request = u64_from_le_bytes(slice_subrange(bytes, 16, 24));
    let chunk = u64_from_le_bytes(slice_subrange(bytes, 24, 32));
    let direction = bytes[32];
    if payload > 1048576 || request == 0 || direction > 1 { return None; }
    let h = Header { payload, tenant, request, chunk, direction };
    proof {
        lemma_auto_spec_u32_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes();
        assert(encoding(h) =~= bytes@);
    }
    Some(h)
}

// Advance only across a whole bounded frame: 33 header bytes, payload, 32 digest.
// The caller must bind available to bytes actually read; I/O is outside this core.
pub fn frame_end(start: u64, payload: u32, available: u64) -> (out: Option<u64>)
    ensures match out {
        Some(end) => payload <= 1048576 && end == start + 65 + payload && end > start
            && end - start <= available,
        None => payload > 1048576 || available < 65 + payload || start + 65 + payload > u64::MAX,
    },
{
    if payload > 1048576 { return None; }
    let length = 65u64 + payload as u64;
    if available < length || start > u64::MAX - length { return None; }
    Some(start + length)
}
}
