//! Verified codecs for the metadata record payloads: request start (kind 2),
//! response head (kind 3), and completion (kind 4). Each has a specification
//! encoding, an executable encoder whose output decodes to the original fields,
//! and an executable decoder that agrees with the specification on every input
//! and re-encodes to the identical bytes. Wall-clock values, HTTP statuses, and
//! outcome codes are structural data supplied by trusted runtime code.
use vstd::prelude::*;
use vstd::bytes::*;
use vstd::slice::{slice_subrange, slice_to_vec};
use crate::framing::append;

verus! {
pub const MAX_DESTINATION: usize = 8192;
// u64 time, u64 selector, u16 destination length, then the destination bytes.
pub const REQUEST_START_PREFIX: usize = 18;
pub const RESPONSE_HEAD_LEN: usize = 10;
pub const COMPLETION_LEN: usize = 25;
// The longest metadata payload: a request start with an 8192-byte destination.
pub const MAX_PAYLOAD: usize = 8210;

pub const OUTCOME_SUCCESS: u8 = 0;
pub const OUTCOME_UPSTREAM_FAILURE: u8 = 1;
pub const OUTCOME_UPSTREAM_TIMEOUT: u8 = 2;
pub const OUTCOME_UPLOAD_FAILURE: u8 = 3;
pub const OUTCOME_DOWNLOAD_FAILURE: u8 = 4;
pub const OUTCOME_CLIENT_DISCONNECT: u8 = 5;
pub const OUTCOME_LOG_REFUSAL: u8 = 6;
pub const OUTCOME_OTHER: u8 = 7;
pub const MAX_OUTCOME: u8 = 7;

#[derive(Debug, PartialEq, Eq)]
pub struct RequestStart { pub time_ms: u64, pub selector: u64, pub destination: Vec<u8> }
#[derive(Debug, PartialEq, Eq)]
pub struct ResponseHead { pub time_ms: u64, pub status: u16 }
#[derive(Debug, PartialEq, Eq)]
pub struct Completion { pub time_ms: u64, pub outcome: u8, pub upload_bytes: u64, pub download_bytes: u64 }

// Request start: destination is 1 to 8192 bytes. Its content is the configured
// URI text; the codec checks only its length.
pub open spec fn request_start_valid(destination: Seq<u8>) -> bool { 1 <= destination.len() <= 8192 }
pub open spec fn request_start_encoding(time_ms: u64, selector: u64, destination: Seq<u8>) -> Seq<u8> {
    spec_u64_to_le_bytes(time_ms) + spec_u64_to_le_bytes(selector)
        + spec_u16_to_le_bytes(destination.len() as u16) + destination
}
pub open spec fn decoded_request_start(bytes: Seq<u8>) -> Option<(u64, u64, Seq<u8>)> {
    if bytes.len() < 18 { None } else {
        let length = spec_u16_from_le_bytes(bytes.subrange(16, 18));
        if length == 0 || length > 8192 || bytes.len() != 18 + length { None }
        else {
            Some((spec_u64_from_le_bytes(bytes.subrange(0, 8)), spec_u64_from_le_bytes(bytes.subrange(8, 16)),
                bytes.subrange(18, bytes.len() as int)))
        }
    }
}

pub proof fn request_start_roundtrip(time_ms: u64, selector: u64, destination: Seq<u8>)
    requires request_start_valid(destination),
    ensures request_start_encoding(time_ms, selector, destination).len() == 18 + destination.len(),
        decoded_request_start(request_start_encoding(time_ms, selector, destination)) == Some((time_ms, selector, destination)),
{
    lemma_auto_spec_u16_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes();
    let bytes = request_start_encoding(time_ms, selector, destination);
    assert(bytes.subrange(0, 8) =~= spec_u64_to_le_bytes(time_ms));
    assert(bytes.subrange(8, 16) =~= spec_u64_to_le_bytes(selector));
    assert(bytes.subrange(16, 18) =~= spec_u16_to_le_bytes(destination.len() as u16));
    assert(bytes.subrange(18, bytes.len() as int) =~= destination);
}

pub fn encode_request_start(time_ms: u64, selector: u64, destination: &[u8]) -> (out: Option<Vec<u8>>)
    ensures match out {
        Some(bytes) => request_start_valid(destination@)
            && bytes@ == request_start_encoding(time_ms, selector, destination@)
            && bytes.len() == 18 + destination.len() && bytes.len() <= 8210
            && decoded_request_start(bytes@) == Some((time_ms, selector, destination@)),
        None => !request_start_valid(destination@),
    },
{
    if destination.len() == 0 || destination.len() > 8192 { return None; }
    proof { lemma_auto_spec_u16_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut bytes = Vec::with_capacity(18 + destination.len());
    append(&mut bytes, u64_to_le_bytes(time_ms).as_slice());
    append(&mut bytes, u64_to_le_bytes(selector).as_slice());
    append(&mut bytes, u16_to_le_bytes(destination.len() as u16).as_slice());
    append(&mut bytes, destination);
    proof {
        assert(bytes@ =~= request_start_encoding(time_ms, selector, destination@));
        request_start_roundtrip(time_ms, selector, destination@);
    }
    Some(bytes)
}

pub fn decode_request_start(bytes: &[u8]) -> (out: Option<RequestStart>)
    ensures match out {
        Some(r) => decoded_request_start(bytes@) == Some((r.time_ms, r.selector, r.destination@))
            && request_start_valid(r.destination@) && bytes.len() == 18 + r.destination.len()
            && bytes@ == request_start_encoding(r.time_ms, r.selector, r.destination@),
        None => decoded_request_start(bytes@).is_none(),
    },
{
    if bytes.len() < 18 { return None; }
    let length = u16_from_le_bytes(slice_subrange(bytes, 16, 18));
    if length == 0 || length > 8192 || bytes.len() != 18 + length as usize { return None; }
    let time_ms = u64_from_le_bytes(slice_subrange(bytes, 0, 8));
    let selector = u64_from_le_bytes(slice_subrange(bytes, 8, 16));
    let destination = slice_to_vec(slice_subrange(bytes, 18, bytes.len()));
    proof {
        lemma_auto_spec_u16_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes();
        assert(request_start_encoding(time_ms, selector, destination@) =~= bytes@);
    }
    Some(RequestStart { time_ms, selector, destination })
}

// Response head: u64 time, u16 HTTP status in 100..=999.
pub open spec fn response_head_valid(status: u16) -> bool { 100 <= status <= 999 }
pub open spec fn response_head_encoding(time_ms: u64, status: u16) -> Seq<u8> {
    spec_u64_to_le_bytes(time_ms) + spec_u16_to_le_bytes(status)
}
pub open spec fn decoded_response_head(bytes: Seq<u8>) -> Option<(u64, u16)> {
    if bytes.len() != 10 { None } else {
        let status = spec_u16_from_le_bytes(bytes.subrange(8, 10));
        if response_head_valid(status) { Some((spec_u64_from_le_bytes(bytes.subrange(0, 8)), status)) } else { None }
    }
}

pub proof fn response_head_roundtrip(time_ms: u64, status: u16)
    requires response_head_valid(status),
    ensures response_head_encoding(time_ms, status).len() == 10,
        decoded_response_head(response_head_encoding(time_ms, status)) == Some((time_ms, status)),
{
    lemma_auto_spec_u16_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes();
    let bytes = response_head_encoding(time_ms, status);
    assert(bytes.subrange(0, 8) =~= spec_u64_to_le_bytes(time_ms));
    assert(bytes.subrange(8, 10) =~= spec_u16_to_le_bytes(status));
}

pub fn encode_response_head(time_ms: u64, status: u16) -> (out: Option<Vec<u8>>)
    ensures match out {
        Some(bytes) => response_head_valid(status) && bytes@ == response_head_encoding(time_ms, status)
            && bytes.len() == 10 && decoded_response_head(bytes@) == Some((time_ms, status)),
        None => !response_head_valid(status),
    },
{
    if status < 100 || status > 999 { return None; }
    proof { lemma_auto_spec_u16_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut bytes = Vec::with_capacity(10);
    append(&mut bytes, u64_to_le_bytes(time_ms).as_slice());
    append(&mut bytes, u16_to_le_bytes(status).as_slice());
    proof {
        assert(bytes@ =~= response_head_encoding(time_ms, status));
        response_head_roundtrip(time_ms, status);
    }
    Some(bytes)
}

pub fn decode_response_head(bytes: &[u8]) -> (out: Option<ResponseHead>)
    ensures match out {
        Some(r) => decoded_response_head(bytes@) == Some((r.time_ms, r.status))
            && response_head_valid(r.status) && bytes.len() == 10
            && bytes@ == response_head_encoding(r.time_ms, r.status),
        None => decoded_response_head(bytes@).is_none(),
    },
{
    if bytes.len() != 10 { return None; }
    let status = u16_from_le_bytes(slice_subrange(bytes, 8, 10));
    if status < 100 || status > 999 { return None; }
    let time_ms = u64_from_le_bytes(slice_subrange(bytes, 0, 8));
    proof {
        lemma_auto_spec_u16_to_from_le_bytes(); lemma_auto_spec_u64_to_from_le_bytes();
        assert(response_head_encoding(time_ms, status) =~= bytes@);
    }
    Some(ResponseHead { time_ms, status })
}

// Completion: u64 time, u8 outcome in 0..=7, u64 accepted upload bytes, u64 accepted download bytes.
pub open spec fn completion_valid(outcome: u8) -> bool { outcome <= 7 }
pub open spec fn completion_encoding(time_ms: u64, outcome: u8, upload_bytes: u64, download_bytes: u64) -> Seq<u8> {
    spec_u64_to_le_bytes(time_ms) + seq![outcome] + spec_u64_to_le_bytes(upload_bytes) + spec_u64_to_le_bytes(download_bytes)
}
pub open spec fn decoded_completion(bytes: Seq<u8>) -> Option<(u64, u8, u64, u64)> {
    if bytes.len() != 25 || !completion_valid(bytes[8]) { None } else {
        Some((spec_u64_from_le_bytes(bytes.subrange(0, 8)), bytes[8],
            spec_u64_from_le_bytes(bytes.subrange(9, 17)), spec_u64_from_le_bytes(bytes.subrange(17, 25))))
    }
}

pub proof fn completion_roundtrip(time_ms: u64, outcome: u8, upload_bytes: u64, download_bytes: u64)
    requires completion_valid(outcome),
    ensures completion_encoding(time_ms, outcome, upload_bytes, download_bytes).len() == 25,
        decoded_completion(completion_encoding(time_ms, outcome, upload_bytes, download_bytes))
            == Some((time_ms, outcome, upload_bytes, download_bytes)),
{
    lemma_auto_spec_u64_to_from_le_bytes();
    let bytes = completion_encoding(time_ms, outcome, upload_bytes, download_bytes);
    assert(bytes.subrange(0, 8) =~= spec_u64_to_le_bytes(time_ms));
    assert(bytes[8] == outcome);
    assert(bytes.subrange(9, 17) =~= spec_u64_to_le_bytes(upload_bytes));
    assert(bytes.subrange(17, 25) =~= spec_u64_to_le_bytes(download_bytes));
}

pub fn encode_completion(time_ms: u64, outcome: u8, upload_bytes: u64, download_bytes: u64) -> (out: Option<Vec<u8>>)
    ensures match out {
        Some(bytes) => completion_valid(outcome)
            && bytes@ == completion_encoding(time_ms, outcome, upload_bytes, download_bytes)
            && bytes.len() == 25
            && decoded_completion(bytes@) == Some((time_ms, outcome, upload_bytes, download_bytes)),
        None => !completion_valid(outcome),
    },
{
    if outcome > 7 { return None; }
    proof { lemma_auto_spec_u64_to_from_le_bytes(); }
    let mut bytes = Vec::with_capacity(25);
    append(&mut bytes, u64_to_le_bytes(time_ms).as_slice());
    bytes.push(outcome);
    append(&mut bytes, u64_to_le_bytes(upload_bytes).as_slice());
    append(&mut bytes, u64_to_le_bytes(download_bytes).as_slice());
    proof {
        assert(bytes@ =~= completion_encoding(time_ms, outcome, upload_bytes, download_bytes));
        completion_roundtrip(time_ms, outcome, upload_bytes, download_bytes);
    }
    Some(bytes)
}

pub fn decode_completion(bytes: &[u8]) -> (out: Option<Completion>)
    ensures match out {
        Some(r) => decoded_completion(bytes@) == Some((r.time_ms, r.outcome, r.upload_bytes, r.download_bytes))
            && completion_valid(r.outcome) && bytes.len() == 25
            && bytes@ == completion_encoding(r.time_ms, r.outcome, r.upload_bytes, r.download_bytes),
        None => decoded_completion(bytes@).is_none(),
    },
{
    if bytes.len() != 25 { return None; }
    let outcome = bytes[8];
    if outcome > 7 { return None; }
    let time_ms = u64_from_le_bytes(slice_subrange(bytes, 0, 8));
    let upload_bytes = u64_from_le_bytes(slice_subrange(bytes, 9, 17));
    let download_bytes = u64_from_le_bytes(slice_subrange(bytes, 17, 25));
    proof {
        lemma_auto_spec_u64_to_from_le_bytes();
        assert(completion_encoding(time_ms, outcome, upload_bytes, download_bytes) =~= bytes@);
    }
    Some(Completion { time_ms, outcome, upload_bytes, download_bytes })
}

// Every metadata payload fits the smallest payload limit the runtime accepts
// for a logger that records metadata, and well under the framing bound.
pub proof fn metadata_payloads_bounded(destination: Seq<u8>)
    requires request_start_valid(destination),
    ensures request_start_encoding(0, 0, destination).len() <= 8210, 8210 <= 1048576,
{
    request_start_roundtrip(0, 0, destination);
}
}
