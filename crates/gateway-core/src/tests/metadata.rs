//! Executable checks of the metadata codecs and the record-kind bounds. The
//! proofs cover every input; these tests pin concrete boundary values.
use crate::framing::{self, Header};
use crate::metadata::*;

fn header(kind: u8) -> Header { Header { payload: 3, tenant: 1, request: 2, chunk: 0, kind } }

#[test]
fn framing_accepts_kinds_up_to_four_and_rejects_five() {
    for kind in 0..=4u8 {
        let bytes = framing::encode(header(kind)).unwrap();
        assert_eq!(bytes.len(), 33); assert_eq!(bytes[32], kind);
        let decoded = framing::decode(&bytes).unwrap();
        assert_eq!((decoded.kind, decoded.chunk, decoded.request), (kind, 0, 2));
    }
    for kind in [5u8, 6, 127, 255] {
        assert!(framing::encode(header(kind)).is_none());
        let mut bytes = framing::encode(header(4)).unwrap(); bytes[32] = kind;
        assert!(framing::decode(&bytes).is_none());
    }
}

#[test]
fn request_start_roundtrips_within_destination_bounds() {
    for length in [1usize, 2, 255, 256, 8191, 8192] {
        let destination: Vec<u8> = (0..length).map(|i| b'a' + (i % 26) as u8).collect();
        let bytes = encode_request_start(u64::MAX, 7, &destination).unwrap();
        assert_eq!(bytes.len(), REQUEST_START_PREFIX + length);
        assert_eq!(&bytes[16..18], &(length as u16).to_le_bytes());
        let decoded = decode_request_start(&bytes).unwrap();
        assert_eq!((decoded.time_ms, decoded.selector), (u64::MAX, 7));
        assert_eq!(decoded.destination, destination);
        // Every truncation and every extension is rejected: the declared length must match.
        for cut in 0..bytes.len() { assert!(decode_request_start(&bytes[..cut]).is_none(), "cut {cut}"); }
        let mut extended = bytes.clone(); extended.push(b'x');
        assert!(decode_request_start(&extended).is_none());
    }
    assert!(encode_request_start(1, 1, b"").is_none());
    assert!(encode_request_start(1, 1, &vec![b'a'; MAX_DESTINATION + 1]).is_none());
    assert_eq!(encode_request_start(1, 1, &vec![b'a'; MAX_DESTINATION]).unwrap().len(), MAX_PAYLOAD);
    // A declared length of zero or above the bound is rejected even with matching bytes.
    let mut zero = encode_request_start(1, 1, b"a").unwrap(); zero[16] = 0; zero.truncate(18);
    assert!(decode_request_start(&zero).is_none());
    let mut oversized = encode_request_start(1, 1, &vec![b'a'; MAX_DESTINATION]).unwrap();
    oversized[16..18].copy_from_slice(&8193u16.to_le_bytes()); oversized.push(b'a');
    assert!(decode_request_start(&oversized).is_none());
}

#[test]
fn response_head_roundtrips_and_rejects_out_of_range_statuses() {
    for status in [100u16, 101, 200, 204, 599, 999] {
        let bytes = encode_response_head(1_700_000_000_000, status).unwrap();
        assert_eq!(bytes.len(), RESPONSE_HEAD_LEN);
        let decoded = decode_response_head(&bytes).unwrap();
        assert_eq!((decoded.time_ms, decoded.status), (1_700_000_000_000, status));
        for cut in 0..bytes.len() { assert!(decode_response_head(&bytes[..cut]).is_none()); }
        let mut extended = bytes.clone(); extended.push(0);
        assert!(decode_response_head(&extended).is_none());
    }
    for status in [0u16, 1, 99, 1000, u16::MAX] {
        assert!(encode_response_head(0, status).is_none());
        let mut bytes = encode_response_head(0, 200).unwrap();
        bytes[8..10].copy_from_slice(&status.to_le_bytes());
        assert!(decode_response_head(&bytes).is_none());
    }
}

#[test]
fn completion_roundtrips_and_rejects_unknown_outcomes() {
    for outcome in 0..=MAX_OUTCOME {
        let bytes = encode_completion(5, outcome, u64::MAX, 42).unwrap();
        assert_eq!(bytes.len(), COMPLETION_LEN); assert_eq!(bytes[8], outcome);
        let decoded = decode_completion(&bytes).unwrap();
        assert_eq!((decoded.time_ms, decoded.outcome, decoded.upload_bytes, decoded.download_bytes), (5, outcome, u64::MAX, 42));
        for cut in 0..bytes.len() { assert!(decode_completion(&bytes[..cut]).is_none()); }
        let mut extended = bytes.clone(); extended.push(0);
        assert!(decode_completion(&extended).is_none());
    }
    for outcome in [8u8, 9, 255] {
        assert!(encode_completion(0, outcome, 0, 0).is_none());
        let mut bytes = encode_completion(0, 0, 0, 0).unwrap(); bytes[8] = outcome;
        assert!(decode_completion(&bytes).is_none());
    }
}
