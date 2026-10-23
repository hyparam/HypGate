use gateway_core::framing::{encode, decode, frame_end, Header};

#[test]
fn header_roundtrips_boundary_values_without_field_aliasing() {
    for payload in [0, 1, 1048576] {
        for tenant in [0, 1, u64::MAX] {
            for request in [1, u64::MAX] {
                for chunk in [0, 1, u64::MAX] {
                    for direction in [0, 1] {
                        let bytes = encode(Header { payload, tenant, request, chunk, direction }).unwrap();
                        assert_eq!(bytes.len(), 33); assert_eq!(&bytes[..4], b"SGR1");
                        let h = decode(&bytes).unwrap();
                        assert_eq!((h.payload, h.tenant, h.request, h.chunk, h.direction),
                            (payload, tenant, request, chunk, direction));
                    }
                }
            }
        }
    }
}

#[test]
fn malformed_headers_and_incomplete_frame_extents_are_rejected() {
    let header = encode(Header { payload: 7, tenant: 3, request: 4, chunk: 5, direction: 1 }).unwrap();
    for end in 0..header.len() { assert!(decode(&header[..end]).is_none()); }
    let mut extra = header.clone(); extra.push(0); assert!(decode(&extra).is_none());
    for offset in 0..4 {
        let mut bad = header.clone(); bad[offset] ^= 1; assert!(decode(&bad).is_none());
    }
    for payload in [1048577, u32::MAX] {
        let mut bad = header.clone(); bad[4..8].copy_from_slice(&payload.to_le_bytes());
        assert!(decode(&bad).is_none());
    }
    let mut bad = header.clone(); bad[16..24].fill(0); assert!(decode(&bad).is_none());
    for direction in 2..=255 { let mut bad = header.clone(); bad[32] = direction; assert!(decode(&bad).is_none()); }
    assert!(encode(Header { payload: 0, tenant: 0, request: 0, chunk: 0, direction: 0 }).is_none());
    for available in 0..72 { assert!(frame_end(56, 7, available).is_none()); }
    assert_eq!(frame_end(56, 7, 72), Some(128));
    assert_eq!(frame_end(u64::MAX - 72, 7, 72), Some(u64::MAX));
    assert!(frame_end(u64::MAX - 71, 7, 72).is_none());
    assert!(frame_end(0, 1048577, u64::MAX).is_none());
}


#[test]
fn recovery_cursor_stops_on_abandoned_or_incomplete_records() {
    use gateway_core::framing::Cursor;
    let mut cursor = Cursor::new(56);
    let ticket = cursor.begin().unwrap();
    assert_eq!(cursor.offset(), 56);
    assert!(cursor.begin().is_none());
    assert!(cursor.accept(ticket, 7, 72));
    assert_eq!(cursor.offset(), 128);
    let ticket = cursor.begin().unwrap();
    assert!(!cursor.accept(ticket, 7, 71));
    assert_eq!(cursor.offset(), 128);
    assert!(cursor.begin().is_none());
    let mut abandoned = Cursor::new(56);
    let _ = abandoned.begin().unwrap();
    assert!(abandoned.begin().is_none());
    assert_eq!(abandoned.offset(), 56);
    let mut overflow = Cursor::new(u64::MAX - 64);
    let ticket = overflow.begin().unwrap();
    assert!(!overflow.accept(ticket, 0, 65));
    assert!(overflow.begin().is_none());
    assert_eq!(overflow.offset(), u64::MAX - 64);
}


#[test]
fn framed_payload_is_exact_and_cannot_disagree_with_header_length() {
    use gateway_core::framing::encode_payload;
    for length in [0, 1, 255, 65536, 1048576] {
        let payload: Vec<_> = (0..length).map(|i| (i % 251) as u8).collect();
        let header = || Header { payload: length as u32, tenant: 19, request: 29, chunk: 37, direction: 1 };
        let frame = encode_payload(header(), &payload).unwrap();
        assert_eq!(&frame[..33], encode(header()).unwrap());
        assert_eq!(&frame[33..], payload);
        assert_eq!(frame.len(), 33 + length);
        assert!(frame.capacity() >= frame.len() + 32);
        let wrong = Header { payload: length as u32 + 1, tenant: 19, request: 29, chunk: 37, direction: 1 };
        assert!(encode_payload(wrong, &payload).is_none());
    }
    assert!(encode_payload(Header { payload: 0, tenant: 0, request: 0, chunk: 0, direction: 0 }, &[]).is_none());
}

#[test]
fn recovered_record_binds_header_payload_checksum_and_cursor() {
    use gateway_core::framing::Cursor;
    for direction in [0, 1] {
        let header = encode(Header { payload: 3, tenant: 19, request: 29, chunk: 37, direction }).unwrap();
        let mut cursor = Cursor::new(56);
        let ticket = cursor.begin().unwrap();
        let record = cursor.accept_record(ticket, &header, vec![7, 8, 9], true).unwrap();
        assert_eq!((record.header.tenant, record.header.request, record.header.chunk, record.header.direction),
            (19, 29, 37, direction));
        assert_eq!(record.bytes, [7, 8, 9]);
        assert_eq!(cursor.offset(), 124);
        assert!(cursor.begin().is_some());
        for (raw, payload, checksum) in [
            (header.clone(), vec![7, 8, 9], false),
            (header.clone(), vec![7, 8], true),
            (header.clone(), vec![7, 8, 9, 10], true),
            (header[..32].to_vec(), vec![7, 8, 9], true),
        ] {
            let mut cursor = Cursor::new(56);
            let ticket = cursor.begin().unwrap();
            assert!(cursor.accept_record(ticket, &raw, payload, checksum).is_none());
            assert_eq!(cursor.offset(), 56);
            assert!(cursor.begin().is_none());
        }
    }
}

#[test]
fn sealed_record_preserves_canonical_header_payload_and_checksum() {
    use gateway_core::framing::RecordBody;
    for length in [0, 1, 1048576] {
        let payload = vec![17; length];
        let header = || Header { payload: length as u32, tenant: 19, request: 29, chunk: 37, direction: 1 };
        let body = RecordBody::new(header(), &payload).unwrap();
        assert_eq!(&body.bytes()[..33], encode(header()).unwrap());
        assert_eq!(&body.bytes()[33..], payload);
        let frame = body.seal(&[23; 32]);
        assert_eq!(frame.bytes().len(), length + 65);
        assert_eq!(&frame.bytes()[..33], encode(header()).unwrap());
        assert_eq!(&frame.bytes()[33..33 + length], payload);
        assert_eq!(&frame.bytes()[33 + length..], &[23; 32]);
        assert!(RecordBody::new(header(), &vec![0; length + 1]).is_none());
    }
}

#[test]
fn session_header_requires_exact_version_length_checksum_and_identity() {
    use gateway_core::framing::{encode_session, decode_session};
    for session in [[0; 16], [255; 16], std::array::from_fn(|i| i as u8)] {
        let encoded = encode_session(&session);
        assert_eq!(&encoded[..8], b"SGLOG001");
        assert_eq!(&encoded[8..], session);
        assert_eq!(decode_session(&encoded, true), Some(session));
        assert_eq!(decode_session(&encoded, false), None);
        for length in 0..encoded.len() { assert_eq!(decode_session(&encoded[..length], true), None); }
        let mut extra = encoded.clone(); extra.push(0);
        assert_eq!(decode_session(&extra, true), None);
        for byte in 0..8 {
            let mut changed = encoded.clone(); changed[byte] ^= 1;
            assert_eq!(decode_session(&changed, true), None);
        }
        // The session is data, not a fixed value or authentication credential.
        let mut changed = encoded.clone(); changed[8] ^= 1;
        let mut expected = session; expected[0] ^= 1;
        assert_eq!(decode_session(&changed, true), Some(expected));
    }
}
