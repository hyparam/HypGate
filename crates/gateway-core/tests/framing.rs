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
