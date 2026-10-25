//! Executable checks of the shipper core: assembler bounds and ordering, batch
//! limits, upload cursor progress, identity encodings, and enrollment transitions.
//! The proofs cover every input; these pin concrete scenarios and boundaries.
use gateway_core::batch_builder::{BatchBuilder, MAX_BYTES, MAX_ROWS};
use gateway_core::enrollment::{Enrollment, Recovery, State, throttle_delay, transport_delay, MAX_DELAY_SECONDS};
use gateway_core::exchange_assembler::{Assembler, saturating_add};
use gateway_core::framing::Header;
use gateway_core::metadata::{encode_completion, encode_request_start, encode_response_head};
use gateway_core::shipping_identity::{batch_id, exchange_key, message_key, part_key};
use gateway_core::upload_cursor::UploadCursor;

fn header(kind: u8, request: u64, chunk: u64, payload: &[u8]) -> Header {
    Header { payload: payload.len() as u32, tenant: 9, request, chunk, kind }
}

#[test]
fn assembler_groups_a_request_in_record_order_and_completes_once() {
    let mut a = Assembler::new(4, 1024);
    let start = encode_request_start(1_000, 7, b"https://api.example/v1").unwrap();
    assert!(a.admit(header(2, 1, 0, &start), &start).is_none());
    assert!(a.admit(header(0, 1, 1, b"abc"), b"abc").is_none());
    assert!(a.admit(header(0, 1, 2, b"def"), b"def").is_none());
    let head = encode_response_head(1_500, 200).unwrap();
    assert!(a.admit(header(3, 1, 0, &head), &head).is_none());
    assert!(a.admit(header(1, 1, 3, b"XY"), b"XY").is_none());
    assert_eq!(a.open_exchanges(), 1);
    let done = encode_completion(2_000, 0, 6, 2).unwrap();
    let e = a.admit(header(4, 1, 0, &done), &done).expect("completion emits");
    assert_eq!(a.open_exchanges(), 0);
    assert_eq!((e.tenant, e.request), (9, 1));
    assert_eq!(e.upload, b"abcdef"); assert_eq!(e.download, b"XY");
    assert_eq!((e.upload_total, e.download_total), (6, 2));
    assert!(!e.truncated && !e.incomplete && !e.orphan);
    assert_eq!(e.start.as_ref().unwrap().destination, b"https://api.example/v1");
    assert_eq!(e.head.as_ref().unwrap().status, 200);
    assert_eq!(e.completion.as_ref().unwrap().outcome, 0);
    // A second completion for the same request is an orphan, never a duplicate of the first.
    let again = a.admit(header(4, 1, 0, &done), &done).unwrap();
    assert!(again.orphan && again.upload.is_empty());
}

#[test]
fn assembler_interleaves_requests_and_truncates_at_the_cap() {
    let mut a = Assembler::new(8, 5);
    let start = encode_request_start(1, 1, b"https://h/p").unwrap();
    for request in [1u64, 2] { assert!(a.admit(header(2, request, 0, &start), &start).is_none()); }
    assert!(a.admit(header(0, 1, 1, b"1234"), b"1234").is_none());
    assert!(a.admit(header(0, 2, 1, b"ab"), b"ab").is_none());
    assert!(a.admit(header(1, 1, 2, b"56789"), b"56789").is_none()); // only one byte of room left
    assert!(a.admit(header(1, 1, 3, b"0"), b"0").is_none());         // nothing retained after truncation
    let done = encode_completion(2, 0, 4, 6).unwrap();
    let one = a.admit(header(4, 1, 0, &done), &done).unwrap();
    assert_eq!(one.upload, b"1234"); assert_eq!(one.download, b"5");
    assert!(one.truncated); assert_eq!((one.upload_total, one.download_total), (4, 6));
    let two = a.admit(header(4, 2, 0, &done), &done).unwrap();
    assert_eq!(two.upload, b"ab"); assert!(!two.truncated);
}

#[test]
fn assembler_evicts_oldest_at_capacity_and_restarts_duplicate_requests() {
    let mut a = Assembler::new(2, 64);
    let start = encode_request_start(1, 1, b"https://h/p").unwrap();
    assert!(a.admit(header(2, 10, 0, &start), &start).is_none());
    assert!(a.admit(header(2, 11, 0, &start), &start).is_none());
    let evicted = a.admit(header(2, 12, 0, &start), &start).expect("capacity eviction");
    assert_eq!(evicted.request, 10); assert!(evicted.incomplete && !evicted.orphan);
    assert_eq!(a.open_exchanges(), 2);
    let restarted = a.admit(header(2, 11, 0, &start), &start).expect("duplicate start evicts the old one");
    assert_eq!(restarted.request, 11); assert!(restarted.incomplete);
    assert_eq!(a.open_exchanges(), 2);
    // Orphans carry just their record and leave the open set alone.
    let orphan = a.admit(header(1, 99, 1, b"zz"), b"zz").unwrap();
    assert!(orphan.orphan && orphan.start.is_none()); assert_eq!(orphan.download, b"zz");
    assert_eq!(a.open_exchanges(), 2);
    let mut drained = Vec::new();
    while let Some(e) = a.evict_oldest() { drained.push(e.request); }
    assert_eq!(drained, vec![12, 11]);
    assert!(a.evict_oldest().is_none());
}

#[test]
fn saturating_add_pins_the_ceiling() {
    assert_eq!(saturating_add(1, 2), 3);
    assert_eq!(saturating_add(u64::MAX - 1, 1), u64::MAX);
    assert_eq!(saturating_add(u64::MAX, 7), u64::MAX);
}

#[test]
fn batch_builder_holds_the_row_and_byte_limits() {
    let mut b = BatchBuilder::new();
    assert!(b.is_empty());
    assert!(b.push(b"{\"a\":1}")); assert!(b.push(b"{}"));
    assert_eq!(b.bytes(), b"{\"a\":1}\n{}\n"); assert_eq!(b.row_count(), 2);
    let body = b.finish();
    assert_eq!(body, b"{\"a\":1}\n{}\n"); assert!(b.is_empty()); assert_eq!(b.len(), 0);
    for _ in 0..MAX_ROWS { assert!(b.push(b"x")); }
    assert!(!b.push(b"x")); assert_eq!(b.row_count(), MAX_ROWS);
    let mut c = BatchBuilder::new();
    let big = vec![b'y'; MAX_BYTES - 1];
    assert!(c.push(&big)); assert_eq!(c.len(), MAX_BYTES);
    assert!(!c.push(b"")); // even an empty row needs its newline
    let mut d = BatchBuilder::new();
    assert!(!d.push(&vec![b'z'; MAX_BYTES]));
    assert!(BatchBuilder::oversized(&vec![b'z'; MAX_BYTES]));
    assert!(!BatchBuilder::oversized(&vec![b'z'; MAX_BYTES - 1]));
}

#[test]
fn upload_cursor_resolves_only_the_acknowledged_in_flight_batch() {
    let session = [7u8; 16]; let digest = [3u8; 32];
    assert!(UploadCursor::restore(1, 2, 0).is_none());
    let mut c = UploadCursor::restore(0, 0, 0).unwrap();
    assert!(c.emit(5)); assert_eq!(c.pending(), 5);
    assert!(!c.open_batch(0, &session, &digest));
    assert!(!c.open_batch(6, &session, &digest));
    assert!(c.open_batch(3, &session, &digest));
    assert!(!c.open_batch(1, &session, &digest)); // one batch at a time
    let id = c.current().unwrap().batch_id().clone();
    assert_eq!(id, batch_id(&session, 0, &digest));
    assert_eq!(c.current().unwrap().range(), (0, 3));
    assert!(!c.acknowledge(&batch_id(&session, 1, &digest)));
    assert!(!c.acknowledge(&id[..55]));
    assert_eq!(c.counts(), (5, 0, 0));
    assert!(c.acknowledge(&id));
    assert_eq!(c.counts(), (5, 3, 0)); assert!(c.current().is_none());
    assert!(!c.acknowledge(&id)); // nothing in flight
    assert!(c.open_batch(2, &session, &digest));
    c.abandon(); assert_eq!(c.counts(), (5, 3, 0));
    // The rebuilt batch over the same range has the same id.
    assert!(c.open_batch(2, &session, &digest));
    assert_eq!(c.current().unwrap().batch_id(), &batch_id(&session, 3, &digest));
    assert!(c.poison()); assert_eq!(c.counts(), (5, 5, 1)); assert!(!c.poison());
    assert!(!c.emit(u64::MAX));
}

#[test]
fn identities_are_fixed_width_and_distinct() {
    let s = [1u8; 16]; let t = [2u8; 16];
    assert_eq!(exchange_key(&s, 5).len(), 24);
    assert_eq!(message_key(&s, 5, 1).len(), 28);
    assert_eq!(part_key(&s, 5, 1, 0).len(), 32);
    assert_eq!(batch_id(&s, 0, &[0; 32]).len(), 56);
    assert_ne!(exchange_key(&s, 5), exchange_key(&t, 5));
    assert_ne!(exchange_key(&s, 5), exchange_key(&s, 6));
    assert_ne!(part_key(&s, 5, 1, 0), part_key(&s, 5, 0, 1));
    assert_ne!(batch_id(&s, 1, &[0; 32]), batch_id(&s, 0, &[0; 32]));
    assert_ne!(batch_id(&s, 0, &[1; 32]), batch_id(&s, 0, &[0; 32]));
    assert_eq!(&part_key(&s, 5, 1, 0)[..28], &message_key(&s, 5, 1)[..]);
}

#[test]
fn enrollment_gates_uploads_and_stops_for_good() {
    let mut e = Enrollment::new();
    assert!(e.needs_bootstrap() && !e.can_upload(0) && !e.needs_refresh(0));
    assert!(!e.enrolled(100, 100)); // already expired
    assert!(e.enrolled(1_000_000, 100));
    assert!(e.can_upload(999_999) && !e.can_upload(1_000_000));
    assert!(!e.needs_refresh(1_000_000 - 86_401));
    assert!(e.needs_refresh(1_000_000 - 86_400) && e.needs_refresh(5_000_000));
    assert_eq!(e.rejected(), Recovery::Refresh);
    assert_eq!(e.rejected(), Recovery::Bootstrap);
    assert!(e.needs_bootstrap());
    assert!(e.enrolled(2_000_000, 100));
    assert_eq!(e.rejected(), Recovery::Refresh);
    e.uploaded();
    assert_eq!(e.rejected(), Recovery::Refresh); // a success re-arms the single refresh
    e.refresh_rejected();
    assert!(e.needs_bootstrap());
    e.revoked();
    assert!(e.is_stopped() && !e.enrolled(3_000_000, 100) && e.rejected() == Recovery::Stop);
    e.refresh_rejected(); assert!(e.is_stopped());
    assert!(matches!(Enrollment::new().rejected(), Recovery::Refresh));
    let _ = State::Unenrolled;
}

#[test]
fn retry_delays_are_bounded() {
    assert_eq!([throttle_delay(0, None), throttle_delay(1, None), throttle_delay(2, None), throttle_delay(3, None), throttle_delay(99, None)], [30, 60, 120, 300, 300]);
    assert_eq!(throttle_delay(0, Some(7)), 7);
    assert_eq!(throttle_delay(0, Some(0)), 30);
    assert_eq!(throttle_delay(0, Some(u64::MAX)), MAX_DELAY_SECONDS);
    assert_eq!([transport_delay(0), transport_delay(1), transport_delay(2), transport_delay(3), transport_delay(6)], [2, 4, 6, 30, 300]);
}
