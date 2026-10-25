use gateway_core::{frame_queue::FrameQueue, framing::{Header, RecordBody, RecordFrame}};

fn frame(bytes: &[u8], chunk: u64) -> RecordFrame {
    RecordBody::new(Header { payload: bytes.len() as u32, tenant: 1, request: 7, chunk, kind: 0 }, bytes)
        .unwrap().seal(&[0; 32]) // Queue tests cover structure; digest correctness is external.
}

#[test]
fn frame_queue_preserves_records_and_completion_associations_through_rejection_and_close() {
    let payloads = [Vec::new(), vec![0, 255, 3], vec![42; 1048576]];
    let mut queue = FrameQueue::new(3);
    for (i, bytes) in payloads.iter().enumerate() {
        assert!(queue.push((frame(bytes, i as u64), i)).is_ok());
    }
    let extra = (frame(b"extra", 3), 99);
    let expected_extra = extra.0.bytes().clone();
    let returned = queue.push(extra).err().unwrap();
    assert_eq!(returned.0.bytes(), &expected_extra); assert_eq!(returned.1, 99);
    queue.close(); assert!(queue.is_closed());
    for (i, bytes) in payloads.iter().enumerate() {
        let (record, completion) = queue.pop().unwrap();
        assert_eq!(completion, i);
        assert_eq!(record.bytes(), frame(bytes, i as u64).bytes());
        assert_eq!(record.bytes().len(), bytes.len() + 65);
    }
    assert_eq!(queue.len(), 0); assert!(queue.pop().is_none());
    assert!(queue.push(returned).is_err()); assert!(queue.is_closed());
}

#[test]
fn configured_payload_limit_rejects_oversize_without_losing_capacity_or_identity() {
    for limit in [0, 1, 32768, 1048576] {
        let mut queue = FrameQueue::with_payload_limit(1, limit);
        if limit < 1048576 {
            let extra = frame(&vec![7; limit + 1], 9);
            let original = extra.bytes().clone();
            let (returned, completion) = queue.push((extra, 99)).err().unwrap();
            assert_eq!(returned.bytes(), &original); assert_eq!(completion, 99);
            assert_eq!(queue.len(), 0); assert!(!queue.is_closed());
        }
        assert!(queue.push((frame(&vec![8; limit], 10), 100)).is_ok());
        let (record, completion) = queue.pop().unwrap();
        assert_eq!(record.bytes().len(), limit + 65); assert_eq!(completion, 100);
        queue.close(); assert!(queue.push((record, completion)).is_err());
    }
}

#[test]
fn encoding_reservation_blocks_competing_admission_and_survives_close() {
    let mut queue = FrameQueue::with_payload_limit(2, 3);
    assert!(queue.push((frame(b"one", 1), 1)).is_ok());
    assert!(queue.reserve()); assert!(!queue.reserve());
    let candidate = queue.push((frame(b"two", 2), 2)).err().unwrap();
    assert_eq!(queue.len(), 1);
    assert!(queue.finish_reserved(candidate).is_ok());
    assert!(!queue.reserve());
    assert_eq!(queue.pop().unwrap().1, 1);
    assert!(queue.reserve());
    queue.close();
    let rejected = queue.finish_reserved((frame(b"end", 3), 3)).err().unwrap();
    assert_eq!(rejected.1, 3); assert_eq!(queue.pop().unwrap().1, 2);
    assert!(queue.pop().is_none()); assert!(!queue.reserve());
}

#[test]
fn rejected_encoding_releases_reservation_without_consuming_a_slot() {
    let mut queue = FrameQueue::with_payload_limit(1, 3);
    assert!(queue.reserve());
    let rejected = queue.finish_reserved((frame(b"over", 1), 9)).err().unwrap();
    assert_eq!(rejected.1, 9); assert_eq!(queue.len(), 0);
    assert!(queue.reserve());
    assert!(queue.finish_reserved((frame(b"fit", 2), 10)).is_ok());
    assert_eq!(queue.pop().unwrap().1, 10);
}

#[test]
fn dequeue_does_not_release_an_unfinished_encoding_reservation() {
    let mut queue = FrameQueue::with_payload_limit(2, 3);
    assert!(queue.push((frame(b"old", 1), 1)).is_ok());
    assert!(queue.reserve());
    assert_eq!(queue.pop().unwrap().1, 1);
    assert!(!queue.reserve());
    let record = queue.push((frame(b"new", 2), 2)).err().unwrap();
    assert!(queue.finish_reserved(record).is_ok());
    assert_eq!(queue.pop().unwrap().1, 2);
    assert!(queue.reserve());
}

#[test]
fn reserved_encoder_checks_admission_limit_and_exact_header_before_building() {
    let mut queue = FrameQueue::<usize>::with_payload_limit(1, 3);
    let header = || Header { payload: 3, tenant: 7, request: 8, chunk: 9, kind: 1 };
    assert!(queue.encode_reserved(header(), b"abc").is_none());
    assert!(queue.reserve());
    let mut oversized = header(); oversized.payload = 4;
    assert!(queue.encode_reserved(oversized, b"abcd").is_none());
    assert!(queue.encode_reserved(header(), b"ab").is_none());
    let mut invalid = header(); invalid.request = 0;
    assert!(queue.encode_reserved(invalid, b"abc").is_none());
    let body = queue.encode_reserved(header(), b"abc").unwrap();
    assert_eq!(body.bytes().len(), 36); assert_eq!(&body.bytes()[33..], b"abc");
    let sealed = body.seal(&[9; 32]);
    assert_eq!(sealed.bytes().len(), 68);
    assert!(queue.finish_reserved((sealed, 42)).is_ok());
    assert!(queue.encode_reserved(header(), b"abc").is_none());
    assert_eq!(queue.pop().unwrap().1, 42);
    assert!(queue.reserve()); queue.close();
    assert!(queue.encode_reserved(header(), b"abc").is_none());
}
