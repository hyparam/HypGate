use gateway_core::{frame_queue::FrameQueue, framing::{Header, RecordBody, RecordFrame}};

fn frame(bytes: &[u8], chunk: u64) -> RecordFrame {
    RecordBody::new(Header { payload: bytes.len() as u32, tenant: 1, request: 7, chunk, direction: 0 }, bytes)
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
