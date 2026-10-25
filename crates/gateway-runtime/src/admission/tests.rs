use super::*;
use crate::test_support::admission;
use crate::transfer::{DurableFrame, receipt_for_test as receipt};

#[test]
fn authorization_failures_return_capacity_and_drop_reclaims_it() {
    let a = admission(1, 4, false);
    assert!(matches!(a.admit(&[0; 32], 7), Err(AdmissionError::Unauthorized)));
    assert!(matches!(a.admit(&[11; 32], 99), Err(AdmissionError::Unauthorized)));
    let r = a.admit(&[11; 32], 7).unwrap();
    let old_id = r.request_id();
    assert_eq!(r.tenant_id(), 1);
    assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
    drop(r);
    assert!(a.admit(&[11; 32], 7).unwrap().request_id() > old_id);
}

#[test]
fn outstanding_ticket_cannot_advance_replacement_request() {
    let a = admission(1, 4, false);
    let mut first = a.admit(&[11; 32], 7).unwrap();
    first.advance(vec![1, 2]).unwrap();
    let ticket = first.prepare(2, Direction::Upload).unwrap();
    drop(first);
    let mut second = a.admit(&[11; 32], 7).unwrap();
    second.advance(vec![3, 4]).unwrap();
    let current = second.prepare(2, Direction::Upload).unwrap();
    assert!(!second.complete(&ticket, 2));
    assert!(second.pending_bytes(&ticket, Direction::Upload).is_none());
    assert_eq!(second.pending_bytes(&current, Direction::Upload), Some(&[3, 4][..]));
    assert!(second.complete(&current, 1));
    let tail = second.prepare(2, Direction::Upload).unwrap();
    assert_eq!(second.pending_bytes(&tail, Direction::Upload), Some(&[4][..]));
}

#[tokio::test]
async fn strict_logging_and_cancellation_keep_the_lease_until_drop() {
    let a = admission(1, 4, true);
    let mut r = a.admit(&[11; 32], 7).unwrap();
    assert!(r.advance(vec![0; 5]).is_none());
    r.advance(vec![1, 2]).unwrap();
    assert!(r.prepare(2, Direction::Upload).is_none());
    struct Log;
    impl AuditLog for Log {
        fn session_id(&self) -> u128 { 0 }
        async fn append(&mut self, record: LogRecord<'_>) -> std::io::Result<DurableFrame> {
            assert_eq!((record.tenant, record.request, record.chunk), (1, 1, 1));
            assert_eq!(record.bytes, &[1, 2]);
            Ok(receipt(record))
        }
    }
    r.audit_current(&mut Log, Direction::Upload).await.unwrap();
    let ticket = r.prepare(2, Direction::Upload).unwrap();
    r.cancel();
    assert!(r.pending_bytes(&ticket, Direction::Upload).is_none());
    assert!(r.complete(&ticket, 1));
    assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
    drop(r);
    assert!(a.admit(&[11; 32], 7).is_ok());
}

#[test]
fn unwinding_releases_owned_request() {
    let a = admission(1, 4, false);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut r = a.admit(&[11; 32], 7).unwrap();
        r.advance(vec![1]).unwrap();
        panic!("simulated handler panic");
    }));
    assert!(result.is_err());
    assert!(a.admit(&[11; 32], 7).is_ok());
}

#[test]
fn concurrent_handlers_share_one_capacity_registry() {
    let a = admission(1, 4, false);
    std::thread::scope(|scope| {
        let r = a.admit(&[11; 32], 7).unwrap();
        scope.spawn(|| {
            assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
        }).join().unwrap();
        drop(r);
        scope.spawn(|| assert!(a.admit(&[11; 32], 7).is_ok())).join().unwrap();
    });
}

#[test]
fn tickets_from_independent_registries_are_rejected() {
    let a = admission(1, 4, false);
    let b = admission(1, 4, false);
    let mut one = a.admit(&[11; 32], 7).unwrap();
    let mut two = b.admit(&[11; 32], 7).unwrap();
    assert_eq!(one.request_id(), two.request_id());
    one.advance(vec![1]).unwrap();
    two.advance(vec![2]).unwrap();
    let foreign = one.prepare(1, Direction::Upload).unwrap();
    let own = two.prepare(1, Direction::Upload).unwrap();
    assert!(two.pending_bytes(&foreign, Direction::Upload).is_none());
    assert!(!two.complete(&foreign, 1));
    assert_eq!(two.pending_bytes(&own, Direction::Upload), Some(&[2][..]));
    assert!(two.complete(&own, 1));
}

#[test]
fn spare_vector_capacity_cannot_escape_the_retained_chunk_budget() {
    let a = admission(1, 4, false);
    let mut r = a.admit(&[11; 32], 7).unwrap();
    let mut oversized = Vec::with_capacity(4096);
    oversized.extend_from_slice(&[1, 2]);
    assert!(r.advance(oversized).is_none());
    assert_eq!(r.advance(vec![3, 4]), Some(1));
    let ticket = r.prepare(2, Direction::Upload).unwrap();
    let mut oversized = Vec::with_capacity(4096);
    oversized.push(9);
    assert!(r.advance(oversized).is_none());
    assert_eq!(r.pending_bytes(&ticket, Direction::Upload), Some(&[3, 4][..]));
    assert!(r.complete(&ticket, 2));
    assert!(r.advance(Vec::with_capacity(4096)).is_none());
    let mut bounded = Vec::with_capacity(4);
    bounded.push(5);
    assert_eq!(r.advance(bounded), Some(2));
    let ticket = r.prepare(1, Direction::Upload).unwrap();
    assert_eq!(r.pending_bytes(&ticket, Direction::Upload), Some(&[5][..]));
    assert!(r.complete(&ticket, 1));
    drop(r);
    assert!(a.admit(&[11; 32], 7).is_ok());
}

#[tokio::test]
async fn canceled_audit_cannot_authorize_or_reuse_the_chunk() {
    struct PendingLog;
    impl AuditLog for PendingLog {
        fn session_id(&self) -> u128 { 0 }
        async fn append(&mut self, record: LogRecord<'_>) -> std::io::Result<DurableFrame> {
            assert_eq!(record.bytes, &[7, 8]);
            std::future::pending().await
        }
    }
    for strict in [true, false] {
        let a = admission(1, 4, strict);
        let mut r = a.admit(&[11; 32], 7).unwrap();
        r.advance(vec![7, 8]).unwrap();
        assert!(tokio::time::timeout(std::time::Duration::from_millis(10),
            r.audit_current(&mut PendingLog, Direction::Download)).await.is_err());
        assert!(r.prepare(2, Direction::Upload).is_none());
        assert!(r.advance(vec![9]).is_none());
        assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
        drop(r);
        assert!(a.admit(&[11; 32], 7).is_ok());
    }
}

#[tokio::test]
async fn mismatched_durable_receipts_never_authorize_forwarding() {
    struct WrongLog(u8);
    impl AuditLog for WrongLog {
        fn session_id(&self) -> u128 { if self.0 == 6 { 1 } else { 0 } }
        async fn append(&mut self, mut record: LogRecord<'_>)
            -> std::io::Result<DurableFrame>
        {
            match self.0 {
                0 => record.tenant += 1,
                1 => record.request += 1,
                2 => record.chunk += 1,
                3 => record.kind = crate::transfer::RecordKind::Download,
                4 => record.bytes = &[8, 7], // same length, different content
                5 => record.bytes = &[7],
                _ => {}, // exact content, but receipt comes from another session
            }
            Ok(receipt(record))
        }
    }
    for strict in [true, false] {
        for mismatch in 0..7 {
            let a = admission(1, 4, strict);
            let mut request = a.admit(&[11; 32], 7).unwrap();
            request.advance(vec![7, 8]).unwrap();
            let result = request.audit_current(&mut WrongLog(mismatch),
                Direction::Upload).await;
            assert_eq!(result, Err(TransferError::InvalidState));
            assert!(request.prepare(2, Direction::Upload).is_none());
            assert!(request.advance(vec![9]).is_none());
            assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
            drop(request);
            assert!(a.admit(&[11; 32], 7).is_ok());
        }
    }
}

#[tokio::test]
async fn request_refuses_logger_session_switch_before_append() {
    struct SwitchingLog { session: u128, calls: usize }
    impl AuditLog for SwitchingLog {
        fn session_id(&self) -> u128 { self.session }
        async fn append(&mut self, record: LogRecord<'_>) -> std::io::Result<DurableFrame> {
            self.calls += 1;
            Ok(receipt(record))
        }
    }
    for strict in [true, false] {
        let a = admission(1, 4, strict);
        let mut request = a.admit(&[11; 32], 7).unwrap();
        request.advance(vec![7, 8]).unwrap();
        let mut log = SwitchingLog { session: 0, calls: 0 };
        request.audit_current(&mut log, Direction::Upload).await.unwrap();
        // Same-session repeated use remains legal; changed designation is rejected
        // before a second append, even if it could issue matching content.
        request.audit_current(&mut log, Direction::Upload).await.unwrap();
        assert_eq!(log.calls, 2);
        log.session = 1;
        assert_eq!(request.audit_current(&mut log, Direction::Upload).await, Err(TransferError::InvalidState));
        assert_eq!(log.calls, 2);
        assert!(request.prepare(2, Direction::Upload).is_none());
    }
}

#[tokio::test]
async fn strict_submission_requires_receipt_for_the_transfer_direction() {
    struct Log;
    impl AuditLog for Log {
        fn session_id(&self) -> u128 { 0 }
        async fn append(&mut self, record: LogRecord<'_>) -> std::io::Result<DurableFrame> { Ok(receipt(record)) }
    }
    for strict in [true, false] {
        let a = admission(1, 4, strict);
        let mut request = a.admit(&[11; 32], 7).unwrap();
        request.advance(vec![1, 2]).unwrap();
        request.audit_current(&mut Log, Direction::Download).await.unwrap();
        if strict { assert!(request.prepare(2, Direction::Upload).is_none()); }
        let ticket = request.prepare(2, Direction::Download).unwrap();
        assert!(request.pending_bytes(&ticket, Direction::Upload).is_none());
        assert_eq!(request.pending_bytes(&ticket, Direction::Download), Some(&[1, 2][..]));
        assert!(request.complete(&ticket, 1));
        let next = request.prepare(1, Direction::Download).unwrap();
        assert_eq!(request.pending_bytes(&next, Direction::Download), Some(&[2][..]));
    }
}
