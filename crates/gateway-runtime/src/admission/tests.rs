use super::*;
use crate::test_support::admission;
use crate::transfer::{AuditReceipt, receipt_for_test as receipt};

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

#[test]
fn strict_logging_and_cancellation_keep_the_lease_until_drop() {
    let a = admission(1, 4, true);
    let mut r = a.admit(&[11; 32], 7).unwrap();
    assert!(r.advance(vec![0; 5]).is_none());
    r.advance(vec![1, 2]).unwrap();
    assert!(r.prepare(2, Direction::Upload).is_none());
    struct Log;
    impl AuditLog for Log {
        fn session_id(&self) -> u128 { 0 }
        fn append(&mut self, record: LogRecord<'_>) -> std::io::Result<AuditReceipt> {
            assert_eq!((record.tenant, record.request, record.chunk), (1, 1, 1));
            assert_eq!(record.bytes, &[1, 2]);
            Ok(receipt(record))
        }
    }
    r.audit_current(&mut Log, Direction::Upload).unwrap();
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

#[test]
fn abandoned_audit_cannot_authorize_or_reuse_the_chunk() {
    // An append that never returns normally (here it unwinds) leaves the
    // request closed: the logger may already have had an unknown effect.
    struct PanickingLog;
    impl AuditLog for PanickingLog {
        fn session_id(&self) -> u128 { 0 }
        fn append(&mut self, record: LogRecord<'_>) -> std::io::Result<AuditReceipt> {
            assert_eq!(record.bytes, &[7, 8]);
            panic!("injected logger failure mid-append");
        }
    }
    for strict in [true, false] {
        let a = admission(1, 4, strict);
        let mut r = a.admit(&[11; 32], 7).unwrap();
        r.advance(vec![7, 8]).unwrap();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = r.audit_current(&mut PanickingLog, Direction::Download);
        })).is_err());
        assert!(r.is_closed());
        assert!(r.prepare(2, Direction::Upload).is_none());
        assert!(r.advance(vec![9]).is_none());
        assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
        drop(r);
        assert!(a.admit(&[11; 32], 7).is_ok());
    }
}

#[test]
fn mismatched_durable_receipts_never_authorize_forwarding() {
    struct WrongLog(u8);
    impl AuditLog for WrongLog {
        fn session_id(&self) -> u128 { if self.0 == 6 { 1 } else { 0 } }
        fn append(&mut self, mut record: LogRecord<'_>) -> std::io::Result<AuditReceipt> {
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
            let result = request.audit_current(&mut WrongLog(mismatch), Direction::Upload);
            assert_eq!(result, Err(TransferError::InvalidState));
            assert!(request.prepare(2, Direction::Upload).is_none());
            assert!(request.advance(vec![9]).is_none());
            assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
            drop(request);
            assert!(a.admit(&[11; 32], 7).is_ok());
        }
    }
}

#[test]
fn request_refuses_logger_session_switch_before_append() {
    struct SwitchingLog { session: u128, calls: usize }
    impl AuditLog for SwitchingLog {
        fn session_id(&self) -> u128 { self.session }
        fn append(&mut self, record: LogRecord<'_>) -> std::io::Result<AuditReceipt> {
            self.calls += 1;
            Ok(receipt(record))
        }
    }
    for strict in [true, false] {
        let a = admission(1, 4, strict);
        let mut request = a.admit(&[11; 32], 7).unwrap();
        request.advance(vec![7, 8]).unwrap();
        let mut log = SwitchingLog { session: 0, calls: 0 };
        request.audit_current(&mut log, Direction::Upload).unwrap();
        // Same-session repeated use remains legal; changed designation is rejected
        // before a second append, even if it could issue matching content.
        request.audit_current(&mut log, Direction::Upload).unwrap();
        assert_eq!(log.calls, 2);
        log.session = 1;
        assert_eq!(request.audit_current(&mut log, Direction::Upload), Err(TransferError::InvalidState));
        assert_eq!(log.calls, 2);
        assert!(request.prepare(2, Direction::Upload).is_none());
    }
}

#[test]
fn strict_submission_requires_receipt_for_the_transfer_direction() {
    struct Log;
    impl AuditLog for Log {
        fn session_id(&self) -> u128 { 0 }
        fn append(&mut self, record: LogRecord<'_>) -> std::io::Result<AuditReceipt> { Ok(receipt(record)) }
    }
    for strict in [true, false] {
        let a = admission(1, 4, strict);
        let mut request = a.admit(&[11; 32], 7).unwrap();
        request.advance(vec![1, 2]).unwrap();
        request.audit_current(&mut Log, Direction::Download).unwrap();
        if strict { assert!(request.prepare(2, Direction::Upload).is_none()); }
        let ticket = request.prepare(2, Direction::Download).unwrap();
        assert!(request.pending_bytes(&ticket, Direction::Upload).is_none());
        assert_eq!(request.pending_bytes(&ticket, Direction::Download), Some(&[1, 2][..]));
        assert!(request.complete(&ticket, 1));
        let next = request.prepare(1, Direction::Download).unwrap();
        assert_eq!(request.pending_bytes(&next, Direction::Download), Some(&[2][..]));
    }
}

#[test]
fn metadata_records_use_chunk_zero_and_never_authorize_body_writes() {
    use crate::transfer::RecordKind;
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    struct Log { seen: Arc<Mutex<Vec<(u64, RecordKind, Vec<u8>)>>>, fail: bool }
    impl AuditLog for Log {
        fn session_id(&self) -> u128 { 0 }
        fn append(&mut self, record: LogRecord<'_>) -> std::io::Result<AuditReceipt> {
            self.seen.lock().unwrap().push((record.chunk, record.kind, record.bytes.to_vec()));
            if self.fail { Err(std::io::ErrorKind::Other.into()) } else { Ok(receipt(record)) }
        }
    }
    for strict in [true, false] {
        let a = admission(1, 4, strict);
        let mut r = a.admit(&[11; 32], 7).unwrap();
        let mut log = Log::default();
        // Body kinds are refused on the metadata path; oversized payloads too.
        assert_eq!(r.audit_metadata(&mut log, RecordKind::Upload, b"x"), Err(TransferError::InvalidState));
        assert_eq!(r.audit_metadata(&mut log, RecordKind::RequestStart, &vec![0; 8211]), Err(TransferError::InvalidState));
        assert!(log.seen.lock().unwrap().is_empty());
        let start = gateway_core::metadata::encode_request_start(5, 7, b"https://example.test/v1").unwrap();
        r.audit_metadata(&mut log, RecordKind::RequestStart, &start).unwrap();
        assert_eq!(*log.seen.lock().unwrap(), vec![(0, RecordKind::RequestStart, start.clone())]);
        // The metadata receipt is not body evidence and did not advance the stream:
        // the next body chunk is still chunk 1, and strict mode still needs its own receipt.
        assert!(r.prepare(1, Direction::Upload).is_none());
        assert_eq!(r.advance(vec![1, 2]), Some(1));
        if strict { assert!(r.prepare(1, Direction::Upload).is_none()); }
        r.audit_current(&mut log, Direction::Upload).unwrap();
        assert_eq!(log.seen.lock().unwrap().last().unwrap().0, 1);
        let ticket = r.prepare(2, Direction::Upload).unwrap();
        assert_eq!(r.pending_bytes(&ticket, Direction::Upload), Some(&[1, 2][..]));
        assert!(r.complete(&ticket, 2));
        let head = gateway_core::metadata::encode_response_head(6, 200).unwrap();
        r.audit_metadata(&mut log, RecordKind::ResponseHead, &head).unwrap();
        // A failed metadata append degrades the request exactly like a failed body append.
        log.fail = true;
        let head = gateway_core::metadata::encode_response_head(7, 200).unwrap();
        assert_eq!(r.audit_metadata(&mut log, RecordKind::ResponseHead, &head), Err(TransferError::Log));
        assert!(r.log_failed());
        assert_eq!(r.is_closed(), strict);
        // Later start/head records are skipped; the completion is still attempted
        // because it describes an exchange that is already over.
        assert_eq!(r.audit_metadata(&mut log, RecordKind::ResponseHead, &head), Err(TransferError::Log));
        let calls = log.seen.lock().unwrap().len();
        log.fail = false;
        let done = gateway_core::metadata::encode_completion(8, 6, 2, 0).unwrap();
        r.audit_metadata(&mut log, RecordKind::Completion, &done).unwrap();
        assert_eq!(log.seen.lock().unwrap().len(), calls + 1);
        assert_eq!(log.seen.lock().unwrap().last().unwrap(), &(0, RecordKind::Completion, done));
    }
}
