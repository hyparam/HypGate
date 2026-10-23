use gateway_core::policy::{Identity, Policy, Route};
use gateway_runtime::admission::{Admission, AdmissionError};

fn admission(slots: usize, strict: bool) -> Admission {
    let r = || Route { tenant: 1, selector: 7, origin: 0, credential: 0 };
    let policy = Policy::validate(vec![Identity { tenant: 1, digest: vec![11; 32] }],
        vec![r()], vec![r()], 1, vec![1]).unwrap();
    Admission::new(policy, slots, 4, strict)
}

#[test]
fn authorization_failures_return_capacity_and_drop_reclaims_it() {
    let a = admission(1, false);
    assert!(matches!(a.admit(&[0; 32], 7), Err(AdmissionError::Unauthorized)));
    assert!(matches!(a.admit(&[11; 32], 99), Err(AdmissionError::Unauthorized)));
    let r = a.admit(&[11; 32], 7).unwrap();
    let old_id = r.request_id();
    assert_eq!((r.tenant_id(), r.origin(), r.credential()), (1, 0, 0));
    assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
    drop(r);
    assert!(a.admit(&[11; 32], 7).unwrap().request_id() > old_id);
}

#[test]
fn outstanding_ticket_cannot_advance_replacement_request() {
    let a = admission(1, false);
    let mut first = a.admit(&[11; 32], 7).unwrap();
    first.advance(vec![1, 2]).unwrap();
    let ticket = first.prepare(2).unwrap();
    drop(first);
    let mut second = a.admit(&[11; 32], 7).unwrap();
    second.advance(vec![3, 4]).unwrap();
    let current = second.prepare(2).unwrap();
    assert!(!second.complete(&ticket, 2));
    assert!(second.pending_bytes(&ticket).is_none());
    assert_eq!(second.pending_bytes(&current), Some(&[3, 4][..]));
    assert!(second.complete(&current, 1));
    let tail = second.prepare(2).unwrap();
    assert_eq!(second.pending_bytes(&tail), Some(&[4][..]));
}

#[tokio::test]
async fn strict_logging_and_cancellation_keep_the_lease_until_drop() {
    let a = admission(1, true);
    let mut r = a.admit(&[11; 32], 7).unwrap();
    assert!(r.advance(vec![0; 5]).is_none());
    r.advance(vec![1, 2]).unwrap();
    assert!(r.prepare(2).is_none());
    struct Log;
    impl gateway_runtime::transfer::AuditLog for Log {
        async fn append(&mut self, record: gateway_runtime::transfer::LogRecord<'_>) -> std::io::Result<()> {
            assert_eq!((record.tenant, record.request, record.chunk), (1, 1, 1));
            assert_eq!(record.bytes, &[1, 2]);
            Ok(())
        }
    }
    r.audit_current(&mut Log, gateway_runtime::transfer::Direction::Upload).await.unwrap();
    let ticket = r.prepare(2).unwrap();
    r.cancel();
    assert!(r.pending_bytes(&ticket).is_none());
    assert!(r.complete(&ticket, 1));
    assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
    drop(r);
    assert!(a.admit(&[11; 32], 7).is_ok());
}

#[test]
fn unwinding_releases_owned_request() {
    let a = admission(1, false);
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
    let a = admission(1, false);
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
    let a = admission(1, false);
    let b = admission(1, false);
    let mut one = a.admit(&[11; 32], 7).unwrap();
    let mut two = b.admit(&[11; 32], 7).unwrap();
    assert_eq!(one.request_id(), two.request_id());
    one.advance(vec![1]).unwrap();
    two.advance(vec![2]).unwrap();
    let foreign = one.prepare(1).unwrap();
    let own = two.prepare(1).unwrap();
    assert!(two.pending_bytes(&foreign).is_none());
    assert!(!two.complete(&foreign, 1));
    assert_eq!(two.pending_bytes(&own), Some(&[2][..]));
    assert!(two.complete(&own, 1));
}


#[test]
fn spare_vector_capacity_cannot_escape_the_retained_chunk_budget() {
    let a = admission(1, false);
    let mut r = a.admit(&[11; 32], 7).unwrap();
    let mut oversized = Vec::with_capacity(4096);
    oversized.extend_from_slice(&[1, 2]);
    assert!(r.advance(oversized).is_none());
    assert_eq!(r.advance(vec![3, 4]), Some(1));
    let ticket = r.prepare(2).unwrap();
    let mut oversized = Vec::with_capacity(4096);
    oversized.push(9);
    assert!(r.advance(oversized).is_none());
    assert_eq!(r.pending_bytes(&ticket), Some(&[3, 4][..]));
    assert!(r.complete(&ticket, 2));
    assert!(r.advance(Vec::with_capacity(4096)).is_none());
    let mut bounded = Vec::with_capacity(4);
    bounded.push(5);
    assert_eq!(r.advance(bounded), Some(2));
    let ticket = r.prepare(1).unwrap();
    assert_eq!(r.pending_bytes(&ticket), Some(&[5][..]));
    assert!(r.complete(&ticket, 1));
    drop(r);
    assert!(a.admit(&[11; 32], 7).is_ok());
}

#[tokio::test]
async fn canceled_audit_cannot_authorize_or_reuse_the_chunk() {
    struct PendingLog;
    impl gateway_runtime::transfer::AuditLog for PendingLog {
        async fn append(&mut self, record: gateway_runtime::transfer::LogRecord<'_>) -> std::io::Result<()> {
            assert_eq!(record.bytes, &[7, 8]);
            std::future::pending().await
        }
    }
    for strict in [true, false] {
        let a = admission(1, strict);
        let mut r = a.admit(&[11; 32], 7).unwrap();
        r.advance(vec![7, 8]).unwrap();
        assert!(tokio::time::timeout(std::time::Duration::from_millis(10),
            r.audit_current(&mut PendingLog, gateway_runtime::transfer::Direction::Download)).await.is_err());
        assert!(r.prepare(2).is_none());
        assert!(r.advance(vec![9]).is_none());
        assert!(matches!(a.admit(&[11; 32], 7), Err(AdmissionError::AtCapacity)));
        drop(r);
        assert!(a.admit(&[11; 32], 7).is_ok());
    }
}
