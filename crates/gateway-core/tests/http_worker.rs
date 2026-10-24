use gateway_core::http_worker::WorkerRegistry;

#[test]
fn every_role_is_single_use_and_survives_other_role_cleanup() {
    let mut registry = WorkerRegistry::new(2);
    let (first, issuer) = registry.acquire().unwrap();
    let (second, other) = registry.acquire().unwrap();
    assert!(registry.issue(&issuer, 4).is_none());
    let mut permits = Vec::new();
    for role in 0..4 {
        permits.push(registry.issue(&issuer, role).unwrap());
        permits.push(registry.issue(&other, role).unwrap());
        assert_eq!(registry.role_usage(role), 2);
        assert!(registry.issue(&issuer, role).is_none());
    }
    for permit in permits {
        let role = permit.role();
        let previous = registry.role_usage(role);
        assert!(registry.finish(permit));
        assert_eq!(registry.role_usage(role), previous - 1);
        assert!(registry.issue(&issuer, role).is_none());
        assert!(registry.issue(&other, role).is_none());
    }
    assert!(registry.release_task(first));
    let (replacement, fresh) = registry.acquire().unwrap();
    for role in 0..4 {
        assert!(registry.issue(&issuer, role).is_none());
        let permit = registry.issue(&fresh, role).unwrap();
        assert!(registry.finish(permit));
    }
    registry.close();
    assert!(registry.release_task(second));
    assert!(registry.release_task(replacement));
    assert_eq!(registry.usage(), (0, 2));
    assert!(registry.is_closed());
    assert!(registry.acquire().is_none());
}

#[test]
fn each_retained_http_role_independently_blocks_worker_reuse() {
    for role in 0..4 {
        let mut registry = WorkerRegistry::new(1);
        let (mut task, issuer) = registry.acquire().unwrap();
        let permit = registry.issue(&issuer, role).unwrap();
        assert!(task.start());
        assert!(task.begin_cleanup());
        assert!(task.finish_cleanup());
        assert!(!registry.release_task(task));
        assert!(registry.is_closed());
        assert_eq!(registry.usage(), (1, 1));
        assert_eq!(registry.role_usage(role), 1);
        assert!(registry.acquire().is_none());
        for kind in 0..4 { assert!(registry.issue(&issuer, kind).is_none()); }
        assert!(registry.finish(permit));
        assert_eq!(registry.role_usage(role), 0);
        assert_eq!(registry.usage(), (1, 1));
    }
}
