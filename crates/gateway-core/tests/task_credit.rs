use gateway_core::{drain::DrainRegistry, resource::ResourceAdmission, task_credit::TaskCredit};

#[test]
fn live_and_cleaning_tasks_cannot_release_connection_capacity() {
    for cleaning in [false, true] {
        let mut registry = ResourceAdmission::new(1, 0);
        let mut credit = TaskCredit::new(registry.acquire().unwrap());
        assert!(credit.start());
        assert!(!credit.start());
        assert!(!credit.finish_cleanup());
        if cleaning { assert!(credit.begin_cleanup()); }
        assert!(!credit.can_release());
        assert!(!credit.release(&mut registry));
        assert_eq!(registry.usage(), (1, 1));
        assert!(registry.acquire().is_none());
    }
}

#[test]
fn live_and_cleaning_tasks_cannot_release_worker_capacity() {
    for cleaning in [false, true] {
        let mut registry = DrainRegistry::new(1);
        let mut credit = TaskCredit::new(registry.acquire().unwrap());
        assert!(credit.start());
        if cleaning { assert!(credit.begin_cleanup()); }
        registry.close();
        assert!(!credit.release_worker(&mut registry));
        assert_eq!(registry.usage(), (1, 1));
        assert!(registry.is_closed());
    }
}

#[test]
fn completed_cleanup_and_unused_reservations_return_capacity() {
    for started in [false, true] {
        let mut registry = ResourceAdmission::new(1, 0);
        let mut credit = TaskCredit::new(registry.acquire().unwrap());
        assert!(!credit.begin_cleanup());
        assert!(!credit.finish_cleanup());
        if started {
            assert!(credit.start());
            assert!(credit.begin_cleanup());
            assert!(!credit.begin_cleanup());
            assert!(credit.finish_cleanup());
            assert!(!credit.start());
            assert!(!credit.finish_cleanup());
        }
        assert!(credit.release(&mut registry));
        assert_eq!(registry.usage(), (0, 1));
        assert!(registry.acquire().is_some());
    }
}

#[test]
fn cleanup_returns_worker_capacity_without_reopening_admission() {
    let mut registry = DrainRegistry::new(1);
    let mut credit = TaskCredit::new(registry.acquire().unwrap());
    assert!(credit.start());
    registry.close();
    assert!(credit.begin_cleanup());
    assert!(credit.finish_cleanup());
    assert!(credit.release_worker(&mut registry));
    assert_eq!(registry.usage(), (0, 1));
    assert!(registry.acquire().is_none());
}
