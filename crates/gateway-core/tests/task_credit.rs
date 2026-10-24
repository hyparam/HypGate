use gateway_core::{drain::DrainRegistry, resource::ResourceAdmission, task_credit::TaskCredit};

#[test]
fn result_handoff_requires_a_running_credit_and_a_live_admitted_owner() {
    use gateway_core::{owned_stream::OwnedStream, policy::{Identity, Policy, Route}};
    let route = || Route { tenant: 1, selector: 7, origin: 0, credential: 0 };
    let policy = Policy::validate(vec![Identity { tenant: 1, digest: vec![9; 32] }],
        vec![route()], vec![route()], 1, vec![1]).unwrap();
    let mut requests = ResourceAdmission::new(1, 4);
    let key = requests.acquire().unwrap();
    let authority = policy.authenticate(&[9; 32]).unwrap().authorize(7, key.owner()).unwrap();
    let mut owner = OwnedStream::claim(&requests, key, &authority, false).ok().unwrap();
    let absent = ResourceAdmission::new(1, 4);
    let mut jobs = ResourceAdmission::new(1, 0);
    let mut credit = TaskCredit::new(jobs.acquire().unwrap());
    assert!(!credit.handoff_to(&requests, &owner));
    assert!(credit.start());
    assert!(!credit.handoff_to(&requests, &owner));
    assert!(credit.finish_work());
    assert!(!credit.finish_work());
    assert!(!credit.handoff_to(&absent, &owner));
    assert!(!credit.can_release());
    assert!(credit.handoff_to(&requests, &owner));
    assert!(!credit.handoff_to(&requests, &owner));
    assert!(credit.release(&mut jobs));
    assert_eq!(requests.usage(), (1, 1));
    assert_eq!(jobs.usage(), (0, 1));
    let mut canceled = TaskCredit::new(jobs.acquire().unwrap());
    assert!(canceled.start());
    assert!(canceled.finish_work());
    owner.cancel();
    assert!(!canceled.handoff_to(&requests, &owner));
    assert!(!canceled.release(&mut jobs));
    assert_eq!(jobs.usage(), (1, 1));
    assert!(owner.retire(&mut requests));
}

#[test]
fn live_and_cleaning_tasks_cannot_release_connection_capacity() {
    for phase in 0..3 {
        let mut registry = ResourceAdmission::new(1, 0);
        let mut credit = TaskCredit::new(registry.acquire().unwrap());
        assert!(credit.start());
        assert!(!credit.start());
        assert!(!credit.finish_cleanup());
        if phase == 1 { assert!(credit.begin_cleanup()); }
        if phase == 2 { assert!(credit.finish_work()); }
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

#[test]
fn task_cleanup_requires_its_own_completed_value_owner() {
    let mut registry = ResourceAdmission::new(2, 0);
    let mut first = TaskCredit::new(registry.acquire().unwrap());
    let mut second = TaskCredit::new(registry.acquire().unwrap());
    assert!(first.start()); assert!(second.start());
    let mut one = first.begin_cleanup_with(vec![1, 2]).ok().unwrap();
    let mut two = second.begin_cleanup_with(vec![3, 4]).ok().unwrap();
    assert!(!one.finish());
    assert!(!first.finish_cleanup_with(&one));
    let value = one.take().unwrap();
    assert_eq!(value, vec![1, 2]);
    assert!(one.take().is_none());
    assert!(!first.finish_cleanup_with(&one));
    assert!(!first.can_release());
    drop(value);
    assert!(one.finish());
    assert!(!second.finish_cleanup_with(&one));
    assert!(!second.can_release());
    assert!(first.finish_cleanup_with(&one));
    assert!(first.release(&mut registry));
    assert_eq!(registry.usage(), (1, 2));
    assert_eq!(two.take().unwrap(), vec![3, 4]);
    assert!(two.finish());
    assert!(second.finish_cleanup_with(&two));
    assert!(second.release(&mut registry));
    assert_eq!(registry.usage(), (0, 2));
}

#[test]
fn abandoned_task_cleanup_strands_its_registry_slot() {
    let mut registry = ResourceAdmission::new(1, 0);
    let mut credit = TaskCredit::new(registry.acquire().unwrap());
    assert!(credit.start());
    let cleanup = credit.begin_cleanup_with(vec![7]).ok().unwrap();
    drop(cleanup);
    assert!(!credit.release(&mut registry));
    assert!(registry.acquire().is_none());
}
