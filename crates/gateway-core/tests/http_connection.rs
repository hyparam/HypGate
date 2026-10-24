use gateway_core::{http_connection::ResponseSlot, resource::ResourceAdmission};

#[test]
fn response_permit_is_single_use_even_after_cleanup() {
    let mut registry = ResourceAdmission::new(1, 0);
    let (mut slot, task) = ResponseSlot::reserve(registry.acquire().unwrap());
    let permit = slot.issue().unwrap();
    assert!(slot.issue().is_none());
    assert!(slot.finish(permit));
    assert!(slot.issue().is_none());
    assert!(slot.release_task(task, &mut registry));
    assert_eq!(registry.usage(), (0, 1));
    assert!(slot.issue().is_none());
}

#[test]
fn task_cleanup_cannot_release_a_retained_response() {
    let mut registry = ResourceAdmission::new(1, 0);
    let (mut slot, mut task) = ResponseSlot::reserve(registry.acquire().unwrap());
    let permit = slot.issue().unwrap();
    assert!(task.start());
    assert!(task.begin_cleanup());
    assert!(task.finish_cleanup());
    assert!(!slot.release_task(task, &mut registry));
    assert!(registry.acquire().is_none());
    assert!(slot.finish(permit));
    // A late return cannot resurrect the consumed parent credit.
    assert_eq!(registry.usage(), (1, 1));
    assert!(slot.issue().is_none());
}

#[test]
fn foreign_response_permit_and_task_cannot_release_connection() {
    let mut registry = ResourceAdmission::new(2, 0);
    let (mut first, first_task) = ResponseSlot::reserve(registry.acquire().unwrap());
    let (mut second, second_task) = ResponseSlot::reserve(registry.acquire().unwrap());
    let first_permit = first.issue().unwrap();
    let second_permit = second.issue().unwrap();
    assert!(!first.finish(second_permit));
    assert!(first.finish(first_permit));
    assert!(!first.release_task(second_task, &mut registry));
    assert!(!second.release_task(first_task, &mut registry));
    assert_eq!(registry.usage(), (2, 2));
}

#[test]
fn retiring_an_unused_connection_prevents_late_issuance() {
    let mut registry = ResourceAdmission::new(1, 0);
    let (mut slot, task) = ResponseSlot::reserve(registry.acquire().unwrap());
    assert!(slot.release_task(task, &mut registry));
    assert!(slot.issue().is_none());
    assert!(registry.acquire().is_some());
}

#[test]
fn registry_counts_live_responses_and_rejects_stale_issuers_after_reuse() {
    use gateway_core::http_connection::ResponseRegistry;
    let mut registry = ResponseRegistry::new(2);
    let (first, old_issuer) = registry.acquire().unwrap();
    let (second, second_issuer) = registry.acquire().unwrap();
    let first_body = registry.issue(&old_issuer).unwrap();
    let second_body = registry.issue(&second_issuer).unwrap();
    assert_eq!(registry.response_count(), 2);
    assert!(registry.issue(&old_issuer).is_none());
    assert!(registry.acquire().is_none());
    assert!(registry.finish(first_body));
    assert!(registry.issue(&old_issuer).is_none());
    assert_eq!(registry.response_count(), 1);
    assert!(registry.release_task(first));
    assert_eq!(registry.usage(), (1, 2));
    let (replacement, new_issuer) = registry.acquire().unwrap();
    assert!(registry.issue(&old_issuer).is_none());
    let replacement_body = registry.issue(&new_issuer).unwrap();
    assert_eq!(registry.response_count(), 2);
    assert!(registry.finish(second_body));
    assert!(registry.release_task(second));
    assert_eq!(registry.response_count(), 1);
    assert_eq!(registry.usage(), (1, 2));
    assert!(registry.finish(replacement_body));
    assert!(registry.release_task(replacement));
    assert_eq!(registry.response_count(), 0);
    assert_eq!(registry.usage(), (0, 2));
}

#[test]
fn registry_preserves_response_charge_after_failed_task_release() {
    use gateway_core::http_connection::ResponseRegistry;
    let mut registry = ResponseRegistry::new(1);
    let (task, issuer) = registry.acquire().unwrap();
    let body = registry.issue(&issuer).unwrap();
    assert!(!registry.release_task(task));
    assert_eq!(registry.response_count(), 1);
    assert_eq!(registry.usage(), (1, 1));
    assert!(registry.acquire().is_none());
    assert!(registry.issue(&issuer).is_none());
    assert!(registry.finish(body));
    assert_eq!(registry.response_count(), 0);
    assert_eq!(registry.usage(), (1, 1));
    assert!(registry.acquire().is_none());
}
