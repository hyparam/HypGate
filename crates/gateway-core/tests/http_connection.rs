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
