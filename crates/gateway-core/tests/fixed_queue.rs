use gateway_core::fixed_queue::FixedQueue;
use std::collections::VecDeque;

#[test]
fn fixed_queue_matches_fifo_through_wraparound_and_full_rejection() {
    for capacity in [1, 2, 31, 32, 33, 1024] {
        let mut queue = FixedQueue::new(capacity);
        let mut model = VecDeque::new();
        let mut random = 17u64;
        for step in 0..16000u64 {
            random = random.wrapping_mul(6364136223846793005).wrapping_add(1);
            if random >> 62 != 0 {
                let value = vec![step, random];
                let expected = if model.len() == capacity { Err(value.clone()) }
                    else { model.push_back(value.clone()); Ok(()) };
                assert_eq!(queue.push(value), expected);
            } else { assert_eq!(queue.pop(), model.pop_front()); }
            assert_eq!(queue.len(), model.len());
            assert_eq!(queue.is_full(), model.len() == capacity);
        }
        while let Some(expected) = model.pop_front() { assert_eq!(queue.pop(), Some(expected)); }
        assert!(queue.pop().is_none()); assert_eq!(queue.len(), 0);
    }
}

#[test]
fn fixed_queue_moves_and_drops_each_value_once() {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    struct Value(Arc<AtomicUsize>);
    impl Drop for Value { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut queue = FixedQueue::new(1);
    assert!(queue.push(Value(dropped.clone())).is_ok());
    let rejected = queue.push(Value(dropped.clone())).err().unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 0);
    drop(rejected);
    let value = queue.pop().unwrap();
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert!(queue.push(Value(dropped.clone())).is_ok());
    drop(queue);
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    drop(value);
    assert_eq!(dropped.load(Ordering::SeqCst), 3);
}
