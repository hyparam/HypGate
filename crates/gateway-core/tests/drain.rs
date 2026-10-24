use gateway_core::drain::DrainRegistry;

#[test]
fn closure_preserves_outstanding_credits_and_never_reopens() {
    let mut registry = DrainRegistry::new(2);
    let first = registry.acquire().unwrap();
    let second = registry.acquire().unwrap();
    assert!(registry.acquire().is_none());
    registry.close(); registry.close();
    assert!(registry.is_closed());
    assert_eq!(registry.usage(), (2, 2));
    assert!(registry.acquire().is_none());
    assert!(registry.release(&first));
    assert!(!registry.release(&first));
    assert_eq!(registry.usage(), (1, 2));
    assert!(registry.acquire().is_none());
    assert!(registry.release(&second));
    assert_eq!(registry.usage(), (0, 2));
    assert!(registry.acquire().is_none());
}
