use gateway_core::policy::{Identity, Policy, Route};

fn identity(tenant: u64, byte: u8) -> Identity {
    Identity { tenant, digest: vec![byte; 32] }
}
fn route(tenant: u64, selector: u64, origin: usize, credential: usize) -> Route {
    Route { tenant, selector, origin, credential }
}
fn policy() -> Policy {
    Policy::validate(
        vec![identity(1, 11), identity(2, 22)],
        vec![route(1, 7, 0, 0), route(2, 7, 1, 1), route(2, 8, 1, 1)],
        vec![route(1, 7, 0, 0), route(2, 7, 1, 1), route(2, 8, 1, 1)],
        2, vec![1, 2],
    ).unwrap()
}

#[test]
fn authentication_and_tenant_scoped_dispatch() {
    let p = policy();
    assert!(p.authenticate(&[0; 32]).is_none());
    assert!(p.authenticate(&[11; 31]).is_none());
    let one = p.authenticate(&[11; 32]).unwrap();
    let two = p.authenticate(&[22; 32]).unwrap();
    assert!(one.authorize(8, 1).is_none());
    assert!(one.authorize(7, 0).is_none());
    assert!(one.authorize(99, 1).is_none());
    let a = one.authorize(7, 41).unwrap();
    let b = two.authorize(7, 42).unwrap();
    assert_eq!((a.origin(), a.credential(), a.tenant_id(), a.request_id()), (0, 0, 1, 41));
    assert_eq!((b.origin(), b.credential(), b.tenant_id(), b.request_id()), (1, 1, 2, 42));
}

#[test]
fn candidate_configuration_cannot_expand_root_grants() {
    // Check every combination in a small domain, including out-of-range handles.
    for tenant in 0..4 {
        for selector in 6..9 {
            for origin in 0..3 {
                for credential in 0..3 {
                    let p = Policy::validate(
                        vec![identity(1, 11), identity(2, 22)],
                        vec![route(1, 7, 0, 0), route(2, 8, 1, 1)],
                        vec![route(tenant, selector, origin, credential)],
                        2, vec![1, 2],
                    );
                    let permitted = (tenant, selector, origin, credential) == (1, 7, 0, 0)
                        || (tenant, selector, origin, credential) == (2, 8, 1, 1);
                    assert_eq!(p.is_some(), permitted);
                }
            }
        }
    }
}

#[test]
fn inconsistent_root_handles_and_unknown_tenants_are_rejected() {
    for (tenant, origin, credential) in [(1, 0, 1), (1, 2, 0), (1, 0, 2), (9, 0, 0)] {
        assert!(Policy::validate(
            vec![identity(1, 11), identity(2, 22)],
            vec![route(tenant, 7, origin, credential)],
            vec![route(tenant, 7, origin, credential)],
            2, vec![tenant, 2],
        ).is_none());
    }
}

#[test]
fn ambiguous_identity_and_route_configuration_is_rejected() {
    assert!(Policy::validate(vec![identity(1, 11), identity(1, 22)], vec![], vec![], 0, vec![]).is_none());
    assert!(Policy::validate(vec![identity(1, 11), identity(2, 11)], vec![], vec![], 0, vec![]).is_none());
    assert!(Policy::validate(vec![Identity { tenant: 1, digest: vec![1; 31] }], vec![], vec![], 0, vec![]).is_none());
    assert!(Policy::validate(
        vec![identity(1, 11)],
        vec![route(1, 7, 0, 0), route(1, 7, 1, 0)],
        vec![route(1, 7, 0, 0), route(1, 7, 1, 0)],
        2, vec![1],
    ).is_none());
}

#[test]
fn tokens_cannot_switch_to_another_policy() {
    let first = policy();
    let second = Policy::validate(vec![identity(1, 11)], vec![], vec![], 0, vec![]).unwrap();
    let authenticated = first.authenticate(&[11; 32]).unwrap();
    let other = second.authenticate(&[11; 32]).unwrap();
    assert!(authenticated.authorize(7, 1).is_some());
    assert!(other.authorize(7, 1).is_none());
    // authorize is a method on the authentication token; it takes no replacement policy.
}
