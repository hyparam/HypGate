use gateway_core::{policy::{Identity, Policy, Route}, resolved_route::ResolvedRoute};
#[test]
fn selected_values_match_authorized_indices_and_reject_other_authorities() {
    let route = |selector, origin, credential| Route { tenant: 1, selector, origin, credential };
    let policy = Policy::validate(vec![Identity { tenant: 1, digest: vec![9; 32] }],
        vec![route(7, 1, 0), route(8, 0, 1)], vec![route(7, 1, 0), route(8, 0, 1)], 2, vec![1, 1]).unwrap();
    let identity = policy.authenticate(&[9; 32]).unwrap();
    let auth = identity.authorize(7, 1).unwrap();
    let other_route = identity.authorize(8, 1).unwrap();
    let other_request = identity.authorize(7, 2).unwrap();
    let destinations = vec!["destination zero", "destination one"];
    let credentials = vec!["credential zero", "credential one"];
    let resolved = ResolvedRoute::resolve(&auth, &destinations, &credentials).unwrap();
    assert_eq!(resolved.destination(&auth), Some(&"destination one"));
    assert_eq!(resolved.credential(&auth), Some(&"credential zero"));
    for wrong in [&other_route, &other_request] {
        assert!(resolved.destination(wrong).is_none());
        assert!(resolved.credential(wrong).is_none());
    }
    assert!(ResolvedRoute::resolve(&auth, &vec!["short"], &credentials).is_none());
    assert!(ResolvedRoute::resolve(&auth, &destinations, &Vec::<&str>::new()).is_none());
}
