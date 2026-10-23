use gateway_core::{policy::{Identity, Policy, Route}, resource::ResourceAdmission};

#[test]
fn stream_creation_binds_live_capacity_and_authority_once() {
    let route = || Route { tenant: 1, selector: 7, origin: 0, credential: 0 };
    let policy = Policy::validate(vec![Identity { tenant: 1, digest: vec![9; 32] }],
        vec![route()], vec![route()], 1, vec![1]).unwrap();
    let identity = policy.authenticate(&[9; 32]).unwrap();
    let mut registry = ResourceAdmission::new(2, 4);
    let mut first = registry.acquire().unwrap();
    let mut second = registry.acquire().unwrap();
    let first_authority = identity.authorize(7, first.owner()).unwrap();
    let second_authority = identity.authorize(7, second.owner()).unwrap();
    assert!(registry.authorized_stream(&mut first, &second_authority, true).is_none());
    let mut stream = registry.authorized_stream(&mut first, &first_authority, true).unwrap();
    assert!(registry.authorized_stream(&mut first, &first_authority, true).is_none());
    assert!(stream.advance(vec![0; 5]).is_none());
    let chunk = stream.advance(vec![1, 2, 3, 4]).unwrap();
    assert!(stream.prepare(4).is_none());
    assert!(stream.acknowledge(first.owner(), chunk, 4));
    let ticket = stream.prepare(4).unwrap();
    assert!(stream.complete(&ticket, 4));
    drop(stream);
    assert!(registry.release(&first));
    assert!(registry.release(&second));
    assert!(registry.authorized_stream(&mut second, &second_authority, false).is_none());
    let mut replacement = registry.acquire().unwrap();
    assert!(registry.authorized_stream(&mut replacement, &first_authority, false).is_none());
    let authority = identity.authorize(7, replacement.owner()).unwrap();
    assert!(registry.authorized_stream(&mut replacement, &authority, false).is_some());
}
