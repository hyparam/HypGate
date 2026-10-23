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
    assert!(registry.release_stream(&first, stream));
    assert!(registry.release(&second));
    assert!(registry.authorized_stream(&mut second, &second_authority, false).is_none());
    let mut replacement = registry.acquire().unwrap();
    assert!(registry.authorized_stream(&mut replacement, &first_authority, false).is_none());
    let authority = identity.authorize(7, replacement.owner()).unwrap();
    assert!(registry.authorized_stream(&mut replacement, &authority, false).is_some());
}

#[test]
fn usage_counts_live_slots_including_holes_and_replacements() {
    let mut registry = ResourceAdmission::new(3, 4);
    assert_eq!(registry.usage(), (0, 3));
    let first = registry.acquire().unwrap();
    let middle = registry.acquire().unwrap();
    let last = registry.acquire().unwrap();
    assert_eq!(registry.usage(), (3, 3));
    assert!(registry.release(&middle));
    assert_eq!(registry.usage(), (2, 3));
    let replacement = registry.acquire().unwrap();
    assert_eq!(registry.usage(), (3, 3));
    assert!(!registry.release(&middle));
    assert_eq!(registry.usage(), (3, 3));
    for key in [first, replacement, last] { assert!(registry.release(&key)); }
    assert_eq!(registry.usage(), (0, 3));
    assert_eq!(ResourceAdmission::new(0, 4).usage(), (0, 0));
}


#[test]
fn normalized_limits_reject_overflow_and_enforce_combined_payload_budget() {
    use gateway_core::resource::validate_limits;
    for (requests, chunk, expected) in [
        (0, 1, false), (1, 0, false), (1, 1, true),
        (65536, 2048, true), (65536, 2049, false), (65537, 1, false),
        (128, 1048576, true), (129, 1048576, false), (1, 1048577, false),
        (usize::MAX, usize::MAX, false), (1, usize::MAX, false), (usize::MAX, 1, false),
    ] {
        assert_eq!(validate_limits(requests, chunk), expected, "{requests} slots of {chunk}");
    }
}


#[test]
fn retirement_rejects_wrong_unclaimed_and_stale_stream_ownership() {
    use gateway_core::stream::StreamChunk;
    let route = || Route { tenant: 1, selector: 7, origin: 0, credential: 0 };
    let policy = Policy::validate(vec![Identity { tenant: 1, digest: vec![9; 32] }],
        vec![route()], vec![route()], 1, vec![1]).unwrap();
    let identity = policy.authenticate(&[9; 32]).unwrap();
    let mut registry = ResourceAdmission::new(2, 4);
    let mut first = registry.acquire().unwrap(); let mut second = registry.acquire().unwrap();
    let authority = identity.authorize(7, first.owner()).unwrap();
    let first_stream = registry.authorized_stream(&mut first, &authority, true).unwrap();
    let authority = identity.authorize(7, second.owner()).unwrap();
    let second_stream = registry.authorized_stream(&mut second, &authority, true).unwrap();
    assert!(!registry.release_stream(&first, second_stream));
    assert_eq!(registry.usage(), (2, 2));
    assert!(registry.release_stream(&first, first_stream));
    assert_eq!(registry.usage(), (1, 2));
    let replacement = registry.acquire().unwrap();
    let forged = StreamChunk::new(replacement.owner(), vec![1], 4, true).unwrap();
    assert!(!registry.release_stream(&replacement, forged)); // no authorized construction
    let stale = StreamChunk::new(first.owner(), vec![], 4, true).unwrap();
    assert!(!registry.release_stream(&first, stale));
    assert_eq!(registry.usage(), (2, 2));
    assert!(registry.release(&replacement)); assert!(registry.release(&second));
}

#[test]
fn audit_record_binds_authority_current_chunk_and_exact_payload() {
    use gateway_core::stream::StreamChunk;
    let route = || Route { tenant: 42, selector: 7, origin: 0, credential: 0 };
    let policy = Policy::validate(vec![Identity { tenant: 42, digest: vec![9; 32] }],
        vec![route()], vec![route()], 1, vec![42]).unwrap();
    let identity = policy.authenticate(&[9; 32]).unwrap();
    let authority = identity.authorize(7, 11).unwrap();
    let other = identity.authorize(7, 12).unwrap();
    let mut stream = StreamChunk::new(11, vec![], 4, true).unwrap();
    let chunk = stream.advance(vec![3, 1, 4]).unwrap();
    for direction in [0, 1] {
        let (header, bytes) = stream.audit_record(&authority, direction).unwrap();
        assert_eq!((header.tenant, header.request, header.chunk, header.direction, header.payload),
            (42, 11, chunk, direction, 3));
        assert_eq!(bytes, &[3, 1, 4]);
    }
    assert!(stream.audit_record(&other, 0).is_none());
    assert!(stream.audit_record(&authority, 2).is_none());
    stream.cancel();
    assert!(stream.audit_record(&authority, 0).is_none());
    let mut failed = StreamChunk::new(11, vec![1], 4, false).unwrap();
    failed.fail_log();
    assert!(failed.audit_record(&authority, 0).is_none());
    let oversized = StreamChunk::new(11, vec![0; 1048577], 1048577, false).unwrap();
    assert!(oversized.audit_record(&authority, 0).is_none());
}
