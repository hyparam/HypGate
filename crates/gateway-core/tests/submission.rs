use gateway_core::{policy::{Identity, Policy, Route}, resource::ResourceAdmission,
    owned_stream::OwnedStream, submission::AuthorizedWrite, journal_binding::JournalBinding,
    journal::Journal, framing::{RecordBody, Header}};

#[test]
fn submission_binds_request_route_and_exact_audited_range() {
    let route = |selector, origin, credential| Route { tenant: 1, selector, origin, credential };
    let policy = Policy::validate(vec![Identity { tenant: 1, digest: vec![9; 32] }],
        vec![route(7, 0, 0), route(8, 1, 1)], vec![route(7, 0, 0), route(8, 1, 1)], 2, vec![1, 1]).unwrap();
    let identity = policy.authenticate(&[9; 32]).unwrap();
    for (strict, cleanup) in [true, false].into_iter().flat_map(|strict| (0..3).map(move |cleanup| (strict, cleanup))) {
        let mut registry = ResourceAdmission::new(2, 4);
        let first = registry.acquire().unwrap();
        let second = registry.acquire().unwrap();
        let authority = identity.authorize(7, first.owner()).unwrap();
        let other_route = identity.authorize(8, first.owner()).unwrap();
        let other_request = identity.authorize(7, second.owner()).unwrap();
        let destinations = vec!["provider zero", "provider one"];
        let credentials = vec!["credential zero", "credential one"];
        let resolved = gateway_core::resolved_route::ResolvedRoute::resolve(&authority, &destinations, &credentials).unwrap();
        let wrong_route = gateway_core::resolved_route::ResolvedRoute::resolve(&other_route, &destinations, &credentials).unwrap();
        let wrong_request = gateway_core::resolved_route::ResolvedRoute::resolve(&other_request, &destinations, &credentials).unwrap();
        let mut stream = OwnedStream::claim(&registry, first, &authority, strict).ok().unwrap();
        let chunk = stream.advance(vec![1, 2, 3, 4]).unwrap();
        let mut binding = JournalBinding::new();
        assert!(binding.bind(17));
        assert!(AuthorizedWrite::prepare(&mut stream, &other_request, &binding, 0, 4).is_none());
        if strict {
            assert!(AuthorizedWrite::prepare(&mut stream, &authority, &binding, 0, 4).is_none());
            let frame = RecordBody::new(Header { payload: 4, tenant: 1, request: authority.request_id(), chunk, direction: 0 }, &[1, 2, 3, 4])
                .unwrap().seal(&[0; 32]);
            let mut journal = Journal::new(17);
            let ticket = journal.begin(frame.bytes().len() as u64).unwrap();
            let receipt = journal.commit_frame(&ticket, frame).unwrap();
            assert!(stream.acknowledge_receipt(&authority, &binding, 0, &receipt));
        }
        let mut foreign = JournalBinding::new();
        assert!(foreign.bind(18));
        if strict { assert!(AuthorizedWrite::prepare(&mut stream, &authority, &foreign, 0, 3).is_none()); }
        assert!(AuthorizedWrite::prepare(&mut stream, &authority, &binding, 2, 3).is_none());
        if strict { assert!(AuthorizedWrite::prepare(&mut stream, &authority, &binding, 1, 3).is_none()); }
        let write = AuthorizedWrite::prepare(&mut stream, &authority, &binding, 0, 3).unwrap();
        assert_eq!(resolved.write_bytes(&write, &stream, &authority, &binding, 0), Some(&[1, 2, 3][..]));
        assert!(wrong_route.write_bytes(&write, &stream, &authority, &binding, 0).is_none());
        assert!(wrong_request.write_bytes(&write, &stream, &authority, &binding, 0).is_none());
        assert!(resolved.write_bytes(&write, &stream, &authority, &binding, 1).is_none());
        assert_eq!(resolved.write_bytes(&write, &stream, &authority, &foreign, 0).is_none(), strict);
        assert_eq!(write.bytes(&stream, &authority, &binding, 0), Some(&[1, 2, 3][..]));
        assert_eq!(write.bytes(&stream, &authority, &foreign, 0).is_none(), strict);
        assert!(write.bytes(&stream, &authority, &binding, 1).is_none());
        assert!(write.bytes(&stream, &authority, &binding, 2).is_none());
        assert!(write.bytes(&stream, &other_route, &binding, 0).is_none());
        assert!(write.bytes(&stream, &other_request, &binding, 0).is_none());
        assert!(!write.complete(&mut stream, 4));
        assert!(write.complete(&mut stream, 2));
        assert!(write.bytes(&stream, &authority, &binding, 0).is_none());
        let next = AuthorizedWrite::prepare(&mut stream, &authority, &binding, 0, 4).unwrap();
        assert_eq!(next.bytes(&stream, &authority, &binding, 0), Some(&[3, 4][..]));
        if cleanup == 0 {
            stream.cancel();
            assert!(next.bytes(&stream, &authority, &binding, 0).is_none());
            assert!(next.complete(&mut stream, 1)); // account an already issued write
        } else {
            assert!(next.complete(&mut stream, 2));
            if cleanup == 1 { stream.advance(vec![1, 2, 3, 4]).unwrap(); }
            else {
                assert!(stream.begin_read());
                stream.read_buffer().copy_from_slice(&[1, 2, 3, 4]);
                assert!(stream.finish_read(4));
            }
            assert!(!stream.is_audited_for(&authority, &binding));
            assert_eq!(AuthorizedWrite::prepare(&mut stream, &authority, &binding, 0, 4).is_none(), strict);
        }
        assert!(stream.retire(&mut registry));
        assert!(registry.release(&second));
    }
}
