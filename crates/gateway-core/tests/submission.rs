use gateway_core::{policy::{Identity, Policy, Route}, resource::ResourceAdmission,
    owned_stream::OwnedStream, submission::AuthorizedWrite, journal_binding::JournalBinding,
    journal::Journal, framing::{RecordBody, Header}};

#[test]
fn submission_binds_request_route_and_exact_audited_range() {
    let route = |selector, origin, credential| Route { tenant: 1, selector, origin, credential };
    let policy = Policy::validate(vec![Identity { tenant: 1, digest: vec![9; 32] }],
        vec![route(7, 0, 0), route(8, 1, 1)], vec![route(7, 0, 0), route(8, 1, 1)], 2, vec![1, 1]).unwrap();
    let identity = policy.authenticate(&[9; 32]).unwrap();
    for strict in [true, false] {
        let mut registry = ResourceAdmission::new(2, 4);
        let first = registry.acquire().unwrap();
        let second = registry.acquire().unwrap();
        let authority = identity.authorize(7, first.owner()).unwrap();
        let other_route = identity.authorize(8, first.owner()).unwrap();
        let other_request = identity.authorize(7, second.owner()).unwrap();
        let mut stream = OwnedStream::claim(&registry, first, &authority, strict).ok().unwrap();
        let chunk = stream.advance(vec![1, 2, 3, 4]).unwrap();
        assert!(AuthorizedWrite::prepare(&mut stream, &other_request, 4).is_none());
        if strict {
            assert!(AuthorizedWrite::prepare(&mut stream, &authority, 4).is_none());
            let frame = RecordBody::new(Header { payload: 4, tenant: 1, request: authority.request_id(), chunk, direction: 0 }, &[1, 2, 3, 4])
                .unwrap().seal(&[0; 32]);
            let mut journal = Journal::new(17);
            let ticket = journal.begin(frame.bytes().len() as u64).unwrap();
            let receipt = journal.commit_frame(&ticket, frame).unwrap();
            let mut binding = JournalBinding::new();
            assert!(binding.bind(17));
            assert!(stream.acknowledge_receipt(&authority, &binding, 0, &receipt));
        }
        let write = AuthorizedWrite::prepare(&mut stream, &authority, 3).unwrap();
        assert_eq!(write.bytes(stream.stream(), &authority), Some(&[1, 2, 3][..]));
        assert!(write.bytes(stream.stream(), &other_route).is_none());
        assert!(write.bytes(stream.stream(), &other_request).is_none());
        assert!(!write.complete(&mut stream, 4));
        assert!(write.complete(&mut stream, 2));
        assert!(write.bytes(stream.stream(), &authority).is_none());
        let next = AuthorizedWrite::prepare(&mut stream, &authority, 4).unwrap();
        assert_eq!(next.bytes(stream.stream(), &authority), Some(&[3, 4][..]));
        stream.cancel();
        assert!(next.bytes(stream.stream(), &authority).is_none());
        assert!(next.complete(&mut stream, 1)); // account an already issued write
        assert!(stream.retire(&mut registry));
        assert!(registry.release(&second));
    }
}
