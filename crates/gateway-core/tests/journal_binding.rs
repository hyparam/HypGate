use gateway_core::{journal_binding::JournalBinding, journal::{Journal, DurableFrame}, framing::{Header, RecordBody}};
fn receipt(session: u128) -> DurableFrame {
    let frame = RecordBody::new(Header { payload: 3, tenant: 1, request: 2, chunk: 3, kind: 0 }, b"abc")
        .unwrap().seal(&[0; 32]);
    let mut journal = Journal::new(session);
    let ticket = journal.begin(frame.bytes().len() as u64).unwrap();
    journal.commit_frame(&ticket, frame).unwrap()
}
#[test]
fn designation_is_required_and_cannot_change() {
    for session in [0, 1, u128::MAX] {
        let own = receipt(session);
        let foreign = receipt(session ^ 1);
        let mut binding = JournalBinding::new();
        assert!(!binding.accepts(&own));
        assert!(binding.bind(session));
        assert!(binding.bind(session));
        assert!(!binding.bind(session ^ 1));
        assert!(binding.accepts(&own));
        assert!(!binding.accepts(&foreign));
    }
}
