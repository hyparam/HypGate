//! Executable checks of the shipper core: assembler bounds and ordering, batch
//! limits, upload cursor progress, identity encodings, enrollment transitions,
//! and the shipper machine that composes them.
//! The proofs cover every input; these pin concrete scenarios and boundaries.
use gateway_core::batch_builder::{BatchBuilder, MAX_BYTES, MAX_ROWS};
use gateway_core::enrollment::{Enrollment, Recovery, State, throttle_delay, transport_delay, MAX_DELAY_SECONDS};
use gateway_core::exchange_assembler::{Assembler, saturating_add};
use gateway_core::framing::Header;
use gateway_core::metadata::{encode_completion, encode_request_start, encode_response_head};
use gateway_core::shipper::{checksum, Action, Credential, Emitted, Machine, Outcome, Path, Reply};
use gateway_core::shipping_identity::{batch_id, exchange_key, message_key, part_key};
use gateway_core::upload_cursor::UploadCursor;

fn header(kind: u8, request: u64, chunk: u64, payload: &[u8]) -> Header {
    Header { payload: payload.len() as u32, tenant: 9, request, chunk, kind }
}

#[test]
fn assembler_groups_a_request_in_record_order_and_completes_once() {
    let mut a = Assembler::new(4, 1024);
    let start = encode_request_start(1_000, 7, b"https://api.example/v1").unwrap();
    assert!(a.admit(header(2, 1, 0, &start), &start).is_none());
    assert!(a.admit(header(0, 1, 1, b"abc"), b"abc").is_none());
    assert!(a.admit(header(0, 1, 2, b"def"), b"def").is_none());
    let head = encode_response_head(1_500, 200).unwrap();
    assert!(a.admit(header(3, 1, 0, &head), &head).is_none());
    assert!(a.admit(header(1, 1, 3, b"XY"), b"XY").is_none());
    assert_eq!(a.open_exchanges(), 1);
    let done = encode_completion(2_000, 0, 6, 2).unwrap();
    let e = a.admit(header(4, 1, 0, &done), &done).expect("completion emits");
    assert_eq!(a.open_exchanges(), 0);
    assert_eq!((e.tenant, e.request), (9, 1));
    assert_eq!(e.upload, b"abcdef"); assert_eq!(e.download, b"XY");
    assert_eq!((e.upload_total, e.download_total), (6, 2));
    assert!(!e.truncated && !e.incomplete && !e.orphan);
    assert_eq!(e.start.as_ref().unwrap().destination, b"https://api.example/v1");
    assert_eq!(e.head.as_ref().unwrap().status, 200);
    assert_eq!(e.completion.as_ref().unwrap().outcome, 0);
    // A second completion for the same request is an orphan, never a duplicate of the first.
    let again = a.admit(header(4, 1, 0, &done), &done).unwrap();
    assert!(again.orphan && again.upload.is_empty());
}

#[test]
fn assembler_interleaves_requests_and_truncates_at_the_cap() {
    let mut a = Assembler::new(8, 5);
    let start = encode_request_start(1, 1, b"https://h/p").unwrap();
    for request in [1u64, 2] { assert!(a.admit(header(2, request, 0, &start), &start).is_none()); }
    assert!(a.admit(header(0, 1, 1, b"1234"), b"1234").is_none());
    assert!(a.admit(header(0, 2, 1, b"ab"), b"ab").is_none());
    assert!(a.admit(header(1, 1, 2, b"56789"), b"56789").is_none()); // only one byte of room left
    assert!(a.admit(header(1, 1, 3, b"0"), b"0").is_none());         // nothing retained after truncation
    let done = encode_completion(2, 0, 4, 6).unwrap();
    let one = a.admit(header(4, 1, 0, &done), &done).unwrap();
    assert_eq!(one.upload, b"1234"); assert_eq!(one.download, b"5");
    assert!(one.truncated); assert_eq!((one.upload_total, one.download_total), (4, 6));
    let two = a.admit(header(4, 2, 0, &done), &done).unwrap();
    assert_eq!(two.upload, b"ab"); assert!(!two.truncated);
}

#[test]
fn assembler_evicts_oldest_at_capacity_and_restarts_duplicate_requests() {
    let mut a = Assembler::new(2, 64);
    let start = encode_request_start(1, 1, b"https://h/p").unwrap();
    assert!(a.admit(header(2, 10, 0, &start), &start).is_none());
    assert!(a.admit(header(2, 11, 0, &start), &start).is_none());
    let evicted = a.admit(header(2, 12, 0, &start), &start).expect("capacity eviction");
    assert_eq!(evicted.request, 10); assert!(evicted.incomplete && !evicted.orphan);
    assert_eq!(a.open_exchanges(), 2);
    let restarted = a.admit(header(2, 11, 0, &start), &start).expect("duplicate start evicts the old one");
    assert_eq!(restarted.request, 11); assert!(restarted.incomplete);
    assert_eq!(a.open_exchanges(), 2);
    // Orphans carry just their record and leave the open set alone.
    let orphan = a.admit(header(1, 99, 1, b"zz"), b"zz").unwrap();
    assert!(orphan.orphan && orphan.start.is_none()); assert_eq!(orphan.download, b"zz");
    assert_eq!(a.open_exchanges(), 2);
    let mut drained = Vec::new();
    while let Some(e) = a.evict_oldest() { drained.push(e.request); }
    assert_eq!(drained, vec![12, 11]);
    assert!(a.evict_oldest().is_none());
}

#[test]
fn saturating_add_pins_the_ceiling() {
    assert_eq!(saturating_add(1, 2), 3);
    assert_eq!(saturating_add(u64::MAX - 1, 1), u64::MAX);
    assert_eq!(saturating_add(u64::MAX, 7), u64::MAX);
}

#[test]
fn batch_builder_holds_the_row_and_byte_limits() {
    let mut b = BatchBuilder::new();
    assert!(b.is_empty());
    assert!(b.push(b"{\"a\":1}")); assert!(b.push(b"{}"));
    assert_eq!(b.bytes(), b"{\"a\":1}\n{}\n"); assert_eq!(b.row_count(), 2);
    let body = b.finish();
    assert_eq!(body, b"{\"a\":1}\n{}\n"); assert!(b.is_empty()); assert_eq!(b.len(), 0);
    for _ in 0..MAX_ROWS { assert!(b.push(b"x")); }
    assert!(!b.push(b"x")); assert_eq!(b.row_count(), MAX_ROWS);
    let mut c = BatchBuilder::new();
    let big = vec![b'y'; MAX_BYTES - 1];
    assert!(c.push(&big)); assert_eq!(c.len(), MAX_BYTES);
    assert!(!c.push(b"")); // even an empty row needs its newline
    let mut d = BatchBuilder::new();
    assert!(!d.push(&vec![b'z'; MAX_BYTES]));
    assert!(BatchBuilder::oversized(&vec![b'z'; MAX_BYTES]));
    assert!(!BatchBuilder::oversized(&vec![b'z'; MAX_BYTES - 1]));
}

#[test]
fn upload_cursor_resolves_only_the_acknowledged_in_flight_batch() {
    let session = [7u8; 16]; let digest = 3u64;
    assert!(UploadCursor::restore(1, 2, 0).is_none());
    let mut c = UploadCursor::restore(0, 0, 0).unwrap();
    assert!(c.emit(5)); assert_eq!(c.pending(), 5);
    assert!(!c.open_batch(0, &session, digest));
    assert!(!c.open_batch(6, &session, digest));
    assert!(c.open_batch(3, &session, digest));
    assert!(!c.open_batch(1, &session, digest)); // one batch at a time
    let id = c.current().unwrap().batch_id().clone();
    assert_eq!(id, batch_id(&session, 0, 3, digest));
    assert_eq!(c.current().unwrap().range(), (0, 3));
    assert!(!c.acknowledge(&batch_id(&session, 1, 3, digest)));
    assert!(!c.acknowledge(&id[..39]));
    assert_eq!(c.counts(), (5, 0, 0));
    assert!(c.acknowledge(&id));
    assert_eq!(c.counts(), (5, 3, 0)); assert!(c.current().is_none());
    assert!(!c.acknowledge(&id)); // nothing in flight
    assert!(c.open_batch(2, &session, digest));
    c.abandon(); assert_eq!(c.counts(), (5, 3, 0));
    // The rebuilt batch over the same range has the same id.
    assert!(c.open_batch(2, &session, digest));
    assert_eq!(c.current().unwrap().batch_id(), &batch_id(&session, 3, 5, digest));
    assert!(c.poison()); assert_eq!(c.counts(), (5, 5, 1)); assert!(!c.poison());
    assert!(!c.emit(u64::MAX));
}

#[test]
fn identities_are_fixed_width_and_distinct() {
    let s = [1u8; 16]; let t = [2u8; 16];
    assert_eq!(exchange_key(&s, 5).len(), 24);
    assert_eq!(message_key(&s, 5, 1).len(), 28);
    assert_eq!(part_key(&s, 5, 1, 0).len(), 32);
    assert_eq!(batch_id(&s, 0, 1, 0).len(), 40);
    assert_ne!(exchange_key(&s, 5), exchange_key(&t, 5));
    assert_ne!(exchange_key(&s, 5), exchange_key(&s, 6));
    assert_ne!(part_key(&s, 5, 1, 0), part_key(&s, 5, 0, 1));
    assert_ne!(batch_id(&s, 1, 2, 0), batch_id(&s, 0, 2, 0));
    assert_ne!(batch_id(&s, 0, 2, 0), batch_id(&s, 0, 1, 0));
    assert_ne!(batch_id(&s, 0, 1, 1), batch_id(&s, 0, 1, 0));
    assert_eq!(&part_key(&s, 5, 1, 0)[..28], &message_key(&s, 5, 1)[..]);
}

#[test]
fn enrollment_gates_uploads_and_stops_for_good() {
    let mut e = Enrollment::new();
    assert!(e.needs_bootstrap() && !e.can_upload(0) && !e.needs_refresh(0));
    assert!(!e.enrolled(100, 100)); // already expired
    assert!(e.enrolled(1_000_000, 100));
    assert!(e.can_upload(999_999) && !e.can_upload(1_000_000));
    assert!(!e.needs_refresh(999_999), "a fresh unexpired token can upload first");
    e.uploaded();
    assert!(!e.needs_refresh(1_000_000 - 86_401));
    assert!(e.needs_refresh(1_000_000 - 86_400) && e.needs_refresh(5_000_000));
    assert_eq!(e.rejected(), Recovery::Refresh);
    assert_eq!(e.rejected(), Recovery::Bootstrap);
    assert!(e.needs_bootstrap());
    assert!(e.enrolled(2_000_000, 100));
    assert_eq!(e.rejected(), Recovery::Refresh);
    e.uploaded();
    assert_eq!(e.rejected(), Recovery::Refresh); // a success re-arms the single refresh
    e.refresh_rejected();
    assert!(e.needs_bootstrap());
    e.revoked();
    assert!(e.is_stopped() && !e.enrolled(3_000_000, 100) && e.rejected() == Recovery::Stop);
    e.refresh_rejected(); assert!(e.is_stopped());
    assert!(matches!(Enrollment::new().rejected(), Recovery::Refresh));
    let _ = State::Unenrolled;
}

#[test]
fn retry_delays_are_bounded() {
    assert_eq!([throttle_delay(0, None), throttle_delay(1, None), throttle_delay(2, None), throttle_delay(3, None), throttle_delay(99, None)], [30, 60, 120, 300, 300]);
    assert_eq!(throttle_delay(0, Some(7)), 7);
    assert_eq!(throttle_delay(0, Some(0)), 30);
    assert_eq!(throttle_delay(0, Some(u64::MAX)), MAX_DELAY_SECONDS);
    assert_eq!([transport_delay(0), transport_delay(1), transport_delay(2), transport_delay(3), transport_delay(6)], [2, 4, 6, 30, 300]);
}

// ---- shipper machine --------------------------------------------------------

const DAY: u64 = 86_400;

/// Feed one complete exchange through the machine and return its token.
fn feed(m: &mut Machine, request: u64, upload: &[u8]) -> Emitted {
    let start = encode_request_start(1_000, 7, b"https://api.example/v1").unwrap();
    assert!(m.admit(header(2, request, 0, &start), &start).is_none());
    assert!(m.admit(header(0, request, 1, upload), upload).is_none());
    let done = encode_completion(2_000, 0, upload.len() as u64, 0).unwrap();
    m.admit(header(4, request, 0, &done), &done).expect("completion emits")
}

/// Feed one complete exchange; `None` when the machine's checkpoint skips it.
fn feed_opt(m: &mut Machine, request: u64, upload: &[u8]) -> Option<Emitted> {
    let start = encode_request_start(1_000, 7, b"https://api.example/v1").unwrap();
    assert!(m.admit(header(2, request, 0, &start), &start).is_none());
    assert!(m.admit(header(0, request, 1, upload), upload).is_none());
    let done = encode_completion(2_000, 0, upload.len() as u64, 0).unwrap();
    m.admit(header(4, request, 0, &done), &done)
}

fn ok_reply(status: u16) -> Reply { Reply { status, retry_after: None, revocation: false, credential: None } }
fn credential_reply(jwt: &[u8], expires_at: u64) -> Reply {
    Reply { status: 200, retry_after: None, revocation: false, credential: Some(Credential { jwt: jwt.to_vec(), expires_at }) }
}
fn send(m: &mut Machine, now: u64) -> gateway_core::shipper::Request {
    // Reading comes first whenever the log may have grown; report its end, then act.
    match m.next(now) { Action::Read => { m.end_of_log(); } other => panic!("expected read, got {}", name(&other)) }
    match m.next(now) { Action::Send(r) => r, other => panic!("expected send, got {}", name(&other)) }
}
fn name(a: &Action) -> &'static str {
    match a { Action::Read => "read", Action::Send(_) => "send", Action::Sleep(_) => "sleep", Action::Poisoned => "poisoned", Action::Idle => "idle", Action::Stopped => "stopped" }
}

#[test]
fn machine_enrolls_then_ships_queued_exchanges_in_order_and_resolves_on_acknowledgment() {
    let session = [7u8; 16];
    let mut m = Machine::new(b"tok\"en\\".to_vec(), session, 4, 1024, 0, 0);
    assert!(!m.is_enrolled(100) && !m.is_stopped());
    assert!(matches!(m.next(100), Action::Read), "an empty queue reads first");
    assert!(m.wants_records());
    let a = feed(&mut m, 1, b"aaa"); let b = feed(&mut m, 2, b"bb");
    assert_eq!((a.position(), b.position()), (0, 1));
    assert_eq!(a.exchange().upload, b"aaa");
    let b = m.enqueue(b, b"{b}\n".to_vec(), 1).expect_err("tokens are accepted in emission order only");
    assert_eq!(b.position(), 1);
    assert!(m.enqueue(a, b"{a}\n".to_vec(), 1).is_ok());
    assert_eq!(m.queue_len(), 1);
    m.end_of_log();
    // Unenrolled: the first request is a bootstrap carrying the escaped token and no bearer.
    let r = match m.next(100) { Action::Send(r) => r, other => panic!("{}", name(&other)) };
    assert_eq!(r.path, Path::Bootstrap);
    assert_eq!(r.body, br#"{"bootstrap_token":"tok\"en\\"}"#);
    assert!(r.bearer.is_none() && r.batch_id.is_none());
    assert_eq!(m.reply(100, ok_reply(503)), Outcome::Deferred(30));
    assert!(matches!(m.next(100), Action::Sleep(30)));
    let r = send(&mut m, 100);
    assert_eq!(r.path, Path::Bootstrap);
    assert_eq!(m.reply(100, credential_reply(b"jwt-one", 100 + 21 * DAY)), Outcome::Enrolled);
    assert!(m.is_enrolled(100));
    assert!(m.enqueue(b, b"{b}\n".to_vec(), 1).is_ok());
    let r = send(&mut m, 100);
    assert_eq!(r.path, Path::Ingest);
    assert_eq!(r.body, b"{a}\n{b}\n");
    assert_eq!(r.bearer.as_deref(), Some(&b"jwt-one"[..]));
    assert_eq!(r.batch_id.as_deref(), Some(&batch_id(&session, 0, 2, checksum(b"{a}\n{b}\n"))[..]));
    assert_eq!(m.reply(100, ok_reply(202)), Outcome::Acknowledged(2));
    assert_eq!((m.progress(), m.queue_len()), ((2, 0), 0));
    assert!(matches!(m.next(100), Action::Read));
    m.end_of_log();
    assert!(matches!(m.next(100), Action::Idle));
}

#[test]
fn machine_isolates_then_poisons_rejected_exchanges_refreshes_once_and_stops_on_revocation() {
    let session = [9u8; 16];
    let mut m = Machine::new(b"t".to_vec(), session, 8, 1024, 0, 0);
    assert!(m.adopt_identity(b"jwt-old".to_vec(), 50 + 21 * DAY, 50));
    for (request, body) in [(1u64, &b"{c}\n"[..]), (2, b"{d}\n")] {
        let t = feed(&mut m, request, b"x");
        assert!(m.enqueue(t, body.to_vec(), 1).is_ok());
    }
    let r = send(&mut m, 50);
    assert_eq!((r.path, r.body.as_slice()), (Path::Ingest, &b"{c}\n{d}\n"[..]));
    assert_eq!(m.reply(50, ok_reply(422)), Outcome::Isolating);
    assert_eq!((m.progress(), m.queue_len()), ((0, 0), 2));
    let r = send(&mut m, 50);
    assert_eq!(r.body, b"{c}\n");
    assert_eq!(m.reply(50, ok_reply(422)), Outcome::Poisoned);
    assert_eq!((m.progress(), m.queue_len()), ((1, 1), 1));
    let r = send(&mut m, 50);
    assert_eq!(r.body, b"{d}\n");
    assert_eq!(m.reply(50, ok_reply(401)), Outcome::Nothing);
    let r = send(&mut m, 50);
    assert_eq!((r.path, r.body.len(), r.bearer.as_deref()), (Path::Refresh, 0, Some(&b"jwt-old"[..])));
    assert_eq!(m.reply(50, credential_reply(b"jwt-new", 60 + 21 * DAY)), Outcome::Enrolled);
    let r = send(&mut m, 50);
    assert_eq!((r.path, r.bearer.as_deref()), (Path::Ingest, Some(&b"jwt-new"[..])));
    assert_eq!(m.reply(50, ok_reply(401)), Outcome::Nothing, "a fresh credential earns one refresh again");
    let r = send(&mut m, 50);
    assert_eq!(r.path, Path::Refresh);
    assert_eq!(m.reply(50, ok_reply(401)), Outcome::Unenrolled, "a rejected refresh means bootstrap");
    assert!(!m.is_enrolled(50));
    let r = send(&mut m, 50);
    assert_eq!(r.path, Path::Bootstrap);
    assert_eq!(m.reply(50, Reply { status: 403, retry_after: None, revocation: true, credential: None }), Outcome::Revoked);
    assert!(m.is_stopped() && matches!(m.next(50), Action::Stopped));
    assert_eq!((m.progress(), m.queue_len()), ((1, 1), 1), "nothing was lost or invented");
}

#[test]
fn machine_skips_checkpointed_exchanges_poisons_oversized_ones_and_bounds_its_queue() {
    let session = [3u8; 16];
    let mut m = Machine::new(b"t".to_vec(), session, 2, 1024, 1, 4);
    assert!(m.adopt_identity(b"jwt".to_vec(), 2 * DAY, 0));
    let start = encode_request_start(1, 7, b"https://h/p").unwrap();
    let done = encode_completion(2, 0, 0, 0).unwrap();
    assert!(m.admit(header(2, 1, 0, &start), &start).is_none());
    assert!(m.admit(header(4, 1, 0, &done), &done).is_none(), "exchange 0 is already on the server");
    assert_eq!(m.emitted_count(), 1);
    assert!(m.wants_records());
    let t = feed(&mut m, 2, b"y");
    assert!(m.wants_records(), "one outstanding token leaves room for one more");
    assert!(m.enqueue(t, vec![b'z'; 4 * 1024 * 1024 + 1], 1).is_ok());
    let t = feed(&mut m, 3, b"y");
    assert!(!m.wants_records(), "one queued plus one outstanding reaches the bound of 2");
    assert!(m.enqueue(t, b"{ok}\n".to_vec(), 1).is_ok());
    assert!(!m.wants_records(), "queue full");
    assert!(matches!(m.next(0), Action::Poisoned), "an exchange no batch can hold is poisoned unsent");
    assert_eq!(m.progress(), (2, 5));
    let r = match m.next(0) { Action::Read => { m.end_of_log(); match m.next(0) { Action::Send(r) => r, o => panic!("{}", name(&o)) } } Action::Send(r) => r, o => panic!("{}", name(&o)) };
    assert_eq!(r.body, b"{ok}\n");
    assert_eq!(r.batch_id.as_deref(), Some(&batch_id(&session, 2, 3, checksum(b"{ok}\n"))[..]));
    assert_eq!(m.reply(0, Reply { status: 429, retry_after: Some(7), revocation: false, credential: None }), Outcome::Deferred(7));
    assert!(matches!(m.next(0), Action::Sleep(7)));
    // Nearing expiry, a refresh goes out before the retry.
    let r = send(&mut m, DAY);
    assert_eq!(r.path, Path::Refresh);
    assert_eq!(m.reply(DAY, ok_reply(401)), Outcome::Unenrolled);
    let r = send(&mut m, DAY);
    assert_eq!(r.path, Path::Bootstrap);
    assert_eq!(m.reply(DAY, credential_reply(b"j2", DAY + 1)), Outcome::Enrolled);
    let r = send(&mut m, DAY + 1);
    assert_eq!(r.path, Path::Refresh, "even a fresh credential must refresh once expired");
    assert_eq!(m.reply(DAY, credential_reply(b"j3", DAY)), Outcome::Deferred(30), "an already expired credential is refused");
}

#[test]
fn checksum_is_deterministic_and_sensitive_to_every_byte() {
    assert_eq!(checksum(b""), 0xcbf29ce484222325);
    assert_eq!(checksum(b"a"), 0xaf63dc4c8601ec8c);
    assert_eq!(checksum(b"ab"), checksum(b"ab"));
    assert_ne!(checksum(b"ab"), checksum(b"ba"));
    assert_ne!(checksum(b"ab"), checksum(b"ab\0"));
}

#[test]
fn restart_from_a_checkpoint_skips_exactly_the_resolved_exchanges() {
    let session = [4u8; 16];
    let mut first = Machine::new(b"t".to_vec(), session, 8, 1024, 0, 0);
    assert!(first.adopt_identity(b"jwt".to_vec(), 30 * DAY, 0));
    for (request, body) in [(11u64, &b"{a}\n"[..]), (12, b"{b}\n")] {
        let t = feed(&mut first, request, b"x");
        assert_eq!(t.exchange().request, request);
        assert!(first.enqueue(t, body.to_vec(), 1).is_ok());
    }
    let r = send(&mut first, 0);
    assert_eq!(r.body, b"{a}\n{b}\n");
    assert_eq!(first.reply(0, ok_reply(202)), Outcome::Acknowledged(2));
    let checkpoint = first.progress();
    assert_eq!(checkpoint, (2, 0));
    // A third exchange is read and sent, and the process dies before any reply.
    let t = feed(&mut first, 13, b"x");
    assert!(first.enqueue(t, b"{c}\n".to_vec(), 1).is_ok());
    let r = send(&mut first, 0);
    assert_eq!(r.body, b"{c}\n");
    drop(first);

    // The restarted machine replays the same records from the checkpoint:
    // the two resolved exchanges are numbered and skipped, the third is sent
    // again under the same batch id.
    let mut second = Machine::new(b"t".to_vec(), session, 8, 1024, checkpoint.0, checkpoint.1);
    assert!(second.adopt_identity(b"jwt".to_vec(), 30 * DAY, 0));
    assert!(feed_opt(&mut second, 11, b"x").is_none());
    assert!(feed_opt(&mut second, 12, b"x").is_none());
    assert_eq!(second.emitted_count(), 2);
    let t = feed_opt(&mut second, 13, b"x").expect("the unresolved exchange is emitted again");
    assert_eq!((t.position(), t.exchange().request), (2, 13));
    assert!(second.enqueue(t, b"{c}\n".to_vec(), 1).is_ok());
    let again = send(&mut second, 0);
    assert_eq!(again.body, r.body);
    assert_eq!(again.batch_id, r.batch_id);
    assert_eq!(again.batch_id.as_deref(), Some(&batch_id(&session, 2, 3, checksum(b"{c}\n"))[..]));
    assert_eq!(second.reply(0, ok_reply(202)), Outcome::Acknowledged(1));
    assert_eq!(second.progress(), (3, 0));
}

/// A fake server with the HypAware ledger and dedup semantics: a repeated
/// batch id is acknowledged without storing, and a repeated row is dropped.
#[derive(Default)]
struct Ledger { ids: std::collections::HashSet<Vec<u8>>, stored: Vec<Vec<u8>> }
impl Ledger {
    fn ingest(&mut self, request: &gateway_core::shipper::Request) -> Reply {
        assert_eq!(request.path, Path::Ingest);
        let id = request.batch_id.clone().unwrap();
        if self.ids.insert(id) {
            for row in request.body.split_inclusive(|b| *b == b'\n') {
                if !self.stored.iter().any(|r| r == row) { self.stored.push(row.to_vec()); }
            }
        }
        ok_reply(202)
    }
}

/// Run the shipper over `requests` exchanges against a ledger, dying after
/// `kill_at` machine steps (never, when `kill_at` is `None`) and restarting
/// from the checkpoint. Returns the stored rows and the number of steps.
fn run_with_crash(requests: u64, kill_at: Option<usize>, ledger: &mut Ledger) -> usize {
    let session = [8u8; 16];
    let records: Vec<(u8, u64, u64, Vec<u8>)> = (1..=requests).flat_map(|request| {
        let start = encode_request_start(1_000, 7, b"https://api.example/v1").unwrap();
        let body = format!("req-{request}").into_bytes();
        let done = encode_completion(2_000, 0, body.len() as u64, 0).unwrap();
        vec![(2, request, 0, start), (0, request, 1, body), (4, request, 0, done)]
    }).collect();
    let (mut checkpoint, mut steps, mut crashed) = ((0u64, 0u64), 0usize, false);
    loop {
        let mut m = Machine::new(b"t".to_vec(), session, 3, 1024, checkpoint.0, checkpoint.1);
        assert!(m.adopt_identity(b"jwt".to_vec(), 30 * DAY, 0));
        let mut next_record = 0usize;
        let mut finished = false;
        while !finished {
            if !crashed && kill_at == Some(steps) { crashed = true; break; }
            steps += 1;
            match m.next(0) {
                Action::Read => {
                    if next_record < records.len() {
                        let (kind, request, chunk, payload) = &records[next_record]; next_record += 1;
                        if let Some(t) = m.admit(header(*kind, *request, *chunk, payload), payload) {
                            let body = format!("{{\"r\":{}}}\n", t.exchange().request).into_bytes();
                            assert!(m.enqueue(t, body, 1).is_ok());
                        }
                    } else { m.end_of_log(); }
                }
                Action::Send(request) => {
                    let reply = ledger.ingest(&request);
                    if let Outcome::Acknowledged(_) = m.reply(0, reply) { checkpoint = m.progress(); }
                }
                Action::Idle => { finished = next_record == records.len() && m.queue_len() == 0; }
                other => panic!("unexpected {}", name(&other)),
            }
        }
        if finished { return steps; }
    }
}

#[test]
fn a_crash_at_any_step_resends_only_the_unacknowledged_exchanges_and_the_server_stores_each_once() {
    let mut reference = Ledger::default();
    let steps = run_with_crash(7, None, &mut reference);
    assert_eq!(reference.stored.len(), 7);
    for kill_at in 0..steps {
        let mut ledger = Ledger::default();
        run_with_crash(7, Some(kill_at), &mut ledger);
        assert_eq!(ledger.stored, reference.stored, "crash after step {kill_at}");
    }
}

#[test]
fn short_lived_enrollment_uploads_before_renewing_again() {
    for lifetime in [1, 3600, DAY] {
        for bootstrap in [true, false] {
            let mut m = Machine::new(b"token".to_vec(), [7; 16], 4, 1024, 0, 0);
            let token = feed(&mut m, 1, b"body");
            assert!(m.enqueue(token, b"{}\n".to_vec(), 1).is_ok());
            if !bootstrap { assert!(m.adopt_identity(b"old".to_vec(), 101, 100)); }
            let request = send(&mut m, 100);
            assert_eq!(request.path, if bootstrap { Path::Bootstrap } else { Path::Refresh });
            assert_eq!(m.reply(100, credential_reply(b"fresh", 100 + lifetime)), Outcome::Enrolled);
            let request = send(&mut m, 100 + lifetime - 1);
            assert_eq!(request.path, Path::Ingest, "a usable fresh token must not refresh forever");
            assert_eq!(m.reply(100 + lifetime - 1, ok_reply(202)), Outcome::Acknowledged(1));
            assert_eq!(m.progress(), (1, 0));
            // The next batch may renew proactively again, but must then upload.
            let token = feed(&mut m, 2, b"next");
            assert!(m.enqueue(token, b"{}\n".to_vec(), 1).is_ok());
            assert_eq!(send(&mut m, 100 + lifetime - 1).path, Path::Refresh);
        }
    }
}

#[test]
fn fresh_credentials_still_expire_and_rejected_uploads_still_refresh() {
    for status in [401, 0] {
        let mut m = Machine::new(b"token".to_vec(), [7; 16], 4, 1024, 0, 0);
        let token = feed(&mut m, 1, b"body");
        assert!(m.enqueue(token, b"{}\n".to_vec(), 1).is_ok());
        assert_eq!(send(&mut m, 100).path, Path::Bootstrap);
        m.reply(100, credential_reply(b"fresh", 101));
        if status == 401 {
            assert_eq!(send(&mut m, 100).path, Path::Ingest);
            m.reply(100, ok_reply(401));
            assert_eq!(send(&mut m, 100).path, Path::Refresh);
        } else {
            assert_eq!(send(&mut m, 101).path, Path::Refresh, "freshness never authorizes expired tokens");
        }
        assert_eq!(m.progress(), (0, 0));
    }
}

#[test]
fn progress_witness_drains_batches_with_advancing_time_and_one_second_tokens() {
    use gateway_core::shipping_progress::{drain_successful_suffix, ServiceWindow};
    let mut m = Machine::new(b"token".to_vec(), [7; 16], 4, 1024, 0, 0);
    for request in 1..=3 {
        let token = feed(&mut m, request, b"body");
        // Each projection consumes a batch's row allowance, forcing three rounds.
        assert!(m.enqueue(token, b"{}\n".to_vec(), MAX_ROWS).is_ok());
    }
    let service = vec![
        ServiceWindow { now: 100, upload_at: 100, expires_at: 101, status: 200 },
        ServiceWindow { now: 200, upload_at: 200, expires_at: 201, status: 202 },
        ServiceWindow { now: 300, upload_at: 300, expires_at: 301, status: 200 },
    ];
    drain_successful_suffix(&mut m, &service);
    assert_eq!(m.queue_len(), 0);
    assert_eq!(m.progress(), (3, 0));
}
