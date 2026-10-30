//! Executable checks of the exchange driver against a scripted `Effects`.
//! The proofs cover every trace the driver can take; these pin the concrete
//! sequence of effects and bytes on the paths an operator sees.
use crate::framed_copy::{Framed, Downloaded};
use crate::request_context::TransferKey;
use crate::exchange_driver::*;
use crate::exchange_lifecycle::Fault;
use crate::headers::Field;
use crate::http1_exchange::Refusal;
use crate::http1_framing::Framing;
use crate::http1_head::{RequestHead, StatusHead};
use crate::owned_stream::OwnedStream;
use crate::policy::Route;
use crate::resource::ResourceAdmission;

fn field(name: &str, value: &str) -> Field { Field { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec(), sensitive: false } }
fn post() -> RequestHead {
    RequestHead { method: b"POST".to_vec(), target: b"/routes/7".to_vec(), fields: vec![field("host", "h"), field("content-length", "5"), field("authorization", "Bearer token")] }
}

fn configured() -> crate::request_context::ProviderConfig {
        use crate::config_schema::{Root, IdentityInput, CredentialInput, CredentialKind, Limits, Logging};
        struct Secret;
        impl crate::config_build::Secrets for Secret {
            fn get(&mut self, _: &[u8]) -> Option<Vec<u8>> { Some(b"k".to_vec()) }
        }
        let digest = crate::sha256::digest(b"token");
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let config = crate::request_context::ProviderConfig::load(Root {
            identities: vec![IdentityInput { tenant: 1, sha256: hex.into_bytes() }],
            destinations: vec![b"https://api.example/v1/messages".to_vec()],
            credentials: vec![CredentialInput { tenant: 1, kind: CredentialKind::ApiKey, env: b"KEY".to_vec() }],
            grants: vec![Route { tenant: 1, selector: 7, origin: 0, credential: 0 }],
            limits: Limits { requests: 1, chunk_bytes: 4096 }, logging: Logging::Strict,
            durability: crate::audit_receipt::Durability::Durable,
        }, &mut Secret).ok().unwrap();
    config
}

/// A real completed copy: the same verified driver that production uses reads,
/// audits and writes the bytes whose framing this fake records.
fn finished_copy(key: &TransferKey, direction: u8, input: &[u8], stream: Option<crate::http1_exchange::ChunkStream>, output: &mut Vec<u8>, foreign: bool) -> Downloaded {
    finished_copy_with_limit(key, direction, input, stream, output, foreign, usize::MAX)
}
fn finished_copy_with_limit(key: &TransferKey, direction: u8, input: &[u8], stream: Option<crate::http1_exchange::ChunkStream>, output: &mut Vec<u8>, foreign: bool, limit: usize) -> Downloaded {
    struct Primitive<'a> { input: &'a [u8] }
    impl crate::body_driver::Effects for Primitive<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> Option<usize> {
            let n = buffer.len().min(self.input.len());
            buffer[..n].copy_from_slice(&self.input[..n]); self.input = &self.input[n..]; Some(n)
        }
        fn session(&self) -> u128 { 0 }
        fn audit(&mut self, header: crate::framing::Header, bytes: &[u8]) -> Option<crate::audit_receipt::AuditReceipt> {
            let frame = crate::framing::RecordBody::new(header, bytes)?.seal(&[0; 32]);
            let mut journal = crate::journal::Journal::new(0);
            let ticket = journal.begin(frame.bytes().len() as u64)?;
            Some(journal.commit_frame(&ticket, frame)?.into_receipt())
        }
        fn write(&mut self, _: &crate::request_context::Context<'_>, delivery: &crate::body_copy::Delivery<'_>, _: u8) -> Option<usize> {
            let bytes = delivery.bytes();
            Some(bytes.len())
        }
        fn flush(&mut self) -> bool { true }
    }
    let config = configured();
    let mut registry = ResourceAdmission::new(2, 4096);
    let _held = if foreign { registry.acquire() } else { None };
    let lease = registry.acquire().unwrap();
    let context = config.authorize(&crate::sha256::digest(b"token"), 7, lease.owner()).unwrap();
    let mut owner = OwnedStream::claim(&registry, lease, context.authority(), true).ok().unwrap();
    let own_key = context.transfer_key();
    let key = if foreign { &own_key } else { key };
    struct Socket<'a>(&'a mut Vec<u8>, usize);
    impl crate::sink::Sink for Socket<'_> {
        fn put(&mut self, bytes: &[u8]) -> crate::sink::Put {
            if self.0.len() >= self.1 { return crate::sink::Put::Failed; }
            let n = bytes.len().min(2).min(self.1 - self.0.len());
            self.0.extend_from_slice(&bytes[..n]); crate::sink::Put::Wrote(n)
        }
    }
    impl crate::sink::FlushSink for Socket<'_> { fn flush(&mut self) -> bool { true } }
    match stream {
        Some(stream) => Downloaded::Stream(crate::framed_copy::copy(&context, key, &mut owner, &mut crate::journal_binding::JournalBinding::new(),
            Primitive { input }, Socket(output, limit), stream, direction).0),
        None => Downloaded::Fixed(Ok(crate::body_driver::copy(&context, key, &mut owner, &mut crate::journal_binding::JournalBinding::new(),
            &mut Primitive { input }, direction).ok().unwrap())),
    }
}

/// What the scripted runtime should answer.
struct Script {
    head: HeadKind, endpoint: Option<(u16, Vec<u8>)>, worker: bool, admit: Option<Refusal>, strict: bool, log_healthy: bool,
    start_ok: bool, connect: Option<ConnectFailure>, statuses: Vec<StatusHead>, response_logged: bool, download_ok: bool, completion_ok: bool, foreign_upload: bool, swapped_download: bool,
}
#[derive(Clone, Copy)]
enum HeadKind { Post, Get(&'static str), TooLarge, Malformed, Closed, Continue }
impl Default for Script {
    fn default() -> Self {
        Self { head: HeadKind::Post, endpoint: None, worker: true, admit: None, strict: true, log_healthy: true, start_ok: true, connect: None,
            statuses: vec![StatusHead { status: 200, fields: vec![field("content-type", "text/plain"), field("transfer-encoding", "chunked")] }],
            response_logged: true, download_ok: true, completion_ok: true, foreign_upload: false, swapped_download: false }
    }
}

/// The scripted runtime: records every effect in order.
struct Fake { script: Script, calls: Vec<String>, client: Vec<u8>, upstream: Vec<u8>, closed: usize, counts: (u64, u64) }
impl Fake {
    fn new(script: Script) -> Self { Self { script, calls: Vec::new(), client: Vec::new(), upstream: Vec::new(), closed: 0, counts: (0, 0) } }
    fn note(&mut self, call: &str) { self.calls.push(call.to_owned()); }
}
impl Effects for Fake {
    fn read_head(&mut self) -> HeadRead {
        self.note("read_head");
        match self.script.head {
            HeadKind::Post => HeadRead::Head(post()),
            HeadKind::Continue => { let mut head = post(); head.fields.push(field("expect", "100-continue")); HeadRead::Head(head) }
            HeadKind::Get(target) => HeadRead::Head(RequestHead { method: b"GET".to_vec(), target: target.as_bytes().to_vec(), fields: vec![field("host", "h")] }),
            HeadKind::TooLarge => HeadRead::TooLarge,
            HeadKind::Malformed => HeadRead::Malformed,
            HeadKind::Closed => HeadRead::Closed,
        }
    }
    fn write_client(&mut self, bytes: &Vec<u8>, _scope: WriteScope) -> bool { self.note("write_client"); self.client.extend_from_slice(bytes); true }
    fn close_client(&mut self) { self.note("close_client"); self.closed += 1; }
    fn endpoint(&mut self, _target: &Vec<u8>) -> Option<FixedResponse> {
        self.note("endpoint");
        self.script.endpoint.clone().map(|(status, body)| FixedResponse { status, fields: Vec::new(), body })
    }
    fn acquire_worker(&mut self) -> bool { self.note("acquire_worker"); self.script.worker }
    fn admit(&mut self, _head: &RequestHead) -> Admit {
        self.note("admit");
        match self.script.admit { Some(refusal) => Admit::Refused(refusal), None => Admit::Admitted }
    }
    fn strict(&mut self) -> bool { self.note("strict"); self.script.strict }
    fn log_healthy(&mut self) -> bool { self.note("log_healthy"); self.script.log_healthy }
    fn now_ms(&mut self) -> u64 { 1_700_000_000_000 }
    fn audit_request_start(&mut self) -> bool { self.note("audit_request_start"); self.script.start_ok }
    fn bind_input(&mut self, framing: Framing) -> bool { self.note(&format!("bind_input {framing:?}")); true }
    fn upstream_head(&mut self, input: &RequestHead) -> Option<crate::request_context::ProviderHead> {
        self.note("upstream_head");
        let config = configured();
        let digest = crate::sha256::digest(b"token");
        let context = config.authorize(&digest, 7, 1)?;
        let checked = crate::request_context::CheckedHead::parse(input).ok()?;
        context.prepare(&checked).ok()
    }
    fn connect(&mut self) -> Result<(), ConnectFailure> {
        self.note("connect");
        match self.script.connect { Some(failure) => Err(failure), None => Ok(()) }
    }
    fn write_upstream(&mut self, bytes: &Vec<u8>) -> bool { self.note("write_upstream"); self.upstream.extend_from_slice(bytes); true }
    fn upload(&mut self, key: &TransferKey, stream: crate::http1_exchange::ChunkStream) -> Framed {
        self.note("upload");
        match finished_copy(key, 0, b"hello", Some(stream), &mut self.upstream, self.script.foreign_upload) {
            Downloaded::Stream(f) => f, _ => unreachable!(),
        }
    }
    fn read_status_head(&mut self) -> Result<StatusHead, Failure> {
        self.note("read_status_head");
        if self.script.statuses.is_empty() { return Err(Failure::Io); }
        Ok(self.script.statuses.remove(0))
    }
    fn audit_response_head(&mut self, status: u16) -> bool { self.note(&format!("audit_response_head {status}")); self.script.response_logged }
    fn download(&mut self, key: &TransferKey, framing: Framing, body: Body) -> Downloaded {
        self.note(&format!("download {framing:?}"));
        let copied = match body {
            Body::Stream(stream) => finished_copy(key, if self.script.swapped_download { 0 } else { 1 }, b"data: hi\n\n", Some(stream), &mut self.client, false),
            Body::Fixed => finished_copy(key, 1, b"", None, &mut self.client, false),
        };
        if self.script.download_ok { copied } else {
            match copied { Downloaded::Stream(mut f) => { f.reject(Failure::Io); Downloaded::Stream(f) }, _ => Downloaded::Fixed(Err(Failure::Io)) }
        }
    }
    fn audit_completion(&mut self, payload: &Vec<u8>) -> bool {
        self.note("audit_completion");
        let (_, outcome, upload, download) = crate::metadata::decode_completion(payload).map(|c| (c.time_ms, c.outcome, c.upload_bytes, c.download_bytes)).unwrap();
        self.counts = (upload, download);
        self.calls.push(format!("outcome {outcome}"));
        self.script.completion_ok
    }
    fn observe(&mut self, event: Event) { self.note(&format!("{event:?}")); }
}

fn run(script: Script) -> (Fake, bool) {
    let mut fake = Fake::new(script);
    let driven = drive(&mut fake);
    let recorded = driven.closed.was_recorded();
    (fake, recorded)
}
fn client_text(fake: &Fake) -> String { String::from_utf8_lossy(&fake.client).into_owned() }

#[test]
fn a_streamed_exchange_takes_the_audited_order_and_ends_with_the_last_chunk() {
    let (fake, recorded) = run(Script::default());
    assert!(recorded);
    assert_eq!(fake.counts, (5, 10));
    let expected = ["read_head", "acquire_worker", "admit", "strict", "log_healthy", "audit_request_start", "bind_input Length(5)", "upstream_head",
        "connect", "write_upstream", "upload", "write_upstream", "read_status_head", "audit_response_head 200", "write_client",
        "download Chunked", "write_client", "close_client", "log_healthy", "audit_completion", "outcome 0"];
    assert_eq!(fake.calls, expected, "{:?}", fake.calls);
    let text = client_text(&fake);
    assert!(text.starts_with("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n"), "{text}");
    assert!(text.ends_with("a\r\ndata: hi\n\n\r\n0\r\n\r\n"), "{text}");
    let upstream = String::from_utf8_lossy(&fake.upstream);
    assert!(upstream.starts_with("POST /v1/messages HTTP/1.1\r\nhost: api.example\r\nx-api-key: k\r\naccept-encoding: identity\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"), "{upstream}");
    assert!(upstream.ends_with("5\r\nhello\r\n0\r\n\r\n"), "{upstream}");
}

#[test]
fn a_bodiless_status_is_complete_at_its_head() {
    for (status, reason) in [(204, "No Content"), (304, "Not Modified")] {
        let script = Script { statuses: vec![StatusHead { status, fields: vec![field("content-type", "text/plain"), field("set-cookie", "s"), field("content-length", "123")] }], ..Script::default() };
        let (fake, recorded) = run(script);
        assert!(recorded);
        assert_eq!(client_text(&fake), format!("HTTP/1.1 {status} {reason}\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\n"));
        assert!(fake.calls.contains(&"download Length(0)".to_owned()));
        assert!(fake.calls.iter().filter(|c| *c == "write_client").count() == 1);
    }
}

#[test]
fn interim_statuses_are_skipped_and_the_continue_is_sent_once() {
    let script = Script { head: HeadKind::Continue,
        statuses: vec![StatusHead { status: 100, fields: vec![] }, StatusHead { status: 103, fields: vec![field("link", "x")] },
            StatusHead { status: 200, fields: vec![field("content-length", "0")] }], ..Script::default() };
    let (fake, recorded) = run(script);
    assert!(recorded);
    let text = client_text(&fake);
    assert!(text.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n"), "{text}");
    assert_eq!(fake.calls.iter().filter(|c| *c == "read_status_head").count(), 3);
}

#[test]
fn interim_heads_beyond_the_cap_are_an_upstream_failure() {
    use crate::exchange_driver::MAX_INTERIM_HEADS;
    let cap = MAX_INTERIM_HEADS as usize;
    let interim = || StatusHead { status: 103, fields: vec![] };
    // Exactly the cap is tolerated.
    let mut statuses: Vec<StatusHead> = (0..cap).map(|_| interim()).collect();
    statuses.push(StatusHead { status: 200, fields: vec![field("content-length", "0")] });
    let (fake, recorded) = run(Script { statuses, ..Script::default() });
    assert!(recorded);
    assert!(client_text(&fake).starts_with("HTTP/1.1 200 OK\r\n"), "{}", client_text(&fake));
    assert_eq!(fake.calls.iter().filter(|c| *c == "read_status_head").count(), cap + 1);
    // One more is refused as an HTTP fault without reading further.
    let statuses: Vec<StatusHead> = (0..cap + 4).map(|_| interim()).collect();
    let (fake, recorded) = run(Script { statuses, ..Script::default() });
    assert!(recorded);
    assert!(client_text(&fake).starts_with("HTTP/1.1 502 "), "{}", client_text(&fake));
    assert!(fake.calls.contains(&format!("{:?}", Event::Failed(Fault::Http))));
    assert_eq!(fake.calls.iter().filter(|c| *c == "read_status_head").count(), cap + 1);
}

#[test]
fn refusals_before_admission_write_the_table_status_and_no_record() {
    for (script, status) in [
        (Script { head: HeadKind::TooLarge, ..Script::default() }, 431),
        (Script { head: HeadKind::Malformed, ..Script::default() }, 400),
        (Script { worker: false, ..Script::default() }, 503),
        (Script { admit: Some(Refusal::Unauthorized), ..Script::default() }, 401),
        (Script { admit: Some(Refusal::MethodNotAllowed), ..Script::default() }, 405),
    ] {
        let (fake, recorded) = run(script);
        assert!(!recorded);
        assert!(client_text(&fake).starts_with(&format!("HTTP/1.1 {status} ")), "{}", client_text(&fake));
        assert!(!fake.calls.iter().any(|c| c.starts_with("audit") || c == "connect"), "{:?}", fake.calls);
        assert_eq!(fake.closed, 1);
    }
    let (fake, recorded) = run(Script { head: HeadKind::Closed, ..Script::default() });
    assert!(!recorded && fake.client.is_empty());
}

#[test]
fn operator_endpoints_answer_without_a_worker() {
    let (fake, recorded) = run(Script { head: HeadKind::Get("/healthz"), endpoint: Some((200, b"ok\n".to_vec())), ..Script::default() });
    assert!(!recorded);
    assert_eq!(client_text(&fake), "HTTP/1.1 200 OK\r\nconnection: close\r\ncontent-length: 3\r\n\r\nok\n");
    assert!(!fake.calls.contains(&"acquire_worker".to_owned()));
}

#[test]
fn strict_mode_refuses_without_a_record_and_still_writes_the_completion() {
    let (fake, recorded) = run(Script { log_healthy: false, ..Script::default() });
    assert!(!recorded, "the completion is skipped while the logger is unhealthy");
    assert!(client_text(&fake).starts_with("HTTP/1.1 503 "));
    assert!(!fake.calls.contains(&"connect".to_owned()));
    let (fake, recorded) = run(Script { start_ok: false, ..Script::default() });
    assert!(recorded);
    assert!(client_text(&fake).starts_with("HTTP/1.1 503 "));
    assert!(!fake.calls.contains(&"connect".to_owned()));
    assert!(fake.calls.contains(&format!("outcome {}", crate::metadata::OUTCOME_LOG_REFUSAL)));
}

#[test]
fn availability_mode_forwards_past_failed_records() {
    let (fake, recorded) = run(Script { strict: false, start_ok: false, response_logged: false, ..Script::default() });
    assert!(recorded);
    assert!(fake.calls.contains(&"connect".to_owned()));
    assert!(client_text(&fake).starts_with("HTTP/1.1 200 OK"));
    assert!(fake.calls.contains(&"outcome 0".to_owned()));
}

#[test]
fn strict_mode_stops_before_the_head_when_its_record_fails() {
    let (fake, recorded) = run(Script { response_logged: false, ..Script::default() });
    assert!(recorded);
    assert!(client_text(&fake).starts_with("HTTP/1.1 502 "), "{}", client_text(&fake));
    assert!(fake.calls.contains(&format!("{:?}", Event::Failed(Fault::Log))));
    assert!(fake.calls.contains(&format!("outcome {}", crate::metadata::OUTCOME_LOG_REFUSAL)));
}

#[test]
fn connect_failures_answer_the_fault_table() {
    for (failure, status, outcome) in [
        (ConnectFailure::Resolve, 502, crate::metadata::OUTCOME_UPSTREAM_FAILURE),
        (ConnectFailure::Tls, 502, crate::metadata::OUTCOME_UPSTREAM_FAILURE),
        (ConnectFailure::Timeout, 504, crate::metadata::OUTCOME_UPSTREAM_TIMEOUT),
        (ConnectFailure::Cancelled, 502, crate::metadata::OUTCOME_CLIENT_DISCONNECT),
    ] {
        let (fake, recorded) = run(Script { connect: Some(failure), ..Script::default() });
        assert!(recorded);
        assert!(client_text(&fake).starts_with(&format!("HTTP/1.1 {status} ")), "{failure:?}: {}", client_text(&fake));
        assert!(fake.calls.contains(&format!("outcome {outcome}")), "{:?}", fake.calls);
        assert!(!fake.calls.contains(&"write_upstream".to_owned()));
    }
}

#[test]
fn a_failed_download_truncates_the_stream_without_a_last_chunk() {
    let (fake, recorded) = run(Script { download_ok: false, ..Script::default() });
    assert!(recorded);
    let text = client_text(&fake);
    assert!(text.starts_with("HTTP/1.1 200 OK"));
    assert!(text.ends_with("a\r\ndata: hi\n\n\r\n"), "no last chunk after a truncated body: {text}");
    assert!(fake.calls.contains(&format!("{:?}", Event::Failed(Fault::Download))));
    assert!(fake.calls.contains(&format!("outcome {}", crate::metadata::OUTCOME_DOWNLOAD_FAILURE)));
    assert_eq!(fake.calls.iter().filter(|c| *c == "write_client").count(), 1, "only the head came from the driver");
}

#[test]
fn an_upstream_refusal_is_a_metadata_fault() {
    let (fake, recorded) = run(Script { statuses: vec![StatusHead { status: 101, fields: vec![] }], ..Script::default() });
    assert!(recorded);
    assert!(client_text(&fake).starts_with("HTTP/1.1 502 "));
    assert!(fake.calls.contains(&format!("outcome {}", crate::metadata::OUTCOME_OTHER)));
}

#[test]
fn foreign_upload_and_swapped_download_cannot_report_success() {
    let (foreign, _) = run(Script { foreign_upload: true, ..Script::default() });
    assert!(foreign.calls.contains(&format!("outcome {}", crate::metadata::OUTCOME_UPLOAD_FAILURE)));
    assert!(!foreign.calls.contains(&"read_status_head".to_owned()));
    assert_eq!(foreign.counts, (0, 0));
    assert!(!foreign.upstream.ends_with(b"0\r\n\r\n"));
    let (swapped, _) = run(Script { swapped_download: true, ..Script::default() });
    assert!(swapped.calls.contains(&format!("outcome {}", crate::metadata::OUTCOME_DOWNLOAD_FAILURE)));
    assert_eq!(swapped.counts, (0, 0));
    assert!(!swapped.client.ends_with(b"0\r\n\r\n"));
}

#[test]
fn sealed_framed_copy_handles_every_wire_failure_offset() {
    let config = configured();
    let context = config.authorize(&crate::sha256::digest(b"token"), 7, 1).unwrap();
    let key = context.transfer_key();
    let expected = b"5\r\nhello\r\n";
    for limit in 0..=expected.len() {
        let mut wire = Vec::new();
        let Downloaded::Stream(framed) = finished_copy_with_limit(&key, 0, b"hello", Some(crate::http1_exchange::ChunkStream::new()), &mut wire, false, limit) else { panic!("expected framed result") };
        assert_eq!(wire, expected[..limit]);
        assert_eq!(framed.body_failure().is_none(), limit == expected.len());
        let (copy, stream) = framed.into_parts();
        assert!(!stream.is_ended(), "only the connection driver writes the terminal chunk");
        match copy {
            Ok(copy) => assert_eq!(copy.accepted_bytes(), 5),
            Err(failure) => assert_eq!(failure, Failure::Io),
        }
    }
}
