//! Verified driver for one inbound connection, from the request head to the
//! completion record. The runtime supplies an `Effects` implementation with
//! explicit adapter obligations: it reads a head, moves bytes, opens the provider
//! connection, runs the two body copies, and appends records. This driver is
//! what sequences those effects and what calls the verified machines, so the
//! order the audit contract promises is checked here rather than promised by
//! the runtime: the request-start record precedes any network effect, the
//! response-head record precedes the head reaching the client, every byte
//! handed to the client is the connection machine's output in order, and an
//! admitted exchange ends with exactly one completion record or one explicit
//! skip while the logger is unhealthy. The effects themselves stay trusted.
//!
//! The driver trace is bound to the effect-call history, erasing only internal
//! forwarding/skip milestones. `run` specifies allowed traces; its ordering
//! lemmas therefore apply to the calls made by `drive`, not a declared history.
use vstd::prelude::*;
use crate::body_driver::{Completed, CopySummary};
use crate::framed_copy::{Framed, Downloaded};
use crate::exchange_lifecycle::{Closed, Fault, Lifecycle};
use crate::headers::Field;
use crate::request_context::{ProviderHead, Evidence, TransferKey, TransferIdentity};
use crate::http1_exchange::{ChunkStream, Connection, Refusal, Upstream, UpstreamStatus, failure_status, refusal_status, upstream_status, wants_continue};
use crate::http1_framing::{Framing, framing};
use crate::http1_head::{RequestHead, StatusHead};

verus! {
/// What reading the request head produced.
pub enum HeadRead { Head(RequestHead), TooLarge, Malformed, Closed }
pub open spec fn read_input(read: HeadRead) -> Option<RequestHead> { match read { HeadRead::Head(head) => Some(head), _ => None } }
/// Whether the request was admitted to a route.
pub enum Admit { Admitted, Refused(Refusal) }
/// An operator endpoint's answer.
pub struct FixedResponse { pub status: u16, pub fields: Vec<Field>, pub body: Vec<u8> }
/// Why an effect failed, as the runtime saw it; the driver names the fault.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Failure { Cancelled, Timeout, Log, Io }
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum ConnectFailure { Resolve, Tcp, Tls, Timeout, Cancelled }
/// Where a response body goes: nowhere (a fixed head said so) or a chunk stream.
pub enum Body { Fixed, Stream(ChunkStream) }
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Event { Failed(Fault) }
/// Failure replies use the connection budget so a timed-out exchange can
/// still report 504; forwarded response bytes use the exchange budget.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum WriteScope { Control, Exchange }

/// A supported provider request, independent of whether the driver elects to handle it.
pub open spec fn supported_request(head: RequestHead) -> bool {
    head.method@ == crate::http1_exchange::post()
        && !crate::http1_framing::framing_spec_refused(head.fields@)
}
/// A final provider response that can be forwarded within the configured wire limits.
/// All admitted status codes, fields and reasons are quantified, not enumerated fixtures.
pub open spec fn supported_response(head: StatusHead) -> bool {
    200 <= head.status <= 599 && !crate::http1_framing::framing_spec_refused(head.fields@)
        && crate::headers::within_limits(head.fields@)
        && !crate::headers::bad_connection_element(head.fields@)
        && !crate::headers::nominated(head.fields@, crate::headers::CONTENT_ENCODING@)
        && forall|fields: Seq<Field>, reason: Seq<u8>| #[trigger] crate::headers::response_head_ok(head.fields@, fields)
            && #[trigger] crate::http1_write::reason_ok(reason) && reason.len() <= 32 ==>
            if head.status == 204 || head.status == 304 {
                crate::http1_exchange::fixed_supported(head.status, reason, fields, 0)
            } else { crate::http1_exchange::stream_supported(head.status, reason, fields) }
}

proof fn supported_response_fits(head: StatusHead, fields: Seq<Field>, reason: Seq<u8>)
    requires supported_response(head), crate::headers::response_head_ok(head.fields@, fields),
        crate::http1_write::reason_ok(reason), reason.len() <= 32,
    ensures if head.status == 204 || head.status == 304 {
        crate::http1_exchange::fixed_supported(head.status, reason, fields, 0)
    } else { crate::http1_exchange::stream_supported(head.status, reason, fields) },
{}

/// An actual completion append encodes the reported result and transfer counts;
/// the only alternative is an observed unhealthy logger and no recorded completion.
pub open spec fn completed_as(events: Seq<Step>, result: (u8, u64, u64), recorded: bool) -> bool {
    events.len() > 0 && match events.last() {
        Step::Completion(payload, ok) => {
            let decoded = crate::metadata::decoded_completion(payload);
            ok == recorded && decoded.is_some() && (decoded.unwrap().1, decoded.unwrap().2, decoded.unwrap().3) == result
        },
        Step::LogHealthy(false) => !recorded,
        _ => false,
    }
}

/// Number of interim heads observed since the actual request-head read.
/// This derives from effect history; it cannot be set by the driver.
pub open spec fn interim_heads(events: Seq<Step>) -> nat
    decreases events.len(),
{
    if events.len() == 0 { 0 } else { match events.last() {
        Step::ReadHead(_) => 0,
        Step::Status(status) => interim_heads(events.drop_last()) + (if status < 200 && status != 101 { 1nat } else { 0nat }),
        _ => interim_heads(events.drop_last()),
    } }
}
pub open spec fn supported_status(head: StatusHead, prior: Seq<Step>) -> bool {
    supported_response(head) || (100 <= head.status < 200 && head.status != 101 && interim_heads(prior) < MAX_INTERIM_HEADS)
}

/// The actual latest inbound head, including failed reads. This is derived
/// from observed calls, never supplied as an independent ghost history.
#[verifier::opaque]
pub open spec fn received_input(events: Seq<Step>) -> Option<RequestHead>
    decreases events.len(),
{
    if events.len() == 0 { None } else { match events.last() {
        Step::ReadHead(input) => input, _ => received_input(events.drop_last()),
    } }
}

#[verifier::opaque]
pub open spec fn prepared_identity(events: Seq<Step>) -> Option<TransferIdentity>
    decreases events.len(),
{
    if events.len() == 0 { None } else { match events.last() {
        Step::Prepared(_, _, evidence) => Some(evidence.transfer_identity()), _ => prepared_identity(events.drop_last()),
    } }
}
pub open spec fn copy_summary(out: Result<Completed, Failure>) -> Option<CopySummary> {
    match out { Ok(copy) => Some(copy.summary()), Err(_) => None }
}

/// What the runtime does for the driver. Every method is trusted to perform
/// exactly the effect named and report what happened. Physical source/socket
/// selection and admission-registry association remain adapter obligations.
pub trait Effects {
    /// Observable effect attempts. Runtime adapters must faithfully implement this boundary.
    spec fn events(&self) -> Seq<Step>;
    /// Count only witnessed failed operations or unsupported inputs. A driver cannot
    /// invent a failure to excuse doing nothing: every update is specified below.
    spec fn obstacles(&self) -> nat;
    /// Counts returned by the actual upload/download body-copy machines.
    spec fn transferred(&self) -> (u64, u64);
    fn read_head(&mut self) -> (out: HeadRead)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if match out { HeadRead::Head(head) => supported_request(head), _ => false } { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::ReadHead(read_input(out)));
    fn write_client(&mut self, bytes: &Vec<u8>, scope: WriteScope) -> (out: bool)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::Client(bytes@, scope));
    fn close_client(&mut self)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles(),
            final(self).events() == old(self).events();
    fn endpoint(&mut self, target: &Vec<u8>) -> (out: Option<FixedResponse>)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles(),
            final(self).events() == old(self).events();
    fn acquire_worker(&mut self) -> (out: bool)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::Worker(out));
    fn admit(&mut self, head: &RequestHead) -> (out: Admit)
        requires received_input(self.events()) == Some(*head),
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out is Admitted { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::Admit(out is Admitted));
    fn strict(&mut self) -> (out: bool)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles(),
            final(self).events() == old(self).events().push(Step::Strict(out));
    fn log_healthy(&mut self) -> (out: bool)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::LogHealthy(out));
    fn now_ms(&mut self) -> u64
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles(),
            final(self).events() == old(self).events();
    fn audit_request_start(&mut self) -> (out: bool)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::RequestStart(out));
    fn bind_input(&mut self, framing: Framing) -> (out: bool)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out { 0nat } else { 1nat }),
            final(self).events() == old(self).events();
    /// The adapter prepares this input with its admitted core Context. It cannot
    /// construct ProviderHead itself; Context::prepare establishes this contract.
    fn upstream_head(&mut self, input: &RequestHead) -> (out: Option<ProviderHead>)
        requires received_input(self.events()) == Some(*input),
        ensures final(self).transferred() == old(self).transferred(),
            out.is_some() ==> out.unwrap().valid() && out.unwrap().input() == *input,
            final(self).obstacles() == old(self).obstacles() + (if match out { Some(head) => crate::http1_exchange::request_supported(head.path(), head.fields()), None => false } { 0nat } else { 1nat }),
            final(self).events() == match out {
                Some(head) => old(self).events().push(Step::Prepared(head.path(), head.fields(), head.evidence())), None => old(self).events() };
    fn connect(&mut self) -> (out: Result<(), ConnectFailure>)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out.is_ok() { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::Connect(out.is_ok()));
    fn write_upstream(&mut self, bytes: &Vec<u8>) -> (out: bool)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::UpstreamWrite(bytes@));
    fn upload(&mut self, key: &TransferKey, stream: ChunkStream) -> (out: Framed)
        requires prepared_identity(self.events()) == Some(key.identity()), stream.valid(), !stream.ended(), stream.out().len() == 0, stream.body().len() == 0,
        ensures out.valid(), final(self).transferred() == (match out.result() { Ok(copy) => (copy.accepted(), old(self).transferred().1), Err(_) => old(self).transferred() }),
            final(self).obstacles() == old(self).obstacles() + (if match out.result() { Ok(copy) => copy.is_done() && copy.summary().matches(key.identity(), 0), Err(_) => false } { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::Uploaded(out.sent(), out.summary()));
    fn read_status_head(&mut self) -> (out: Result<StatusHead, Failure>)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if match out { Ok(head) => supported_status(head, old(self).events()), Err(_) => false } { 0nat } else { 1nat }),
            final(self).events() == match out {
            Ok(head) => old(self).events().push(Step::Status(head.status)), Err(_) => old(self).events() };
    fn audit_response_head(&mut self, status: u16) -> (out: bool)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::ResponseHead(status, out));
    fn download(&mut self, key: &TransferKey, framing: Framing, body: Body) -> (out: Downloaded)
        requires prepared_identity(self.events()) == Some(key.identity()),
            match body { Body::Fixed => true, Body::Stream(s) => s.valid() && !s.ended() && s.out().len() == 0 && s.body().len() == 0 },
        ensures out.valid(), final(self).transferred() == (match out.result() { Ok(copy) => (old(self).transferred().0, copy.accepted()), Err(_) => old(self).transferred() }),
            final(self).obstacles() == old(self).obstacles() + (if (match out.result() { Ok(copy) => copy.is_done() && copy.summary().matches(key.identity(), 1), Err(_) => false })
                && out.streamed() == (body is Stream)
                && (!out.streamed() ==> out.result().unwrap().accepted() == 0) { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::Streamed(out.sent(), out.summary()));
    fn audit_completion(&mut self, payload: &Vec<u8>) -> (out: bool)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles() + (if out { 0nat } else { 1nat }),
            final(self).events() == old(self).events().push(Step::Completion(payload@, out));
    fn observe(&mut self, event: Event)
        ensures final(self).transferred() == (old(self).transferred()),
            final(self).obstacles() == old(self).obstacles(),
            final(self).events() == old(self).events();
}

// ---- the allowed traces ------------------------------------------------------

/// One step the driver took, as the trace records it.
pub ghost enum Step {
    ReadHead(Option<RequestHead>),
    Prepared(Seq<u8>, Seq<Field>, Evidence), Status(u16), Uploaded(Seq<u8>, Option<CopySummary>),
    /// Bytes the driver handed to the client.
    Client(Seq<u8>, WriteScope),
    /// Bytes the download effect handed to the client: a chunk stream's frames.
    Streamed(Seq<u8>, Option<CopySummary>),
    Worker(bool), Admit(bool), Strict(bool), RequestStart(bool), Connect(bool),
    UpstreamWrite(Seq<u8>),
    /// The response-head record for this status, and whether it was appended.
    ResponseHead(u16, bool),
    /// The upstream head with this status handed to the client.
    Forward(u16),
    LogHealthy(bool),
    /// The completion record, and whether it was appended.
    Completion(Seq<u8>, bool),
    /// The completion record skipped because the logger was unhealthy.
    CompletionSkipped,
}

/// What the trace so far has established.
pub ghost struct Progress {
    pub read: bool, pub incoming: Option<RequestHead>,
    pub upload: Option<CopySummary>, pub download: Option<CopySummary>,
    pub upload_wire: Seq<u8>, pub download_wire: Seq<u8>,
    pub prepared: Option<(Seq<u8>, Seq<Field>, Evidence)>, pub upstream_head_written: bool, pub last_status: Option<u16>,
    pub worker: bool, pub admitted: bool, pub strict: Option<bool>, pub started: Option<bool>, pub connected: bool,
    pub response_logged: Option<(u16, bool)>, pub forwarded: bool, pub log_healthy: Option<bool>, pub completion: Option<bool>,
}
pub open spec fn initial() -> Progress {
    Progress { upload_wire: Seq::empty(), download_wire: Seq::empty(), read: false, incoming: None, upload: None, download: None, prepared: None, upstream_head_written: false, last_status: None, worker: false, admitted: false, strict: None, started: None, connected: false,
        response_logged: None, forwarded: false, log_healthy: None, completion: None }
}
/// Network effects may follow the request-start record: appended, or refused
/// in availability mode.
pub open spec fn record_allows_dispatch(p: Progress) -> bool {
    p.started == Some(true) || (p.started == Some(false) && p.strict == Some(false))
}
/// The head may reach the client after its record: appended, or refused in
/// availability mode.
pub open spec fn record_allows_forward(p: Progress, status: u16) -> bool {
    p.response_logged == Some((status, true)) || (p.response_logged == Some((status, false)) && p.strict == Some(false))
}
/// The prepared head plus precisely the two gateway framing fields.
pub open spec fn provider_head(bytes: Seq<u8>, path: Seq<u8>, given: Seq<Field>) -> bool {
    exists|all: Seq<Field>| all.len() == given.len() + 2 && all.take(given.len() as int) == given
        && crate::http1_exchange::is_chunked(all[all.len() - 2]) && crate::http1_exchange::is_close(all.last())
        && bytes == crate::http1_write::request_head_bytes(crate::http1_exchange::post(), path, all)
}
/// Only internal proof milestones are erased; every observed effect remains.
pub open spec fn observed_after(events: Seq<Step>, s: Step) -> Seq<Step> {
    match s { Step::Forward(_) | Step::CompletionSkipped => events, _ => events.push(s) }
}
pub open spec fn visible(s: Step) -> Seq<Step> {
    match s { Step::Forward(_) | Step::CompletionSkipped => Seq::empty(), _ => seq![s] }
}
pub open spec fn observations(t: Seq<Step>) -> Seq<Step>
    decreases t.len(),
{ if t.len() == 0 { Seq::empty() } else { observations(t.drop_last()) + visible(t.last()) } }
proof fn observations_push(base: Seq<Step>, t: Seq<Step>, s: Step)
    ensures base + observations(t.push(s)) == observed_after(base + observations(t), s),
        received_input(base + observations(t.push(s))) == (match s { Step::ReadHead(input) => input, _ => received_input(base + observations(t)) }),
        prepared_identity(base + observations(t.push(s))) == (match s { Step::Prepared(_, _, e) => Some(e.transfer_identity()), _ => prepared_identity(base + observations(t)) }),
{ reveal(received_input); reveal(prepared_identity);
  assert(t.push(s).drop_last() =~= t);
  assert(base + observations(t.push(s)) =~= observed_after(base + observations(t), s));
  let events = base + observations(t);
  assert(events.push(s).drop_last() =~= events);
}

/// The one step relation: which step may follow which progress.
pub open spec fn step_ok(p: Progress, s: Step) -> Option<Progress> {
    match s {
        Step::ReadHead(input) => if !p.read && p.prepared.is_none() { Some(Progress { read: true, incoming: input, ..p }) } else { None },
        Step::Prepared(path, fields, evidence) => if p.admitted && p.prepared.is_none() && !p.connected && evidence.binds(path, fields) && p.incoming == Some(evidence.input) { Some(Progress { prepared: Some((path, fields, evidence)), ..p }) } else { None },
        Step::Status(status) => if p.connected { Some(Progress { last_status: Some(status), ..p }) } else { None },
        Step::Uploaded(bytes, copy) => if p.connected && p.upstream_head_written { Some(Progress { upload: copy, upload_wire: bytes, ..p }) } else { None },
        Step::Client(_, scope) => if p.forwarded && scope != WriteScope::Exchange { None } else { Some(p) },
        Step::Streamed(bytes, copy) => Some(Progress { download: copy, download_wire: bytes, ..p }),
        Step::Worker(ok) => if !p.worker && !p.admitted { Some(Progress { worker: ok, ..p }) } else { None },
        Step::Admit(ok) => if p.worker && !p.admitted && p.strict.is_none() { Some(Progress { admitted: ok, ..p }) } else { None },
        Step::Strict(b) => if p.admitted && p.strict.is_none() { Some(Progress { strict: Some(b), ..p }) } else { None },
        Step::RequestStart(ok) => if p.admitted && p.strict.is_some() && p.started.is_none() && !p.connected
            { Some(Progress { started: Some(ok), ..p }) } else { None },
        Step::Connect(ok) => if record_allows_dispatch(p) && !p.connected && p.response_logged.is_none()
            { Some(Progress { connected: ok, ..p }) } else { None },
        Step::UpstreamWrite(bytes) => if p.connected && p.prepared.is_some() &&
            (p.upstream_head_written || provider_head(bytes, p.prepared.unwrap().0, p.prepared.unwrap().1)) {
                Some(Progress { upstream_head_written: true, ..p })
            } else { None },
        Step::ResponseHead(status, ok) => if p.connected && p.response_logged.is_none() && p.last_status == Some(status)
            { Some(Progress { response_logged: Some((status, ok)), ..p }) } else { None },
        Step::Forward(status) => if !p.forwarded && p.upstream_head_written && record_allows_forward(p, status) { Some(Progress { forwarded: true, ..p }) } else { None },
        Step::LogHealthy(b) => Some(Progress { log_healthy: Some(b), ..p }),
        Step::Completion(_, ok) => if p.admitted && p.completion.is_none() { Some(Progress { completion: Some(ok), ..p }) } else { None },
        Step::CompletionSkipped => if p.admitted && p.completion.is_none() && p.log_healthy == Some(false)
            { Some(Progress { completion: Some(false), ..p }) } else { None },
    }
}
/// The progress a trace establishes, or `None` for a trace the driver may not take.
pub open spec fn run(trace: Seq<Step>) -> Option<Progress>
    decreases trace.len(),
{
    if trace.len() == 0 { Some(initial()) }
    else { match run(trace.drop_last()) { Some(p) => step_ok(p, trace.last()), None => None } }
}
/// Successful counts come from two completed primitive-effect histories for
/// the exact identity selected by the provider head, in their proper directions.
pub open spec fn copies_match_counts(p: Progress, upload: u64, download: u64) -> bool {
    p.prepared.is_some() && p.upload.is_some() && p.download.is_some()
        && p.upload.unwrap().matches(p.prepared.unwrap().2.transfer_identity(), 0)
        && p.download.unwrap().matches(p.prepared.unwrap().2.transfer_identity(), 1)
        && p.upload.unwrap().accepted == upload && p.download.unwrap().accepted == download
        && p.upload.unwrap().wire == Some(p.upload_wire)
        && match p.download.unwrap().wire {
            Some(wire) => wire == p.download_wire,
            None => p.download_wire.len() == 0 && download == 0,
        }
}
/// Authorization is retained through every subsequent failure and completion.
pub open spec fn authorized_progress(p: Progress) -> bool {
    (!p.read ==> p.incoming.is_none())
        && (p.prepared.is_some() ==> p.read && p.incoming == Some(p.prepared.unwrap().2.input)
            && p.prepared.unwrap().2.binds(p.prepared.unwrap().0, p.prepared.unwrap().1))
        && (p.upstream_head_written || p.forwarded ==> p.prepared.is_some())
}
pub proof fn lemma_authorized_progress(trace: Seq<Step>)
    requires run(trace).is_some(),
    ensures authorized_progress(run(trace).unwrap()),
    decreases trace.len(),
{
    if trace.len() > 0 { lemma_authorized_progress(trace.drop_last()); }
}

/// Every first provider write is the serialization of the authorized header
/// for the actual observed inbound head. Later writes are upload framing.
pub proof fn provider_head_has_authority(trace: Seq<Step>, i: int)
    requires run(trace).is_some(), 0 <= i < trace.len(), trace[i] is UpstreamWrite,
        !run(trace.take(i)).unwrap().upstream_head_written,
    ensures ({ let p = run(trace.take(i)).unwrap();
        p.prepared.is_some() && p.incoming == Some(p.prepared.unwrap().2.input)
            && p.prepared.unwrap().2.binds(p.prepared.unwrap().0, p.prepared.unwrap().1)
            && provider_head(trace[i]->UpstreamWrite_0, p.prepared.unwrap().0, p.prepared.unwrap().1) }),
{
    lemma_prefix_runs(trace, i + 1);
    let prefix = trace.take(i + 1);
    assert(prefix.drop_last() =~= trace.take(i));
    assert(prefix.last() == trace[i]);
    lemma_authorized_progress(trace.take(i));
}
/// The bytes a trace handed to the client, in order.
pub open spec fn client_writes(trace: Seq<Step>) -> Seq<u8>
    decreases trace.len(),
{
    if trace.len() == 0 { Seq::empty() }
    else { client_writes(trace.drop_last()) + written_by(trace.last()) }
}
pub open spec fn written_by(s: Step) -> Seq<u8> { match s { Step::Client(bytes, _) => bytes, Step::Streamed(bytes, _) => bytes, _ => Seq::empty() } }

proof fn lemma_run_push(t: Seq<Step>, s: Step)
    ensures run(t.push(s)) == (match run(t) { Some(p) => step_ok(p, s), None => None }),
{
    assert(t.push(s).drop_last() =~= t);
}
proof fn lemma_writes_push(t: Seq<Step>, s: Step)
    ensures client_writes(t.push(s)) == client_writes(t) + written_by(s),
{
    assert(t.push(s).drop_last() =~= t);
}

// ---- the driver state ----------------------------------------------------------

/// The driver's state: the trace, its progress, the connection machine, the
/// bytes the machine produced that have not yet been handed to the client,
/// and the bytes a live chunk stream has framed that the connection machine
/// has not yet absorbed (it does so at `finish`).
struct Driver { base: Ghost<Seq<Step>>, trace: Ghost<Seq<Step>>, progress: Ghost<Progress>, connection: Connection, pending: Ghost<Seq<u8>>, streamed: Ghost<Seq<u8>> }

/// The result: the worker's closing proof and the trace, for the theorems.
pub struct Driven { pub closed: Closed, pub trace: Ghost<Seq<Step>>, pub progress: Ghost<Progress>, pub written: Ghost<Seq<u8>>, pub outcome: Ghost<Option<(u8, u64, u64)>> }

/// The reason phrase for a status the gateway writes itself.
fn reason(status: u16) -> (out: Vec<u8>)
    ensures crate::http1_write::reason_ok(out@), out@.len() <= 32,
{
    let text: &[u8] = match status {
        100 => b"Continue", 200 => b"OK", 201 => b"Created", 202 => b"Accepted", 204 => b"No Content", 304 => b"Not Modified",
        400 => b"Bad Request", 401 => b"Unauthorized", 403 => b"Forbidden", 404 => b"Not Found", 405 => b"Method Not Allowed",
        429 => b"Too Many Requests", 431 => b"Request Header Fields Too Large", 500 => b"Internal Server Error",
        502 => b"Bad Gateway", 503 => b"Service Unavailable", 504 => b"Gateway Timeout", 529 => b"Overloaded",
        _ => b"",
    };
    let mut out: Vec<u8> = Vec::new();
    let mut k: usize = 0;
    while k < text.len()
        invariant k <= text.len(), text.len() <= 32, out@.len() == k, forall|j: int| 0 <= j < k ==> out@[j] == text@[j] && crate::http1_head::is_value_byte(#[trigger] out@[j]),
        decreases text.len() - k,
    {
        let b = text[k];
        if !crate::http1_head::value_byte_exec(b) { return Vec::new(); }
        out.push(b);
        k = k + 1;
    }
    out
}

fn is_get(method: &Vec<u8>) -> (out: bool)
    ensures out == (method@ == seq![71u8, 69u8, 84u8]),
{
    let out = method.len() == 3 && method[0] == 71 && method[1] == 69 && method[2] == 84;
    proof { if out { assert(method@ =~= seq![71u8, 69u8, 84u8]); } }
    out
}

/// The fault for a failed effect in a phase: what the runtime saw if it was
/// the deadline, cancellation, or a strict-mode logging refusal, else the phase's own.
fn fault_of(failure: Failure, phase: Fault) -> Fault {
    match failure { Failure::Cancelled => Fault::Cancelled, Failure::Timeout => Fault::Timeout, Failure::Log => Fault::Log, Failure::Io => phase }
}
fn connect_fault(failure: ConnectFailure) -> Fault {
    match failure {
        ConnectFailure::Resolve | ConnectFailure::Tcp => Fault::Connect, ConnectFailure::Tls => Fault::Tls,
        ConnectFailure::Timeout => Fault::Timeout, ConnectFailure::Cancelled => Fault::Cancelled,
    }
}

impl Driver {
    spec fn inv(&self) -> bool {
        run(self.trace@) == Some(self.progress@) && self.connection.valid()
        && (self.progress@.prepared.is_some() ==> prepared_identity(self.base@ + observations(self.trace@)) == Some(self.progress@.prepared.unwrap().2.transfer_identity()))
        && (self.progress@.incoming.is_some() ==> received_input(self.base@ + observations(self.trace@)) == self.progress@.incoming)
        && self.connection.out() + self.streamed@ == client_writes(self.trace@) + self.pending@
        && (self.connection.open() ==> self.streamed@.len() == 0 && !self.progress@.forwarded)
    }
    spec fn settled(&self) -> bool { self.inv() && self.pending@.len() == 0 }

    spec fn bound<E: Effects>(&self, effects: &E) -> bool { effects.events() == self.base@ + observations(self.trace@) }

    fn new<E: Effects>(effects: &E) -> (out: Self)
        ensures out.settled(), out.bound(effects), out.base@ == effects.events(), out.progress@ == initial(), out.connection.open(), !out.connection.interim_sent(),
    {
        let out = Driver { base: Ghost(effects.events()), trace: Ghost(Seq::empty()), progress: Ghost(initial()), connection: Connection::new(), pending: Ghost(Seq::empty()), streamed: Ghost(Seq::empty()) };
        proof { assert(out.connection.out() + out.streamed@ =~= client_writes(out.trace@) + out.pending@); }
        out
    }

    /// Record a step the progress allows.
    fn record<E: Effects>(&mut self, effects: &E, Ghost(s): Ghost<Step>)
        requires old(self).inv(), effects.events() == observed_after(old(self).base@ + observations(old(self).trace@), s),
            step_ok(old(self).progress@, s).is_some(), !(s is Client), !(s is Streamed),
            s is Forward ==> !old(self).connection.open() && old(self).connection.status() == s->Forward_0,
        ensures final(self).inv(), final(self).bound(effects), final(self).base@ == old(self).base@,
            final(self).progress@ == step_ok(old(self).progress@, s).unwrap(),
            final(self).trace@ == old(self).trace@.push(s), final(self).connection == old(self).connection,
            final(self).pending@ == old(self).pending@, final(self).streamed@ == old(self).streamed@,
    {
        proof { lemma_run_push(self.trace@, s); lemma_writes_push(self.trace@, s); observations_push(self.base@, self.trace@, s); }
        self.trace = Ghost(self.trace@.push(s));
        self.progress = Ghost(step_ok(self.progress@, s).unwrap());
    }

    /// Hand the machine's pending bytes to the client and record them.
    fn emit<E: Effects>(&mut self, effects: &mut E, bytes: Vec<u8>, scope: WriteScope) -> (ok: bool)
        requires old(self).inv(), old(self).bound(old(effects)), bytes@ == old(self).pending@,
            old(self).progress@.forwarded ==> scope == WriteScope::Exchange,
        ensures final(effects).events().len() >= old(effects).events().len(),
            final(effects).transferred() == old(effects).transferred(),
            final(effects).obstacles() >= old(effects).obstacles(),
            final(effects).obstacles() == old(effects).obstacles() ==> ok,
            final(self).settled(), final(self).bound(final(effects)), final(self).base@ == old(self).base@, final(self).progress@ == old(self).progress@, final(self).connection == old(self).connection,
            final(self).streamed@ == old(self).streamed@,
    {
        let ok = effects.write_client(&bytes, scope);
        proof { observations_push(self.base@, self.trace@, Step::Client(bytes@, scope)); lemma_run_push(self.trace@, Step::Client(bytes@, scope)); lemma_writes_push(self.trace@, Step::Client(bytes@, scope)); }
        self.trace = Ghost(self.trace@.push(Step::Client(bytes@, scope)));
        self.pending = Ghost(Seq::empty());
        ok
    }
    /// The download effect handed these stream frames to the client.
    fn note_streamed<E: Effects>(&mut self, effects: &E, Ghost(bytes): Ghost<Seq<u8>>, Ghost(summary): Ghost<Option<CopySummary>>)
        requires old(self).settled(), !old(self).connection.open(),
            effects.events() == (old(self).base@ + observations(old(self).trace@)).push(Step::Streamed(bytes, summary)),
        ensures final(self).settled(), final(self).bound(effects), final(self).base@ == old(self).base@, final(self).progress@ == (Progress { download: summary, download_wire: bytes, ..old(self).progress@ }), final(self).connection == old(self).connection,
            final(self).streamed@ == old(self).streamed@ + bytes,
    {
        proof { observations_push(self.base@, self.trace@, Step::Streamed(bytes, summary)); lemma_run_push(self.trace@, Step::Streamed(bytes, summary)); lemma_writes_push(self.trace@, Step::Streamed(bytes, summary)); }
        self.trace = Ghost(self.trace@.push(Step::Streamed(bytes, summary)));
        self.progress = Ghost(Progress { download: summary, download_wire: bytes, ..self.progress@ });
        self.streamed = Ghost(self.streamed@ + bytes);
        proof { assert(self.connection.out() + self.streamed@ =~= client_writes(self.trace@) + self.pending@); }
    }

    /// A complete fixed response, then the client's write side is closed.
    fn respond_fixed<E: Effects>(&mut self, effects: &mut E, status: u16, fields: Vec<Field>, body: &[u8])
        requires old(self).settled(), old(self).bound(old(effects)), !old(self).progress@.forwarded,
        ensures final(effects).events().len() >= old(effects).events().len(),
            final(effects).transferred() == old(effects).transferred(),
            final(effects).obstacles() >= old(effects).obstacles(),
            final(self).settled(), final(self).bound(final(effects)), final(self).base@ == old(self).base@, final(self).progress@ == old(self).progress@,
    {
        let reason = reason(status);
        match self.connection.respond_fixed(status, reason.as_slice(), fields, body) {
            Some(bytes) => {
                self.pending = Ghost(bytes@);
                proof { assert(self.connection.out() + self.streamed@ =~= client_writes(self.trace@) + self.pending@); }
                let _ = self.emit(effects, bytes, WriteScope::Control);
            }
            None => {}
        }
        effects.close_client();
    }
    /// A refusal or failure: the status alone.
    fn refuse<E: Effects>(&mut self, effects: &mut E, status: u16)
        requires old(self).settled(), old(self).bound(old(effects)), !old(self).progress@.forwarded,
        ensures final(effects).events().len() >= old(effects).events().len(),
            final(effects).transferred() == old(effects).transferred(),
            final(effects).obstacles() >= old(effects).obstacles(),
            final(self).settled(), final(self).bound(final(effects)), final(self).base@ == old(self).base@, final(self).progress@ == old(self).progress@,
    {
        let empty: Vec<u8> = Vec::new();
        self.respond_fixed(effects, status, Vec::new(), empty.as_slice());
    }

    /// A connection that never reached admission closes without a lifecycle.
    fn close_without<E: Effects>(self, effects: &E) -> (out: Driven)
        requires effects.events().len() > self.base@.len(),
            self.settled(), self.bound(effects), !self.progress@.admitted,
        ensures effects.events().len() > self.base@.len(),
            effects.events() == self.base@ + observations(out.trace@),
            run(out.trace@) == Some(out.progress@), client_writes(out.trace@) == out.written@,
            out.progress@ == self.progress@, !out.closed.recorded(), out.outcome@.is_none(),
    {
        Driven { closed: Closed::without_request(), trace: self.trace, progress: self.progress, written: Ghost(self.connection.out() + self.streamed@), outcome: Ghost(None) }
    }

    /// Kind 4 for a finished exchange, unless the logger is already unhealthy;
    /// then the skip is recorded instead. The lifecycle closes with the truth.
    fn complete<E: Effects>(mut self, effects: &mut E, life: Lifecycle) -> (out: Driven)
        requires self.settled(), self.bound(old(effects)), self.progress@.admitted, self.progress@.completion.is_none(), life.valid(), life.terminal(),
            life.outcome() == crate::metadata::OUTCOME_SUCCESS ==> copies_match_counts(self.progress@, life.recorded_upload(), life.recorded_download()),
        ensures final(effects).events().len() >= old(effects).events().len(),
            final(effects).transferred() == old(effects).transferred(),
            final(effects).obstacles() >= old(effects).obstacles(),
            final(effects).events().len() > self.base@.len(),
            final(effects).events() == self.base@ + observations(out.trace@),
            completed_as(final(effects).events(), out.outcome@.unwrap(), out.closed.recorded()),
            out.outcome@ == Some((life.outcome(), life.recorded_upload(), life.recorded_download())),
            life.outcome() == crate::metadata::OUTCOME_SUCCESS ==> copies_match_counts(out.progress@, life.recorded_upload(), life.recorded_download()),
            final(effects).obstacles() == old(effects).obstacles() ==> out.closed.recorded(),
            run(out.trace@) == Some(out.progress@), client_writes(out.trace@) == out.written@,
            out.progress@.admitted, out.progress@.completion.is_some(), out.progress@.forwarded == self.progress@.forwarded,
            out.closed.recorded() == (out.progress@.completion == Some(true)),
    {
        if !effects.log_healthy() {
            self.record(effects, Ghost(Step::LogHealthy(false)));
            self.record(effects, Ghost(Step::CompletionSkipped));
            return Driven { closed: life.close(false), trace: self.trace, progress: self.progress, written: Ghost(self.connection.out() + self.streamed@), outcome: Ghost(Some((life.outcome(), life.recorded_upload(), life.recorded_download()))) };
        }
        self.record(effects, Ghost(Step::LogHealthy(true)));
        let now = effects.now_ms();
        let payload = life.completion(now);
        let recorded = effects.audit_completion(&payload);
        self.record(effects, Ghost(Step::Completion(payload@, recorded)));
        proof {
            assert(crate::metadata::decoded_completion(payload@) == Some((now, life.outcome(), life.recorded_upload(), life.recorded_download())));
            assert(exists|time: u64| crate::metadata::decoded_completion(payload@) == Some((time, life.outcome(), life.recorded_upload(), life.recorded_download())));
            assert(effects.events().last() == Step::Completion(payload@, recorded));
            assert(effects.events().len() > 0);
            assert(completed_as(effects.events(), (life.outcome(), life.recorded_upload(), life.recorded_download()), recorded));
        }
        Driven { closed: life.close(recorded), trace: self.trace, progress: self.progress, written: Ghost(self.connection.out() + self.streamed@), outcome: Ghost(Some((life.outcome(), life.recorded_upload(), life.recorded_download()))) }
    }

    /// The request half of the exchange; its result is consumed by the response half.
    #[verifier::rlimit(60)]
    fn send_upload<E: Effects>(&mut self, effects: &mut E, life: &mut Lifecycle, input: &RequestHead) -> (out: Result<TransferKey, Fault>)
        requires old(self).progress@.incoming == Some(*input), old(self).settled(), old(self).bound(old(effects)), record_allows_dispatch(old(self).progress@),
            !old(self).progress@.connected, old(self).progress@.prepared.is_none(), old(self).progress@.admitted, old(self).progress@.response_logged.is_none(),
            old(life).valid(), old(life).open(), !old(life).uploaded(),
        ensures final(self).settled(), final(self).bound(final(effects)), final(self).base@ == old(self).base@,
            final(self).connection == old(self).connection,
            final(self).progress@ == (Progress { prepared: final(self).progress@.prepared, upload: final(self).progress@.upload, upload_wire: final(self).progress@.upload_wire,
                connected: final(self).progress@.connected, upstream_head_written: final(self).progress@.upstream_head_written,
                ..old(self).progress@ }),
            final(effects).obstacles() >= old(effects).obstacles(), final(effects).events().len() >= old(effects).events().len(),
            final(effects).transferred().1 == old(effects).transferred().1,
            final(life).valid(), final(life).open(),
            final(effects).obstacles() == old(effects).obstacles() ==> out.is_ok(),
            out.is_ok() ==> final(life).uploaded() && final(self).progress@.connected && final(self).progress@.upstream_head_written
                && final(life).upload() == final(effects).transferred().0
                && final(self).progress@.prepared.is_some()
                && out.unwrap().identity() == final(self).progress@.prepared.unwrap().2.transfer_identity()
                && final(self).progress@.upload.is_some()
                && final(self).progress@.upload.unwrap().wire == Some(final(self).progress@.upload_wire)
                && final(self).progress@.upload.unwrap().matches(out.unwrap().identity(), 0)
                && final(self).progress@.upload.unwrap().accepted == final(life).upload(),
    {
        let prepared = match effects.upstream_head(input) { Some(head) => head, None => return Err(Fault::Metadata) };
        let ghost evidence = prepared.evidence();
        let (path, fields, key) = prepared.into_dispatch();
        self.record(effects, Ghost(Step::Prepared(path@, fields@, evidence)));
        match effects.connect() {
            Ok(key) => self.record(effects, Ghost(Step::Connect(true))),
            Err(failure) => { self.record(effects, Ghost(Step::Connect(false))); return Err(connect_fault(failure)); }
        }
        let mut upstream = Upstream::new();
        let (head, stream) = match upstream.request(path.as_slice(), fields) { Some(pair) => pair, None => return Err(Fault::Metadata) };
        proof {
            assert(provider_head(head@, path@, fields@)) by {
                let all = upstream.head_fields();
                assert(crate::http1_exchange::is_chunked(all[all.len() - 2]));
                assert(crate::http1_exchange::is_close(all.last()));
            }
        }
        let written = effects.write_upstream(&head);
        self.record(effects, Ghost(Step::UpstreamWrite(head@)));
        if !written { return Err(Fault::Http); }
        let transfer = effects.upload(&key, stream);
        let ghost summary = transfer.summary();
        self.record(effects, Ghost(Step::Uploaded(transfer.sent(), summary)));
        let (uploaded, mut stream) = transfer.into_parts();
        let copy = match uploaded { Ok(copy) => copy, Err(failure) => return Err(fault_of(failure, Fault::Upload)) };
        if !copy.is_finished() || !copy.matches(&key, 0) || stream.is_ended() { return Err(Fault::Upload); }
        let last = stream.end();
        let written = effects.write_upstream(&last);
        self.record(effects, Ghost(Step::UpstreamWrite(last@)));
        if !written { return Err(Fault::Upload); }
        upstream.finish(stream);
        life.upload_finished(copy.body_copy());
        Ok(key)
    }

    /// The provider exchange: connect, upload, read the head, forward it, download.
    /// On `Err` nothing further has been promised to the client beyond what the
    /// connection machine already holds; the caller answers or aborts.
    #[verifier::rlimit(100)]
    fn exchange<E: Effects>(&mut self, effects: &mut E, life: &mut Lifecycle, strict: bool, input: &RequestHead) -> (out: Result<(), Fault>)
        requires old(self).progress@.incoming == Some(*input), old(self).settled(), old(self).bound(old(effects)), record_allows_dispatch(old(self).progress@), !old(self).progress@.connected,
            old(self).progress@.response_logged.is_none(), !old(self).progress@.forwarded, old(self).progress@.completion.is_none(),
            old(self).progress@.prepared.is_none(), old(self).progress@.admitted,
            old(self).progress@.strict == Some(strict), old(self).connection.open(),
            old(life).valid(), old(life).open(), !old(life).uploaded(),
        ensures final(effects).events().len() >= old(effects).events().len(),
            final(effects).obstacles() >= old(effects).obstacles(),
            final(self).settled(), final(self).bound(final(effects)), final(self).base@ == old(self).base@,
            final(self).progress@.admitted == old(self).progress@.admitted,
            final(self).progress@.completion.is_none(), final(life).valid(),
            final(effects).obstacles() == old(effects).obstacles() ==> out.is_ok(),
            out.is_ok() ==> final(life).terminal() && final(life).outcome() == crate::metadata::OUTCOME_SUCCESS
                && final(self).connection.done() && final(self).progress@.forwarded
                && final(life).recorded_upload() == final(effects).transferred().0
                && final(life).recorded_download() == final(effects).transferred().1
                && copies_match_counts(final(self).progress@, final(life).recorded_upload(), final(life).recorded_download()),
            out.is_err() ==> final(life).open(),
    {
        let key = match self.send_upload(effects, life, input) { Ok(key) => key, Err(fault) => return Err(fault) };

        // Response heads until a final one; the machine classifies each.
        let (status, fields, body_framing) = match final_head(self, effects) { Ok(head) => head, Err(fault) => return Err(fault) };
        if status < 200 { return Err(Fault::Metadata); }
        let ghost provider_fields = fields@;
        let ghost provider_head = StatusHead { status, fields };
        proof { assert(effects.obstacles() == old(effects).obstacles() ==> supported_response(provider_head)); }
        let fields = match crate::headers::forward_response(&fields) { Ok(fields) => fields, Err(_) => return Err(Fault::Metadata) };
        // Kind 3 before the head reaches the client. Strict mode stops here on
        // a failed append; availability mode continues with a gap.
        let logged = effects.audit_response_head(status);
        self.record(effects, Ghost(Step::ResponseHead(status, logged)));
        if !logged && strict { return Err(Fault::Log); }
        let reason = reason(status);
        proof {
            if effects.obstacles() == old(effects).obstacles() {
                assert(crate::headers::response_head_ok(provider_fields, fields@));
                supported_response_fits(provider_head, fields@, reason@);
                assert(if status == 204 || status == 304 {
                    crate::http1_exchange::fixed_supported(status, reason@, fields@, 0)
                } else { crate::http1_exchange::stream_supported(status, reason@, fields@) });
            }
        }
        let transfer = if status == 204 || status == 304 {
            // No body may follow: the fixed head is the whole response.
            match self.connection.respond_fixed(status, reason.as_slice(), fields, Vec::<u8>::new().as_slice()) {
                Some(bytes) => {
                    self.pending = Ghost(bytes@);
                    proof { assert(self.connection.out() + self.streamed@ =~= client_writes(self.trace@) + self.pending@); }
                    self.record(effects, Ghost(Step::Forward(status)));
                    if !self.emit(effects, bytes, WriteScope::Exchange) { return Err(Fault::Client); }
                }
                None => return Err(Fault::Metadata),
            }
            effects.download(&key, body_framing, Body::Fixed)
        } else {
            let (head, stream) = match self.connection.respond_stream(status, reason.as_slice(), fields) {
                Some(pair) => pair, None => return Err(Fault::Metadata),
            };
            self.pending = Ghost(head@);
            proof { assert(self.connection.out() + self.streamed@ =~= client_writes(self.trace@) + self.pending@); }
            self.record(effects, Ghost(Step::Forward(status)));
            if !self.emit(effects, head, WriteScope::Exchange) { return Err(Fault::Client); }
            effects.download(&key, body_framing, Body::Stream(stream))
        };
        let ghost summary = transfer.summary();
        self.note_streamed(effects, Ghost(transfer.sent()), Ghost(summary));
        let (copied, body) = transfer.into_parts();
        let copy = match copied { Ok(copy) => copy, Err(failure) => return Err(fault_of(failure, Fault::Download)) };
        if !copy.is_finished() || !copy.matches(&key, 1) { return Err(Fault::Download); }
        match body {
            Body::Fixed => { if copy.accepted_bytes() != 0 || !self.connection.is_done() { return Err(Fault::Download); } }
            Body::Stream(mut stream) => {
                if stream.is_ended() || !self.connection.is_streaming() { return Err(Fault::Download); }
                let last = stream.end();
                self.streamed = Ghost(self.streamed@ + last@);
                self.pending = Ghost(last@);
                proof { assert(self.connection.out() + self.streamed@ =~= client_writes(self.trace@) + self.pending@); }
                let delivered = self.emit(effects, last, WriteScope::Exchange);
                self.connection.finish(stream);
                self.streamed = Ghost(Seq::empty());
                proof { assert(self.connection.out() + self.streamed@ =~= client_writes(self.trace@) + self.pending@); }
                if !delivered { return Err(Fault::Client); }
            }
        }
        life.succeeded(copy.body_copy());
        effects.close_client();
        Ok(())
    }
}

/// The most interim (1xx) heads tolerated before the final one. Beyond it the
/// upstream is treated as an HTTP failure, which bounds the head loop.
pub const MAX_INTERIM_HEADS: u32 = 8;

/// Read status heads until a final one, as the verified classification says.
/// Reads at most `MAX_INTERIM_HEADS + 1` heads.
fn final_head<E: Effects>(d: &mut Driver, effects: &mut E) -> (out: Result<(u16, Vec<Field>, Framing), Fault>)
    requires old(d).settled(), old(d).bound(old(effects)), old(d).progress@.connected,
    ensures final(effects).events().len() >= old(effects).events().len(),
        final(d).connection == old(d).connection,
        final(effects).transferred() == old(effects).transferred(),
        final(effects).obstacles() >= old(effects).obstacles(),
        final(effects).obstacles() == old(effects).obstacles() ==> out.is_ok() && supported_response(StatusHead { status: out.unwrap().0, fields: out.unwrap().1 }),
        final(d).settled(), final(d).bound(final(effects)), final(d).base@ == old(d).base@,
        final(d).progress@ == (Progress { last_status: final(d).progress@.last_status, ..old(d).progress@ }),
        out.is_ok() ==> final(d).progress@.last_status == Some(out.unwrap().0),
{
    let mut interim: u32 = 0;
    loop
        invariant effects.events().len() >= old(effects).events().len(), d.connection == old(d).connection, effects.transferred() == old(effects).transferred(), effects.obstacles() >= old(effects).obstacles(),
            interim_heads(effects.events()) == interim_heads(old(effects).events()) + interim, interim <= MAX_INTERIM_HEADS, d.settled(), d.bound(effects), d.progress@.connected, d.base@ == old(d).base@,
            d.progress@ == (Progress { last_status: d.progress@.last_status, ..old(d).progress@ }),
        decreases MAX_INTERIM_HEADS - interim,
    {
        let ghost before = effects.events();
        let status_head = match effects.read_status_head() { Ok(head) => head, Err(failure) => return Err(fault_of(failure, Fault::Http)) };
        proof {
            assert(effects.events().drop_last() =~= before);
            assert(interim_heads(effects.events()) == interim_heads(before) + (if status_head.status < 200 && status_head.status != 101 { 1nat } else { 0nat }));
        }
        d.record(effects, Ghost(Step::Status(status_head.status)));
        match upstream_status(status_head.status, &status_head.fields) {
            UpstreamStatus::Interim => {
                if interim == MAX_INTERIM_HEADS { return Err(Fault::Http); }
                interim = interim + 1;
            }
            UpstreamStatus::Refused => return Err(Fault::Metadata),
            UpstreamStatus::Bodiless => return Ok((status_head.status, status_head.fields, Framing::Length(0))),
            UpstreamStatus::Framed(framing) => return Ok((status_head.status, status_head.fields, framing)),
        }
    }
}

/// Drive one connection to its end. Every byte handed to the client is the
/// connection machine's output, in order; the trace is one the specification
/// allows; an admitted exchange ends with a completion record or an explicit
/// skip; and the closing proof says whether the record was appended.
pub fn drive<E: Effects>(effects: &mut E) -> (out: Driven)
    ensures crate::gateway_contract::connection(old(effects).events(), final(effects).events(), old(effects).obstacles(),
            final(effects).obstacles(), final(effects).transferred(), out),
        final(effects).obstacles() >= old(effects).obstacles(),
        final(effects).obstacles() == old(effects).obstacles() ==> out.progress@.admitted && out.progress@.forwarded
            && out.closed.recorded() && out.outcome@.is_some() && out.outcome@ == Some((crate::metadata::OUTCOME_SUCCESS, final(effects).transferred().0, final(effects).transferred().1)),
        out.outcome@.is_some() ==> completed_as(final(effects).events(), out.outcome@.unwrap(), out.closed.recorded()),
        final(effects).events() == old(effects).events() + observations(out.trace@), run(out.trace@) == Some(out.progress@), client_writes(out.trace@) == out.written@,
        out.progress@.admitted ==> out.progress@.completion.is_some(),
        out.outcome@.is_some() == out.progress@.admitted,
        out.outcome@.is_some() && out.outcome@.unwrap().0 == crate::metadata::OUTCOME_SUCCESS ==>
            out.progress@.forwarded && copies_match_counts(out.progress@, out.outcome@.unwrap().1, out.outcome@.unwrap().2)
                && out.outcome@.unwrap().1 == final(effects).transferred().0
                && out.outcome@.unwrap().2 == final(effects).transferred().1,
        out.closed.recorded() == (out.progress@.completion == Some(true)),
{
    let out = drive_connection(effects);
    proof { lemma_authorized_progress(out.trace@); }
    out
}

/// Execute the production connection; separate this body from its public
/// contract join so the solver checks each control-flow obligation once.
#[verifier::rlimit(100)]
fn drive_connection<E: Effects>(effects: &mut E) -> (out: Driven)
    ensures final(effects).events().len() > old(effects).events().len(),
        final(effects).obstacles() >= old(effects).obstacles(),
        final(effects).obstacles() == old(effects).obstacles() ==> out.progress@.admitted && out.progress@.forwarded
            && out.closed.recorded() && out.outcome@.is_some() && out.outcome@ == Some((crate::metadata::OUTCOME_SUCCESS, final(effects).transferred().0, final(effects).transferred().1)),
        out.outcome@.is_some() ==> completed_as(final(effects).events(), out.outcome@.unwrap(), out.closed.recorded()),
        final(effects).events() == old(effects).events() + observations(out.trace@), run(out.trace@) == Some(out.progress@), client_writes(out.trace@) == out.written@,
        out.progress@.admitted ==> out.progress@.completion.is_some(),
        out.outcome@.is_some() == out.progress@.admitted,
        out.outcome@.is_some() && out.outcome@.unwrap().0 == crate::metadata::OUTCOME_SUCCESS ==>
            out.progress@.forwarded && copies_match_counts(out.progress@, out.outcome@.unwrap().1, out.outcome@.unwrap().2)
                && out.outcome@.unwrap().1 == final(effects).transferred().0
                && out.outcome@.unwrap().2 == final(effects).transferred().1,
        out.closed.recorded() == (out.progress@.completion == Some(true)),
{
    let mut d = Driver::new(effects);
    let read = effects.read_head();
    d.record(effects, Ghost(Step::ReadHead(read_input(read))));
    let head = match read {
        HeadRead::Head(head) => head,
        HeadRead::TooLarge => { d.refuse(effects, refusal_status(Refusal::HeadTooLarge)); return d.close_without(effects); }
        HeadRead::Malformed => { d.refuse(effects, refusal_status(Refusal::Malformed)); return d.close_without(effects); }
        HeadRead::Closed => return d.close_without(effects),
    };
    let body_framing = match framing(&head.fields, true) {
        Ok(framing) => framing,
        Err(_) => { d.refuse(effects, refusal_status(Refusal::Malformed)); return d.close_without(effects); }
    };
    // A client waiting for permission to send its body gets it; the body is
    // read whether or not the request is then admitted.
    if wants_continue(&head.fields) {
        match d.connection.interim_continue() {
            Some(bytes) => {
                d.pending = Ghost(bytes@);
                proof { assert(d.connection.out() + d.streamed@ =~= client_writes(d.trace@) + d.pending@); }
                let _ = d.emit(effects, bytes, WriteScope::Control);
            }
            None => {}
        }
    }
    if is_get(&head.method) {
        match effects.endpoint(&head.target) {
            Some(response) => { d.respond_fixed(effects, response.status, response.fields, response.body.as_slice()); return d.close_without(effects); }
            None => {}
        }
    }
    if !effects.acquire_worker() {
        d.record(effects, Ghost(Step::Worker(false)));
        d.respond_fixed(effects, refusal_status(Refusal::Unavailable), Vec::new(), b"workers unavailable\n");
        return d.close_without(effects);
    }
    d.record(effects, Ghost(Step::Worker(true)));
    match effects.admit(&head) {
        Admit::Refused(refusal) => {
            d.record(effects, Ghost(Step::Admit(false)));
            d.refuse(effects, refusal_status(refusal));
            return d.close_without(effects);
        }
        Admit::Admitted => d.record(effects, Ghost(Step::Admit(true))),
    }
    let strict = effects.strict();
    d.record(effects, Ghost(Step::Strict(strict)));
    let mut life = Lifecycle::begin();
    // If strict logging is already unavailable, do not even open an upstream
    // connection. Later failures still use the stream gate.
    let healthy = if strict {
        let healthy = effects.log_healthy();
        d.record(effects, Ghost(Step::LogHealthy(healthy)));
        healthy
    } else { true };
    if strict && !healthy {
        d.refuse(effects, refusal_status(Refusal::Unavailable));
        life.failed(Fault::Log);
        return d.complete(effects, life);
    }
    // Kind 2 before any DNS, TCP, or TLS effect. Strict mode needs the
    // acknowledgment before dispatch; availability mode forwards with a gap.
    let started = effects.audit_request_start();
    d.record(effects, Ghost(Step::RequestStart(started)));
    if !started && strict {
        d.refuse(effects, refusal_status(Refusal::Unavailable));
        life.failed(Fault::StartRefused);
        return d.complete(effects, life);
    }
    if !effects.bind_input(body_framing) {
        d.refuse(effects, refusal_status(Refusal::Unavailable));
        life.failed(Fault::InputUnavailable);
        return d.complete(effects, life);
    }
    match d.exchange(effects, &mut life, strict, &head) {
        Ok(()) => {}
        Err(fault) => {
            life.failed(fault);
            effects.observe(Event::Failed(fault));
            if d.connection.is_open() {
                d.refuse(effects, failure_status(fault));
            } else {
                // After the head, closing without the last chunk tells the
                // client the body is truncated; it is never a clean end.
                d.connection.abort();
                effects.close_client();
            }
        }
    }
    d.complete(effects, life)
}

// ---- what an allowed trace guarantees ---------------------------------------------

/// Every prefix of an allowed trace is allowed.
pub proof fn lemma_prefix_runs(t: Seq<Step>, n: int)
    requires run(t).is_some(), 0 <= n <= t.len(),
    ensures run(t.take(n)).is_some(),
    decreases t.len() - n,
{
    if n < t.len() {
        let shorter = t.drop_last();
        assert(shorter =~= t.take(t.len() - 1));
        assert(shorter.take(n) =~= t.take(n));
        lemma_prefix_runs(shorter, n);
    } else {
        assert(t.take(n) =~= t);
    }
}

/// Every explicit write after forwarding begins uses the exchange scope,
/// regardless of status, body length, interim responses, or failure position.
pub proof fn lemma_forwarded_writes_use_exchange_budget(t: Seq<Step>, i: int)
    requires run(t).is_some(), 0 <= i < t.len(), run(t.take(i)).unwrap().forwarded,
    ensures match t[i] { Step::Client(_, scope) => scope == WriteScope::Exchange, _ => true },
{
    lemma_prefix_runs(t, i + 1);
    let prefix = t.take(i + 1);
    assert(prefix.drop_last() =~= t.take(i));
    assert(prefix.last() == t[i]);
}

/// The progress fields that are set have the step that set them in the trace.
pub proof fn lemma_progress_reflects(t: Seq<Step>)
    requires run(t).is_some(),
    ensures ({
        let p = run(t).unwrap();
        (p.started.is_some() ==> exists|j: int| 0 <= j < t.len() && t[j] == Step::RequestStart(p.started.unwrap()))
        && (p.strict.is_some() ==> exists|j: int| 0 <= j < t.len() && t[j] == Step::Strict(p.strict.unwrap()))
        && (p.response_logged.is_some() ==> exists|j: int| 0 <= j < t.len()
            && t[j] == Step::ResponseHead(p.response_logged.unwrap().0, p.response_logged.unwrap().1))
    }),
    decreases t.len(),
{
    if t.len() > 0 {
        let shorter = t.drop_last();
        lemma_progress_reflects(shorter);
        let p = run(t).unwrap();
        let q = run(shorter).unwrap();
        let last = t.len() - 1;
        if p.started.is_some() {
            if q.started == p.started {
                let j = choose|j: int| 0 <= j < shorter.len() && shorter[j] == Step::RequestStart(q.started.unwrap());
                assert(t[j] == Step::RequestStart(p.started.unwrap()));
            } else {
                assert(t[last] == Step::RequestStart(p.started.unwrap()));
            }
        }
        if p.strict.is_some() {
            if q.strict == p.strict {
                let j = choose|j: int| 0 <= j < shorter.len() && shorter[j] == Step::Strict(q.strict.unwrap());
                assert(t[j] == Step::Strict(p.strict.unwrap()));
            } else {
                assert(t[last] == Step::Strict(p.strict.unwrap()));
            }
        }
        if p.response_logged.is_some() {
            if q.response_logged == p.response_logged {
                let j = choose|j: int| 0 <= j < shorter.len()
                    && shorter[j] == Step::ResponseHead(q.response_logged.unwrap().0, q.response_logged.unwrap().1);
                assert(t[j] == Step::ResponseHead(p.response_logged.unwrap().0, p.response_logged.unwrap().1));
            } else {
                assert(t[last] == Step::ResponseHead(p.response_logged.unwrap().0, p.response_logged.unwrap().1));
            }
        }
    }
}

/// No network effect before the request-start record: a connect is preceded
/// by an appended record, or by a refused one in availability mode.
pub proof fn lemma_connect_after_record(t: Seq<Step>, i: int)
    requires run(t).is_some(), 0 <= i < t.len(), t[i] is Connect,
    ensures exists|j: int| 0 <= j < i && (t[j] == Step::RequestStart(true)
        || (t[j] == Step::RequestStart(false) && exists|k: int| 0 <= k < i && t[k] == Step::Strict(false))),
{
    lemma_prefix_runs(t, i + 1);
    let upto = t.take(i + 1);
    let before = t.take(i);
    assert(upto.drop_last() =~= before);
    let p = run(before).unwrap();
    lemma_progress_reflects(before);
    let j = choose|j: int| 0 <= j < before.len() && before[j] == Step::RequestStart(p.started.unwrap());
    if p.started == Some(false) {
        let k = choose|k: int| 0 <= k < before.len() && before[k] == Step::Strict(p.strict.unwrap());
        assert(t[k] == Step::Strict(false));
    }
    assert(t[j] == Step::RequestStart(p.started.unwrap()));
}

/// The head reaches the client only after its record: appended, or refused
/// in availability mode.
pub proof fn lemma_forward_after_record(t: Seq<Step>, i: int, status: u16)
    requires run(t).is_some(), 0 <= i < t.len(), t[i] == Step::Forward(status),
    ensures exists|j: int| 0 <= j < i && (t[j] == Step::ResponseHead(status, true)
        || (t[j] == Step::ResponseHead(status, false) && exists|k: int| 0 <= k < i && t[k] == Step::Strict(false))),
{
    lemma_prefix_runs(t, i + 1);
    let upto = t.take(i + 1);
    let before = t.take(i);
    assert(upto.drop_last() =~= before);
    let p = run(before).unwrap();
    lemma_progress_reflects(before);
    let j = choose|j: int| 0 <= j < before.len()
        && before[j] == Step::ResponseHead(p.response_logged.unwrap().0, p.response_logged.unwrap().1);
    if p.response_logged == Some((status, false)) {
        let k = choose|k: int| 0 <= k < before.len() && before[k] == Step::Strict(p.strict.unwrap());
        assert(t[k] == Step::Strict(false));
    }
    assert(t[j] == Step::ResponseHead(status, p.response_logged.unwrap().1));
}

/// An allowed trace records the completion at most once.
pub proof fn lemma_completion_once(t: Seq<Step>, i: int, j: int)
    requires run(t).is_some(), 0 <= i < j < t.len(), t[i] is Completion || t[i] is CompletionSkipped,
    ensures !(t[j] is Completion || t[j] is CompletionSkipped),
    decreases t.len(),
{
    if j < t.len() - 1 {
        let shorter = t.drop_last();
        assert(shorter =~= t.take(t.len() - 1));
        lemma_completion_once(shorter, i, j);
    } else {
        lemma_prefix_runs(t, i + 1);
        lemma_completion_set(t.take(j));
        assert(t.take(j).take(i + 1) =~= t.take(i + 1));
    }
}
/// A trace with a completion step has its completion set from then on.
proof fn lemma_completion_set(t: Seq<Step>)
    requires run(t).is_some(),
    ensures forall|i: int| 0 <= i < t.len() && (t[i] is Completion || t[i] is CompletionSkipped) ==> run(t).unwrap().completion.is_some(),
    decreases t.len(),
{
    if t.len() > 0 {
        let shorter = t.drop_last();
        lemma_completion_set(shorter);
        assert forall|i: int| 0 <= i < t.len() && (t[i] is Completion || t[i] is CompletionSkipped) implies run(t).unwrap().completion.is_some() by {
            if i < shorter.len() { assert(shorter[i] == t[i]); }
        }
    }
}
}
