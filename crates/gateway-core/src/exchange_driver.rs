//! Verified driver for one inbound connection, from the request head to the
//! completion record. The runtime supplies an `Effects` implementation with
//! no decisions in it: it reads a head, moves bytes, opens the provider
//! connection, runs the two body copies, and appends records. This driver is
//! what sequences those effects and what calls the verified machines, so the
//! order the audit contract promises is checked here rather than promised by
//! the runtime: the request-start record precedes any network effect, the
//! response-head record precedes the head reaching the client, every byte
//! handed to the client is the connection machine's output in order, and an
//! admitted exchange ends with exactly one completion record or one explicit
//! skip while the logger is unhealthy. The effects themselves stay trusted.
//!
//! The driver keeps a ghost trace of the steps it took; `run` is the
//! specification of which traces are allowed, and the lemmas at the end read
//! the ordering properties off any allowed trace.
use vstd::prelude::*;
use crate::body_copy::BodyCopy;
use crate::exchange_lifecycle::{Closed, Fault, Lifecycle};
use crate::headers::Field;
use crate::http1_exchange::{ChunkStream, Connection, Refusal, Upstream, UpstreamStatus, failure_status, refusal_status, upstream_status, wants_continue};
use crate::http1_framing::{Framing, framing};
use crate::http1_head::{RequestHead, StatusHead};

verus! {
/// What reading the request head produced.
pub enum HeadRead { Head(RequestHead), TooLarge, Malformed, Closed }
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

/// What the runtime does for the driver. Every method is trusted to perform
/// exactly the effect named and report what happened; none decides anything.
pub trait Effects {
    fn read_head(&mut self) -> HeadRead;
    /// Hand bytes to the client; false when the client is gone.
    fn write_client(&mut self, bytes: &Vec<u8>, scope: WriteScope) -> bool;
    fn close_client(&mut self);
    /// An operator endpoint for a GET target, answered without a worker.
    fn endpoint(&mut self, target: &Vec<u8>) -> Option<FixedResponse>;
    fn acquire_worker(&mut self) -> bool;
    /// Authenticate, authorize, and bind the route; builds the upstream head.
    fn admit(&mut self, head: &RequestHead) -> Admit;
    fn strict(&mut self) -> bool;
    fn log_healthy(&mut self) -> bool;
    fn now_ms(&mut self) -> u64;
    /// Kind 2; false when the append failed.
    fn audit_request_start(&mut self) -> bool;
    /// Bind the request body, framed as given, to the worker's input role.
    fn bind_input(&mut self, framing: Framing) -> bool;
    /// The upstream path and projected fields the admission built.
    fn upstream_head(&mut self) -> Option<(Vec<u8>, Vec<Field>)>;
    /// Resolve, connect, and complete the TLS handshake under the permit.
    fn connect(&mut self) -> Result<(), ConnectFailure>;
    fn write_upstream(&mut self, bytes: &Vec<u8>) -> bool;
    /// Copy the request body upstream as chunks of `stream`, which comes back
    /// having only been framed through: the runtime is trusted to return the
    /// stream it was given, so the stream's invariant holds.
    fn upload(&mut self, stream: ChunkStream) -> (out: (Result<BodyCopy, Failure>, ChunkStream))
        ensures out.1.valid();
    fn read_status_head(&mut self) -> Result<StatusHead, Failure>;
    /// Kind 3; false when the append failed.
    fn audit_response_head(&mut self, status: u16) -> bool;
    /// Copy the response body, framed as given, to the client through `body`;
    /// `Ok` only when the body was complete as framed. A stream comes back
    /// having only been framed through, as for `upload`.
    fn download(&mut self, framing: Framing, body: Body) -> (out: (Result<BodyCopy, Failure>, Body))
        ensures match out.1 { Body::Stream(stream) => stream.valid(), Body::Fixed => true };
    /// Kind 4; false when the append failed.
    fn audit_completion(&mut self, payload: &Vec<u8>) -> bool;
    fn observe(&mut self, event: Event);
}

// ---- the allowed traces ------------------------------------------------------

/// One step the driver took, as the trace records it.
pub ghost enum Step {
    /// Bytes the driver handed to the client.
    Client(Seq<u8>, WriteScope),
    /// Bytes the download effect handed to the client: a chunk stream's frames.
    Streamed(Seq<u8>),
    Worker(bool), Admit(bool), Strict(bool), RequestStart(bool), Connect(bool),
    UpstreamWrite(Seq<u8>),
    /// The response-head record for this status, and whether it was appended.
    ResponseHead(u16, bool),
    /// The upstream head with this status handed to the client.
    Forward(u16),
    LogHealthy(bool),
    /// The completion record, and whether it was appended.
    Completion(bool),
    /// The completion record skipped because the logger was unhealthy.
    CompletionSkipped,
}

/// What the trace so far has established.
pub ghost struct Progress {
    pub worker: bool, pub admitted: bool, pub strict: Option<bool>, pub started: Option<bool>, pub connected: bool,
    pub response_logged: Option<(u16, bool)>, pub forwarded: bool, pub log_healthy: Option<bool>, pub completion: Option<bool>,
}
pub open spec fn initial() -> Progress {
    Progress { worker: false, admitted: false, strict: None, started: None, connected: false,
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
/// The one step relation: which step may follow which progress.
pub open spec fn step_ok(p: Progress, s: Step) -> Option<Progress> {
    match s {
        Step::Client(_, scope) => if p.forwarded && scope != WriteScope::Exchange { None } else { Some(p) },
        Step::Streamed(_) => Some(p),
        Step::Worker(ok) => if !p.worker && !p.admitted { Some(Progress { worker: ok, ..p }) } else { None },
        Step::Admit(ok) => if p.worker && !p.admitted && p.strict.is_none() { Some(Progress { admitted: ok, ..p }) } else { None },
        Step::Strict(b) => if p.admitted && p.strict.is_none() { Some(Progress { strict: Some(b), ..p }) } else { None },
        Step::RequestStart(ok) => if p.admitted && p.strict.is_some() && p.started.is_none() && !p.connected
            { Some(Progress { started: Some(ok), ..p }) } else { None },
        Step::Connect(ok) => if record_allows_dispatch(p) && !p.connected && p.response_logged.is_none()
            { Some(Progress { connected: ok, ..p }) } else { None },
        Step::UpstreamWrite(_) => if p.connected { Some(p) } else { None },
        Step::ResponseHead(status, ok) => if p.connected && p.response_logged.is_none()
            { Some(Progress { response_logged: Some((status, ok)), ..p }) } else { None },
        Step::Forward(status) => if !p.forwarded && record_allows_forward(p, status) { Some(Progress { forwarded: true, ..p }) } else { None },
        Step::LogHealthy(b) => Some(Progress { log_healthy: Some(b), ..p }),
        Step::Completion(ok) => if p.admitted && p.completion.is_none() { Some(Progress { completion: Some(ok), ..p }) } else { None },
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
/// The bytes a trace handed to the client, in order.
pub open spec fn client_writes(trace: Seq<Step>) -> Seq<u8>
    decreases trace.len(),
{
    if trace.len() == 0 { Seq::empty() }
    else { client_writes(trace.drop_last()) + written_by(trace.last()) }
}
pub open spec fn written_by(s: Step) -> Seq<u8> { match s { Step::Client(bytes, _) => bytes, Step::Streamed(bytes) => bytes, _ => Seq::empty() } }

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
struct Driver { trace: Ghost<Seq<Step>>, progress: Ghost<Progress>, connection: Connection, pending: Ghost<Seq<u8>>, streamed: Ghost<Seq<u8>> }

/// The result: the worker's closing proof and the trace, for the theorems.
pub struct Driven { pub closed: Closed, pub trace: Ghost<Seq<Step>>, pub progress: Ghost<Progress>, pub written: Ghost<Seq<u8>> }

/// The reason phrase for a status the gateway writes itself.
fn reason(status: u16) -> (out: Vec<u8>)
    ensures crate::http1_write::reason_ok(out@),
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
        invariant k <= text.len(), out@.len() == k, forall|j: int| 0 <= j < k ==> out@[j] == text@[j] && crate::http1_head::is_value_byte(#[trigger] out@[j]),
        decreases text.len() - k,
    {
        let b = text[k];
        if !crate::http1_head::value_byte_exec(b) { return Vec::new(); }
        out.push(b);
        k = k + 1;
    }
    out
}

fn is_get(method: &Vec<u8>) -> bool { method.len() == 3 && method[0] == 71 && method[1] == 69 && method[2] == 84 }

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
        && self.connection.out() + self.streamed@ == client_writes(self.trace@) + self.pending@
        && (self.connection.open() ==> self.streamed@.len() == 0 && !self.progress@.forwarded)
    }
    spec fn settled(&self) -> bool { self.inv() && self.pending@.len() == 0 }

    fn new() -> (out: Self)
        ensures out.settled(), out.progress@ == initial(), out.connection.open(), !out.connection.interim_sent(),
    {
        let out = Driver { trace: Ghost(Seq::empty()), progress: Ghost(initial()), connection: Connection::new(), pending: Ghost(Seq::empty()), streamed: Ghost(Seq::empty()) };
        proof { assert(out.connection.out() + out.streamed@ =~= client_writes(out.trace@) + out.pending@); }
        out
    }

    /// Record a step the progress allows.
    fn record(&mut self, Ghost(s): Ghost<Step>)
        requires old(self).inv(), step_ok(old(self).progress@, s).is_some(), !(s is Client), !(s is Streamed),
            s is Forward ==> !old(self).connection.open(),
        ensures final(self).inv(), final(self).progress@ == step_ok(old(self).progress@, s).unwrap(),
            final(self).trace@ == old(self).trace@.push(s), final(self).connection == old(self).connection,
            final(self).pending@ == old(self).pending@, final(self).streamed@ == old(self).streamed@,
    {
        proof { lemma_run_push(self.trace@, s); lemma_writes_push(self.trace@, s); }
        self.trace = Ghost(self.trace@.push(s));
        self.progress = Ghost(step_ok(self.progress@, s).unwrap());
    }

    /// Hand the machine's pending bytes to the client and record them.
    fn emit<E: Effects>(&mut self, effects: &mut E, bytes: Vec<u8>, scope: WriteScope) -> (ok: bool)
        requires old(self).inv(), bytes@ == old(self).pending@,
            old(self).progress@.forwarded ==> scope == WriteScope::Exchange,
        ensures final(self).settled(), final(self).progress@ == old(self).progress@, final(self).connection == old(self).connection,
            final(self).streamed@ == old(self).streamed@,
    {
        let ok = effects.write_client(&bytes, scope);
        proof { lemma_run_push(self.trace@, Step::Client(bytes@, scope)); lemma_writes_push(self.trace@, Step::Client(bytes@, scope)); }
        self.trace = Ghost(self.trace@.push(Step::Client(bytes@, scope)));
        self.pending = Ghost(Seq::empty());
        ok
    }
    /// The download effect handed these stream frames to the client.
    fn note_streamed(&mut self, Ghost(bytes): Ghost<Seq<u8>>)
        requires old(self).settled(), !old(self).connection.open(),
        ensures final(self).settled(), final(self).progress@ == old(self).progress@, final(self).connection == old(self).connection,
            final(self).streamed@ == old(self).streamed@ + bytes,
    {
        proof { lemma_run_push(self.trace@, Step::Streamed(bytes)); lemma_writes_push(self.trace@, Step::Streamed(bytes)); }
        self.trace = Ghost(self.trace@.push(Step::Streamed(bytes)));
        self.streamed = Ghost(self.streamed@ + bytes);
        proof { assert(self.connection.out() + self.streamed@ =~= client_writes(self.trace@) + self.pending@); }
    }

    /// A complete fixed response, then the client's write side is closed.
    fn respond_fixed<E: Effects>(&mut self, effects: &mut E, status: u16, fields: Vec<Field>, body: &[u8])
        requires old(self).settled(), !old(self).progress@.forwarded,
        ensures final(self).settled(), final(self).progress@ == old(self).progress@,
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
        requires old(self).settled(), !old(self).progress@.forwarded,
        ensures final(self).settled(), final(self).progress@ == old(self).progress@,
    {
        let empty: Vec<u8> = Vec::new();
        self.respond_fixed(effects, status, Vec::new(), empty.as_slice());
    }

    /// A connection that never reached admission closes without a lifecycle.
    fn close_without(self) -> (out: Driven)
        requires self.settled(), !self.progress@.admitted,
        ensures run(out.trace@) == Some(out.progress@), client_writes(out.trace@) == out.written@,
            out.progress@ == self.progress@, !out.closed.recorded(),
    {
        Driven { closed: Closed::without_request(), trace: self.trace, progress: self.progress, written: Ghost(self.connection.out() + self.streamed@) }
    }

    /// Kind 4 for a finished exchange, unless the logger is already unhealthy;
    /// then the skip is recorded instead. The lifecycle closes with the truth.
    fn complete<E: Effects>(mut self, effects: &mut E, life: Lifecycle) -> (out: Driven)
        requires self.settled(), self.progress@.admitted, self.progress@.completion.is_none(), life.valid(), life.terminal(),
        ensures run(out.trace@) == Some(out.progress@), client_writes(out.trace@) == out.written@,
            out.progress@.admitted, out.progress@.completion.is_some(),
            out.closed.recorded() == (out.progress@.completion == Some(true)),
    {
        if !effects.log_healthy() {
            self.record(Ghost(Step::LogHealthy(false)));
            self.record(Ghost(Step::CompletionSkipped));
            return Driven { closed: life.close(false), trace: self.trace, progress: self.progress, written: Ghost(self.connection.out() + self.streamed@) };
        }
        self.record(Ghost(Step::LogHealthy(true)));
        let payload = life.completion(effects.now_ms());
        let recorded = effects.audit_completion(&payload);
        self.record(Ghost(Step::Completion(recorded)));
        Driven { closed: life.close(recorded), trace: self.trace, progress: self.progress, written: Ghost(self.connection.out() + self.streamed@) }
    }

    /// The provider exchange: connect, upload, read the head, forward it, download.
    /// On `Err` nothing further has been promised to the client beyond what the
    /// connection machine already holds; the caller answers or aborts.
    fn exchange<E: Effects>(&mut self, effects: &mut E, life: &mut Lifecycle, strict: bool) -> (out: Result<(), Fault>)
        requires old(self).settled(), record_allows_dispatch(old(self).progress@), !old(self).progress@.connected,
            old(self).progress@.response_logged.is_none(), !old(self).progress@.forwarded, old(self).progress@.completion.is_none(),
            old(self).progress@.strict == Some(strict), old(self).connection.open(),
            old(life).valid(), old(life).open(), !old(life).uploaded(),
        ensures final(self).settled(), final(self).progress@.admitted == old(self).progress@.admitted,
            final(self).progress@.completion.is_none(), final(life).valid(),
            out.is_ok() ==> final(life).terminal() && final(self).connection.done(),
            out.is_err() ==> final(life).open(),
    {
        let (path, fields) = match effects.upstream_head() { Some(head) => head, None => return Err(Fault::Metadata) };
        match effects.connect() {
            Ok(()) => self.record(Ghost(Step::Connect(true))),
            Err(failure) => { self.record(Ghost(Step::Connect(false))); return Err(connect_fault(failure)); }
        }
        let mut upstream = Upstream::new();
        let (head, stream) = match upstream.request(path.as_slice(), fields) { Some(pair) => pair, None => return Err(Fault::Metadata) };
        self.record(Ghost(Step::UpstreamWrite(head@)));
        if !effects.write_upstream(&head) { return Err(Fault::Http); }
        let (uploaded, mut stream) = effects.upload(stream);
        let copy = match uploaded { Ok(copy) => copy, Err(failure) => return Err(fault_of(failure, Fault::Upload)) };
        if !copy.is_finished() || stream.is_ended() { return Err(Fault::Upload); }
        let last = stream.end();
        self.record(Ghost(Step::UpstreamWrite(last@)));
        if !effects.write_upstream(&last) { return Err(Fault::Upload); }
        upstream.finish(stream);
        life.upload_finished(&copy);

        // Response heads until a final one; the machine classifies each.
        let (status, fields, body_framing) = match final_head(effects) { Ok(head) => head, Err(fault) => return Err(fault) };
        if status < 200 { return Err(Fault::Metadata); }
        let fields = match crate::headers::forward_response(&fields) { Ok(fields) => fields, Err(_) => return Err(Fault::Metadata) };
        // Kind 3 before the head reaches the client. Strict mode stops here on
        // a failed append; availability mode continues with a gap.
        let logged = effects.audit_response_head(status);
        self.record(Ghost(Step::ResponseHead(status, logged)));
        if !logged && strict { return Err(Fault::Log); }
        let reason = reason(status);
        let (copied, body) = if status == 204 || status == 304 {
            // No body may follow: the fixed head is the whole response.
            match self.connection.respond_fixed(status, reason.as_slice(), fields, Vec::<u8>::new().as_slice()) {
                Some(bytes) => {
                    self.pending = Ghost(bytes@);
                    proof { assert(self.connection.out() + self.streamed@ =~= client_writes(self.trace@) + self.pending@); }
                    self.record(Ghost(Step::Forward(status)));
                    if !self.emit(effects, bytes, WriteScope::Exchange) { return Err(Fault::Client); }
                }
                None => return Err(Fault::Metadata),
            }
            effects.download(body_framing, Body::Fixed)
        } else {
            let (head, stream) = match self.connection.respond_stream(status, reason.as_slice(), fields) {
                Some(pair) => pair, None => return Err(Fault::Metadata),
            };
            self.pending = Ghost(head@);
            proof { assert(self.connection.out() + self.streamed@ =~= client_writes(self.trace@) + self.pending@); }
            self.record(Ghost(Step::Forward(status)));
            if !self.emit(effects, head, WriteScope::Exchange) { return Err(Fault::Client); }
            effects.download(body_framing, Body::Stream(stream))
        };
        // Whatever the stream framed, the effect handed to the client.
        let body = match body {
            Body::Stream(stream) => { self.note_streamed(Ghost(stream.out())); Body::Stream(stream) }
            Body::Fixed => Body::Fixed,
        };
        let copy = match copied { Ok(copy) => copy, Err(failure) => return Err(fault_of(failure, Fault::Download)) };
        if !copy.is_finished() { return Err(Fault::Download); }
        match body {
            Body::Fixed => { if !self.connection.is_done() { return Err(Fault::Download); } }
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
        life.succeeded(&copy);
        effects.close_client();
        Ok(())
    }
}

/// The most interim (1xx) heads tolerated before the final one. Beyond it the
/// upstream is treated as an HTTP failure, which bounds the head loop.
pub const MAX_INTERIM_HEADS: u32 = 8;

/// Read status heads until a final one, as the verified classification says.
/// Reads at most `MAX_INTERIM_HEADS + 1` heads.
fn final_head<E: Effects>(effects: &mut E) -> (out: Result<(u16, Vec<Field>, Framing), Fault>)
{
    let mut interim: u32 = 0;
    loop
        invariant interim <= MAX_INTERIM_HEADS,
        decreases MAX_INTERIM_HEADS - interim,
    {
        let status_head = match effects.read_status_head() { Ok(head) => head, Err(failure) => return Err(fault_of(failure, Fault::Http)) };
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
    ensures run(out.trace@) == Some(out.progress@), client_writes(out.trace@) == out.written@,
        out.progress@.admitted ==> out.progress@.completion.is_some(),
        out.closed.recorded() == (out.progress@.completion == Some(true)),
{
    let mut d = Driver::new();
    let head = match effects.read_head() {
        HeadRead::Head(head) => head,
        HeadRead::TooLarge => { d.refuse(effects, refusal_status(Refusal::HeadTooLarge)); return d.close_without(); }
        HeadRead::Malformed => { d.refuse(effects, refusal_status(Refusal::Malformed)); return d.close_without(); }
        HeadRead::Closed => return d.close_without(),
    };
    let body_framing = match framing(&head.fields, true) {
        Ok(framing) => framing,
        Err(_) => { d.refuse(effects, refusal_status(Refusal::Malformed)); return d.close_without(); }
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
            Some(response) => { d.respond_fixed(effects, response.status, response.fields, response.body.as_slice()); return d.close_without(); }
            None => {}
        }
    }
    if !effects.acquire_worker() {
        d.record(Ghost(Step::Worker(false)));
        d.respond_fixed(effects, refusal_status(Refusal::Unavailable), Vec::new(), b"workers unavailable\n");
        return d.close_without();
    }
    d.record(Ghost(Step::Worker(true)));
    match effects.admit(&head) {
        Admit::Refused(refusal) => {
            d.record(Ghost(Step::Admit(false)));
            d.refuse(effects, refusal_status(refusal));
            return d.close_without();
        }
        Admit::Admitted => d.record(Ghost(Step::Admit(true))),
    }
    let strict = effects.strict();
    d.record(Ghost(Step::Strict(strict)));
    let mut life = Lifecycle::begin();
    // If strict logging is already unavailable, do not even open an upstream
    // connection. Later failures still use the stream gate.
    if strict && !effects.log_healthy() {
        d.refuse(effects, refusal_status(Refusal::Unavailable));
        life.failed(Fault::Log);
        return d.complete(effects, life);
    }
    // Kind 2 before any DNS, TCP, or TLS effect. Strict mode needs the
    // acknowledgment before dispatch; availability mode forwards with a gap.
    let started = effects.audit_request_start();
    d.record(Ghost(Step::RequestStart(started)));
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
    match d.exchange(effects, &mut life, strict) {
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
