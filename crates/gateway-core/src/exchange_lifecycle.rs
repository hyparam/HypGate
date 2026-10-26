//! Verified exchange lifecycle: from admission to the completion record. The
//! lifecycle is open until exactly one terminal event, either a successful
//! download or a named fault, and only a terminal lifecycle can produce the
//! completion payload or the `Closed` token the worker must return. The
//! outcome code is a checked function of the event, and the byte counts of a
//! successful exchange are the counts the body-copy machines proved.
use vstd::prelude::*;
use crate::{body_copy::BodyCopy, destination::Parts, metadata, policy::AuthorizedRequest, resolved_route::ResolvedRoute};

verus! {
/// Why an exchange ended without a complete response.
#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Fault {
    /// Upstream connect, TLS, or HTTP failure.
    Connect, Tls, Http,
    /// The upstream exchange deadline passed.
    Timeout,
    /// The request body could not be forwarded.
    Upload,
    /// The response body could not be forwarded.
    Download,
    /// The client went away or the worker was cancelled.
    Client, Cancelled,
    /// Strict mode refused to forward without a durable record.
    Log, StartRefused,
    /// Metadata handling failed or the input body was unavailable.
    Metadata, InputUnavailable,
}

pub open spec fn outcome_of(fault: Fault) -> u8 {
    match fault {
        Fault::Connect | Fault::Tls | Fault::Http => metadata::OUTCOME_UPSTREAM_FAILURE,
        Fault::Timeout => metadata::OUTCOME_UPSTREAM_TIMEOUT,
        Fault::Upload => metadata::OUTCOME_UPLOAD_FAILURE,
        Fault::Download => metadata::OUTCOME_DOWNLOAD_FAILURE,
        Fault::Client | Fault::Cancelled => metadata::OUTCOME_CLIENT_DISCONNECT,
        Fault::Log | Fault::StartRefused => metadata::OUTCOME_LOG_REFUSAL,
        Fault::Metadata | Fault::InputUnavailable => metadata::OUTCOME_OTHER,
    }
}

pub fn outcome_code(fault: Fault) -> (out: u8)
    ensures out == outcome_of(fault), out <= metadata::MAX_OUTCOME, out != metadata::OUTCOME_SUCCESS,
{
    match fault {
        Fault::Connect | Fault::Tls | Fault::Http => metadata::OUTCOME_UPSTREAM_FAILURE,
        Fault::Timeout => metadata::OUTCOME_UPSTREAM_TIMEOUT,
        Fault::Upload => metadata::OUTCOME_UPLOAD_FAILURE,
        Fault::Download => metadata::OUTCOME_DOWNLOAD_FAILURE,
        Fault::Client | Fault::Cancelled => metadata::OUTCOME_CLIENT_DISCONNECT,
        Fault::Log | Fault::StartRefused => metadata::OUTCOME_LOG_REFUSAL,
        Fault::Metadata | Fault::InputUnavailable => metadata::OUTCOME_OTHER,
    }
}

/// The request-start record payload (kind 2): the clock, the authorized
/// route's selector, and the configured text of the destination the route
/// resolved to. `None` only when the route is not bound to this authority or
/// the destination text is outside the codec's bounds.
pub fn start_record<C>(authority: &AuthorizedRequest, resolved: &ResolvedRoute<'_, Parts, C>, time_ms: u64) -> (out: Option<Vec<u8>>)
    requires authority.valid(),
    ensures match out {
        Some(payload) => resolved.bound_to(authority)
            && metadata::decoded_request_start(payload@)
                == Some((time_ms, authority.binding().selector, resolved.destination_value().text@)),
        None => !resolved.bound_to(authority) || !metadata::request_start_valid(resolved.destination_value().text@),
    },
{
    let destination = match resolved.destination(authority) { Some(destination) => destination, None => return None };
    let route = authority.route();
    metadata::encode_request_start(time_ms, route.selector, destination.text.as_slice())
}

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
enum State { Open, Uploaded, Terminal }

pub struct Lifecycle { state: State, outcome: u8, upload: u64, download: u64 }

impl Lifecycle {
    pub closed spec fn open(&self) -> bool { self.state == State::Open || self.state == State::Uploaded }
    pub closed spec fn uploaded(&self) -> bool { self.state == State::Uploaded }
    pub closed spec fn terminal(&self) -> bool { self.state == State::Terminal }
    pub closed spec fn outcome(&self) -> u8 { self.outcome }
    pub closed spec fn upload(&self) -> u64 { self.upload }
    pub closed spec fn download(&self) -> u64 { self.download }
    pub closed spec fn valid(&self) -> bool {
        self.outcome <= metadata::MAX_OUTCOME
        && (self.state != State::Terminal ==> self.outcome == metadata::OUTCOME_SUCCESS)
    }
    /// The byte counts the completion record carries: those of a successful
    /// exchange, zero for one that ended in a fault.
    pub open spec fn recorded_upload(&self) -> u64 { if self.outcome() == metadata::OUTCOME_SUCCESS { self.upload() } else { 0 } }
    pub open spec fn recorded_download(&self) -> u64 { if self.outcome() == metadata::OUTCOME_SUCCESS { self.download() } else { 0 } }

    pub fn begin() -> (out: Self)
        ensures out.valid(), out.open(), !out.uploaded(),
    { Lifecycle { state: State::Open, outcome: metadata::OUTCOME_SUCCESS, upload: 0, download: 0 } }

    /// The request body reached the provider: its accepted count is the
    /// upload count.
    pub fn upload_finished(&mut self, copy: &BodyCopy)
        requires old(self).valid(), old(self).open(), !old(self).uploaded(), copy.is_done(),
        ensures final(self).valid(), final(self).open(), final(self).uploaded(), final(self).upload() == copy.accepted(),
    {
        self.upload = copy.accepted_bytes();
        self.state = State::Uploaded;
    }

    /// The response body reached the client after the upload: the exchange
    /// succeeded with both proved counts.
    pub fn succeeded(&mut self, copy: &BodyCopy)
        requires old(self).valid(), old(self).uploaded(), copy.is_done(),
        ensures final(self).valid(), final(self).terminal(), final(self).outcome() == metadata::OUTCOME_SUCCESS,
            final(self).upload() == old(self).upload(), final(self).download() == copy.accepted(),
            final(self).recorded_upload() == old(self).upload(), final(self).recorded_download() == copy.accepted(),
    {
        self.download = copy.accepted_bytes();
        self.outcome = metadata::OUTCOME_SUCCESS;
        self.state = State::Terminal;
    }

    /// The exchange ended in a fault; its outcome code is the fault's.
    pub fn failed(&mut self, fault: Fault)
        requires old(self).valid(), old(self).open(),
        ensures final(self).valid(), final(self).terminal(), final(self).outcome() == outcome_of(fault),
            final(self).recorded_upload() == 0, final(self).recorded_download() == 0,
    {
        self.outcome = outcome_code(fault);
        self.state = State::Terminal;
    }

    /// The completion record payload (kind 4) for a finished exchange.
    pub fn completion(&self, time_ms: u64) -> (out: Vec<u8>)
        requires self.valid(), self.terminal(),
        ensures out.len() == metadata::COMPLETION_LEN,
            out@ == metadata::completion_encoding(time_ms, self.outcome(), self.recorded_upload(), self.recorded_download()),
            metadata::decoded_completion(out@) == Some((time_ms, self.outcome(), self.recorded_upload(), self.recorded_download())),
    {
        let (upload, download) = if self.outcome == metadata::OUTCOME_SUCCESS { (self.upload, self.download) } else { (0, 0) };
        match metadata::encode_completion(time_ms, self.outcome, upload, download) {
            Some(bytes) => bytes,
            None => { proof { assert(false); } Vec::new() }
        }
    }

    /// Consume the finished lifecycle. `recorded` says whether the completion
    /// record was appended; the caller may skip it only when the logger is
    /// already unhealthy.
    pub fn close(self, recorded: bool) -> (out: Closed)
        requires self.valid(), self.terminal(),
        ensures out.recorded() == recorded,
    { Closed { recorded } }
}

/// Proof that a worker reached the end of its exchange: either a terminal
/// lifecycle produced it, or the request was never admitted and so has no
/// records anywhere. A worker future must return one.
pub struct Closed { recorded: bool }
impl Closed {
    pub closed spec fn recorded(&self) -> bool { self.recorded }
    /// The one way to close a worker without a lifecycle: the request was
    /// refused before admission, so no exchange and no record exist for it.
    pub fn without_request() -> (out: Self)
        ensures !out.recorded(),
    { Closed { recorded: false } }
    pub fn was_recorded(&self) -> (out: bool)
        ensures out == self.recorded(),
    { self.recorded }
}
}
