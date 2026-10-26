//! This module is trusted Rust, not Verus-verified. It owns registry keys and
//! stream storage so callers cannot return a credit while retaining its stream.
use crate::transfer::{AuditLog, Direction, LogRecord, RecordKind, TransferError};
use gateway_core::policy::{AuthorizedRequest, Policy};
use gateway_core::resource::{RequestKey, ResourceAdmission};
use gateway_core::owned_stream::OwnedStream;
use gateway_core::stream::StreamChunk;
use gateway_core::submission::AuthorizedWrite;
use std::sync::Mutex;

#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Unauthorized,
    AtCapacity,
    Unavailable,
}

pub struct Admission {
    registry: Mutex<ResourceAdmission>,
    policy: Policy,
    strict: bool,
    requests: usize,
}

enum LeaseState { Reserved(RequestKey), Streaming(OwnedStream) }
struct Lease<'a> {
    admission: &'a Admission,
    state: Option<LeaseState>,
}

impl Lease<'_> {
    fn stream(&self) -> &OwnedStream {
        match self.state.as_ref().expect("live lease") {
            LeaseState::Streaming(stream) => stream,
            LeaseState::Reserved(_) => unreachable!("admitted stream"),
        }
    }
    fn stream_mut(&mut self) -> &mut OwnedStream {
        match self.state.as_mut().expect("live lease") {
            LeaseState::Streaming(stream) => stream,
            LeaseState::Reserved(_) => unreachable!("admitted stream"),
        }
    }
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        // Poison permanently closes admission. Do not recover potentially broken
        // registry state merely to reclaim a credit.
        if let Ok(mut registry) = self.admission.registry.lock() {
            let released = match self.state.take() {
                Some(LeaseState::Streaming(stream)) => stream.retire(&mut registry),
                Some(LeaseState::Reserved(key)) => registry.release(&key),
                None => return, // unwinding during ownership transfer retains the slot
            };
            debug_assert!(released, "private lease must own its registry slot");
        }
    }
}

/// The lease owns stream storage and consumes it under the registry lock on drop.
/// There is no public extraction, mutable core reference, or cloning operation.
pub struct Request<'a> {
    authorized: AuthorizedRequest<'a>,
    capacity: usize,
    journal: gateway_core::journal_binding::JournalBinding,
    lease: Lease<'a>,
}

// Leaving a copy by panic or early return must also close the stream: the
// underlying I/O may have had an effect whose completion is now unknown.
// Never reuse/replay it.
pub(crate) struct CancelOnDrop<'r, 'a> { pub(crate) request: &'r mut Request<'a>, pub(crate) armed: bool }
impl Drop for CancelOnDrop<'_, '_> {
    fn drop(&mut self) { if self.armed { self.request.cancel(); } }
}

impl Admission {
    pub(crate) fn healthy(&self) -> bool { !self.registry.is_poisoned() }
    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.registry.lock().unwrap();
            panic!("injected admission panic");
        }));
    }
    pub fn usage(&self) -> Result<(usize, usize), AdmissionError> {
        self.registry.lock().map(|registry| registry.usage()).map_err(|_| AdmissionError::Unavailable)
    }
    pub(crate) fn requires_audit(&self) -> bool { self.strict }
    pub fn new(policy: Policy, requests: usize, chunk_bytes: usize, strict: bool) -> Self {
        Self { registry: Mutex::new(ResourceAdmission::new(requests, chunk_bytes)), policy, strict, requests }
    }
    pub fn request_limit(&self) -> usize { self.requests }

    pub fn admit(&self, digest: &[u8], selector: u64) -> Result<Request<'_>, AdmissionError> {
        let identity = self.policy.authenticate(digest).ok_or(AdmissionError::Unauthorized)?;
        let (mut lease, capacity, request_id) = {
            let mut registry = self.registry.lock().map_err(|_| AdmissionError::Unavailable)?;
            let key = registry.acquire().ok_or(AdmissionError::AtCapacity)?;
            let capacity = registry.capacity(&key).expect("fresh registry key");
            let request_id = key.owner();
            (Lease { admission: self, state: Some(LeaseState::Reserved(key)) }, capacity, request_id)
        };
        // Any early return drops the lease, including failed route authorization.
        let authorized = identity.authorize(selector, request_id)
            .ok_or(AdmissionError::Unauthorized)?;
        {
            let registry = self.registry.lock().map_err(|_| AdmissionError::Unavailable)?;
            let Some(LeaseState::Reserved(key)) = lease.state.take() else { unreachable!("new reservation") };
            match OwnedStream::claim(&registry, key, &authorized, self.strict) {
                Ok(stream) => lease.state = Some(LeaseState::Streaming(stream)),
                Err(key) => {
                    lease.state = Some(LeaseState::Reserved(key));
                    return Err(AdmissionError::Unavailable);
                }
            }
        }
        Ok(Request { authorized, capacity, journal: gateway_core::journal_binding::JournalBinding::new(), lease })
    }
}

pub struct WriteTicket<'a> {
    admission: &'a Admission,
    core: AuthorizedWrite,
}

impl<'a> Request<'a> {
    pub(crate) fn authority(&self) -> &AuthorizedRequest<'a> { &self.authorized }
    /// The caller transfers an owned background result into this request while
    /// retaining its exclusive borrow. No background slot is released first.
    pub(crate) fn adopt_background<T>(&mut self, credit: &mut gateway_core::task_credit::TaskCredit,
        value: gateway_core::task_credit::TaskResult<T>) -> Result<T, gateway_core::task_credit::TaskResult<T>>
    {
        let Ok(registry) = self.lease.admission.registry.lock() else { return Err(value); };
        value.adopt(credit, &registry, self.lease.stream())
    }

    fn stream(&self) -> &StreamChunk { self.lease.stream().stream() }
    fn stream_mut(&mut self) -> &mut OwnedStream { self.lease.stream_mut() }
    pub(crate) fn owned(&self) -> &OwnedStream { self.lease.stream() }
    /// The verified owner, its authority, and its journal designation, for the
    /// body-copy machine. The lease keeps ownership; nothing is extracted.
    pub(crate) fn parts(&mut self) -> (&mut OwnedStream, &AuthorizedRequest<'a>, &mut gateway_core::journal_binding::JournalBinding) {
        (self.lease.stream_mut(), &self.authorized, &mut self.journal)
    }
    /// The stream this ticket was prepared against, if the ticket is ours.
    fn bound_stream(&self, ticket: &WriteTicket<'_>) -> Option<&OwnedStream> {
        std::ptr::eq(ticket.admission, self.lease.admission).then(|| self.lease.stream())
    }
    pub fn request_id(&self) -> u64 { self.authorized.request_id() }
    pub fn tenant_id(&self) -> u64 { self.authorized.tenant_id() }
    pub(crate) fn is_closed(&self) -> bool { self.stream().is_closed() }
    pub(crate) fn log_failed(&self) -> bool { self.stream().is_failed() }
    pub(crate) fn strict(&self) -> bool { self.lease.admission.strict }

    pub fn advance(&mut self, bytes: Vec<u8>) -> Option<u64> {
        // Verus models payload length, not Vec backing capacity. Reject excess
        // spare allocation at the trusted ownership boundary before retaining it.
        if bytes.capacity() > self.capacity { return None; }
        self.stream_mut().advance(bytes)
    }
    /// Bind the logger's result to this request's current immutable chunk.
    /// The logger remains trusted to report actual durability. An abandoned
    /// append closes the stream, since it may already have had an unknown effect.
    pub fn audit_current<L: AuditLog>(&mut self, log: &mut L, direction: Direction)
        -> Result<(), TransferError>
    {
        let mut pending = CancelOnDrop { request: self, armed: true };
        if pending.request.is_closed() || pending.request.log_failed() {
            return Err(TransferError::InvalidState);
        }
        if !pending.request.journal.bind(log.session_id()) {
            return Err(TransferError::InvalidState);
        }
        let direction_id = direction.id();
        let (header, bytes) = pending.request.stream()
            .audit_record(&pending.request.authorized, direction_id)
            .ok_or(TransferError::InvalidState)?;
        let chunk = header.chunk;
        let record = LogRecord { tenant: header.tenant, request: header.request,
            chunk, kind: direction.into(), bytes };
        let receipt = match log.append(record) {
            Ok(receipt) => receipt,
            Err(_) => {
                pending.request.fail_log();
                pending.armed = false;
                return Err(TransferError::Log);
            }
        };
        if !pending.request.lease.stream_mut().acknowledge_receipt(&pending.request.authorized, &pending.request.journal, direction_id, &receipt) {
            return Err(TransferError::InvalidState);
        }
        pending.armed = false;
        Ok(())
    }
    /// Append one metadata record (kinds 2 to 4) for this request. Metadata
    /// records use chunk id 0, which the verified `audit_record` never issues
    /// for a body chunk, and they never touch the body stream: no chunk
    /// advance, no capacity use, no durable offset. The receipt is checked
    /// against the designated journal session and the exact record, as body
    /// receipts are, but it authorizes nothing. A failed append marks the
    /// request log-failed exactly like a failed body append. The completion
    /// record describes an exchange that is already over, so it is attempted
    /// even for a closed or log-failed request; the caller skips it only when
    /// the logger itself is unhealthy.
    pub(crate) fn audit_metadata<L: AuditLog>(&mut self, log: &mut L, kind: RecordKind, payload: &[u8])
        -> Result<(), TransferError>
    {
        if kind.direction().is_some() || payload.len() > gateway_core::metadata::MAX_PAYLOAD {
            return Err(TransferError::InvalidState);
        }
        let completion = kind == RecordKind::Completion;
        // A request already marked log-failed skips later appends, as the body
        // path does; the gap was counted at the first failure.
        if self.log_failed() && !completion { return Err(TransferError::Log); }
        let mut pending = CancelOnDrop { request: self, armed: !completion };
        if pending.request.is_closed() && !completion { return Err(TransferError::InvalidState); }
        if !pending.request.journal.bind(log.session_id()) {
            return Err(TransferError::InvalidState);
        }
        let header = gateway_core::framing::Header { payload: payload.len() as u32, tenant: pending.request.tenant_id(),
            request: pending.request.request_id(), chunk: 0, kind: kind.id() };
        let record = LogRecord { tenant: header.tenant, request: header.request, chunk: 0, kind, bytes: payload };
        let receipt = match log.append(record) {
            Ok(receipt) => receipt,
            Err(_) => {
                if !completion { pending.request.fail_log(); }
                pending.armed = false;
                return Err(TransferError::Log);
            }
        };
        if !pending.request.journal.accepts(&receipt) || !receipt.matches_record(header, payload) {
            return Err(TransferError::InvalidState);
        }
        pending.armed = false;
        Ok(())
    }
    pub fn prepare(&mut self, max: usize, direction: Direction) -> Option<WriteTicket<'a>> {
        AuthorizedWrite::prepare(self.lease.stream_mut(), &self.authorized, &self.journal, direction.id(), max)
            .map(|core| WriteTicket { admission: self.lease.admission, core })
    }
    pub fn pending_bytes(&self, ticket: &WriteTicket<'_>, direction: Direction) -> Option<&[u8]> {
        ticket.core.bytes(self.bound_stream(ticket)?, &self.authorized, &self.journal, direction.id())
    }
    pub fn complete(&mut self, ticket: &WriteTicket<'_>, count: usize) -> bool {
        if self.bound_stream(ticket).is_none() { return false; }
        ticket.core.complete(self.stream_mut(), count)
    }
    pub fn cancel(&mut self) { self.stream_mut().cancel(); }
    pub fn fail_log(&mut self) { self.stream_mut().fail_log(); }
}

#[cfg(test)]
mod tests;
