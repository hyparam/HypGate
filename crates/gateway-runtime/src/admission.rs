//! This module is trusted Rust, not Verus-verified. It owns registry keys and
//! stream storage so callers cannot return a credit while retaining its stream.
use crate::transfer::{AuditLog, Direction, LogRecord, TransferError};
use gateway_core::policy::{AuthorizedRequest, Policy};
use gateway_core::resource::{RequestKey, ResourceAdmission};
use gateway_core::owned_stream::OwnedStream;
use gateway_core::stream::{StreamChunk, Ticket};
use std::sync::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt};

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
    log_failed: bool,
    lease: Lease<'a>,
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
        Ok(Request { authorized, capacity, log_failed: false, lease })
    }
}

pub struct WriteTicket<'a> {
    admission: &'a Admission,
    core: Ticket,
}

impl<'a> Request<'a> {
    fn stream(&self) -> &StreamChunk {
        match self.lease.state.as_ref().expect("live lease") {
            LeaseState::Streaming(stream) => stream.stream(),
            LeaseState::Reserved(_) => unreachable!("admitted stream"),
        }
    }
    fn stream_mut(&mut self) -> &mut OwnedStream {
        match self.lease.state.as_mut().expect("live lease") {
            LeaseState::Streaming(stream) => stream,
            LeaseState::Reserved(_) => unreachable!("admitted stream"),
        }
    }
    pub fn request_id(&self) -> u64 { self.authorized.request_id() }
    pub fn tenant_id(&self) -> u64 { self.authorized.tenant_id() }
    pub fn origin(&self) -> usize { self.authorized.origin() }
    pub fn credential(&self) -> usize { self.authorized.credential() }
    pub(crate) fn capacity(&self) -> usize { self.capacity }
    pub(crate) fn is_closed(&self) -> bool { self.stream().is_closed() }
    pub(crate) fn log_failed(&self) -> bool { self.log_failed }
    pub(crate) fn strict(&self) -> bool { self.lease.admission.strict }

    pub(crate) async fn read_next<R: AsyncRead + Unpin>(&mut self, reader: &mut R)
        -> Result<usize, TransferError>
    {
        if !self.stream_mut().begin_read() { return Err(TransferError::InvalidState); }
        let length = reader.read(self.stream_mut().read_buffer()).await.map_err(|_| TransferError::Read)?;
        if !self.stream_mut().finish_read(length) { return Err(TransferError::InvalidState); }
        Ok(length)
    }

    pub fn advance(&mut self, bytes: Vec<u8>) -> Option<u64> {
        // Verus models payload length, not Vec backing capacity. Reject excess
        // spare allocation at the trusted ownership boundary before retaining it.
        if bytes.capacity() > self.capacity { return None; }
        self.stream_mut().advance(bytes)
    }
    /// Bind the awaited logger result to this request's current immutable chunk.
    /// The logger remains trusted to report actual durability. Cancellation closes
    /// the stream, since an append may already have had an unknown effect.
    pub async fn audit_current<L: AuditLog>(&mut self, log: &mut L, direction: Direction)
        -> Result<(), TransferError>
    {
        struct Pending<'r, 'a> { request: &'r mut Request<'a>, armed: bool }
        impl Drop for Pending<'_, '_> {
            fn drop(&mut self) { if self.armed { self.request.cancel(); } }
        }
        let mut pending = Pending { request: self, armed: true };
        if pending.request.is_closed() || pending.request.log_failed() {
            return Err(TransferError::InvalidState);
        }
        let direction_id = match direction { Direction::Upload => 0, Direction::Download => 1 };
        let (header, bytes) = pending.request.stream()
            .audit_record(&pending.request.authorized, direction_id)
            .ok_or(TransferError::InvalidState)?;
        let chunk = header.chunk;
        let record = LogRecord { tenant: header.tenant, request: header.request,
            chunk, direction, bytes };
        let receipt = match log.append(record).await {
            Ok(receipt) => receipt,
            Err(_) => {
                pending.request.fail_log();
                pending.armed = false;
                return Err(TransferError::Log);
            }
        };
        let Some(LeaseState::Streaming(stream)) = pending.request.lease.state.as_mut() else {
            unreachable!("admitted stream")
        };
        if !stream.acknowledge_receipt(&pending.request.authorized, direction_id, &receipt) {
            return Err(TransferError::InvalidState);
        }
        pending.armed = false;
        Ok(())
    }
    pub fn prepare(&mut self, max: usize) -> Option<WriteTicket<'a>> {
        self.stream_mut().prepare(max).map(|core| WriteTicket { admission: self.lease.admission, core })
    }
    pub fn pending_bytes(&self, ticket: &WriteTicket<'_>) -> Option<&[u8]> {
        if !std::ptr::eq(ticket.admission, self.lease.admission) { return None; }
        self.stream().pending_bytes(&ticket.core)
    }
    pub fn complete(&mut self, ticket: &WriteTicket<'_>, count: usize) -> bool {
        if !std::ptr::eq(ticket.admission, self.lease.admission) { return false; }
        self.stream_mut().complete(&ticket.core, count)
    }
    pub fn cancel(&mut self) { self.stream_mut().cancel(); }
    pub fn fail_log(&mut self) { self.log_failed = true; self.stream_mut().fail_log(); }
}
