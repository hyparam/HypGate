//! This module is trusted Rust, not Verus-verified. It owns registry keys and
//! stream storage so callers cannot return a credit while retaining its stream.
use gateway_core::policy::{AuthorizedRequest, Policy};
use gateway_core::resource::{RequestKey, ResourceAdmission};
use gateway_core::stream::{StreamChunk, Ticket};
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
}

struct Lease<'a> {
    admission: &'a Admission,
    key: RequestKey,
}

impl Drop for Lease<'_> {
    fn drop(&mut self) {
        // Poison permanently closes admission. Do not recover potentially broken
        // registry state merely to reclaim a credit.
        if let Ok(mut registry) = self.admission.registry.lock() {
            let released = registry.release(&self.key);
            debug_assert!(released, "private lease must own its registry slot");
        }
    }
}

/// Fields drop in declaration order: stream storage before the capacity lease.
/// There is no public extraction, mutable core reference, or cloning operation.
pub struct Request<'a> {
    authorized: AuthorizedRequest<'a>,
    stream: StreamChunk,
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
        Self { registry: Mutex::new(ResourceAdmission::new(requests, chunk_bytes)), policy, strict }
    }

    pub fn admit(&self, digest: &[u8], selector: u64) -> Result<Request<'_>, AdmissionError> {
        let identity = self.policy.authenticate(digest).ok_or(AdmissionError::Unauthorized)?;
        let (mut lease, capacity) = {
            let mut registry = self.registry.lock().map_err(|_| AdmissionError::Unavailable)?;
            let key = registry.acquire().ok_or(AdmissionError::AtCapacity)?;
            let capacity = registry.capacity(&key).expect("fresh registry key");
            (Lease { admission: self, key }, capacity)
        };
        // Any early return drops the lease, including failed route authorization.
        let authorized = identity.authorize(selector, lease.key.owner())
            .ok_or(AdmissionError::Unauthorized)?;
        let stream = {
            let registry = self.registry.lock().map_err(|_| AdmissionError::Unavailable)?;
            registry.authorized_stream(&mut lease.key, &authorized, self.strict)
                .ok_or(AdmissionError::Unavailable)?
        };
        Ok(Request { authorized, stream, capacity, log_failed: false, lease })
    }
}

pub struct WriteTicket<'a> {
    admission: &'a Admission,
    core: Ticket,
}

impl<'a> Request<'a> {
    pub fn request_id(&self) -> u64 { self.authorized.request_id() }
    pub fn tenant_id(&self) -> u64 { self.authorized.tenant_id() }
    pub fn origin(&self) -> usize { self.authorized.origin() }
    pub fn credential(&self) -> usize { self.authorized.credential() }
    pub(crate) fn capacity(&self) -> usize { self.capacity }
    pub(crate) fn is_closed(&self) -> bool { self.stream.is_closed() }
    pub(crate) fn log_bytes(&self) -> &[u8] { self.stream.log_bytes() }
    pub(crate) fn log_failed(&self) -> bool { self.log_failed }
    pub(crate) fn strict(&self) -> bool { self.lease.admission.strict }

    pub(crate) fn discard_completed(&mut self) -> bool { self.stream.discard_completed() }

    pub fn advance(&mut self, bytes: Vec<u8>) -> Option<u64> {
        // Verus models payload length, not Vec backing capacity. Reject excess
        // spare allocation at the trusted ownership boundary before retaining it.
        if bytes.capacity() > self.capacity { return None; }
        self.stream.advance(bytes)
    }
    pub fn acknowledge(&mut self, chunk: u64, end: usize) -> bool {
        self.stream.acknowledge(self.lease.key.owner(), chunk, end)
    }
    pub fn prepare(&mut self, max: usize) -> Option<WriteTicket<'a>> {
        self.stream.prepare(max).map(|core| WriteTicket { admission: self.lease.admission, core })
    }
    pub fn pending_bytes(&self, ticket: &WriteTicket<'_>) -> Option<&[u8]> {
        if !std::ptr::eq(ticket.admission, self.lease.admission) { return None; }
        self.stream.pending_bytes(&ticket.core)
    }
    pub fn complete(&mut self, ticket: &WriteTicket<'_>, count: usize) -> bool {
        if !std::ptr::eq(ticket.admission, self.lease.admission) { return false; }
        self.stream.complete(&ticket.core, count)
    }
    pub fn cancel(&mut self) { self.stream.cancel(); }
    pub fn fail_log(&mut self) { self.log_failed = true; self.stream.fail_log(); }
}
