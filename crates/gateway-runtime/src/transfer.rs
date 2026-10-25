//! Trusted async driver for verified stream transitions. The writer's accepted
//! count and the logger's durable acknowledgment are external contracts.
use crate::admission::{CancelOnDrop, Request};
pub use gateway_core::journal::DurableFrame;
use std::{future::Future, io};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction { Upload, Download }
impl Direction { pub(crate) fn id(self) -> u8 { match self { Self::Upload => 0, Self::Download => 1 } } }

/// The record kinds of the audit log. Body kinds carry forwarded bytes under
/// the body chunk ids (1 and up); metadata kinds carry the verified payload
/// codecs in `gateway_core::metadata` under the reserved chunk id 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind { Upload, Download, RequestStart, ResponseHead, Completion }
impl RecordKind {
    pub fn id(self) -> u8 {
        match self {
            Self::Upload => gateway_core::framing::KIND_UPLOAD, Self::Download => gateway_core::framing::KIND_DOWNLOAD,
            Self::RequestStart => gateway_core::framing::KIND_REQUEST_START,
            Self::ResponseHead => gateway_core::framing::KIND_RESPONSE_HEAD,
            Self::Completion => gateway_core::framing::KIND_COMPLETION,
        }
    }
    /// Every kind the verified framing accepts has a name; nothing else does.
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Upload), 1 => Some(Self::Download), 2 => Some(Self::RequestStart),
            3 => Some(Self::ResponseHead), 4 => Some(Self::Completion), _ => None,
        }
    }
    /// The body direction of a body kind; metadata kinds have none.
    pub fn direction(self) -> Option<Direction> {
        match self { Self::Upload => Some(Direction::Upload), Self::Download => Some(Direction::Download), _ => None }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Upload => "upload", Self::Download => "download", Self::RequestStart => "request_start",
            Self::ResponseHead => "response_head", Self::Completion => "completion",
        }
    }
}
impl From<Direction> for RecordKind {
    fn from(direction: Direction) -> Self {
        match direction { Direction::Upload => Self::Upload, Direction::Download => Self::Download }
    }
}

pub struct LogRecord<'a> {
    pub tenant: u64,
    pub request: u64,
    pub chunk: u64,
    pub kind: RecordKind,
    pub bytes: &'a [u8],
}

pub trait AuditLog {
    /// Stable identity of the designated journal; must match every returned receipt.
    fn session_id(&self) -> u128;
    /// Returns an owned journal receipt for this exact record, durable under the logger's documented
    /// crash model. Implementations must bound work and retain any buffer credits
    /// for effects that survive cancellation. The receipt retains its frame until
    /// consumed or dropped. DiskLog supplies this implementation.
    fn append<'a>(&'a mut self, record: LogRecord<'a>)
        -> impl Future<Output = io::Result<DurableFrame>> + Send + 'a;
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError { Read, Write, WriteZero, Flush, Log, InvalidState, CounterExhausted }

#[derive(Debug, PartialEq, Eq)]
pub struct TransferStats {
    pub accepted_bytes: u64,
    pub audit_gap: bool,
}

// Production uses the same resolved owner for dispatch and every body range.
// The direct binding supports embedders with their own trusted writer mapping.
pub(crate) trait BodyBinding: Sync {
    fn bytes<'r>(&self, request: &'r Request<'_>, ticket: &crate::admission::WriteTicket<'_>, direction: Direction) -> Option<&'r [u8]>;
}
#[cfg(test)]
impl BodyBinding for () {
    fn bytes<'r>(&self, request: &'r Request<'_>, ticket: &crate::admission::WriteTicket<'_>, direction: Direction) -> Option<&'r [u8]> {
        request.pending_bytes(ticket, direction)
    }
}
impl<D: Sync, C: Sync> BodyBinding for gateway_core::resolved_route::ResolvedRoute<'_, D, C> {
    fn bytes<'r>(&self, request: &'r Request<'_>, ticket: &crate::admission::WriteTicket<'_>, direction: Direction) -> Option<&'r [u8]> {
        request.routed_bytes(self, ticket, direction)
    }
}

#[cfg(test)]
pub(crate) async fn copy_body<R, W, L>(request: &mut Request<'_>, reader: &mut R,
    writer: &mut W, log: &mut L, direction: Direction) -> Result<TransferStats, TransferError>
where R: AsyncRead + Unpin, W: AsyncWrite + Unpin, L: AuditLog {
    copy_body_bound(request, reader, writer, log, direction, &()).await
}

/// Copy one body sequentially using one outstanding write and one awaited log
/// append. Successful EOF leaves the request usable for the next direction.
/// Errors or cancellation close it. EOF/framing correctness belongs to the HTTP
/// body adapter. No detached task, transparent retry, or whole-body buffering.
pub(crate) async fn copy_body_bound<R, W, L, B>(request: &mut Request<'_>, reader: &mut R,
    writer: &mut W, log: &mut L, direction: Direction, binding: &B) -> Result<TransferStats, TransferError>
where R: AsyncRead + Unpin, W: AsyncWrite + Unpin, L: AuditLog, B: BodyBinding {
    let mut guard = CancelOnDrop { request, armed: true };
    let capacity = guard.request.capacity();
    if capacity == 0 || guard.request.is_closed() { return Err(TransferError::InvalidState); }
    let mut total = 0u64;
    loop {
        // The verified owner drops completed stream storage before allocating
        // its next read buffer, then moves the filled prefix back into the stream.
        let length = guard.request.read_next(reader).await?;
        if length == 0 {
            guard.armed = false;
            return Ok(TransferStats { accepted_bytes: total, audit_gap: guard.request.log_failed() });
        }
        let next_total = total.checked_add(length as u64).ok_or(TransferError::CounterExhausted)?;
        if !guard.request.log_failed() {
            match guard.request.audit_current(log, direction).await {
                Ok(()) | Err(TransferError::Log) => {},
                Err(error) => return Err(error),
            }
        }
        if guard.request.log_failed() && guard.request.strict() { return Err(TransferError::Log); }
        let mut sent = 0;
        while sent < length {
            let ticket = guard.request.prepare(length - sent, direction).ok_or(TransferError::InvalidState)?;
            let bytes = binding.bytes(guard.request, &ticket, direction).ok_or(TransferError::InvalidState)?;
            let count = writer.write(bytes).await.map_err(|_| TransferError::Write)?;
            if !guard.request.complete(&ticket, count) { return Err(TransferError::InvalidState); }
            if count == 0 { return Err(TransferError::WriteZero); }
            sent += count;
        }
        writer.flush().await.map_err(|_| TransferError::Flush)?;
        total = next_total;
    }
}

#[cfg(test)]
pub(crate) fn receipt_for_test(record: LogRecord<'_>) -> DurableFrame {
    let frame = gateway_core::framing::RecordBody::new(gateway_core::framing::Header {
        payload: record.bytes.len() as u32, tenant: record.tenant, request: record.request,
        chunk: record.chunk, kind: record.kind.id(),
    }, record.bytes).unwrap().seal(&[0; 32]);
    let mut journal = gateway_core::journal::Journal::new(0);
    let ticket = journal.begin(frame.bytes().len() as u64).unwrap();
    journal.commit_frame(&ticket, frame).unwrap()
}

#[cfg(test)]
mod tests;
