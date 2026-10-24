//! Trusted async driver for verified stream transitions. The writer's accepted
//! count and the logger's durable acknowledgment are external contracts.
use crate::admission::Request;
pub use gateway_core::journal::DurableFrame;
use std::{future::Future, io};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction { Upload, Download }

pub struct LogRecord<'a> {
    pub tenant: u64,
    pub request: u64,
    pub chunk: u64,
    pub direction: Direction,
    pub bytes: &'a [u8],
}

pub trait AuditLog {
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

// Dropping a pending future must also close the stream: the underlying I/O may
// have had an effect whose completion is now unknown. Never reuse/replay it.
struct CancelOnDrop<'r, 'a> { request: &'r mut Request<'a>, armed: bool }
impl Drop for CancelOnDrop<'_, '_> {
    fn drop(&mut self) { if self.armed { self.request.cancel(); } }
}

/// Copy one body sequentially using one outstanding write and one awaited log
/// append. Successful EOF leaves the request usable for the next direction.
/// Errors or cancellation close it. EOF/framing correctness belongs to the HTTP
/// body adapter. No detached task, transparent retry, or whole-body buffering.
pub async fn copy_body<R, W, L>(request: &mut Request<'_>, reader: &mut R,
    writer: &mut W, log: &mut L, direction: Direction) -> Result<TransferStats, TransferError>
where R: AsyncRead + Unpin, W: AsyncWrite + Unpin, L: AuditLog {
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
            let ticket = guard.request.prepare(length - sent).ok_or(TransferError::InvalidState)?;
            let bytes = guard.request.pending_bytes(&ticket).ok_or(TransferError::InvalidState)?;
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
        chunk: record.chunk, direction: match record.direction { Direction::Upload => 0, Direction::Download => 1 },
    }, record.bytes).unwrap().seal(&[0; 32]);
    let mut journal = gateway_core::journal::Journal::new(0);
    let ticket = journal.begin(frame.bytes().len() as u64).unwrap();
    journal.commit_frame(&ticket, frame).unwrap()
}

#[cfg(test)]
mod tests;
