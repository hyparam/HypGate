//! Blocking shell around the verified body-copy machine. The reader's bytes,
//! the writer's accepted count, and the logger's durable acknowledgment are
//! external contracts; which of them happens next is the machine's decision.
use crate::admission::{CancelOnDrop, Request};
use crate::net::{read_uninterrupted, write_uninterrupted};
pub use gateway_core::audit_receipt::AuditReceipt;
use gateway_core::{body_copy::{Action, BodyCopy, Failure}};
use std::io::{self, Read, Write};

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
    /// Returns an owned journal receipt for this exact record, durable under
    /// the logger's documented crash model. Implementations must bound their
    /// work: this blocks the calling thread. The receipt retains its frame
    /// until consumed or dropped. DiskLog supplies this implementation.
    fn append(&mut self, record: LogRecord<'_>) -> io::Result<AuditReceipt>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransferError { Read, Write, WriteZero, Flush, Log, InvalidState, CounterExhausted }
impl From<Failure> for TransferError {
    fn from(failure: Failure) -> Self {
        match failure {
            Failure::Read => Self::Read, Failure::Write => Self::Write, Failure::WriteZero => Self::WriteZero,
            Failure::Flush => Self::Flush, Failure::Log => Self::Log, Failure::InvalidState => Self::InvalidState,
            Failure::CounterExhausted => Self::CounterExhausted,
        }
    }
}

#[cfg(test)]
pub(crate) fn copy_body<R, W, L>(request: &mut Request<'_>, reader: &mut R,
    writer: &mut W, log: &mut L, direction: Direction) -> Result<BodyCopy, TransferError>
where R: Read, W: Write, L: AuditLog {
    copy_body_bound(request, reader, writer, log, direction)
}

/// Copy one body under the verified `BodyCopy` machine. The machine names each
/// effect (read, append, write, flush); this loop performs it and reports the
/// result back. Nothing here decides what is read, logged, released, or
/// counted. Successful EOF leaves the request usable for the next direction;
/// errors or a panic close it. EOF/framing correctness belongs to the HTTP
/// body adapter. No detached thread, transparent retry, or whole-body buffering.
pub(crate) fn copy_body_bound<R, W, L>(request: &mut Request<'_>, reader: &mut R,
    writer: &mut W, log: &mut L, direction: Direction) -> Result<BodyCopy, TransferError>
where R: Read, W: Write, L: AuditLog {
    let mut guard = CancelOnDrop { request, armed: true };
    let owner = guard.request.owned().ok_or(TransferError::InvalidState)?;
    let mut copy = BodyCopy::begin(owner, direction.id()).ok_or(TransferError::InvalidState)?;
    loop {
        match copy.next() {
            Action::Read => {
                let Some((stream, _, _)) = guard.request.parts() else { return Err(TransferError::InvalidState) };
                if copy.begin_read(stream) {
                    let length = read_uninterrupted(reader, copy.read_buffer(stream)).ok();
                    copy.finish_read(stream, length);
                }
            }
            Action::Audit => {
                let session = log.session_id();
                let Some((stream, authority, journal)) = guard.request.parts() else { return Err(TransferError::InvalidState) };
                if let Some((header, bytes)) = copy.audit_record(stream, authority, journal, session) {
                    let record = LogRecord { tenant: header.tenant, request: header.request, chunk: header.chunk,
                        kind: direction.into(), bytes };
                    let receipt = log.append(record).ok();
                    copy.finish_audit(stream, authority, journal, receipt.as_ref());
                }
            }
            Action::Write => {
                let Some((stream, context, journal)) = guard.request.copy_parts() else { return Err(TransferError::InvalidState) };
                if let Some((write, bytes)) = context.write_bytes(&mut copy, stream, journal) {
                    let count = write_uninterrupted(writer, bytes).ok();
                    copy.finish_write(stream, &write, count);
                }
            }
            Action::Flush => {
                let ok = writer.flush().is_ok();
                let Some((stream, _, _)) = guard.request.parts() else { return Err(TransferError::InvalidState) };
                copy.finish_flush(stream, ok);
            }
            Action::Done => { guard.armed = false; return Ok(copy); }
            Action::Failed(failure) => return Err(failure.into()),
        }
    }
}

#[cfg(test)]
pub(crate) fn receipt_for_test(record: LogRecord<'_>) -> AuditReceipt {
    let frame = gateway_core::framing::RecordBody::new(gateway_core::framing::Header {
        payload: record.bytes.len() as u32, tenant: record.tenant, request: record.request,
        chunk: record.chunk, kind: record.kind.id(),
    }, record.bytes).unwrap().seal(&[0; 32]);
    let mut journal = gateway_core::journal::Journal::new(0);
    let ticket = journal.begin(frame.bytes().len() as u64).unwrap();
    journal.commit_frame(&ticket, frame).unwrap().into_receipt()
}

#[cfg(test)]
mod tests;
