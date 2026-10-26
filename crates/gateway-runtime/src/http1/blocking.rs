//! The blocking half of the adapter: the same byte movement as the async
//! half, over `std::io::Read`, for code that runs on its own thread with no
//! executor. The cloud shipping client uses it. Like the async half it
//! decides nothing about what a byte means; the parser and the chunk decoder
//! do, and the caller's stream decides how long a read may take.
use super::{HeadError, READ_BYTES};
use gateway_core::headers::{MAX_BYTES, Rejection};
use gateway_core::http1_chunked::{ChunkDecoder, Step};
use gateway_core::http1_framing::Framing;
use gateway_core::http1_head::{StatusHead, StatusProgress, parse_status};
use std::io::{self, Read};

/// Read from `io` until a status head parses. The bytes after the head are
/// returned; what the status means is the exchange machine's decision.
pub(crate) fn read_status_head<R: Read>(io: &mut R, leftover: Vec<u8>) -> Result<(StatusHead, Vec<u8>), HeadError> {
    let mut buffer = leftover;
    loop {
        match parse_status(&buffer) {
            StatusProgress::Complete(head, len) => { let rest = buffer.split_off(len); return Ok((head, rest)); }
            StatusProgress::Rejected(Rejection::TooLarge) => return Err(HeadError::TooLarge),
            StatusProgress::Rejected(Rejection::BadRequest) => return Err(HeadError::Malformed),
            StatusProgress::Incomplete => fill(io, &mut buffer)?,
        }
    }
}
/// Read more head bytes, never past the head limit.
fn fill<R: Read>(io: &mut R, buffer: &mut Vec<u8>) -> Result<(), HeadError> {
    if buffer.len() >= MAX_BYTES { return Err(HeadError::TooLarge); }
    let room = MAX_BYTES - buffer.len();
    let start = buffer.len();
    buffer.resize(start + room.min(READ_BYTES), 0);
    let n = read_uninterrupted(io, &mut buffer[start..]).map_err(|_| HeadError::Io)?;
    buffer.truncate(start + n);
    if n == 0 { return Err(HeadError::Closed); }
    Ok(())
}
/// One read, retried only when the call was interrupted before any byte moved.
fn read_uninterrupted<R: Read>(io: &mut R, out: &mut [u8]) -> io::Result<usize> {
    loop {
        match io.read(out) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            other => return other,
        }
    }
}

/// The body that follows a head, read from `io` after the head's leftover
/// bytes and delimited as `framing` says. Reads yield only body bytes; the
/// end of the body is a clean EOF, and a body that stops early, a chunk
/// coding fault, or data missing after a fixed length is an error.
pub(crate) struct BodyReader<R> { io: R, buffer: Vec<u8>, pos: usize, state: State }
enum State { Length { remaining: u64 }, Chunked(ChunkDecoder), UntilClose, Done, Failed }

impl<R> BodyReader<R> {
    pub(crate) fn new(io: R, leftover: Vec<u8>, framing: Framing) -> Self {
        let state = match framing {
            Framing::Length(0) => State::Done,
            Framing::Length(n) => State::Length { remaining: n },
            Framing::Chunked => State::Chunked(ChunkDecoder::new()),
            Framing::UntilClose => State::UntilClose,
        };
        Self { io, buffer: leftover, pos: 0, state }
    }
}

impl<R: Read> Read for BodyReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() { return Ok(0); }
        loop {
            match &self.state {
                State::Done => return Ok(0),
                State::Failed => return Err(io::ErrorKind::InvalidData.into()),
                _ => {}
            }
            if self.pos < self.buffer.len() {
                let available = &self.buffer[self.pos..];
                match &mut self.state {
                    State::Length { remaining } => {
                        let n = (*remaining).min(available.len() as u64).min(out.len() as u64) as usize;
                        out[..n].copy_from_slice(&available[..n]);
                        self.pos += n;
                        *remaining -= n as u64;
                        if *remaining == 0 { self.state = State::Done; }
                        return Ok(n);
                    }
                    State::UntilClose => {
                        let n = available.len().min(out.len());
                        out[..n].copy_from_slice(&available[..n]);
                        self.pos += n;
                        return Ok(n);
                    }
                    State::Chunked(decoder) => {
                        // Offer at most what the caller can take, so a data step fits.
                        let window = &available[..available.len().min(out.len())];
                        match decoder.feed(window) {
                            Step::Framing(n) => { self.pos += n; }
                            Step::Data(n) => { out[..n].copy_from_slice(&window[..n]); self.pos += n; return Ok(n); }
                            Step::Done(n) => { self.pos += n; self.state = State::Done; return Ok(0); }
                            Step::Rejected => { self.state = State::Failed; return Err(io::ErrorKind::InvalidData.into()); }
                        }
                        continue;
                    }
                    State::Done | State::Failed => unreachable!("handled above"),
                }
            }
            // The buffer is spent: read more body bytes.
            self.buffer.clear();
            self.pos = 0;
            self.buffer.resize(READ_BYTES, 0);
            match read_uninterrupted(&mut self.io, &mut self.buffer) {
                Err(e) => { self.buffer.clear(); self.state = State::Failed; return Err(e); }
                Ok(0) => {
                    self.buffer.clear();
                    return match self.state {
                        State::UntilClose => { self.state = State::Done; Ok(0) }
                        _ => { self.state = State::Failed; Err(io::ErrorKind::UnexpectedEof.into()) }
                    };
                }
                Ok(n) => self.buffer.truncate(n),
            }
        }
    }
}
