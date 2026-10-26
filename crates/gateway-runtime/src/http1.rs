//! The HTTP/1.1 wire adapter over the verified codec. Heads are parsed by
//! `gateway_core::http1_head`, framing is chosen by `http1_framing`, chunk
//! coding is `http1_chunked`, and heads are written by `http1_write`. This
//! module only moves bytes between blocking sockets and those functions: it
//! reads into bounded buffers, hands the buffer to the parser, copies the body
//! bytes the decoder names, and writes the bytes the encoders produce. It
//! makes no decision about what a byte means, and how long a read may take
//! is the caller's stream's business (`net::Timed`).
use crate::net::{read_uninterrupted, write_uninterrupted};
use gateway_core::headers::{Field, MAX_BYTES, Rejection};
use gateway_core::http1_chunked::{ChunkDecoder, Step};
use gateway_core::http1_exchange::ChunkStream;
use gateway_core::http1_framing::Framing;
use gateway_core::http1_head::{RequestHead, RequestProgress, StatusHead, StatusProgress, parse_request, parse_status};
use std::io::{self, Read, Write};

/// One socket read, and the most body bytes buffered ahead of the copy.
pub(crate) const READ_BYTES: usize = 32 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeadError { TooLarge, Malformed, Closed, Io }

/// Read from `io` until a request head parses. The bytes after the head are returned.
pub(crate) fn read_request_head<R: Read>(io: &mut R, leftover: Vec<u8>) -> Result<(RequestHead, Vec<u8>), HeadError> {
    let mut buffer = leftover;
    loop {
        match parse_request(&buffer) {
            RequestProgress::Complete(head, len) => { let rest = buffer.split_off(len); return Ok((head, rest)); }
            RequestProgress::Rejected(Rejection::TooLarge) => return Err(HeadError::TooLarge),
            RequestProgress::Rejected(Rejection::BadRequest) => return Err(HeadError::Malformed),
            RequestProgress::Incomplete => fill(io, &mut buffer)?,
        }
    }
}
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
    /// Whether the whole body was read and well framed.
    pub(crate) fn is_complete(&self) -> bool { matches!(self.state, State::Done) }
    /// The stream, once the body is complete; bytes read ahead are none, since reads stop at the body's end.
    #[cfg(test)]
    pub(crate) fn into_inner(self) -> R { self.io }
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

/// Writes a body to `io` as chunks through a verified `ChunkStream`: each
/// `write` becomes one chunk and `finish` writes the last chunk and flushes.
/// The underlying stream is not closed; the caller decides what happens to
/// the connection, and takes the stream back to finish its machine.
pub(crate) struct ChunkedWriter<W> { io: W, stream: ChunkStream }
impl<W> ChunkedWriter<W> {
    pub(crate) fn new(io: W, stream: ChunkStream) -> Self { Self { io, stream } }
    /// The stream for the machine that issued it, ended only if `finish` completed, and the writer.
    pub(crate) fn into_parts(self) -> (W, ChunkStream) { (self.io, self.stream) }
}
impl<W: Write> ChunkedWriter<W> {
    /// The last chunk, then a flush. The stream is ended afterwards.
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if self.stream.is_ended() { return Err(io::ErrorKind::BrokenPipe.into()); }
        let bytes = self.stream.end();
        self.io.write_all(&bytes)?;
        self.io.flush()
    }
}
impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.stream.is_ended() { return Err(io::ErrorKind::BrokenPipe.into()); }
        if bytes.is_empty() { return Ok(0); }
        let framed = self.stream.frame(bytes);
        self.io.write_all(&framed)?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> { self.io.flush() }
}

/// Write everything, retrying interrupted calls, as `write_all` does, but
/// through the crate's one retry point.
pub(crate) fn write_fully<W: Write + ?Sized>(io: &mut W, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        match write_uninterrupted(io, bytes)? {
            0 => return Err(io::ErrorKind::WriteZero.into()),
            n => bytes = &bytes[n..],
        }
    }
    Ok(())
}

/// A field for the writers.
pub(crate) fn field(name: &'static [u8], value: Vec<u8>) -> Field { Field { name: name.to_vec(), value, sensitive: false } }
/// The reason phrase written for a status the gateway produces itself.
pub(crate) fn reason(status: u16) -> &'static [u8] {
    match status {
        100 => b"Continue", 200 => b"OK", 400 => b"Bad Request", 401 => b"Unauthorized", 405 => b"Method Not Allowed",
        408 => b"Request Timeout", 431 => b"Request Header Fields Too Large", 500 => b"Internal Server Error",
        502 => b"Bad Gateway", 503 => b"Service Unavailable", 504 => b"Gateway Timeout", _ => b"",
    }
}
