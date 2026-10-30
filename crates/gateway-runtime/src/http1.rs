//! The HTTP/1.1 wire adapter over the verified codec. Heads are parsed by
//! `gateway_core::http1_head`, framing is chosen by `http1_framing`, chunk
//! coding is `http1_chunked`, bodies are delimited by `http1_body`, and heads
//! are written by `http1_write`; the read buffers, their cursors, and the
//! order bytes are fed are the verified drivers in `body_reader`, and the
//! write loop and chunk writer are the verified drivers in `sink`. This
//! module only moves bytes between blocking sockets and those functions: one
//! socket read appends to the driver's buffer, the verified body reader copies
//! decoded bytes into the caller's buffer, and one socket write takes the prefix
//! the driver offers. It
//! makes no decision about what a byte means, and how long a read may take
//! is the caller's stream's business (`net::Timed`).
use crate::net::{read_uninterrupted, write_uninterrupted};
use gateway_core::body_reader::{Fill, Read as BodyRead, Source};
use gateway_core::headers::Field;
use gateway_core::http1_exchange::ChunkStream;
use gateway_core::http1_framing::Framing;
use gateway_core::http1_head::{RequestHead, StatusHead};
use gateway_core::sink::{ChunkWriter, Put, Sink, WriteError};
use std::io::{self, Read, Write};

pub(crate) use gateway_core::body_reader::HeadError;

/// The socket as the verified drivers see it: one read appends up to `max`
/// bytes, one write takes a prefix of what is offered, or either reports the
/// close or the failure. The last failure is kept so the drivers' callers
/// can return it.
struct Wire<R> { io: R, error: Option<io::Error> }
impl<R> Wire<R> {
    fn new(io: R) -> Self { Wire { io, error: None } }
    /// The error for a driver's failure: the stored one, or the kind the outcome names.
    fn failure(&mut self, error: WriteError) -> io::Error {
        match error {
            WriteError::Closed => io::ErrorKind::WriteZero.into(),
            WriteError::Failed => self.error.take().unwrap_or_else(|| io::ErrorKind::Other.into()),
        }
    }
}
impl<W: Write> Sink for Wire<W> {
    fn put(&mut self, bytes: &[u8]) -> Put {
        match write_uninterrupted(&mut self.io, bytes) {
            Err(e) => { self.error = Some(e); Put::Failed }
            Ok(0) => Put::Closed,
            Ok(n) => Put::Wrote(n.min(bytes.len())),
        }
    }
}
impl<R: Read> Source for Wire<R> {
    fn fill(&mut self, buffer: &mut Vec<u8>, max: usize) -> Fill {
        let start = buffer.len();
        buffer.resize(start.saturating_add(max), 0);
        let Some(room) = buffer.get_mut(start..) else { buffer.truncate(start); return Fill::Failed };
        match read_uninterrupted(&mut self.io, room) {
            Err(e) => { buffer.truncate(start); self.error = Some(e); Fill::Failed }
            Ok(0) => { buffer.truncate(start); Fill::Closed }
            Ok(n) => { buffer.truncate(start.saturating_add(n.min(max))); Fill::Bytes }
        }
    }
}

/// Read from `io` until a request head parses. The bytes after the head are returned.
pub(crate) fn read_request_head<R: Read>(io: &mut R, leftover: Vec<u8>) -> Result<(RequestHead, Vec<u8>), HeadError> {
    gateway_core::body_reader::read_request_head(&mut Wire::new(io), leftover).map(|r| (r.head, r.rest))
}
/// Read from `io` until a status head parses. The bytes after the head are
/// returned; what the status means is the exchange machine's decision.
pub(crate) fn read_status_head<R: Read>(io: &mut R, leftover: Vec<u8>) -> Result<(StatusHead, Vec<u8>), HeadError> {
    gateway_core::body_reader::read_status_head(&mut Wire::new(io), leftover).map(|r| (r.head, r.rest))
}

/// The body that follows a head, read from `io` after the head's leftover
/// bytes and delimited as `framing` says. Reads yield only body bytes; the
/// end of the body is a clean EOF, and a body that stops early, a chunk
/// coding fault, or data missing after a fixed length is an error. The
/// buffer, its cursor, and the decoder are the verified driver's; this type
/// owns the socket; the verified driver's `read_into` copies decoded bytes.
pub(crate) struct BodyReader<R> { wire: Wire<R>, driver: gateway_core::body_reader::BodyReader }

impl<R> BodyReader<R> {
    pub(crate) fn new(io: R, leftover: Vec<u8>, framing: Framing) -> Self {
        Self { wire: Wire::new(io), driver: gateway_core::body_reader::BodyReader::new(leftover, framing) }
    }
    /// Whether the whole body was read and well framed.
    pub(crate) fn is_complete(&self) -> bool { self.driver.is_complete() }
}

impl<R: Read> Read for BodyReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() { return Ok(0); }
        match self.driver.read_into(&mut self.wire, out) {
            BodyRead::Data(_, n) => Ok(n),
            BodyRead::End => Ok(0),
            BodyRead::Truncated => Err(io::ErrorKind::UnexpectedEof.into()),
            BodyRead::Malformed => Err(io::ErrorKind::InvalidData.into()),
            BodyRead::Failed => Err(self.wire.error.take().unwrap_or_else(|| io::ErrorKind::InvalidData.into())),
        }
    }
}

/// Writes a body to `io` as chunks through the verified chunk writer: each
/// `write` becomes one chunk and `finish` writes the last chunk and flushes.
/// The underlying stream is not closed; the caller decides what happens to
/// the connection, and takes the stream back to finish its machine.
pub(crate) struct ChunkedWriter<W> { driver: ChunkWriter<Wire<W>> }
impl<W: Write> ChunkedWriter<W> {
    pub(crate) fn new(io: W, stream: ChunkStream) -> Self { Self { driver: ChunkWriter::new(Wire::new(io), stream) } }
    /// The stream for the machine that issued it, ended only if `finish` completed, and the writer.
    pub(crate) fn into_parts(self) -> (W, ChunkStream) { let (wire, stream) = self.driver.into_parts(); (wire.io, stream) }
    /// The last chunk, then a flush. The stream is ended afterwards. The
    /// production driver ends the stream itself and writes the last chunk
    /// through its own client write; the test fixtures use this.
    #[cfg(test)]
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        if self.driver.is_ended() || self.driver.has_failed() { return Err(io::ErrorKind::BrokenPipe.into()); }
        if let Err(e) = self.driver.finish() { return Err(self.driver.sink.failure(e)); }
        self.driver.sink.io.flush()
    }
}
impl<W: Write> Write for ChunkedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.driver.is_ended() || self.driver.has_failed() { return Err(io::ErrorKind::BrokenPipe.into()); }
        if bytes.is_empty() { return Ok(0); }
        match self.driver.write(bytes) {
            Ok(()) => Ok(bytes.len()),
            Err(e) => Err(self.driver.sink.failure(e)),
        }
    }
    fn flush(&mut self) -> io::Result<()> { self.driver.sink.io.flush() }
}

/// Write everything, through the verified write loop and the crate's one
/// retry point. A write that accepts nothing is `WriteZero`, as `write_all`
/// reports it.
pub(crate) fn write_fully<W: Write + ?Sized>(io: &mut W, bytes: &[u8]) -> io::Result<()> {
    let mut wire = Wire::new(io);
    match gateway_core::sink::write_all(&mut wire, bytes).result {
        Ok(()) => Ok(()),
        Err(e) => Err(wire.failure(e)),
    }
}

/// One client exchange over `io` under the verified driver: the head and
/// body written once, in order, the reply head read past interim ones, and
/// the reply body read within `cap`. The socket's own error, if the wire
/// failed, is not needed by the caller, who classifies by its deadline.
pub(crate) fn client_exchange<IO: Read + Write>(io: &mut IO, head: &[u8], body: &[u8], cap: usize)
    -> Result<gateway_core::client_exchange::Reply, gateway_core::client_exchange::ClientFault>
{
    gateway_core::client_exchange::exchange(&mut Wire::new(io), head, body, cap).result
}

/// A field for the writers.
pub(crate) fn field(name: &'static [u8], value: Vec<u8>) -> Field { Field { name: name.to_vec(), value, sensitive: false } }
/// The reason phrase for a status a test fixture writes; the production
/// driver's phrases live in `gateway_core::exchange_driver`.
#[cfg(test)]
pub(crate) fn reason(status: u16) -> &'static [u8] {
    match status {
        100 => b"Continue", 200 => b"OK", 400 => b"Bad Request", 401 => b"Unauthorized", 405 => b"Method Not Allowed",
        408 => b"Request Timeout", 431 => b"Request Header Fields Too Large", 500 => b"Internal Server Error",
        502 => b"Bad Gateway", 503 => b"Service Unavailable", 504 => b"Gateway Timeout", _ => b"",
    }
}
