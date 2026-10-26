//! The HTTP/1.1 wire adapter over the verified codec. Heads are parsed by
//! `gateway_core::http1_head`, framing is chosen by `http1_framing`, chunk
//! coding is `http1_chunked`, and heads are written by `http1_write`. This
//! module only moves bytes between sockets and those functions: it reads
//! into bounded buffers, hands the buffer to the parser, copies the body
//! bytes the decoder names, and writes the bytes the encoders produce. It
//! makes no decision about what a byte means. `blocking` is the same over
//! `std::io` for threads that run no executor.
use gateway_core::headers::{Field, MAX_BYTES, Rejection};
use gateway_core::http1_chunked::{ChunkDecoder, Step};
use gateway_core::http1_exchange::ChunkStream;
use gateway_core::http1_framing::Framing;
use gateway_core::http1_head::{RequestHead, RequestProgress, StatusHead, StatusProgress, parse_request, parse_status};
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

pub(crate) mod blocking;

/// One socket read, and the most body bytes buffered ahead of the copy.
pub(crate) const READ_BYTES: usize = 32 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeadError { TooLarge, Malformed, Closed, Io }

/// Read from `io` until a request head parses. The bytes after the head are returned.
pub(crate) async fn read_request_head<R: AsyncRead + Unpin>(io: &mut R, leftover: Vec<u8>) -> Result<(RequestHead, Vec<u8>), HeadError> {
    let mut buffer = leftover;
    loop {
        match parse_request(&buffer) {
            RequestProgress::Complete(head, len) => { let rest = buffer.split_off(len); return Ok((head, rest)); }
            RequestProgress::Rejected(Rejection::TooLarge) => return Err(HeadError::TooLarge),
            RequestProgress::Rejected(Rejection::BadRequest) => return Err(HeadError::Malformed),
            RequestProgress::Incomplete => fill(io, &mut buffer).await?,
        }
    }
}
/// Read from `io` until a status head parses. The bytes after the head are
/// returned; what the status means is the exchange machine's decision.
pub(crate) async fn read_status_head<R: AsyncRead + Unpin>(io: &mut R, leftover: Vec<u8>) -> Result<(StatusHead, Vec<u8>), HeadError> {
    let mut buffer = leftover;
    loop {
        match parse_status(&buffer) {
            StatusProgress::Complete(head, len) => { let rest = buffer.split_off(len); return Ok((head, rest)); }
            StatusProgress::Rejected(Rejection::TooLarge) => return Err(HeadError::TooLarge),
            StatusProgress::Rejected(Rejection::BadRequest) => return Err(HeadError::Malformed),
            StatusProgress::Incomplete => fill(io, &mut buffer).await?,
        }
    }
}
/// Read more head bytes, never past the head limit.
async fn fill<R: AsyncRead + Unpin>(io: &mut R, buffer: &mut Vec<u8>) -> Result<(), HeadError> {
    if buffer.len() >= MAX_BYTES { return Err(HeadError::TooLarge); }
    let room = MAX_BYTES - buffer.len();
    let start = buffer.len();
    buffer.resize(start + room.min(READ_BYTES), 0);
    let n = io.read(&mut buffer[start..]).await.map_err(|_| HeadError::Io)?;
    buffer.truncate(start + n);
    if n == 0 { return Err(HeadError::Closed); }
    Ok(())
}

/// The body that follows a head, read from `io` after the head's leftover
/// bytes and delimited as `framing` says. Reads yield only body bytes; the
/// end of the body is a clean EOF, and a body that stops early, a chunk
/// coding fault, or data after a fixed length is an error.
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
    pub(crate) fn into_inner(self) -> R { self.io }
}

impl<R: AsyncRead + Unpin> AsyncRead for BodyReader<R> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 { return Poll::Ready(Ok(())); }
        loop {
            match &mut this.state {
                State::Done => return Poll::Ready(Ok(())),
                State::Failed => return Poll::Ready(Err(io::ErrorKind::InvalidData.into())),
                _ => {}
            }
            if this.pos < this.buffer.len() {
                let available = &this.buffer[this.pos..];
                match &mut this.state {
                    State::Length { remaining } => {
                        let n = (*remaining).min(available.len() as u64).min(out.remaining() as u64) as usize;
                        out.put_slice(&available[..n]);
                        this.pos += n;
                        *remaining -= n as u64;
                        if *remaining == 0 { this.state = State::Done; }
                        return Poll::Ready(Ok(()));
                    }
                    State::UntilClose => {
                        let n = available.len().min(out.remaining());
                        out.put_slice(&available[..n]);
                        this.pos += n;
                        return Poll::Ready(Ok(()));
                    }
                    State::Chunked(decoder) => {
                        // Offer at most what the caller can take, so a data step fits.
                        let window = &available[..available.len().min(out.remaining())];
                        match decoder.feed(window) {
                            Step::Framing(n) => { this.pos += n; }
                            Step::Data(n) => { out.put_slice(&window[..n]); this.pos += n; return Poll::Ready(Ok(())); }
                            Step::Done(n) => { this.pos += n; this.state = State::Done; return Poll::Ready(Ok(())); }
                            Step::Rejected => { this.state = State::Failed; return Poll::Ready(Err(io::ErrorKind::InvalidData.into())); }
                        }
                        continue;
                    }
                    State::Done | State::Failed => unreachable!("handled above"),
                }
            }
            // The buffer is spent: read more body bytes.
            this.buffer.clear();
            this.pos = 0;
            this.buffer.resize(READ_BYTES, 0);
            let mut fresh = ReadBuf::new(&mut this.buffer);
            match Pin::new(&mut this.io).poll_read(cx, &mut fresh) {
                Poll::Pending => { this.buffer.clear(); return Poll::Pending; }
                Poll::Ready(Err(e)) => { this.buffer.clear(); this.state = State::Failed; return Poll::Ready(Err(e)); }
                Poll::Ready(Ok(())) => {
                    let n = fresh.filled().len();
                    this.buffer.truncate(n);
                    if n == 0 {
                        return match this.state {
                            State::UntilClose => { this.state = State::Done; Poll::Ready(Ok(())) }
                            _ => { this.state = State::Failed; Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())) }
                        };
                    }
                }
            }
        }
    }
}

/// Writes a body to `io` as chunks through a verified `ChunkStream`: each
/// `write` becomes one chunk and `shutdown` writes the last chunk and
/// flushes. The underlying stream is not closed; the caller decides what
/// happens to the connection, and takes the stream back to finish its machine.
pub(crate) struct ChunkedWriter<W> { io: W, stream: Option<ChunkStream>, pending: Vec<u8>, written: usize, claim: Option<usize> }
impl<W> ChunkedWriter<W> {
    pub(crate) fn new(io: W, stream: ChunkStream) -> Self { Self { io, stream: Some(stream), pending: Vec::new(), written: 0, claim: None } }
    /// The stream, for the machine that issued it; ended only if `shutdown` completed.
    pub(crate) fn into_stream(mut self) -> ChunkStream { self.stream.take().expect("live stream") }
}
impl<W: AsyncWrite + Unpin> ChunkedWriter<W> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            match Pin::new(&mut self.io).poll_write(cx, &self.pending[self.written..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => self.written += n,
            }
        }
        self.pending.clear();
        self.written = 0;
        Poll::Ready(Ok(()))
    }
}
impl<W: AsyncWrite + Unpin> AsyncWrite for ChunkedWriter<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let Some(stream) = this.stream.as_mut() else { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); };
        if stream.is_ended() { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        if bytes.is_empty() { return Poll::Ready(Ok(0)); }
        if this.claim.is_none() {
            // A new chunk; a repeated poll of the same write keeps draining the old one.
            this.pending = stream.frame(bytes);
            this.written = 0;
            this.claim = Some(bytes.len());
        }
        match this.poll_drain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(this.claim.take().unwrap_or(0))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_flush(cx),
            other => other,
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let Some(stream) = this.stream.as_mut() else { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); };
        if !stream.is_ended() && this.claim.is_none() {
            this.pending = stream.end();
            this.written = 0;
        }
        match this.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.io).poll_flush(cx),
            other => other,
        }
    }
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
