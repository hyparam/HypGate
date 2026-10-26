//! A small blocking HTTP/1.1 client and fixture server for tests, built on
//! the verified codec. Peers in tests speak the same bytes the gateway does,
//! and raw byte fixtures cover the malformed cases.
use crate::http1::{self, BodyReader, ChunkedWriter, read_request_head, read_status_head};
use gateway_core::headers::Field;
use gateway_core::http1_framing::{Framing, framing};
use gateway_core::http1_head::{RequestHead, StatusHead};
use gateway_core::http1_write::{write_request_head, write_status_head};
use std::io::{self, Read, Write};

pub(crate) fn field(name: &str, value: &str) -> Field {
    Field { name: name.as_bytes().to_vec(), value: value.as_bytes().to_vec(), sensitive: false }
}
pub(crate) fn value_of<'a>(fields: &'a [Field], name: &str) -> Option<&'a [u8]> {
    fields.iter().find(|f| f.name == name.as_bytes()).map(|f| f.value.as_slice())
}
pub(crate) fn has(fields: &[Field], name: &str) -> bool { value_of(fields, name).is_some() }

/// A parsed request with its whole body.
pub(crate) struct Received { pub head: RequestHead, pub body: Vec<u8> }
impl Received {
    pub(crate) fn header(&self, name: &str) -> Option<&str> { value_of(&self.head.fields, name).and_then(|v| std::str::from_utf8(v).ok()) }
    pub(crate) fn target(&self) -> &str { std::str::from_utf8(&self.head.target).unwrap() }
}

/// Read one request and all of its body from `io`.
pub(crate) fn read_request<IO: Read>(io: &mut IO) -> io::Result<Received> {
    let (head, leftover) = read_request_head(io, Vec::new()).map_err(|e| io::Error::other(format!("{e:?}")))?;
    let framing = framing(&head.fields, true).map_err(|_| io::Error::other("framing"))?;
    let mut reader = BodyReader::new(io, leftover, framing);
    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    Ok(Received { head, body })
}

/// Write a complete response with a Content-Length body and close nothing.
pub(crate) fn write_response<IO: Write>(io: &mut IO, status: u16, fields: &[(&str, &str)], body: &[u8]) -> io::Result<()> {
    let mut all: Vec<Field> = fields.iter().map(|(n, v)| field(n, v)).collect();
    all.push(field("content-length", &body.len().to_string()));
    all.push(field("connection", "close"));
    let mut bytes = Vec::new();
    write_status_head(status, http1::reason(status), &all, &mut bytes);
    bytes.extend_from_slice(body);
    io.write_all(&bytes)?;
    io.flush()
}

/// Start a chunked response; then `send` chunks and `finish`, or drop to truncate.
pub(crate) struct Streaming<IO> { io: ChunkedWriter<IO> }
pub(crate) fn start_streaming<IO: Write>(mut io: IO, status: u16, fields: &[(&str, &str)]) -> io::Result<Streaming<IO>> {
    let mut all: Vec<Field> = fields.iter().map(|(n, v)| field(n, v)).collect();
    all.push(field("transfer-encoding", "chunked"));
    all.push(field("connection", "close"));
    let mut bytes = Vec::new();
    write_status_head(status, http1::reason(status), &all, &mut bytes);
    io.write_all(&bytes)?;
    io.flush()?;
    Ok(Streaming { io: ChunkedWriter::new(io, gateway_core::http1_exchange::ChunkStream::new()) })
}
impl<IO: Write> Streaming<IO> {
    pub(crate) fn send(&mut self, chunk: &[u8]) -> io::Result<()> { self.io.write_all(chunk)?; self.io.flush() }
    /// The last chunk; the stream is complete. Returns the underlying stream.
    pub(crate) fn finish(mut self) -> io::Result<IO> { self.io.finish()?; Ok(self.io.into_parts().0) }
    /// Give the stream back without the last chunk: a truncated body.
    pub(crate) fn truncate(self) -> IO { self.io.into_parts().0 }
}

/// A received response: head, and a reader for the body.
pub(crate) struct Answer<IO> { pub status: u16, pub fields: Vec<Field>, body: BodyReader<IO>, no_body: bool }
impl<IO: Read> Answer<IO> {
    pub(crate) fn header(&self, name: &str) -> Option<&str> { value_of(&self.fields, name).and_then(|v| std::str::from_utf8(v).ok()) }
    /// The next piece of body, or `None` at the clean end; an error is a truncated body.
    pub(crate) fn chunk(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.no_body { return Ok(None); }
        let mut buffer = vec![0u8; 64 * 1024];
        let n = self.body.read(&mut buffer)?;
        if n == 0 { return Ok(None); }
        buffer.truncate(n);
        Ok(Some(buffer))
    }
    /// The whole body, or an error if it is truncated.
    pub(crate) fn collect(mut self) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(piece) = self.chunk()? { out.extend_from_slice(&piece); }
        Ok(out)
    }
    /// The stream under the answer, once the body is done with.
    pub(crate) fn into_inner(self) -> IO { self.body.into_inner() }
}

/// Send one request with a Content-Length body and read the response head.
pub(crate) fn send_request<IO: Read + Write>(mut io: IO, method: &str, target: &str, fields: &[(&str, &str)], body: &[u8])
    -> io::Result<Answer<IO>>
{
    let mut all: Vec<Field> = fields.iter().map(|(n, v)| field(n, v)).collect();
    all.push(field("content-length", &body.len().to_string()));
    let mut bytes = Vec::new();
    write_request_head(method.as_bytes(), target.as_bytes(), &all, &mut bytes);
    bytes.extend_from_slice(body);
    io.write_all(&bytes)?;
    io.flush()?;
    read_response(io)
}

/// Read a response head from `io` and set up its body reader.
pub(crate) fn read_response<IO: Read>(mut io: IO) -> io::Result<Answer<IO>> {
    let mut leftover = Vec::new();
    let head = loop {
        let (head, rest) = read_status_head(&mut io, leftover).map_err(|e| io::Error::other(format!("{e:?}")))?;
        if head.status < 200 && head.status != 101 { leftover = rest; continue; }
        leftover = rest;
        break head;
    };
    let StatusHead { status, fields } = head;
    let no_body = status == 204 || status == 304;
    let body_framing = if no_body { Framing::Length(0) } else { framing(&fields, false).map_err(|_| io::Error::other("framing"))? };
    Ok(Answer { status, fields, body: BodyReader::new(io, leftover, body_framing), no_body })
}

/// Write raw bytes and read everything the peer sends back until it closes.
pub(crate) fn raw_exchange<IO: Read + Write>(io: &mut IO, bytes: &[u8]) -> io::Result<Vec<u8>> {
    io.write_all(bytes)?;
    io.flush()?;
    let mut out = Vec::new();
    io.read_to_end(&mut out)?;
    Ok(out)
}
