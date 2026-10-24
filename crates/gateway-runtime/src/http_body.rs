//! Trusted bridge between HTTP body frames and the byte-stream core.
use bytes::Bytes;
#[cfg(test)]
use bytes::Buf;
use gateway_core::{read_buffer::ReadBuffer, output_frame::OutputFrame};
#[cfg(test)]
use gateway_core::output_frame::MAX_OUTPUT_FRAME;
use http_body::{Body, Frame};
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, sync::oneshot};
use std::future::Future;
mod slot;

// Matches the inbound and upstream HTTP/1 parser buffer limits. This bounds
// the reader-owned copy. Hyper's own parser/body allocations remain separate.
pub(crate) const MAX_INPUT_FRAME: usize = 32 * 1024;

pub(crate) struct Reader<B> { body: B, buffered: ReadBuffer, ended: bool }
impl<B> Reader<B> {
    pub(crate) fn new(body: B) -> Self { Self { body, buffered: ReadBuffer::new(MAX_INPUT_FRAME), ended: false } }
}
impl<B: Body<Data = Bytes> + Unpin> AsyncRead for Reader<B> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 { return Poll::Ready(Ok(())); }
        // Bound work per poll even if a peer produces empty frames indefinitely.
        for _ in 0..16 {
            if !this.buffered.is_empty() {
                let n = out.remaining().min(this.buffered.len());
                out.put_slice(this.buffered.peek(n));
                assert!(this.buffered.consume(n));
                return Poll::Ready(Ok(()));
            }
            if this.ended { return Poll::Ready(Ok(())); }
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => { this.ended = true; return Poll::Ready(Ok(())); }
                Poll::Ready(Some(Err(_))) => { this.ended = true; return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())); },
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    // A short Bytes view may retain an arbitrarily large owner.
                    // Copy only the bounded visible frame, then release our input
                    // reference before yielding or keeping a partial remainder.
                    Ok(data) if this.buffered.load(&data) => {},
                    _ => {
                        this.ended = true;
                        return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                    }, // oversized frames and trailers unsupported
                },
            }
        }
        cx.waker().wake_by_ref(); Poll::Pending
    }
}

#[cfg(not(test))]
use gateway_core::http_message::HttpMessage as Message;

// The alternate test item permits observable backing-owner probes. Ordinary
// data paths in both builds carry the same verified OutputFrame.
#[cfg(test)]
enum Message {
    Data(OutputFrame), End,
    // Inject custom backing owners only for dependency/destructor probes.
    #[cfg(test)]
    Probe(Bytes),
}
#[cfg(not(test))]
fn message_data(message: Message) -> Option<Bytes> { message.into_payload().map(Bytes::from) }
#[cfg(test)]
fn message_data(message: Message) -> Option<Bytes> {
    match message { Message::Data(frame) => Some(Bytes::from(frame.into_vec())), Message::Probe(bytes) => Some(bytes), Message::End => None }
}
pub(crate) struct Writer { sender: slot::Sender<Message>, max_frame: usize, ended: bool, drained: oneshot::Receiver<()>, complete: bool }
pub(crate) struct ChannelBody {
    receiver: Option<slot::Receiver<Message>>, ended: bool, drained: Option<oneshot::Sender<()>>,
    response: Option<ResponseOwnership>,
}

// Cloning the issuer does not clone a permit: the checked slot issues once.
#[derive(Clone)]
pub(crate) struct ConnectionResponses(std::sync::Arc<std::sync::Mutex<gateway_core::http_connection::ResponseSlot>>);
struct ResponseOwnership {
    issuer: ConnectionResponses,
    permit: gateway_core::http_connection::ResponsePermit,
}
impl ConnectionResponses {
    pub(crate) fn reserve(key: gateway_core::resource::RequestKey) -> (Self, gateway_core::task_credit::TaskCredit) {
        let (slot, task) = gateway_core::http_connection::ResponseSlot::reserve(key);
        (Self(std::sync::Arc::new(std::sync::Mutex::new(slot))), task)
    }
    pub(crate) fn channel(&self, max_frame: usize) -> Option<(Writer, ChannelBody)> {
        let permit = self.0.lock().ok()?.issue()?;
        let (writer, mut body) = channel(max_frame);
        body.response = Some(ResponseOwnership { issuer: self.clone(), permit });
        Some((writer, body))
    }
    pub(crate) fn release_task(&self, task: gateway_core::task_credit::TaskCredit,
        registry: &mut gateway_core::resource::ResourceAdmission) -> bool
    {
        self.0.lock().is_ok_and(|mut slot| slot.release_task(task, registry))
    }
}
impl Drop for ChannelBody {
    fn drop(&mut self) {
        // Explicit normal-return boundary: a panic must not return the permit
        // through automatic field cleanup while payload destruction unwinds.
        drop(self.receiver.take());
        if let Some(response) = self.response.take() {
            if let Ok(mut slot) = response.issuer.0.lock() {
                assert!(slot.finish(response.permit), "response belongs to connection");
            }
        }
    }
}
pub(crate) fn channel(max_frame: usize) -> (Writer, ChannelBody) {
    let (sender, receiver) = slot::channel();
    let (done, drained) = oneshot::channel();
    (Writer { sender, max_frame, ended: false, drained, complete: false },
        ChannelBody { receiver: Some(receiver), ended: false, drained: Some(done), response: None })
}
impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.ended || this.max_frame == 0 { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        if bytes.is_empty() { return Poll::Ready(Ok(0)); }
        let mut n = 0;
        match this.sender.poll_send_with(cx, || {
            let frame = OutputFrame::copy_prefix(bytes, this.max_frame);
            n = frame.len();
            Message::Data(frame)
        }) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(())) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Completion means accepted into the bounded HTTP body queue, not socket
        // delivery. There is no extra buffering in this writer to flush.
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.complete { return Poll::Ready(Ok(())); }
        if !this.ended { match this.sender.poll_send_with(cx, || Message::End) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Ok(())) => {
                this.ended = true;
            }
        } }
        match Pin::new(&mut this.drained).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => { this.complete = true; Poll::Ready(Ok(())) }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }
}
impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        if this.ended { return Poll::Ready(None); }
        match this.receiver.as_mut().expect("live receiver").poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(message)) => {
                if let Some(data) = message_data(message) { return Poll::Ready(Some(Ok(Frame::data(data)))); }
                this.ended = true;
                if let Some(done) = this.drained.take() { let _ = done.send(()); }
                Poll::Ready(None)
            }
            Poll::Ready(None) => {
                this.ended = true;
                // Dropped/canceled upload is not a successful HTTP EOF.
                Poll::Ready(Some(Err(io::ErrorKind::UnexpectedEof.into())))
            }
        }
    }
    fn is_end_stream(&self) -> bool { self.ended }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn panicking_response_payload_strands_its_connection_permit() {
        struct Payload;
        impl AsRef<[u8]> for Payload { fn as_ref(&self) -> &[u8] { b"data" } }
        impl Drop for Payload { fn drop(&mut self) { panic!("injected response cleanup panic"); } }
        let mut registry = gateway_core::resource::ResourceAdmission::new(1, 0);
        let (responses, task) = ConnectionResponses::reserve(registry.acquire().unwrap());
        let (mut writer, body) = responses.channel(4).unwrap();
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(writer.sender.poll_send_with(&mut context,
            || Message::Probe(Bytes::from_owner(Payload))), Poll::Ready(Ok(()))));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(body))).is_err());
        assert!(!responses.release_task(task, &mut registry));
        assert!(registry.acquire().is_none());
        assert!(responses.channel(4).is_none());
    }

    #[tokio::test]
    async fn output_copy_enforces_core_limit_even_for_oversized_configuration() {
        let (mut writer, mut body) = channel(usize::MAX);
        let input = vec![7; MAX_OUTPUT_FRAME + 3];
        let count = writer.write(&input).await.unwrap();
        assert_eq!(count, MAX_OUTPUT_FRAME);
        let bytes = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(bytes.as_ref(), &input[..count]);
        assert_eq!(writer.write(&input[count..]).await.unwrap(), 3);
        let tail = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(tail.as_ref(), &[7; 3]);
    }

    #[tokio::test]
    async fn incoming_trailer_parser_enforces_byte_and_field_limits() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let padded = |size: usize| format!("x-pad: {}\r\n\r\n", "p".repeat(size - 11));
            for (trailers, accepted, count) in [
                (padded(MAX_INPUT_FRAME - 1), true, 1),
                (padded(MAX_INPUT_FRAME), false, 1),
                (format!("{}\r\n", "x: y\r\n".repeat(100)), true, 100),
                (format!("{}\r\n", "x: y\r\n".repeat(101)), false, 101),
            ] {
                let (client, mut peer) = tokio::io::duplex(128 * 1024);
                let provider = tokio::spawn(async move {
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(peer.read_u8().await.unwrap());
                        assert!(request.len() < 1024);
                    }
                    let response = format!("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n1\r\nx\r\n0\r\n{trailers}");
                    peer.write_all(response.as_bytes()).await.unwrap();
                    peer.shutdown().await.unwrap();
                });
                let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                    .max_buf_size(MAX_INPUT_FRAME).max_header_size(MAX_INPUT_FRAME).max_headers(100).writev(true)
                    .handshake(hyper_util::rt::TokioIo::new(crate::http_io::ReadLimited::new(client))).await.unwrap();
                let driver = tokio::spawn(connection);
                let mut body = sender.send_request(http::Request::new(http_body_util::Empty::<Bytes>::new()))
                    .await.unwrap().into_body();
                assert_eq!(body.frame().await.unwrap().unwrap().into_data().unwrap(), "x");
                let next = body.frame().await.expect("trailers or parser error");
                if accepted {
                    assert_eq!(next.unwrap().into_trailers().unwrap().len(), count);
                    assert!(body.frame().await.is_none());
                } else {
                    assert!(next.is_err(), "oversized trailers must fail before delivery");
                }
                drop(body); drop(sender);
                let result = driver.await.unwrap();
                if accepted { result.unwrap(); }
                provider.await.unwrap();
            }
        }).await.unwrap();
    }

    #[tokio::test]
    async fn incoming_body_read_ahead_stays_bounded_with_a_slow_reader() {
        use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
        struct Input {
            wire: Bytes, read: Arc<AtomicUsize>, dropped: Arc<AtomicBool>, written: bool,
        }
        impl Drop for Input {
            fn drop(&mut self) { self.dropped.store(true, Ordering::SeqCst); }
        }
        impl AsyncRead for Input {
            fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                if !self.written || self.wire.is_empty() { return Poll::Pending; }
                let n = out.remaining().min(self.wire.len());
                out.put_slice(&self.wire[..n]); self.wire.advance(n);
                self.read.fetch_add(n, Ordering::SeqCst);
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for Input {
            fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
                self.written = true; Poll::Ready(Ok(data.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        }
        let read = Arc::new(AtomicUsize::new(0));
        let dropped = Arc::new(AtomicBool::new(false));
        let size = 2 * 1024 * 1024;
        let head = format!("HTTP/1.1 200 OK\r\ncontent-length: {size}\r\nx-retained: value\r\n\r\n");
        let mut wire = head.as_bytes().to_vec(); wire.resize(head.len() + size, 42);
        let input = Input { wire: Bytes::from(wire), read: read.clone(), dropped: dropped.clone(), written: false };
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(MAX_INPUT_FRAME).max_header_size(MAX_INPUT_FRAME).max_headers(100).writev(true)
            .handshake(hyper_util::rt::TokioIo::new(crate::http_io::ReadLimited::new(input))).await.unwrap();
        let mut connection = Box::pin(connection);
        let mut response = Box::pin(sender.send_request(http::Request::new(http_body_util::Empty::<Bytes>::new())));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let mut received = None;
        for _ in 0..64 {
            tokio::task::yield_now().await;
            assert!(connection.as_mut().poll(&mut cx).is_pending());
            if let Poll::Ready(result) = response.as_mut().poll(&mut cx) { received = Some(result.unwrap()); break; }
        }
        let (parts, incoming) = received.expect("response head delivered").into_parts();
        let mut reader = Reader::new(incoming);
        let mut consumed = 0;
        // Hold the original parsed header view while the body forces replacement
        // parser allocations. Each round consumes only one application byte.
        for round in 0..64 {
            let before = read.load(Ordering::SeqCst);
            for _ in 0..32 {
                tokio::task::yield_now().await;
                assert!(connection.as_mut().poll(&mut cx).is_pending());
            }
            let after = read.load(Ordering::SeqCst);
            assert!(after - head.len() <= consumed + 4 * MAX_INPUT_FRAME);
            if round > 1 { assert_eq!(after, before, "no extra reads while detached remainder is full"); }
            let mut byte = [0]; let mut out = ReadBuf::new(&mut byte);
            assert!(matches!(Pin::new(&mut reader).poll_read(&mut cx, &mut out), Poll::Ready(Ok(()))));
            assert_eq!(out.filled(), &[42]); consumed += 1;
        }
        assert_eq!(parts.headers["x-retained"], "value");
        assert!(read.load(Ordering::SeqCst) < head.len() + size);
        drop(parts); drop(reader); drop(response); drop(sender); drop(connection);
        assert!(dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn queued_hyper_output_preserves_duplex_bytes_with_short_nonvectored_writes() {
        use hyper_util::rt::TokioIo;
        struct ShortWrites(tokio::io::DuplexStream);
        impl AsyncRead for ShortWrites {
            fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.0).poll_read(cx, out)
            }
        }
        impl AsyncWrite for ShortWrites {
            fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.0).poll_write(cx, &bytes[..bytes.len().min(7)])
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.0).poll_flush(cx) }
            fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.0).poll_shutdown(cx) }
            // Use AsyncWrite's default non-vectored fallback deliberately.
        }
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let expected: Vec<u8> = (0..65537).map(|i| (i % 251) as u8).collect();
            let (client, server) = tokio::io::duplex(257);
            let client = ShortWrites(client);
            assert!(!client.is_write_vectored());
            let server_task = tokio::spawn(async move {
                let (done, completed) = oneshot::channel();
                let done = std::sync::Mutex::new(Some(done));
                let service = hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                    let done = done.lock().unwrap().take().expect("one exchange");
                    async move {
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        let (mut writer, body) = channel(16384);
                        tokio::spawn(async move {
                            writer.write_all(&bytes).await.unwrap(); writer.shutdown().await.unwrap();
                            done.send(()).unwrap();
                        });
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(body))
                    }
                });
                hyper::server::conn::http1::Builder::new().keep_alive(false).writev(true)
                    .max_buf_size(MAX_INPUT_FRAME).serve_connection(TokioIo::new(ShortWrites(server)), service).await.unwrap();
                completed.await.unwrap();
            });
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new().writev(true)
                .max_buf_size(MAX_INPUT_FRAME).handshake(TokioIo::new(client)).await.unwrap();
            let driver = tokio::spawn(connection);
            let (mut writer, body) = channel(16384);
            let request = hyper::Request::builder().method("POST").uri("/").header("host", "localhost").body(body).unwrap();
            let upload = async { writer.write_all(&expected).await.unwrap(); writer.shutdown().await.unwrap(); };
            let response = async {
                sender.send_request(request).await.unwrap().into_body().collect().await.unwrap().to_bytes()
            };
            let ((), received) = tokio::join!(upload, response);
            assert_eq!(received.as_ref(), expected);
            drop(sender); driver.await.unwrap().unwrap(); server_task.await.unwrap();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn queued_hyper_partial_writes_bound_original_payload_owners() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        struct Payload { bytes: Vec<u8>, live: Arc<AtomicUsize> }
        impl AsRef<[u8]> for Payload { fn as_ref(&self) -> &[u8] { &self.bytes } }
        impl Drop for Payload { fn drop(&mut self) { self.live.fetch_sub(self.bytes.len(), Ordering::SeqCst); } }
        struct BudgetIo(Arc<AtomicUsize>);
        impl AsyncRead for BudgetIo {
            fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> { Poll::Pending }
        }
        impl AsyncWrite for BudgetIo {
            fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
                let n = bytes.len().min(self.0.load(Ordering::SeqCst));
                if n == 0 { return Poll::Pending; }
                self.0.fetch_sub(n, Ordering::SeqCst);
                Poll::Ready(Ok(n))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        }
        for frame_size in [1, 1024, 16384] {
            let budget = Arc::new(AtomicUsize::new(0));
            let live = Arc::new(AtomicUsize::new(0));
            let (mut sender, connection) = hyper::client::conn::http1::Builder::new().writev(true)
                .max_buf_size(MAX_INPUT_FRAME).handshake(hyper_util::rt::TokioIo::new(BudgetIo(budget.clone()))).await.unwrap();
            let (mut writer, body) = channel(frame_size);
            let mut response = Box::pin(sender.send_request(http::Request::post("/").body(body).unwrap()));
            let mut connection = Box::pin(connection);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            // Queue threshold + crossing frame + partially consumed front owner
            // + application mailbox. 13 covers even a combined chunk/end suffix.
            let ceiling = (17 * frame_size).min(MAX_INPUT_FRAME + 3 * frame_size + 13);
            let mut accepted = 0;
            let mut peak = 0;
            for round in 0..64 {
                budget.store([0, 1, frame_size / 2, frame_size - 1, frame_size + 17][round % 5], Ordering::SeqCst);
                for _ in 0..48 {
                    tokio::task::yield_now().await;
                    assert!(response.as_mut().poll(&mut cx).is_pending());
                    assert!(connection.as_mut().poll(&mut cx).is_pending());
                    match writer.sender.poll_send_with(&mut cx, || {
                        live.fetch_add(frame_size, Ordering::SeqCst);
                        Message::Probe(Bytes::from_owner(Payload { bytes: vec![42; frame_size], live: live.clone() }))
                    }) {
                        Poll::Ready(Ok(())) => accepted += frame_size,
                        Poll::Pending => {},
                        Poll::Ready(Err(())) => panic!("unexpected channel closure"),
                    }
                    let retained = live.load(Ordering::SeqCst);
                    peak = peak.max(retained);
                    assert!(retained <= ceiling, "frame={frame_size}, retained={retained}, ceiling={ceiling}");
                }
            }
            assert!(accepted > ceiling, "must exercise replacement, not just initial fill");
            assert!(peak > frame_size);
            drop(connection); drop(response); drop(sender); drop(writer);
            assert_eq!(live.load(Ordering::SeqCst), 0, "all payload owners released on cancellation");
        }
    }

    #[tokio::test]
    async fn canceled_sender_is_an_error_not_successful_eof() {
        let (mut writer, mut body) = channel(2);
        assert_eq!(writer.write(b"abcd").await.unwrap(), 2);
        drop(writer);
        assert_eq!(body.frame().await.unwrap().unwrap().into_data().unwrap(), "ab");
        assert!(body.frame().await.unwrap().is_err());
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn explicit_end_marker_preserves_fragmented_bytes() {
        let (mut writer, body) = channel(2);
        let produce = async { writer.write_all(b"abcdef").await.unwrap(); writer.shutdown().await.unwrap(); };
        let consume = async { let mut out = Vec::new(); Reader::new(body).read_to_end(&mut out).await.unwrap(); out };
        let ((), bytes) = tokio::join!(produce, consume);
        assert_eq!(bytes, b"abcdef");
    }

    #[tokio::test]
    async fn oversized_input_frame_is_rejected_without_retention_or_resumption() {
        struct Frames { polls: std::sync::Arc<std::sync::atomic::AtomicUsize> }
        impl Body for Frames {
            type Data = Bytes; type Error = io::Error;
            fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
                self.polls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Poll::Ready(Some(Ok(Frame::data(Bytes::from(vec![7; MAX_INPUT_FRAME + 1])))))
            }
        }
        let polls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut reader = Reader::new(Frames { polls: polls.clone() });
        let mut out = [0; 1];
        assert_eq!(reader.read(&mut out).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(reader.buffered.is_empty());
        assert_eq!(reader.read(&mut out).await.unwrap(), 0);
        assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn maximum_input_frame_survives_small_reads_without_reordering() {
        let expected: Vec<_> = (0..MAX_INPUT_FRAME).map(|i| (i % 251) as u8).collect();
        let mut reader = Reader::new(http_body_util::Full::new(Bytes::from(expected.clone())));
        let mut actual = Vec::new();
        let mut small = [0; 97];
        loop {
            let n = reader.read(&mut small).await.unwrap();
            if n == 0 { break; }
            actual.extend_from_slice(&small[..n]);
            assert!(reader.buffered.len() <= MAX_INPUT_FRAME);
        }
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn small_frame_releases_large_backing_owner_before_partial_reads_finish() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        struct Backing { bytes: Vec<u8>, dropped: Arc<AtomicUsize> }
        impl AsRef<[u8]> for Backing { fn as_ref(&self) -> &[u8] { &self.bytes } }
        impl Drop for Backing { fn drop(&mut self) { self.dropped.fetch_add(1, Ordering::Relaxed); } }
        let dropped = Arc::new(AtomicUsize::new(0));
        let backing = Bytes::from_owner(Backing {
            bytes: (0..MAX_INPUT_FRAME * 8).map(|i| (i % 251) as u8).collect(),
            dropped: dropped.clone(),
        });
        let frame = backing.slice(31..71);
        let expected = frame.to_vec();
        drop(backing);
        let mut reader = Reader::new(http_body_util::Full::new(frame));
        let mut first = [0; 1];
        assert_eq!(reader.read(&mut first).await.unwrap(), 1);
        assert_eq!(first[0], expected[0]);
        assert_eq!(reader.buffered.retained_bytes(), 40);
        assert_eq!(reader.buffered.len(), 39);
        // Full has transferred its only reference. The reader must not retain
        // the 256 KiB owner while holding the remaining 39 visible bytes.
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        let mut rest = [0; 39];
        reader.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, &expected[1..]);
        assert_eq!(reader.buffered.retained_bytes(), 0);
        assert!(reader.buffered.is_empty());
        assert_eq!(reader.read(&mut first).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn trailer_frames_are_rejected_instead_of_silently_lost() {
        struct Trailers;
        impl Body for Trailers {
            type Data = Bytes; type Error = io::Error;
            fn poll_frame(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
                Poll::Ready(Some(Ok(Frame::trailers(http::HeaderMap::new()))))
            }
        }
        let mut out = Vec::new();
        assert_eq!(Reader::new(Trailers).read_to_end(&mut out).await.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn canceled_backpressured_write_never_sends_stale_bytes() {
        let (mut writer, mut body) = channel(4);
        writer.write_all(b"head").await.unwrap();
        let mut context = Context::from_waker(std::task::Waker::noop());
        let mut blocked = Box::pin(writer.write(b"old!"));
        assert!(blocked.as_mut().poll(&mut context).is_pending());
        drop(blocked); // keep the Writer, cancel only this write operation
        assert_eq!(body.frame().await.unwrap().unwrap().into_data().unwrap(), "head");
        assert_eq!(writer.write(b"new!").await.unwrap(), 4);
        assert_eq!(body.frame().await.unwrap().unwrap().into_data().unwrap(), "new!");
        let finish = async { writer.shutdown().await.unwrap(); };
        let drain = async { assert!(body.frame().await.is_none()); };
        tokio::join!(finish, drain);
    }

    #[tokio::test]
    async fn dropped_receiver_fails_pending_data_and_end_acknowledgment() {
        let mut context = Context::from_waker(std::task::Waker::noop());
        let (mut writer, body) = channel(4);
        writer.write_all(b"head").await.unwrap();
        let mut blocked = Box::pin(writer.write(b"next"));
        assert!(blocked.as_mut().poll(&mut context).is_pending());
        drop(body);
        assert_eq!(blocked.await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);

        let (mut writer, body) = channel(4);
        let mut finish = Box::pin(writer.shutdown());
        // End is enqueued, but success requires the consumer's acknowledgment.
        assert!(finish.as_mut().poll(&mut context).is_pending());
        drop(body);
        assert_eq!(finish.await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn canceled_shutdown_before_end_enqueue_cannot_report_clean_eof() {
        let (mut writer, mut body) = channel(4);
        writer.write_all(b"head").await.unwrap();
        let mut context = Context::from_waker(std::task::Waker::noop());
        let mut finish = Box::pin(writer.shutdown());
        assert!(finish.as_mut().poll(&mut context).is_pending());
        drop(finish); drop(writer);
        assert_eq!(body.frame().await.unwrap().unwrap().into_data().unwrap(), "head");
        assert_eq!(body.frame().await.unwrap().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(body.frame().await.is_none());
    }


    #[test]
    fn receiver_drop_discards_queued_payload_and_prevents_late_construction() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        struct Payload { bytes: [u8; 4], dropped: Arc<AtomicUsize> }
        impl AsRef<[u8]> for Payload { fn as_ref(&self) -> &[u8] { &self.bytes } }
        impl Drop for Payload { fn drop(&mut self) { self.dropped.fetch_add(1, Ordering::SeqCst); } }
        let dropped = Arc::new(AtomicUsize::new(0));
        let (mut writer, body) = channel(4);
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(writer.sender.poll_send_with(&mut context, || Message::Probe(Bytes::from_owner(Payload {
            bytes: *b"data", dropped: dropped.clone(),
        }))), Poll::Ready(Ok(()))));
        drop(body);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(matches!(writer.sender.poll_send_with(&mut context, || panic!("late allocation")), Poll::Ready(Err(()))));
        assert!(matches!(Pin::new(&mut writer).poll_write(&mut context, b"more"), Poll::Ready(Err(_))));
        drop(writer);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn large_valid_http_head_does_not_make_body_frames_fail() {
        struct Input<'a> { bytes: &'a [u8], written: bool }
        impl AsyncRead for Input<'_> {
            fn poll_read(mut self: Pin<&mut Self>, _: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                if !self.written || self.bytes.is_empty() { return Poll::Pending; }
                let n = self.bytes.len().min(out.remaining());
                out.put_slice(&self.bytes[..n]); self.bytes = &self.bytes[n..]; Poll::Ready(Ok(()))
            }
        }
        impl AsyncWrite for Input<'_> {
            fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> { self.written = true; cx.waker().wake_by_ref(); Poll::Ready(Ok(data.len())) }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
        }
        let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        for inbound in [false, true] {
            for chunked in [false, true] {
                let line = if inbound { "POST / HTTP/1.1\r\nHost: localhost" } else { "HTTP/1.1 200 OK" };
                let framing = if chunked { "Transfer-Encoding: chunked".to_owned() } else { format!("Content-Length: {}", payload.len()) };
                let prefix = format!("{line}\r\n{framing}\r\nX-Pad: ");
                let mut wire = format!("{prefix}{}\r\n\r\n", "x".repeat(MAX_INPUT_FRAME - prefix.len() - 4)).into_bytes();
                if chunked { wire.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes()); }
                wire.extend_from_slice(&payload);
                if chunked { wire.extend_from_slice(b"\r\n0\r\n\r\n"); }
                if inbound {
                    let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let observed = called.clone();
                    let expected = &payload;
                    let service = hyper::service::service_fn(move |request: http::Request<hyper::body::Incoming>| {
                        let observed = observed.clone();
                        async move {
                            let mut actual = Vec::new();
                            Reader::new(request.into_body()).read_to_end(&mut actual).await.unwrap();
                            assert_eq!(&actual, expected);
                            observed.store(true, std::sync::atomic::Ordering::SeqCst);
                            Ok::<_, std::convert::Infallible>(http::Response::new(http_body_util::Empty::<Bytes>::new()))
                        }
                    });
                    hyper::server::conn::http1::Builder::new().keep_alive(false)
                        .max_buf_size(MAX_INPUT_FRAME).max_header_size(MAX_INPUT_FRAME)
                        .serve_connection(hyper_util::rt::TokioIo::new(crate::http_io::ReadLimited::new(Input { bytes: &wire, written: true })), service)
                        .await.unwrap();
                    assert!(called.load(std::sync::atomic::Ordering::SeqCst));
                    continue;
                }
                let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                    .max_buf_size(MAX_INPUT_FRAME).max_header_size(MAX_INPUT_FRAME)
                    .handshake(hyper_util::rt::TokioIo::new(crate::http_io::ReadLimited::new(Input { bytes: &wire, written: false }))).await.unwrap();
                let consume = async {
                    let response = sender.send_request(http::Request::new(http_body_util::Empty::<Bytes>::new())).await.unwrap();
                    let mut actual = Vec::new();
                    Reader::new(response.into_body()).read_to_end(&mut actual).await.unwrap();
                    assert_eq!(actual, payload);
                    drop(sender);
                };
                let (result, ()) = tokio::join!(connection, consume);
                result.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn stalled_hyper_output_bounds_body_consumption_and_cancellation() {
        // No socket/kernel queue: every write remains pending. Exercise both
        // Hyper buffer strategies, including tiny chunks that hit the queue's
        // entry limit before its byte threshold.
        struct Stalled;
        impl AsyncRead for Stalled {
            fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<io::Result<()>> { Poll::Pending }
        }
        impl AsyncWrite for Stalled {
            fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> { Poll::Pending }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Pending }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Pending }
            fn is_write_vectored(&self) -> bool { true }
            fn poll_write_vectored(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> { Poll::Pending }
        }
        for vectored in [false, true] {
            for frame_size in [1, 1024, 16384] {
                let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                    .max_buf_size(MAX_INPUT_FRAME).writev(vectored)
                    .handshake(hyper_util::rt::TokioIo::new(Stalled)).await.unwrap();
                let (mut writer, body) = channel(frame_size);
                let request = http::Request::post("/").body(body).unwrap();
                let mut response = Box::pin(sender.send_request(request));
                let mut connection = Box::pin(connection);
                let mut context = Context::from_waker(std::task::Waker::noop());
                let bytes = vec![42; frame_size];
                let ceiling = MAX_INPUT_FRAME + 2 * frame_size;
                let mut accepted = 0;
                let mut stalled_polls = 0;
                for _ in 0..ceiling / frame_size + 32 {
                    // Renew Tokio's cooperative task budget so scheduling
                    // exhaustion cannot masquerade as transport backpressure.
                    tokio::task::yield_now().await;
                    assert!(response.as_mut().poll(&mut context).is_pending());
                    assert!(connection.as_mut().poll(&mut context).is_pending());
                    match Pin::new(&mut writer).poll_write(&mut context, &bytes) {
                        Poll::Ready(Ok(n)) => { assert_eq!(n, frame_size); accepted += n; stalled_polls = 0; }
                        Poll::Pending => { stalled_polls += 1; }
                        other => panic!("unexpected write result: {other:?}"),
                    }
                    // One threshold-crossing frame and one application-channel
                    // frame are permitted. This is consumed payload, not heap.
                    assert!(accepted <= ceiling, "vectored={vectored}, frame={frame_size}, accepted={accepted}");
                    if stalled_polls == 16 { break; }
                }
                assert!(accepted > frame_size, "vectored={vectored}, frame={frame_size}, accepted={accepted}");
                assert_eq!(stalled_polls, 16);
                if vectored { assert!(accepted <= 17 * frame_size); }
                drop(connection); drop(response); drop(sender);
                assert_eq!(writer.write(&bytes).await.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
            }
        }
    }

}
