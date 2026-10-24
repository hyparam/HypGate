//! Trusted bridge between HTTP body frames and the byte-stream core.
use bytes::{Buf, Bytes};
use http_body::{Body, Frame};
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, sync::{mpsc, oneshot}};
use std::future::Future;
use tokio_util::sync::PollSender;

// Matches the inbound and upstream HTTP/1 parser buffer limits. This bounds
// the reader-owned copy. Hyper's own parser/body allocations remain separate.
pub(crate) const MAX_INPUT_FRAME: usize = 32 * 1024;

pub(crate) struct Reader<B> { body: B, buffered: Bytes, ended: bool }
impl<B> Reader<B> {
    pub(crate) fn new(body: B) -> Self { Self { body, buffered: Bytes::new(), ended: false } }
}
impl<B: Body<Data = Bytes> + Unpin> AsyncRead for Reader<B> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 { return Poll::Ready(Ok(())); }
        // Bound work per poll even if a peer produces empty frames indefinitely.
        for _ in 0..16 {
            if !this.buffered.is_empty() {
                let n = out.remaining().min(this.buffered.len());
                out.put_slice(&this.buffered[..n]); this.buffered.advance(n);
                if this.buffered.is_empty() { this.buffered = Bytes::new(); }
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
                    Ok(data) if data.len() <= MAX_INPUT_FRAME => this.buffered = Bytes::copy_from_slice(&data),
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

enum Message { Data(Bytes), End }
pub(crate) struct Writer { sender: PollSender<Message>, max_frame: usize, ended: bool, drained: oneshot::Receiver<()>, complete: bool }
pub(crate) struct ChannelBody { receiver: mpsc::Receiver<Message>, ended: bool, drained: Option<oneshot::Sender<()>> }
pub(crate) fn channel(max_frame: usize) -> (Writer, ChannelBody) {
    let (sender, receiver) = mpsc::channel(1);
    let (done, drained) = oneshot::channel();
    (Writer { sender: PollSender::new(sender), max_frame, ended: false, drained, complete: false },
        ChannelBody { receiver, ended: false, drained: Some(done) })
}
impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.ended || this.max_frame == 0 { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        if bytes.is_empty() { return Poll::Ready(Ok(0)); }
        match this.sender.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Ok(())) => {
                let n = bytes.len().min(this.max_frame);
                let result = this.sender.send_item(Message::Data(Bytes::copy_from_slice(&bytes[..n])));
                Poll::Ready(result.map(|()| n).map_err(|_| io::ErrorKind::BrokenPipe.into()))
            }
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
        if !this.ended { match this.sender.poll_reserve(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(_)) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            Poll::Ready(Ok(())) => {
                this.ended = true;
                if this.sender.send_item(Message::End).is_err() { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
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
        match this.receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Message::Data(data))) => Poll::Ready(Some(Ok(Frame::data(data)))),
            Poll::Ready(Some(Message::End)) => {
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
        // Full has transferred its only reference. The reader must not retain
        // the 256 KiB owner while holding the remaining 39 visible bytes.
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        let mut rest = [0; 39];
        reader.read_exact(&mut rest).await.unwrap();
        assert_eq!(&rest, &expected[1..]);
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
    fn reserved_send_after_receiver_drop_retains_payload_until_sender_cleanup() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        struct Payload { bytes: [u8; 4], dropped: Arc<AtomicUsize> }
        impl AsRef<[u8]> for Payload { fn as_ref(&self) -> &[u8] { &self.bytes } }
        impl Drop for Payload { fn drop(&mut self) { self.dropped.fetch_add(1, Ordering::SeqCst); } }
        let dropped = Arc::new(AtomicUsize::new(0));
        let (mut writer, body) = channel(4);
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(writer.sender.poll_reserve(&mut context), Poll::Ready(Ok(()))));
        // Model receiver destruction on another executor thread between the
        // Writer's reservation and send. No new reservation follows closure.
        drop(body);
        assert!(writer.sender.send_item(Message::Data(Bytes::from_owner(Payload {
            bytes: *b"late", dropped: dropped.clone(),
        }))).is_ok());
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert!(matches!(Pin::new(&mut writer).poll_write(&mut context, b"more"), Poll::Ready(Err(_))));
        // PollSender still owns a sender reference even after observing closure.
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(writer);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
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
