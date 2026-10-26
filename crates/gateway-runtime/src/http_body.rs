//! Trusted bridge between the HTTP adapter's byte streams and the byte-stream
//! core. A `Reader` binds a worker's HTTP role to the body it reads; a
//! `Writer`/`ChannelBody` pair is the bounded one-frame queue between a
//! worker's body copy and the connection task that writes the wire.
use gateway_core::output_frame::OutputFrame;
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, sync::oneshot};
use std::future::Future;
mod slot;
mod worker;
pub(crate) use worker::WorkerHttp;

// Matches the HTTP/1 adapter's read size. This bounds one body read.
pub(crate) const MAX_INPUT_FRAME: usize = 32 * 1024;

/// A body source bound to a worker's reader role. Reads pass straight through
/// to the framed body; the role is released when the reader is dropped.
pub(crate) struct Reader<B> { body: Option<B>, charge: Option<worker::Charge> }
impl<B> Reader<B> {
    pub(crate) fn new(body: B) -> Self { Self { body: Some(body), charge: None } }
    pub(crate) fn body(&self) -> &B { self.body.as_ref().expect("live reader") }
}
impl<B> Drop for Reader<B> {
    fn drop(&mut self) {
        drop(self.body.take());
        if let Some(charge) = self.charge.take() { charge.finish(); }
    }
}
impl<B: AsyncRead + Unpin> AsyncRead for Reader<B> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().body.as_mut().expect("live reader")).poll_read(cx, out)
    }
}

pub(crate) enum Message { Data(OutputFrame), End }

pub(crate) struct Writer { sender: Option<slot::Sender<Message>>, charge: Option<worker::Charge>, upload: Option<std::sync::Arc<worker::UploadCharge>>, max_frame: usize, ended: bool, drained: oneshot::Receiver<()>, complete: bool }
pub(crate) struct ChannelBody {
    receiver: Option<slot::Receiver<Message>>, ended: bool, drained: Option<oneshot::Sender<()>>,
    response: Option<ResponseOwnership>,
    upload: Option<std::sync::Arc<worker::UploadCharge>>,
    // The rest of a frame a byte-stream reader has not taken yet.
    partial: Vec<u8>, partial_pos: usize,
}

// Cloning the issuer does not clone a permit: the checked slot issues once.
#[derive(Clone)]
pub(crate) struct ConnectionResponses(std::sync::Arc<ResponseSource>);
struct ResponseSource {
    registry: std::sync::Arc<std::sync::Mutex<gateway_core::http_connection::ResponseRegistry>>,
    issuer: gateway_core::http_connection::ResponseIssuer,
}
struct ResponseOwnership {
    issuer: ConnectionResponses,
    permit: gateway_core::http_connection::RegisteredResponse,
}
impl ConnectionResponses {
    pub(crate) fn new(registry: std::sync::Arc<std::sync::Mutex<gateway_core::http_connection::ResponseRegistry>>,
        issuer: gateway_core::http_connection::ResponseIssuer) -> Self
    { Self(std::sync::Arc::new(ResponseSource { registry, issuer })) }
    pub(crate) fn channel(&self, max_frame: usize) -> Option<(Writer, ChannelBody)> {
        let permit = self.0.registry.lock().ok()?.issue(&self.0.issuer)?;
        let (writer, mut body) = channel(max_frame);
        body.response = Some(ResponseOwnership { issuer: self.clone(), permit });
        Some((writer, body))
    }
}
impl Drop for ChannelBody {
    fn drop(&mut self) {
        let _upload_cleanup = worker::UploadCleanup::new(&self.upload);
        // Explicit normal-return boundary: a panic must not return the permit
        // through automatic field cleanup while payload destruction unwinds.
        drop(self.receiver.take());
        if let Some(response) = self.response.take() {
            if let Ok(mut registry) = response.issuer.0.registry.lock() {
                assert!(registry.finish(response.permit), "response belongs to connection");
            }
        }
    }
}
pub(crate) fn channel(max_frame: usize) -> (Writer, ChannelBody) {
    let (sender, receiver) = slot::channel();
    let (done, drained) = oneshot::channel();
    (Writer { sender: Some(sender), charge: None, upload: None, max_frame, ended: false, drained, complete: false },
        ChannelBody { receiver: Some(receiver), ended: false, drained: Some(done), response: None, upload: None, partial: Vec::new(), partial_pos: 0 })
}
impl Drop for Writer {
    fn drop(&mut self) {
        let _upload_cleanup = worker::UploadCleanup::new(&self.upload);
        drop(self.sender.take());
        if let Some(charge) = self.charge.take() { charge.finish(); }
    }
}
impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.ended || this.max_frame == 0 { return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())); }
        if bytes.is_empty() { return Poll::Ready(Ok(0)); }
        let mut n = 0;
        match this.sender.as_mut().expect("live sender").poll_send_with(cx, || {
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
        // Completion means accepted into the bounded body queue, not socket
        // delivery. There is no extra buffering in this writer to flush.
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.complete { return Poll::Ready(Ok(())); }
        if !this.ended { match this.sender.as_mut().expect("live sender").poll_send_with(cx, || Message::End) {
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
impl ChannelBody {
    /// The next body frame: `None` after the clean end marker; an error when
    /// the writer went away without one, which is never a clean end.
    pub(crate) fn poll_frame(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Vec<u8>>>> {
        if self.ended { return Poll::Ready(None); }
        match self.receiver.as_mut().expect("live receiver").poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Message::Data(frame))) => Poll::Ready(Some(Ok(frame.into_vec()))),
            Poll::Ready(Some(Message::End)) => {
                self.ended = true;
                if let Some(done) = self.drained.take() { let _ = done.send(()); }
                Poll::Ready(None)
            }
            Poll::Ready(None) => {
                self.ended = true;
                // Dropped/canceled upload is not a successful HTTP EOF.
                Poll::Ready(Some(Err(io::ErrorKind::UnexpectedEof.into())))
            }
        }
    }
    pub(crate) fn next_frame(&mut self) -> impl Future<Output = Option<io::Result<Vec<u8>>>> + '_ {
        std::future::poll_fn(|cx| self.poll_frame(cx))
    }
}

/// `ChannelBody` as a byte stream, for readers that take one. A frame larger
/// than the destination buffer is handed out over several reads.
impl AsyncRead for ChannelBody {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if out.remaining() == 0 { return Poll::Ready(Ok(())); }
        if this.partial_pos >= this.partial.len() {
            match this.poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(Some(Ok(frame))) => { this.partial = frame; this.partial_pos = 0; }
            }
        }
        let rest = &this.partial[this.partial_pos..];
        let n = rest.len().min(out.remaining());
        out.put_slice(&rest[..n]);
        this.partial_pos += n;
        if this.partial_pos >= this.partial.len() { this.partial.clear(); this.partial_pos = 0; }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn response_permit_returns_only_when_the_body_is_dropped() {
        let registry = std::sync::Arc::new(std::sync::Mutex::new(gateway_core::http_connection::ResponseRegistry::new(1)));
        let (task, issuer) = registry.lock().unwrap().acquire().unwrap();
        let responses = ConnectionResponses::new(registry.clone(), issuer);
        let (mut writer, body) = responses.channel(4).unwrap();
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(writer.sender.as_mut().expect("live sender").poll_send_with(&mut context,
            || Message::Data(OutputFrame::copy_prefix(b"data", 4))), Poll::Ready(Ok(()))));
        assert_eq!(registry.lock().unwrap().response_count(), 1);
        drop(body);
        assert_eq!(registry.lock().unwrap().response_count(), 0);
        assert!(registry.lock().unwrap().release_task(task));
        assert_eq!(registry.lock().unwrap().usage(), (0, 1));
        drop(writer);
    }

    #[tokio::test]
    async fn canceled_sender_is_an_error_not_successful_eof() {
        let (mut writer, mut body) = channel(2);
        assert_eq!(writer.write(b"abcd").await.unwrap(), 2);
        drop(writer);
        assert_eq!(body.next_frame().await.unwrap().unwrap(), b"ab");
        assert!(body.next_frame().await.unwrap().is_err());
        assert!(body.next_frame().await.is_none());
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
    async fn canceled_backpressured_write_never_sends_stale_bytes() {
        let (mut writer, mut body) = channel(4);
        writer.write_all(b"head").await.unwrap();
        let mut context = Context::from_waker(std::task::Waker::noop());
        let mut blocked = Box::pin(writer.write(b"old!"));
        assert!(blocked.as_mut().poll(&mut context).is_pending());
        drop(blocked); // keep the Writer, cancel only this write operation
        assert_eq!(body.next_frame().await.unwrap().unwrap(), b"head");
        assert_eq!(writer.write(b"new!").await.unwrap(), 4);
        assert_eq!(body.next_frame().await.unwrap().unwrap(), b"new!");
        let finish = async { writer.shutdown().await.unwrap(); };
        let drain = async { assert!(body.next_frame().await.is_none()); };
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
        assert_eq!(body.next_frame().await.unwrap().unwrap(), b"head");
        assert_eq!(body.next_frame().await.unwrap().unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        assert!(body.next_frame().await.is_none());
    }

    #[test]
    fn receiver_drop_prevents_late_construction() {
        let (mut writer, body) = channel(4);
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(writer.sender.as_mut().expect("live sender").poll_send_with(&mut context,
            || Message::Data(OutputFrame::copy_prefix(b"data", 4))), Poll::Ready(Ok(()))));
        drop(body);
        assert!(matches!(writer.sender.as_mut().expect("live sender").poll_send_with(&mut context, || panic!("late allocation")), Poll::Ready(Err(()))));
        assert!(matches!(Pin::new(&mut writer).poll_write(&mut context, b"more"), Poll::Ready(Err(_))));
    }
}
