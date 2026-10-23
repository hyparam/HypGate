//! Trusted bridge between HTTP body frames and the byte-stream core.
use bytes::{Buf, Bytes};
use http_body::{Body, Frame};
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::{io::{AsyncRead, AsyncWrite, ReadBuf}, sync::{mpsc, oneshot}};
use std::future::Future;
use tokio_util::sync::PollSender;

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
                return Poll::Ready(Ok(()));
            }
            if this.ended { return Poll::Ready(Ok(())); }
            match Pin::new(&mut this.body).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => { this.ended = true; return Poll::Ready(Ok(())); }
                Poll::Ready(Some(Err(_))) => return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) => this.buffered = data,
                    Err(_) => return Poll::Ready(Err(io::ErrorKind::InvalidData.into())), // trailers unsupported
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
}
