//! Bound each HTTP plaintext read independently of Hyper's backing capacity.
use std::{io, pin::Pin, task::{Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct ReadLimited<T>(T);
impl<T> ReadLimited<T> {
    pub(crate) fn new(io: T) -> Self { Self(io) }
}
impl<T: AsyncRead + Unpin> AsyncRead for ReadLimited<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let limit = out.remaining().min(crate::http_body::MAX_INPUT_FRAME);
        if limit == 0 { return Poll::Ready(Ok(())); }
        // Initialize only this bounded projection. Using the safe initialized
        // slice avoids unsafe propagation of ReadBuf's initialization markers.
        let mut bounded = ReadBuf::new(out.initialize_unfilled_to(limit));
        match Pin::new(&mut self.get_mut().0).poll_read(cx, &mut bounded) {
            Poll::Ready(Ok(())) => {
                let n = bounded.filled().len();
                out.advance(n);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for ReadLimited<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool { self.0.is_write_vectored() }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_projection_preserves_prefix_pending_error_and_eof() {
        struct Source { polls: usize }
        impl AsyncRead for Source {
            fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                assert!(out.remaining() <= crate::http_body::MAX_INPUT_FRAME);
                self.polls += 1;
                match self.polls {
                    1 => { cx.waker().wake_by_ref(); Poll::Pending }
                    2 => Poll::Ready(Err(io::ErrorKind::ConnectionReset.into())),
                    3 => { out.put_slice(&vec![7; out.remaining()]); Poll::Ready(Ok(())) }
                    _ => Poll::Ready(Ok(())),
                }
            }
        }
        let mut source = ReadLimited::new(Source { polls: 0 });
        let mut storage = vec![0; 3 * crate::http_body::MAX_INPUT_FRAME];
        let mut out = ReadBuf::new(&mut storage);
        out.put_slice(b"keep");
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(Pin::new(&mut source).poll_read(&mut cx, &mut out).is_pending());
        assert_eq!(out.filled(), b"keep");
        assert!(matches!(Pin::new(&mut source).poll_read(&mut cx, &mut out), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::ConnectionReset));
        assert_eq!(out.filled(), b"keep");
        assert!(matches!(Pin::new(&mut source).poll_read(&mut cx, &mut out), Poll::Ready(Ok(()))));
        assert_eq!(&out.filled()[..4], b"keep");
        assert_eq!(out.filled().len(), 4 + crate::http_body::MAX_INPUT_FRAME);
        assert!(out.filled()[4..].iter().all(|byte| *byte == 7));
        assert!(matches!(Pin::new(&mut source).poll_read(&mut cx, &mut out), Poll::Ready(Ok(()))));
        assert_eq!(out.filled().len(), 4 + crate::http_body::MAX_INPUT_FRAME);
        let mut empty = ReadBuf::new(&mut []);
        assert!(matches!(Pin::new(&mut source).poll_read(&mut cx, &mut empty), Poll::Ready(Ok(()))));
        assert_eq!(source.0.polls, 4);
    }
}
