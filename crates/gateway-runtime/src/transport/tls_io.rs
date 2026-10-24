//! Drain previously queued TLS ciphertext before another plaintext write.
//!
//! rustls moves pending key-update replies into its output queue before checking
//! application capacity. Repeated writes must not do that while output is stuck.
use std::{io, pin::Pin, task::{ready, Context, Poll}};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct DrainBeforeWrite<T>(pub(super) T);
impl<T: AsyncRead + Unpin> AsyncRead for DrainBeforeWrite<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, out)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for DrainBeforeWrite<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let io = &mut self.get_mut().0;
        ready!(Pin::new(&mut *io).poll_flush(cx))?;
        Pin::new(io).poll_write(cx, bytes)
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        let io = &mut self.get_mut().0;
        ready!(Pin::new(&mut *io).poll_flush(cx))?;
        Pin::new(io).poll_write_vectored(cx, bytes)
    }
    fn is_write_vectored(&self) -> bool { self.0.is_write_vectored() }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Stalled { flush: u8, writes: usize }
    impl AsyncRead for Stalled {
        fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            out.put_slice(b"x"); Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for Stalled {
        fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
            self.writes += 1; Poll::Ready(Ok(bytes.len()))
        }
        fn poll_write_vectored(mut self: Pin<&mut Self>, _: &mut Context<'_>, bytes: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
            self.writes += 1; Poll::Ready(Ok(bytes.iter().map(|b| b.len()).sum()))
        }
        fn is_write_vectored(&self) -> bool { true }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            match self.flush { 0 => Poll::Pending, 1 => Poll::Ready(Ok(())), _ => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())) }
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> { Poll::Ready(Ok(())) }
    }
    #[test]
    fn stalled_flush_blocks_all_writes_but_not_reads_and_propagates_errors() {
        let mut io = DrainBeforeWrite(Stalled { flush: 0, writes: 0 });
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let slices = [io::IoSlice::new(b"a"), io::IoSlice::new(b"bc")];
        assert!(io.is_write_vectored());
        for _ in 0..100 {
            assert!(Pin::new(&mut io).poll_write(&mut cx, b"x").is_pending());
            assert!(Pin::new(&mut io).poll_write_vectored(&mut cx, &slices).is_pending());
            let mut bytes = [0]; let mut out = ReadBuf::new(&mut bytes);
            assert!(matches!(Pin::new(&mut io).poll_read(&mut cx, &mut out), Poll::Ready(Ok(()))));
            assert_eq!(out.filled(), b"x");
        }
        assert_eq!(io.0.writes, 0);
        io.0.flush = 1;
        assert!(matches!(Pin::new(&mut io).poll_write(&mut cx, b"x"), Poll::Ready(Ok(1))));
        assert!(matches!(Pin::new(&mut io).poll_write_vectored(&mut cx, &slices), Poll::Ready(Ok(3))));
        io.0.flush = 2;
        assert!(matches!(Pin::new(&mut io).poll_write(&mut cx, b"x"), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe));
        assert!(matches!(Pin::new(&mut io).poll_write_vectored(&mut cx, &slices), Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe));
        assert_eq!(io.0.writes, 2);
    }
}
