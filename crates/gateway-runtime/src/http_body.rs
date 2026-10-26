//! Trusted bridge between the HTTP adapter's byte streams and the byte-stream
//! core. A `Reader` binds a worker's HTTP role to the body it reads; a
//! `Charged` writer binds a role to the writer that frames body bytes onto a
//! connection. Roles are released when these are dropped, so a worker's
//! credit cannot return while one of its streams is still alive.
use std::io::{self, Read};
mod worker;
pub(crate) use worker::WorkerHttp;

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
impl<B: Read> Read for Reader<B> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> { self.body.as_mut().expect("live reader").read(out) }
}
