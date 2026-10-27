//! Trusted bridge between the HTTP adapter's byte streams and the byte-stream
//! core. A `Reader` binds a worker's HTTP role to the body it reads; a
//! `Charged` writer binds a role to the writer that frames body bytes onto a
//! connection. Roles are released when these are dropped, so a worker's
//! credit cannot return while one of its streams is still alive.
use std::io::{self, Read};
mod worker;
pub(crate) use worker::WorkerHttp;

/// A body source bound to a worker's reader role. Reads pass straight through
/// to the framed body. Fields drop in declaration order, so the body is gone
/// before the guard releases the role.
pub(crate) struct Reader<B> {
    body: B,
    #[allow(dead_code)] // held for its destructor
    charge: worker::ChargeGuard,
}
impl<B> Reader<B> {
    pub(crate) fn body(&self) -> &B { &self.body }
}
impl<B: Read> Read for Reader<B> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> { self.body.read(out) }
}
