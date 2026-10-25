//! Verified NDJSON batch assembly within the server's row and byte limits. The
//! builder owns the body: each accepted row is appended unchanged followed by
//! one newline, and no state can exceed 5,000 rows or 4 MiB. A row that could
//! never fit is reported as oversized so the caller can poison it instead of
//! splitting it.
use vstd::prelude::*;
use crate::framing::append;

verus! {
pub const MAX_ROWS: usize = 5000;
pub const MAX_BYTES: usize = 4 * 1024 * 1024;

pub struct BatchBuilder { body: Vec<u8>, rows: usize }

impl BatchBuilder {
    pub closed spec fn body(&self) -> Seq<u8> { self.body@ }
    pub closed spec fn rows(&self) -> nat { self.rows as nat }
    pub closed spec fn valid(&self) -> bool { self.rows <= MAX_ROWS && self.body@.len() <= MAX_BYTES }

    pub fn new() -> (out: Self)
        ensures out.valid(), out.rows() == 0, out.body() == Seq::<u8>::empty(),
    { BatchBuilder { body: Vec::new(), rows: 0 } }

    pub fn row_count(&self) -> (out: usize) ensures out == self.rows(), { self.rows }
    pub fn len(&self) -> (out: usize) ensures out == self.body().len(), { self.body.len() }
    pub fn is_empty(&self) -> (out: bool) ensures out == (self.rows() == 0), { self.rows == 0 }
    pub fn bytes(&self) -> (out: &Vec<u8>) ensures out@ == self.body(), { &self.body }

    /// A row that no batch can hold, with or without other rows.
    pub fn oversized(row: &[u8]) -> (out: bool)
        ensures out == (row@.len() + 1 > MAX_BYTES),
    { row.len() >= MAX_BYTES }

    /// Append one row and its newline when both limits still hold afterwards.
    pub fn push(&mut self, row: &[u8]) -> (ok: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            ok == (old(self).rows() < MAX_ROWS && old(self).body().len() + row@.len() + 1 <= MAX_BYTES),
            ok ==> final(self).rows() == old(self).rows() + 1
                && final(self).body() == old(self).body() + row@ + seq![10u8],
            !ok ==> *final(self) == *old(self),
    {
        if self.rows >= MAX_ROWS || row.len() >= MAX_BYTES - self.body.len() { return false; }
        append(&mut self.body, row);
        self.body.push(10);
        self.rows = self.rows + 1;
        true
    }

    /// Take the finished body, leaving an empty builder.
    pub fn finish(&mut self) -> (out: Vec<u8>)
        requires old(self).valid(),
        ensures out@ == old(self).body(), final(self).valid(), final(self).rows() == 0,
            final(self).body() == Seq::<u8>::empty(),
    {
        let mut body = Vec::new();
        core::mem::swap(&mut body, &mut self.body);
        self.rows = 0;
        body
    }
}
}
