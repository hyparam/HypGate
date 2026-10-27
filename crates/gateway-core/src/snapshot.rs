//! Bounded snapshot reads and seeks, verified over primitive file effects.
use vstd::prelude::*;
use crate::recovery::{ReadError, SeekSource, Source};

verus! {
/// A primitive short read into the supplied buffer, or an absolute seek.
/// Metadata, bytes, syscall outcomes, and checksum correspondence are trusted.
/// The core, not this interface, chooses the snapshot limit and every read size.
/// A failed read may advance the file cursor within the requested extent; the
/// snapshot must not read again until a successful seek establishes its position.
pub trait FileRead {
    spec fn valid(&self) -> bool;
    spec fn data(&self) -> Seq<u8>;
    spec fn position(&self) -> nat;
    spec fn digest(bytes: Seq<u8>) -> Seq<u8>;

    fn fill(&mut self, buffer: &mut Vec<u8>, max: usize) -> (ok: bool)
        requires old(self).valid(), max > 0, old(buffer).len() + max <= 1048576,
            old(self).position() + max <= old(self).data().len(),
        ensures final(self).valid(), final(self).data() == old(self).data(),
            if ok {
                old(buffer).len() < final(buffer).len() <= old(buffer).len() + max
                && final(self).position() == old(self).position() + final(buffer).len() - old(buffer).len()
                && final(buffer)@ == old(buffer)@ + old(self).data().subrange(old(self).position() as int, final(self).position() as int)
            } else { final(buffer)@ == old(buffer)@
                && old(self).position() <= final(self).position() <= old(self).position() + max };
    fn seek(&mut self, offset: u64) -> (ok: bool)
        requires old(self).valid(), offset <= old(self).data().len(),
        ensures final(self).valid(), final(self).data() == old(self).data(),
            final(self).position() == if ok { offset as nat } else { old(self).position() };
    fn checksum_valid(&self, header: &[u8], payload: &[u8], checksum: &[u8]) -> (ok: bool)
        ensures ok == (Self::digest(header@ + payload@) == checksum@);
}

pub struct Snapshot<R: FileRead> {
    file: R, length: u64, position: u64, failed: bool,
    errors: Ghost<nat>,
}
impl<R: FileRead> Snapshot<R> {
    pub fn new(file: R, length: u64) -> (out: Self)
        requires file.valid(), file.position() == 0, length <= file.data().len(),
        ensures out.valid(), out.position() == 0, out.data() == file.data().take(length as int),
            out.io_errors() == 0,
    { Self { file, length, position: 0, failed: false, errors: Ghost(0) } }
}
impl<R: FileRead> Source for Snapshot<R> {
    closed spec fn valid(&self) -> bool {
        self.file.valid() && self.position <= self.length <= self.file.data().len()
            && self.file.position() <= self.length
            && (!self.failed ==> self.file.position() == self.position)
    }
    closed spec fn data(&self) -> Seq<u8> { self.file.data().take(self.length as int) }
    closed spec fn position(&self) -> nat { self.file.position() }
    closed spec fn io_errors(&self) -> nat { self.errors@ }
    open spec fn digest(bytes: Seq<u8>) -> Seq<u8> { R::digest(bytes) }

    fn read_exact(&mut self, length: usize) -> (out: Result<Vec<u8>, ReadError>) {
        // A failed syscall may have moved the underlying cursor by an unknown
        // amount. Only a successful absolute seek can reestablish its value.
        if self.failed { proof { self.errors@ = self.errors@ + 1; } return Err(ReadError::Io); }
        let mut bytes: Vec<u8> = Vec::new();
        proof { assert(bytes@ =~= self.file.data().subrange(self.position as int, self.position as int)); }
        while bytes.len() < length
            invariant self.valid(), old(self).valid(), !self.failed, !old(self).failed, bytes.len() <= length <= 1048576,
                self.length == old(self).length, self.file.data() == old(self).file.data(),
                self.io_errors() == old(self).io_errors(),
                self.position == old(self).position + bytes.len(),
                bytes@ == self.file.data().subrange(old(self).position as int, self.position as int),
            decreases length - bytes.len(),
        {
            let remaining = self.length - self.position;
            if remaining == 0 {
                return Err(if bytes.len() == 0 { ReadError::Eof } else { ReadError::Incomplete });
            }
            let needed = length - bytes.len();
            let max = if remaining < needed as u64 { remaining as usize } else { needed };
            let before = bytes.len();
            let ghost prior = bytes@;
            let ghost at = self.position;
            if !self.file.fill(&mut bytes, max) {
                self.failed = true;
                proof { self.errors@ = self.errors@ + 1; }
                return Err(ReadError::Io);
            }
            self.position += (bytes.len() - before) as u64;
            proof {
                assert(prior + self.file.data().subrange(at as int, self.position as int)
                    =~= self.file.data().subrange(old(self).position as int, self.position as int));
            }
        }
        proof { assert(bytes@ =~= self.data().subrange(old(self).position as int, self.position as int)); }
        Ok(bytes)
    }
    fn checksum_valid(&self, header: &[u8], payload: &[u8], checksum: &[u8]) -> (ok: bool) {
        self.file.checksum_valid(header, payload, checksum)
    }
}
impl<R: FileRead> SeekSource for Snapshot<R> {
    fn seek(&mut self, offset: u64) -> (ok: bool) {
        if offset > self.length { return false; }
        if !self.file.seek(offset) { return false; }
        self.position = offset;
        self.failed = false;
        true
    }
}
}
