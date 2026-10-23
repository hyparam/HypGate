//! Verified scanner over an explicit trusted sequential-read/checksum interface.
use vstd::prelude::*;
use vstd::slice::slice_subrange;
use crate::framing::{self, Cursor, RecoveredRecord};

verus! {
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError { Eof, Incomplete, Io }
#[derive(Debug, PartialEq, Eq)]
pub enum ScanError { Incomplete, Io, Corrupt }

// Implementations outside the verified crate are trusted to satisfy these
// contracts. The data model is a stable byte stream relative to construction.
pub trait Source: Sized {
    spec fn valid(&self) -> bool;
    spec fn data(&self) -> Seq<u8>;
    spec fn position(&self) -> nat;
    spec fn io_errors(&self) -> nat;
    spec fn digest(bytes: Seq<u8>) -> Seq<u8>;

    fn read_exact(&mut self, length: usize) -> (out: Result<Vec<u8>, ReadError>)
        requires old(self).valid(), length <= 1048576,
        ensures final(self).valid(), final(self).data() == old(self).data(),
            old(self).position() <= final(self).position() <= final(self).data().len(),
            final(self).io_errors() == old(self).io_errors()
                + match out { Err(ReadError::Io) => 1nat, _ => 0nat },
            match out {
                Ok(bytes) => bytes.len() == length
                    && final(self).position() == old(self).position() + length
                    && bytes@ == final(self).data().subrange(old(self).position() as int, final(self).position() as int),
                Err(ReadError::Eof) => length > 0 && old(self).position() == final(self).data().len()
                    && final(self).position() == old(self).position(),
                Err(ReadError::Incomplete) => length > 0 && old(self).position() + length > final(self).data().len()
                    && final(self).position() == final(self).data().len(),
                Err(ReadError::Io) => true,
            };

    fn checksum_valid(&self, header: &[u8], payload: &[u8], checksum: &[u8]) -> (ok: bool)
        ensures ok == (Self::digest(header@ + payload@) == checksum@);
}

pub open spec fn complete_record<R: Source>(data: Seq<u8>, start: nat) -> bool {
    start + 33 <= data.len() && match framing::decoded(data.subrange(start as int, start as int + 33)) {
        Some(h) => {
            let end = start + 65 + h.payload;
            end <= data.len() && end <= u64::MAX
                && R::digest(data.subrange(start as int, end as int - 32))
                    == data.subrange(end as int - 32, end as int)
        },
        None => false,
    }
}

pub struct Scanner<R: Source> { source: R, cursor: Cursor, session: [u8; 16] }
impl<R: Source> Scanner<R> {
    pub closed spec fn valid(&self) -> bool {
        self.source.valid() && self.cursor.position() <= self.source.position()
            && (!self.cursor.stopped() ==> self.cursor.position() == self.source.position())
    }
    pub closed spec fn data(&self) -> Seq<u8> { self.source.data() }
    pub closed spec fn position(&self) -> u64 { self.cursor.position() }
    pub closed spec fn io_errors(&self) -> nat { self.source.io_errors() }
    pub closed spec fn session_id(&self) -> [u8; 16] { self.session }
    pub closed spec fn stopped(&self) -> bool { self.cursor.stopped() }

    pub fn new(mut source: R) -> (out: Result<Self, ScanError>)
        requires source.valid(), source.position() == 0,
        ensures match out {
            Ok(scanner) => scanner.valid() && scanner.position() == 56 && !scanner.stopped()
                && scanner.data() == source.data()
                && scanner.data().subrange(0, 24) == framing::session_encoding(scanner.session_id()@)
                && R::digest(scanner.data().subrange(0, 24)) == scanner.data().subrange(24, 56),
            Err(_) => true,
        },
    {
        let header = match source.read_exact(56) {
            Ok(bytes) => bytes,
            Err(ReadError::Io) => return Err(ScanError::Io),
            Err(_) => return Err(ScanError::Incomplete),
        };
        let prefix = slice_subrange(header.as_slice(), 0, 24);
        let checksum = slice_subrange(header.as_slice(), 24, 56);
        let empty: Vec<u8> = Vec::new();
        let checked = source.checksum_valid(prefix, empty.as_slice(), checksum);
        proof { assert(prefix@ + empty@ =~= prefix@); }
        let session = match framing::decode_session(prefix, checked) {
            Some(session) => session, None => return Err(ScanError::Corrupt),
        };
        proof {
            assert(prefix@ =~= source.data().subrange(0, 24));
            assert(checksum@ =~= source.data().subrange(24, 56));
        }
        Ok(Scanner { source, cursor: Cursor::new(56), session })
    }

    pub fn session(&self) -> (out: [u8; 16])
        ensures out == self.session_id(),
    { self.session }
    pub fn offset(&self) -> (out: u64)
        ensures out == self.position(),
    { self.cursor.offset() }

    pub fn next_record(&mut self) -> (out: Result<Option<RecoveredRecord>, ScanError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).data() == old(self).data(),
            final(self).session_id() == old(self).session_id(),
            match out {
                Ok(Some(record)) => !old(self).stopped() && !final(self).stopped()
                    && final(self).position() == old(self).position() + 65 + record.bytes.len()
                    && final(self).position() <= final(self).data().len()
                    && framing::decoded(final(self).data().subrange(old(self).position() as int,
                        old(self).position() as int + 33)) == Some(record.header)
                    && record.bytes@ == final(self).data().subrange(old(self).position() as int + 33,
                        final(self).position() as int - 32)
                    && framing::valid(record.header) && record.header.payload == record.bytes.len()
                    && R::digest(final(self).data().subrange(old(self).position() as int,
                        final(self).position() as int - 32)) == final(self).data().subrange(
                        final(self).position() as int - 32, final(self).position() as int),
                Ok(None) => final(self).stopped() && final(self).position() == old(self).position()
                    && (old(self).stopped() || old(self).position() == old(self).data().len()),
                Err(error) => final(self).stopped() && final(self).position() == old(self).position()
                    && match error {
                        ScanError::Io => final(self).io_errors() > old(self).io_errors(),
                        _ => !complete_record::<R>(old(self).data(), old(self).position() as nat),
                    },
            },
    {
        let ticket = match self.cursor.begin() { Some(ticket) => ticket, None => return Ok(None) };
        let header = match self.source.read_exact(33) {
            Ok(bytes) => bytes,
            Err(ReadError::Eof) => return Ok(None),
            Err(ReadError::Incomplete) => return Err(ScanError::Incomplete),
            Err(ReadError::Io) => return Err(ScanError::Io),
        };
        let fields = match framing::decode(header.as_slice()) {
            Some(fields) => fields, None => return Err(ScanError::Corrupt),
        };
        let bytes = match self.source.read_exact(fields.payload as usize) {
            Ok(bytes) => bytes,
            Err(ReadError::Io) => return Err(ScanError::Io),
            Err(_) => return Err(ScanError::Incomplete),
        };
        let checksum = match self.source.read_exact(32) {
            Ok(bytes) => bytes,
            Err(ReadError::Io) => return Err(ScanError::Io),
            Err(_) => return Err(ScanError::Incomplete),
        };
        let checked = self.source.checksum_valid(header.as_slice(), bytes.as_slice(), checksum.as_slice());
        proof {
            assert(header@ + bytes@ =~= self.source.data().subrange(old(self).position() as int,
                self.source.position() as int - 32));
        }
        match self.cursor.accept_record(ticket, header.as_slice(), bytes, checked) {
            Some(record) => Ok(Some(record)),
            None => Err(ScanError::Corrupt),
        }
    }
}
}
