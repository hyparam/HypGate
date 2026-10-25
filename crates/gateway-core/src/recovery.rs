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

proof fn matching_subrange(data: Seq<u8>, whole: Seq<u8>, start: nat, lo: nat, hi: nat)
    requires start + whole.len() <= data.len(), lo <= hi <= whole.len(),
        data.subrange(start as int, (start + whole.len()) as int) == whole,
    ensures data.subrange((start + lo) as int, (start + hi) as int)
        == whole.subrange(lo as int, hi as int),
{
    assert forall|i: int| 0 <= i < hi - lo implies
        data.subrange((start + lo) as int, (start + hi) as int)[i]
            == whole.subrange(lo as int, hi as int)[i] by {
        assert(data.subrange(start as int, (start + whole.len()) as int)[lo + i] == whole[lo + i]);
    }
    assert(data.subrange((start + lo) as int, (start + hi) as int)
        =~= whole.subrange(lo as int, hi as int));
}

pub proof fn canonical_frame_is_complete<R: Source>(frame: &framing::RecordFrame,
    data: Seq<u8>, start: nat)
    requires frame.valid(), start + frame.contents().len() <= data.len(),
        start + frame.contents().len() <= u64::MAX,
        data.subrange(start as int, (start + frame.contents().len()) as int) == frame.contents(),
        R::digest(framing::encoding(frame.header()) + frame.payload()) == frame.checksum(),
    ensures complete_record::<R>(data, start),
        framing::decoded(data.subrange(start as int, start as int + 33)) == Some(frame.header()),
        data.subrange(start as int + 33, (start + frame.contents().len()) as int - 32) == frame.payload(),
        frame.contents().len() == 65 + frame.payload().len(),
{
    frame.retained_size();
    let end = start + frame.contents().len();
    matching_subrange(data, frame.contents(), start, 33, (frame.contents().len() - 32) as nat);
    matching_subrange(data, frame.contents(), start, (frame.contents().len() - 32) as nat, frame.contents().len());
    assert(data.subrange(start as int, start as int + 33) =~= framing::encoding(frame.header()));
    assert(data.subrange(start as int + 33, end as int - 32) =~= frame.payload());
    assert(data.subrange(start as int, end as int - 32) =~= framing::encoding(frame.header()) + frame.payload());
    assert(data.subrange(end as int - 32, end as int) =~= frame.checksum());
}

pub struct Scanner<R: Source> { source: R, cursor: Cursor, session: [u8; 16] }
pub open spec fn scanner_step<R: Source>(before: &Scanner<R>, after: &Scanner<R>,
    out: Result<Option<RecoveredRecord>, ScanError>) -> bool {
    after.valid() && after.data() == before.data() && after.session_id() == before.session_id()
        && match out {
                Ok(Some(record)) => !before.stopped() && !after.stopped()
                    && after.position() == before.position() + 65 + record.bytes.len()
                    && after.position() <= after.data().len()
                    && framing::decoded(after.data().subrange(before.position() as int,
                        before.position() as int + 33)) == Some(record.header)
                    && record.bytes@ == after.data().subrange(before.position() as int + 33,
                        after.position() as int - 32)
                    && framing::valid(record.header) && record.header.payload == record.bytes.len()
                    && R::digest(after.data().subrange(before.position() as int,
                        after.position() as int - 32)) == after.data().subrange(
                        after.position() as int - 32, after.position() as int),
                Ok(None) => after.stopped() && after.position() == before.position()
                    && (before.stopped() || before.position() == before.data().len()),
                Err(error) => after.stopped() && after.position() == before.position()
                    && match error {
                        ScanError::Io => after.io_errors() > before.io_errors(),
                        _ => !complete_record::<R>(before.data(), before.position() as nat),
                    },
            }
}

pub proof fn recover_frame_step<R: Source>(before: &Scanner<R>, after: &Scanner<R>,
    out: Result<Option<RecoveredRecord>, ScanError>, frame: &framing::RecordFrame)
    requires before.valid(), !before.stopped(), scanner_step(before, after, out),
        after.io_errors() == before.io_errors(), frame.valid(),
        before.position() + frame.contents().len() <= before.data().len(),
        before.position() + frame.contents().len() <= u64::MAX,
        before.data().subrange(before.position() as int,
            (before.position() + frame.contents().len()) as int) == frame.contents(),
        R::digest(framing::encoding(frame.header()) + frame.payload()) == frame.checksum(),
    ensures !after.stopped(), after.position() == before.position() + frame.contents().len(),
        match out {
            Ok(Some(record)) => record.header == frame.header() && record.bytes@ == frame.payload(),
            _ => false,
        },
{
    canonical_frame_is_complete::<R>(frame, before.data(), before.position() as nat);
    frame.canonical();
}

// Every recovered header has a kind in 0..=4, and that kind is exactly the one
// the writer encoded: metadata records recover through the same step as body
// records, with their payload bytes returned unchanged for the metadata codecs.
pub proof fn recovered_kind_in_range<R: Source>(before: &Scanner<R>, after: &Scanner<R>,
    out: Result<Option<RecoveredRecord>, ScanError>)
    requires scanner_step(before, after, out),
    ensures match out {
        Ok(Some(record)) => record.header.kind <= 4
            && (framing::body_kind(record.header.kind) || framing::metadata_kind(record.header.kind)),
        _ => true,
    },
{}

pub proof fn recover_metadata_frame_step<R: Source>(before: &Scanner<R>, after: &Scanner<R>,
    out: Result<Option<RecoveredRecord>, ScanError>, frame: &framing::RecordFrame)
    requires before.valid(), !before.stopped(), scanner_step(before, after, out),
        after.io_errors() == before.io_errors(), frame.valid(), framing::metadata_kind(frame.header().kind),
        before.position() + frame.contents().len() <= before.data().len(),
        before.position() + frame.contents().len() <= u64::MAX,
        before.data().subrange(before.position() as int,
            (before.position() + frame.contents().len()) as int) == frame.contents(),
        R::digest(framing::encoding(frame.header()) + frame.payload()) == frame.checksum(),
    ensures !after.stopped(), after.position() == before.position() + frame.contents().len(),
        match out {
            Ok(Some(record)) => record.header == frame.header() && record.bytes@ == frame.payload()
                && framing::metadata_kind(record.header.kind) && !framing::body_kind(record.header.kind),
            _ => false,
        },
{
    recover_frame_step::<R>(before, after, out, frame);
}

pub proof fn reconstruct_prefix<R: Source>(frames: Seq<framing::RecordFrame>, data: Seq<u8>,
    start: nat, states: Seq<Scanner<R>>, results: Seq<Result<Option<RecoveredRecord>, ScanError>>)
    requires
        forall|i: int| 0 <= i < frames.len() ==> #[trigger] frames[i].valid(),
        forall|i: int| 0 <= i < frames.len() ==> R::digest(framing::encoding(frames[i].header())
            + frames[i].payload()) == #[trigger] frames[i].checksum(),
        start + crate::audit_journal::encoded_frames(frames).len() <= data.len(),
        start + crate::audit_journal::encoded_frames(frames).len() <= u64::MAX,
        data.subrange(start as int, (start + crate::audit_journal::encoded_frames(frames).len()) as int)
            == crate::audit_journal::encoded_frames(frames),
        states.len() == frames.len() + 1, results.len() == frames.len(),
        states[0].position() == start, !states[0].stopped(),
        forall|i: int| 0 <= i < states.len() ==> #[trigger] states[i].valid()
            && states[i].data() == data && states[i].io_errors() == states[0].io_errors(),
        forall|i: int| 0 <= i < results.len() ==> scanner_step(&states[i], &states[i + 1], results[i]),
    ensures !states.last().stopped(),
        states.last().position() == start + crate::audit_journal::encoded_frames(frames).len(),
        forall|i: int| 0 <= i < results.len() ==> match #[trigger] results[i] {
            Ok(Some(record)) => record.header == frames[i].header() && record.bytes@ == frames[i].payload(),
            _ => false,
        },
    decreases frames.len(),
{
    if frames.len() > 0 {
        let prior = frames.drop_last();
        let prefix = crate::audit_journal::encoded_frames(prior);
        let last = frames.last();
        assert(data.subrange(start as int, (start + prefix.len()) as int) =~= prefix);
        reconstruct_prefix::<R>(prior, data, start, states.drop_last(), results.drop_last());
        matching_subrange(data, crate::audit_journal::encoded_frames(frames), start,
            prefix.len(), crate::audit_journal::encoded_frames(frames).len());
        assert(data.subrange((start + prefix.len()) as int,
            (start + prefix.len() + last.contents().len()) as int) =~= last.contents());
        let i = results.len() as int - 1;
        assert(states[i].valid() && states[i + 1].valid());
        recover_frame_step::<R>(&states[i], &states[i + 1], results[i], &last);
        assert forall|j: int| 0 <= j < results.len() implies match #[trigger] results[j] {
            Ok(Some(record)) => record.header == frames[j].header() && record.bytes@ == frames[j].payload(),
            _ => false,
        } by {
            if j < i {
                assert(results[j] == results.drop_last()[j]);
                assert(frames[j] == prior[j]);
            } else { assert(frames[j] == last); }
        }
    }
}

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

    /// Continue scanning a file whose header was already validated by `new`,
    /// from a byte offset that an earlier scanner reported as its valid end.
    /// The caller supplies a source positioned at that offset over the same
    /// file; the offset being a record boundary and the session matching the
    /// file are trusted facts carried by the shipper's checkpoint.
    pub fn resume(source: R, session: [u8; 16], offset: u64) -> (out: Self)
        requires source.valid(), source.position() == offset, offset >= 56,
        ensures out.valid(), out.position() == offset, !out.stopped(),
            out.data() == source.data(), out.session_id() == session,
            out.io_errors() == source.io_errors(),
    { Scanner { source, cursor: Cursor::new(offset), session } }

    pub fn session(&self) -> (out: [u8; 16])
        ensures out == self.session_id(),
    { self.session }
    pub fn offset(&self) -> (out: u64)
        ensures out == self.position(),
    { self.cursor.offset() }

    pub fn next_record(&mut self) -> (out: Result<Option<RecoveredRecord>, ScanError>)
        requires old(self).valid(),
        ensures scanner_step(old(self), final(self), out),
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
