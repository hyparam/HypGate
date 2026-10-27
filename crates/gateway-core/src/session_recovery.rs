//! Verified recovery across append-only segments of one logical journal.
use vstd::prelude::*;
use crate::{framing::{self, Header, RecoveredRecord}, recovery::{self, ScanError, Scanner, SeekSource, Source}};

verus! {
/// Immutable eventual bytes plus monotone observations of existing segments.
/// An open returns a bounded snapshot of those bytes. Once a matching successor
/// header has been observed, opening its predecessor returns the whole sealed
/// predecessor. Merely observing an unrelated adjacent file does not seal it.
/// Filesystem path/visibility correspondence is trusted. Snapshot bounds and
/// the writer's seal-before-create order are separately verified in `snapshot`
/// and `segment_protocol`; physical visibility of those effects remains assumed.
/// Header parsing, cursor selection, and every traversal decision are verified.
pub trait Files: Sized {
    type Reader: SeekSource;
    spec fn valid(&self) -> bool;
    spec fn contents(&self, index: u64) -> Seq<u8>;
    spec fn seen(&self, index: u64) -> bool;
    fn open(&mut self, index: u64) -> (out: Result<Option<Self::Reader>, ScanError>)
        requires old(self).valid(),
        ensures final(self).valid(),
            forall|i: u64| final(self).contents(i) == old(self).contents(i),
            forall|i: u64| old(self).seen(i) ==> final(self).seen(i),
            match out {
                Ok(Some(source)) => source.valid() && source.position() == 0
                    && source.data().is_prefix_of(final(self).contents(index)) && final(self).seen(index)
                    && ((index < u64::MAX && old(self).seen((index + 1) as u64)
                        && old(self).contents(index).len() >= 56 && old(self).contents((index + 1) as u64).len() >= 56
                        && old(self).contents(index).subrange(0, 24) == old(self).contents((index + 1) as u64).subrange(0, 24)
                        && Self::Reader::digest(old(self).contents((index + 1) as u64).subrange(0, 24))
                            == old(self).contents((index + 1) as u64).subrange(24, 56))
                        ==> source.data() == final(self).contents(index)),
                _ => true,
            };
}

/// A matching, checksummed successor header witnesses the writer's seal.
/// A foreign file or a mere filename collision does not establish a seal.
pub open spec fn sealed<F: Files>(files: &F, index: u64) -> bool {
    index < u64::MAX && files.seen((index + 1) as u64)
        && files.contents(index).len() >= 56 && files.contents((index + 1) as u64).len() >= 56
        && files.contents(index).subrange(0, 24) == files.contents((index + 1) as u64).subrange(0, 24)
        && F::Reader::digest(files.contents((index + 1) as u64).subrange(0, 24))
            == files.contents((index + 1) as u64).subrange(24, 56)
}

pub open spec fn header_valid<R: Source>(data: Seq<u8>, session: [u8; 16]) -> bool {
    data.len() >= 56 && data.subrange(0, 24) == framing::session_encoding(session@)
        && R::digest(data.subrange(0, 24)) == data.subrange(24, 56)
}

proof fn header_extends<R: Source>(data: Seq<u8>, full: Seq<u8>, session: [u8; 16])
    requires data.is_prefix_of(full), header_valid::<R>(data, session),
    ensures header_valid::<R>(full, session),
{
    assert(data.subrange(0, 24) =~= full.subrange(0, 24));
    assert(data.subrange(24, 56) =~= full.subrange(24, 56));
}

/// A cursor is reachable only by consuming complete records, starting exactly
/// after the file header. A malformed or incomplete tail cannot be jumped over.
pub open spec fn boundary<R: Source>(data: Seq<u8>, start: nat, end: nat) -> bool
    decreases (if end >= start { end - start } else { 0 }),
{
    start <= end && end <= data.len() && (start == end
        || (recovery::complete_record::<R>(data, start) && recovery::record_end(data, start) <= end
            && boundary::<R>(data, recovery::record_end(data, start), end)))
}

proof fn boundary_advance<R: Source>(data: Seq<u8>, start: nat, cursor: nat, end: nat)
    requires boundary::<R>(data, start, cursor), recovery::complete_record::<R>(data, cursor),
        end == recovery::record_end(data, cursor),
    ensures boundary::<R>(data, start, end),
    decreases cursor - start,
{
    assert(cursor < end <= data.len());
    if start < cursor { boundary_advance::<R>(data, recovery::record_end(data, start), cursor, end); }
    else { assert(boundary::<R>(data, end, end)); }
    reveal_with_fuel(boundary, 2);
}

proof fn boundary_end<R: Source>(data: Seq<u8>, start: nat)
    requires boundary::<R>(data, start, data.len()),
    ensures recovery::scan_end::<R>(data, start) == data.len(),
    decreases data.len() - start,
{
    if start < data.len() { boundary_end::<R>(data, recovery::record_end(data, start)); }
}

pub open spec fn closed_segment<F: Files>(files: &F, index: u64, session: [u8; 16]) -> bool {
    header_valid::<F::Reader>(files.contents(index), session)
        && recovery::scan_end::<F::Reader>(files.contents(index), 56) == files.contents(index).len()
}

/// All recoverable records in the preceding, consecutively numbered segments.
pub open spec fn preceding<F: Files>(files: &F, index: u64) -> Seq<(Header, Seq<u8>)>
    decreases index,
{
    if index == 0 { Seq::empty() }
    else { preceding(files, (index - 1) as u64) + recovery::records_from::<F::Reader>(files.contents((index - 1) as u64), 56) }
}

proof fn same_preceding<F: Files>(before: &F, after: &F, index: u64)
    requires forall|i: u64| before.contents(i) == after.contents(i),
    ensures preceding(before, index) == preceding(after, index),
    decreases index,
{
    if index > 0 { same_preceding(before, after, (index - 1) as u64); }
}

proof fn same_closed<F: Files>(before: &F, after: &F, index: u64, session: [u8; 16])
    requires forall|i: u64| before.contents(i) == after.contents(i),
        forall|i: u64| i < index ==> closed_segment(before, i, session),
    ensures forall|i: u64| i < index ==> closed_segment(after, i, session),
{
    assert forall|i: u64| i < index implies closed_segment(after, i, session) by {
        assert(closed_segment(before, i, session));
        assert(before.contents(i) == after.contents(i));
    }
}

fn open_scanner<F: Files>(files: &mut F, index: u64) -> (out: Result<Option<Scanner<F::Reader>>, ScanError>)
    requires old(files).valid(),
    ensures final(files).valid(),
        forall|i: u64| final(files).contents(i) == old(files).contents(i),
        forall|i: u64| old(files).seen(i) ==> final(files).seen(i),
        match out {
            Ok(Some(scanner)) => scanner.valid() && !scanner.stopped() && scanner.position() == 56
                && header_valid::<F::Reader>(scanner.data(), scanner.session_id())
                && scanner.data().is_prefix_of(final(files).contents(index)) && final(files).seen(index)
                && (sealed(old(files), index) ==> scanner.data() == final(files).contents(index)),
            _ => true,
        },
{
    let source = match files.open(index) {
        Ok(Some(source)) => source,
        Ok(None) => return Ok(None),
        Err(error) => return Err(error),
    };
    match Scanner::new(source) {
        Ok(scanner) => Ok(Some(scanner)), Err(error) => Err(error),
    }
}

pub struct SessionScanner<F: Files> {
    files: F,
    scanner: Option<Scanner<F::Reader>>,
    session: [u8; 16],
    index: u64,
    offset: u64,
    failed: bool,
    emitted: Ghost<Seq<(Header, Seq<u8>)>>,
}
impl<F: Files> SessionScanner<F> {
    pub closed spec fn files(&self) -> F { self.files }
    pub closed spec fn session_id(&self) -> [u8; 16] { self.session }
    pub closed spec fn index(&self) -> u64 { self.index }
    pub closed spec fn position(&self) -> u64 { self.offset }
    pub closed spec fn failed(&self) -> bool { self.failed }
    pub closed spec fn emitted(&self) -> Seq<(Header, Seq<u8>)> { self.emitted@ }
    pub closed spec fn valid(&self) -> bool {
        self.files.valid() && self.offset >= 56
            && header_valid::<F::Reader>(self.files.contents(self.index), self.session)
            && boundary::<F::Reader>(self.files.contents(self.index), 56, self.offset as nat)
            && (forall|i: u64| i < self.index ==> closed_segment(&self.files, i, self.session))
            && self.emitted@ + recovery::records_from::<F::Reader>(self.files.contents(self.index), self.offset as nat)
                == preceding(&self.files, self.index) + recovery::records_from::<F::Reader>(self.files.contents(self.index), 56)
            && match self.scanner {
                Some(scanner) => scanner.valid() && !scanner.stopped() && scanner.position() == self.offset
                    && scanner.session_id() == self.session && scanner.data().is_prefix_of(self.files.contents(self.index)),
                None => true,
            }
    }
    pub fn new(mut files: F) -> (out: Result<Self, ScanError>)
        requires files.valid(),
        ensures match out {
            Ok(scanner) => scanner.valid() && scanner.index() == 0 && scanner.position() == 56
                && !scanner.failed() && scanner.emitted() == Seq::<(Header, Seq<u8>)>::empty(),
            Err(_) => true,
        },
    {
        let scanner = match open_scanner(&mut files, 0) {
            Ok(Some(scanner)) => scanner,
            Ok(None) => return Err(ScanError::Io),
            Err(error) => return Err(error),
        };
        let session = scanner.session();
        proof { header_extends::<F::Reader>(scanner.data(), files.contents(0), session); }
        let out = Self { files, scanner: Some(scanner), session, index: 0, offset: 56,
            failed: false, emitted: Ghost(Seq::empty()) };
        proof { assert(Seq::<(Header, Seq<u8>)>::empty() + recovery::records_from::<F::Reader>(out.files.contents(0), 56)
            =~= recovery::records_from::<F::Reader>(out.files.contents(0), 56)); }
        Ok(out)
    }
    pub proof fn recovered_prefix(&self)
        requires self.valid(),
        ensures self.emitted().is_prefix_of(preceding(&self.files(), self.index())
                + recovery::records_from::<F::Reader>(self.files().contents(self.index()), 56)),
            forall|i: u64| i < self.index() ==> closed_segment(&self.files(), i, self.session_id()),
            boundary::<F::Reader>(self.files().contents(self.index()), 56, self.position() as nat),
    {
        let all = preceding(&self.files, self.index) + recovery::records_from::<F::Reader>(self.files.contents(self.index), 56);
        assert(self.emitted@ =~= all.take(self.emitted@.len() as int));
    }

    /// At the actual end of the current file, all complete records in every
    /// segment through that file have been emitted exactly once.
    pub proof fn recovered_to_end(&self)
        requires self.valid(), self.position() == self.files().contents(self.index()).len(),
        ensures self.emitted() == preceding(&self.files(), self.index())
            + recovery::records_from::<F::Reader>(self.files().contents(self.index()), 56),
    {
        assert(!recovery::complete_record::<F::Reader>(self.files.contents(self.index), self.offset as nat));
        assert(self.emitted@ + Seq::<(Header, Seq<u8>)>::empty() =~= self.emitted@);
    }

    pub fn session(&self) -> (out: [u8; 16]) ensures out == self.session_id(), { self.session }
    pub fn segment(&self) -> (out: u64) ensures out == self.index(), { self.index }
    pub fn offset(&self) -> (out: u64) ensures out == self.position(), { self.offset }

    /// Every returned record extends the exact recovered sequence by one. No
    /// record is repeated or omitted, including across snapshot refreshes.
    pub fn next_record(&mut self) -> (out: Result<Option<RecoveredRecord>, ScanError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).session_id() == old(self).session_id(),
            final(self).index() >= old(self).index(),
            forall|i: u64| final(self).files().contents(i) == old(self).files().contents(i),
            match out {
                Ok(Some(record)) => final(self).emitted() == old(self).emitted().push((record.header, record.bytes@)),
                _ => final(self).emitted() == old(self).emitted(),
            },
            old(self).failed() ==> *final(self) == *old(self),
            matches!(out, Err(ScanError::Io) | Err(ScanError::Corrupt)) ==> final(self).failed(),
    {
        if self.failed { return Ok(None); }
        let out = self.step();
        if matches!(out, Err(ScanError::Io) | Err(ScanError::Corrupt)) { self.failed = true; }
        out
    }

    fn read_current(&mut self) -> (out: Result<Option<RecoveredRecord>, ScanError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).session == old(self).session,
            final(self).index == old(self).index, final(self).failed == old(self).failed,
            forall|i: u64| final(self).files.contents(i) == old(self).files.contents(i),
            forall|i: u64| old(self).files.seen(i) ==> final(self).files.seen(i),
            match out {
                Ok(Some(record)) => final(self).emitted@ == old(self).emitted@.push((record.header, record.bytes@))
                    && final(self).offset == old(self).offset + 65 + record.bytes.len(),
                _ => final(self).emitted@ == old(self).emitted@ && final(self).offset == old(self).offset
                    && final(self).scanner.is_none(),
            },
            out is Ok && out->Ok_0.is_none() && old(self).scanner.is_none()
                && sealed(&old(self).files, old(self).index)
                ==> final(self).offset == final(self).files.contents(final(self).index).len(),
    {
        let mut scanner = match self.scanner.take() {
            Some(scanner) => scanner,
            None => {
                let opened = open_scanner(&mut self.files, self.index);
                proof { same_preceding(&old(self).files, &self.files, self.index);
                    same_closed(&old(self).files, &self.files, self.index, self.session); }
                let scanner = match opened {
                    Ok(Some(scanner)) => scanner,
                    Ok(None) => return Err(ScanError::Io),
                    Err(error) => return Err(error),
                };
                proof { same_preceding(&old(self).files, &self.files, self.index);
                    same_closed(&old(self).files, &self.files, self.index, self.session); }
                if scanner.session() != self.session { return Err(ScanError::Corrupt); }
                match scanner.restart(self.offset) {
                    Ok(scanner) => scanner,
                    Err(error) => return Err(error),
                }
            }
        };
        let ghost before = scanner;
        let out = scanner.next_record();
        match out {
            Ok(Some(record)) => {
                self.offset = scanner.offset();
                proof {
                    let data = before.data();
                    let full = self.files.contents(self.index);
                    let start = old(self).offset as nat;
                    assert(recovery::complete_record::<F::Reader>(data, start));
                    recovery::lemma_complete_extends::<F::Reader>(data, full, start);
                    assert(recovery::record_end(full, start) == self.offset);
                    boundary_advance::<F::Reader>(full, 56, start, self.offset as nat);
                    assert(recovery::record_at(full, start) == (record.header, record.bytes@));
                    self.emitted@ = self.emitted@.push((record.header, record.bytes@));
                    assert(self.emitted@ + recovery::records_from::<F::Reader>(full, self.offset as nat)
                        =~= preceding(&self.files, self.index) + recovery::records_from::<F::Reader>(full, 56));
                }
                proof {
                    assert(scanner.valid());
                    assert(!scanner.stopped());
                    assert(scanner.position() == self.offset);
                    assert(scanner.session_id() == self.session);
                    assert(scanner.data().is_prefix_of(self.files.contents(self.index)));
                }
                self.scanner = Some(scanner);
                assert(self.valid());
                Ok(Some(record))
            }
            Ok(None) => { assert(self.valid()); Ok(None) },
            Err(error) => { assert(self.valid()); Err(error) },
        }
    }

    fn step(&mut self) -> (out: Result<Option<RecoveredRecord>, ScanError>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).session == old(self).session,
            final(self).index >= old(self).index,
            forall|i: u64| final(self).files.contents(i) == old(self).files.contents(i),
            match out {
                Ok(Some(record)) => final(self).emitted@ == old(self).emitted@.push((record.header, record.bytes@)),
                _ => final(self).emitted@ == old(self).emitted@,
            },
    {
        loop
            invariant self.valid(), self.session == old(self).session,
                self.index >= old(self).index, self.emitted@ == old(self).emitted@,
                forall|i: u64| self.files.contents(i) == old(self).files.contents(i),
            decreases u64::MAX - self.index,
        {
            match self.read_current() {
                Ok(None) => {},
                other => return other,
            }
            if self.index == u64::MAX { return Err(ScanError::Corrupt); }
            let next = self.index + 1;
            let ghost before_files = self.files;
            let opened = open_scanner(&mut self.files, next);
            proof { same_preceding(&before_files, &self.files, self.index);
                same_closed(&before_files, &self.files, self.index, self.session); }
            let candidate = match opened {
                Ok(Some(scanner)) => scanner,
                Ok(None) => return Ok(None),
                Err(error) => return Err(error),
            };
            proof { same_preceding(&before_files, &self.files, self.index);
                same_closed(&before_files, &self.files, self.index, self.session); }
            if candidate.session() != self.session { return Err(ScanError::Corrupt); }
            proof {
                assert(header_valid::<F::Reader>(candidate.data(), candidate.session_id()));
                assert(candidate.session_id()@ == self.session@);
                assert(header_valid::<F::Reader>(candidate.data(), self.session));
                header_extends::<F::Reader>(candidate.data(), self.files.contents(next), self.session);
                assert(sealed(&self.files, self.index));
            }
            // Discovering a successor seals the predecessor. Reopening it now
            // closes the race between an earlier snapshot EOF and rotation.
            match self.read_current() {
                Ok(None) => {},
                other => return other,
            }
            proof {
                assert(self.offset == self.files.contents(self.index).len());
                boundary_end::<F::Reader>(self.files.contents(self.index), 56);
                assert(closed_segment(&self.files, self.index, self.session));
                assert forall|i: u64| i < next implies closed_segment(&self.files, i, self.session) by {
                    if i != self.index { assert(i < self.index); }
                }
                header_extends::<F::Reader>(candidate.data(), self.files.contents(next), self.session);
                assert(!recovery::complete_record::<F::Reader>(self.files.contents(self.index), self.offset as nat));
                assert(self.emitted@ =~= preceding(&self.files, next));
            }
            proof {
                assert(candidate.valid());
                assert(!candidate.stopped());
                assert(candidate.position() == 56);
                assert(candidate.session_id() == self.session);
            }
            self.index = next;
            self.offset = 56;
            self.scanner = Some(candidate);
            proof {
                assert(self.scanner->Some_0.data().is_prefix_of(self.files.contents(self.index)));
 assert(self.emitted@ + recovery::records_from::<F::Reader>(self.files.contents(self.index), 56)
                =~= preceding(&self.files, self.index) + recovery::records_from::<F::Reader>(self.files.contents(self.index), 56)); }
        }
    }
}
}
