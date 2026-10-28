//! SSE data framing: dispatch only on blank lines, join data fields with LF,
//! remove exactly one optional space, and accept LF, CRLF, or CR line endings.
//! An unterminated final event is discarded, as required by the event-stream protocol.
use vstd::prelude::*;
use vstd::slice::slice_subrange;

verus! {
pub const DATA: [u8; 4] = *b"data";
pub const DATA_COLON: [u8; 5] = *b"data:";
pub open spec fn delimiter(b: u8) -> bool { b == 10 || b == 13 }
pub open spec fn line_boundary(bytes: Seq<u8>, start: int, end: int) -> bool {
    start <= end <= bytes.len() && (end == bytes.len() || delimiter(bytes[end]))
        && forall|i: int| start <= i < end ==> !delimiter(bytes[i])
}
pub open spec fn line_end(bytes: Seq<u8>, start: int) -> int
    recommends 0 <= start <= bytes.len(),
{
    choose|end: int| line_boundary(bytes, start, end)
}
pub open spec fn after_line(bytes: Seq<u8>, end: int) -> int
    recommends 0 <= end <= bytes.len(),
{
    if end == bytes.len() { end }
    else if bytes[end] == 13 && end + 1 < bytes.len() && bytes[end + 1] == 10 { end + 2 }
    else { end + 1 }
}
pub open spec fn data_value(line: Seq<u8>) -> Option<Seq<u8>> {
    if line == DATA@ { Some(Seq::empty()) }
    else if line.len() >= 5 && line.subrange(0, 5) == DATA_COLON@ {
        let start = if line.len() > 5 && line[5] == 32 { 6int } else { 5int };
        Some(line.subrange(start, line.len() as int))
    } else { None }
}
pub open spec fn joined(data: Seq<u8>, present: bool, more: Seq<u8>) -> Seq<u8> {
    (if present { data + seq![10u8] } else { Seq::empty() }) + more
}
/// Independent functional grammar: data fields accumulate until a blank line;
/// comments and other fields do not change the pending data. EOF never dispatches.
#[verifier::opaque]
pub open spec fn scan(bytes: Seq<u8>, start: int, data: Seq<u8>, present: bool) -> Seq<Seq<u8>>
    decreases bytes.len() - start,
{
    if start < 0 || start >= bytes.len() { Seq::empty() }
    else {
        let end = line_end(bytes, start);
        let next = after_line(bytes, end);
        if end < start || end >= bytes.len() || next <= start || next > bytes.len() { Seq::empty() }
        else {
            let line = bytes.subrange(start, end);
            if line.len() == 0 {
                (if present { seq![data] } else { Seq::empty() }) + scan(bytes, next, Seq::empty(), false)
            } else {
                match data_value(line) {
                    Some(more) => scan(bytes, next, joined(data, present, more), true),
                    None => scan(bytes, next, data, present),
                }
            }
        }
    }
}
pub open spec fn event_data(bytes: Seq<u8>) -> Seq<Seq<u8>> { scan(bytes, 0, Seq::empty(), false) }

fn read_line(bytes: &[u8], start: usize) -> (out: (usize, usize))
    requires start < bytes.len(),
    ensures start <= out.0 <= bytes.len(), start < out.1 <= bytes.len(),
        out.0 == line_end(bytes@, start as int), out.1 == after_line(bytes@, out.0 as int),
{
    let mut end = start;
    while end < bytes.len() && bytes[end] != 10 && bytes[end] != 13
        invariant start <= end <= bytes.len(), forall|i: int| start <= i < end ==> !delimiter(bytes@[i]),
        decreases bytes.len() - end,
    { end = end + 1; }
    proof {
        assert(start <= end <= bytes.len() && (end == bytes.len() || delimiter(bytes@[end as int]))
            && forall|i: int| start <= i < end ==> !delimiter(bytes@[i]));
        assert(line_boundary(bytes@, start as int, end as int));
        assert(exists|e: int| line_boundary(bytes@, start as int, e));
        let chosen = line_end(bytes@, start as int);
        assert(chosen == end) by {
            if chosen < end { assert(!delimiter(bytes@[chosen])); }
            if chosen > end { assert(!delimiter(bytes@[end as int])); }
        }
    }
    let next = if end == bytes.len() { end }
        else if bytes[end] == 13 && end + 1 < bytes.len() && bytes[end + 1] == 10 { end + 2 }
        else { end + 1 };
    (end, next)
}
fn field_data(line: &[u8]) -> (out: Option<&[u8]>)
    ensures match out { Some(s) => data_value(line@) == Some(s@) && s.len() <= line.len(), None => data_value(line@).is_none() },
{
    if crate::headers::eq(line, DATA.as_slice()) { return Some(slice_subrange(line, line.len(), line.len())); }
    if line.len() >= 5 && crate::headers::eq(slice_subrange(line, 0, 5), DATA_COLON.as_slice()) {
        let start = if line.len() > 5 && line[5] == 32 { 6 } else { 5 };
        return Some(slice_subrange(line, start, line.len()));
    }
    None
}
/// One event at a time: the pending data never grows beyond the input consumed.
pub struct Reader<'a> { bytes: &'a [u8], start: usize }
impl<'a> Reader<'a> {
    pub closed spec fn valid(&self) -> bool { self.start <= self.bytes.len() }
    pub closed spec fn remaining(&self) -> Seq<Seq<u8>> { scan(self.bytes@, self.start as int, Seq::empty(), false) }
    pub closed spec fn left(&self) -> nat { (self.bytes.len() - self.start) as nat }
    pub fn new(bytes: &'a [u8]) -> (out: Self)
        ensures out.valid(), out.remaining() == event_data(bytes@), out.left() == bytes.len(),
    { Reader { bytes, start: 0 } }

    /// Compose framing with JSON soundness and completeness. Each call consumes
    /// exactly one event, even if its data is not JSON (for example `[DONE]`).
    pub fn next_json(&mut self) -> (out: Option<Option<crate::json::Value>>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).left() <= old(self).left(),
            match out {
                None => old(self).remaining().len() == 0 && final(self).left() == 0,
                Some(parsed) => old(self).remaining().len() > 0
                    && old(self).remaining() == seq![old(self).remaining()[0]] + final(self).remaining()
                    && final(self).left() < old(self).left()
                    && (match parsed { Some(v) => crate::json::document(old(self).remaining()[0], v), None => true })
                    && (forall|v: crate::json::Value| #[trigger] crate::json::document(old(self).remaining()[0], v)
                        && crate::json::depth(v) <= crate::json::MAX_DEPTH ==>
                            match parsed { Some(w) => crate::json::same(w, v), None => false }),
            },
    {
        let data = match self.next() { Some(data) => data, None => return None };
        Some(crate::json::parse(data.as_slice()))
    }

    /// The next dispatch is exactly the first event of the remaining grammar.
    #[verifier::loop_isolation(false)]
    #[verifier::rlimit(60)]
    pub fn next(&mut self) -> (out: Option<Vec<u8>>)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).left() <= old(self).left(),
            match out {
                Some(data) => old(self).remaining() == seq![data@] + final(self).remaining()
                    && final(self).left() < old(self).left() && data.len() <= old(self).left() - final(self).left(),
                None => old(self).remaining().len() == 0 && final(self).left() == 0,
            },
    {
        let mut data: Vec<u8> = Vec::new();
        let mut present = false;
        let ghost initial = self.start;
        while self.start < self.bytes.len()
            invariant self.valid(), initial == old(self).start, self.bytes == old(self).bytes,
                initial <= self.start, !present ==> data@.len() == 0,
                data.len() <= self.start - initial,
                present ==> data.len() < self.start - initial,
                scan(self.bytes@, self.start as int, data@, present) == old(self).remaining(),
            decreases self.bytes.len() - self.start,
        {
            proof { reveal(scan); }
            let (end, next) = read_line(self.bytes, self.start);
            if end == self.bytes.len() { self.start = end; return None; }
            let line = slice_subrange(self.bytes, self.start, end);
            if line.len() == 0 {
                self.start = next;
                if present { return Some(data); }
                proof { assert(data@ =~= Seq::<u8>::empty()); }
            } else {
                if let Some(more) = field_data(line) {
                    let ghost old_data = data@;
                    if present { data.push(10); }
                    crate::framing::append(&mut data, more);
                    proof { assert(data@ =~= joined(old_data, present, more@)); }
                    present = true;
                }
                self.start = next;
            }
        }
        proof { reveal(scan); }
        None
    }
}
}
