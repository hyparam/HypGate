//! Verified HTTP/1.1 head parsing. A head is a start line and field lines,
//! each ended by CRLF, closed by an empty line, within 32 KiB and 100 fields.
//! The grammar is the relational specification below (`request_head_ok`,
//! `status_head_ok`); the parsers are proved sound and complete against it:
//! a returned head satisfies the grammar for exactly the bytes consumed, and
//! when none is returned no prefix of the buffer satisfies it, so nothing
//! well-formed is refused and nothing malformed is accepted. Obsolete line
//! folding, bare CR or LF, control bytes, HTTP/1.0, and absolute-form targets
//! are outside the grammar and therefore rejected. Field names come out
//! lowercased and values trimmed of surrounding blanks, the shape the
//! verified header projection consumes.
use vstd::prelude::*;
use vstd::slice::{slice_subrange, slice_to_vec};
use crate::headers::{Field, MAX_BYTES, MAX_FIELDS, Rejection, lowercase, tchar};

verus! {
/// The bytes of `HTTP/1.1`, the only version accepted or written.
pub open spec fn version() -> Seq<u8> { seq![72u8, 84u8, 84u8, 80u8, 47u8, 49u8, 46u8, 49u8] }
pub const CR: u8 = 13;
pub const LF: u8 = 10;
pub const SP: u8 = 32;
pub const COLON: u8 = 58;

pub open spec fn is_vchar(b: u8) -> bool { 33 <= b <= 126 }
/// A byte a field value or reason phrase may contain: visible, blank, or obs-text.
pub open spec fn is_value_byte(b: u8) -> bool { is_vchar(b) || crate::headers::is_blank(b) || b >= 128 }
pub open spec fn is_digit(b: u8) -> bool { 48 <= b <= 57 }
pub open spec fn is_break(b: u8) -> bool { b == CR || b == LF }
/// Bytes `i`, `i + 1` of `s` are CR LF.
pub open spec fn crlf_at(s: Seq<u8>, i: int) -> bool { 0 <= i && i + 1 < s.len() && s[i] == CR && s[i + 1] == LF }
/// No CR or LF anywhere in `s`.
pub open spec fn clean(s: Seq<u8>) -> bool { forall|k: int| 0 <= k < s.len() ==> !is_break(#[trigger] s[k]) }
/// Wire equality: the sensitivity flag is runtime metadata, not wire content.
pub open spec fn field_eq(a: Field, b: Field) -> bool { a.name@ == b.name@ && a.value@ == b.value@ }
pub open spec fn fields_eq(a: Seq<Field>, b: Seq<Field>) -> bool {
    a.len() == b.len() && forall|i: int| 0 <= i < a.len() ==> field_eq(#[trigger] a[i], b[i])
}

// ---- field lines -----------------------------------------------------------

/// `line` (without its CRLF) is `name ":" OWS value OWS` with the colon at `c`
/// and the value at `[s, e)`; `f` is that field with a lowercased name. The
/// parser marks parsed fields not sensitive; the flag is not wire content.
pub open spec fn field_split(line: Seq<u8>, f: Field, c: int, s: int, e: int) -> bool {
    split_shape(line, c, s, e)
        && f.name@ == crate::headers::lower_seq(line.subrange(0, c)) && f.value@ == line.subrange(s, e)
}
/// The positional part of `field_split`.
pub open spec fn split_shape(line: Seq<u8>, c: int, s: int, e: int) -> bool {
    0 < c < line.len() && line[c] == COLON && c + 1 <= s <= e <= line.len()
        && (forall|k: int| 0 <= k < c ==> crate::headers::is_tchar(#[trigger] line[k]))
        && (forall|k: int| c + 1 <= k < s ==> crate::headers::is_blank(#[trigger] line[k]))
        && (forall|k: int| e <= k < line.len() ==> crate::headers::is_blank(#[trigger] line[k]))
        && (s == e || (!crate::headers::is_blank(line[s]) && !crate::headers::is_blank(line[e - 1])))
        && (forall|k: int| s <= k < e ==> is_value_byte(#[trigger] line[k]))
}
pub open spec fn field_line_ok(line: Seq<u8>, f: Field) -> bool {
    exists|c: int, s: int, e: int| #[trigger] field_split(line, f, c, s, e)
}
/// From `start`, `bytes` holds the field lines of `fields` and then the empty
/// line, ending exactly at `bytes.len()`.
pub open spec fn lines_ok(bytes: Seq<u8>, start: int, fields: Seq<Field>) -> bool
    decreases bytes.len() - start when 0 <= start <= bytes.len()
{
    if crlf_at(bytes, start) { start + 2 == bytes.len() && fields.len() == 0 }
    else {
        exists|e: int| start < e && #[trigger] crlf_at(bytes, e) && clean(bytes.subrange(start, e))
            && fields.len() >= 1 && field_line_ok(bytes.subrange(start, e), fields[0])
            && lines_ok(bytes, e + 2, fields.drop_first())
    }
}
/// The field block of a head: lines within the limits.
pub open spec fn fields_ok(bytes: Seq<u8>, start: int, fields: Seq<Field>) -> bool {
    0 <= start <= bytes.len() && bytes.len() <= MAX_BYTES && fields.len() <= MAX_FIELDS && lines_ok(bytes, start, fields)
}

// ---- start lines -----------------------------------------------------------

/// `line` is `method SP origin-form-target SP HTTP/1.1` with the blanks at `a`, `b`.
pub open spec fn request_line_split(line: Seq<u8>, method: Seq<u8>, target: Seq<u8>, a: int, b: int) -> bool {
    0 < a && a + 1 < b && b + 9 == line.len() && line[a] == SP && line[b] == SP
        && (forall|k: int| 0 <= k < a ==> crate::headers::is_tchar(#[trigger] line[k])) && method == line.subrange(0, a)
        && line[a + 1] == 47 && (forall|k: int| a + 1 <= k < b ==> is_vchar(#[trigger] line[k])) && target == line.subrange(a + 1, b)
        && line.subrange(b + 1, line.len() as int) == version()
}
pub open spec fn request_line_ok(line: Seq<u8>, method: Seq<u8>, target: Seq<u8>) -> bool {
    exists|a: int, b: int| #[trigger] request_line_split(line, method, target, a, b)
}
/// `line` is `HTTP/1.1 SP 3DIGIT [SP reason]`, the code between 100 and 599.
pub open spec fn status_line_ok(line: Seq<u8>, status: u16) -> bool {
    line.len() >= 12 && line.subrange(0, 8) == version() && line[8] == SP
        && 49 <= line[9] <= 53 && is_digit(line[10]) && is_digit(line[11])
        && status == (line[9] - 48) * 100 + (line[10] - 48) * 10 + (line[11] - 48)
        && (line.len() == 12 || (line[12] == SP && forall|k: int| 13 <= k < line.len() ==> is_value_byte(#[trigger] line[k])))
}

pub struct RequestHead { pub method: Vec<u8>, pub target: Vec<u8>, pub fields: Vec<Field> }
pub struct StatusHead { pub status: u16, pub fields: Vec<Field> }

/// `bytes` is exactly one request head for `head`.
pub open spec fn request_head_ok(bytes: Seq<u8>, head: RequestHead) -> bool {
    exists|e: int| #[trigger] crlf_at(bytes, e) && clean(bytes.subrange(0, e))
        && request_line_ok(bytes.subrange(0, e), head.method@, head.target@) && fields_ok(bytes, e + 2, head.fields@)
}
/// `bytes` is exactly one status head for `head`.
pub open spec fn status_head_ok(bytes: Seq<u8>, head: StatusHead) -> bool {
    exists|e: int| #[trigger] crlf_at(bytes, e) && clean(bytes.subrange(0, e))
        && status_line_ok(bytes.subrange(0, e), head.status) && fields_ok(bytes, e + 2, head.fields@)
}
/// No prefix of `bytes` is a request head.
pub open spec fn no_request_head(bytes: Seq<u8>) -> bool {
    forall|len: int, head: RequestHead| 0 <= len <= bytes.len() ==> !(#[trigger] request_head_ok(bytes.subrange(0, len), head))
}
pub open spec fn no_status_head(bytes: Seq<u8>) -> bool {
    forall|len: int, head: StatusHead| 0 <= len <= bytes.len() ==> !(#[trigger] status_head_ok(bytes.subrange(0, len), head))
}
/// No prefix of `bytes` holds a field block from `start`.
pub open spec fn no_fields(bytes: Seq<u8>, start: int) -> bool {
    forall|end: int, fields: Seq<Field>| 0 <= end <= bytes.len() ==> !(#[trigger] fields_ok(bytes.subrange(0, end), start, fields))
}

pub enum RequestProgress { Complete(RequestHead, usize), Incomplete, Rejected(Rejection) }
pub enum StatusProgress { Complete(StatusHead, usize), Incomplete, Rejected(Rejection) }
enum FieldsProgress { Complete(Vec<Field>, usize), Incomplete, Rejected(Rejection) }

// ---- exec helpers ----------------------------------------------------------

/// `s` is exactly `HTTP/1.1`.
pub fn is_version(s: &[u8]) -> (out: bool)
    ensures out == (s@ == version()),
{
    let ok = s.len() == 8 && s[0] == 72 && s[1] == 84 && s[2] == 84 && s[3] == 80 && s[4] == 47 && s[5] == 49 && s[6] == 46 && s[7] == 49;
    proof { if ok { assert(s@ =~= version()); } else if s@ == version() { assert(s@.len() == 8); assert(false); } }
    ok
}

fn blank(b: u8) -> (out: bool) ensures out == crate::headers::is_blank(b) { b == 32 || b == 9 }
fn vchar(b: u8) -> (out: bool) ensures out == is_vchar(b) { b >= 33 && b <= 126 }
pub fn value_byte_exec(b: u8) -> (out: bool) ensures out == is_value_byte(b) { (b >= 33 && b <= 126) || b == 32 || b == 9 || b >= 128 }

/// The first CR or LF at or after `from`, or `s.len()`.
fn find_break(s: &[u8], from: usize) -> (out: usize)
    requires from <= s.len(),
    ensures from <= out <= s.len(), clean(s@.subrange(from as int, out as int)),
        out < s.len() ==> is_break(s@[out as int]),
{
    let mut k: usize = from;
    while k < s.len()
        invariant from <= k <= s.len(), forall|j: int| from <= j < k ==> !is_break(#[trigger] s@[j]),
        decreases s.len() - k,
    {
        if s[k] == CR || s[k] == LF { return k; }
        k = k + 1;
    }
    k
}
/// The first byte `b` at or after `from`, or `s.len()`.
fn find(s: &[u8], from: usize, b: u8) -> (out: usize)
    requires from <= s.len(),
    ensures from <= out <= s.len(), forall|j: int| from <= j < out ==> #[trigger] s@[j] != b,
        out < s.len() ==> s@[out as int] == b,
{
    let mut k: usize = from;
    while k < s.len()
        invariant from <= k <= s.len(), forall|j: int| from <= j < k ==> #[trigger] s@[j] != b,
        decreases s.len() - k,
    {
        if s[k] == b { return k; }
        k = k + 1;
    }
    k
}
fn all_tchar(s: &[u8], from: usize, to: usize) -> (out: bool)
    requires from <= to <= s.len(),
    ensures out == forall|k: int| from <= k < to ==> crate::headers::is_tchar(#[trigger] s@[k]),
{
    let mut k: usize = from;
    while k < to
        invariant from <= k <= to <= s.len(), forall|j: int| from <= j < k ==> crate::headers::is_tchar(#[trigger] s@[j]),
        decreases to - k,
    {
        if !tchar(s[k]) { return false; }
        k = k + 1;
    }
    true
}
fn all_vchar(s: &[u8], from: usize, to: usize) -> (out: bool)
    requires from <= to <= s.len(),
    ensures out == forall|k: int| from <= k < to ==> is_vchar(#[trigger] s@[k]),
{
    let mut k: usize = from;
    while k < to
        invariant from <= k <= to <= s.len(), forall|j: int| from <= j < k ==> is_vchar(#[trigger] s@[j]),
        decreases to - k,
    {
        if !vchar(s[k]) { return false; }
        k = k + 1;
    }
    true
}
fn all_value_bytes(s: &[u8], from: usize, to: usize) -> (out: bool)
    requires from <= to <= s.len(),
    ensures out == forall|k: int| from <= k < to ==> is_value_byte(#[trigger] s@[k]),
{
    let mut k: usize = from;
    while k < to
        invariant from <= k <= to <= s.len(), forall|j: int| from <= j < k ==> is_value_byte(#[trigger] s@[j]),
        decreases to - k,
    {
        if !value_byte_exec(s[k]) { return false; }
        k = k + 1;
    }
    true
}
/// The first non-blank at or after `from`, or `s.len()`.
fn skip_blanks(s: &[u8], from: usize) -> (out: usize)
    requires from <= s.len(),
    ensures from <= out <= s.len(), forall|j: int| from <= j < out ==> crate::headers::is_blank(#[trigger] s@[j]),
        out < s.len() ==> !crate::headers::is_blank(s@[out as int]),
{
    let mut k: usize = from;
    while k < s.len()
        invariant from <= k <= s.len(), forall|j: int| from <= j < k ==> crate::headers::is_blank(#[trigger] s@[j]),
        decreases s.len() - k,
    {
        if !blank(s[k]) { return k; }
        k = k + 1;
    }
    k
}
/// One past the last non-blank at or after `from`, or `from` when all blank.
fn trim_end(s: &[u8], from: usize) -> (out: usize)
    requires from <= s.len(),
    ensures from <= out <= s.len(), forall|j: int| out <= j < s.len() ==> crate::headers::is_blank(#[trigger] s@[j]),
        out > from ==> !crate::headers::is_blank(s@[out - 1]),
{
    let mut k: usize = s.len();
    while k > from
        invariant from <= k <= s.len(), forall|j: int| k <= j < s.len() ==> crate::headers::is_blank(#[trigger] s@[j]),
        decreases k,
    {
        if !blank(s[k - 1]) { return k; }
        k = k - 1;
    }
    k
}

// ---- field line ------------------------------------------------------------

/// What the parser's search finds: the first colon, the first non-blank after
/// it, and the end of the last non-blank.
pub open spec fn search_shape(line: Seq<u8>, c: int, s: int, e: int) -> bool {
    0 < c < line.len() && line[c] == COLON && (forall|k: int| 0 <= k < c ==> #[trigger] line[k] != COLON)
        && c + 1 <= s <= line.len() && (forall|k: int| c + 1 <= k < s ==> crate::headers::is_blank(#[trigger] line[k])) && (s < line.len() ==> !crate::headers::is_blank(line[s]))
        && s <= e <= line.len() && (forall|k: int| e <= k < line.len() ==> crate::headers::is_blank(#[trigger] line[k])) && (e > s ==> !crate::headers::is_blank(line[e - 1]))
}

/// A split names the same colon and the same value bytes as the search.
proof fn lemma_search_split(line: Seq<u8>, c: int, s: int, e: int, c2: int, s2: int, e2: int)
    requires search_shape(line, c, s, e), split_shape(line, c2, s2, e2),
    ensures c2 == c, line.subrange(s2, e2) == line.subrange(s, e),
{
    assert forall|k: int| 0 <= k < c2 implies #[trigger] line[k] != COLON by { assert(crate::headers::is_tchar(line[k])); }
    assert(c2 == c);
    if s2 == e2 {
        // Everything after the colon is blank, so the search found an empty value too.
        assert forall|k: int| c + 1 <= k < line.len() implies crate::headers::is_blank(#[trigger] line[k]) by {
            if k < s2 { } else { assert(e2 <= k); }
        }
        if s < line.len() { assert(crate::headers::is_blank(line[s])); assert(false); }
        assert(s == line.len() && e == line.len());
        assert(line.subrange(s2, e2) =~= line.subrange(s, e));
    } else {
        if s2 < s { assert(crate::headers::is_blank(line[s2])); assert(false); }
        if s < s2 { assert(crate::headers::is_blank(line[s])); assert(false); }
        if e2 < e { assert(e > s); assert(crate::headers::is_blank(line[e - 1])); assert(false); }
        if e < e2 { assert(crate::headers::is_blank(line[e2 - 1])); assert(false); }
    }
}

/// Two fields that fit the same line are equal.
proof fn lemma_field_line_unique(line: Seq<u8>, f1: Field, f2: Field)
    requires field_line_ok(line, f1), field_line_ok(line, f2),
    ensures field_eq(f1, f2),
{
    let (c1, s1, e1) = choose|c: int, s: int, e: int| #[trigger] field_split(line, f1, c, s, e);
    let (c2, s2, e2) = choose|c: int, s: int, e: int| #[trigger] field_split(line, f2, c, s, e);
    // The first split is also what a search would find, up to its value range.
    assert forall|k: int| 0 <= k < c1 implies #[trigger] line[k] != COLON by { assert(crate::headers::is_tchar(line[k])); }
    if s1 == e1 {
        assert forall|k: int| c1 + 1 <= k < line.len() implies crate::headers::is_blank(#[trigger] line[k]) by { if k < s1 { } else { assert(e1 <= k); } }
        assert(search_shape(line, c1, line.len() as int, line.len() as int));
        lemma_search_split(line, c1, line.len() as int, line.len() as int, c2, s2, e2);
        assert(line.subrange(s1, e1) =~= line.subrange(line.len() as int, line.len() as int));
    } else {
        assert(search_shape(line, c1, s1, e1));
        lemma_search_split(line, c1, s1, e1, c2, s2, e2);
    }
}

/// Parse one field line (without its CRLF); `None` exactly when no field fits it.
fn parse_field_line(line: &[u8]) -> (out: Option<Field>)
    ensures match out {
        Some(f) => field_line_ok(line@, f),
        None => forall|f: Field| !field_line_ok(line@, f),
    },
{
    let c = find(line, 0, COLON);
    if c == 0 || c >= line.len() || !all_tchar(line, 0, c) {
        proof { assert forall|f: Field| !field_line_ok(line@, f) by { if field_line_ok(line@, f) {
            let (c2, s2, e2) = choose|c2: int, s2: int, e2: int| #[trigger] field_split(line@, f, c2, s2, e2);
            assert forall|k: int| 0 <= k < c2 implies #[trigger] line@[k] != COLON by { assert(crate::headers::is_tchar(line@[k])); }
            assert(c2 == c);
        } } }
        return None;
    }
    let s = skip_blanks(line, c + 1);
    let e = trim_end(line, s);
    if !all_value_bytes(line, s, e) {
        proof { assert forall|f: Field| !field_line_ok(line@, f) by { if field_line_ok(line@, f) {
            let (c2, s2, e2) = choose|c2: int, s2: int, e2: int| #[trigger] field_split(line@, f, c2, s2, e2);
            lemma_search_split(line@, c as int, s as int, e as int, c2, s2, e2);
            assert forall|k: int| s <= k < e implies is_value_byte(#[trigger] line@[k]) by {
                assert(line@.subrange(s as int, e as int)[k - s] == line@[k]);
                assert(line@.subrange(s2, e2)[k - s] == line@[s2 + k - s]);
            }
        } } }
        return None;
    }
    let f = Field { name: lowercase(slice_subrange(line, 0, c)), value: slice_to_vec(slice_subrange(line, s, e)), sensitive: false };
    proof { assert(field_split(line@, f, c as int, s as int, e as int)); }
    Some(f)
}

// ---- prefixes and breaks ---------------------------------------------------

/// Facts about a prefix `p = bytes.subrange(0, end)`.
proof fn lemma_prefix_crlf(bytes: Seq<u8>, end: int, e: int)
    requires 0 <= end <= bytes.len(), crlf_at(bytes.subrange(0, end), e),
    ensures crlf_at(bytes, e), e + 2 <= end,
{}
proof fn lemma_prefix_subrange(bytes: Seq<u8>, end: int, a: int, b: int)
    requires 0 <= a <= b <= end <= bytes.len(),
    ensures bytes.subrange(0, end).subrange(a, b) == bytes.subrange(a, b),
{
    assert(bytes.subrange(0, end).subrange(a, b) =~= bytes.subrange(a, b));
}
/// A clean run up to a CRLF at `e` means the first break at or after `start` is `e`, a CR.
proof fn lemma_first_break(bytes: Seq<u8>, start: int, e: int, found: int)
    requires 0 <= start <= e, crlf_at(bytes, e), clean(bytes.subrange(start, e)),
        start <= found <= bytes.len(), clean(bytes.subrange(start, found)), found < bytes.len() ==> is_break(bytes[found]),
    ensures found == e,
{
    if found < e { assert(bytes.subrange(start, e)[found - start] == bytes[found]); assert(!is_break(bytes[found])); assert(false); }
    if e < found { assert(bytes.subrange(start, found)[e - start] == bytes[e]); assert(is_break(bytes[e])); assert(false); }
}
/// The one line a block has at `start` when the block does not end there.
proof fn lemma_block_line(bytes: Seq<u8>, end: int, start: int, rest: Seq<Field>, found: int) -> (e: int)
    requires 0 <= start <= end <= bytes.len(), lines_ok(bytes.subrange(0, end), start, rest), !crlf_at(bytes.subrange(0, end), start),
        start <= found <= bytes.len(), clean(bytes.subrange(start, found)), found < bytes.len() ==> is_break(bytes[found]),
    ensures e == found, start < e, crlf_at(bytes, e), e + 2 <= end, clean(bytes.subrange(start, e)),
        rest.len() >= 1, field_line_ok(bytes.subrange(start, e), rest[0]), lines_ok(bytes.subrange(0, end), e + 2, rest.drop_first()),
{
    let p = bytes.subrange(0, end);
    let e = choose|e: int| start < e && #[trigger] crlf_at(p, e) && clean(p.subrange(start, e))
        && rest.len() >= 1 && field_line_ok(p.subrange(start, e), rest[0]) && lines_ok(p, e + 2, rest.drop_first());
    lemma_prefix_crlf(bytes, end, e);
    lemma_prefix_subrange(bytes, end, start, e);
    lemma_first_break(bytes, start, e, found);
    e
}

// ---- field block -----------------------------------------------------------

/// The completeness invariant of `parse_fields`: every block from `origin`
/// within some prefix agrees with the `parsed` lines and continues at `start`.
pub open spec fn blocks_agree(bytes: Seq<u8>, origin: int, start: int, parsed: Seq<Field>) -> bool {
    forall|end: int, all: Seq<Field>| 0 <= end <= bytes.len() && #[trigger] fields_ok(bytes.subrange(0, end), origin, all)
        ==> start <= end && all.len() >= parsed.len() && fields_eq(all.take(parsed.len() as int), parsed)
            && lines_ok(bytes.subrange(0, end), start, all.skip(parsed.len() as int))
}
/// The soundness invariant of `parse_fields`: the `parsed` lines compose with
/// any block that continues at `start`.
pub open spec fn blocks_compose(bytes: Seq<u8>, origin: int, start: int, parsed: Seq<Field>) -> bool {
    forall|end: int, tail: Seq<Field>| start <= end <= bytes.len() && #[trigger] lines_ok(bytes.subrange(0, end), start, tail)
        ==> lines_ok(bytes.subrange(0, end), origin, parsed + tail)
}

/// Parse field lines from `start` to the empty line. Sound and complete.
fn parse_fields(buffer: &[u8], start: usize) -> (out: FieldsProgress)
    requires start <= buffer.len(),
    ensures match out {
        FieldsProgress::Complete(fields, end) => start <= end <= buffer.len() && fields_ok(buffer@.subrange(0, end as int), start as int, fields@),
        FieldsProgress::Incomplete => buffer.len() < MAX_BYTES && no_fields(buffer@, start as int),
        FieldsProgress::Rejected(_) => no_fields(buffer@, start as int),
    },
{
    let mut cursor = start;
    let mut fields: Vec<Field> = Vec::new();
    proof {
        assert forall|end: int, all: Seq<Field>| 0 <= end <= buffer@.len() && #[trigger] fields_ok(buffer@.subrange(0, end), (start as int), all)
            implies (start as int) <= end && all.len() >= 0 && fields_eq(all.take(0), fields@) && lines_ok(buffer@.subrange(0, end), (start as int), all.skip(0)) by {
            assert(all.skip(0) =~= all);
        }
        assert forall|end: int, tail: Seq<Field>| (start as int) <= end <= buffer@.len() && #[trigger] lines_ok(buffer@.subrange(0, end), (start as int), tail)
            implies lines_ok(buffer@.subrange(0, end), (start as int), fields@ + tail) by {
            assert(fields@ + tail =~= tail);
        }
    }
    loop
        invariant
            cursor <= buffer.len(), start <= cursor, fields.len() <= MAX_FIELDS,
            blocks_compose(buffer@, (start as int), cursor as int, fields@),
            blocks_agree(buffer@, (start as int), cursor as int, fields@),
        decreases buffer.len() - cursor,
    {
        if cursor > MAX_BYTES - 2 {
            // Any block from here ends at or after cursor + 2, past the limit.
            proof { assert forall|end: int, all: Seq<Field>| 0 <= end <= buffer@.len() implies !(#[trigger] fields_ok(buffer@.subrange(0, end), (start as int), all)) by {
                if fields_ok(buffer@.subrange(0, end), (start as int), all) { lemma_lines_end(buffer@.subrange(0, end), cursor as int, all.skip(fields.len() as int)); }
            } }
            return FieldsProgress::Rejected(Rejection::TooLarge);
        }
        if cursor + 1 < buffer.len() && buffer[cursor] == CR && buffer[cursor + 1] == LF {
            let end = cursor + 2;
            proof {
                let p = buffer@.subrange(0, end as int);
                assert(p[cursor as int] == CR && p[cursor as int + 1] == LF);
                assert(crlf_at(p, cursor as int));
                assert(lines_ok(p, cursor as int, Seq::<Field>::empty()));
                assert(lines_ok(p, (start as int), fields@ + Seq::<Field>::empty()));
                assert(fields@ + Seq::<Field>::empty() =~= fields@);
            }
            return FieldsProgress::Complete(fields, end);
        }
        let p = find_break(buffer, cursor);
        if p < buffer.len() && buffer[p] == LF {
            proof { lemma_no_fields_without_crlf(buffer@, (start as int), cursor as int, p as int, fields@); }
            return FieldsProgress::Rejected(Rejection::BadRequest);
        }
        if p == buffer.len() || p + 1 == buffer.len() {
            proof { lemma_no_fields_without_crlf(buffer@, (start as int), cursor as int, p as int, fields@); }
            return if buffer.len() >= MAX_BYTES { FieldsProgress::Rejected(Rejection::TooLarge) } else { FieldsProgress::Incomplete };
        }
        if buffer[p + 1] != LF {
            proof { lemma_no_fields_without_crlf(buffer@, (start as int), cursor as int, p as int, fields@); }
            return FieldsProgress::Rejected(Rejection::BadRequest);
        }
        // CRLF at p > cursor (p == cursor was the empty line above).
        if fields.len() == MAX_FIELDS {
            proof { lemma_no_fields_over_count(buffer@, (start as int), cursor as int, p as int, fields@); }
            return FieldsProgress::Rejected(Rejection::TooLarge);
        }
        let field = match parse_field_line(slice_subrange(buffer, cursor, p)) {
            Some(field) => field,
            None => {
                proof { lemma_no_fields_bad_line(buffer@, (start as int), cursor as int, p as int, fields@); }
                return FieldsProgress::Rejected(Rejection::BadRequest);
            }
        };
        proof {
            lemma_fields_step_compose(buffer@, (start as int), cursor as int, p as int, fields@, field);
            lemma_fields_step_agree(buffer@, (start as int), cursor as int, p as int, fields@, field);
        }
        fields.push(field);
        cursor = p + 2;
    }
}

/// A block from `start` ends at `start + 2` or later.
proof fn lemma_lines_end(p: Seq<u8>, start: int, fields: Seq<Field>)
    requires 0 <= start <= p.len(), lines_ok(p, start, fields),
    ensures start + 2 <= p.len(),
{}

/// At `start` the next break is not a CRLF, so no block passes through `start`.
proof fn lemma_no_fields_without_crlf(bytes: Seq<u8>, origin: int, start: int, found: int, parsed: Seq<Field>)
    requires
        0 <= origin <= start <= bytes.len(), start <= found <= bytes.len(),
        clean(bytes.subrange(start, found)), found < bytes.len() ==> is_break(bytes[found]),
        found == bytes.len() || found + 1 == bytes.len() || bytes[found] == LF || bytes[found + 1] != LF,
        blocks_agree(bytes, origin, start, parsed),
    ensures no_fields(bytes, origin),
{
    assert forall|end: int, all: Seq<Field>| 0 <= end <= bytes.len() implies !(#[trigger] fields_ok(bytes.subrange(0, end), origin, all)) by {
        if fields_ok(bytes.subrange(0, end), origin, all) {
            let p = bytes.subrange(0, end);
            let rest = all.skip(parsed.len() as int);
            if crlf_at(p, start) {
                lemma_prefix_crlf(bytes, end, start);
                lemma_first_break(bytes, start, start, found);
            } else {
                let e = lemma_block_line(bytes, end, start, rest, found);
            }
        }
    }
}

/// A CRLF-ended line at `start` while 100 fields are parsed: any block has 101.
proof fn lemma_no_fields_over_count(bytes: Seq<u8>, origin: int, start: int, e: int, parsed: Seq<Field>)
    requires
        0 <= origin <= start < e, crlf_at(bytes, e), clean(bytes.subrange(start, e)), parsed.len() == MAX_FIELDS,
        blocks_agree(bytes, origin, start, parsed),
    ensures no_fields(bytes, origin),
{
    assert forall|end: int, all: Seq<Field>| 0 <= end <= bytes.len() implies !(#[trigger] fields_ok(bytes.subrange(0, end), origin, all)) by {
        if fields_ok(bytes.subrange(0, end), origin, all) {
            let p = bytes.subrange(0, end);
            let rest = all.skip(parsed.len() as int);
            assert(!crlf_at(p, start)) by { assert(bytes.subrange(start, e)[0] == bytes[start]); }
            let e2 = lemma_block_line(bytes, end, start, rest, e);
            assert(all.len() >= MAX_FIELDS + 1);
        }
    }
}

/// The line `[start, e)` fits no field, so no block passes through `start`.
proof fn lemma_no_fields_bad_line(bytes: Seq<u8>, origin: int, start: int, e: int, parsed: Seq<Field>)
    requires
        0 <= origin <= start < e, crlf_at(bytes, e), clean(bytes.subrange(start, e)),
        forall|f: Field| !field_line_ok(bytes.subrange(start, e), f),
        blocks_agree(bytes, origin, start, parsed),
    ensures no_fields(bytes, origin),
{
    assert forall|end: int, all: Seq<Field>| 0 <= end <= bytes.len() implies !(#[trigger] fields_ok(bytes.subrange(0, end), origin, all)) by {
        if fields_ok(bytes.subrange(0, end), origin, all) {
            let p = bytes.subrange(0, end);
            let rest = all.skip(parsed.len() as int);
            assert(!crlf_at(p, start)) by { assert(bytes.subrange(start, e)[0] == bytes[start]); }
            let e2 = lemma_block_line(bytes, end, start, rest, e);
        }
    }
}

/// One parsed line `[start, e)` with field `f` extends the soundness invariant.
proof fn lemma_fields_step_compose(bytes: Seq<u8>, origin: int, start: int, e: int, parsed: Seq<Field>, f: Field)
    requires
        0 <= origin <= start < e, crlf_at(bytes, e), clean(bytes.subrange(start, e)), field_line_ok(bytes.subrange(start, e), f),
        blocks_compose(bytes, origin, start, parsed),
    ensures blocks_compose(bytes, origin, e + 2, parsed.push(f)),
{
    assert forall|end: int, tail: Seq<Field>| e + 2 <= end <= bytes.len() && #[trigger] lines_ok(bytes.subrange(0, end), e + 2, tail)
        implies lines_ok(bytes.subrange(0, end), origin, parsed.push(f) + tail) by {
        let p = bytes.subrange(0, end);
        lemma_prefix_subrange(bytes, end, start, e);
        assert(crlf_at(p, e));
        assert(!crlf_at(p, start)) by { assert(bytes.subrange(start, e)[0] == bytes[start]); }
        let line = seq![f] + tail;
        assert(line[0] == f);
        assert(line.drop_first() =~= tail);
        assert(lines_ok(p, start, line));
        assert(parsed + line =~= parsed.push(f) + tail);
    }
}

/// One parsed line `[start, e)` with field `f` extends the completeness invariant.
proof fn lemma_fields_step_agree(bytes: Seq<u8>, origin: int, start: int, e: int, parsed: Seq<Field>, f: Field)
    requires
        0 <= origin <= start < e, crlf_at(bytes, e), clean(bytes.subrange(start, e)), field_line_ok(bytes.subrange(start, e), f),
        blocks_agree(bytes, origin, start, parsed),
    ensures blocks_agree(bytes, origin, e + 2, parsed.push(f)),
{
    let n = parsed.len() as int;
    assert forall|end: int, all: Seq<Field>| 0 <= end <= bytes.len() && #[trigger] fields_ok(bytes.subrange(0, end), origin, all)
        implies e + 2 <= end && all.len() >= n + 1 && fields_eq(all.take(n + 1), parsed.push(f)) && lines_ok(bytes.subrange(0, end), e + 2, all.skip(n + 1)) by {
        let p = bytes.subrange(0, end);
        let rest = all.skip(n);
        assert(!crlf_at(p, start)) by { assert(bytes.subrange(start, e)[0] == bytes[start]); }
        let e2 = lemma_block_line(bytes, end, start, rest, e);
        lemma_field_line_unique(bytes.subrange(start, e), rest[0], f);
        assert(rest.drop_first() =~= all.skip(n + 1));
        assert(all.take(n + 1) =~= all.take(n).push(all[n]));
        assert(all[n] == rest[0]);
    }
}

// ---- start lines -----------------------------------------------------------

/// Parse a request line (without its CRLF).
fn parse_request_line(line: &[u8]) -> (out: Option<(Vec<u8>, Vec<u8>)>)
    ensures match out {
        Some(parts) => request_line_ok(line@, parts.0@, parts.1@),
        None => forall|m: Seq<u8>, t: Seq<u8>| !request_line_ok(line@, m, t),
    },
{
    let a = find(line, 0, SP);
    if a == 0 || a >= line.len() || !all_tchar(line, 0, a) {
        proof { assert forall|m: Seq<u8>, t: Seq<u8>| !request_line_ok(line@, m, t) by { if request_line_ok(line@, m, t) {
            let (a2, b2) = choose|a2: int, b2: int| #[trigger] request_line_split(line@, m, t, a2, b2);
            assert forall|k: int| 0 <= k < a2 implies #[trigger] line@[k] != SP by { assert(crate::headers::is_tchar(line@[k])); }
            assert(a2 == a);
        } } }
        return None;
    }
    let b = find(line, a + 1, SP);
    if b >= line.len() || b == a + 1 || line[a + 1] != 47 || !all_vchar(line, a + 1, b) || line.len() - b != 9
        || !is_version(slice_subrange(line, b + 1, line.len())) {
        proof { assert forall|m: Seq<u8>, t: Seq<u8>| !request_line_ok(line@, m, t) by { if request_line_ok(line@, m, t) {
            let (a2, b2) = choose|a2: int, b2: int| #[trigger] request_line_split(line@, m, t, a2, b2);
            assert forall|k: int| 0 <= k < a2 implies #[trigger] line@[k] != SP by { assert(crate::headers::is_tchar(line@[k])); }
            assert(a2 == a);
            assert forall|k: int| a2 + 1 <= k < b2 implies #[trigger] line@[k] != SP by { assert(is_vchar(line@[k])); }
            assert(b2 == b);
        } } }
        return None;
    }
    let method = slice_to_vec(slice_subrange(line, 0, a));
    let target = slice_to_vec(slice_subrange(line, a + 1, b));
    proof { assert(request_line_split(line@, method@, target@, a as int, b as int)); }
    Some((method, target))
}

/// Parse a status line (without its CRLF).
fn parse_status_line(line: &[u8]) -> (out: Option<u16>)
    ensures match out {
        Some(status) => status_line_ok(line@, status),
        None => forall|s: u16| !status_line_ok(line@, s),
    },
{
    if line.len() < 12 || !is_version(slice_subrange(line, 0, 8)) || line[8] != SP
        || line[9] < 49 || line[9] > 53 || line[10] < 48 || line[10] > 57 || line[11] < 48 || line[11] > 57 {
        return None;
    }
    if line.len() > 12 && (line[12] != SP || !all_value_bytes(line, 13, line.len())) { return None; }
    let hundreds: u16 = (line[9] - 48) as u16;
    let tens: u16 = (line[10] - 48) as u16;
    let ones: u16 = (line[11] - 48) as u16;
    let status: u16 = hundreds * 100 + tens * 10 + ones;
    Some(status)
}

// ---- heads -----------------------------------------------------------------

/// The CRLF ending a request head's start line, with the prefix facts lifted to `bytes`.
proof fn request_head_line_end(bytes: Seq<u8>, len: int, head: RequestHead) -> (e: int)
    requires 0 <= len <= bytes.len(), request_head_ok(bytes.subrange(0, len), head),
    ensures crlf_at(bytes, e), e + 2 <= len, clean(bytes.subrange(0, e)),
        request_line_ok(bytes.subrange(0, e), head.method@, head.target@), fields_ok(bytes.subrange(0, len), e + 2, head.fields@),
{
    let p = bytes.subrange(0, len);
    let e = choose|e: int| #[trigger] crlf_at(p, e) && clean(p.subrange(0, e))
        && request_line_ok(p.subrange(0, e), head.method@, head.target@) && fields_ok(p, e + 2, head.fields@);
    lemma_prefix_crlf(bytes, len, e);
    lemma_prefix_subrange(bytes, len, 0, e);
    e
}
proof fn status_head_line_end(bytes: Seq<u8>, len: int, head: StatusHead) -> (e: int)
    requires 0 <= len <= bytes.len(), status_head_ok(bytes.subrange(0, len), head),
    ensures crlf_at(bytes, e), e + 2 <= len, clean(bytes.subrange(0, e)),
        status_line_ok(bytes.subrange(0, e), head.status), fields_ok(bytes.subrange(0, len), e + 2, head.fields@),
{
    let p = bytes.subrange(0, len);
    let e = choose|e: int| #[trigger] crlf_at(p, e) && clean(p.subrange(0, e))
        && status_line_ok(p.subrange(0, e), head.status) && fields_ok(p, e + 2, head.fields@);
    lemma_prefix_crlf(bytes, len, e);
    lemma_prefix_subrange(bytes, len, 0, e);
    e
}

/// The first break from 0 is not a CRLF: no head at all.
proof fn lemma_no_head_without_crlf(bytes: Seq<u8>, found: int)
    requires 0 <= found <= bytes.len(), clean(bytes.subrange(0, found)), found < bytes.len() ==> is_break(bytes[found]),
        found == bytes.len() || found + 1 == bytes.len() || bytes[found] == LF || bytes[found + 1] != LF,
    ensures no_request_head(bytes), no_status_head(bytes),
{
    assert forall|len: int, head: RequestHead| 0 <= len <= bytes.len() implies !(#[trigger] request_head_ok(bytes.subrange(0, len), head)) by {
        if request_head_ok(bytes.subrange(0, len), head) {
            let e = request_head_line_end(bytes, len, head);
            lemma_first_break(bytes, 0, e, found);
        }
    }
    assert forall|len: int, head: StatusHead| 0 <= len <= bytes.len() implies !(#[trigger] status_head_ok(bytes.subrange(0, len), head)) by {
        if status_head_ok(bytes.subrange(0, len), head) {
            let e = status_head_line_end(bytes, len, head);
            lemma_first_break(bytes, 0, e, found);
        }
    }
}

/// The start line ends at `e`; a head's start line is that one, and its field block follows it.
proof fn lemma_head_start_line(bytes: Seq<u8>, e: int)
    requires crlf_at(bytes, e), clean(bytes.subrange(0, e)),
    ensures
        forall|len: int, head: RequestHead| 0 <= len <= bytes.len() && #[trigger] request_head_ok(bytes.subrange(0, len), head)
            ==> request_line_ok(bytes.subrange(0, e), head.method@, head.target@) && fields_ok(bytes.subrange(0, len), e + 2, head.fields@),
        forall|len: int, head: StatusHead| 0 <= len <= bytes.len() && #[trigger] status_head_ok(bytes.subrange(0, len), head)
            ==> status_line_ok(bytes.subrange(0, e), head.status) && fields_ok(bytes.subrange(0, len), e + 2, head.fields@),
{
    assert forall|len: int, head: RequestHead| 0 <= len <= bytes.len() && #[trigger] request_head_ok(bytes.subrange(0, len), head)
        implies request_line_ok(bytes.subrange(0, e), head.method@, head.target@) && fields_ok(bytes.subrange(0, len), e + 2, head.fields@) by {
        let e2 = request_head_line_end(bytes, len, head);
        lemma_first_break(bytes, 0, e2, e);
    }
    assert forall|len: int, head: StatusHead| 0 <= len <= bytes.len() && #[trigger] status_head_ok(bytes.subrange(0, len), head)
        implies status_line_ok(bytes.subrange(0, e), head.status) && fields_ok(bytes.subrange(0, len), e + 2, head.fields@) by {
        let e2 = status_head_line_end(bytes, len, head);
        lemma_first_break(bytes, 0, e2, e);
    }
}

/// Parse a request head from the front of `buffer`. Sound and complete for the grammar.
pub fn parse_request(buffer: &[u8]) -> (out: RequestProgress)
    ensures match out {
        RequestProgress::Complete(head, len) => len <= buffer.len() && request_head_ok(buffer@.subrange(0, len as int), head),
        RequestProgress::Incomplete => buffer.len() < MAX_BYTES && no_request_head(buffer@),
        RequestProgress::Rejected(_) => no_request_head(buffer@),
    },
{
    let e = find_break(buffer, 0);
    if e < buffer.len() && buffer[e] == LF {
        proof { lemma_no_head_without_crlf(buffer@, e as int); }
        return RequestProgress::Rejected(Rejection::BadRequest);
    }
    if e == buffer.len() || e + 1 == buffer.len() {
        proof { lemma_no_head_without_crlf(buffer@, e as int); }
        return if buffer.len() >= MAX_BYTES { RequestProgress::Rejected(Rejection::TooLarge) } else { RequestProgress::Incomplete };
    }
    if buffer[e + 1] != LF {
        proof { lemma_no_head_without_crlf(buffer@, e as int); }
        return RequestProgress::Rejected(Rejection::BadRequest);
    }
    proof { lemma_head_start_line(buffer@, e as int); }
    let (method, target) = match parse_request_line(slice_subrange(buffer, 0, e)) {
        Some(parts) => parts,
        None => { return RequestProgress::Rejected(Rejection::BadRequest); }
    };
    match parse_fields(buffer, e + 2) {
        FieldsProgress::Complete(fields, len) => {
            let head = RequestHead { method, target, fields };
            proof {
                let p = buffer@.subrange(0, len as int);
                lemma_prefix_subrange(buffer@, len as int, 0, e as int);
                assert(crlf_at(p, e as int));
                assert(request_head_ok(p, head));
            }
            RequestProgress::Complete(head, len)
        }
        FieldsProgress::Incomplete => RequestProgress::Incomplete,
        FieldsProgress::Rejected(why) => RequestProgress::Rejected(why),
    }
}

/// Parse a status head from the front of `buffer`. Sound and complete for the grammar.
pub fn parse_status(buffer: &[u8]) -> (out: StatusProgress)
    ensures match out {
        StatusProgress::Complete(head, len) => len <= buffer.len() && status_head_ok(buffer@.subrange(0, len as int), head),
        StatusProgress::Incomplete => buffer.len() < MAX_BYTES && no_status_head(buffer@),
        StatusProgress::Rejected(_) => no_status_head(buffer@),
    },
{
    let e = find_break(buffer, 0);
    if e < buffer.len() && buffer[e] == LF {
        proof { lemma_no_head_without_crlf(buffer@, e as int); }
        return StatusProgress::Rejected(Rejection::BadRequest);
    }
    if e == buffer.len() || e + 1 == buffer.len() {
        proof { lemma_no_head_without_crlf(buffer@, e as int); }
        return if buffer.len() >= MAX_BYTES { StatusProgress::Rejected(Rejection::TooLarge) } else { StatusProgress::Incomplete };
    }
    if buffer[e + 1] != LF {
        proof { lemma_no_head_without_crlf(buffer@, e as int); }
        return StatusProgress::Rejected(Rejection::BadRequest);
    }
    proof { lemma_head_start_line(buffer@, e as int); }
    let status = match parse_status_line(slice_subrange(buffer, 0, e)) {
        Some(status) => status,
        None => { return StatusProgress::Rejected(Rejection::BadRequest); }
    };
    match parse_fields(buffer, e + 2) {
        FieldsProgress::Complete(fields, len) => {
            let head = StatusHead { status, fields };
            proof {
                let p = buffer@.subrange(0, len as int);
                lemma_prefix_subrange(buffer@, len as int, 0, e as int);
                assert(crlf_at(p, e as int));
                assert(status_head_ok(p, head));
            }
            StatusProgress::Complete(head, len)
        }
        FieldsProgress::Incomplete => StatusProgress::Incomplete,
        FieldsProgress::Rejected(why) => StatusProgress::Rejected(why),
    }
}
}
