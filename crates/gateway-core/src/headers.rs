//! Verified header projection for both directions of an exchange. Headers are
//! byte fields (lowercase name, value, sensitivity). The checked facts: an
//! outgoing request carries only allowlisted client headers plus exactly one
//! Host, exactly one configured credential, and exactly one Accept-Encoding;
//! the client's own Authorization never leaves; a response carries only
//! allowlisted provider headers; nothing is fabricated, every forwarded field
//! is one of the input fields; Connection-nominated names are dropped; and the
//! head stays within the field-count and byte limits. The runtime converts
//! Hyper's header map to and from these fields and does nothing else.
use vstd::prelude::*;
use vstd::slice::slice_to_vec;

verus! {
pub const MAX_FIELDS: usize = 100;
pub const MAX_BYTES: usize = 32768;

pub const CONTENT_TYPE: [u8; 12] = *b"content-type";
pub const ACCEPT: [u8; 6] = *b"accept";
pub const ANTHROPIC_VERSION: [u8; 17] = *b"anthropic-version";
pub const ANTHROPIC_BETA: [u8; 14] = *b"anthropic-beta";
pub const OPENAI_BETA: [u8; 11] = *b"openai-beta";
pub const CONTENT_ENCODING: [u8; 16] = *b"content-encoding";
pub const CACHE_CONTROL: [u8; 13] = *b"cache-control";
pub const RETRY_AFTER: [u8; 11] = *b"retry-after";
pub const REQUEST_ID: [u8; 10] = *b"request-id";
pub const X_REQUEST_ID: [u8; 12] = *b"x-request-id";
pub const HOST: [u8; 4] = *b"host";
pub const AUTHORIZATION: [u8; 13] = [97, 117, 116, 104, 111, 114, 105, 122, 97, 116, 105, 111, 110];
pub const X_API_KEY: [u8; 9] = [120, 45, 97, 112, 105, 45, 107, 101, 121];
pub const ACCEPT_ENCODING: [u8; 15] = *b"accept-encoding";
pub const IDENTITY: [u8; 8] = *b"identity";
pub const CONNECTION: [u8; 10] = *b"connection";
pub const UPGRADE: [u8; 7] = *b"upgrade";
pub const TRAILER: [u8; 7] = *b"trailer";

/// One header field. Names are lowercase ASCII, as Hyper stores them.
pub struct Field { pub name: Vec<u8>, pub value: Vec<u8>, pub sensitive: bool }

#[derive(PartialEq, Eq, Structural, Clone, Copy, Debug)]
pub enum Rejection { TooLarge, BadRequest }

pub open spec fn request_allowed(name: Seq<u8>) -> bool {
    name == CONTENT_TYPE@ || name == ACCEPT@ || name == ANTHROPIC_VERSION@
        || name == ANTHROPIC_BETA@ || name == OPENAI_BETA@
}
pub open spec fn response_allowed(name: Seq<u8>) -> bool {
    name == CONTENT_TYPE@ || name == CONTENT_ENCODING@ || name == CACHE_CONTROL@
        || name == RETRY_AFTER@ || name == REQUEST_ID@ || name == X_REQUEST_ID@
}
pub open spec fn allowed(request: bool, name: Seq<u8>) -> bool {
    if request { request_allowed(name) } else { response_allowed(name) }
}
pub open spec fn lower_byte(b: u8) -> u8 { if 65 <= b <= 90 { (b + 32) as u8 } else { b } }
pub open spec fn lower_seq(s: Seq<u8>) -> Seq<u8> { Seq::new(s.len(), |i: int| lower_byte(s[i])) }
/// RFC 9110 token characters, the bytes a header name may contain.
pub open spec fn is_tchar(b: u8) -> bool {
    (48 <= b <= 57) || (65 <= b <= 90) || (97 <= b <= 122)
        || b == 33 || (35 <= b <= 39) || b == 42 || b == 43 || b == 45 || b == 46
        || b == 94 || b == 95 || b == 96 || b == 124 || b == 126
}
pub open spec fn is_blank(b: u8) -> bool { b == 32 || b == 9 }
/// Bytes `[s, e)` of `value` are one comma-delimited element with its
/// surrounding blanks removed.
pub open spec fn element_bounds(value: Seq<u8>, start: int, s: int, e: int, end: int) -> bool {
    0 <= start <= s <= e <= end <= value.len()
        && (start == 0 || value[start - 1] == 44) && (end == value.len() || value[end] == 44)
        && (forall|k: int| start <= k < s ==> is_blank(#[trigger] value[k]))
        && (forall|k: int| e <= k < end ==> is_blank(#[trigger] value[k]))
        && (s == e || (!is_blank(value[s]) && !is_blank(value[e - 1])))
        && (forall|k: int| start <= k < end ==> #[trigger] value[k] != 44)
}
pub open spec fn element_at(value: Seq<u8>, s: int, e: int) -> bool {
    exists|start: int, end: int| #[trigger] element_bounds(value, start, s, e, end)
}
/// `name` is the lowercased element `[s, e)` of the Connection field at `i`.
pub open spec fn nominated_in(fields: Seq<Field>, i: int, s: int, e: int, name: Seq<u8>) -> bool {
    0 <= i < fields.len() && fields[i].name@ == CONNECTION@
        && 0 <= s <= e <= fields[i].value@.len() && element_at(fields[i].value@, s, e)
        && name == lower_seq(fields[i].value@.subrange(s, e))
}
/// Some Connection field nominates `name` as one of its elements.
pub open spec fn nominated(fields: Seq<Field>, name: Seq<u8>) -> bool {
    exists|i: int, s: int, e: int| #[trigger] nominated_in(fields, i, s, e, name)
}
/// Every allowlisted name some Connection field nominates is in `hop`.
pub open spec fn complete(fields: Seq<Field>, request: bool, hop: Seq<Vec<u8>>) -> bool {
    forall|name: Seq<u8>| #[trigger] nominated(fields, name) && allowed(request, name) ==> in_list(hop, name)
}
/// `complete` restricted to the first `i` fields.
pub open spec fn complete_upto(fields: Seq<Field>, i: int, request: bool, hop: Seq<Vec<u8>>) -> bool {
    forall|j: int, s: int, e: int, name: Seq<u8>| 0 <= j < i && #[trigger] nominated_in(fields, j, s, e, name)
        && allowed(request, name) ==> in_list(hop, name)
}
/// Every element of `value` that ends before `limit` and lowercases to an
/// allowlisted name is in `hop`.
pub open spec fn elements_covered(value: Seq<u8>, limit: int, request: bool, hop: Seq<Vec<u8>>) -> bool {
    forall|start: int, s: int, e: int, end: int| #[trigger] element_bounds(value, start, s, e, end) && end < limit
        && allowed(request, lower_seq(value.subrange(s, e))) ==> in_list(hop, lower_seq(value.subrange(s, e)))
}
pub open spec fn names_total(fields: Seq<Field>) -> nat
    decreases fields.len(),
{
    if fields.len() == 0 { 0 } else { names_total(fields.drop_last()) + fields.last().name@.len() + fields.last().value@.len() }
}
pub open spec fn within_limits(fields: Seq<Field>) -> bool {
    fields.len() <= MAX_FIELDS && names_total(fields) <= MAX_BYTES
}
pub open spec fn count_named(fields: Seq<Field>, name: Seq<u8>) -> nat {
    fields.filter(|f: Field| f.name@ == name).len()
}
pub open spec fn has_name(fields: Seq<Field>, name: Seq<u8>) -> bool {
    exists|i: int| 0 <= i < fields.len() && #[trigger] fields[i].name@ == name
}
pub open spec fn in_list(list: Seq<Vec<u8>>, name: Seq<u8>) -> bool {
    exists|i: int| 0 <= i < list.len() && #[trigger] list[i]@ == name
}
/// `out[k]` is a copy of some input field.
pub open spec fn copied_from(fields: Seq<Field>, out: Field) -> bool {
    exists|j: int| 0 <= j < fields.len() && #[trigger] fields[j].name@ == out.name@
        && fields[j].value@ == out.value@ && fields[j].sensitive == out.sensitive
}

pub fn eq(a: &[u8], b: &[u8]) -> (out: bool)
    ensures out == (a@ == b@),
{
    if a.len() != b.len() { return false; }
    let mut i: usize = 0;
    while i < a.len()
        invariant i <= a.len(), a.len() == b.len(), forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a.len() - i,
    {
        if a[i] != b[i] { return false; }
        i = i + 1;
    }
    proof { assert(a@ =~= b@); }
    true
}

fn lower(b: u8) -> (out: u8)
    ensures out == lower_byte(b),
{ if b >= 65 && b <= 90 { b + 32 } else { b } }

pub fn lowercase(name: &[u8]) -> (out: Vec<u8>)
    ensures out@ == lower_seq(name@),
{
    let mut out: Vec<u8> = Vec::with_capacity(name.len());
    let mut i: usize = 0;
    while i < name.len()
        invariant i <= name.len(), out@.len() == i, forall|j: int| 0 <= j < i ==> out@[j] == lower_byte(name@[j]),
        decreases name.len() - i,
    {
        out.push(lower(name[i]));
        i = i + 1;
    }
    proof { assert(out@ =~= lower_seq(name@)); }
    out
}

pub fn tchar(b: u8) -> (out: bool)
    ensures out == is_tchar(b),
{
    (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122)
        || b == 33 || (b >= 35 && b <= 39) || b == 42 || b == 43 || b == 45 || b == 46
        || b == 94 || b == 95 || b == 96 || b == 124 || b == 126
}

pub fn allowed_name(request: bool, name: &[u8]) -> (out: bool)
    ensures out == allowed(request, name@),
{
    if request {
        eq(name, CONTENT_TYPE.as_slice()) || eq(name, ACCEPT.as_slice()) || eq(name, ANTHROPIC_VERSION.as_slice())
            || eq(name, ANTHROPIC_BETA.as_slice()) || eq(name, OPENAI_BETA.as_slice())
    } else {
        eq(name, CONTENT_TYPE.as_slice()) || eq(name, CONTENT_ENCODING.as_slice()) || eq(name, CACHE_CONTROL.as_slice())
            || eq(name, RETRY_AFTER.as_slice()) || eq(name, REQUEST_ID.as_slice()) || eq(name, X_REQUEST_ID.as_slice())
    }
}

pub fn count(fields: &Vec<Field>, name: &[u8]) -> (out: usize)
    ensures out == count_named(fields@, name@),
{
    let mut i: usize = 0; let mut n: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(), n == count_named(fields@.subrange(0, i as int), name@),
        decreases fields.len() - i,
    {
        proof { reveal(Seq::filter); assert(fields@.subrange(0, i as int + 1).drop_last() =~= fields@.subrange(0, i as int)); }
        if eq(fields[i].name.as_slice(), name) { n = n + 1; }
        i = i + 1;
    }
    proof { assert(fields@.subrange(0, fields.len() as int) =~= fields@); }
    n
}

pub fn has(fields: &Vec<Field>, name: &[u8]) -> (out: bool)
    ensures out == has_name(fields@, name@),
{
    let mut i: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(), forall|j: int| 0 <= j < i ==> #[trigger] fields@[j].name@ != name@,
        decreases fields.len() - i,
    {
        if eq(fields[i].name.as_slice(), name) { return true; }
        i = i + 1;
    }
    false
}

fn listed(list: &Vec<Vec<u8>>, name: &[u8]) -> (out: bool)
    ensures out == in_list(list@, name@),
{
    let mut i: usize = 0;
    while i < list.len()
        invariant i <= list.len(), forall|j: int| 0 <= j < i ==> #[trigger] list@[j]@ != name@,
        decreases list.len() - i,
    {
        if eq(list[i].as_slice(), name) { return true; }
        i = i + 1;
    }
    false
}

/// The head's field count and total name/value bytes are within the limits.
pub fn fits(fields: &Vec<Field>) -> (out: bool)
    ensures out == within_limits(fields@),
{
    if fields.len() > MAX_FIELDS { return false; }
    let mut i: usize = 0; let mut total: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(), total == names_total(fields@.subrange(0, i as int)), total <= MAX_BYTES,
        decreases fields.len() - i,
    {
        proof { assert(fields@.subrange(0, i as int + 1).drop_last() =~= fields@.subrange(0, i as int)); }
        let field = &fields[i];
        if field.name.len() > MAX_BYTES - total || field.value.len() > MAX_BYTES - total - field.name.len() {
            proof { lemma_total_prefix(fields@, i as int + 1); }
            return false;
        }
        total = total + field.name.len() + field.value.len();
        i = i + 1;
    }
    proof { assert(fields@.subrange(0, fields.len() as int) =~= fields@); }
    true
}

// The byte total of a prefix is at most the total of the whole sequence.
proof fn lemma_total_prefix(fields: Seq<Field>, n: int)
    requires 0 <= n <= fields.len(),
    ensures names_total(fields.subrange(0, n)) <= names_total(fields),
    decreases fields.len() - n,
{
    if n < fields.len() {
        assert(fields.subrange(0, n + 1).drop_last() =~= fields.subrange(0, n));
        lemma_total_prefix(fields, n + 1);
    } else {
        assert(fields.subrange(0, n) =~= fields);
    }
}

// The request allowlist and the three injected names are pairwise distinct;
// their lengths already differ.
proof fn lemma_names_distinct()
    ensures CONTENT_TYPE@.len() == 12, ACCEPT@.len() == 6, ANTHROPIC_VERSION@.len() == 17, ANTHROPIC_BETA@.len() == 14,
        OPENAI_BETA@.len() == 11, HOST@.len() == 4, AUTHORIZATION@.len() == 13, X_API_KEY@.len() == 9, ACCEPT_ENCODING@.len() == 15,
        forall|name: Seq<u8>| #[trigger] request_allowed(name) ==> name != HOST@ && name != AUTHORIZATION@ && name != X_API_KEY@ && name != ACCEPT_ENCODING@,
{
    assert forall|name: Seq<u8>| #[trigger] request_allowed(name)
        implies name != HOST@ && name != AUTHORIZATION@ && name != X_API_KEY@ && name != ACCEPT_ENCODING@
    by {
        assert(name.len() == 12 || name.len() == 6 || name.len() == 17 || name.len() == 14 || name.len() == 11);
    }
}

proof fn lemma_in_list_push(list: Seq<Vec<u8>>, name: Seq<u8>, x: Vec<u8>)
    requires in_list(list, name),
    ensures in_list(list.push(x), name),
{
    let j = choose|j: int| 0 <= j < list.len() && #[trigger] list[j]@ == name;
    assert(list.push(x)[j]@ == name);
}

/// An explicit malformed Connection element, including empty comma elements.
pub open spec fn bad_connection_element(fields: Seq<Field>) -> bool {
    exists|i: int, start: int, s: int, e: int, end: int| 0 <= i < fields.len()
        && fields[i].name@ == CONNECTION@ && element_bounds(fields[i].value@, start, s, e, end)
        && (s == e || exists|k: int| s <= k < e && !is_tchar(fields[i].value@[k]))
}
/// The names a Connection header nominates as hop-by-hop among the allowlisted
/// names, lowercased and distinct. `None` when any element is empty or is not
/// a header-name token. Every returned name is allowlisted and is one element
/// of some Connection value, and every allowlisted name that any Connection
/// value nominates is returned: the list is exactly the nominations.
pub fn nominations(fields: &Vec<Field>, request: bool) -> (out: Option<Vec<Vec<u8>>>)
    ensures match out {
        Some(hop) => (forall|k: int| 0 <= k < hop.len() ==> allowed(request, #[trigger] hop@[k]@)
            && nominated(fields@, hop@[k]@)) && complete(fields@, request, hop@),
        None => bad_connection_element(fields@),
    },
{
    let mut hop: Vec<Vec<u8>> = Vec::new();
    let mut i: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(),
            forall|k: int| 0 <= k < hop.len() ==> allowed(request, #[trigger] hop@[k]@)
                && nominated(fields@, hop@[k]@),
            complete_upto(fields@, i as int, request, hop@),
        decreases fields.len() - i,
    {
        if eq(fields[i].name.as_slice(), CONNECTION.as_slice()) {
            let value = fields[i].value.as_slice();
            let mut start: usize = 0;
            let mut more = true;
            // Each iteration consumes one comma-delimited element.
            while more
                invariant i < fields.len(), fields@[i as int].name@ == CONNECTION@, value@ == fields@[i as int].value@,
                    start <= value.len(),
                    start == 0 || value@[start as int - 1] == 44,
                    forall|k: int| 0 <= k < hop.len() ==> allowed(request, #[trigger] hop@[k]@)
                        && nominated(fields@, hop@[k]@),
                    complete_upto(fields@, i as int, request, hop@),
                    elements_covered(value@, if more { start as int } else { value@.len() as int + 1 }, request, hop@),
                decreases value.len() - start, (if more { 1int } else { 0int }),
            {
                // Find the end of this element.
                let mut end: usize = start;
                while end < value.len() && value[end] != 44
                    invariant start <= end <= value.len(), forall|k: int| start <= k < end ==> #[trigger] value@[k] != 44,
                    decreases value.len() - end,
                { end = end + 1; }
                // Trim blanks.
                let mut s: usize = start;
                while s < end && (value[s] == 32 || value[s] == 9)
                    invariant start <= s <= end <= value.len(), forall|k: int| start <= k < s ==> is_blank(#[trigger] value@[k]),
                    decreases end - s,
                { s = s + 1; }
                let mut e: usize = end;
                while e > s && (value[e - 1] == 32 || value[e - 1] == 9)
                    invariant s <= e <= end <= value.len(), forall|k: int| e <= k < end ==> is_blank(#[trigger] value@[k]),
                    decreases e - s,
                { e = e - 1; }
                if s == e {
                    proof { assert(element_bounds(value@, start as int, s as int, e as int, end as int));
                        assert(bad_connection_element(fields@)); }
                    return None;
                }
                let mut t: usize = s;
                while t < e
                    invariant element_bounds(value@, start as int, s as int, e as int, end as int),
                        i < fields.len(), fields@[i as int].name@ == CONNECTION@, fields@[i as int].value@ == value@,
                        s <= t <= e <= value.len(), forall|k: int| s <= k < t ==> is_tchar(#[trigger] value@[k]),
                    decreases e - t,
                {
                    if !tchar(value[t]) {
                        proof { assert(element_bounds(value@, start as int, s as int, e as int, end as int));
                            assert(exists|k: int| s <= k < e && !is_tchar(value@[k]));
                            assert(bad_connection_element(fields@)); }
                        return None;
                    }
                    t = t + 1;
                }
                let name = lowercase(vstd::slice::slice_subrange(value, s, e));
                proof {
                    assert(end as int == value@.len() || value@[end as int] == 44);
                    assert(element_bounds(value@, start as int, s as int, e as int, end as int));
                    assert(element_at(value@, s as int, e as int));
                    assert(name@ == lower_seq(fields@[i as int].value@.subrange(s as int, e as int)));
                    assert(nominated_in(fields@, i as int, s as int, e as int, name@));
                }
                let ghost before = hop@;
                let was_allowed = allowed_name(request, name.as_slice());
                let was_listed = listed(&hop, name.as_slice());
                let pushed = was_allowed && !was_listed;
                if pushed { hop.push(name); }
                proof {
                    assert(pushed ==> hop@ == before.push(name));
                    assert(!pushed ==> hop@ == before);
                    // Whatever was covered stays covered, and this element is now covered.
                    assert forall|st: int, s2: int, e2: int, en: int| #[trigger] element_bounds(value@, st, s2, e2, en)
                        && en < end + 1 && allowed(request, lower_seq(value@.subrange(s2, e2)))
                        implies in_list(hop@, lower_seq(value@.subrange(s2, e2))) by {
                        if en < start {
                            assert(in_list(before, lower_seq(value@.subrange(s2, e2))));
                            if pushed { lemma_in_list_push(before, lower_seq(value@.subrange(s2, e2)), name); }
                        } else {
                            // The element lies in this comma-delimited segment, so its bounds are ours.
                            assert(st == start) by {
                                if st > start { assert(value@[st - 1] == 44); }
                                if st < start { assert(value@[start as int - 1] == 44); }
                            }
                            assert(en == end) by { if en < end { assert(value@[en] == 44); } }
                            assert(s2 < e2) by { if s2 == e2 { assert(is_blank(value@[s as int])); } }
                            assert(s2 == s as int) by {
                                if s2 < s { assert(is_blank(value@[s2])); }
                                if s2 > s { assert(is_blank(value@[s as int])); }
                            }
                            assert(e2 == e as int) by {
                                if e2 < e { assert(is_blank(value@[e as int - 1])); }
                                if e2 > e { assert(is_blank(value@[e2 - 1])); }
                            }
                            assert(lower_seq(value@.subrange(s2, e2)) == name@);
                            assert(was_allowed);
                            if pushed { assert(hop@[hop@.len() - 1]@ == name@); } else { assert(was_listed); assert(in_list(before, name@)); }
                        }
                    }
                    assert forall|j: int, s2: int, e2: int, n: Seq<u8>| 0 <= j < i && #[trigger] nominated_in(fields@, j, s2, e2, n)
                        && allowed(request, n) implies in_list(hop@, n) by {
                        assert(in_list(before, n));
                        if pushed { lemma_in_list_push(before, n, name); }
                    }
                }
                if end == value.len() { more = false; } else { start = end + 1; }
            }
            proof {
                assert forall|j: int, s2: int, e2: int, n: Seq<u8>| 0 <= j < i + 1 && #[trigger] nominated_in(fields@, j, s2, e2, n)
                    && allowed(request, n) implies in_list(hop@, n) by {
                    if j == i {
                        let (st, en) = choose|st: int, en: int| #[trigger] element_bounds(value@, st, s2, e2, en);
                        assert(en < value@.len() as int + 1);
                    }
                }
            }
        } else {
            proof {
                assert forall|j: int, s2: int, e2: int, n: Seq<u8>| 0 <= j < i + 1 && #[trigger] nominated_in(fields@, j, s2, e2, n)
                    && allowed(request, n) implies in_list(hop@, n) by {
                    if j == i { assert(fields@[i as int].name@ == CONNECTION@); }
                }
            }
        }
        i = i + 1;
    }
    proof {
        assert forall|name: Seq<u8>| #[trigger] nominated(fields@, name) && allowed(request, name) implies in_list(hop@, name) by {
            let (j, s2, e2) = choose|j: int, s2: int, e2: int| #[trigger] nominated_in(fields@, j, s2, e2, name);
        }
    }
    Some(hop)
}

/// Observable fields, excluding vector allocation identity.
pub open spec fn field_view(f: Field) -> (Seq<u8>, Seq<u8>, bool) { (f.name@, f.value@, f.sensitive) }
pub open spec fn views(fields: Seq<Field>) -> Seq<(Seq<u8>, Seq<u8>, bool)> {
    fields.map(|i: int, f: Field| field_view(f))
}
pub open spec fn retained_prefix(fields: Seq<Field>, request: bool, n: int) -> Seq<(Seq<u8>, Seq<u8>, bool)>
    decreases n,
{
    if n <= 0 || n > fields.len() { Seq::empty() }
    else { retained_prefix(fields, request, n - 1) +
        if allowed(request, fields[n - 1].name@) && !nominated(fields, fields[n - 1].name@) {
            seq![field_view(fields[n - 1])]
        } else { Seq::empty() } }
}
pub open spec fn retained(fields: Seq<Field>, request: bool) -> Seq<(Seq<u8>, Seq<u8>, bool)> {
    retained_prefix(fields, request, fields.len() as int)
}
proof fn nomination_iff(fields: Seq<Field>, request: bool, hop: Seq<Vec<u8>>, name: Seq<u8>)
    requires complete(fields, request, hop), allowed(request, name),
        forall|k: int| 0 <= k < hop.len() ==> nominated(fields, #[trigger] hop[k]@),
    ensures in_list(hop, name) == nominated(fields, name),
{
    if in_list(hop, name) {
        let k = choose|k: int| 0 <= k < hop.len() && #[trigger] hop[k]@ == name;
    }
}

/// The input fields whose names are allowlisted for this direction and not
/// nominated hop-by-hop, in input order, each copied byte for byte.
#[verifier::loop_isolation(false)]
fn project(fields: &Vec<Field>, request: bool, hop: &Vec<Vec<u8>>) -> (out: Vec<Field>)
    requires complete(fields@, request, hop@),
        forall|k: int| 0 <= k < hop.len() ==> nominated(fields@, #[trigger] hop@[k]@),
    ensures views(out@) == retained(fields@, request), forall|k: int| 0 <= k < out@.len() ==> allowed(request, #[trigger] out@[k].name@)
            && !in_list(hop@, out@[k].name@) && copied_from(fields@, out@[k]),
        out@.len() <= fields@.len(),
{
    let mut out: Vec<Field> = Vec::new();
    let mut i: usize = 0;
    while i < fields.len()
        invariant i <= fields.len(), out@.len() <= i,
            views(out@) == retained_prefix(fields@, request, i as int),
            forall|k: int| 0 <= k < out@.len() ==> allowed(request, #[trigger] out@[k].name@)
                && !in_list(hop@, out@[k].name@) && copied_from(fields@, out@[k]),
        decreases fields.len() - i,
    {
        let field = &fields[i];
        let ghost before = out@;
        proof {
            if allowed(request, field.name@) { nomination_iff(fields@, request, hop@, field.name@); }
        }
        if allowed_name(request, field.name.as_slice()) && !listed(hop, field.name.as_slice()) {
            let copy = Field { name: slice_to_vec(field.name.as_slice()), value: slice_to_vec(field.value.as_slice()), sensitive: field.sensitive };
            out.push(copy);
            proof { assert(views(out@) =~= views(before).push(field_view(*field))); }
        }
        proof {
            assert(views(fields@.take(i as int + 1)) =~= views(fields@.take(i as int)).push(field_view(*field)));
            reveal(Seq::filter);
        }
        i = i + 1;
    }
    proof { assert(fields@.take(fields.len() as int) =~= fields@); }
    out
}

/// Every checked fact about an outgoing request head.
pub open spec fn request_head_ok(fields: Seq<Field>, out: Seq<Field>, host: Seq<u8>, credential_name: Seq<u8>, credential: Seq<u8>) -> bool {
    // Exactly the retained fields in order, followed by the three injected fields.
    out.len() >= 3 && views(out).take(out.len() - 3) == retained(fields, true)
    && (forall|k: int| 0 <= k < out.len() ==> request_allowed(#[trigger] out[k].name@)
        || out[k].name@ == HOST@ || out[k].name@ == credential_name || out[k].name@ == ACCEPT_ENCODING@)
    // Allowlisted fields are copies of input fields, and none was Connection-nominated.
    && (forall|k: int| 0 <= k < out.len() && request_allowed(#[trigger] out[k].name@) ==> copied_from(fields, out[k]) && !nominated(fields, out[k].name@))
    // Exactly one Host, one credential, one Accept-Encoding, with these values.
    && count_named(out, HOST@) == 1 && count_named(out, credential_name) == 1 && count_named(out, ACCEPT_ENCODING@) == 1
    && (forall|k: int| 0 <= k < out.len() && #[trigger] out[k].name@ == HOST@ ==> out[k].value@ == host)
    && (forall|k: int| 0 <= k < out.len() && #[trigger] out[k].name@ == credential_name ==> out[k].value@ == credential && out[k].sensitive)
    && (forall|k: int| 0 <= k < out.len() && #[trigger] out[k].name@ == ACCEPT_ENCODING@ ==> out[k].value@ == IDENTITY@)
    // The client's own Authorization never leaves, nor any other credential header.
    && (credential_name != AUTHORIZATION@ ==> !has_name(out, AUTHORIZATION@))
    && (credential_name != X_API_KEY@ ==> !has_name(out, X_API_KEY@))
    // The input head was within limits and carried no framing or encoding changes.
    && request_input_ok(fields)
    && out.len() <= fields.len() + 3
}

/// The input facts `request_head_ok` records: within limits, no framing or
/// encoding changes, no duplicate content type or API version.
pub open spec fn request_input_ok(fields: Seq<Field>) -> bool {
    within_limits(fields) && !has_name(fields, CONTENT_ENCODING@) && !has_name(fields, UPGRADE@) && !has_name(fields, TRAILER@)
    && count_named(fields, CONTENT_TYPE@) <= 1 && count_named(fields, ANTHROPIC_VERSION@) <= 1
}

/// Every rejection rule for an inbound request head, before any slot is
/// taken. Returns the hop-by-hop nominations the projection will drop.
pub fn check_request(fields: &Vec<Field>) -> (out: Result<Vec<Vec<u8>>, Rejection>)
    ensures match out {
        Ok(hop) => request_input_ok(fields@) && complete(fields@, true, hop@)
            && forall|k: int| 0 <= k < hop.len() ==> request_allowed(#[trigger] hop@[k]@) && nominated(fields@, hop@[k]@),
        Err(Rejection::TooLarge) => !within_limits(fields@),
        Err(Rejection::BadRequest) => !request_input_ok(fields@) || bad_connection_element(fields@),
    },
{
    if !fits(fields) { return Err(Rejection::TooLarge); }
    let hop = match nominations(fields, true) { Some(hop) => hop, None => return Err(Rejection::BadRequest) };
    if has(fields, CONTENT_ENCODING.as_slice()) || has(fields, UPGRADE.as_slice()) || has(fields, TRAILER.as_slice()) {
        return Err(Rejection::BadRequest);
    }
    if count(fields, CONTENT_TYPE.as_slice()) > 1 || count(fields, ANTHROPIC_VERSION.as_slice()) > 1 {
        return Err(Rejection::BadRequest);
    }
    Ok(hop)
}

/// Build the outgoing request head: the allowlisted client headers that no
/// Connection header nominated, then Host, the configured credential, and
/// `Accept-Encoding: identity`.
pub fn forward_request(fields: &Vec<Field>, host: &[u8], credential_name: &[u8], credential: &[u8]) -> (out: Result<Vec<Field>, Rejection>)
    requires credential_name@ == AUTHORIZATION@ || credential_name@ == X_API_KEY@,
    ensures match out {
        Ok(head) => request_head_ok(fields@, head@, host@, credential_name@, credential@),
        Err(Rejection::TooLarge) => !within_limits(fields@),
        Err(Rejection::BadRequest) => !request_input_ok(fields@) || bad_connection_element(fields@),
    },
{
    let hop = match check_request(fields) { Ok(hop) => hop, Err(rejection) => return Err(rejection) };
    let mut head = project(fields, true, &hop);
    proof {
        lemma_names_distinct();
        reveal(Seq::filter);
        assert(count_named(head@, HOST@) == 0) by { lemma_filter_none(head@, HOST@); }
        assert(count_named(head@, credential_name@) == 0) by { lemma_filter_none(head@, credential_name@); }
        assert(count_named(head@, ACCEPT_ENCODING@) == 0) by { lemma_filter_none(head@, ACCEPT_ENCODING@); }
    }
    let ghost projected = head@;
    head.push(Field { name: slice_to_vec(HOST.as_slice()), value: slice_to_vec(host), sensitive: false });
    head.push(Field { name: slice_to_vec(credential_name), value: slice_to_vec(credential), sensitive: true });
    head.push(Field { name: slice_to_vec(ACCEPT_ENCODING.as_slice()), value: slice_to_vec(IDENTITY.as_slice()), sensitive: false });
    proof {
        reveal(Seq::filter);
        assert(views(head@).take(projected.len() as int) =~= views(projected));
        assert(head@.subrange(0, projected.len() as int) =~= projected);
        lemma_filter_push_three(projected, head@, HOST@, credential_name@, ACCEPT_ENCODING@);
    }
    Ok(head)
}

/// Every checked fact about a forwarded response head.
pub open spec fn response_head_ok(fields: Seq<Field>, out: Seq<Field>) -> bool {
    views(out) == retained(fields, false) && (forall|k: int| 0 <= k < out.len() ==> response_allowed(#[trigger] out[k].name@) && copied_from(fields, out[k])
        && !nominated(fields, out[k].name@))
    && within_limits(fields) && !nominated(fields, CONTENT_ENCODING@)
    && out.len() <= fields.len()
}

/// Build the forwarded response head: the allowlisted provider headers that no
/// Connection header nominated. A response that nominates its own
/// Content-Encoding is rejected, because dropping the header while keeping the
/// encoded bytes would change their meaning. The nomination list is complete,
/// so this is the exact rule, not an approximation.
pub fn forward_response(fields: &Vec<Field>) -> (out: Result<Vec<Field>, Rejection>)
    ensures match out {
        Ok(head) => response_head_ok(fields@, head@),
        Err(Rejection::TooLarge) => !within_limits(fields@),
        Err(Rejection::BadRequest) => bad_connection_element(fields@) || nominated(fields@, CONTENT_ENCODING@),
    },
{
    if !fits(fields) { return Err(Rejection::TooLarge); }
    let hop = match nominations(fields, false) { Some(hop) => hop, None => return Err(Rejection::BadRequest) };
    if listed(&hop, CONTENT_ENCODING.as_slice()) { return Err(Rejection::BadRequest); }
    Ok(project(fields, false, &hop))
}

// A sequence with no field of the given name has a zero count for it.
pub proof fn lemma_filter_none(fields: Seq<Field>, name: Seq<u8>)
    requires forall|k: int| 0 <= k < fields.len() ==> #[trigger] fields[k].name@ != name,
    ensures count_named(fields, name) == 0,
    decreases fields.len(),
{
    reveal(Seq::filter);
    if fields.len() > 0 {
        lemma_filter_none(fields.drop_last(), name);
    }
}

// Pushing three fields with three distinct names onto a sequence that has
// none of them gives exactly one of each.
proof fn lemma_filter_push_three(base: Seq<Field>, out: Seq<Field>, a: Seq<u8>, b: Seq<u8>, c: Seq<u8>)
    requires a != b, b != c, a != c,
        count_named(base, a) == 0, count_named(base, b) == 0, count_named(base, c) == 0,
        out.len() == base.len() + 3, out.subrange(0, base.len() as int) == base,
        out[base.len() as int].name@ == a, out[base.len() as int + 1].name@ == b, out[base.len() as int + 2].name@ == c,
    ensures count_named(out, a) == 1, count_named(out, b) == 1, count_named(out, c) == 1,
{
    reveal(Seq::filter);
    let one = out.subrange(0, base.len() as int + 1);
    let two = out.subrange(0, base.len() as int + 2);
    assert(one.drop_last() =~= base);
    assert(two.drop_last() =~= one);
    assert(out.drop_last() =~= two);
    assert(one.last() == out[base.len() as int]);
    assert(two.last() == out[base.len() as int + 1]);
    assert(out.last() == out[base.len() as int + 2]);
    assert(count_named(one, a) == 1); assert(count_named(one, b) == 0); assert(count_named(one, c) == 0);
    assert(count_named(two, a) == 1); assert(count_named(two, b) == 1); assert(count_named(two, c) == 0);
}
}
